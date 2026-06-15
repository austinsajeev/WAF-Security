"""
AegisAI-X — Redis Blocklist Sync Worker
=========================================
The missing feedback loop: Gateway ↔ Blocklist

Flow:
  PostgreSQL ip_blocklist (source of truth)
      ↓  (this worker, every 10s)
  Redis SET  aegisai:blocklist:<ip> = "1" (with TTL)
      ↓  (Nginx reads via lua/openresty OR checked by a lightweight filter)
  Gateway denies blocked IPs before WAF even runs

Also handles:
  - Expired block cleanup (auto-expire via Redis TTL)
  - Block removals (unblock propagation)
  - Metrics for Prometheus

Run as: python blocklist_sync.py
"""

import os
import time
import logging
import redis
import psycopg2
import psycopg2.extras
from datetime             import datetime, timezone
from prometheus_client    import start_http_server, Gauge, Counter

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
PG_DSN            = os.environ.get("PG_DSN", "postgresql://aegisai:password@localhost/aegisai_db")
REDIS_URL         = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
SYNC_INTERVAL_SEC = int(os.environ.get("BLOCKLIST_SYNC_INTERVAL", "10"))
METRICS_PORT      = int(os.environ.get("BLOCKLIST_METRICS_PORT", "9102"))

# Redis key pattern used by Nginx (lua block) to check IPs
# nginx.conf lua block: if redis.get("aegisai:blocklist:" .. ip) then return 403
REDIS_KEY_PREFIX = "aegisai:blocklist:"

log = logging.getLogger("aegisai.blocklist_sync")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)

# ---------------------------------------------------------------------------
# Prometheus Metrics
# ---------------------------------------------------------------------------
ACTIVE_BLOCKS    = Gauge(
    'aegisai_blocklist_active_entries',
    'Number of currently active IP blocks in Redis'
)
SYNCED_TOTAL     = Counter(
    'aegisai_blocklist_synced_total',
    'Total number of IPs synced to Redis'
)
REMOVED_TOTAL    = Counter(
    'aegisai_blocklist_removed_total',
    'Total number of IPs removed from Redis (expired/unblocked)'
)
SYNC_ERRORS      = Counter(
    'aegisai_blocklist_sync_errors_total',
    'Total sync errors'
)
LAST_SYNC_TS     = Gauge(
    'aegisai_blocklist_last_sync_timestamp',
    'Unix timestamp of last successful sync'
)


# ---------------------------------------------------------------------------
# DB Connections
# ---------------------------------------------------------------------------
def get_pg():
    return psycopg2.connect(PG_DSN, cursor_factory=psycopg2.extras.RealDictCursor)

def get_redis():
    return redis.from_url(REDIS_URL, decode_responses=True)


# ---------------------------------------------------------------------------
# Core sync logic
# ---------------------------------------------------------------------------
def sync_blocklist(pg_conn, r: redis.Redis):
    """
    Pull all active blocks from PostgreSQL and sync to Redis.
    Uses pipeline for efficiency — one round-trip for all writes.
    """
    now = datetime.now(timezone.utc)

    # Fetch all currently active blocks
    with pg_conn.cursor() as cur:
        cur.execute("""
            SELECT ip::text, expires_at
            FROM ip_blocklist
            WHERE is_active = TRUE
              AND (expires_at IS NULL OR expires_at > NOW())
        """)
        active_blocks = cur.fetchall()

    # Fetch IPs that were recently unblocked or expired (cleanup)
    with pg_conn.cursor() as cur:
        cur.execute("""
            SELECT ip::text
            FROM ip_blocklist
            WHERE is_active = FALSE
               OR (expires_at IS NOT NULL AND expires_at <= NOW())
        """)
        inactive_ips = [row["ip"] for row in cur.fetchall()]

    # Build active set for fast lookup
    active_ips = {row["ip"] for row in active_blocks}

    # --- Sync active blocks to Redis ---
    pipe = r.pipeline(transaction=False)   # non-transactional pipeline = faster
    synced = 0

    for row in active_blocks:
        ip         = row["ip"]
        expires_at = row["expires_at"]
        redis_key  = f"{REDIS_KEY_PREFIX}{ip}"

        if expires_at:
            # Compute seconds until expiry
            ttl = int((expires_at - now).total_seconds())
            if ttl <= 0:
                continue   # already expired — skip
            pipe.set(redis_key, "1", ex=ttl)
        else:
            # Permanent block — long TTL (30 days), refreshed every sync
            pipe.set(redis_key, "1", ex=86400 * 30)

        synced += 1

    # --- Remove inactive/expired IPs from Redis ---
    removed = 0
    for ip in inactive_ips:
        if ip not in active_ips:
            pipe.delete(f"{REDIS_KEY_PREFIX}{ip}")
            removed += 1

    pipe.execute()

    # --- Update metrics ---
    SYNCED_TOTAL.inc(synced)
    REMOVED_TOTAL.inc(removed)
    ACTIVE_BLOCKS.set(len(active_blocks))
    LAST_SYNC_TS.set(time.time())

    if synced > 0 or removed > 0:
        log.info(
            "Blocklist sync | active=%d synced=%d removed=%d",
            len(active_blocks), synced, removed
        )


def auto_expire_pg(pg_conn):
    """
    Mark expired blocks as inactive in PostgreSQL so they are excluded
    from future syncs.
    """
    with pg_conn.cursor() as cur:
        cur.execute("""
            UPDATE ip_blocklist
            SET is_active = FALSE
            WHERE is_active = TRUE
              AND expires_at IS NOT NULL
              AND expires_at <= NOW()
        """)
        expired_count = cur.rowcount
    pg_conn.commit()

    if expired_count > 0:
        log.info("Auto-expired %d IP blocks in PostgreSQL", expired_count)


# ---------------------------------------------------------------------------
# Nginx Integration Note
# ---------------------------------------------------------------------------
# To make Nginx check Redis blocklist, add to nginx.conf http block:
#
#   lua_shared_dict blocklist_cache 10m;
#
# And in each location block (requires OpenResty / lua-nginx-module):
#
#   access_by_lua_block {
#       local redis = require "resty.redis"
#       local r = redis:new()
#       r:connect("127.0.0.1", 6379)
#       local blocked = r:get("aegisai:blocklist:" .. ngx.var.remote_addr)
#       if blocked == "1" then
#           ngx.status = 403
#           ngx.say("Blocked by AegisAI-X")
#           return ngx.exit(403)
#       end
#   }
#
# Alternative (simpler — no Lua needed):
#   Use a Nginx "geo" module with a dynamically updated conf file.
#   The sync worker writes a new nginx_blocklist.conf and signals Nginx to reload.
#   See: write_nginx_blocklist() below.

def write_nginx_blocklist(active_blocks: list, output_path: str = "/etc/nginx/conf.d/blocklist.conf"):
    """
    Alternative to Lua: generate an Nginx geo block that Nginx reads natively.
    Nginx reloads with: nginx -s reload (signal sent after writing)

    Generated file format:
        geo $is_blocked {
            default 0;
            1.2.3.4 1;
            5.6.7.8 1;
        }
    Example usage in nginx.conf:
        if ($is_blocked) { return 403; }
    """
    import subprocess

    lines = ["geo $is_blocked {", "    default 0;"]
    for row in active_blocks:
        lines.append(f"    {row['ip']} 1;")
    lines.append("}")

    content = "\n".join(lines) + "\n"

    try:
        with open(output_path, "w") as f:
            f.write(content)
        # Reload Nginx gracefully (no dropped connections)
        subprocess.run(["nginx", "-s", "reload"], check=True, capture_output=True)
        log.info("Nginx blocklist updated: %d IPs, Nginx reloaded", len(active_blocks))
    except Exception as e:
        log.error("Failed to write/reload nginx blocklist: %s", e)


# ---------------------------------------------------------------------------
# Main Loop
# ---------------------------------------------------------------------------
def run():
    log.info("AegisAI-X Blocklist Sync Worker starting (interval=%ds)...", SYNC_INTERVAL_SEC)
    start_http_server(METRICS_PORT)
    log.info("Prometheus metrics on port %d", METRICS_PORT)

    pg = get_pg()
    r  = get_redis()

    # Perform initial full sync immediately on start
    log.info("Performing initial full sync...")
    try:
        auto_expire_pg(pg)
        sync_blocklist(pg, r)
    except Exception as e:
        log.error("Initial sync failed: %s", e)

    while True:
        time.sleep(SYNC_INTERVAL_SEC)
        try:
            auto_expire_pg(pg)
            sync_blocklist(pg, r)
        except psycopg2.OperationalError:
            log.error("PostgreSQL connection lost. Reconnecting...")
            try:
                pg.close()
            except Exception:
                pass
            pg = get_pg()
        except redis.exceptions.ConnectionError:
            log.error("Redis connection lost. Reconnecting...")
            r = get_redis()
        except Exception as e:
            SYNC_ERRORS.inc()
            log.exception("Unexpected error in sync loop: %s", e)


if __name__ == "__main__":
    run()
