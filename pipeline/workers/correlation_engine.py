"""
AegisAI-X — Alert Correlation Engine
======================================
Polls ClickHouse for raw WAF events and request patterns,
evaluates configurable alert_rules from PostgreSQL,
and creates correlated incidents (many events → one incident).

Design principles:
  - One incident per attack campaign, NOT one per event
  - Dedup window prevents duplicate incidents for ongoing attacks
  - All rules are loaded from DB — no code deploy needed to tune thresholds
  - Sends notifications via pluggable notifiers (Slack, Email)

Run as: python correlation_engine.py
Metrics: Prometheus exposed on port 9101 (scraped by Prometheus server)
"""

import os
import json
import time
from prometheus_client import start_http_server, Gauge, Counter, Histogram
import logging
import smtplib
import requests
import clickhouse_connect
import psycopg2
import psycopg2.extras
import redis
from datetime    import datetime, timezone, timedelta
from email.mime.text import MIMEText
from dataclasses import dataclass, field
from typing      import Optional

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
CH_HOST      = os.environ.get("CH_HOST", "localhost")
CH_USER      = os.environ.get("CH_USER", "aegisai_reader")
CH_PASSWORD  = os.environ.get("CH_PASSWORD")
CH_DB        = os.environ.get("CH_DB", "aegisai_db")

PG_DSN       = os.environ.get("PG_DSN", "postgresql://aegisai:password@localhost/aegisai_db")
REDIS_URL    = os.environ.get("REDIS_URL", "redis://redis:6379/0")

SLACK_WEBHOOK = os.environ.get("SLACK_WEBHOOK_URL")   # optional
SMTP_HOST     = os.environ.get("SMTP_HOST")
SMTP_PORT     = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER     = os.environ.get("SMTP_USER")
SMTP_PASS     = os.environ.get("SMTP_PASS")
ALERT_EMAIL   = os.environ.get("ALERT_EMAIL")

# How often the engine polls ClickHouse (seconds)
POLL_INTERVAL = 30
METRICS_PORT  = int(os.environ.get("CORRELATION_METRICS_PORT", "9101"))

log = logging.getLogger("aegisai.correlation")
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

# ---------------------------------------------------------------------------
# Prometheus Metrics
# ---------------------------------------------------------------------------
# CRITICAL: If this gauge stops updating, the engine is dead.
# Alert rule: time() - aegisai_correlation_last_poll_timestamp > 120 → CRITICAL
LAST_POLL_TIMESTAMP  = Gauge(
    'aegisai_correlation_last_poll_timestamp',
    'Unix timestamp of last successful correlation poll cycle'
)
INCIDENTS_CREATED    = Counter(
    'aegisai_incidents_created_total',
    'Total incidents created by the correlation engine',
    ['severity', 'attack_type']
)
INCIDENTS_UPDATED    = Counter(
    'aegisai_incidents_updated_total',
    'Total existing incidents updated (event count bumped)'
)
POLL_DURATION        = Histogram(
    'aegisai_correlation_poll_duration_seconds',
    'Duration of each full correlation poll cycle'
)
RULES_EVALUATED      = Counter(
    'aegisai_correlation_rules_evaluated_total',
    'Number of rule evaluations executed',
    ['rule_name']
)
WORKER_UP            = Gauge(
    'aegisai_correlation_worker_up',
    '1 if the correlation worker is running, 0 if stopped'
)


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------
@dataclass
class AlertRule:
    id: int
    name: str
    description: str
    conditions: dict
    incident_severity: str
    attack_type: str
    dedup_window_seconds: int


@dataclass
class IncidentCandidate:
    rule_name: str
    rule: AlertRule
    site_id: str
    severity: str
    attack_type: str
    source_ip: Optional[str]
    source_country: Optional[str]
    event_count: int
    endpoints_targeted: list[str] = field(default_factory=list)
    ch_query_filter: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Database connections
# ---------------------------------------------------------------------------
def get_pg():
    return psycopg2.connect(PG_DSN, cursor_factory=psycopg2.extras.RealDictCursor)

def get_ch():
    return clickhouse_connect.get_client(
        host=CH_HOST, port=8123, username=CH_USER, password=CH_PASSWORD,
        database=CH_DB, secure=False
    )

def get_redis():
    return redis.from_url(REDIS_URL, decode_responses=True)


# ---------------------------------------------------------------------------
# Rule Loader (from PostgreSQL)
# ---------------------------------------------------------------------------
def load_rules(pg_conn) -> list[AlertRule]:
    with pg_conn.cursor() as cur:
        cur.execute("""
            SELECT id, name, description, conditions, incident_severity,
                   attack_type, dedup_window_seconds
            FROM alert_rules WHERE enabled = TRUE
        """)
        rows = cur.fetchall()
    rules = [
        AlertRule(
            id=r["id"], name=r["name"], description=r["description"],
            conditions=r["conditions"], incident_severity=r["incident_severity"],
            attack_type=r["attack_type"],
            dedup_window_seconds=r["dedup_window_seconds"]
        )
        for r in rows
    ]
    log.info("Loaded %d active alert rules from DB", len(rules))
    return rules


# ---------------------------------------------------------------------------
# Evaluators — one per rule metric type
# ---------------------------------------------------------------------------
def eval_waf_block_rate(rule: AlertRule, ch, since: datetime) -> list[IncidentCandidate]:
    """Detect mass WAF block events per site."""
    conditions = rule.conditions
    window_s   = conditions.get("window_seconds", 60)
    threshold  = conditions.get("threshold", 50)

    # Query: count WAF blocks per site in rolling window
    query = f"""
        SELECT
            site_id,
            remote_addr,
            country_code,
            count()      AS block_count,
            []           AS endpoints
        FROM waf_events
        WHERE
            timestamp >= now() - INTERVAL {window_s} SECOND
            AND action_taken = 'block'
        GROUP BY site_id, remote_addr, country_code
        HAVING block_count >= {threshold}
        ORDER BY block_count DESC
        LIMIT 50
    """
    result = ch.query(query)
    candidates = []
    for row in result.named_results():
        candidates.append(IncidentCandidate(
            rule_name=rule.name, rule=rule,
            site_id=row["site_id"], severity=rule.incident_severity,
            attack_type=rule.attack_type,
            source_ip=row["remote_addr"], source_country=row["country_code"],
            event_count=row["block_count"],
            endpoints_targeted=list(row["endpoints"])[:10],
            ch_query_filter={"site_id": row["site_id"], "remote_addr": str(row["remote_addr"])}
        ))
    return candidates


def eval_auth_failure_rate(rule: AlertRule, ch, since: datetime) -> list[IncidentCandidate]:
    """Detect brute force: high auth failure rate from single IP."""
    conditions = rule.conditions
    window_s   = conditions.get("window_seconds", 300)
    threshold  = conditions.get("threshold", 20)

    query = f"""
        SELECT
            site_id,
            remote_addr,
            country_code,
            count() AS fail_count,
            groupArray(DISTINCT uri) AS endpoints
        FROM request_logs
        WHERE
            timestamp >= now() - INTERVAL {window_s} SECOND
            AND status_code IN (401, 403)
            AND multiSearchAnyCaseInsensitive(uri, ['login', 'auth', 'signin', 'password'])
        GROUP BY site_id, remote_addr, country_code
        HAVING fail_count >= {threshold}
        ORDER BY fail_count DESC
        LIMIT 50
    """
    result = ch.query(query)
    candidates = []
    for row in result.named_results():
        candidates.append(IncidentCandidate(
            rule_name=rule.name, rule=rule,
            site_id=row["site_id"], severity=rule.incident_severity,
            attack_type="brute_force",
            source_ip=row["remote_addr"], source_country=row["country_code"],
            event_count=row["fail_count"],
            endpoints_targeted=list(row["endpoints"])[:5],
            ch_query_filter={"site_id": row["site_id"], "remote_addr": str(row["remote_addr"])}
        ))
    return candidates


def eval_rule_tag(rule: AlertRule, ch, since: datetime) -> list[IncidentCandidate]:
    """Detect specific WAF rule tags (sqli, xss, etc.)."""
    conditions     = rule.conditions
    tag            = conditions.get("rule_tag", "")
    min_score      = conditions.get("min_anomaly_score", 0)

    query = f"""
        SELECT
            site_id,
            remote_addr,
            country_code,
            count() AS event_count,
            max(anomaly_score) AS max_score,
            [] AS endpoints
        FROM waf_events
        WHERE
            timestamp >= now() - INTERVAL 5 MINUTE
            AND rule_tag = '{tag}'
            AND anomaly_score >= {min_score}
        GROUP BY site_id, remote_addr, country_code
        HAVING event_count >= 1
        ORDER BY max_score DESC
        LIMIT 50
    """
    result = ch.query(query)
    candidates = []
    for row in result.named_results():
        candidates.append(IncidentCandidate(
            rule_name=rule.name, rule=rule,
            site_id=row["site_id"], severity=rule.incident_severity,
            attack_type=rule.attack_type,
            source_ip=row["remote_addr"], source_country=row["country_code"],
            event_count=row["event_count"],
            endpoints_targeted=list(row["endpoints"])[:5],
            ch_query_filter={"site_id": row["site_id"], "rule_tag": tag}
        ))
    return candidates


def eval_traffic_spike(rule: AlertRule, ch, since: datetime) -> list[IncidentCandidate]:
    """Detect request rate 3x above 1h baseline per site."""
    conditions  = rule.conditions
    multiplier  = conditions.get("threshold", 3.0)
    window_s    = conditions.get("window_seconds", 300)

    query = f"""
        WITH
            -- Current rate (last N seconds)
            current AS (
                SELECT site_id, count() AS current_count
                FROM request_logs
                WHERE timestamp >= now() - INTERVAL {window_s} SECOND
                GROUP BY site_id
            ),
            -- Baseline rate (1h average scaled to same window)
            baseline AS (
                SELECT
                    site_id,
                    count() / (3600.0 / {window_s}) AS baseline_count
                FROM request_logs
                WHERE timestamp >= now() - INTERVAL 1 HOUR
                  AND timestamp < now() - INTERVAL {window_s} SECOND
                GROUP BY site_id
            )
        SELECT
            c.site_id,
            c.current_count,
            b.baseline_count,
            c.current_count / greatest(b.baseline_count, 1) AS spike_ratio
        FROM current c
        JOIN baseline b ON c.site_id = b.site_id
        WHERE c.current_count / greatest(b.baseline_count, 1) >= {multiplier}
        ORDER BY spike_ratio DESC
    """
    result = ch.query(query)
    candidates = []
    for row in result.named_results():
        candidates.append(IncidentCandidate(
            rule_name=rule.name, rule=rule,
            site_id=row["site_id"], severity=rule.incident_severity,
            attack_type="ddos",
            source_ip=None, source_country=None,
            event_count=int(row["current_count"]),
            ch_query_filter={"site_id": row["site_id"], "metric": "traffic_spike",
                             "ratio": float(row["spike_ratio"])}
        ))
    return candidates


# Map rule metric → evaluator function
EVALUATORS = {
    "waf_block_rate":          eval_waf_block_rate,
    "auth_failure_rate":       eval_auth_failure_rate,
    "rule_tag":                eval_rule_tag,
    "request_rate_multiplier": eval_traffic_spike,
    "cross_site_ip":           None,   # registered below
    "cross_site_ua":           None,   # registered below
}


def eval_cross_site_ip(rule: AlertRule, ch, since: datetime) -> list[IncidentCandidate]:
    """Detect same IP attacking 2+ distinct sites within the detection window."""
    conditions = rule.conditions
    window_s   = conditions.get("window_seconds", 600)
    min_sites  = conditions.get("min_sites", 2)

    query = f"""
        SELECT
            remote_addr,
            uniqExact(site_id)  AS site_count,
            groupArray(DISTINCT site_id) AS sites
        FROM waf_events
        WHERE timestamp >= now() - INTERVAL {window_s} SECOND
        GROUP BY remote_addr
        HAVING site_count >= {min_sites}
        ORDER BY site_count DESC
        LIMIT 25
    """
    result = ch.query(query)
    candidates = []
    for row in result.named_results():
        candidates.append(IncidentCandidate(
            rule_name=rule.name, rule=rule,
            site_id="multi", severity=rule.incident_severity,
            attack_type=rule.attack_type,
            source_ip=str(row["remote_addr"]), source_country=None,
            event_count=int(row["site_count"]),
            ch_query_filter={"remote_addr": str(row["remote_addr"]), "sites": list(row["sites"])}
        ))
    return candidates


def eval_cross_site_ua(rule: AlertRule, ch, since: datetime) -> list[IncidentCandidate]:
    """Detect same User-Agent hitting 2+ distinct sites within the detection window."""
    conditions = rule.conditions
    window_s   = conditions.get("window_seconds", 600)
    min_sites  = conditions.get("min_sites", 2)

    query = f"""
        SELECT
            user_agent,
            uniqExact(site_id)  AS site_count,
            groupArray(DISTINCT site_id) AS sites
        FROM request_logs
        WHERE
            timestamp >= now() - INTERVAL {window_s} SECOND
            AND length(user_agent) > 10
        GROUP BY user_agent
        HAVING site_count >= {min_sites}
        ORDER BY site_count DESC
        LIMIT 25
    """
    result = ch.query(query)
    candidates = []
    for row in result.named_results():
        candidates.append(IncidentCandidate(
            rule_name=rule.name, rule=rule,
            site_id="multi", severity=rule.incident_severity,
            attack_type=rule.attack_type,
            source_ip=None, source_country=None,
            event_count=int(row["site_count"]),
            ch_query_filter={"user_agent": row["user_agent"][:256], "sites": list(row["sites"])}
        ))
    return candidates


EVALUATORS["cross_site_ip"]  = eval_cross_site_ip
EVALUATORS["cross_site_ua"]  = eval_cross_site_ua


# ---------------------------------------------------------------------------
# Incident Writer (to PostgreSQL)
# ---------------------------------------------------------------------------
def create_or_update_incident(candidate: IncidentCandidate, pg_conn, ch_client, redis_client) -> Optional[str]:
    """
    Check dedup window — if an open incident for same rule+site+ip exists within
    dedup_window_seconds, update its stats. Otherwise open a new incident.
    Returns incident UUID or None if nothing was done.
    """
    dedup_cutoff = datetime.now(timezone.utc) - timedelta(
        seconds=candidate.rule.dedup_window_seconds
    )

    with pg_conn.cursor() as cur:
        # Check for existing open incident within dedup window
        cur.execute("""
            SELECT id, event_count FROM incidents
            WHERE site_id = %s
              AND attack_type = %s::attack_type
              AND status NOT IN ('RESOLVED','FALSE_POSITIVE')
              AND (source_ip = %s OR source_ip IS NULL)
              AND last_seen >= %s
            ORDER BY opened_at DESC
            LIMIT 1
        """, (
            candidate.site_id,
            candidate.attack_type,
            str(candidate.source_ip) if candidate.source_ip else None,
            dedup_cutoff,
        ))
        existing = cur.fetchone()

        if existing:
            # Update existing incident (ongoing attack — just bump stats)
            cur.execute("""
                UPDATE incidents
                SET event_count = event_count + %s,
                    last_seen   = NOW()
                WHERE id = %s
            """, (candidate.event_count, existing["id"]))
            pg_conn.commit()
            log.info("Updated incident %s (+%d events)", existing["id"], candidate.event_count)
            return str(existing["id"])
        else:
            # Create new incident
            cur.execute("""
                INSERT INTO incidents (
                    site_id, attack_type, severity, status,
                    source_ip, source_country, event_count,
                    endpoints_targeted, ch_query_filter
                ) VALUES (
                    %s, %s::attack_type, %s::incident_severity, 'OPEN',
                    %s, %s, %s, %s, %s
                ) RETURNING id
            """, (
                candidate.site_id,
                candidate.attack_type,
                candidate.severity,
                str(candidate.source_ip) if candidate.source_ip else None,
                candidate.source_country,
                candidate.event_count,
                candidate.endpoints_targeted,
                json.dumps(candidate.ch_query_filter),
            ))
            incident_id = str(cur.fetchone()["id"])

            # --- SOAR-lite: calculate confidence score ---
            confidence = 50  # base
            if candidate.severity == "CRITICAL": confidence = min(100, confidence + 35)
            elif candidate.severity == "HIGH":   confidence = min(100, confidence + 20)
            if candidate.event_count >= 50:      confidence = min(100, confidence + 15)
            elif candidate.event_count >= 20:    confidence = min(100, confidence + 10)

            # --- Phase 3 ML Boost (Safe Integration) ---
            # Max 20% boost if IP is flagged as an outlier in ML cache
            if candidate.source_ip and redis_client:
                try:
                    score_str = redis_client.get(f"aegisai:ml_score:{candidate.source_ip}")
                    if score_str:
                        a_score = float(score_str)
                        # score is positive where higher = more anomalous.
                        ml_boost = min(20, max(5, int(a_score * 20)))
                        confidence = min(100, confidence + ml_boost)
                        log.info(f"[Phase 3] Applied ML confidence boost for {candidate.source_ip}: +{ml_boost}% (from cache)")
                except Exception as e:
                    log.error(f"Failed to fetch ML reputation for {candidate.source_ip}: {e}")

            # Update incident with confidence score
            auto_block = bool(confidence >= 75 and candidate.source_ip)
            block_ttl  = 3600 if candidate.severity == "HIGH" else 86400  # 1h or 24h
            cur.execute("""
                UPDATE incidents SET
                    confidence_score = %s,
                    auto_blocked = %s,
                    block_ttl_seconds = %s
                WHERE id = %s
            """, (confidence, auto_block, block_ttl if auto_block else None, incident_id))

            # ---------------------------------------------------------------
            # PHASE 4: Active Edge Enforcement
            # If confidence >= 75 and we have a source IP, push to blocklist.
            # This feeds the blocklist_sync worker which propagates to Redis/Nginx.
            # ---------------------------------------------------------------
            if auto_block and candidate.source_ip:
                try:
                    cur.execute("""
                        INSERT INTO ip_blocklist (ip, incident_id, reason, source, blocked_by, expires_at, is_active)
                        VALUES (%s::inet, %s::uuid, %s, 'auto', 'correlation_engine', NOW() + (%s * INTERVAL '1 second'), TRUE)
                        ON CONFLICT (ip) DO UPDATE SET
                            is_active  = TRUE,
                            expires_at = NOW() + (EXCLUDED.expires_at - NOW()),
                            incident_id = EXCLUDED.incident_id
                    """, (
                        str(candidate.source_ip),
                        incident_id,
                        f"Auto-blocked: {candidate.attack_type} | confidence={confidence}",
                        block_ttl,
                    ))
                    log.warning(
                        "🚫 AUTO-BLOCK | ip=%s ttl=%ds incident=%s",
                        candidate.source_ip, block_ttl, incident_id
                    )
                    # Also push directly to Redis for zero-latency enforcement
                    if redis_client:
                        try:
                            redis_client.set(
                                f"aegisai:blocklist:{candidate.source_ip}",
                                "1", ex=block_ttl
                            )
                            log.info("⚡ Redis blocklist updated: %s (TTL=%ds)", candidate.source_ip, block_ttl)
                        except Exception as re:
                            log.error("Redis blocklist push failed: %s", re)
                except Exception as be:
                    log.error("ip_blocklist insert failed: %s", be)

            # Record to timeline
            cur.execute("""
                INSERT INTO incident_timeline (incident_id, action, to_status, actor, detail)
                VALUES (%s, 'opened', 'OPEN', 'system', %s)
            """, (incident_id, f"Auto-detected by rule: {candidate.rule_name} | confidence={confidence}"))

            pg_conn.commit()
            log.warning(
                "NEW INCIDENT %s | site=%s type=%s severity=%s ip=%s events=%d confidence=%d auto_block=%s",
                incident_id, candidate.site_id, candidate.attack_type,
                candidate.severity, candidate.source_ip, candidate.event_count, confidence, auto_block
            )
            return incident_id


# ---------------------------------------------------------------------------
# Notifiers
# ---------------------------------------------------------------------------
def notify_slack(incident_id: str, candidate: IncidentCandidate):
    if not SLACK_WEBHOOK:
        return
    severity_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(
        candidate.severity, "⚪"
    )
    payload = {
        "text": f"{severity_emoji} *New AegisAI-X Incident* `{incident_id[:8]}`",
        "attachments": [{
            "color": {"CRITICAL": "danger", "HIGH": "warning"}.get(candidate.severity, "good"),
            "fields": [
                {"title": "Site",       "value": candidate.site_id,     "short": True},
                {"title": "Type",       "value": candidate.attack_type,  "short": True},
                {"title": "Severity",   "value": candidate.severity,     "short": True},
                {"title": "Source IP",  "value": candidate.source_ip or "Multiple", "short": True},
                {"title": "Events",     "value": str(candidate.event_count), "short": True},
                {"title": "Rule",       "value": candidate.rule_name,    "short": True},
            ],
            "footer": "AegisAI-X Correlation Engine",
            "ts": int(datetime.now().timestamp()),
        }]
    }
    try:
        requests.post(SLACK_WEBHOOK, json=payload, timeout=5)
    except Exception as e:
        log.error("Slack notification failed: %s", e)


def notify_email(incident_id: str, candidate: IncidentCandidate):
    if not all([SMTP_HOST, ALERT_EMAIL]):
        return
    body = f"""
AegisAI-X Security Incident Alert

Incident ID : {incident_id}
Site        : {candidate.site_id}
Type        : {candidate.attack_type}
Severity    : {candidate.severity}
Source IP   : {candidate.source_ip or 'Multiple'}
Event Count : {candidate.event_count}
Rule        : {candidate.rule_name}
Time        : {datetime.now(timezone.utc).isoformat()}

Log in to the AegisAI-X SOC Dashboard to investigate.
    """.strip()
    msg = MIMEText(body)
    msg["Subject"] = f"[AegisAI-X] {candidate.severity} Incident — {candidate.site_id}"
    msg["From"]    = SMTP_USER
    msg["To"]      = ALERT_EMAIL
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
            s.starttls()
            s.login(SMTP_USER, SMTP_PASS)
            s.sendmail(SMTP_USER, [ALERT_EMAIL], msg.as_string())
    except Exception as e:
        log.error("Email notification failed: %s", e)


# ---------------------------------------------------------------------------
# Main poll loop
# ---------------------------------------------------------------------------
def run():
    log.info("AegisAI-X Correlation Engine starting (poll every %ds)...", POLL_INTERVAL)
    log.info("Prometheus metrics exposed on port %d", METRICS_PORT)
    start_http_server(METRICS_PORT)   # expose /metrics for Prometheus scraping
    WORKER_UP.set(1)

    pg = get_pg()
    ch = get_ch()
    try:
        redis_conn = get_redis()
    except Exception as e:
        log.error(f"Failed to connect to Redis: {e}")
        redis_conn = None

    while True:
        loop_start = time.time()
        since = datetime.now(timezone.utc) - timedelta(seconds=POLL_INTERVAL * 2)

        try:
            rules = load_rules(pg)
            total_new = 0

            with POLL_DURATION.time():   # measure full cycle duration
                for rule in rules:
                    cond      = rule.conditions
                    metric    = cond.get("metric") or ("rule_tag" if cond.get("rule_tag") else None)
                    evaluator = EVALUATORS.get(metric)
                    if not evaluator:
                        log.warning("No evaluator for rule '%s' metric '%s'", rule.name, metric)
                        continue

                    RULES_EVALUATED.labels(rule_name=rule.name).inc()

                    try:
                        candidates = evaluator(rule, ch, since)
                    except Exception as e:
                        log.error("Evaluator failed for rule '%s': %s", rule.name, e)
                        continue

                    for candidate in candidates:
                        incident_id = create_or_update_incident(candidate, pg, ch, redis_conn)
                        if incident_id:
                            total_new += 1
                            INCIDENTS_CREATED.labels(
                                severity=candidate.severity,
                                attack_type=candidate.attack_type
                            ).inc()
                            if candidate.severity in ("CRITICAL", "HIGH"):
                                notify_slack(incident_id, candidate)
                                notify_email(incident_id, candidate)
                        else:
                            INCIDENTS_UPDATED.inc()

            # Heartbeat — updated every successful cycle
            # Prometheus alert fires if this stops updating
            LAST_POLL_TIMESTAMP.set(time.time())
            log.info("Correlation cycle complete | incidents: %d", total_new)

        except psycopg2.OperationalError:
            log.error("PostgreSQL connection lost. Reconnecting...")
            pg = get_pg()
        except Exception as e:
            log.exception("Unexpected error in correlation loop: %s", e)

        # Sleep for remainder of poll interval
        elapsed = time.time() - loop_start
        time.sleep(max(0, POLL_INTERVAL - elapsed))


if __name__ == "__main__":
    run()
