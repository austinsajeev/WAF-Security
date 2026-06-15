"""
AegisAI-X — FastAPI Backend
=============================
Serves the SOC Dashboard with:
  - JWT + MFA authentication (RBAC: admin / analyst / viewer)
  - Incident lifecycle CRUD APIs
  - ClickHouse analytics queries (live dashboard data)
  - IP blocklist management
  - Alert rules management

Run: uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
"""


import os, json, logging, redis
from datetime    import datetime, timezone, timedelta
from typing      import Optional, List
from functools   import wraps

import clickhouse_connect
import psycopg2, psycopg2.extras
import pyotp, bcrypt
from fastapi            import FastAPI, Depends, HTTPException, status, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security   import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses  import JSONResponse
from jose               import jwt, JWTError
from pydantic           import BaseModel, EmailStr
from slowapi            import Limiter, _rate_limit_exceeded_handler
from slowapi.util       import get_remote_address
from slowapi.errors     import RateLimitExceeded

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
REDIS_URL      = os.environ.get("REDIS_URL", "redis://redis:6379/0")
JWT_SECRET     = os.environ["JWT_SECRET"]
JWT_ALGORITHM  = "HS256"
JWT_EXPIRE_MIN = int(os.environ.get("JWT_EXPIRE_MIN", "60"))

CH_HOST     = os.environ.get("CH_HOST", "clickhouse")
CH_USER     = os.environ.get("CH_USER", "aegisai")
CH_PASSWORD = os.environ.get("CH_PASSWORD", "aegisai_ch_pass")
CH_DB       = os.environ.get("CH_DB", "aegisai_db")
PG_DSN      = os.environ.get(
    "PG_DSN",
    "postgresql://aegisai:aegisai_pg_pass@postgres/aegisai_db"
)

log = logging.getLogger("aegisai.api")

# ---------------------------------------------------------------------------
# Rate Limiter (slowapi — Redis-backed for distributed deployments)
# ---------------------------------------------------------------------------
redis_client = redis.from_url(REDIS_URL, decode_responses=True)
limiter      = Limiter(key_func=get_remote_address, storage_uri=REDIS_URL)

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(
    title="AegisAI-X SOC API",
    version="2.0.0",
    description="Security Operations Center API for AegisAI-X platform",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://soc.internal", "http://localhost:3000"],
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token")


# ---------------------------------------------------------------------------
# DB Helpers
# ---------------------------------------------------------------------------
def get_pg():
    conn = psycopg2.connect(PG_DSN, cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        yield conn
    finally:
        conn.close()

# Bug 3 fix: module-level singleton — one connection, reused across all requests.
# Also resets on failure so the next request retries instead of caching a broken state.
_ch_client = None

def get_ch():
    global _ch_client
    if _ch_client is None:
        try:
            _ch_client = clickhouse_connect.get_client(
                host=CH_HOST, port=8123, username=CH_USER,
                password=CH_PASSWORD, database=CH_DB, secure=False
            )
        except Exception as e:
            _ch_client = None  # reset so next request retries
            raise RuntimeError(f"ClickHouse connection failed: {e}") from e
    return _ch_client


# ---------------------------------------------------------------------------
# Auth & RBAC
# ---------------------------------------------------------------------------
def create_token(user_id: str, role: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE_MIN)
    return jwt.encode(
        {"sub": user_id, "role": role, "exp": expire},
        JWT_SECRET, algorithm=JWT_ALGORITHM
    )


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    pg=Depends(get_pg)
) -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id: str = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Token expired or invalid")

    # Check token revocation list (logout support)
    if redis_client.get(f"aegisai:revoked_token:{token[:32]}"):
        raise HTTPException(status_code=401, detail="Token has been revoked")

    with pg.cursor() as cur:
        cur.execute("SELECT * FROM users WHERE id=%s AND is_active=TRUE", (user_id,))
        user = cur.fetchone()
    if not user:
        raise HTTPException(status_code=401, detail="User not found or disabled")
    return dict(user)


def require_role(*roles: str):
    """Decorator-style role guard. Usage: Depends(require_role('admin', 'analyst'))"""
    async def checker(user: dict = Depends(get_current_user)):
        if user["role"] not in roles:
            raise HTTPException(status_code=403, detail=f"Role '{user['role']}' not permitted")
        return user
    return checker


def site_access_guard(user: dict, site_id: str):
    """Check user has access to the requested site (admin = all access)."""
    if user["role"] == "admin":
        return
    if site_id not in (user["site_access"] or []):
        raise HTTPException(status_code=403, detail="No access to this site")


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------
class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    requires_mfa: bool = False
    mfa_token: Optional[str] = None   # short-lived token to complete MFA step

class MFAVerifyRequest(BaseModel):
    mfa_token: str
    totp_code: str

class IncidentUpdateRequest(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    notes: Optional[str] = None
    resolution: Optional[str] = None

class BlockIPRequest(BaseModel):
    ip: str
    reason: str
    incident_id: Optional[str] = None
    expires_hours: Optional[int] = None   # None = permanent


# ---------------------------------------------------------------------------
# Auth Endpoints
# ---------------------------------------------------------------------------
@app.post("/api/auth/token", response_model=TokenResponse, tags=["Auth"])
@limiter.limit("5/minute")   # Max 5 login attempts per IP per minute
async def login(request: Request, form: OAuth2PasswordRequestForm = Depends(), pg=Depends(get_pg)):
    with pg.cursor() as cur:
        cur.execute("SELECT * FROM users WHERE username=%s AND is_active=TRUE", (form.username,))
        user = cur.fetchone()

    if not user or not bcrypt.checkpw(form.password.encode(), user["password_hash"].encode()):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # If MFA enabled, return a short-lived MFA token instead of full JWT
    if user["mfa_enabled"]:
        mfa_token = create_token(str(user["id"]), "mfa_pending")
        return TokenResponse(requires_mfa=True, mfa_token=mfa_token, access_token="")

    # No MFA — return full access token
    token = create_token(str(user["id"]), user["role"])
    with pg.cursor() as cur:
        cur.execute("UPDATE users SET last_login=NOW() WHERE id=%s", (user["id"],))
    pg.commit()
    return TokenResponse(access_token=token)


@app.post("/api/auth/mfa/verify", response_model=TokenResponse, tags=["Auth"])
@limiter.limit("3/minute")   # Stricter — 3 TOTP attempts per minute
async def verify_mfa(request: Request, req: MFAVerifyRequest, pg=Depends(get_pg)):
    """Second step of MFA login — verify TOTP code."""
    try:
        payload = jwt.decode(req.mfa_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get("role") != "mfa_pending":
            raise HTTPException(status_code=400, detail="Invalid MFA token")
        user_id = payload["sub"]
    except JWTError:
        raise HTTPException(status_code=401, detail="MFA token expired")

    with pg.cursor() as cur:
        cur.execute("SELECT * FROM users WHERE id=%s", (user_id,))
        user = cur.fetchone()

    totp = pyotp.TOTP(user["mfa_secret"])
    if not totp.verify(req.totp_code, valid_window=1):
        raise HTTPException(status_code=401, detail="Invalid TOTP code")

    token = create_token(user_id, user["role"])
    with pg.cursor() as cur:
        cur.execute("UPDATE users SET last_login=NOW() WHERE id=%s", (user_id,))
    pg.commit()
    return TokenResponse(access_token=token)


@app.post("/api/auth/logout", tags=["Auth"])
async def logout(
    request: Request,
    token: str = Depends(oauth2_scheme)
):
    """Revoke current token by adding it to Redis revocation list."""
    redis_client.set(
        f"aegisai:revoked_token:{token[:32]}",
        "1",
        ex=JWT_EXPIRE_MIN * 60   # expires same time as token would
    )
    return {"success": True, "message": "Logged out"}


# ---------------------------------------------------------------------------
# Incident Endpoints
# ---------------------------------------------------------------------------
@app.get("/api/incidents", tags=["Incidents"])
async def list_incidents(
    site_id:   Optional[str] = None,
    status:    Optional[str] = None,
    severity:  Optional[str] = None,
    page:      int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    user  = Depends(require_role("admin", "analyst", "viewer")),
    pg    = Depends(get_pg),
):
    """List incidents with optional filters. Respects site-level RBAC."""
    offset = (page - 1) * page_size
    filters = ["TRUE"]
    params  = []

    # Enforce site access
    if user["role"] != "admin" and user["site_access"]:
        filters.append("site_id = ANY(%s)")
        params.append(user["site_access"])

    if site_id:
        site_access_guard(user, site_id)
        filters.append("site_id = %s")
        params.append(site_id)
    if status:
        filters.append("status = %s::incident_status")
        params.append(status)
    if severity:
        filters.append("severity = %s::incident_severity")
        params.append(severity)

    where = " AND ".join(filters)
    with pg.cursor() as cur:
        cur.execute(
            f"SELECT COUNT(*) AS total FROM incidents WHERE {where}", params
        )
        total = cur.fetchone()["total"]

        cur.execute(
            f"""SELECT id, site_id, attack_type, severity, status,
                       source_ip, source_country, event_count,
                       endpoints_targeted, first_seen, last_seen,
                       opened_at, acknowledged_at, resolved_at, assigned_to
                FROM incidents WHERE {where}
                ORDER BY opened_at DESC
                LIMIT %s OFFSET %s""",
            params + [page_size, offset]
        )
        rows = cur.fetchall()

    return {
        "total": total, "page": page, "page_size": page_size,
        "incidents": [dict(r) for r in rows]
    }


@app.get("/api/incidents/{incident_id}", tags=["Incidents"])
async def get_incident(
    incident_id: str,
    user = Depends(require_role("admin", "analyst", "viewer")),
    pg   = Depends(get_pg),
):
    with pg.cursor() as cur:
        cur.execute("SELECT * FROM incidents WHERE id=%s", (incident_id,))
        inc = cur.fetchone()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    site_access_guard(user, inc["site_id"])

    # Also fetch timeline
    with pg.cursor() as cur:
        cur.execute(
            "SELECT * FROM incident_timeline WHERE incident_id=%s ORDER BY created_at",
            (incident_id,)
        )
        timeline = cur.fetchall()

    return {"incident": dict(inc), "timeline": [dict(t) for t in timeline]}


@app.patch("/api/incidents/{incident_id}", tags=["Incidents"])
async def update_incident(
    incident_id: str,
    req: IncidentUpdateRequest,
    user = Depends(require_role("admin", "analyst")),
    pg   = Depends(get_pg),
):
    with pg.cursor() as cur:
        cur.execute("SELECT * FROM incidents WHERE id=%s", (incident_id,))
        inc = cur.fetchone()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    site_access_guard(user, inc["site_id"])

    updates, params = [], []

    if req.status:
        # Record status transition in timeline
        with pg.cursor() as cur:
            cur.execute("""
                INSERT INTO incident_timeline
                    (incident_id, action, from_status, to_status, actor, detail)
                VALUES (%s, 'status_changed', %s::incident_status, %s::incident_status, %s, %s)
            """, (incident_id, inc["status"], req.status, user["username"],
                  f"Status changed to {req.status}"))
        if req.status == "ACKNOWLEDGED":
            updates.append("acknowledged_at = NOW()")
        elif req.status == "RESOLVED":
            updates.append("resolved_at = NOW()")
        updates.append("status = %s::incident_status")
        params.append(req.status)

    if req.assigned_to:
        updates.append("assigned_to = %s")
        params.append(req.assigned_to)
    if req.notes is not None:
        updates.append("notes = %s")
        params.append(req.notes)
    if req.resolution is not None:
        updates.append("resolution = %s")
        params.append(req.resolution)

    if updates:
        params.append(incident_id)
        with pg.cursor() as cur:
            cur.execute(
                f"UPDATE incidents SET {', '.join(updates)} WHERE id = %s",
                params
            )
        pg.commit()

    return {"success": True, "incident_id": incident_id}


# ---------------------------------------------------------------------------
# Dashboard Analytics (ClickHouse-backed)
# ---------------------------------------------------------------------------
@app.get("/api/dashboard/overview", tags=["Dashboard"])
async def dashboard_overview(
    site_id: Optional[str] = None,
    hours:   int = Query(24, ge=1, le=168),
    user = Depends(require_role("admin", "analyst", "viewer")),
):
    """Returns top-level attack stats for SOC overview panel."""
    ch = get_ch()
    site_filter = f"AND site_id = '{site_id}'" if site_id else ""

    # Requests + WAF blocks overview
    r = ch.query(f"""
        SELECT
            count()                                   AS total_requests,
            countIf(waf_score > 0)                    AS waf_hits,
            countIf(waf_action = 'block')             AS blocked,
            countIf(status_code >= 500)               AS server_errors,
            uniq(remote_addr)                         AS unique_ips
        FROM request_logs
        WHERE timestamp >= now() - INTERVAL {hours} HOUR
        {site_filter}
    """)
    stats = dict(zip(r.column_names, r.first_row or [0]*5))

    # Top attack types
    ar = ch.query(f"""
        SELECT rule_tag, count() AS cnt
        FROM waf_events
        WHERE timestamp >= now() - INTERVAL {hours} HOUR
        {site_filter}
        GROUP BY rule_tag ORDER BY cnt DESC LIMIT 5
    """)
    stats["top_attack_types"] = ar.named_results()

    # Top attacking IPs
    ir = ch.query(f"""
        SELECT remote_addr, country_code, count() AS hits
        FROM waf_events
        WHERE timestamp >= now() - INTERVAL {hours} HOUR
        {site_filter}
        GROUP BY remote_addr, country_code
        ORDER BY hits DESC LIMIT 10
    """)
    stats["top_attacking_ips"] = ir.named_results()

    return stats


@app.get("/api/dashboard/timeline", tags=["Dashboard"])
async def attack_timeline(
    site_id:  Optional[str] = None,
    hours:    int = Query(24, ge=1, le=168),
    interval: str = Query("1 HOUR", description="ClickHouse interval: '5 MINUTE', '1 HOUR', '1 DAY'"),
    user = Depends(require_role("admin", "analyst", "viewer")),
):
    """Time-series data for attack trend chart."""
    ch = get_ch()
    site_filter = f"AND site_id = '{site_id}'" if site_id else ""
    r = ch.query(f"""
        SELECT
            toStartOfInterval(timestamp, INTERVAL {interval}) AS bucket,
            count()                                            AS events,
            countIf(severity = 'CRITICAL')                    AS critical,
            countIf(severity = 'ERROR')                       AS high
        FROM waf_events
        WHERE timestamp >= now() - INTERVAL {hours} HOUR
        {site_filter}
        GROUP BY bucket ORDER BY bucket
    """)
    return {"timeline": r.named_results()}


@app.get("/api/dashboard/sites", tags=["Dashboard"])
async def site_overview(
    user = Depends(require_role("admin", "analyst", "viewer")),
    pg   = Depends(get_pg),
):
    """Per-site incident summary for the sites panel."""
    ch = get_ch()
    r = ch.query("""
        SELECT
            site_id,
            count()                          AS total_events,
            countIf(severity IN ('CRITICAL','ERROR')) AS high_events,
            max(timestamp)                   AS last_event
        FROM waf_events
        WHERE timestamp >= now() - INTERVAL 24 HOUR
        GROUP BY site_id ORDER BY high_events DESC
    """)
    return {"sites": r.named_results()}


# ---------------------------------------------------------------------------
# IP Blocklist Endpoints
# ---------------------------------------------------------------------------
@app.post("/api/blocklist", tags=["Blocklist"])
async def block_ip(
    req: BlockIPRequest,
    user = Depends(require_role("admin", "analyst")),
    pg   = Depends(get_pg),
):
    expires = (
        datetime.now(timezone.utc) + timedelta(hours=req.expires_hours)
        if req.expires_hours else None
    )
    with pg.cursor() as cur:
        cur.execute("""
            INSERT INTO ip_blocklist (ip, reason, source, incident_id, blocked_by, expires_at)
            VALUES (%s, %s, 'manual', %s, %s, %s)
            ON CONFLICT (ip) DO UPDATE
                SET reason=EXCLUDED.reason, blocked_by=EXCLUDED.blocked_by,
                    blocked_at=NOW(), expires_at=EXCLUDED.expires_at, is_active=TRUE
        """, (req.ip, req.reason, req.incident_id, user["username"], expires))
    pg.commit()
    return {"success": True, "ip": req.ip, "expires_at": expires}


@app.get("/api/blocklist", tags=["Blocklist"])
async def get_blocklist(
    active_only: bool = True,
    user = Depends(require_role("admin", "analyst", "viewer")),
    pg   = Depends(get_pg),
):
    with pg.cursor() as cur:
        if active_only:
            cur.execute(
                "SELECT * FROM ip_blocklist WHERE is_active=TRUE ORDER BY blocked_at DESC"
            )
        else:
            cur.execute("SELECT * FROM ip_blocklist ORDER BY blocked_at DESC LIMIT 500")
        rows = cur.fetchall()
    return {"blocklist": [dict(r) for r in rows]}


# ---------------------------------------------------------------------------
# Health Check
# ---------------------------------------------------------------------------
@app.get("/health", tags=["System"])
async def health():
    return {"status": "ok", "service": "aegisai-x-api", "ts": datetime.now(timezone.utc).isoformat()}


# ---------------------------------------------------------------------------
# ML Status Endpoint (Day 3) — Phase 3 Anomaly Detection Health
# ---------------------------------------------------------------------------
@app.get("/api/ml/status", tags=["ML"])
async def ml_status():
    """
    Returns the live state of the Isolation Forest anomaly detection pipeline.

    Combines data from:
      - Redis  : aegisai:ml_score:<ip>  (cached outlier scores, TTL 1h)
      - ClickHouse: ip_reputation table (last training run results)
      - ClickHouse: ip_features table   (training dataset size)

    No auth required — safe to poll from the dashboard without a JWT.
    """
    now_utc = datetime.now(timezone.utc).isoformat()
    try:
        ch = get_ch()
    except Exception as e:
        log.error("ml_status: ClickHouse unavailable: %s", e)
        return {
            "status": "DEGRADED",
            "detail": f"ClickHouse unavailable: {e}",
            "phase3_boost_active": False,
            "model": {
                "last_trained_at": None, "ips_scored": 0, "outliers_detected": 0,
                "avg_anomaly_score": 0.0, "max_anomaly_score": 0.0,
                "contamination_rate": 0.0, "retrain_interval_minutes": 15,
                "algorithm": "IsolationForest",
                "features": ["request_rate", "error_rate", "unique_endpoints", "attack_pct"],
                "contamination": 0.03,
            },
            "training_dataset": {"ip_feature_vectors": 0, "ips_with_attacks": 0, "avg_attack_pct": 0.0},
            "redis_cache": {"cached_outlier_count": 0, "top_outliers": []},
            "evaluated_at": now_utc,
        }

    # helper: sanitize floats — ClickHouse returns NaN/Infinity on empty tables
    import math
    def safe_float(v):
        f = float(v or 0)
        return 0.0 if (math.isnan(f) or math.isinf(f)) else f

    # ── 1. Redis: cached outlier IPs (set by ml_worker after each training run)
    redis_outlier_keys = redis_client.keys("aegisai:ml_score:*")
    cached_outliers = []
    for key in redis_outlier_keys:
        ip = key.replace("aegisai:ml_score:", "")
        score = redis_client.get(key)
        ttl   = redis_client.ttl(key)
        if score is not None:
            cached_outliers.append({
                "ip":            ip,
                "anomaly_score": round(safe_float(score), 4),
                "cache_ttl_sec": ttl,
            })
    cached_outliers.sort(key=lambda x: x["anomaly_score"], reverse=True)

    # ── 2. ClickHouse: last training run stats (ip_reputation, last 2h)
    model_stats = {
        "last_trained_at":    None,
        "ips_scored":         0,
        "outliers_detected":  0,
        "avg_anomaly_score":  0.0,
        "max_anomaly_score":  0.0,
        "contamination_rate": 0.0,
    }
    try:
        r = ch.query("""
            SELECT
                max(computed_at)            AS last_trained_at,
                count()                     AS ips_scored,
                countIf(is_outlier = 1)     AS outliers_detected,
                round(avg(anomaly_score),4) AS avg_score,
                round(max(anomaly_score),4) AS max_score
            FROM aegisai_db.ip_reputation
            WHERE computed_at >= now() - INTERVAL 2 HOUR
        """)
        if r.result_rows and r.result_rows[0][0]:
            row = r.result_rows[0]
            ips_scored       = int(row[1]) if row[1] else 0
            outliers         = int(row[2]) if row[2] else 0
            model_stats = {
                "last_trained_at":    row[0].isoformat() if row[0] else None,
                "ips_scored":         ips_scored,
                "outliers_detected":  outliers,
                "avg_anomaly_score":  safe_float(row[3]),
                "max_anomaly_score":  safe_float(row[4]),
                "contamination_rate": round(outliers / max(ips_scored, 1) * 100, 2),
            }
    except Exception as e:
        log.warning("ml_status: ip_reputation query failed: %s", e)

    # ── 3. ClickHouse: training dataset size (ip_features, last 48h)
    training_data = {"ip_feature_vectors": 0, "ips_with_attacks": 0, "avg_attack_pct": 0.0}
    try:
        r2 = ch.query("""
            SELECT
                count()                         AS total_vectors,
                countIf(attack_pct > 0)         AS ips_with_attacks,
                round(avg(attack_pct) * 100, 1) AS avg_attack_pct
            FROM aegisai_db.ip_features
            WHERE computed_at >= now() - INTERVAL 48 HOUR
        """)
        if r2.result_rows:
            row2 = r2.result_rows[0]
            training_data = {
                "ip_feature_vectors": int(row2[0] or 0),
                "ips_with_attacks":   int(row2[1] or 0),
                "avg_attack_pct":     safe_float(row2[2]),
            }
    except Exception as e:
        log.warning("ml_status: ip_features query failed: %s", e)

    # ── 4. Derive model health status
    model_trained   = model_stats["last_trained_at"] is not None
    redis_active    = len(cached_outliers) > 0
    phase3_boost_on = model_trained and redis_active

    if not model_trained:
        health_status = "NOT_TRAINED"
        health_detail = "No training run found in last 2 hours. Check ml_worker logs."
    elif training_data["ip_feature_vectors"] < 50:
        health_status = "WARMING_UP"
        health_detail = f"Only {training_data['ip_feature_vectors']} IP vectors. Need ≥50 to train."
    elif model_stats["ips_scored"] > 0:
        health_status = "HEALTHY"
        health_detail = (
            f"Model trained on {model_stats['ips_scored']} IPs. "
            f"{model_stats['outliers_detected']} outliers cached in Redis."
        )
    else:
        health_status = "DEGRADED"
        health_detail = "Model exists but no IPs were scored in last run."

    return {
        "status":          health_status,
        "detail":          health_detail,
        "phase3_boost_active": phase3_boost_on,
        "model": {
            **model_stats,
            "retrain_interval_minutes": 15,
            "algorithm":               "IsolationForest",
            "features": ["request_rate", "error_rate", "unique_endpoints", "attack_pct"],
            "contamination": 0.03,
        },
        "training_dataset": training_data,
        "redis_cache": {
            "cached_outlier_count": len(cached_outliers),
            "top_outliers":         cached_outliers[:10],
        },
        "evaluated_at": now_utc,
    }


# ---------------------------------------------------------------------------
# Analytics: Dead Letter Queue
# ---------------------------------------------------------------------------
@app.get("/api/analytics/dead-letters/summary", tags=["Analytics"])
async def dead_letter_summary(
    user = Depends(require_role("admin", "analyst")),
):
    """
    Returns dead letter counts grouped by rejection reason (last 24h)
    plus an hourly event count trend for the last 24 buckets.
    """
    ch = get_ch()
    try:
        # Count by reason
        by_reason_result = ch.query("""
            SELECT
                reject_reason,
                count() AS event_count
            FROM aegisai_db.dead_letter_queue
            WHERE rejected_at >= now() - INTERVAL 24 HOUR
            GROUP BY reject_reason
            ORDER BY event_count DESC
        """)
        by_reason = [
            {"reason": r["reject_reason"], "count": r["event_count"]}
            for r in by_reason_result.named_results()
        ]

        # Hourly trend
        hourly_result = ch.query("""
            SELECT
                toStartOfHour(rejected_at) AS hour,
                count() AS event_count
            FROM aegisai_db.dead_letter_queue
            WHERE rejected_at >= now() - INTERVAL 24 HOUR
            GROUP BY hour
            ORDER BY hour ASC
        """)
        hourly = [
            {"hour": r["hour"].isoformat(), "count": r["event_count"]}
            for r in hourly_result.named_results()
        ]

        total = sum(r["count"] for r in by_reason)
        return {
            "period_hours": 24,
            "total_dead_letters": total,
            "by_reason": by_reason,
            "hourly_trend": hourly,
        }
    except Exception as e:
        log.error("Dead letter summary query failed: %s", e)
        raise HTTPException(status_code=500, detail="Failed to query dead letter data")


# ---------------------------------------------------------------------------
# System: Phase 3 Readiness Gate
# ---------------------------------------------------------------------------
@app.get("/api/system/phase3-readiness", tags=["System"])
async def phase3_readiness(
    user = Depends(require_role("admin", "analyst")),
    pg   = Depends(get_pg),
):
    """
    Enhanced Phase 3 (AI/ML) readiness assessment.
    Now validates data quality, diversity, and baseline volume.
    """
    ch = get_ch()
    criteria = {}
    score = 0

    # 1. Ingestion Volume & Quality
    try:
        r = ch.query("""
            SELECT 
                count() AS total,
                uniqExact(remote_addr) AS unique_ips,
                uniqExact(label) AS label_count
            FROM aegisai_db.request_logs
            WHERE timestamp >= now() - INTERVAL 24 HOUR
        """)
        row = list(r.named_results())[0]
        total, ips, labels = row["total"], row["unique_ips"], row["label_count"]
        
        # Stricter thresholds for high-quality baseline
        passed = (total >= 200 and ips >= 10 and labels >= 2)
        criteria["baseline_volume"] = {
            "passed": passed,
            "value": f"logs={total}, unique_ips={ips}, labels={labels}",
            "threshold": ">=200 logs, >=10 IPs, >=2 classes",
            "weight": 30,
        }
        if passed: score += 30
    except Exception as e:
        criteria["baseline_volume"] = {"passed": False, "error": str(e), "weight": 30}

    # 2. Statistical Sanity (Non-synthetic checks)
    try:
        r = ch.query("""
            SELECT 
                varSamp(request_rate) AS rate_var,
                abs(skewSamp(request_rate)) AS rate_skew
            FROM aegisai_db.ip_features
            WHERE computed_at >= now() - INTERVAL 12 HOUR
        """)
        row = list(r.named_results())[0]
        var = row["rate_var"] or 0
        skew = row["rate_skew"] or 0
        
        # Real traffic shouldn't be constant (var > 0) and shouldn't be uniform (skew > 0)
        passed = (var > 0.0001 and skew > 0.01)
        criteria["distribution_sanity"] = {
            "passed": passed,
            "value": f"var={var:.4f}, skew={skew:.4f}",
            "threshold": "variance > 0.0001, skew > 0.01",
            "weight": 30,
        }
        if passed: score += 30
    except Exception as e:
        criteria["distribution_sanity"] = {"passed": False, "error": str(e), "weight": 30}

    # 3. Temporal Stability (Drift check)
    try:
        r = ch.query("""
            SELECT
                avgIf(request_rate, hour_bucket >= toStartOfHour(now()) - INTERVAL 1 HOUR
                                  AND hour_bucket < toStartOfHour(now())) AS prev_avg,
                avgIf(request_rate, hour_bucket >= toStartOfHour(now()))  AS curr_avg
            FROM aegisai_db.ip_features
            WHERE hour_bucket >= toStartOfHour(now()) - INTERVAL 2 HOUR
        """)
        row = list(r.named_results())[0]
        prev = float(row["prev_avg"] or 0)
        curr = float(row["curr_avg"] or 0)
        # Drift = how much the current hour deviates from the previous.
        # > 50% change = unstable baseline, not safe to train on.
        drift_pct = abs(curr - prev) / max(prev, 0.001) * 100
        passed = drift_pct < 50
        criteria["temporal_stability"] = {
            "passed": passed,
            "value": f"prev_avg={prev:.4f}, curr_avg={curr:.4f}, drift={drift_pct:.1f}%",
            "threshold": "Drift < 50% hourly",
            "weight": 20,
        }
        if passed:
            score += 20
    except Exception as e:
        criteria["temporal_stability"] = {"passed": False, "error": str(e), "weight": 20}

    # 4. Schema & Pipeline Health
    try:
        r = ch.query("SELECT count() FROM aegisai_db.ip_features")
        f_cnt = list(r.result_rows)[0][0]
        passed = f_cnt > 0
        criteria["pipeline_health"] = {
            "passed": passed,
            "value": f"feature_rows={f_cnt}",
            "threshold": ">0 rows in ip_features",
            "weight": 20,
        }
        if passed: score += 20
    except Exception:
        criteria["pipeline_health"] = {"passed": False, "weight": 20}

    ready = (score >= 80) and criteria["distribution_sanity"]["passed"]
    return {
        "ready": ready,
        "score": score,
        "max_score": 100,
        "status": "READY" if ready else "HARDENING",
        "workflow_step": "Phase 3 (ML Inference)" if ready else "Phase 2.5 (Data Collection)",
        "criteria": criteria,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Gateway Control Endpoints
# ---------------------------------------------------------------------------
import docker

class GatewayModeUpdate(BaseModel):
    mode: str  # "On" or "DetectionOnly"

@app.get("/api/gateway/mode", tags=["System"])
async def get_gateway_mode(user: dict = Depends(get_current_user)):
    """Get the current WAF rule engine mode."""
    mode = redis_client.get("aegisai:config:waf_mode")
    if not mode:
        # Default to On if not set in Redis (ModSecurity defaults to On)
        mode = "On"
    return {"mode": mode}

@app.post("/api/gateway/mode", tags=["System"])
async def set_gateway_mode(data: GatewayModeUpdate, user: dict = Depends(require_role("admin", "analyst"))):
    """Dynamically update the WAF mode in the gateway container."""
    if data.mode not in ["On", "DetectionOnly"]:
        raise HTTPException(status_code=400, detail="Invalid mode. Must be 'On' or 'DetectionOnly'")
    
    try:
        client = docker.from_env()
        container = client.containers.get('aegisai-gateway')
        
        # Replace SecRuleEngine in modsecurity.conf
        sed_cmd = f"sed -i 's/SecRuleEngine .*/SecRuleEngine {data.mode}/g' /etc/nginx/modsecurity.d/modsecurity.conf"
        exit_code, output = container.exec_run(sed_cmd)
        if exit_code != 0:
            raise Exception(f"Failed to update modsecurity.conf: {output.decode()}")
        
        # Reload Nginx gracefully
        exit_code, output = container.exec_run("nginx -s reload")
        if exit_code != 0:
            raise Exception(f"Failed to reload nginx: {output.decode()}")
            
        # Save state to Redis
        redis_client.set("aegisai:config:waf_mode", data.mode)
        
        return {"status": "success", "mode": data.mode, "message": f"WAF mode set to {data.mode} and Nginx reloaded"}
        
    except docker.errors.NotFound:
        raise HTTPException(status_code=500, detail="aegisai-gateway container not found. Ensure Docker socket is mounted.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

