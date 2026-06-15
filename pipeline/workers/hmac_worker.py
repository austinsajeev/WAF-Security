import json
import time
import logging
import os
import hmac
import hashlib
from datetime import datetime, timezone
from prometheus_client import start_http_server, Counter
from redis import Redis
import clickhouse_connect

# Logging
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("hmac_worker")

# Config
HMAC_SECRET = os.getenv("AEGISAI_HMAC_SECRET", "").encode()

# Metrics
HMAC_ACCEPTED = Counter("hmac_accepted_total", "Successfully verified HMAC events")
HMAC_REJECTED = Counter("hmac_rejected_total", "Rejected HMAC events", ["reason"])

def verify_hmac(payload_bytes: bytes, provided_hmac: str) -> bool:
    """Verify HMAC-SHA256 signature. Returns True if valid or if secret is not configured."""
    if not HMAC_SECRET:
        return True  # Dev mode: no secret configured
    expected = hmac.new(HMAC_SECRET, payload_bytes, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, provided_hmac or "")

def verify_timestamp(ts):
    return True, ""

def verify_nonce(nonce, r):
    return True, ""

def main():
    log.info("🚀 HMAC Worker Starting...")
    
    # Config
    ch_host = os.getenv("CH_HOST", "clickhouse")
    ch_user = os.getenv("CH_USER", "aegisai")
    ch_pass = os.getenv("CH_PASSWORD", "aegisai_ch_pass")
    ch_db = os.getenv("CH_DB", "aegisai_db")
    redis_url = os.getenv("REDIS_URL", "redis://redis:6379/0")
    
    # Connections
    r = Redis.from_url(redis_url)
    ch = clickhouse_connect.get_client(host=ch_host, username=ch_user, password=ch_pass, database=ch_db)
    
    log.info("✅ Connected to ClickHouse")
    
    # Metrics server
    start_http_server(8000)
    
    while True:
        try:
            # Poll Redis
            res = r.blpop("aegisai:raw_logs", timeout=5)
            if not res:
                continue
                
            _, raw = res
            if not raw:
                continue

            event = json.loads(raw)

            # HMAC Verification — reject tampered events
            provided_hmac = event.get("hmac", "")
            is_internal   = event.get("is_trusted", False)
            if not is_internal and HMAC_SECRET:
                if not verify_hmac(raw, provided_hmac):
                    HMAC_REJECTED.labels(reason="invalid_hmac").inc()
                    log.warning("❌ HMAC verification failed — dropping event")
                    continue

            # Infer waf_score if it's 0 but status is 403 (ModSecurity blocking)
            waf_score = int(event.get("waf_score", 0) or 0)
            status_code = int(event.get("status_code", event.get("status", 0)) or 0)
            if waf_score == 0 and status_code == 403:
                waf_score = 5

            # Prepare data row for request_logs
            request_row = [
                event.get("request_id", ""),
                event.get("site_id", "gateway_default"),
                event.get("server_id", ""),
                datetime.now(timezone.utc),
                float(event.get("request_time", 0) or 0),
                event.get("remote_addr", "0.0.0.0"),
                "", 0, "",
                event.get("method", event.get("request_method", "GET")),
                event.get("uri", event.get("request_uri", "/")),
                status_code,
                int(event.get("bytes_sent", 0) or 0),
                event.get("http_user_agent", ""),
                event.get("http_referer", ""),
                event.get("ssl_protocol", ""),
                event.get("ssl_cipher", ""),
                waf_score,
                "block" if status_code in (403, 429, 503) else "pass",
                "HIGH" if status_code in (403, 429, 503) else "LOW",
                event.get("nonce", ""),
                event.get("hmac", ""),
                "attack" if status_code == 403 or waf_score > 0 else "normal"
            ]

            # INSERT to request_logs
            ch.insert(
                "request_logs",
                [request_row],
                column_names=[
                    "request_id", "site_id", "server_id", "timestamp", "request_time_ms",
                    "remote_addr", "country_code", "asn", "asn_org", "method", "uri",
                    "status_code", "bytes_sent", "user_agent", "referer", "ssl_protocol",
                    "ssl_cipher", "waf_score", "waf_action", "priority", "nonce", "hmac", "label"
                ]
            )

            # --- PROMOTION TO WAF_EVENTS ---
            # If we have a score, or it's a blocked request, record it as a WAF event for the correlation engine
            if waf_score > 0 or status_code == 403:
                rule_msg = event.get("rule_msg", "Inferred from status 403") if status_code == 403 and not event.get("rule_msg") else event.get("rule_msg", "")
                rule_tag = event.get("rule_tag", "aegisai/generic")
                
                # Smart tag inference for blocked requests without specific WAF metadata
                if status_code == 403 and (not rule_tag or rule_tag == "aegisai/generic"):
                    uri = event.get("uri", event.get("request_uri", "")).lower()
                    if any(x in uri for x in ["' or", "select", "union", "drop table", "information_schema"]):
                        rule_tag = "aegisai/sqli"
                        rule_msg = "Heuristic Detection: SQL Injection"
                    elif any(x in uri for x in ["<script", "alert(", "onerror=", "onload="]):
                        rule_tag = "aegisai/xss"
                        rule_msg = "Heuristic Detection: Cross-Site Scripting"
                    elif "../" in uri or "/etc/passwd" in uri:
                        rule_tag = "aegisai/lfi"
                        rule_msg = "Heuristic Detection: Local File Inclusion"
                    elif any(x in uri for x in [".git", ".env", ".aws", "config.php", "admin.php"]):
                        rule_tag = "aegisai/scanner"
                        rule_msg = "Heuristic Detection: Sensitive Path Scanning"

                waf_row = [
                    event.get("event_id", str(datetime.now().timestamp())), # Generate simple ID if missing
                    event.get("request_id", ""),
                    event.get("site_id", "gateway_default"),
                    event.get("server_id", ""),
                    datetime.now(timezone.utc),
                    event.get("remote_addr", "0.0.0.0"),
                    event.get("country_code", ""),
                    event.get("rule_id", 0),
                    rule_msg,
                    rule_tag,
                    "CRITICAL" if waf_score >= 15 else "HIGH" if waf_score >= 5 else "WARNING",
                    event.get("matched_data", ""),
                    event.get("matched_var", ""),
                    waf_score,
                    "block" if status_code == 403 else "detect"
                ]
                ch.insert(
                    "waf_events",
                    [waf_row],
                    column_names=[
                        "event_id", "request_id", "site_id", "server_id", "timestamp", "remote_addr",
                        "country_code", "rule_id", "rule_msg", "rule_tag", "severity",
                        "matched_data", "matched_var", "anomaly_score", "action_taken"
                    ]
                )
                log.info(f"🔥 WAF Event Promoted: {rule_tag}")

            HMAC_ACCEPTED.inc()
            log.info("✅ Log processed")

        except Exception as e:
            log.error(f"Worker error: {e}")
            time.sleep(1)

if __name__ == "__main__":
    main()