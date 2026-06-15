"""
AegisAI-X — Attack Simulation Tool
====================================
Pushes realistic WAF events and access logs into the Redis ingestion stream
for end-to-end pipeline testing.

Signing protocol:
  1. Build event dict (WITHOUT hmac field)
  2. Serialize to canonical JSON (sort_keys=True)
  3. Compute HMAC-SHA256 of that string
  4. Push to Redis stream with TWO separate fields:
       "payload"  = canonical JSON string
       "hmac"     = hex HMAC signature
  The HMAC worker reads both fields independently — no JSON re-parsing for verification.

Run inside the api container:
  docker exec aegisai-api python /app/tools/simulate_attack.py
"""

import json
import time
import hmac
import hashlib
import uuid
import redis
import os
import sys
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Configuration — NO hardcoded secrets
# ---------------------------------------------------------------------------
REDIS_URL   = os.environ.get("REDIS_URL", "redis://redis:6379/0")
STREAM_KEY  = "aegisai:raw_logs"

try:
    HMAC_SECRET = os.environ["AEGISAI_HMAC_SECRET"].encode()
except KeyError:
    print("ERROR: AEGISAI_HMAC_SECRET environment variable is not set.", file=sys.stderr)
    print("Set it to the same value as the hmac_worker service.", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Core signing + publishing
# ---------------------------------------------------------------------------
def sign_payload(payload_str: str) -> str:
    """Compute HMAC-SHA256 of the canonical payload string."""
    return hmac.new(HMAC_SECRET, payload_str.encode(), hashlib.sha256).hexdigest()


def push_event(event: dict) -> None:
    """
    Push event to the Redis LIST that hmac_worker lpop()s from.
    Embeds the HMAC signature directly inside the JSON payload,
    matching exactly what hmac_worker expects.
    """
    r = redis.from_url(REDIS_URL)

    # Build the signable payload WITHOUT hmac field first
    payload_str = json.dumps(event, sort_keys=True)
    sig = sign_payload(payload_str)

    # Add hmac into the event, then push the whole thing as a JSON string
    # hmac_worker does: event = json.loads(raw), then reads event.get("hmac")
    event_with_sig = {**event, "hmac": sig}
    r.rpush(STREAM_KEY, json.dumps(event_with_sig))

    label = event.get("rule_msg") or event.get("request_uri") or event.get("log_type")
    print(f"  ✓ Pushed [{event.get('log_type')}] {label}")


# ---------------------------------------------------------------------------
# Attack Scenarios
# ---------------------------------------------------------------------------
def simulate_sqli(site_id: str = "site_001") -> None:
    print(f"\n--- SQL Injection Attack on {site_id} ---")
    push_event({
        "event_id":    str(uuid.uuid4()),
        "request_id":  str(uuid.uuid4()),
        "site_id":     site_id,
        "server_id":   "gw-node-01",
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "remote_addr": "192.168.1.100",
        "country_code": "US",
        "log_type":    "waf_event",
        "rule_id":     100001,
        "rule_msg":    "AegisAI: SQL Injection Attempt Detected",
        "rule_tag":    "aegisai/sqli",
        "severity":    "CRITICAL",
        "matched_data": "admin' OR '1'='1",
        "matched_var":  "ARGS:password",
        "waf_score":     25,
        "action_taken": "detect",
        "nonce":       str(uuid.uuid4()),
    })


def simulate_xss(site_id: str = "site_001") -> None:
    print(f"\n--- XSS Attack on {site_id} ---")
    push_event({
        "event_id":    str(uuid.uuid4()),
        "request_id":  str(uuid.uuid4()),
        "site_id":     site_id,
        "server_id":   "gw-node-01",
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "remote_addr": "10.0.0.50",
        "country_code": "IN",
        "log_type":    "waf_event",
        "rule_id":     100002,
        "rule_msg":    "AegisAI: XSS Attempt Detected",
        "rule_tag":    "aegisai/xss",
        "severity":    "CRITICAL",
        "matched_data": "<script>alert('pwned')</script>",
        "matched_var":  "ARGS:q",
        "waf_score":     20,
        "action_taken": "detect",
        "nonce":       str(uuid.uuid4()),
    })


def simulate_brute_force(site_id: str = "site_001", count: int = 25) -> None:
    print(f"\n--- Brute Force Attack ({count} failures) on {site_id} ---")
    ip = "45.33.32.156"
    for i in range(count):
        push_event({
            "request_id":    str(uuid.uuid4()),
            "site_id":       site_id,
            "server_id":     "gw-node-01",
            "timestamp":     datetime.now(timezone.utc).isoformat(),
            "remote_addr":   ip,
            "country_code":  "US",
            "log_type":      "access",
            "request_method": "POST",
            "request_uri":   "/api/v1/auth/login",
            "status":        401,
            "request_time":  0.05,
            "bytes_sent":    42,
            "http_user_agent": "Mozilla/5.0 (Hydra)",
            "waf_score":     0,
            "nonce":         str(uuid.uuid4()),
        })
        time.sleep(0.05)


def simulate_cross_site(site_ids: list = None) -> None:
    """Same IP hammering multiple sites — triggers cross-site correlation."""
    if site_ids is None:
        site_ids = ["site_001", "site_002", "site_003"]
    print(f"\n--- Cross-Site Attack on {site_ids} ---")
    ip = "198.51.100.99"
    for site in site_ids:
        for _ in range(5):
            push_event({
                "event_id":    str(uuid.uuid4()),
                "request_id":  str(uuid.uuid4()),
                "site_id":     site,
                "server_id":   "gw-node-02",
                "timestamp":   datetime.now(timezone.utc).isoformat(),
                "remote_addr": ip,
                "country_code": "RU",
                "log_type":    "waf_event",
                "rule_id":     100005,
                "rule_msg":    "AegisAI: Scanning Detected",
                "rule_tag":    "aegisai/scan",
                "severity":    "WARNING",
                "matched_data": "",
                "matched_var":  "REQUEST_URI",
                "waf_score":     10,
                "action_taken": "detect",
                "nonce":       str(uuid.uuid4()),
            })
            time.sleep(0.02)


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("AegisAI-X Attack Simulator")
    print(f"Stream: {STREAM_KEY}  |  Worker secret: {'*' * 8}")

    simulate_sqli()
    time.sleep(0.5)

    simulate_xss()
    time.sleep(0.5)

    simulate_brute_force()
    time.sleep(0.5)

    simulate_cross_site()

    print("\n✅ Simulation complete — check the SOC Dashboard and hmac_worker logs.")
