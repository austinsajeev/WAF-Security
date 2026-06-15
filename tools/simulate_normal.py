import json
import time
import hmac
import hashlib
import uuid
import redis
import os
import random
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# AegisAI-X — Realistic Normal Traffic Simulator (v2.0)
# ===============================================
# Generates non-uniform, legitimate-looking traffic pattern:
# - Session Persistence: Same IP/UA for multiple sequential requests
# - Non-uniform delay: Jittered session inter-arrivals
# - Distribution-based paths
# - Status code noise (94% success, 6% random errors)
# ---------------------------------------------------------------------------

REDIS_URL   = os.environ.get("REDIS_URL", "redis://redis:6379/0")
HMAC_SECRET = os.environ.get("AEGISAI_HMAC_SECRET", "dev-hmac-secret-change-in-production").encode()
STREAM_KEY  = "aegisai:raw_logs"

ENDPOINTS = [
    ("/", 0.35), ("/products", 0.15), ("/api/v1/status", 0.10),
    ("/inventory", 0.05), ("/login", 0.10), ("/about", 0.05),
    ("/blog", 0.05), ("/search?q=query", 0.10), ("/contact", 0.05)
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/123.0.6312.122",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Firefox/124.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) Version/17.4 Safari/604.1"
]

# Persona pool: 50 unique IPs
NORMAL_IPS = [f"10.50.{random.randint(1, 254)}.{random.randint(1, 254)}" for _ in range(50)]

def sign_payload(payload_str: str) -> str:
    return hmac.new(HMAC_SECRET, payload_str.encode(), hashlib.sha256).hexdigest()

def push_event(event: dict) -> None:
    r = redis.from_url(REDIS_URL)
    payload_str = json.dumps(event, sort_keys=True)
    sig = sign_payload(payload_str)
    
    event_with_sig = {**event, "hmac": sig}
    r.rpush(STREAM_KEY, json.dumps(event_with_sig))

def simulate_session(session_id: int):
    """Simulate a single user session navigating multiple pages."""
    ip = NORMAL_IPS[session_id % len(NORMAL_IPS)]
    ua = random.choice(USER_AGENTS)
    site_id = "site_001"
    
    pages = random.randint(2, 15)
    print(f"[*] Session {session_id} ({ip}) starting - navigating {pages} pages...")
    
    for _ in range(pages):
        path = random.choices([p[0] for p in ENDPOINTS], weights=[p[1] for p in ENDPOINTS])[0]
        
        # Real-world status distribution
        status = 200
        if random.random() < 0.06:
            status = random.choice([401, 403, 404, 500, 503])
            
        event = {
            "request_id":     str(uuid.uuid4()),
            "site_id":        site_id,
            "server_id":      "gw-node-01",
            "timestamp":      datetime.now(timezone.utc).isoformat(),
            "remote_addr":    ip,
            "country_code":   "US",
            "log_type":       "access",
            "request_method": random.choice(["GET", "GET", "GET", "POST"]),
            "request_uri":    path,
            "status":         status,
            "request_time":   round(random.uniform(0.01, 0.5), 3),
            "bytes_sent":     random.randint(256, 12000),
            "http_user_agent": ua,
            "waf_score":      0,
            "nonce":          str(uuid.uuid4())
        }
        
        try:
            push_event(event)
            print(f"    - {path} ({status})")
        except Exception as e:
            print(f"    ! Error: {e}")
            
        time.sleep(random.uniform(0.5, 3.0))

if __name__ == "__main__":
    count = 15
    print(f"=== AegisAI-X: Starting {count} Normal Traffic Sessions ===")
    for i in range(count):
        simulate_session(i)
        time.sleep(random.uniform(0.5, 2.0))
    print("=== Simulation Complete ===")
