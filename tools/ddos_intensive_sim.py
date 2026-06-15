"""
AegisAI-X — Intensive DDoS Simulation v2.0
==========================================
Simulates a massive distributed layer 7 HTTP flood.
Tests:
  - Nginx Rate Limiting (100r/s)
  - Correlation Engine (Traffic Spike Rule)
  - ML Outlier Detection (IP behavioral patterns)
"""

import json, time, hmac, hashlib, uuid, redis, os, sys, random
from datetime import datetime, timezone

# ── Config ──────────────────────────────────────────────────────────────────
REDIS_URL   = os.environ.get("REDIS_URL", "redis://redis:6379/0")
STREAM_KEY  = "aegisai:raw_logs"
HMAC_SECRET = os.environ.get("AEGISAI_HMAC_SECRET", "dev-hmac-secret-change-in-production").encode()

r = redis.from_url(REDIS_URL)

# ── DDoS Parameters ────────────────────────────────────────────────────────
TARGET_SITE = "gateway_default"
BOT_IPS     = [f"195.122.{random.randint(10, 250)}.{i}" for i in range(1, 100)]
PATHS       = ["/", "/api/v1/search", "/login", "/products", "/contact", "/api/status"]
AGENTS      = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Go-http-client/1.1",
    "python-requests/2.31.0",
    "Apache-HttpClient/4.5.13 (Java/11.0.12)",
    "curl/8.1.2"
]

def push(event: dict):
    payload_str = json.dumps(event, sort_keys=True)
    sig = hmac.new(HMAC_SECRET, payload_str.encode(), hashlib.sha256).hexdigest()
    r.rpush(STREAM_KEY, json.dumps({**event, "hmac": sig}))

def simulate_flood(count=1500, burst_delay=0.005):
    print(f"\n🚀 STARTING INTENSIVE DDOS FLOOD: {count} requests from {len(BOT_IPS)} IPs")
    print(f"Target: {TARGET_SITE} | Delay: {burst_delay}s")
    
    start_time = time.time()
    for i in range(count):
        ip      = random.choice(BOT_IPS)
        uri     = random.choice(PATHS)
        ua      = random.choice(AGENTS)
        
        # Simulate Nginx blocking some of them (rate limiting)
        # 30% of requests are blocked (status 429)
        status = 200 if random.random() > 0.3 else 429
        
        push({
            "request_id":      str(uuid.uuid4()),
            "site_id":         TARGET_SITE,
            "server_id":       "gw-node-01",
            "timestamp":       datetime.now(timezone.utc).isoformat(),
            "remote_addr":     ip,
            "country_code":    "RU" if i % 2 == 0 else "CN",
            "log_type":        "access",
            "request_method":  "GET",
            "request_uri":     uri,
            "status":          status,
            "request_time":    0.001 if status == 429 else 0.045,
            "bytes_sent":      random.randint(400, 1200),
            "http_user_agent": ua,
            "waf_score":       0,
            "nonce":           str(uuid.uuid4()),
        })
        
        if i % 100 == 0:
            print(f"  ⚡ Flood progress: {i}/{count} requests sent...")
        
        # Very short delay to overwhelm the pipeline
        time.sleep(burst_delay)

    duration = time.time() - start_time
    print(f"\n✅ DDOS SIMULATION COMPLETE | {count} reqs in {duration:.2f}s (~{count/duration:.1f} req/s)")

if __name__ == "__main__":
    simulate_flood()
