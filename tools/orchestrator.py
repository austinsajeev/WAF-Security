import os
import time
import random
import requests
import uuid
from datetime import datetime

# ---------------------------------------------------------------------------
# AegisAI-X — Phased Traffic Orchestrator
# =======================================
# Generates realistic, phased HTTP traffic directly to the Nginx gateway.
# Supports 4 distinct phases (A, B, C, D) to train ML anomaly models.
# Ensures session persistence (IP + UA) via X-Forwarded-For.
# ---------------------------------------------------------------------------

GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://localhost")

ENDPOINTS = [
    ("/", 0.40), ("/products", 0.20), ("/api/v1/status", 0.10),
    ("/inventory", 0.05), ("/about", 0.05), ("/blog", 0.05),
    ("/contact", 0.05), ("/docs", 0.10)
]

LOGIN_ENDPOINTS = [("/login", 0.70), ("/api/v1/auth", 0.30)]

ATTACK_PAYLOADS = [
    ("/?q=1' OR '1'='1", "SQLi"),
    ("/?search=<script>alert('XSS')</script>", "XSS"),
    ("/?file=../../../../etc/passwd", "LFI"),
    ("/admin.php", "Admin Scanner"),
    ("/.env", "Env Scanner"),
    ("/.git/config", "Git Scanner"),
    ("/api/v1/users?id=1; DROP TABLE users", "SQLi")
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/123.0.6312.122",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Firefox/124.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) Version/17.4 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Safari/604.1"
]

MALICIOUS_AGENTS = ["sqlmap/1.5", "masscan/1.3", "python-requests/2.31.0", "curl/7.68.0"]

# Generate a fixed pool of normal User Personas for session persistence
PERSONAS = []
for _ in range(50):
    PERSONAS.append({
        "ip": f"10.50.{random.randint(1, 254)}.{random.randint(1, 254)}",
        "ua": random.choice(USER_AGENTS)
    })

def make_request(persona: dict, path: str, is_attack: bool = False):
    """Sends an HTTP request to the gateway using persona attributes."""
    url = f"{GATEWAY_URL.rstrip('/')}{path}"
    
    # In a real environment, X-Forwarded-For must be trusted by Nginx.
    # We use it here to ensure the pipeline sees IP diversity.
    headers = {
        "User-Agent": persona["ua"],
        "X-Forwarded-For": persona["ip"],
        "X-Request-Id": str(uuid.uuid4())
    }
    
    try:
        # We don't care about the response content, just triggering the gateway
        r = requests.get(url, headers=headers, timeout=5)
        status = r.status_code
        label = "ATTACK" if is_attack else "NORMAL"
        print(f"[{label}] {persona['ip']} -> {path} ({status})")
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Connection to gateway failed: {e}")

def get_random_normal_path(heavy_login=False):
    """Selects a normal path, optionally skewing towards logins."""
    if heavy_login and random.random() < 0.6:
        return random.choices([p[0] for p in LOGIN_ENDPOINTS], weights=[p[1] for p in LOGIN_ENDPOINTS])[0]
    return random.choices([p[0] for p in ENDPOINTS], weights=[p[1] for p in ENDPOINTS])[0]

# =============================================================================
# Traffic Phases
# =============================================================================

def phase_a_low_normal(duration_secs: int = 60):
    print("\n--- [ PHASE A: Low Normal Traffic ] ---")
    end_time = time.time() + duration_secs
    while time.time() < end_time:
        persona = random.choice(PERSONAS)
        path = get_random_normal_path()
        make_request(persona, path)
        # Random high delay (low traffic)
        time.sleep(random.uniform(1.0, 3.0))

def phase_b_increased_activity(duration_secs: int = 60):
    print("\n--- [ PHASE B: Increased Activity (Spike) ] ---")
    end_time = time.time() + duration_secs
    while time.time() < end_time:
        persona = random.choice(PERSONAS)
        # Heavy login behavior simulating an event or rush
        path = get_random_normal_path(heavy_login=True)
        make_request(persona, path)
        # Random short delay (high traffic)
        time.sleep(random.uniform(0.1, 0.8))

def phase_c_mixed_attacks(duration_secs: int = 60):
    print("\n--- [ PHASE C: Mixed Attacks + Normal ] ---")
    end_time = time.time() + duration_secs
    
    # Generate 5 dedicated attack personas
    attackers = []
    for _ in range(5):
        attackers.append({
            "ip": f"192.168.100.{random.randint(1, 254)}",
            "ua": random.choice(MALICIOUS_AGENTS)
        })

    while time.time() < end_time:
        # 30% chance for attack, 70% chance for normal traffic
        if random.random() < 0.3:
            attacker = random.choice(attackers)
            payload = random.choice(ATTACK_PAYLOADS)[0]
            make_request(attacker, payload, is_attack=True)
        else:
            persona = random.choice(PERSONAS)
            path = get_random_normal_path()
            make_request(persona, path)
        
        # Fast, chaotic delays
        time.sleep(random.uniform(0.1, 1.0))

def phase_d_recovery(duration_secs: int = 60):
    print("\n--- [ PHASE D: Recovery (Return to Normal) ] ---")
    end_time = time.time() + duration_secs
    while time.time() < end_time:
        persona = random.choice(PERSONAS)
        path = get_random_normal_path()
        make_request(persona, path)
        # Gradually recovering delays
        time.sleep(random.uniform(0.5, 2.5))

def run_orchestrator():
    print("=" * 60)
    print(" AegisAI-X Traffic Orchestrator Initializing...")
    print(f" Target Gateway: {GATEWAY_URL}")
    print("=" * 60)
    
    # Default: 2 minutes per phase for a full 8-minute cycle
    PHASE_DURATION = int(os.environ.get("PHASE_DURATION_SECS", 120))
    
    while True:
        try:
            phase_a_low_normal(PHASE_DURATION)
            phase_b_increased_activity(PHASE_DURATION)
            phase_c_mixed_attacks(PHASE_DURATION)
            phase_d_recovery(PHASE_DURATION)
            print("\n[INFO] Cycle complete. Restarting in 10 seconds...")
            time.sleep(10)
        except KeyboardInterrupt:
            print("\n[INFO] Orchestrator stopped by user.")
            break
        except Exception as e:
            print(f"\n[ERROR] Orchestrator encountered an error: {e}")
            time.sleep(5)

if __name__ == "__main__":
    run_orchestrator()
