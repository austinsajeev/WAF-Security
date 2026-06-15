# =============================================================================
# AegisAI-X — Deployment Script
# =============================================================================
# Give this file + the project folder to your IT team / sysadmin.
# They just need to run: bash deploy.sh
# =============================================================================

#!/bin/bash
set -e

echo "============================================================"
echo "  AegisAI-X — Production Deployment"
echo "============================================================"

# ── Step 1: Check Docker ──
if ! command -v docker &> /dev/null; then
    echo "❌ Docker not found. Installing..."
    curl -fsSL https://get.docker.com | sh
    sudo usermod -aG docker $USER
    echo "✅ Docker installed. Please log out and back in, then re-run this script."
    exit 1
fi
echo "✅ Docker found: $(docker --version)"

# ── Step 2: Generate production secrets ──
if grep -q "change-this" .env 2>/dev/null || grep -q "dev-hmac" .env 2>/dev/null; then
    echo "🔑 Generating production secrets..."
    HMAC_SECRET=$(openssl rand -hex 32)
    JWT_SECRET=$(openssl rand -hex 32)
    PG_PASS=$(openssl rand -base64 24 | tr -d '=/+' | head -c 24)
    CH_PASS=$(openssl rand -base64 24 | tr -d '=/+' | head -c 24)

    cat > .env <<EOF
# AegisAI-X Production Secrets (AUTO-GENERATED)
AEGISAI_HMAC_SECRET=${HMAC_SECRET}
JWT_SECRET=${JWT_SECRET}
CH_PASSWORD=${CH_PASS}
PG_PASSWORD=${PG_PASS}
SLACK_WEBHOOK_URL=
EOF
    echo "✅ Secrets generated and saved to .env"
else
    echo "✅ .env already configured"
fi

# ── Step 3: Build and deploy ──
echo "🚀 Building and deploying all containers..."
docker compose up -d --build

# ── Step 4: Wait for services to be ready ──
echo "⏳ Waiting for services to start (30s)..."
sleep 30

# ── Step 5: Seed admin user ──
echo "👤 Creating default admin user..."
docker exec aegisai-api python -c "
import psycopg2, bcrypt, os
conn = psycopg2.connect(os.environ.get('PG_DSN', 'postgresql://aegisai:aegisai_pg_pass@postgres/aegisai_db'))
cur = conn.cursor()
hash_pw = bcrypt.hashpw(b'AegisAdmin2026!', bcrypt.gensalt()).decode()
cur.execute(\"\"\"INSERT INTO users (username, email, password_hash, role, is_active)
VALUES ('admin', 'admin@aegisai.local', %s, 'admin', true)
ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash\"\"\", (hash_pw,))
conn.commit()
print('Admin user created.')
" 2>/dev/null || echo "⚠️  Admin user may already exist"

# ── Step 6: Verify ──
echo ""
echo "============================================================"
echo "  ✅ DEPLOYMENT COMPLETE"
echo "============================================================"
echo ""
echo "  Dashboard:  http://$(hostname -I | awk '{print $1}'):3000"
echo "  API:        http://$(hostname -I | awk '{print $1}'):8000"
echo "  Grafana:    http://$(hostname -I | awk '{print $1}'):3001"
echo ""
echo "  Login Credentials:"
echo "    Username: admin"
echo "    Password: AegisAdmin2026!"
echo ""
echo "  ⚠️  CHANGE THE ADMIN PASSWORD AFTER FIRST LOGIN!"
echo ""
echo "  Container Status:"
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | head -20
echo ""
echo "============================================================"
