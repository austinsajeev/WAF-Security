# AegisAI-X — AI-Powered Web Application Firewall Security Platform

AegisAI-X is a full-stack, enterprise-grade Web Application Firewall (WAF) security platform that combines real-time traffic inspection, machine learning anomaly detection, automated incident management, and a live Security Operations Center (SOC) dashboard. It is designed to protect multiple websites simultaneously and automatically respond to attacks without human intervention.

---

## What It Does

- Blocks malicious web traffic in real time — SQL Injection, XSS, DDoS, Brute Force, LFI, and scanner attacks
- Collects and stores every HTTP request across all protected sites for analysis
- Detects behavioral anomalies using an Isolation Forest machine learning model
- Automatically raises security incidents and sends alerts to SOC analysts
- Auto-blocks high-confidence attacking IPs at the network edge
- Provides a live SOC dashboard for incident investigation and response

---

## Core Components

### Gateway (Nginx + ModSecurity)
Every HTTP request passes through Nginx with ModSecurity v3 and the OWASP Core Rule Set v4. Each request is scored for attack patterns and either blocked or logged with a structured JSON record.

### Log Pipeline (Filebeat + Redis + HMAC Worker)
Filebeat ships logs in real-time, signing each event with HMAC-SHA256 to prevent tampering. A Python worker consumes events from Redis, verifies signatures, normalizes fields, and stores them in ClickHouse.

### Feature Builder & Geo Enricher
Workers aggregate per-IP behavioral statistics (request rate, error rate, unique endpoints visited, attack percentage) and enrich IPs with country and ASN data.

### ML Anomaly Detection — Phase 3
An Isolation Forest model (scikit-learn) runs every 15 minutes, training on IP behavior features and scoring all active IPs. The top 3% most anomalous IPs are flagged as outliers and cached in Redis for real-time lookup.

### Correlation Engine
Runs every 30 seconds, evaluating configurable alert rules against ClickHouse data. It groups many raw events into a single incident, applies a confidence score (boosted by the ML outlier scores), and automatically blocks IPs with confidence ≥ 75%. Alerts are sent via Slack and email.

### FastAPI Backend
A production-grade REST API with JWT authentication, TOTP-based multi-factor authentication (MFA), and role-based access control (admin, analyst, viewer). It serves live analytics from ClickHouse and manages incidents and the IP blocklist.

### SOC Dashboard (React + Vite)
A live frontend with pages for attack overview, incident management, IP blocklist control, per-site summaries, and ML model health status.

### Observability (Prometheus + Grafana)
All workers expose Prometheus metrics. Grafana dashboards cover SOC overview, node health, pipeline ingestion rates, and ML training status.

---

## Technology Stack

| Layer | Technology |
|---|---|
| Gateway / WAF | Nginx 1.25+, ModSecurity v3, OWASP CRS v4 |
| Log Shipping | Filebeat 8.x |
| Message Queue | Redis 7 |
| Time-Series Database | ClickHouse 23.8 |
| Relational Database | PostgreSQL 16 |
| Pipeline Workers | Python 3.11 |
| ML / AI | scikit-learn (Isolation Forest), pandas, joblib |
| API | FastAPI, JWT, TOTP MFA, bcrypt, slowapi |
| Frontend | React 18, Vite |
| Metrics | Prometheus 2.52, Grafana 10.4 |
| Deployment | Docker Compose, Ansible |

---

## Security Design

- **Log Integrity** — Every log event is HMAC-SHA256 signed at the gateway. Tampered events are dropped before ingestion.
- **Zero-Trust Auth** — All API access requires JWT. MFA (TOTP) is supported per user. Tokens are revocable via Redis.
- **RBAC + Site Isolation** — Analysts can only access incidents for their assigned sites. Admins have full access.
- **mTLS Between Nodes** — Gateway nodes use mutual TLS with a private internal CA for secure communication.
- **Rate Limiting** — Login is limited to 5 attempts/minute and MFA to 3 attempts/minute per IP.
- **Secrets Management** — All credentials are loaded from environment variables. No secrets are committed to version control.
- **Auto-Response** — High-confidence incidents trigger automatic IP blocking without requiring human approval.

---

## Deployment

The project is containerized with Docker Compose for local development and testing. Production deployments use Ansible with a canary rollout strategy — starting with 2 pilot servers, then expanding to full production after a review gate.

### Quick Start

```bash
# Copy and fill in your secrets
cp .env.example .env

# Start all services
docker compose up -d
```

---

## Detection Capabilities

| Attack Type | Detection Method |
|---|---|
| SQL Injection | ModSecurity CRS + HMAC worker heuristics |
| Cross-Site Scripting (XSS) | ModSecurity CRS + heuristics |
| Local File Inclusion (LFI) | ModSecurity CRS + heuristics |
| Brute Force / Credential Stuffing | Correlation Engine (auth failure rate rule) |
| DDoS / Traffic Spike | Correlation Engine (3× baseline threshold) |
| Multi-Site Campaigns | Correlation Engine (cross-site IP / User-Agent rules) |
| Behavioral Anomalies | ML Isolation Forest (Phase 3) |
| Sensitive Path Scanning | HMAC worker heuristics (.env, .git, admin probes) |

---

## Environment Variables

Copy `.env.example` to `.env` and configure the following before running:

```
AEGISAI_HMAC_SECRET   — HMAC signing key for log integrity
JWT_SECRET            — Secret for JWT token signing
CH_PASSWORD           — ClickHouse database password
PG_PASSWORD           — PostgreSQL database password
SLACK_WEBHOOK_URL     — (Optional) Slack webhook for incident alerts
SMTP_HOST / SMTP_USER / SMTP_PASS / ALERT_EMAIL — (Optional) Email alerts
```

---

## Project Structure

```
aegisai-x/
├── backend/          # FastAPI REST API
├── dashboard/        # React + Vite SOC frontend
├── gateway/          # Nginx config, ModSecurity rules, Filebeat config
├── pipeline/         # Python workers (HMAC, ML, Correlation, Geo, Features, Blocklist)
├── storage/          # ClickHouse and PostgreSQL schemas
├── observability/    # Prometheus config, alert rules, Grafana dashboards
├── ansible/          # Production deployment playbook
├── tools/            # Attack simulation and validation scripts
├── docs/             # WAF promotion checklist
├── docker-compose.yml
└── .env.example
```

---

## Roadmap

- **Phase 1** — Gateway deployment, log ingestion, ClickHouse schema, Prometheus
- **Phase 2** — Correlation engine, incident lifecycle, alerting
- **Phase 3** — AI/ML anomaly detection (Isolation Forest) ✅
- **Phase 4** — Active edge enforcement (auto-blocking at Nginx from ML + Correlation) ✅
- **Phase 5** — Threat intelligence feed integration, GeoIP blocking policies

---

## License

This project is for internal security infrastructure use.
