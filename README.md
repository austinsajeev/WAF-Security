# =============================================================================
# AegisAI-X Phase 1 — Deployment Guide
# =============================================================================

## Project Structure

```
aegisai-x/
├── gateway/
│   ├── nginx/
│   │   ├── nginx.conf                        # A. Main Nginx config
│   │   ├── sites-available/
│   │   │   └── site_template.conf            # A. Per-site vhost template
│   │   └── modsecurity/
│   │       └── modsec_main.conf              # A. ModSecurity WAF config
│   └── filebeat/
│       └── filebeat.yml                      # C. Log shipping agent
├── storage/
│   └── clickhouse/
│       └── schema.sql                        # B. ClickHouse tables + views
├── ansible/
│   └── deploy_gateway.yml                    # D. Canary → full rollout
└── observability/
    └── prometheus/
        ├── prometheus.yml                    # E. Metrics scrape config
        └── rules/
            └── gateway_alerts.yml            # E. Alert rules
```

---

## Prerequisites

| Component | Version | Install |
|---|---|---|
| Nginx | 1.25+ | `apt install nginx` |
| ModSecurity | 3.x | `apt install libmodsecurity3 libmodsecurity-dev` |
| OWASP CRS | 4.x | `apt install modsecurity-crs` |
| Filebeat | 8.x | [elastic.co/downloads](https://www.elastic.co/downloads/beats/filebeat) |
| ClickHouse | 24.x | [clickhouse.com/docs](https://clickhouse.com/docs/en/install) |
| Ansible | 2.15+ | `pip install ansible` |
| Prometheus | 2.50+ | [prometheus.io/download](https://prometheus.io/download/) |

---

## Phase 1 Deployment Order

### Step 1 — PKI Setup (do this FIRST)
Generate the internal CA and per-node certificates for mTLS.

```bash
# On Central Server — create CA
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
    -out ca.crt -subj "/CN=AegisAI-X Internal CA"

# Per gateway node — generate and sign node cert
openssl genrsa -out gateway-node1.key 2048
openssl req -new -key gateway-node1.key \
    -out gateway-node1.csr -subj "/CN=gateway-node1"
openssl x509 -req -in gateway-node1.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out gateway-node1.crt -days 365

# Distribute: ca.crt to ALL nodes, node-specific crt+key to each node
# Store in: /etc/aegisai/pki/
```

### Step 2 — ClickHouse Schema
```bash
# On Central Server
clickhouse-client --multiquery < storage/clickhouse/schema.sql
```

### Step 3 — Deploy Gateway (2 pilot servers via Ansible)
```bash
# Test on 2 servers first before canary rollout
ansible-playbook -i inventories/pilot.ini deploy_gateway.yml \
    -e "aegisai_version=1.0.0"
```

### Step 4 — Canary Rollout (10 servers)
```bash
ansible-playbook -i inventories/production.ini deploy_gateway.yml \
    -e "aegisai_version=1.0.0"
# Watch Grafana dashboard during the 5-minute review gate
```

### Step 5 — Full Rollout
```bash
# Set auto_rollout=true to skip the human review pause
ansible-playbook -i inventories/production.ini deploy_gateway.yml \
    -e "aegisai_version=1.0.0" \
    -e "auto_rollout=true"
```

### Step 6 — Prometheus + Alertmanager
```bash
# On Central Server
cp observability/prometheus/prometheus.yml /etc/prometheus/
cp observability/prometheus/rules/*.yml /etc/prometheus/rules/
systemctl restart prometheus
```

---

## Adding a New Website

1. Copy `gateway/nginx/sites-available/site_template.conf`
2. Replace all `{{ PLACEHOLDERS }}`
3. Commit to Git
4. Deploy via Ansible: `ansible-playbook deploy_gateway.yml -l <server>`

---

## Rollback

```bash
ansible-playbook -i inventories/production.ini deploy_gateway.yml \
    -e "rollback=true" \
    -e "rollback_version=1.0.0"
```

---

## Environment Variables (set per gateway node in `/etc/aegisai/gateway.env`)

```bash
SITE_ID=site_042
AEGISAI_HMAC_SECRET=<256-bit-secret>
# HOSTNAME is set automatically by OS
```

---

## WAF Tuning (Phase 3 prerequisite)

After 2 weeks in `DetectionOnly` mode:
1. Review false positives in ClickHouse: `SELECT rule_id, count() FROM waf_events GROUP BY rule_id ORDER BY count() DESC`
2. Add exclusions in `modsec_main.conf` for known-good traffic
3. Change `SecRuleEngine DetectionOnly` → `SecRuleEngine On`
4. Deploy change via Ansible canary rollout

---

## Key Dashboards (Grafana)

| Dashboard | Purpose |
|---|---|
| **AegisAI — SOC Overview** | Per-site attack counts, top IPs, WAF block rate |
| **AegisAI — Node Health** | Per-gateway CPU, latency, Filebeat lag |
| **AegisAI — Pipeline** | ClickHouse insert rate, disk usage, query latency |

---

> **Next Phase**: After 30 days of stable data, proceed to Phase 2 (Alerting Engine + Incident Lifecycle) and Phase 3 (AI/ML Anomaly Detection).
