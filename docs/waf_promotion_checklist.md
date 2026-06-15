# WAF Promotion Checklist
## AegisAI-X — From DetectionOnly → Enforcement Mode

> [!CAUTION]
> Do NOT switch `SecRuleEngine` from `DetectionOnly` to `On` without completing this checklist.
> Premature enforcement will block legitimate traffic and create outages.

---

## Prerequisites
- [ ] Minimum **14 days** of data collected in DetectionOnly mode on target site
- [ ] ClickHouse has at least **1 week of clean baseline** (no confirmed attacks distorting data)
- [ ] Grafana / SOC Dashboard is live and analysts are actively monitoring

---

## Step 1 — False Positive Analysis

Run this query on ClickHouse for each site before promoting:

```sql
-- Top WAF rule hits against known-good traffic
-- Focus on rules triggered by authenticated users or internal IPs
SELECT
    rule_id,
    rule_msg,
    rule_tag,
    count()          AS hit_count,
    uniq(remote_addr) AS ip_count,
    max(anomaly_score) AS max_score
FROM waf_events
WHERE
    site_id   = 'YOUR_SITE_ID'
    AND timestamp >= now() - INTERVAL 14 DAY
GROUP BY rule_id, rule_msg, rule_tag
ORDER BY hit_count DESC
LIMIT 30;
```

**Acceptance criteria:**
- [ ] False positive rate < 1% of total requests
- [ ] No rule is hitting > 100x per day from verified-clean IPs
- [ ] All CRITICAL rule hits (anomaly score > 50) have been investigated

---

## Step 2 — Top Rule Validation

For each rule in your top-10 by hit count:

| Rule ID | Rule Description | Hit Count | False Positive? | Action |
|---------|-----------------|-----------|-----------------|--------|
| 942100  | SQL Injection    |           | ☐ Yes / ☐ No   | Enable / Exclude |
| 941100  | XSS via libinj   |           | ☐ Yes / ☐ No   | Enable / Exclude |
| 930120  | OS File Access   |           | ☐ Yes / ☐ No   | Enable / Exclude |
| ...     | ...              |           |                 |        |

Write exclusions for FP rules **before** switching to enforcement:
```nginx
# In modsec_main.conf — example exclusion for rule 942100 on /api/search
SecRuleUpdateTargetById 942100 "!ARGS:query"
```

---

## Step 3 — Attack Simulation Test

Run a controlled attack simulation against a **staging instance** (never production) to verify detection:

- [ ] `sqlmap -u "https://staging.site.com/?id=1"` — should trigger rule 942100
- [ ] `nikto -h https://staging.site.com` — should trigger scanner rules
- [ ] Manual XSS payload in a form field — should trigger rule 941100
- [ ] Path traversal: `curl https://staging.site.com/../../etc/passwd` — should trigger rule 930120

**Tools needed:**
```bash
# Install on a test machine (NOT on any production server)
apt install sqlmap nikto
```

Acceptance criteria:
- [ ] All 4 attack types are detected and would be blocked
- [ ] No latency increase > 10ms during simulation

---

## Step 4 — Canary Enforcement

Switch **one** low-traffic site to enforcement mode first:

```bash
# In modsec_main.conf for pilot site only:
SecRuleEngine On   # Change from DetectionOnly
```

Deploy via Ansible to 1 server:
```bash
ansible-playbook -i inventories/production.ini deploy_gateway.yml \
    -l pilot_server \
    -e "modsec_mode=On"
```

Monitor for 48 hours:
- [ ] No legitimate user complaints
- [ ] Block rate is < 0.5% of total requests
- [ ] Zero increase in 5xx error rate on the site

---

## Step 5 — Full Promotion

Only after Step 4 passes:

- [ ] Update `modsec_main.conf`: `SecRuleEngine On`
- [ ] Commit to Git with tag: `waf-enforcement-v1.0`
- [ ] Deploy via Ansible canary rollout
- [ ] Monitor Grafana "WAF Block Rate" dashboard for 1 hour post-deployment
- [ ] Brief the on-call team — enforcement mode is now active
- [ ] Update internal documentation

---

## Rollback Trigger

Immediately rollback if any of the following occur within 2h of enforcement:

| Condition | Threshold |
|---|---|
| 5xx error rate increase | > 2% above baseline |
| Block rate | > 5% of total requests |
| User complaints | Any confirmed legitimate user blocked |

Rollback command:
```bash
ansible-playbook -i inventories/production.ini deploy_gateway.yml \
    -e "rollback=true" \
    -e "rollback_version=<last-good-tag>"
```

---

## Sign-Off

| Role | Name | Date | Signature |
|---|---|---|---|
| Security Lead | | | |
| DevOps Lead   | | | |
| Site Owner    | | | |
