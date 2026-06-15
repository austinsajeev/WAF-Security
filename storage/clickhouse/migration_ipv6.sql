-- =============================================================================
-- AegisAI-X — IPv6 Migration Script
-- Migrates remote_addr from IPv4 → IPv6 using safe rename strategy
-- (avoids heavy ALTER TABLE rebuild on large datasets)
-- =============================================================================
-- Strategy:
--   1. Create new tables with IPv6 type
--   2. Backfill data with IPv4→IPv6 mapping
--   3. Pause workers briefly
--   4. Rename old ↔ new (atomic)
--   5. Verify
--   6. Drop old tables after validation period
-- =============================================================================

USE aegisai_db;

-- =============================================================================
-- STEP 1: Create shadow tables with IPv6
-- =============================================================================

CREATE TABLE IF NOT EXISTS request_logs_v2 (
    request_id          String,
    site_id             LowCardinality(String),
    server_id           LowCardinality(String),
    timestamp           DateTime64(3, 'UTC'),
    request_time_ms     Float32,
    remote_addr         IPv6,               -- NEW: IPv6 (IPv4 as ::ffff:x.x.x.x)
    country_code        LowCardinality(String),
    asn                 UInt32,
    asn_org             String,
    method              LowCardinality(String),
    uri                 String,
    status_code         UInt16,
    bytes_sent          UInt32,
    user_agent          String,
    referer             String,
    ssl_protocol        LowCardinality(String),
    ssl_cipher          String,
    waf_score           UInt16 DEFAULT 0,
    waf_action          LowCardinality(String) DEFAULT 'pass',
    priority            LowCardinality(String) DEFAULT 'LOW',
    nonce               String,
    hmac                String
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (site_id, timestamp, remote_addr)
TTL toDateTime(timestamp) + INTERVAL 365 DAY DELETE
SETTINGS index_granularity = 8192;


CREATE TABLE IF NOT EXISTS waf_events_v2 (
    event_id            String,
    request_id          String,
    site_id             LowCardinality(String),
    server_id           LowCardinality(String),
    timestamp           DateTime64(3, 'UTC'),
    remote_addr         IPv6,               -- NEW: IPv6
    country_code        LowCardinality(String),
    rule_id             UInt32,
    rule_msg            String,
    rule_tag            String,
    severity            LowCardinality(String),
    matched_data        String,
    matched_var         String,
    anomaly_score       UInt16,
    action_taken        LowCardinality(String),
    priority            LowCardinality(String) DEFAULT 'HIGH'
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (site_id, timestamp, severity)
TTL toDateTime(timestamp) + INTERVAL 2 YEAR DELETE
SETTINGS index_granularity = 8192;


-- =============================================================================
-- STEP 2: Backfill existing data (IPv4 → IPv6-mapped)
-- In production run as a background INSERT SELECT, not inline.
-- =============================================================================

INSERT INTO request_logs_v2
SELECT
    request_id, site_id, server_id, timestamp, request_time_ms,
    IPv6NumToString(IPv4ToIPv6(remote_addr)) AS remote_addr,   -- ::ffff:x.x.x.x
    country_code, asn, asn_org, method, uri, status_code,
    bytes_sent, user_agent, referer, ssl_protocol, ssl_cipher,
    waf_score, waf_action, priority, nonce, hmac
FROM request_logs;


INSERT INTO waf_events_v2
SELECT
    event_id, request_id, site_id, server_id, timestamp,
    IPv6NumToString(IPv4ToIPv6(remote_addr)) AS remote_addr,
    country_code, rule_id, rule_msg, rule_tag, severity,
    matched_data, matched_var, anomaly_score, action_taken, priority
FROM waf_events;


-- =============================================================================
-- STEP 3: PAUSE hmac_worker before this step (stop writing to old tables)
--   docker-compose stop hmac_worker
-- =============================================================================


-- =============================================================================
-- STEP 4: Atomic rename (run as a single statement)
-- =============================================================================

RENAME TABLE
    request_logs    TO request_logs_ipv4_old,
    request_logs_v2 TO request_logs,
    waf_events      TO waf_events_ipv4_old,
    waf_events_v2   TO waf_events;


-- =============================================================================
-- STEP 5: Restart worker
--   docker-compose start hmac_worker
-- =============================================================================


-- =============================================================================
-- STEP 6: Verify (run manually after worker restarts)
-- =============================================================================

-- Check new tables have data
-- SELECT count(), max(timestamp) FROM request_logs;
-- SELECT count(), max(timestamp) FROM waf_events;
-- SELECT remote_addr FROM waf_events LIMIT 5;
-- Expected: ::ffff:192.168.1.100 etc.


-- =============================================================================
-- STEP 7: Drop old tables (after 24h validation period)
-- =============================================================================

-- DROP TABLE IF EXISTS request_logs_ipv4_old;
-- DROP TABLE IF EXISTS waf_events_ipv4_old;
