-- =============================================================================
-- AegisAI-X — ClickHouse Schema
-- Version: 1.0.0
-- Engine: ReplicatedMergeTree (survives node failure)
-- =============================================================================
-- Naming: aegisai_db
-- Tables:
--   1. request_logs      — All HTTP request metadata (hot data)
--   2. waf_events        — WAF rule hits and attack detections
--   3. ip_reputation     — Internal IP score cache (updated by workers)
--   4. incidents         — Correlated incidents with lifecycle state
-- =============================================================================

CREATE DATABASE IF NOT EXISTS aegisai_db;

USE aegisai_db;


-- =============================================================================
-- TABLE 1: request_logs
-- Stores all incoming request metadata from all gateway nodes.
-- HIGH volume — uses TTL tiering for cost control.
-- =============================================================================
CREATE TABLE IF NOT EXISTS request_logs
(
    -- Identity & Routing
    request_id          String,                 -- UUID per request (from $request_id)
    site_id             LowCardinality(String), -- e.g. "site_042" — low cardinality = efficient
    server_id           LowCardinality(String), -- hostname of the gateway node
    
    -- Timing
    timestamp           DateTime64(3, 'UTC'),   -- millisecond precision
    request_time_ms     Float32,                -- upstream response time in ms
    
    -- Network
    remote_addr         IPv6,                   -- client IP (IPv4 stored as ::ffff:x.x.x.x)
    country_code        LowCardinality(String), -- 2-letter ISO country (e.g. "IN", "US")
    asn                 UInt32,                 -- Autonomous System Number
    asn_org             String,                 -- ASN organization name
    
    -- HTTP Request
    method              LowCardinality(String), -- GET, POST, etc.
    uri                 String,                 -- full request URI
    status_code         UInt16,                 -- HTTP response code
    bytes_sent          UInt32,                 -- response size in bytes
    user_agent          String,                 -- raw User-Agent header
    referer             String,                 -- Referer header
    
    -- TLS
    ssl_protocol        LowCardinality(String), -- TLSv1.2 / TLSv1.3
    ssl_cipher          String,                 -- cipher suite used
    
    -- WAF
    waf_score           UInt16 DEFAULT 0,       -- ModSecurity anomaly score (0 = clean)
    waf_action          LowCardinality(String) DEFAULT 'pass', -- pass/block/detect
    
    -- Log Priority (for backpressure drop policy)
    -- HIGH = blocked attacks, auth failures
    -- MEDIUM = suspicious patterns (high waf_score, rare endpoints)
    -- LOW = normal traffic
    priority            LowCardinality(String) DEFAULT 'LOW',

    -- Integrity
    nonce               String,                 -- replay protection nonce from Filebeat
    hmac                String                  -- HMAC-SHA256 of log line (verified by worker)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (site_id, timestamp, remote_addr)
-- TTL TIERS:
--   Cold: 1 year  — compressed, slow-query-only storage
TTL
    timestamp + INTERVAL 365 DAY DELETE
SETTINGS
    index_granularity = 8192;


-- =============================================================================
-- TABLE 2: waf_events
-- Stores all WAF rule hits separately for fast attack analytics.
-- Lower volume than request_logs — kept longer.
-- =============================================================================
CREATE TABLE IF NOT EXISTS waf_events
(
    event_id            String,
    request_id          String,                 -- FK to request_logs
    site_id             LowCardinality(String),
    server_id           LowCardinality(String),
    timestamp           DateTime64(3, 'UTC'),
    remote_addr         IPv6,                   -- IPv4 stored as ::ffff:x.x.x.x
    country_code        LowCardinality(String),
    
    -- Attack Details
    rule_id             UInt32,                 -- ModSecurity rule ID e.g. 942100
    rule_msg            String,                 -- Human-readable rule description
    rule_tag            String,                 -- e.g. "aegisai/sqli"
    severity            LowCardinality(String), -- CRITICAL/ERROR/WARNING/NOTICE
    matched_data        String,                 -- actual matched payload
    matched_var         String,                 -- which variable was matched (ARGS, URI, etc.)
    anomaly_score       UInt16,
    action_taken        LowCardinality(String), -- detect/block
    
    -- Priority for backpressure
    priority            LowCardinality(String) DEFAULT 'HIGH'
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (site_id, timestamp, severity)
TTL timestamp + INTERVAL 2 YEAR DELETE
SETTINGS index_granularity = 8192;


-- =============================================================================
-- TABLE 3: ip_reputation
-- Internal IP reputation cache. Updated by processing workers.
-- Replaces over-reliance on external APIs (AbuseIPDB rate limits).
-- =============================================================================
CREATE TABLE IF NOT EXISTS ip_reputation
(
    ip                  IPv4,
    score               UInt8,                  -- 0=clean, 100=confirmed malicious
    block_count         UInt32 DEFAULT 0,       -- total WAF blocks from this IP
    first_seen          DateTime,
    last_seen           DateTime,
    last_updated        DateTime,
    country_code        LowCardinality(String),
    asn                 UInt32,
    
    -- Source tags (which feeds flagged this IP)
    sources             Array(String),          -- e.g. ['abuseipdb', 'internal_waf', 'brute_force']
    
    -- Enrichment
    is_tor              UInt8 DEFAULT 0,        -- 1 if Tor exit node
    is_vpn              UInt8 DEFAULT 0,        -- 1 if known VPN/proxy
    is_datacenter       UInt8 DEFAULT 0         -- 1 if datacenter ASN (not residential)
)
ENGINE = ReplacingMergeTree(last_updated)
ORDER BY ip
TTL last_updated + INTERVAL 7 DAY DELETE   -- stale entries auto-expire after 7 days
SETTINGS index_granularity = 8192;


-- =============================================================================
-- Useful Materialized Views for Dashboard Performance
-- Pre-aggregate common queries so the dashboard stays fast at scale.
-- =============================================================================

-- Hourly attack counts per site
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_hourly_attacks
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (site_id, hour, severity)
POPULATE
AS
SELECT
    site_id,
    toStartOfHour(timestamp) AS hour,
    severity,
    count()                  AS event_count
FROM waf_events
GROUP BY site_id, hour, severity;


-- Top attacking IPs per site per day
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_daily_top_ips
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(day)
ORDER BY (site_id, day, remote_addr)
POPULATE
AS
SELECT
    site_id,
    toDate(timestamp)   AS day,
    remote_addr,
    count()             AS hit_count,
    max(anomaly_score)  AS max_score,
    argMax(severity, anomaly_score) AS worst_severity
FROM waf_events
GROUP BY site_id, day, remote_addr;


-- =============================================================================
-- INDEXES: Additional skip indexes for common dashboard queries
-- =============================================================================

-- Fast lookup by IP in request_logs
ALTER TABLE request_logs
    ADD INDEX idx_remote_addr remote_addr TYPE bloom_filter(0.01) GRANULARITY 4;

-- Fast lookup by WAF rule tag in waf_events
ALTER TABLE waf_events
    ADD INDEX idx_rule_tag rule_tag TYPE bloom_filter(0.01) GRANULARITY 4;


-- =============================================================================
-- SAMPLE VERIFICATION QUERIES
-- Run after data starts flowing to confirm schema health
-- =============================================================================

-- Check log ingestion rate (should have data within minutes of deployment)
-- SELECT site_id, count(), max(timestamp) FROM request_logs GROUP BY site_id;

-- Check WAF event rate
-- SELECT site_id, severity, count() FROM waf_events GROUP BY site_id, severity ORDER BY count() DESC;

-- Find top attacking IPs in last 24h
-- SELECT remote_addr, count() as hits, max(anomaly_score) as max_score
-- FROM waf_events
-- WHERE timestamp >= now() - INTERVAL 24 HOUR
-- GROUP BY remote_addr ORDER BY hits DESC LIMIT 20;
