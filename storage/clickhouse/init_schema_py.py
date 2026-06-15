import clickhouse_connect

# Correct credentials for local Docker stack
client = clickhouse_connect.get_client(
    host='clickhouse', 
    port=8123, 
    username='aegisai', 
    password='aegisai_ch_pass'
)

queries = [
    "CREATE DATABASE IF NOT EXISTS aegisai_db",
    """
    CREATE TABLE IF NOT EXISTS aegisai_db.request_logs (
        request_id String, site_id LowCardinality(String), server_id LowCardinality(String),
        timestamp DateTime64(3, 'UTC'), request_time_ms Float32, remote_addr IPv4,
        country_code LowCardinality(String), asn UInt32, asn_org String,
        method LowCardinality(String), uri String, status_code UInt16, bytes_sent UInt32,
        user_agent String, referer String, ssl_protocol LowCardinality(String), ssl_cipher String,
        waf_score UInt16 DEFAULT 0, waf_action LowCardinality(String) DEFAULT 'pass',
        priority LowCardinality(String) DEFAULT 'LOW', nonce String, hmac String
    ) ENGINE = MergeTree()
    PARTITION BY toYYYYMM(timestamp)
    ORDER BY (site_id, timestamp, remote_addr)
    TTL toDateTime(timestamp) + INTERVAL 365 DAY DELETE
    SETTINGS index_granularity = 8192
    """,
    """
    CREATE TABLE IF NOT EXISTS aegisai_db.waf_events (
        event_id String, request_id String, site_id LowCardinality(String), server_id LowCardinality(String),
        timestamp DateTime64(3, 'UTC'), remote_addr IPv4, country_code LowCardinality(String),
        rule_id UInt32, rule_msg String, rule_tag String, severity LowCardinality(String),
        matched_data String, matched_var String, anomaly_score UInt16, action_taken LowCardinality(String),
        priority LowCardinality(String) DEFAULT 'HIGH'
    ) ENGINE = MergeTree()
    PARTITION BY toYYYYMM(timestamp)
    ORDER BY (site_id, timestamp, severity)
    TTL toDateTime(timestamp) + INTERVAL 2 YEAR DELETE
    SETTINGS index_granularity = 8192
    """,
    """
    CREATE TABLE IF NOT EXISTS aegisai_db.dead_letter_queue (
        server_id String, site_id String, nonce String, original_timestamp String,
        reject_reason String, rejected_at DateTime, raw_payload String
    ) ENGINE = MergeTree()
    PARTITION BY toYYYYMM(rejected_at)
    ORDER BY rejected_at
    TTL rejected_at + INTERVAL 7 DAY DELETE
    SETTINGS index_granularity = 8192
    """,
    """
    CREATE TABLE IF NOT EXISTS aegisai_db.sites (
        site_id String, domain String, created_at DateTime DEFAULT now()
    ) ENGINE = MergeTree()
    ORDER BY site_id
    """,
    "INSERT INTO aegisai_db.sites (site_id, domain) VALUES ('site_001', 'example.com') IF NOT EXISTS",
    """
    CREATE TABLE IF NOT EXISTS aegisai_db.ip_reputation (
        ip IPv4, score UInt8, block_count UInt32 DEFAULT 0, first_seen DateTime, last_seen DateTime,
        last_updated DateTime, country_code LowCardinality(String), asn UInt32, sources Array(String),
        is_tor UInt8 DEFAULT 0, is_vpn UInt8 DEFAULT 0, is_datacenter UInt8 DEFAULT 0
    ) ENGINE = ReplacingMergeTree(last_updated)
    ORDER BY ip
    TTL last_updated + INTERVAL 7 DAY DELETE
    SETTINGS index_granularity = 8192
    """,
    """
    CREATE MATERIALIZED VIEW IF NOT EXISTS aegisai_db.mv_hourly_attacks
    ENGINE = SummingMergeTree()
    PARTITION BY toYYYYMM(hour)
    ORDER BY (site_id, hour, severity)
    POPULATE AS
    SELECT site_id, toStartOfHour(timestamp) AS hour, severity, count() AS event_count
    FROM aegisai_db.waf_events
    GROUP BY site_id, hour, severity
    """,
    """
    CREATE MATERIALIZED VIEW IF NOT EXISTS aegisai_db.mv_daily_top_ips
    ENGINE = SummingMergeTree()
    PARTITION BY toYYYYMM(day)
    ORDER BY (site_id, day, remote_addr)
    POPULATE AS
    SELECT site_id, toDate(timestamp) AS day, remote_addr, count() AS hit_count,
           max(anomaly_score) AS max_score, argMax(severity, anomaly_score) AS worst_severity
    FROM aegisai_db.waf_events
    GROUP BY site_id, day, remote_addr
    """
]

# Phase 3 Prerequisites
phase3_queries = [
    # Add label column (weak label from WAF, strong label from incident) to request_logs
    "ALTER TABLE aegisai_db.request_logs ADD COLUMN IF NOT EXISTS label LowCardinality(String) DEFAULT 'unknown'",

    # ip_features: Behavioral feature store for Isolation Forest
    """
    CREATE TABLE IF NOT EXISTS aegisai_db.ip_features (
        ip              IPv6,
        hour_bucket     DateTime,
        request_count   UInt32,
        request_rate    Float32,
        unique_endpoints UInt16,
        error_rate      Float32,
        attack_pct      Float32,
        hour_of_day     UInt8,
        ua_count        UInt8,
        computed_at     DateTime DEFAULT now()
    ) ENGINE = ReplacingMergeTree()
    PARTITION BY toYYYYMM(hour_bucket)
    ORDER BY (ip, hour_bucket)
    TTL hour_bucket + INTERVAL 90 DAY DELETE
    SETTINGS index_granularity = 8192
    """,
    # Phase 3: ML Anomaly Reputation
    "DROP TABLE IF EXISTS aegisai_db.ip_reputation",
    """
    CREATE TABLE IF NOT EXISTS aegisai_db.ip_reputation (
        ip              IPv6,
        anomaly_score   Float32,
        is_outlier      UInt8,
        computed_at     DateTime64(3, 'UTC') DEFAULT now()
    ) ENGINE = ReplacingMergeTree(computed_at)
    PARTITION BY toYYYYMM(computed_at)
    ORDER BY (ip)
    TTL toStartOfDay(toDateTime(computed_at)) + INTERVAL 30 DAY DELETE
    SETTINGS index_granularity = 8192
    """
]

for q in queries + phase3_queries:
    try:
        if "INSERT" in q:
            check = client.query("SELECT count() FROM aegisai_db.sites WHERE site_id = 'site_001'")
            if check.result_rows[0][0] == 0:
                client.command(q)
        else:
            client.command(q)
    except Exception as e:
        print(f"Error executing {q[:50]}...: {e}")

print("Schema initialized successfully!")
