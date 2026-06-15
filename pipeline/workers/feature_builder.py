"""
AegisAI-X — Enhanced Feature Builder (Phase 2.5 Hardened)
==========================================================
Hardened for Phase 3 Readiness:
- Consistent IPv6 handling (standardized across pipeline)
- Automated labeling (WAF hits = weak labels)
- Diversity and volume thresholding
- Performance-optimized ClickHouse-side aggregation
"""

import os
import time
import logging
import clickhouse_connect
from datetime import datetime, timezone

log = logging.getLogger("aegisai.feature_builder")
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

CH_HOST     = os.environ.get("CH_HOST", "clickhouse")
CH_USER     = os.environ.get("CH_USER", "aegisai")
CH_PASSWORD = os.environ.get("CH_PASSWORD", "aegisai_ch_pass")
CH_DB       = os.environ.get("CH_DB", "aegisai_db")
RUN_INTERVAL  = int(os.environ.get("FEATURE_INTERVAL", "300"))   # bridge runs every 5 min
BUILD_INTERVAL = int(os.environ.get("BUILD_INTERVAL", "3600"))    # feature build hourly

def bridge_waf_events(ch):
    """
    Promote request_logs rows with WAF hits into waf_events.
    Bridges the gap until a dedicated ModSecurity audit log parser exists.
    Maps waf_score >= 5 → action_taken='block', lower → 'detect'.
    """
    log.info("Bridging WAF events from request_logs...")
    ch.command("""
        INSERT INTO aegisai_db.waf_events
            (event_id, request_id, site_id, server_id,
             timestamp, remote_addr, country_code,
             rule_id, rule_msg, rule_tag, severity,
             matched_data, matched_var, anomaly_score, action_taken)
        SELECT
            generateUUIDv4()                             AS event_id,
            request_id,
            site_id,
            server_id,
            timestamp,
            remote_addr,
            country_code,
            0                                            AS rule_id,
            'Nginx WAF Score Hit'                        AS rule_msg,
            'nginx_waf'                                  AS rule_tag,
            if(waf_score >= 10, 'CRITICAL',
               if(waf_score >= 5, 'HIGH', 'MEDIUM'))     AS severity,
            uri                                          AS matched_data,
            'uri'                                        AS matched_var,
            waf_score                                    AS anomaly_score,
            if(waf_score >= 5, 'block', 'detect')        AS action_taken
        FROM aegisai_db.request_logs
        WHERE waf_score > 0
          AND timestamp >= now() - INTERVAL 2 HOUR
          AND (request_id) NOT IN (
              SELECT request_id
              FROM aegisai_db.waf_events
              WHERE timestamp >= now() - INTERVAL 2 HOUR
                AND rule_tag = 'nginx_waf'
          )
    """)
    log.info("WAF bridge complete.")


def build_features(ch):
    """
    Compute behavior features and labels for all IPs in the last hour.
    This creates the training/inference dataset for the Isolation Forest model.
    """
    log.info("Starting behavioral feature aggregation (Last Hour)...")

    # This single query performs the heavy lifting:
    # 1. Grouping by IPv6 (native type handling)
    # 2. Computing 6 core behavioral features
    # 3. Applying Weak Labeling (attack=1 if WAF hit exists)
    # 4. Filter for IP diversity (ignore ultra-low volume noise)
    
    query = """
    INSERT INTO aegisai_db.ip_features
    SELECT
        remote_addr                                AS ip,
        toStartOfHour(now())                       AS hour_bucket,
        count()                                    AS request_count,
        count() / 60.0                             AS request_rate,
        uniqExact(uri)                             AS unique_endpoints,
        countIf(status_code >= 400) / count()    AS error_rate,
        countIf(waf_score > 0) / count()           AS attack_pct,
        toHour(now())                              AS hour_of_day,
        uniqExact(user_agent)                      AS ua_count,
        now()                                      AS computed_at
    FROM aegisai_db.request_logs
    WHERE timestamp >= now() - INTERVAL 1 HOUR
    GROUP BY remote_addr
    HAVING request_count >= 5
    """

    try:
        ch.command(query)
        # Ensure request_logs labels are also updated for supervised baseline
        ch.command("""
            ALTER TABLE aegisai_db.request_logs
            UPDATE label = 'attack' WHERE waf_score > 0 AND label = 'unknown'
        """)
        ch.command("""
            ALTER TABLE aegisai_db.request_logs
            UPDATE label = 'normal' WHERE waf_score = 0 AND label = 'unknown'
        """)
        log.info("Feature vectors computed and labels synchronized.")
    except Exception as e:
        log.error("Feature aggregation failed: %s", e)
        raise

def run():
    log.info("AegisAI-X Feature Builder (v2.0 IPv6) starting...")
    try:
        ch = clickhouse_connect.get_client(
            host=CH_HOST, port=8123, username=CH_USER,
            password=CH_PASSWORD, database=CH_DB, secure=False
        )
    except Exception as e:
        log.error("Failed to connect to ClickHouse: %s", e)
        return

    cycle = 0
    while True:
        try:
            bridge_waf_events(ch)          # runs every cycle (every 5 min)
            if cycle % (BUILD_INTERVAL // RUN_INTERVAL) == 0:
                build_features(ch)         # runs hourly
        except Exception as e:
            log.exception("Error in build cycle: %s", e)

        cycle += 1
        log.info("Sleeping for %ds...", RUN_INTERVAL)
        time.sleep(RUN_INTERVAL)

if __name__ == "__main__":
    run()
