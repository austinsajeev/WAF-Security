-- =============================================================================
-- AegisAI-X — Phase 2.5+ Migration
-- Run this AFTER the initial incident_schema.sql
-- Adds: audit_log table, confidence_score on incidents, SOAR-lite TTL block field
-- =============================================================================

-- ---------------------------------------------------------------------------
-- TABLE: audit_log
-- Immutable SOC accountability log. Tracks all user-initiated actions.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_log (
    id          BIGSERIAL PRIMARY KEY,
    user_id     UUID REFERENCES users(id),
    username    VARCHAR(128) NOT NULL DEFAULT 'system',
    action      VARCHAR(64)  NOT NULL,   -- 'ip_block', 'ip_unblock', 'incident_state_change', 'blocklist_import'
    target_type VARCHAR(32)  NOT NULL,   -- 'ip', 'incident', 'blocklist'
    target_id   VARCHAR(256),            -- IP address or incident UUID
    detail      TEXT,                    -- human-readable summary
    metadata    JSONB,                   -- machine-readable context
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_log_user    ON audit_log (user_id, created_at DESC);
CREATE INDEX idx_audit_log_action  ON audit_log (action, created_at DESC);
CREATE INDEX idx_audit_log_target  ON audit_log (target_type, target_id);

-- ---------------------------------------------------------------------------
-- Add confidence_score to incidents (SOAR-lite policy engine)
-- low (0-39) = log only, medium (40-74) = alert, high (75-100) = auto-block
-- ---------------------------------------------------------------------------
ALTER TABLE incidents
    ADD COLUMN IF NOT EXISTS confidence_score  SMALLINT NOT NULL DEFAULT 50,
    ADD COLUMN IF NOT EXISTS auto_blocked      BOOLEAN  NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS block_ttl_seconds INTEGER;  -- NULL = permanent

-- ---------------------------------------------------------------------------
-- New alert_rules for cross-site correlation (Phase 2.5)
-- ---------------------------------------------------------------------------
INSERT INTO alert_rules (name, description, conditions, incident_severity, attack_type, dedup_window_seconds)
VALUES
(
    'cross_site_ip',
    'Same source IP attacking 2+ distinct sites within 10 minutes',
    '{"metric": "cross_site_ip", "window_seconds": 600, "min_sites": 2}',
    'CRITICAL', 'unknown', 600
),
(
    'cross_site_ua',
    'Same User-Agent fingerprint seen on 2+ distinct sites within 10 minutes',
    '{"metric": "cross_site_ua", "window_seconds": 600, "min_sites": 2}',
    'HIGH', 'bot', 600
)
ON CONFLICT (name) DO NOTHING;
