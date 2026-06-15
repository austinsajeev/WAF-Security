-- =============================================================================
-- AegisAI-X — PostgreSQL Incident Schema
-- Phase 2: Incident lifecycle management
-- =============================================================================
-- Why PostgreSQL (not ClickHouse)?
--   ClickHouse is append-only / optimized for bulk reads.
--   Incidents need: UPDATE (status changes), transactions, FK constraints.
--   PostgreSQL is the right tool for mutable, relational incident state.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Extensions
-- ---------------------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";      -- UUID generation
CREATE EXTENSION IF NOT EXISTS "pg_trgm";        -- fuzzy text search on notes

-- ---------------------------------------------------------------------------
-- Enum Types
-- ---------------------------------------------------------------------------
CREATE TYPE incident_status AS ENUM (
    'OPEN',
    'ACKNOWLEDGED',
    'INVESTIGATING',
    'RESOLVED',
    'FALSE_POSITIVE'    -- reviewed and marked as not a real attack
);

CREATE TYPE incident_severity AS ENUM (
    'CRITICAL',         -- active breach / DDoS / mass attack
    'HIGH',             -- brute force / sustained WAF blocks
    'MEDIUM',           -- suspicious patterns requiring investigation
    'LOW',              -- informational
    'INFO'
);

CREATE TYPE attack_type AS ENUM (
    'sqli',
    'xss',
    'path_traversal',
    'brute_force',
    'ddos',
    'scanner',
    'api_abuse',
    'bot',
    'data_scraping',
    'anomaly',
    'unknown'
);

-- =============================================================================
-- TABLE: incidents
-- Core incident record, one row per correlated security event.
-- =============================================================================
CREATE TABLE incidents (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Identity
    site_id             VARCHAR(64)  NOT NULL,
    server_id           VARCHAR(128),

    -- Classification
    attack_type         attack_type  NOT NULL DEFAULT 'unknown',
    severity            incident_severity NOT NULL,
    status              incident_status   NOT NULL DEFAULT 'OPEN',
    
    -- Source data (links back to ClickHouse)
    source_ip           INET,                       -- primary attacker IP
    source_country      CHAR(2),                    -- ISO country code
    source_asn          INTEGER,
    rule_id             INTEGER,                    -- ModSecurity rule that triggered
    rule_tag            VARCHAR(128),
    
    -- Statistics (set by correlation engine, updated as events arrive)
    event_count         INTEGER NOT NULL DEFAULT 1, -- # of raw events correlated
    unique_ips          INTEGER NOT NULL DEFAULT 1,
    endpoints_targeted  TEXT[],                     -- array of URIs attacked
    
    -- Timeline
    first_seen          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    opened_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    acknowledged_at     TIMESTAMPTZ,
    resolved_at         TIMESTAMPTZ,
    
    -- Assignment & Ownership
    assigned_to         VARCHAR(128),               -- username/email of assignee
    
    -- Free-text investigation notes
    notes               TEXT,
    
    -- Resolution notes
    resolution          TEXT,
    
    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- ClickHouse correlation key (batch of raw log IDs linked to this incident)
    ch_query_filter     JSONB                       -- stored ClickHouse query to re-run for context
);

-- Indexes for dashboard queries
CREATE INDEX idx_incidents_site_id    ON incidents (site_id);
CREATE INDEX idx_incidents_status     ON incidents (status);
CREATE INDEX idx_incidents_severity   ON incidents (severity);
CREATE INDEX idx_incidents_opened_at  ON incidents (opened_at DESC);
CREATE INDEX idx_incidents_source_ip  ON incidents (source_ip);
CREATE INDEX idx_incidents_attack_type ON incidents (attack_type);
-- Full-text on notes for analyst search
CREATE INDEX idx_incidents_notes_trgm ON incidents USING GIN (notes gin_trgm_ops);


-- =============================================================================
-- TABLE: incident_timeline
-- Append-only audit log of all status changes and analyst actions.
-- Never updated — only inserted.
-- =============================================================================
CREATE TABLE incident_timeline (
    id              BIGSERIAL PRIMARY KEY,
    incident_id     UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    
    -- What happened
    action          VARCHAR(64) NOT NULL,          -- e.g. 'status_changed', 'note_added', 'assigned', 'ip_blocked'
    from_status     incident_status,
    to_status       incident_status,
    
    -- Who did it
    actor           VARCHAR(128) NOT NULL,          -- username, or 'system' for auto-actions
    
    -- Details
    detail          TEXT,
    metadata        JSONB,                          -- flexible key-value for action-specific data
    
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_timeline_incident_id ON incident_timeline (incident_id, created_at DESC);


-- =============================================================================
-- TABLE: ip_blocklist
-- Actively blocked IPs. Checked by the Gateway via Redis (synced from here).
-- =============================================================================
CREATE TABLE ip_blocklist (
    ip              INET PRIMARY KEY,
    reason          TEXT NOT NULL,
    source          VARCHAR(64) NOT NULL DEFAULT 'manual', -- 'manual', 'auto_brute_force', 'abuseipdb', etc.
    incident_id     UUID REFERENCES incidents(id),
    
    blocked_by      VARCHAR(128) NOT NULL,
    blocked_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ,                   -- NULL = permanent block
    
    -- Tracking
    unblocked_at    TIMESTAMPTZ,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE INDEX idx_blocklist_active    ON ip_blocklist (is_active, ip);
CREATE INDEX idx_blocklist_expires   ON ip_blocklist (expires_at) WHERE expires_at IS NOT NULL;


-- =============================================================================
-- TABLE: alert_rules
-- Configurable correlation rules used by the alert engine.
-- Stored in DB so they can be updated from dashboard without code deployments.
-- =============================================================================
CREATE TABLE alert_rules (
    id              SERIAL PRIMARY KEY,
    name            VARCHAR(128) NOT NULL UNIQUE,
    description     TEXT,
    
    -- Trigger conditions (JSON config evaluated by correlation engine)
    conditions      JSONB NOT NULL,
    -- Example:
    -- {
    --   "metric": "waf_block_rate",
    --   "window_seconds": 120,
    --   "threshold": 50,
    --   "per": "site_id"
    -- }
    
    -- Resulting incident
    incident_severity  incident_severity NOT NULL DEFAULT 'HIGH',
    attack_type        attack_type NOT NULL DEFAULT 'unknown',
    
    -- Aggregation: how many raw events → 1 incident
    dedup_window_seconds  INTEGER NOT NULL DEFAULT 300,  -- suppress duplicate incidents for 5 min
    
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed with default correlation rules
INSERT INTO alert_rules (name, description, conditions, incident_severity, attack_type, dedup_window_seconds) VALUES
(
    'mass_waf_blocks',
    'More than 50 WAF blocks per minute on a single site',
    '{"metric": "waf_block_rate", "window_seconds": 60, "threshold": 50, "group_by": "site_id"}',
    'CRITICAL', 'unknown', 600
),
(
    'brute_force_auth',
    'More than 20 auth failures from a single IP in 5 minutes',
    '{"metric": "auth_failure_rate", "window_seconds": 300, "threshold": 20, "group_by": "source_ip"}',
    'HIGH', 'brute_force', 900
),
(
    'sql_injection_attempt',
    'Any SQLi rule hit with anomaly score > 20',
    '{"rule_tag": "aegisai/sqli", "min_anomaly_score": 20}',
    'HIGH', 'sqli', 300
),
(
    'xss_attempt',
    'Any XSS rule hit with anomaly score > 20',
    '{"rule_tag": "aegisai/xss", "min_anomaly_score": 20}',
    'MEDIUM', 'xss', 300
),
(
    'traffic_spike',
    'Request rate 3x above 1h baseline for a site',
    '{"metric": "request_rate_multiplier", "window_seconds": 300, "threshold": 3.0, "group_by": "site_id"}',
    'HIGH', 'ddos', 900
),
(
    'scanner_detected',
    'Known scanner UA string detected',
    '{"rule_tag": "aegisai/scanner", "event_count": 1}',
    'MEDIUM', 'scanner', 120
);


-- =============================================================================
-- TABLE: users (SOC Dashboard RBAC)
-- =============================================================================
CREATE TABLE users (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username    VARCHAR(64) NOT NULL UNIQUE,
    email       VARCHAR(128) NOT NULL UNIQUE,
    
    -- Auth
    password_hash  VARCHAR(256) NOT NULL,          -- bcrypt hash
    mfa_secret     VARCHAR(64),                    -- TOTP secret (NULL = MFA not enrolled)
    mfa_enabled    BOOLEAN NOT NULL DEFAULT FALSE,
    
    -- RBAC
    role        VARCHAR(32) NOT NULL DEFAULT 'analyst',  -- 'admin', 'analyst', 'viewer'
    
    -- Access control per site
    site_access TEXT[] DEFAULT '{}',               -- empty = access all sites (for admin)
    
    -- Auth state
    last_login  TIMESTAMPTZ,
    is_active   BOOLEAN NOT NULL DEFAULT TRUE,
    
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- =============================================================================
-- Trigger: auto-update updated_at on incidents and users
-- =============================================================================
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER incidents_updated_at
    BEFORE UPDATE ON incidents
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
