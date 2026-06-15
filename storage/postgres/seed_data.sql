-- =============================================================================
-- AegisAI-X — PostgreSQL Seed Data (Development / Docker)
-- Pre-populates the DB so the SOC dashboard is not empty on first launch
-- =============================================================================

-- Default admin user (password: "aegisai-admin-2024")
-- Change password immediately after first login
INSERT INTO users (username, email, password_hash, mfa_enabled, role)
VALUES (
    'admin',
    'admin@aegisai.internal',
    '$2b$12$LQv3c1yqBWVHxkd26N8Q4.XEXkFBRFtAfU65kV3hNP/EJT.2VzB3K',  -- bcrypt of "aegisai-admin-2024"
    FALSE,
    'admin'
) ON CONFLICT (username) DO NOTHING;

-- Sample analyst user (password: "analyst123")
INSERT INTO users (username, email, password_hash, mfa_enabled, role)
VALUES (
    'analyst1',
    'analyst1@aegisai.internal',
    '$2b$12$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uivHT/Ra.',  -- bcrypt of "analyst123"
    FALSE,
    'analyst'
) ON CONFLICT (username) DO NOTHING;

-- Sample incidents for demo
INSERT INTO incidents (
    site_id, attack_type, severity, status,
    source_ip, source_country, event_count,
    endpoints_targeted, first_seen, last_seen
) VALUES
(
    'site_001', 'brute_force', 'HIGH', 'OPEN',
    '45.33.32.156', 'US', 847,
    ARRAY['/login', '/admin/login', '/api/v1/auth'],
    NOW() - INTERVAL '2 hours', NOW() - INTERVAL '15 minutes'
),
(
    'site_002', 'sqli', 'CRITICAL', 'INVESTIGATING',
    '185.220.101.34', 'RU', 23,
    ARRAY['/api/users?id=1', '/search?q=test'],
    NOW() - INTERVAL '45 minutes', NOW() - INTERVAL '5 minutes'
),
(
    'site_001', 'scanner', 'MEDIUM', 'ACKNOWLEDGED',
    '80.82.77.33', 'DE', 1205,
    ARRAY['/wp-admin', '/phpmyadmin', '/.env', '/config.php'],
    NOW() - INTERVAL '6 hours', NOW() - INTERVAL '1 hour'
),
(
    'site_003', 'ddos', 'HIGH', 'OPEN',
    NULL, NULL, 45230,
    ARRAY['/api/products', '/api/search'],
    NOW() - INTERVAL '30 minutes', NOW() - INTERVAL '1 minute'
),
(
    'site_002', 'xss', 'MEDIUM', 'RESOLVED',
    '192.241.135.144', 'US', 12,
    ARRAY['/comments', '/profile/bio'],
    NOW() - INTERVAL '2 days', NOW() - INTERVAL '2 days' + INTERVAL '20 minutes'
);

-- Add timeline entries for the incidents
DO $$
DECLARE
    inc_id UUID;
BEGIN
    -- Timeline for brute force incident
    SELECT id INTO inc_id FROM incidents WHERE attack_type = 'brute_force' AND site_id = 'site_001' LIMIT 1;
    INSERT INTO incident_timeline (incident_id, action, to_status, actor, detail) VALUES
    (inc_id, 'opened', 'OPEN', 'system', 'Auto-detected by rule: brute_force_auth — 847 auth failures from 45.33.32.156');

    -- Timeline for SQLi incident
    SELECT id INTO inc_id FROM incidents WHERE attack_type = 'sqli' AND site_id = 'site_002' LIMIT 1;
    INSERT INTO incident_timeline (incident_id, action, to_status, actor, detail) VALUES
    (inc_id, 'opened', 'OPEN', 'system', 'Auto-detected by rule: sql_injection_attempt — anomaly score 85'),
    (inc_id, 'status_changed', 'INVESTIGATING', 'analyst1', 'Confirmed SQLi attempt in access logs. Reviewing payload.');

    -- Timeline for scanner incident
    SELECT id INTO inc_id FROM incidents WHERE attack_type = 'scanner' AND site_id = 'site_001' LIMIT 1;
    INSERT INTO incident_timeline (incident_id, action, to_status, actor, detail) VALUES
    (inc_id, 'opened', 'OPEN', 'system', 'Auto-detected by rule: scanner_detected'),
    (inc_id, 'status_changed', 'ACKNOWLEDGED', 'admin', 'Known scanning IP — monitoring.');
END $$;

-- Sample blocked IPs
INSERT INTO ip_blocklist (ip, reason, source, blocked_by, expires_at) VALUES
('185.220.101.34', 'Active SQLi attack — incident #2', 'manual', 'analyst1', NOW() + INTERVAL '7 days'),
('45.33.32.156',   'Brute force — 847 auth failures', 'auto_brute_force', 'system', NOW() + INTERVAL '24 hours')
ON CONFLICT (ip) DO NOTHING;
