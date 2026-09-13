CREATE TABLE IF NOT EXISTS bootstrap_state (
    state_id TEXT PRIMARY KEY,
    generation BIGINT NOT NULL CHECK (generation >= 0),
    phase TEXT NOT NULL,
    cloud_identity_id TEXT NOT NULL,
    cloud_profile_id TEXT NOT NULL,
    enrolled_agents TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS enrollment_grants (
    grant_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    token_digest TEXT NOT NULL,
    issued_at_unix_ms BIGINT NOT NULL CHECK (issued_at_unix_ms >= 0),
    expires_at_unix_ms BIGINT NOT NULL CHECK (expires_at_unix_ms >= issued_at_unix_ms),
    used_at_unix_ms BIGINT
);
CREATE INDEX IF NOT EXISTS enrollment_grants_agent_idx ON enrollment_grants(agent_id);
