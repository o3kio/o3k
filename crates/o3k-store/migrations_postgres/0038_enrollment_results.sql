CREATE TABLE IF NOT EXISTS enrollment_results (
    grant_id TEXT PRIMARY KEY NOT NULL,
    agent_id TEXT NOT NULL,
    agent_epoch TEXT NOT NULL,
    token_digest TEXT NOT NULL,
    csr_sha256 TEXT NOT NULL,
    certificate_fingerprint_sha256 TEXT NOT NULL,
    client_certificate_chain_pem TEXT NOT NULL,
    ca_certificate_pem TEXT NOT NULL,
    ca_fingerprint_sha256 TEXT NOT NULL,
    certificate_expires_at_unix_ms BIGINT NOT NULL CHECK (certificate_expires_at_unix_ms >= 0),
    rotation_deadline_unix_ms BIGINT NOT NULL CHECK (rotation_deadline_unix_ms >= 0),
    issued_at_unix_ms BIGINT NOT NULL CHECK (issued_at_unix_ms >= 0),
    registered_at_unix_ms BIGINT CHECK (registered_at_unix_ms >= 0)
);
CREATE INDEX IF NOT EXISTS enrollment_results_agent_idx
    ON enrollment_results(agent_id, agent_epoch);
