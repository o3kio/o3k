CREATE TABLE IF NOT EXISTS network_plan_work (
    command_id TEXT PRIMARY KEY, operation_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE, target_host_id TEXT NOT NULL,
    target_agent_id TEXT NOT NULL, target_agent_epoch TEXT NOT NULL,
    controller_id TEXT NOT NULL, controller_epoch TEXT NOT NULL,
    fencing_token BIGINT NOT NULL, deadline_unix_ms BIGINT NOT NULL,
    fingerprint_sha256 TEXT NOT NULL, snapshot BYTEA NOT NULL,
    state TEXT NOT NULL, revision BIGINT NOT NULL DEFAULT 0,
    outcome BYTEA, created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS network_plan_work_unresolved_idx ON network_plan_work(state, created_at);
