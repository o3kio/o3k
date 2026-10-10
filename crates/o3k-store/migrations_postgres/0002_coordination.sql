-- 0002_coordination.sql
-- Controller sessions and durable work leases with monotonic fencing tokens.

CREATE TABLE IF NOT EXISTS controller_sessions (
    controller_id VARCHAR(64) NOT NULL,
    controller_epoch VARCHAR(64) NOT NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    heartbeat_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    lease_until TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    software_version VARCHAR(64) NOT NULL,
    source_commit VARCHAR(64) NOT NULL,
    state VARCHAR(32) NOT NULL DEFAULT 'Active',
    PRIMARY KEY (controller_id, controller_epoch)
);

CREATE TABLE IF NOT EXISTS work_leases (
    work_key VARCHAR(255) PRIMARY KEY,
    work_kind VARCHAR(64) NOT NULL,
    owner_controller_id VARCHAR(64) NOT NULL,
    owner_controller_epoch VARCHAR(64) NOT NULL,
    fencing_token BIGINT NOT NULL DEFAULT 1,
    lease_until TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Fencing generations survive release of the currently active lease.  The
-- active row is intentionally removable, but its authority generation is not.
CREATE TABLE IF NOT EXISTS work_lease_fence_counters (
    work_key VARCHAR(255) PRIMARY KEY,
    fencing_token BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_work_leases_owner ON work_leases(owner_controller_id, owner_controller_epoch);
CREATE INDEX IF NOT EXISTS idx_work_leases_expiry ON work_leases(lease_until);
