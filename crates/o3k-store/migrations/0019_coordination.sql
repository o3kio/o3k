-- 0019_coordination.sql
-- Controller sessions and durable work leases for SQLite store conformance.

CREATE TABLE IF NOT EXISTS controller_sessions (
    controller_id TEXT NOT NULL,
    controller_epoch TEXT NOT NULL,
    started_at TEXT NOT NULL DEFAULT (datetime('now')),
    heartbeat_at TEXT NOT NULL DEFAULT (datetime('now')),
    lease_until TEXT NOT NULL DEFAULT (datetime('now')),
    software_version TEXT NOT NULL,
    source_commit TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'Active',
    PRIMARY KEY (controller_id, controller_epoch)
);

CREATE TABLE IF NOT EXISTS work_leases (
    work_key TEXT PRIMARY KEY,
    work_kind TEXT NOT NULL,
    owner_controller_id TEXT NOT NULL,
    owner_controller_epoch TEXT NOT NULL,
    fencing_token INTEGER NOT NULL DEFAULT 1,
    lease_until TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Fencing generations survive release of the currently active lease.  The
-- active row is intentionally removable, but its authority generation is not.
CREATE TABLE IF NOT EXISTS work_lease_fence_counters (
    work_key TEXT PRIMARY KEY,
    fencing_token INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_work_leases_owner ON work_leases(owner_controller_id, owner_controller_epoch);
CREATE INDEX IF NOT EXISTS idx_work_leases_expiry ON work_leases(lease_until);
