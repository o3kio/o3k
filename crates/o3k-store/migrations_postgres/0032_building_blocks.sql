CREATE TABLE IF NOT EXISTS building_blocks (
    block_id TEXT PRIMARY KEY,
    generation BIGINT NOT NULL CHECK (generation >= 0),
    state TEXT NOT NULL,
    execution_identity TEXT NOT NULL,
    resource_provider_ids TEXT NOT NULL,
    failure_domain_id TEXT,
    cloud_profile_id TEXT,
    drain_blockers TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
