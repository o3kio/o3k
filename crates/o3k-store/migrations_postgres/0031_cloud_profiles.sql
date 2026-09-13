CREATE TABLE IF NOT EXISTS cloud_profiles (
    profile_id TEXT PRIMARY KEY,
    generation BIGINT NOT NULL CHECK (generation >= 0),
    payload TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
