ALTER TABLE placement_providers ADD COLUMN parent_provider_id TEXT REFERENCES placement_providers(id);
ALTER TABLE placement_providers ADD COLUMN location TEXT;

CREATE INDEX IF NOT EXISTS idx_placement_providers_parent ON placement_providers(parent_provider_id);
CREATE TABLE IF NOT EXISTS placement_provider_traits (
    provider_id TEXT NOT NULL REFERENCES placement_providers(id) ON DELETE CASCADE,
    trait TEXT NOT NULL,
    PRIMARY KEY (provider_id, trait)
);
CREATE TABLE IF NOT EXISTS placement_provider_failure_domains (
    provider_id TEXT NOT NULL REFERENCES placement_providers(id) ON DELETE CASCADE,
    failure_domain_id TEXT NOT NULL,
    PRIMARY KEY (provider_id, failure_domain_id)
);
