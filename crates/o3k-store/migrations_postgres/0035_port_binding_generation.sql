ALTER TABLE network_ports
    ADD COLUMN binding_generation BIGINT NOT NULL DEFAULT 0
    CHECK (binding_generation >= 0);
