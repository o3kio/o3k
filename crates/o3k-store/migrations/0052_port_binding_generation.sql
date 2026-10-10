ALTER TABLE network_ports
    ADD COLUMN binding_generation INTEGER NOT NULL DEFAULT 0
    CHECK (binding_generation >= 0);
