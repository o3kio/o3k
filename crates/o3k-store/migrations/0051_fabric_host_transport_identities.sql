CREATE TABLE canonical_fabric_host_transport_identities (
    host_id TEXT PRIMARY KEY NOT NULL,
    agent_id TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL UNIQUE,
    underlay_endpoint TEXT NOT NULL,
    fabric_transport_ip TEXT NOT NULL UNIQUE,
    provider_version TEXT NOT NULL,
    fabric_generation INTEGER NOT NULL CHECK (fabric_generation > 0),
    underlay_mtu INTEGER NOT NULL CHECK (underlay_mtu > 0),
    fabric_mtu INTEGER NOT NULL CHECK (fabric_mtu > 0 AND fabric_mtu < underlay_mtu),
    administrative_state TEXT NOT NULL CHECK (administrative_state IN ('enabled', 'disabled', 'draining'))
);
