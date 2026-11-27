# Issue #1241 — remote compute-host enrollment plan

- Issue: #1241
- Deployment/evidence profile: `o3k-early-access-v1`, Ubuntu 24.04, one to three hosts.
- Canonical domain: Cloud Kernel compute/agent identity and bootstrap enrollment.
- Compatibility adapter: none; existing `/bootstrap/join` authority is reused.
- Authority mode: O3K implemented; installation-local root-only TLS issuer on the controller.
- Expected files: `packaging/get-o3k.sh`, `packaging/bootstrap-certs.sh`, `bins/o3k/src/native_cli.rs`, `crates/o3k-native-api/src/bootstrap.rs`, controller adapter wiring, operator/EA enrollment documentation, and focused enrollment/revocation tests.
- Contracts: SPEC-0015 enrollment requires local key/CSR generation, server-authenticated transport, one-use grants, SAN binding, rotation/revocation; ADR-0191 requires EA installation-local trust and distinct host identities.
- Intended flow: replacement host generates key and CSR locally; controller signs only a grant-bound CSR using a root-owned mode-0600 installation-local CA key; communication is through an authenticated SSH tunnel to the controller-local bootstrap API; no private key or CA key crosses the boundary.
- Database/execution assumptions: existing durable enrollment grant, agent epoch fencing, certificate fingerprint binding, and `/bootstrap/join` projection remain canonical; no daemon is added.
- Tests first: CSR subject/SAN binding, grant scope and expiry, one-use signing, private-key non-export, restart persistence, revoked/stale certificate rejection, and clean two/three-host enrollment.
- Implementation note: SPEC-0015 §3 is authoritative. The implementation must add the EnrollRequest/CSR signing path while preserving the existing durable grant, agent-ID binding, epoch fencing, and revocation projections. The SSH tunnel is an additional guard; it cannot replace server-authenticated TLS.
- Non-goals: new daemon, copied CA/private keys, broad PKI lifecycle, enterprise HA, or changing existing authority semantics.
