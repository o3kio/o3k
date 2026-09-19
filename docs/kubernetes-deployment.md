# Kubernetes Single-Controller Deployment

This document describes the OCI and Helm deployment model for running the
**O3K Control Plane** on Kubernetes as a first-class deployment target, conforming
to [ADR-0167](adr/ADR-0167-kubernetes-native-control-plane-deployment.md) and
[SPEC-0024](specs/SPEC-0024-product-profiles-and-claims.md).

## Architecture Overview

```text
       Kubernetes Cluster (Namespace: o3k-system)
   +-------------------------------------------------+
   |                                                 |
   |   Deployment: o3kd (replicas: 1)                |
   |   - Unprivileged UID 10001 (o3k:o3k)            |
   |   - PostgreSQL persistence required             |
   |   - PersistentVolumeClaim: /var/lib/o3k         |
   |   - Probes: /healthz, /readyz                   |
   |                                                 |
   |   Service: o3k-api (Port 5000 -> 8080)          |
   |   Service: o3k-compute (Port 18443 -> 18443)    |
   |                                                 |
   |   Secrets:                                      |
   |   - o3k-database (database-url)                 |
   |   - o3k-bootstrap-auth (password/signing-key)   |
   |   - o3k-control-tls (mTLS certs/CA)             |
   +-------------------------------------------------+
                           |
                           | gRPC / mTLS (Port 18443)
                           v
   +-------------------------------------------------+
   | External Hypervisor Host (KVM/libvirt)          |
   |                                                 |
   |   o3k-compute daemon                            |
   |   - Direct access to /dev/kvm and libvirt       |
   |   - Local network bridge and TAP management     |
   |   - Ephemeral guest disk overlays               |
   +-------------------------------------------------+
```

### Core Invariants

1. **Kubernetes operates the control plane; O3K operates the cloud**:
   - Kubernetes CRDs must NOT be created for O3K tenant resources (VMs, networks, ports, images).
   - Kubernetes API dependencies are hard-forbidden in Cloud Kernel crates (`crates/o3k-core`, `crates/o3k-store`, etc.).
2. **Single-Controller Invariant (`replicaCount: 1`)**:
   - P6 supports single-controller deployments only (`strategy: Recreate`).
   - `values.schema.json` and Helm template assertions strictly reject `replicaCount > 1`.
   - Multi-controller HA with lease fencing is deferred to P7.
3. **Database Invariant**:
   - PostgreSQL 16 is the required database backend.
   - SQLite is rejected at startup with `ConfigError::KubernetesRequiresPostgres`.
4. **Execution Isolation**:
   - Container runs as unprivileged user `10001:10001` with `readOnlyRootFilesystem: false` and dropped capabilities.
   - Privileged hypervisor access (`/dev/kvm`, libvirt, TAP devices) remains strictly external on hypervisor hosts.

---

## OCI Container Image

The container image packages `o3kd` (Cloud Kernel daemon) and `o3k` (diagnostic CLI).

- **Source Dockerfile**: [`deployments/docker/Dockerfile.o3kd`](../deployments/docker/Dockerfile.o3kd)
- **Local build Dockerfile**: [`deployments/docker/Dockerfile.o3kd-local`](../deployments/docker/Dockerfile.o3kd-local)
- **Image Name**: `ghcr.io/o3kio/o3kd:0.4.0-rc.4` (matching Cargo workspace version)
- **Security Posture**:
  - Base: Ubuntu 24.04 (matching host glibc)
  - Non-root user: `o3k:o3k` (UID/GID `10001`)
  - Entrypoint: `/usr/local/bin/o3kd`
  - Utility binaries: `genisoimage`, `ca-certificates`, `curl`

---

## Versioning and Artifact Consistency Policy

To prevent configuration drift and guarantee source-bound artifact integrity:
1. **Application Version Authority**: The Cargo workspace version in `Cargo.toml` (`[workspace.package].version`) is the canonical source of truth for the O3K application version (`0.4.0-rc.4`).
2. **Helm `appVersion`**: The Helm chart `appVersion` in [`deployments/helm/o3k/Chart.yaml`](../deployments/helm/o3k/Chart.yaml) strictly mirrors the Cargo workspace version.
3. **Helm `version`**: The Helm chart `version` (e.g. `0.1.0`) tracks chart packaging revisions independently from `appVersion` to allow packaging-only improvements without bumping application semver.
4. **OCI Image Tags**: The default image tag in `values.yaml` defaults to `.Chart.AppVersion`.
5. **OCI Image Labels**: Every OCI image is built with standardized OCI labels (`org.opencontainers.image.version`, `org.opencontainers.image.revision`, `org.opencontainers.image.source`).
6. **Automated Drift Gate**: [`tests/kubernetes-version-consistency.sh`](../tests/kubernetes-version-consistency.sh) runs in CI and strictly blocks any pull request where Cargo workspace version, Helm `appVersion`, default image tag, or Dockerfile metadata differ.

---

## Helm Chart

The Helm chart is located at [`deployments/helm/o3k`](../deployments/helm/o3k/).

### Chart Structure

```text
deployments/helm/o3k/
├── Chart.yaml
├── values.yaml
├── values.schema.json
└── templates/
    ├── _helpers.tpl
    ├── configmap.yaml
    ├── deployment.yaml
    ├── pvc.yaml
    ├── service-account.yaml
    ├── service-api.yaml
    └── service-compute.yaml
```

### Key Values Configuration

| Key | Default | Description |
|-----|---------|-------------|
| `replicaCount` | `1` | Strictly enforced `1` |
| `database.backend` | `"postgres"` | Must be `"postgres"` |
| `database.existingSecret` | `"o3k-database"` | Secret containing `database-url` |
| `persistence.enabled` | `true` | Durable PVC for image/artifact storage |
| `persistence.size` | `"10Gi"` | Size of persistent volume |
| `tls.enabled` | `false` | Enable mTLS for compute agent gRPC |
| `tls.existingSecret` | `"o3k-control-tls"` | Secret containing `server.pem`, `server-key.pem`, `ca.pem` |
| `tls.authorizedAgents` | `""` | Comma-separated `agent_id=sha256_fingerprint` |
| `auth.existingSecret` | `""` | Secret containing bootstrap password and signing key |
| `service.api.type` | `"ClusterIP"` | Service type for OpenStack REST API |
| `service.compute.type` | `"NodePort"` | Service type for external compute agent gRPC |

---

## In-Pod Diagnostics

Run `o3k doctor` inside the control plane container:

```bash
kubectl --namespace o3k-system exec -it deployment/o3k -- o3k doctor
```

In Kubernetes mode, `o3k doctor` automatically recognizes the container environment and returns `NOT_APPLICABLE` for host-only checks (systemd units, local `/dev/kvm`, local bridge interfaces), while strictly verifying:
- Control plane liveness (`/healthz`) and readiness (`/readyz`)
- PostgreSQL database connectivity and migration integrity
- PVC volume mount permissions
- Identity bootstrap credentials and token issuance
- Service discovery endpoints
- mTLS certificate validity

---

## Acceptance Test Suites

| Suite | Script | Scope |
|-------|--------|-------|
| Version Consistency Gate | `tests/kubernetes-version-consistency.sh` | Automated verification that Cargo version, Helm appVersion, and OCI image metadata match |
| Helm Lint & Schema Validation | `tests/helm-lint-and-template.sh` | Linting, rendering, and negative testing (rejection of replicaCount > 1, SQLite) |
| Portable TestLab | `tests/portable-kubernetes-testlab.sh` | Kind cluster + PostgreSQL 16 + Helm + Keystone/Glance/Nova/Neutron/Placement verification |
| Real KVM Acceptance | `tests/real-kubernetes-kvm-acceptance.sh` | External `o3k-compute` connecting via mTLS to `o3kd` on Kubernetes + CirrOS guest on KVM |
