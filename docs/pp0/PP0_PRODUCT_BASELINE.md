# PP.0 — Product Baseline Freeze (Demo v1 / Small-Edge v1)

Tracking: issue #969 (PP.0), umbrella #968 (Production Phase).
Normative: [SPEC-0048](../specs/SPEC-0048-pp0-demo-and-small-edge-baseline-freeze.md).
Baseline: protected main `096e46792aad3af1e425fb844f449c4dcbfa5da2` (P15
complete; protected certification run
[35365369016](https://github.com/o3kio/o3k/actions/runs/35365369016) passed
the P15.7 convergence gate at the exact completion SHA).

PP.0 answers **"what exactly are we going to ship?"**. It freezes contracts
only. PP.1 asks "can we build and publish the exact release artifact?", and
PP.2 asks "can a fresh supported machine install and run it through the
canonical P15 bootstrap path?".

## 1. The two frozen profiles

| | o3k-demo-v1 | o3k-small-edge-v1 |
|---|---|---|
| Purpose | demo / development / evaluation | one-site production hardening |
| Hosts | single x86_64 host | 1–20 hypervisor **target envelope** (not a proven support claim) |
| OS | Ubuntu 24.04 / Debian 12 | Ubuntu 24.04 / Debian 12 |
| Compute | libvirt/KVM via `o3k-compute` agent | same, per hypervisor |
| Network | bounded flat bridge | bounded declared network profile (`o3k-network` agent required) |
| Storage | native ephemeral-root only | bounded declared storage profile |
| Database | SQLite default, PostgreSQL target | SQLite w/ documented limits, PostgreSQL production target |
| Bootstrap | canonical `o3k init` + authenticated `o3k join`, one local BuildingBlock | authenticated BuildingBlock lifecycle |
| Araf | optional client only | optional client only (PP.3/PP.4) |

Both are machine-readable in `compatibility/product-profiles.yaml` with
matching state records in `docs/status/current-state.yaml`; #433 validation
(`scripts/validate-profile-state.py`, plus `tests/pp0-contracts.sh` invoked
through the `tests/profile-state.sh` governance entry point) remains the
single claim-truth mechanism. The `supported_targets` block in each profile
is the frozen build/install target envelope, explicitly **not** an OS
support claim until PP.2 fresh-install evidence exists.

**Not claimed by either profile:** production readiness, GA, HA,
multi-region, cells/sharding, datacenter scale, live migration, automatic
evacuation, arbitrary OpenStack parity, proven 1–20-host scale.

## 2. Runtime component requirements (audit summary)

| Component | Demo | Small-Edge | Binary | User | Authority | Readiness |
|---|---|---|---|---|---|---|
| `o3kd` control plane | required | required | `o3kd` | `o3k` | Cloud Kernel controller | `/readyz` runtime+bootstrap gates |
| `o3k` CLI | required | required | `o3k` | operator | operator entrypoint | `o3k doctor` exit 0 |
| `o3k-compute` | required | required | `o3k-compute` | `o3k-compute` (+`libvirt`,`kvm`) | execution boundary only | `/readyz` :9100 |
| `o3k-network` agent | not packaged | required | `o3k-network` | — | execution boundary only | startup reconcile |
| libvirt/KVM + dnsmasq | required | required | host packages | — | none (host) | `qemu:///system` capabilities |
| native storage | in-process library | in-process library | — | — | `o3kd` work-lease | volume manifest ready |
| external Cinder | not in this profile | not in this profile | external | — | external-owned (SPEC-0023) | o3kd probe |

There is no `o3k-storage` daemon; native storage is an in-process library in
`o3kd`. PKI/enrollment is the canonical P15.6 path: `o3k init` issues a
single-use enrollment grant; `o3k join` presents the agent certificate
(public material only); identities are certificate-bound.

## 3. Installer/release machinery audit (classification)

| Assumption / machinery | Classification |
|---|---|
| `get-o3k.sh` download → sha256 verify → `install.sh` → health gates | VALID |
| `install.sh` ownership markers, foreign-file refusal, install manifest | VALID |
| `install.sh` cargo-compiles `o3kd`/`o3k`/`o3k-compute` on target when prebuilt binaries are absent | **RESOLVED in PP.1 (v0.4.0-rc.1)** — release bundles now fail closed on a missing required binary; cargo fallback remains only for repo-tree dev installs |
| Upgrade fence (semver compare, delegate-download, no auto-upgrade) | VALID |
| `o3k upgrade` engine (schema/version fence, doctor gate, backup) | VALID |
| reset/uninstall/purge ownership fencing (P15.7 fail-closed model) | VALID |
| systemd units `o3kd.service` / `o3k-compute.service` | VALID |
| `o3k-network.service` unit for the small-edge network agent | **RESOLVED in PP.1 (v0.4.0-rc.1)** — unit shipped, installed but never enabled (canonical init/join enrollment) |
| `packaging/bootstrap-testlab.sh` (raw `openstack` CLI topology, no init/join) | **STALE-PRE-P15** — reconcile in PP.1/PP.2 |
| Automated release pipeline publishing to GitHub Releases | **PARTIAL in PP.1** — first RC published via the operator-run pipeline scripts; a protected GitHub Actions release workflow remains follow-up |
| Artifact signature/provenance attestation | **RESOLVED in PP.1 (v0.4.0-rc.1)** — ed25519 release key (`release-verify.pub` committed), `release-digests.txt/.sig` + `provenance.json` published per release |
| `o3k-network` packaging/unit | **RESOLVED in PP.1 (v0.4.0-rc.1)** — binary built (Debian-12 baseline), bundled, installed |
| Full upgrade/rollback/crash-resume | **LATER-PHASE** — issue #640 / PP.6–P17 |
| Araf deployment integration | **LATER-PHASE** — PP.3/PP.4 |

## 4. Frozen contracts

- `contracts/release-bundle-v1.yaml` — release assets, bundle contents,
  distribution model (GitHub Release is canonical; get.o3k.io is a
  convenience redirect only), traceability.
- `contracts/installer-v1.yaml` — installer phases and authority boundary,
  convergent re-run, lifecycle safety (reset ≠ uninstall ≠ purge; no foreign
  deletion without ownership proof), upgrade boundary.
- `contracts/araf-compatibility-v1.yaml` — Araf is a separately versioned
  client, consumes real native APIs, owns no O3K state, not required for
  readiness; exact version pinning required before integration ships.

## 5. What PP hardens next

- **PP.1**: build/publish the exact release bundle (incl. signing/provenance,
  `o3k-network` packaging, TestLab bootstrap reconciliation).
- **PP.2**: fresh supported machine installs and runs via canonical
  init/join.
- **PP.3/PP.4**: Araf deployment integration (real APIs, pinned version).
- **PP.5**: 1–20 hypervisor scale evidence before any support claim.

## 6. Still unsupported

Multi-region, cells/sharding, live migration, automatic evacuation, HA,
production/GA claims, arbitrary OpenStack parity, native persistent volumes
(alpha gate remains ephemeral-root), and any scale claim beyond the evidence
recorded in `docs/status/current-state.yaml`.
