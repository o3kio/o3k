# SPEC-0048 — PP.0 Demo and Small-Edge v1 Baseline Freeze

Status: Accepted with PP.0 (issue #969; contract-freeze definitions, no new
support claims; human approval recorded in the PP.0 PR review)
Related issue: [#969](https://github.com/o3kio/o3k/issues/969) (PP.0), [#968](https://github.com/o3kio/o3k/issues/968) (Production Phase umbrella)
Related decision: [ADR-0184](../adr/ADR-0184-p15-scale-and-composition-foundation.md), [SPEC-0047](SPEC-0047-p15-scale-and-composition-foundation.md)
Related contracts: [contracts/release-bundle-v1.yaml](../../contracts/release-bundle-v1.yaml), [contracts/installer-v1.yaml](../../contracts/installer-v1.yaml), [contracts/araf-compatibility-v1.yaml](../../contracts/araf-compatibility-v1.yaml), [compatibility/product-profiles.yaml](../../compatibility/product-profiles.yaml)

## 1. Purpose

P15 established the canonical scale/composition authorities (LocationRegistry
topology, Placement, ManifestRegistry, CloudProfile, BuildingBlock, agent
registry, canonical init/join, IAM/PKI — ADR-0184/SPEC-0047), and the
protected P15.7 convergence gate passed at the exact completion SHA
096e4679 (run 35365369016). PP.0 turns that completed foundation into a
precisely defined product baseline before any new release is published or
installed.

PP.0 answers: *what exactly is `o3k-demo-v1`, what exactly is
`o3k-small-edge-v1`, and what binaries, services, configuration, release
artifacts, and installer behavior are required to instantiate those
profiles?*

PP.0 creates **definitions, not support claims**.

## 2. Scope and non-goals

PP.0 is an audit + contract freeze. It freezes definitions; it does not
build, publish, or install anything.

Non-goals (verbatim boundaries): no release publication; no PP.1
implementation; no installer architecture rewrite; no Araf deployment; no
P16/P17/P18/P19 work; no new schedulers, topology authority, service
breadth, or cells/sharding; no live migration; no automatic evacuation; no
production-readiness claims. The two stale pre-P15 installer assumptions
found by the audit (target compilation in `packaging/install.sh` and raw
`openstack` CLI topology in `packaging/bootstrap-testlab.sh`) and the
missing `o3k-network.service` unit are recorded in the contracts as PP.1
implementation requirements, not silently preserved.

## 3. Claim-truth mechanism

The #433 machinery remains the single claim-truth mechanism: the frozen
profiles are validated by `scripts/validate-profile-state.py` (profile set,
field contract, evidence vocabulary, profile-scoped evidence with explicit
`shared_run`/`inherited_from` rules, source commits, tracker consistency),
and the release/installer/Araf contract files are validated by
`tests/pp0-contracts.sh`, which runs both standalone and through the
`tests/profile-state.sh` governance entry point.

## 4. The frozen profiles

Both profiles are registered in `compatibility/product-profiles.yaml` with
matching state records in `docs/status/current-state.yaml` (the #433
machinery, `scripts/validate-profile-state.py`, remains the single
claim-truth mechanism).

### 4.1 o3k-demo-v1

Single supported Linux x86_64 host (Ubuntu 24.04 / Debian 12), local
KVM/libvirt, canonical `o3k init`, authenticated local `o3k join`, one local
BuildingBlock, real native O3K API, real Placement, real topology, real
CloudProfile, real compute, bounded flat networking, bounded image handling,
native ephemeral-root storage, SQLite default.

This profile is for demo, development, and evaluation. It is **not**
production, HA, multi-node, multi-region, datacenter scale, live migration,
or automatic evacuation. Araf is not required for correctness (see §9).

### 4.2 o3k-small-edge-v1

One site; 1–20 hypervisor **target envelope** (a PP hardening target, not a
support claim until PP.5 evidence); authenticated BuildingBlock lifecycle;
durable topology; capability-aware Placement; CloudProfile; real compute
execution; bounded network/storage profiles; PostgreSQL production target;
native O3K API; selected OpenStack and Terraform/OpenTofu compatibility.

Explicitly excluded: multi-region, cells/sharding, arbitrary datacenter
scale, automatic evacuation, live migration, arbitrary OpenStack parity,
unsupported external services.

## 5. Authority boundary (installer and packaging)

PP packaging/install logic may **orchestrate** the canonical P15
authorities. It must **never** recreate them. The installer must not
directly fabricate topology, Placement providers, BuildingBlocks,
CloudProfile state, service readiness, or agent identity when canonical P15
workflows (`o3k init` / `o3k join`) exist.

Audit finding (STALE-PRE-P15): `packaging/bootstrap-testlab.sh` still
provisions its TestLab topology via raw `openstack` CLI calls instead of the
canonical init/join path used by the protected P15.7 runner. It must be
reconciled in PP.1/PP.2; the frozen contract forbids extending that pattern.

## 6. Release bundle contract

`contracts/release-bundle-v1.yaml` freezes the canonical assets:
`install.sh`, `o3k-<version>-linux-x86_64.tar.gz` (+ `.sha256`),
`manifest.json`, `SHA256SUMS`, SPDX SBOM, and provenance/signature material.
The GitHub Release asset is the canonical public distribution source;
`get.o3k.io` is only a convenience redirect/reviewed entrypoint and must
never become an independent artifact authority. Every installed binary must
be traceable to release version, source SHA, manifest, checksum, and
SBOM/provenance. Target hosts must not compile O3K from source.

Known gaps (PP.1 implementation required, not PP.0 scope): no automated
release pipeline publishes the bundle yet, and authenticity
signature/provenance attestation does not exist yet (SHA-256 integrity
exists today).

## 7. Installer, lifecycle, and upgrade semantics

`contracts/installer-v1.yaml` freezes:

- installer phases: preflight → artifact verification → install → canonical
  prerequisites → canonical init/join → canonical readiness wait → safe
  credential exposure; re-runs are convergent; unsupported environments fail
  before destructive mutation;
- lifecycle safety: `reset`, `uninstall`, and `purge` are distinct; nothing
  foreign (VMs, pools, bridges, PostgreSQL data, containers, certificates,
  files) is deleted without O3K ownership proof (reusing, not duplicating,
  the P15.7 fail-closed ownership model); ambiguous state is reported and
  preserved;
- upgrade boundary: same-version re-run converges; upgrades go forward only
  through the fenced `o3k upgrade` path with schema/version checks and
  backup; arbitrary downgrade/rollback is not promised (general
  rollback/crash-resume remains issue #640 / PP.6–P17).

## 8. Runtime component requirements

The per-profile runtime component tables (required/optional, binary, user,
authority, readiness) live in `compatibility/product-profiles.yaml` under
each frozen profile. Summary: both profiles require `o3kd`, `o3k`, and
`o3k-compute` (libvirt/KVM agent); `o3k-small-edge-v1` additionally requires
the `o3k-network` execution agent; there is no `o3k-storage` daemon (native
storage is an in-process library; external Cinder remains external per
SPEC-0023).

## 9. Araf compatibility boundary

`contracts/araf-compatibility-v1.yaml` freezes the model: an O3K release
plus a separately versioned compatible Araf release; PP must eventually pin
an exact Araf version/digest. Araf consumes real O3K native APIs, owns no
O3K state, and is not required for `o3kd` readiness. No fixture/demo fake
mode may satisfy the final real demo profile. PP.3 owns artifact/deployment
integration; PP.4A owns Araf native-console certification. PP.4 Core owns
the O3K-native lifecycle and the bounded OpenStack/Horizon compatibility
witness independently of Araf browser/runtime readiness.

Horizon is an unmodified external OpenStack compatibility witness, never the
O3K product dashboard or a readiness authority. Its exact version and
artifact/provider digest are pinned by the PP.4 Core evidence manifest; it
does not become a product dependency.

## 10. Claim discipline

PP.0 makes no production-readiness, GA, HA, multi-region, live-migration,
automatic-evacuation, or proven 1–20-host-scale claims. Every profile claim
remains subject to #433 validation and the evidence vocabulary of
SPEC-0024.

## 11. Phase boundaries

- PP.0 (this spec): what exactly are we going to ship?
- PP.1: can we build and publish the exact release artifact?
- PP.2: can a fresh supported machine install and run it through the
  canonical P15 bootstrap path?

Later PP phases own Araf deployment integration (PP.3), Araf native-console
certification (PP.4A), O3K Demo/Core acceptance (PP.4), and scale evidence
(PP.5). PP.0 does not start any of them.
