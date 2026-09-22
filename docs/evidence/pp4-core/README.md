# PP.4 Core evidence

This directory is reserved for evidence from the dedicated PP.4 Core campaign.
It is deliberately separate from the historical Araf-oriented material under
`docs/evidence/pp4/`.

The immutable runtime candidate is `v0.4.0-rc.18` at source
`da00eeaa878956f438a62648f40c783e06a076d7` (archive SHA-256
`01d20d6676d4c56bb6630d9878a66a97d57a59cbeccf3934f4c12206ab5f8dcc`).

Status: **INCOMPLETE**. Public release integrity and exact-source CI are
green, and the campaign helper self-tests pass. The disposable smoke harness
reached public installation, release verification, canonical init/join,
BuildingBlock/compute readiness, TestLab image/network/keypair setup, and a
real TestLab libvirt guest boot. It then proved one native create through
`Operation=succeeded`, stable collision-safe port allocation (`192.0.2.3`
beside the compatibility port at `192.0.2.2`), a managed/running
`o3k-compute` libvirt domain, and guest console output. The required same-key
native replay returned HTTP 500 (`INTERNAL_ERROR`) after the first resource was
already active; this is a product/runtime idempotency defect in rc.18, not a
harness authentication failure. The exact redacted observation is recorded in
`rc18-native-replay-failure.json`.

Because the immutable candidate fails a mandatory PP.4 Core invariant, the
reverse compatibility workload, Horizon witness, Ubuntu full matrix, and
Debian full matrix were not run. No PP.4 Core certification or merge claim is
made. A runtime correction requires a successor public RC; rc.18 is retained
as a failed historical candidate.

The campaign attempts are retained as controller-local run directories under
`target/` and are not release evidence. They contain no credentials; temporary
credential files are created mode 0600 and removed by the VM harness trap.

## Successor: rc.19 cross-process replay proof

The rc.18 replay defect is corrected, and the successor candidate adds the
independent cross-process proof that the replay authority is durable rather
than process-local. The gate spawns two genuinely independent runtimes that
share only the durable store and requires them to converge on one canonical
identity with zero duplicate side effects. See
`rc19-cross-process-replay.json` for the gate, the durable invariants it
asserts, and the three convergence defects this proof exposed and corrected.

## rc.21 historical native evidence

`v0.4.0-rc.21` is an immutable published prerelease at source
`0a3fa9f186ba99cfee91a95e3df928b861e17667`. Its replay purpose succeeded: the
cross-process gate passed on both SQLite and PostgreSQL, covering sequential,
concurrent, in-flight, terminal, restart, and different-body conflict cases
with one canonical reservation, operation, resource, port, Placement
allocation, quota reservation, and provider execution. The fresh disposable
Ubuntu smoke also passed canonical init/join, native create, a real KVM guest,
same-key replay, and changed-body conflict. See
`rc21-native-smoke-pass.json` for the bounded smoke record.

rc.21 is not the final PP.4 Core candidate. The publisher generated and
manually verified a Sigstore bundle, but the public installer did not consume
that authentication before archive extraction. The two-OS PP.4 campaign,
bounded Horizon witness, full cross-interface lifecycle, reinstall/purge, and
foreign-state/secret evidence therefore remain **not-proven**. The successor
source now carries the two bounded repairs the pinned client proved necessary
(see below); the successor version is selected by tag/release enumeration at
publication time and no tag or publication occurs in this iteration.

## rc.22 failed candidate: unscoped Keystone authentication

`v0.4.0-rc.22` is an immutable published prerelease at source
`15162af7582f72d98475a79ee369e8902574ffee`. Its public trust chain is green
and its fresh disposable Ubuntu 24.04 KVM campaign passed release identity,
canonical init/join, BuildingBlock, public topology, Placement, native network
and native-first create, same-key replay, changed-body conflict, OpenStack
observation, compatibility create with native projection, and the
cross-interface lifecycle.

It then failed the required unmodified Horizon witness, and the failure is a
**product defect, not a harness defect**. Horizon 2024.1 authenticates
unscoped first — `openstack_auth.backend.KeystoneBackend.authenticate`
unconditionally calls `plugin.get_access_info(unscoped_auth, session=session)`
before scoping to a project, and no Horizon setting supplies a project that
would skip it. O3K rc.22 answers every unscoped (and every scope-less)
`POST /v3/auth/tokens` with `400 invalid authentication request`, while the
equivalent project-scoped request returns 201. `SPEC-0004` declares a project
scope only, so this is a declared-subset boundary rather than an accident —
but the subset cannot satisfy the Horizon journey that PP.4 Core requires.

Consequently rc.22 is a **failed immutable candidate**, PP.4 Core is
**INCOMPLETE** on it, the Debian matrix was not started, and Horizon was not
patched around the gap. Supporting unscoped authentication is a normative
scope change to `SPEC-0004` and requires an accepted issue/spec amendment
before implementation, followed by a successor RC. See
`rc22-horizon-unscoped-auth-defect.json` for the exact request/response
matrix, the canonical identities proven before the failure, and the
harness-defect lineage that preceded this classification.

## Successor preparation: bounded Keystone login slice and the 2026.1 witness

The successor candidate carries two bounded compatibility slices under SPEC-0022
baseline change control, both tracked as issues and neither claiming blanket
parity:

- **#1031 — Keystone/Horizon login bootstrap.** Tracing the real pinned client
  proved the sequence `POST /v3/auth/tokens` (unscoped) →
  `GET /v3/users/{user_id}/projects` → `POST /v3/auth/tokens` (project-scoped) →
  `GET /v3/projects`. O3K now answers all four, keeps an identity-only token
  unable to authorize any operation, and authorizes `GET /v3/projects` as an
  authorization-filtered project-visibility read rather than Keystone project
  administration.
- **#1032 — bounded collection pagination.** The pinned client's SDK guard
  reported `Endless pagination loop detected` because O3K ignored `limit` and
  `marker` and emitted no collection links, so the marker probe repeated a page
  instead of ending. The bounded fix covers only the Nova and Neutron
  collections the accepted journey exercises.

The Horizon witness is pinned to **OpenStack 2026.1**,
`quay.io/openstack.kolla/horizon:2026.1-ubuntu-noble` at OCI manifest digest
`sha256:723903d16317c53172f08c7f930b2c326f8b7fa16da98bf032e05ef287e0b048`
(Horizon `25.7.4.dev26`); `docs/evidence/pp4/horizon-artifact.yaml` records the
resolution and the date it was checked. The rc.22 references to Horizon 2024.1
above are historical and are deliberately never mixed with 2026.1 witness
evidence.

Two development confirmations exist for the successor slices, both explicitly
non-certifying because they were produced by hand-swapping a locally built
binary into the retained rc.22 VM:

- `rc23-dev-horizon-login-preflight.json` — the login slice reaches an
  authenticated session and exposes the remaining mandatory gaps.
- `rc23-dev-horizon-full-witness.json` — the complete bounded witness passes,
  including the Instances panel that previously answered HTTP 500, native
  resource visibility, O3K independence from Horizon, and recovery after the
  witness is re-created. It also records the residual client observations with
  their classification: the compute API-selector message as a harness defect,
  the pagination loop as an O3K defect (#1032), and the missing
  `/limits` and `os-simple-tenant-usage` reads as tracked recoverable gaps
  outside the accepted witness bar.
