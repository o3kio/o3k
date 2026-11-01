# #1086 A10 Phase B and C1 installed qualification plan

Status: executable qualification plan and infrastructure inventory. No C1
installed qualification was run by this work. Synthetic journal signatures are
test-only and are not production evidence.

## Scope and authority

- Issue: #1086 under PP.6 #975; bounded implementation also references #1086.
- Profile: virtualized `o3k-small-edge-v1`, PostgreSQL 16, inactive branch only.
- Domain: O3K recovery journal and installation/startup exclusion.
- Authority mode: O3K-owned recovery protocol; no OpenStack adapter or public
  API. Existing D8 protected-directory and target reservation primitives remain
  the filesystem/lock authority.
- Contracts consulted: ADR-0189 A10/C1/C1.1, ADR-0190, SPEC-0050 §§7.1–7.3,
  §8, and `docs/pp/PP6_TECHNICAL_CONTRACT_APPROVAL.md`.
- Exact source baseline: `107ded898df4b2da6ca6c4d3c5672cc2a7afd453`.
- Bounded Phase B files: `bins/o3k/src/restore_journal_v2.rs`, module export in
  `bins/o3k/src/lib.rs`, and this evidence plan.
- No backup format, database schema, migration, service topology, API, provider,
  controller, or C1.1 checkpoint format is changed.

## Qualification sequence

1. **Select an immutable candidate.** Merge the exact-head reviewed bounded
   implementation. Use the existing protected release tag/release environment
   workflow in `.github/workflows/release.yml`; verify the signed GitHub
   OIDC/Sigstore release bundle, provenance, tag commit, source tree, archive,
   installed manifest, and binary digests. Do not assemble a local replacement
   release or alter the immutable tag. Candidate must include the A10 code and
   the later separately accepted C1 policy-selection contract before runtime
   use.
2. **Provision clean guests.** Use the existing online `runner-2404`
   (`self-hosted`, `Linux`, `X64`, `kvm`, `libvirt`, `docker`, `o3k-testlab`)
   only as a disposable VM host. Create two clean, isolated guests from
   authenticated Debian 12 and Ubuntu 24.04 cloud images. Each guest needs a
   local ext4 filesystem reserved for `/var/lib/o3k-recovery-state` and
   `/var/lib/o3k-recovery`, with the exact C1/D8 owners, groups, modes and
   device/inode recorded in the signed installation policy. No host bind mount
   to canonical O3K state; no shared PostgreSQL or production network route.
3. **Install and attest.** Install through the public authenticated candidate
   path. Record guest image digest, OS release/kernel, candidate tag/source SHA,
   Sigstore bundle verification, installed release manifest, package/file
   ownership, systemd unit hash/state, recovery paths and ext4 mount facts.
4. **Perform custody ceremony.** A human recovery custodian generates or
   activates the separate offline `restore_journal` signer under the approved
   custody procedure, issues an exact site/installation/profile/backend scoped
   short-lived journal-authority certificate, signs current revocation state,
   and distributes the authenticated trust bundle through the independently
   administered trust-distribution channel. Record key IDs, purpose, serial,
   validity, revocation sequence/digest and custody witnesses, never private
   key material. The private journal key must never enter either VM.
5. **Run installed denial matrix.** On both clean guests, install a synthetic
   isolated inactive journal created by the approved test-signing setup and
   verify ordinary `o3kd` systemd start, direct CLI/maintenance store opening,
   upgrade, rollback, restart and reboot all deny operational store access for
   every inactive phase including `INACTIVE_VERIFIED`. Verify no readiness/API
   listener, lease/controller ownership, reconciliation, provider dispatch or
   source database access. Capture bounded logs, unit/process/socket state,
   store-open audit evidence, and before/after hashes for canonical state.
   Then remove only the disposable guests and preserve the signed evidence.
6. **Review exact evidence.** A reviewer checks candidate provenance, each
   VM's installed identity, signer purpose/scope/freshness/revocation,
   ext4/path binding, denial matrix, zero canonical-store/database mutation,
   no API readiness/provider dispatch, and clean resource teardown. Test signer
   evidence remains explicitly non-production.

## Missing resources and human actions

- **Available from repository settings:** one online KVM/libvirt/Docker
  self-hosted Actions runner (`runner-2404`); protected release workflow uses
  GitHub OIDC and Sigstore; CI has PostgreSQL 16 service containers. These do
  not themselves provide clean installed qualification guests or offline
  custody.
- **Not demonstrated available:** two disposable clean guest allocations with
  authenticated Debian 12 and Ubuntu 24.04 images, isolated networks, local
  ext4 journal/state volumes, console/serial capture and reliable destruction.
  The current online runner is one VM host; reserve capacity for two guests or
  obtain a second isolated host if concurrent independent OS evidence is
  required.
- **Not demonstrated available:** an exact A10/C1-enabled published release
  candidate. Existing release workflow can produce one only after protected
  merge and an approved immutable release tag; current PP.4 candidates do not
  establish the recovery support claim.
- **Missing contract input:** C1 `InstallationPolicy` currently lacks the
  explicit signed A10 inactive-branch selection and deployment binding required
  by SPEC-0050 §7.1. The installed verifier cannot safely authorize journal-v2
  from the existing policy. A narrow normative SPEC/ADR amendment and matching
  signed-policy schema/model update are required before installed A10 use.
- **Human custody actions required:** name the recovery custodian and witnesses;
  approve offline signer hardware/storage and ceremony; create the
  `restore_journal` key/certificate and separate trust root; approve trust
  distribution endpoint/operator and revocation publication cadence; authorize
  a test-only isolated signer only for non-production denial tests; approve
  access to the release environment/tag and qualification guests. No production
  keys may be fabricated or replaced for this work.
- **Distinct PostgreSQL Option B dependency:** the online artifact-signing
  HSM/PKCS#11 service, its accepted transport/trust schema, and its custody
  procedure are separate from the offline C1 journal/evidence signer. They are
  not needed to validate synthetic Phase B signatures and are not satisfied by
  the journal signer.

## Acceptance/evidence limits

The Phase B unit fixtures use deterministic test-only Ed25519 keys. They prove
protocol behavior only. The code has no PostgreSQL restore executor and this
campaign creates no database, restores no dump, materializes no target, reads
no canonical source database, and enables no service. C1 installed startup
denial and release qualification remain NOT RUN until the missing contract and
infrastructure/custody prerequisites above are provided.

## Phase B implementation run evidence

- Previous checkpoint command status/log: **unavailable**. No prior Cargo
  process, exit-status file, or retained log was present when this work resumed;
  no result is inferred for that run.
- Protected baseline: `HEAD` and `git merge-base HEAD
  107ded898df4b2da6ca6c4d3c5672cc2a7afd453` both equal
  `107ded898df4b2da6ca6c4d3c5672cc2a7afd453`.
- `cargo test -p o3k restore_journal_v2 --all-features`: exit 0, 9 passed.
- `cargo test -p o3k --all-features`: exit 0. The package suite passed,
  including 40 C1 reanchor tests and 6 restore-preflight tests. Existing
  root/unshare/ext4-dependent tests reported ignored under their declared
  prerequisites; no ignored result is counted as qualification evidence.
- `cargo fmt --all -- --check`: exit 0.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`:
  exit 0.
- The full `cargo test --workspace --all-features` command was not run. The
  workspace contains PostgreSQL integration tests that create/drop databases
  and restore dumps (including `crates/o3k-store/tests/postgres_ops.rs`); that
  would cross the explicit Phase B no-database-mutation boundary. No PostgreSQL
  target or dump was created/restored by this campaign.
- Initial v2 unit-test attempts failed because test assertions disagreed with
  the allowed `FILES_RESTORED_INACTIVE -> INACTIVE_VERIFIED` transition and a
  v1-format scan used an incorrect window. Both were corrected before the
  passing run. Captured logs are `/tmp/o3k-a10-v2-targeted-cargo-test.log`,
  `/tmp/o3k-a10-v2-targeted-cargo-test-2.log`, and
  `/tmp/o3k-a10-v2-targeted-final.log`.
- The existing D8 protected-file crash test now covers before file fsync,
  after file fsync, after rename, and after directory fsync. Its three
  privileged ext4 tests are ignored in the package run because this process is
  unprivileged; their crash-boundary behavior is therefore **not verified on
  this host**. The v2 publisher uses the D8 protected-directory CAS/fsync/rename
  primitive and has no separate authority or mutation executor.
- Synthetic Ed25519 fixtures are protocol tests only. Startup denial is exposed
  as a pure validation boundary; installed systemd/maintenance/upgrade/rollback
  exclusion has not been qualified, and the current C1 policy cannot authorize
  the v2 A10 selection until the normative policy gap above is resolved.
- No PR has been opened. The repository's normal pull-request `cargo-test`
  workflow runs `cargo test --workspace --all-features` against a PostgreSQL
  service; existing workspace tests create/drop databases and restore test
  dumps. That conflicts with this Phase B campaign's explicit no-database-
  mutation constraint. A Phase-B-safe protected CI lane or an explicit contract
  clarification is needed before opening the PR and triggering that workflow.

The C1.1 authenticated checkpoint/rotation contract remains v1-only. This plan
does not checkpoint or rotate journal v2. PP.7 and full PP.6 acceptance are out
of scope.

## Exact-source installed qualification readiness (2026-11-01)

This section supersedes historical readiness statements above where they say
that the A10 policy contract is missing, that Phase B's current branch passed
workspace commands, or that a PR cannot be opened. The preserved worktree's
historical log is retained as provenance and is not evidence for this branch.

### Candidate and release artifact

The exact protected base for this implementation is
`30a6c6e504ae57d46e686cd45d9960fe0f5291c6`; the A10.1 implementation it
contains is PR #1198 final reviewed head
`e1d6d4e13ce7bbe2cc3353f8dc8e9d78d853cef6`, merged with the publisher disabled
in production builds. Installed qualification requires a new immutable
release built from the final reviewed Phase B merge commit. Its archive,
installer, signed release manifest, executable inventory, SHA256SUMS, Sigstore
bundle and provenance must identify that same source and exact version. No
Phase B-capable immutable artifact exists yet, so an exact Phase B release
version cannot be named.

The current version pins are inconsistent: `packaging/get-o3k.sh` defaults to
`v0.4.0-rc.24`, while workspace `Cargo.toml`, `packaging/channels.yaml`, the
worker alpha channel and release gate name `v0.4.0-rc.5`. Neither pin proves
that an artifact contains #1198 or this Phase B candidate. Resolve the version
in the supported release pipeline and produce a new exact-source signed
artifact; do not qualify against either existing pin or assemble a local
archive.

Verify the artifact through the protected release workflow, including its
GitHub OIDC/Sigstore identity, provenance policy and published asset digests.
Install only that immutable archive using its byte-identical tagged
installer. The release manifest must authenticate both policy-format
authorities and the executable inventory. Keep offline installation-policy,
journal, evidence and trust-root private keys outside production binaries and
guests. Test-only signing fixtures are suitable for source tests only. An
installed run needs witnessed custodian procedures and separately administered
trust/revocation distribution; retain key IDs, purpose, validity, revocation
sequence and witnesses, never private key bytes.

### Shortest host path and resources

Use one clean Debian 12 guest and one clean Ubuntu 24.04 guest, sequentially on
the disposable KVM/libvirt runner if capacity permits. Each needs real systemd
as PID 1, root access for installation and denial assertions, isolated
networking, console capture, reliable guest destruction, and dedicated local
ext4 filesystems for protected recovery-state and journal directories. Verify
filesystem type, mount source, owner/group/mode, device/inode, no-follow
behavior and D8 lock behavior inside each guest. Container overlay filesystems
and host bind mounts do not qualify. Phase B needs no PostgreSQL service or
restore target; PG16 is a Phase C resource only.

After the exact signed release and authorized test-signing setup are available,
install it, exercise authenticated v1/C1.1 compatibility first, then v2
selection with a signed `PREFLIGHTED` journal. Test ordinary startup,
CLI/maintenance, upgrade/rollback, systemd restart and reboot denial, including
no listener/readiness, controller session/lease, unauthorized canonical
operational-store access, or provider dispatch. Capture before/after identities
and hashes, bounded logs, process/unit/socket state and ext4 facts on both OSes.
Preserve ordinary v1 behavior when A10 is absent or unselected.

### Remaining D8-A10-01 through -16 process gaps

All 16 remain **NOT_RUN as exact-release installed process qualification** on
clean Debian 12 and Ubuntu 24.04. PR #1198 source-built process evidence does
not close these release-specific lanes. Required cases remain: (01) malformed
selector staging; (02) staged policy without selector; (03) policy without a
valid migration selector; (04) selector durable before policy/high-water; (05)
missing/truncated/wrong-signed policy; (06) stale high-water; (07) stale
manifest; (08) old verifier/rollback startup; (09) removed or regressed
selector; (10) interrupted publication and changed resume input; (11) stale
clock, revoked signer, missing trust or inode mismatch; (12)
`INACTIVE_VERIFIED` operational admission denial; (13) compute restart cleanup
and domain-restoration denial; (14) compute restart during D8; (15) an old
compute process still executing before D8 acquisition; and (16) crash during
compute preparation before D8 acquisition. Phase B unit tests do not execute
these installed processes.

### Durability, approval and evidence disposition

The preserved D8 test names four process-crash points around file fsync, rename
and directory fsync, but its privileged local-ext4 test is ignored in ordinary
package runs. SIGKILL, process restart and successful fsync calls are not
power-loss evidence. A separate lane must forcibly power off each guest at
publication boundaries, reboot from the same ext4 volume, and verify only a
complete old or new authenticated generation is accepted. Record hypervisor,
storage cache and flush behavior; infrastructure must support repeatable hard
power cuts and preserve guest disks for examination.

A separate production-enablement owner decision and exact-revision
security/release review are required before enabling A10 migration publication
in production. Accepted A10/A10.1 decisions authorize bounded
implementation/testing, not production enablement, Phase C mutation or
operational restore GO. Phase C also requires its D4/D8/D9/D10/D12/D13
prerequisites and authorization. Original activated-recovery obligations in
#1086/#975 remain open and cannot be closed by `INACTIVE_VERIFIED`.

### This integration branch evidence

- Preserved worktree at inspection: HEAD
  `107ded898df4b2da6ca6c4d3c5672cc2a7afd453`, branch
  `pp6/1086-a10-journal-v2`, two modified tracked files and two untracked
  files. Changes were carried into the integration branch without modifying
  that worktree.
- Protected integration base:
  `30a6c6e504ae57d46e686cd45d9960fe0f5291c6`. Journal-v2 unit suite: **PASS**,
  11 passed. `cargo fmt --all -- --check`: **PASS**;
  `cargo clippy --workspace --all-targets --all-features -- -D warnings`:
  **PASS**; `cargo test --workspace --all-features`: **PASS**, zero failures
  (PostgreSQL conformance tests requiring `O3K_DATABASE_URL` and privileged
  ext4 tests were ignored). Privileged ext4 crash tests: **NOT_RUN**.
  Selected-v2 journal process tests, real-systemd, installed-release and
  power-loss evidence remain **NOT_RUN**.
- This implementation is source-level. No PostgreSQL target was created or
  changed, no controller was activated, and the production migration publisher
  remains disabled.
