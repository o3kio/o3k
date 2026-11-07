# PP.6 Stage 2 installed-release qualification matrix

## Current rc.27 installed qualification status (2026-11-07)

**Status: PP.6 BLOCKED; #975 remains OPEN.** Protected `main` is
`32b5e209c724277c2fc77a1a58fb3a7543bbbbb9`, merged from parent
`48c88c674adfb61edcac7d3aa78780e968c54573` through PR #1221. PR #1221 exact
reviewed head `5df40ce3db9dca643e936413cd288c2d649df122` was approved by
`senolcolak`; exact-head CI `42284063096`, Mock Cinder `42284063141`,
PostgreSQL pressure `42284063089`, merge-queue CI `42290049783`, Mock Cinder
`42290049543`, PostgreSQL pressure `42290049792`, post-merge CI `42294370899`,
Mock Cinder `42294370799`, and closure guard `42294376766` passed.

The qualification harness identity is SHA-256
`d94de11ec15fa484e40c944146aee39715ba8274935b70fc166bf9403ef6723d`.
Keep it separate from immutable `v0.4.0-rc.27`: tag object
`80cdab1568ef0972602214d0c4656ad70858c07e`, source
`9427e7668afa76bf1f043c9adabe1d616cf5924a`, release workflow run
`42044020384` attempt 2, archive SHA-256
`dea259144d16eb2cfa59169b5cf73e0e5df528663209e6b8bc34ea3d7da74f05`.
Independent keyless Sigstore/OIDC/transparency/provenance, signed manifest,
asset digest and extracted archive verification passed. The self-contained
A10 verifier confirmed `recovery-migrate-v2` publisher exclusion. This is
artifact authentication, not an installed executable identity.

### Ubuntu 24.04 priority lane

Fresh host preflight `pp6-e4-dedicated-preflight-20261107-004` passed on
authorized host `o3k-pp6-local-runner`; transcript SHA-256
`0d8f6d77898c165ee39ac7fe34f37ecac138fab065aa16a6114bf7946aa226f3`.
The official Ubuntu 24.04 cloud image passed signed Canonical SHA256SUMS
verification with expected and actual SHA-256
`04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94`.

Runs `pp6-e4-20261107-ubuntu01`, `ubuntu02`, and `ubuntu03` each passed guest
provisioning on Ubuntu 24.04.5: NoCloud, static IP and expected MAC, pinned
SSH, systemd, and distinct ext4 state/journal mounts. Each installer attempt
then failed before O3K executables/service units were installed:

| Run | Installer outcome | Q1 installed identity | Q2 |
|---|---|---|---|
| `pp6-e4-20261107-ubuntu01` | `file://` source rejected by curl; preceding SSH variable-expansion attempt also failed authentication | **FAIL**; no installed executable | **NOT_RUN** |
| `pp6-e4-20261107-ubuntu02` | release authenticity passed; `apt-get update` failed exit 100 on restricted-index size mismatch against signed InRelease metadata | **FAIL**; no installed executable | **NOT_RUN** |
| `pp6-e4-20261107-ubuntu03` | rc.27 authenticity/archive verification and A10 check passed, then immutable installer rejected pre-created `o3k` account home `/nonexistent`; it requires `/var/lib/o3k` | **FAIL**; no installed executable; result JSON SHA-256 `c53d68e7b77eda40dfb665cedaa5b1dfcc8565222914bacc4c93cabed9fad2a0` | **NOT_RUN** |

The narrow harness-only fix is PR #1222, exact head
`15811dcf4ce6c2af25de00660e5e335eb826ad70`; it changes the test guest
account home to `/var/lib/o3k` and adds a regression. At this update it is
OPEN, requested from `senolcolak`, has no review, and is
`REVIEW_REQUIRED` / `BLOCKED`. CI run `42358204722` has Rust
IN_PROGRESS (other reported CI jobs passed); Mock Cinder `42358204764` and
PostgreSQL pressure `42358204641` passed. Do not use this changed harness
until exact-head review, every protected check, and protected merge pass.

### Independent Debian 13 lane

After the Ubuntu attempts, fresh preflight
`pp6-e4-dedicated-preflight-20261107-debian02` passed; transcript SHA-256
`359b093c58c7c11bb0ff0a062670b15ebf642b1d3eb902aaafe4a5a89c20f6be`. Host
had root, nested `/dev/kvm`, 8 CPUs, 32,079,972 kB available memory,
258,471,243,776 bytes free in `/var/lib/libvirt`, IPv4/IPv6 forwarding off,
no production route, no active guest/custom network, and required commands.
Inactive pools point only at retained earlier PP6 run paths.

The official Debian 13 image's SHA-512 matched the HTTPS cloud manifest
exactly. Manifest SHA-256 is
`12d276e2c1befd925a35509659c8887cd931ece7aba9bd8597cf13322aa1d225`; image
SHA-512 is
`f46f0671a6e5bdec5291ab8972bae2f10e5408c2f64a74078f11efc2f06a436a9d0313ed50e0472542eeabf780e9f7c792ac0a314c6c20507fcd9fd81b468c3d`,
image SHA-256 is
`b2aca2bee42c7082fd6aba4a5bb1a89612087a405e99896920f3346f7b23b9d1`. The
cloud path returned HTTP 404 for `SHA512SUMS.sign`; record HTTPS origin and
exact manifest checksum as provenance, with no detached-signature claim.

`pp6-e4-20261107-debian13-001` is a pre-provision FAIL: the wrapper created
the run directory to capture stdout before invoking the harness, which
correctly refused the existing path; no guest was made. Separate run
`pp6-e4-20261107-debian13-002`, using
only protected harness `32b5e209c724277c2fc77a1a58fb3a7543bbbbb9` and SHA
`d94de11ec15fa484e40c944146aee39715ba8274935b70fc166bf9403ef6723d`, failed
the 600-second SSH deadline at `192.168.195.20`. Its bounded serial log
repeats GRUB `Booting Debian GNU/Linux`; NIC counters report zero TX packets
and bytes; neighbor resolution is FAILED. Domain/network XML, QEMU/libvirt
logs, bridge/routes/neighbors and preflight/image identity are retained under
`/var/lib/o3k-pp6-qualification/runs/pp6-e4-20261107-debian13-002/evidence/`.
Evidence manifest SHA-256:
`f1ddd9e6ea9d06b0fbe49b70e4647f6bc86cd3b742ef5410f16457ad3600dc24`. SSH
never became available, so cloud-init and guest journal were inaccessible;
the boot root cause is unresolved. Ownership-checked cleanup removed the
run-owned guest/network and retained evidence. Installer unsupported-platform
rejection is **NOT_RUN**. Debian 13 support is not claimed.

The existing installed-release acceptance plan specifies Debian 12 and Ubuntu
24.04, while current owner direction prohibits new Debian 12 tests and names
Debian 13/Ubuntu 24.04. Debian 13 is not a substitute for Debian 12, and its
unsupported rejection does not meet the Debian 12 acceptance target. This
target conflict requires owner resolution; keep Debian 12 unprovisioned.

### Current evidence classes and next gate

- **E1:** local #1222 regression passed 16/16 and Python compilation passed;
  exact-head CI is not
  fully complete while Rust remains in progress.
- **E2:** #1221 exact-head, merge-queue, and post-merge checks passed. #1222
  exact-head review and protected checks remain incomplete.
- **E3:** Ubuntu guest provisioning passed in three independent runs; Debian
  13 guest boot failed. No E3 result becomes E4.
- **E4:** **FAIL/BLOCKED**. Artifact authentication passed. Ubuntu installer
  attempts failed before installed executable identity; Debian 13 did not
  boot. Q1 installed identity has no PASS; Q2 is NOT_RUN. Historical
  `pp6-e4-20261106-0194` remains FAIL with its original unresolved diagnosis
  and hashes.
- **E5:** physical host power loss **NOT_RUN**. Guest reboot/force-restart is
  not E5.

Next action: complete independent review and all protected gates for PR #1222,
then use only its protected merge for a fresh Ubuntu 24.04 run and repeat Q1
then Q2. Keep all prior installer attempts FAIL. #975 stays OPEN; backup /
restore, PKI, observability, upgrade/recovery, pressure, docs, independent
review and zero BLOCKER/HIGH/MEDIUM owner acceptance remain required. No A10
publisher enablement, production restore mutation, Araf, PP.7 or general
Debian 13 support work is authorized here.

## Historical rc.27 guest-boot status (2026-11-06; superseded above)

Protected `main` is `48c88c674adfb61edcac7d3aa78780e968c54573`; this is the
qualification harness identity, separate from rc.27 source
`9427e7668afa76bf1f043c9adabe1d616cf5924a`, annotated tag object
`80cdab1568ef0972602214d0c4656ad70858c07e`, and authenticated archive
SHA-256 `dea259144d16eb2cfa59169b5cf73e0e5df528663209e6b8bc34ea3d7da74f05`.
The Debian 12 release-build baseline remains historical and unchanged. Debian
13 is an owner-directed future guest target; rc.27's installer supports
Ubuntu 24.04 and Debian 12 and rejects Debian 13.

Run `pp6-e4-20261106-0194` failed Debian 13 live-boot provisioning on the
authorized host. SSH to static IP `192.168.116.20` timed out; the host bridge
observed one packet/90 bytes received and no transmitted traffic, with an
unresolved neighbor. QEMU command logging confirms the intended root disk boot
index and virtio NIC MAC, but not guest progress. The original attempt did not
retain domain XML or a serial transcript; guest cloud-init diagnostics were
unavailable because SSH never came up. This evidence does not distinguish
firmware/kernel/initramfs failure, NoCloud discovery, network application,
interface matching, or SSH key/authentication failure. Root cause remains
unresolved. Result JSON SHA-256:
`318f41009750970701764a7c6cf319b548bb8be050a4e41a4c0cfd6ec532c0af`;
attempt transcript:
`8273941a26d4ea2791a8d9874e9a666a2a042ae9134745f00a3e0a6119ef6a85`;
QEMU log:
`4aeda397d28e90514f56b5f0975b26709270f1b1aef6c65f7792867a0932ab71`.
The host preflight passed (transcript SHA-256
`2533035aa42be4b0799b9b3e095d5bf3a5c2790e9d539bbe08d7b6c335483a1f`), and
ownership-checked cleanup passed with evidence retained. E4 is BLOCKED;
Debian 13 Q1/Q2 are NOT_RUN, Ubuntu 24.04 Q1/Q2 are NOT_RUN, and no installed
release evidence exists.

A harness-only change is proposed to allow either guest independently or both
by default and retain bounded serial, domain/network XML, host bridge/interface,
route, neighbor, SSH and available cloud-init diagnostics on failure. The
change is not yet merged and provides no live-boot evidence. After exact-head
review/checks and protected merge, run Debian 13 and Ubuntu 24.04 independently
with fresh run IDs; retain every failed attempt. Only after successful Ubuntu
boot may immutable rc.27 authentication and Ubuntu Q1/Q2 proceed. For Debian
13, test live boot first, then record the published installer's allowlist
rejection as expected unsupported-platform behavior; do not bypass it.

Keep #975 OPEN. These updates do not establish Debian 13 product support, PP.6
GO, independent security acceptance, E5 physical power-loss evidence, or
production restore activation.

**Status:** executable plan; PP.6 remains **BLOCKED**. **Status snapshot:**
protected `main` at `c454134e584288b49637b11592bb0b59351d022a` (2026-11-04),
the merge-queue commit for PR #1215. PR #1215 reviewed head was
`2d2ebcc1fd5253727ba08581c8d5577efb8d7e7e`; its source implementation head
was `3e9e53f867fd8b23bb629fd545e36443565ec4bd`. PRs #1212–#1215 are merged;
their exact reviewed heads and protected merge identities are recorded below.
The proposed successor is `v0.4.0-rc.27`; no tag or GitHub Release exists,
so its authenticated release identity and installed qualification are NOT_RUN.
**Previously authenticated
release:** immutable `v0.4.0-rc.26`, source
`901af47b306aa779aed72ef61ef25184fabf24eb`, tag object
`b295a9a031ae2969497b6311ea87ee1ff421f676`.

**Authority:** #975 and #1086 retain their original acceptance criteria and
remain open. Exact-head owner decisions on PRs #1192 and #1193 ACCEPT bounded
A10.1 contract implementation and testing under SPEC-0050 §7.4. They do not
authorize production publisher enablement, PostgreSQL restore-target mutation,
controller activation, independent security acceptance, or PP.6 final GO.
No PP.7 or Araf work is included.

The rc.26 release assets authenticated successfully: protected workflow/OIDC
identity, Sigstore/Rekor proof, signed digest manifest, archive and bundle
integrity, source/version/upgrade-floor binding, Debian 12 glibc floor,
and production A10 publisher exclusion all passed. Separately, the rc.26
packaged verifier failed during guest verification with exit status 2 because
the archive did not contain
`bins/o3k/tests/fixtures/a10-release-verify.pub`; **no installed-release Q1 or
Q2 pass is inferred from the successful asset authentication**. PR #1214
fixes this package self-containment defect and adds extracted-archive negative
coverage. rc.26 remains immutable and is not to be retagged or repaired.

The rc.27 source includes protected merges #1212–#1214 and PR #1215, with
aligned version pins and candidate notes. PR #1215 was approved by
`senolcolak` at exact head `2d2ebcc1fd5253727ba08581c8d5577efb8d7e7e`.
Its exact-head protected checks passed in run `41909388446`; merge-queue CI
`41914575991`, Mock Cinder `41914576072`, and PostgreSQL tablespace
`41914576122` all passed on synthetic merge candidate
`c454134e584288b49637b11592bb0b59351d022a`. The queue merged PR #1215 to
protected `main` at that commit. This freezes the source candidate only; it
does not build or authenticate release assets. Tag creation and publication
remain stopped pending explicit owner release authorization.

## Evidence classes

Results must never be promoted between these classes:

- **E1 — source/unit:** tests at an identified source revision.
- **E2 — protected CI:** checks and merge-group runs for an exact reviewed head.
- **E3 — qualification-only process:** source-built binaries, explicitly
  authorized isolated fixtures, real filesystems/processes, and test-only
  signers. This includes the debug A10 publisher journey.
- **E4 — authenticated installed-release:** an immutable Sigstore/provenance
  verified release installed on clean Debian 12 and Ubuntu 24.04 guests, with
  exact release and executable identity captured.
- **E5 — physical host power-loss:** authorized BMC/PDU interruption of suitable
  disposable hardware. Guest force-restart and SIGKILL are not E5.

The production release intentionally excludes `o3k recovery-migrate-v2`.
Do not inject the debug publisher into a production bundle. E3 publisher
execution is qualification-only and must never be reported as an installed
production migration. Installed E4 tests exercise the production consumer,
startup denial, policy/trust, and safety behavior using separately authorized
fixtures; they do not assert that a production publisher ran.

## Merged rc.27 preparation evidence

| PR | Reviewed head → protected merge | Change and evidence classification |
|---|---|---|
| #1212 | `dd959349157b5b181b4ac589526476fcc6302e93` → `c984175d4bd45437236fa8267c9a5b562f02e621` | Signed journal restart tests. Source tests and protected PR checks passed; no installed-release or power-loss claim. |
| #1213 | `b4315c7fe8f296893fd6a86c3c69ed177d26396b` → `3dc280a563bbd3d1f63e2180ad7deba6f78461c2` | Harness pins the guest root device to virtio `vda`; serializes cloud-init as JSON/YAML; waits for cloud-init completion; parses actual DHCP lease timestamp/MAC/protocol layout; checks ext4 devices as guest root; permits cleanup only for run-owned disks owned by `libvirt-qemu`; records the generated SSH host public key in the ownership marker. Tests cover serialization, DHCP parsing, and root-device selection. A local run with harness SHA-256 `f1a64595d6eafe74d55bd972cfad2102298151e98fd2a5c04fbf2f80168cc76d` successfully provisioned Debian 12 and Ubuntu 24.04 guests, captured guest/disk identities and distinct ext4 state/journal mounts with host forwarding disabled, then removed run-owned guests/network while retaining evidence at `/var/tmp/pp6-local-20261104/evidence`. It recorded `NOT_INSTALLED`: E3 infrastructure evidence only, not Q1/Q2 or E4. |
| #1214 | `cb6dba632276830e022038ea399c7a43164e3bff` → `ee54bacd9e8185089412c7cb1ffa3be5870b6c9b` | Makes packaged A10 verification self-contained and runs it against an extracted archive in a clean environment. Negative cases cover malformed checksums, changed content, A10 fault marker, embedded public test key, linked publisher symbol, missing `nm`, failing `strings`; optimized and stripped binaries pass, and release `o3k` rejects the excluded `recovery-migrate-v2` command. PR checks passed. rc.26 fail-before returned exit 2 because `bins/o3k/tests/fixtures/a10-release-verify.pub` was absent, even though its release assets authenticated; local fix-after bundle regression is source-built E1 evidence, not a new authenticated release. |
| #1215 | `2d2ebcc1fd5253727ba08581c8d5577efb8d7e7e` → `c454134e584288b49637b11592bb0b59351d022a` | Aligns Cargo/installer/worker/Helm/Docker version references and candidate release notes; preserves Debian 12 baseline and extracted self-contained A10 verifier coverage. Repairs the non-root-only Debian 12 platform fixture for the upgrade-process test and makes PostgreSQL Docker cleanup fail closed by requiring a successful empty full-ID container listing after failed inspect. Reviewer `senolcolak` approved the exact head; PR checks passed in `41909388446`; merge-queue CI `41914575991`, Mock Cinder `41914576072`, and PostgreSQL tablespace `41914576122` passed. This prepares source only and does not create a release. |

### Post-merge cargo-test failure disposition

Protected-main run `41919177633` failed the `cargo-test` job. Its exact log
records `backup_create::tests::impostor_executor_is_rejected_by_listener`
returning `source-unavailable` instead of `unauthorized-peer`. This outcome
comes from `execute_inner()` preflight before it connects to the Unix listener;
the listener was bound before its accept thread started. The failure therefore
does not demonstrate that peer authentication was bypassed or misclassified.
The run log does not identify which preflight filesystem metadata lookup
failed, so the underlying transient source of this one-off result is not
established and is not labeled a proven race.

On protected source `c454134e584288b49637b11592bb0b59351d022a`, the focused
all-feature library test passed 50 consecutive invocations and the complete
`o3k` library suite passed 475 tests with 6 ignored. PR #1216's protected CI
also passed on its current documentation head. These results demonstrate
non-reproduction, not the missing path's identity. Retain run
`41919177633` as **FAIL (unresolved source-preflight fixture/runner anomaly)**;
do not hide or weaken the assertion. Release readiness remains BLOCKED until
the failed run is accepted through the required independent release decision
or a reproducible cause is fixed and protected checks pass.

Candidate source implementation head `3e9e53f867fd8b23bb629fd545e36443565ec4bd`
passes
`cargo fmt --all -- --check`, workspace Clippy with warnings denied, and
`cargo test --workspace --all-features`. The PP.6 harness tests pass 9/9;
release-gate, bundle-integrity, worker-asset-sync, actionlint/workflow, and
release publisher-exclusion regressions pass. Installer negatives pass 27/27
with the root-only full-wrapper case skipped because this runner is not root.
The extracted rc.27 packaging regression archive passes all 11 A10 positive
and negative cases outside the checkout. That local archive used the
authenticated rc.26 binaries solely to exercise rc.27 packaging/verifier
source; it is not an rc.27 build, release artifact, or source-to-binary
identity claim. A direct local optimized build was rejected by the glibc
baseline check (host glibc 2.39 exceeds Debian 12's 2.36 ceiling); the
protected Debian 12 build remains mandatory.

The PR #1215 runs `41897296059` and `41902153244` failed the PostgreSQL
outage/reconnect step during investigation. The final full-ID listing fix
passed that Docker outage lane and all other branch checks on code head
`3e9e53f867fd8b23bb629fd545e36443565ec4bd`; final reviewed head
`2d2ebcc1fd5253727ba08581c8d5577efb8d7e7e` passed all PR checks in
`41909388446`. Reviewer `senolcolak` approved that exact final head. The merge
queue then passed CI `41914575991`, Mock Cinder `41914576072`, and PostgreSQL
tablespace `41914576122` before merging to
`c454134e584288b49637b11592bb0b59351d022a`. Earlier failed attempts are
retained as diagnostic history. Passing checks and source-built regressions do
not authorize release publication.

## Historical candidate Q1/Q2 status snapshot (2026-11-06; superseded above)

These are the proposed rc.27 installed-release lanes. No host preflight or guest
installation has been performed for this candidate in this preparation. The
prior rc.26 verifier failure is recorded separately above; its guest OS was
not identified in the retained evidence cited here.

| Operating system | Q1 authenticity and installed executable identity | Q2 clean install, service health, bootstrap, idempotence, foreign-state preservation |
|---|---|---|
| Debian 12 | **NOT_RUN / BLOCKED** — rc.27 has no authenticated release assets or installed identity | **NOT_RUN / BLOCKED** — no rc.27 installation |
| Ubuntu 24.04 | **NOT_RUN / BLOCKED** — rc.27 has no authenticated release assets or installed identity | **NOT_RUN / BLOCKED** — no rc.27 installation |

## Historical evidence classification snapshot (2026-11-06; superseded above)

| Tier / lane | Result |
|---|---|
| E1 source/unit | **PASS** at proposed source commit `3e9e53f867fd8b23bb629fd545e36443565ec4bd`: format, workspace Clippy with warnings denied, all-feature workspace tests, focused Docker-listing cleanup test, harness unit tests, workflow validation, release gate, bundle integrity, installer negatives (27 pass; root-only wrapper skipped), publisher exclusion, and extracted packaging regression. The local archive reused authenticated rc.26 binaries and is not candidate release identity evidence. |
| E2 protected CI | **PASS** on exact reviewed PR head `2d2ebcc1fd5253727ba08581c8d5577efb8d7e7e`: all PR checks passed in run `41909388446`. The protected merge queue then passed CI `41914575991`, Mock Cinder `41914576072`, and PostgreSQL tablespace `41914576122` on merge candidate and final protected source `c454134e584288b49637b11592bb0b59351d022a`. Earlier heads failed the upgrade process matrix because the Ubuntu 26.04 CI host is outside the supported platform allowlist. Head `29c580a` also exposed a PostgreSQL Docker cleanup wording failure; `24671ac`'s string matcher did not resolve it. |
| E3 qualification-only process | **PASS** for #1213 local provisioning and ownership-checked cleanup; **PASS** for #1214's source-built extracted-bundle regression. Both are non-installed evidence. The current local rc.27 packaging regression is E1 package verification only, not an E3 guest process. |
| E4 authenticated installed release | **NOT_RUN / BLOCKED**: rc.26 verifier failure prevented installation; rc.27 is not published and no Q1/Q2 guest installation has run. |
| E5 physical host power loss | **NOT_RUN / BLOCKED**: requires separately authorized disposable bare-metal host and BMC/PDU control. |

## Historical critical-dependency snapshot (2026-11-06; superseded above)

1. **B0 — governance:** PASS for protected merges #1212–#1214 and the current
   protected-main merge queue. PR #1212 reviewed head
   `dd959349157b5b181b4ac589526476fcc6302e93`, merge
   `c984175d4bd45437236fa8267c9a5b562f02e621`; PR #1213 reviewed head
   `b4315c7fe8f296893fd6a86c3c69ed177d26396b`, merge
   `3dc280a563bbd3d1f63e2180ad7deba6f78461c2`; PR #1214 reviewed head
   `cb6dba632276830e022038ea399c7a43164e3bff`, merge
   `ee54bacd9e8185089412c7cb1ffa3be5870b6c9b`. PR #1215 reviewed head
   `2d2ebcc1fd5253727ba08581c8d5577efb8d7e7e`, protected merge
   `c454134e584288b49637b11592bb0b59351d022a`; exact-head review, PR checks,
   and merge-queue checks passed. #975 and #1086 remain OPEN,
   as do the other PP.6 acceptance workstreams.
2. **B1 — candidate and host:** rc.27 is only a proposed source candidate;
   there is no tag/release or authenticated artifact yet. rc.26 assets are
   authenticated, but its guest verifier failed before installation. PR #1213
   also records successful E3 local provisioning and ownership-checked cleanup
   using harness SHA-256 `f1a64595d6eafe74d55bd972cfad2102298151e98fd2a5c04fbf2f80168cc76d`:
   both guest identities, root/state/journal disk inodes, disabled host
   forwarding, separate ext4 state/journal mounts, and cleanup of run-owned
   guests/network were captured; evidence was retained at
   `/var/tmp/pp6-local-20261104/evidence`. The run was `NOT_INSTALLED`; this is
   not E4. For E4, first authenticate rc.27, then repeat read-only preflight on
   the explicitly authorized dedicated host with authenticated images and
   fixtures. E5 additionally requires authorized physical power control.
3. **B2 — custody and fencing:** provide approved offline signer custody,
   trust/revocation distribution, and independently administered D7 fencing
   for the recovery lanes that require them. Witnessed BMC/PDU procedures are
   required for E5 only, not for independent E4 qualification. Test keys
   cannot substitute for production custody.
4. **B3 — restore implementation:** complete the accepted SQLite and
   PostgreSQL 16 restore paths, D4 source/target writer exclusion, canonical
   parity, interruption handling, and foreign-state negatives.
5. **B4 — activation scope:** original activated recovery remains controlling;
   an amendment would require explicit owner acceptance. D3
   identity/credential/lease/epoch
   invalidation and D8 boot-bound handoff remain required.
   `INACTIVE_VERIFIED` does not satisfy activation.
6. **B5 — remaining operations:** PKI lifecycle, exact-artifact
   upgrade/rollback/recovery, pressure lanes, diagnostics/support bundle, and
   evidence-backed runbooks.
7. **B6 — acceptance:** independent security/release review with zero
   actionable BLOCKER/HIGH/MEDIUM findings and final owner GO.

## Read-only host preflight

The proposed rc.27 qualification must begin with a fresh read-only preflight on
the explicitly authorized dedicated disposable host, after rc.27 is
authenticated. PR #1213 records a separate successful local E3 harness run
with SHA-256
`f1a64595d6eafe74d55bd972cfad2102298151e98fd2a5c04fbf2f80168cc76d`; it
validated provisioning and cleanup ownership, but does not replace a fresh
preflight or prove installed-release behavior. Its evidence records both guest
identities, root/state/journal disk inodes, host forwarding disabled, separate
ext4 state/journal mounts, and cleanup of run-owned VMs/network while retaining
evidence under `/var/tmp/pp6-local-20261104/evidence`. The harness reported
`NOT_INSTALLED`; classify this as E3 only.

| Requirement | Shared development runner observation | Status |
|---|---|---|
| Harness safety tests | 7/7 pass at `bf04c8b6` | PASS (E1 only) |
| KVM and libvirt tools | `/dev/kvm`; AMD-V; virsh 10.0.0; qemu-img 8.2.2; all required tools present | PASS, insufficient alone |
| CPU / memory / space | 16 CPUs; about 58.5 GiB available memory; 181 GiB free on shared ext4 | PASS, shared and insufficient alone |
| Forwarding disabled everywhere | IPv4 `ip_forward=1`; all inspected IPv4/IPv6 interface forwarding controls are `1` | **FAIL** |
| Dedicated, unrelated-workload-free host | Running `o3k-a10-systemd-qualification` VM, other libvirt networks, Docker containers, nginx, PostgreSQL, NFS and dnsmasq | **FAIL** |
| Trusted digest-pinned Debian 12 / Ubuntu 24.04 images | No qualification images supplied; nothing to verify | NOT_RUN |
| Authorized physical power control | No observable BMC/PDU authority or IPMI device; guest force-restart is not a substitute | **BLOCKED (E5 only; not an E4 gate)** |
| Guest provision/install/recovery/power tests | Prohibited on this host and not attempted | NOT_RUN |

### Historical shared-development-host assessment (2026-11-03)

The shared development runner inspected on 2026-11-03 was **NOT READY** and
was not authorized for provisioning. That historical observation is not a
current assessment of the dedicated host used for PR #1213's E3 local run and
does not authorize reuse of the shared host. The inspected session was
`ubuntu` (UID 1000), not root. `systemd-detect-virt` reported KVM and
`systemctl is-system-running` reported `degraded`. The host had a pre-existing stopped libvirt guest
`o3k-a10-systemd-qualification`, multiple unrelated libvirt/container
networks, and unrelated routed interfaces. Host IPv4 `ip_forward` and IPv6
`conf/all/forwarding` are both `1`. No guest, route, firewall, forwarding,
service, package, or disk state was changed. Q1/Q2 provisioning was not
attempted. The BMC/PDU prerequisite for E5 and authenticated guest-image
prerequisite for E4 were not available for verification in this session.

No current host preflight has been run in this preparation. For rc.27 E4,
use only the dedicated disposable qualification host specified below, with
explicit root administrative access and authorization for this run. Perform
the read-only host preflight before provisioning, and do not reuse the shared
development runner. Supply authenticated official Debian 12 and Ubuntu 24.04
cloud images with vendor metadata/digests, plus host-isolated package/image
fixtures. The earlier rc.26 asset authenticity and PR #1213 E3 provisioning
evidence are not installed E4 evidence.

## Exact dedicated-host provisioning specification

This is a provisioning request, not an observed host or a support claim:

- Disposable dedicated x86_64 KVM/libvirt host with hardware AMD-V/Intel VT-x
  and EPT/NPT. Bare metal is required for E5; nested virtualization is not a
  substitute for physical power tests.
- Minimum 8 physical cores (16 recommended), 32 GiB RAM, 256 GiB OS storage;
  512 GiB or more recommended for images, run disks, and retained evidence.
- Debian 12 or Ubuntu 24.04 host with real systemd, persistent journald,
  `qemu-kvm`, `libvirt-daemon-system`, `virtinst`, `qemu-utils`, `genisoimage`,
  and OpenSSH. No Docker, unrelated guests, production services, or default NAT
  network.
- At least 8 CPUs, 16 GiB available memory, and 35 GiB free at provisioning
  time, as enforced by `host-env.py`; retain operational headroom above these
  minima.
- Every IPv4/IPv6 forwarding control disabled. Dedicated management network;
  only the harness's run-scoped, `forward mode='none'` bridge for guest SSH.
- Official Debian 12 genericcloud amd64 and Ubuntu 24.04 amd64 qcow2 images,
  downloaded over TLS from vendor mirrors. Assessment-time candidates are
  Debian build `20261026-2643`
  (`https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2`,
  vendor SHA-512 `3622c990108a044ed411652f8741e77c5822c365114d7b940206b243f8fb617b8586792df4cdb7afba1b71d1a09289d8ed632124688f2c8352cb08190a1e9868`)
  and Ubuntu build `20261017`
  (`https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img`,
  vendor SHA-256 `04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94`).
  Authenticate the vendor metadata (`SHA512SUMS` for Debian and signed
  `SHA256SUMS` for Ubuntu), verify the vendor digest, then compute the local
  SHA-256 required by `host-env.py`. Store images as regular, non-symlink,
  read-only files under `/srv/qualification`; record vendor URL, build,
  metadata, vendor digest, and local SHA-256.
- A host-only APT package snapshot/repository reachable over the run bridge,
  with signed vendor metadata and every package required by the tagged
  installer. Also stage the pinned CirrOS 0.6.3 image with SHA-256
  `7d6355852aeb6dbcd191bcda7cd74f1536cfe5cbf8a10495a7283a8396e4b75b`.
  Guests have no direct outbound access; dependencies and fixtures arrive only
  through this host-only repository and run-scoped SSH.
- The harness creates, per guest, a 24 GiB root overlay plus distinct 4 GiB
  `vdb` recovery-state and 4 GiB `vdc` journal qcow2 devices, formatted ext4
  and mounted at `/var/lib/o3k/state` and `/var/lib/o3k/journal`. Do not replace
  these with bind mounts, overlayfs, tmpfs, or a shared filesystem.
- For E5 only: independently administered BMC with Redfish or an authenticated
  managed PDU outlet, explicitly authorized for physical power cuts of only
  this host. Its absence does not block E4 when the E4 host/image/safety
  prerequisites are satisfied.
  Record device identity, source serial, operator, authorization, UTC events,
  storage cache/flush configuration, and console/evidence collector. Verify the
  host remains off until the authorized restart.
- No production credentials, database URLs, tokens, routes, data, signing keys,
  or unrelated workloads. Only disposable qualification identities and
  explicitly authorized fixture material.

## Execution preconditions and common commands

After B1/B2 are satisfied, choose a fresh lowercase run ID and export the exact
values from the verified release; never copy them from an unverified manifest:

```bash
export RUN_ID=pp6-rc27-run01
export TAG=v0.4.0-rc.27
export SOURCE_SHA=<exact-tag-commit>
export ARTIFACT_SHA256=<archive-digest-from-verified-sigstore-manifest>
gh release download "$TAG" --repo o3kio/o3k --dir release
RELEASE_SOURCE_COMMIT="$SOURCE_SHA" \
  packaging/verify-release-sigstore.sh "$TAG" release
```

Provision only on the dedicated host after its read-only preflight passes:

```bash
O3K_PP6_QUAL_ROOT=/var/lib/o3k-pp6-qualification \
  tests/pp6-qualification/host-env.py provision \
  --run-id "$RUN_ID" \
  --debian-image /srv/qualification/debian-12.qcow2 \
  --debian-sha256 <authenticated-debian-image-sha256> \
  --ubuntu-image /srv/qualification/ubuntu-24.04.qcow2 \
  --ubuntu-sha256 <authenticated-ubuntu-image-sha256>
```

The run network has no external forwarding. On the host, stage the already
verified assets and pinned guest fixture over run-scoped SSH. Repeat with
`GUEST=ubuntu2404`; use the byte-identical tagged installer against the staged
`file://` directory, not an Internet URL. This is an explicit isolated
qualification override, not a production channel change:

```bash
export QUAL_ROOT=/var/lib/o3k-pp6-qualification
export GUEST=debian12
GUEST_IP="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["guests"][sys.argv[2]]["ip"])' \
  "$QUAL_ROOT/runs/$RUN_ID/.o3k-pp6-owned.json" "$GUEST")"
SSH_OPTS=(-i "$QUAL_ROOT/runs/$RUN_ID/private/$GUEST/id_ed25519" \
  -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
  -o "UserKnownHostsFile=$QUAL_ROOT/runs/$RUN_ID/private/$GUEST/known_hosts")
ssh "${SSH_OPTS[@]}" "o3kqual@$GUEST_IP" "mkdir -p /tmp/o3k-release/$TAG"
scp "${SSH_OPTS[@]}" -r release/. "o3kqual@$GUEST_IP:/tmp/o3k-release/$TAG/"
scp "${SSH_OPTS[@]}" /srv/qualification/cirros-0.6.3-x86_64-disk.img \
  "o3kqual@$GUEST_IP:/tmp/"

# Inside the guest, after configuring only the host-only APT snapshot:
sudo install -d -m 0755 /var/lib/o3k/image-cache
sudo install -m 0644 /tmp/cirros-0.6.3-x86_64-disk.img \
  /var/lib/o3k/image-cache/cirros-0.6.3-x86_64-disk.img
sudo env O3K_RELEASE_BASE=file:///tmp/o3k-release \
  O3K_TESTLAB_IMAGE_CACHE_DIR=/var/lib/o3k/image-cache O3K_SKIP_ARAF=1 \
  sh "/tmp/o3k-release/$TAG/install.sh"
```

Then capture both installations separately:

```bash
tests/pp6-qualification/host-env.py capture-installation \
  --run-id "$RUN_ID" --guest debian12 \
  --source-sha "$SOURCE_SHA" --version "${TAG#v}" \
  --artifact-sha256 "$ARTIFACT_SHA256"
tests/pp6-qualification/host-env.py capture-installation \
  --run-id "$RUN_ID" --guest ubuntu2404 \
  --source-sha "$SOURCE_SHA" --version "${TAG#v}" \
  --artifact-sha256 "$ARTIFACT_SHA256"
```

Every scenario runs on both operating systems unless explicitly marked
host-level. Retain exact commands, exit statuses, before/after state, redacted
logs, and negative assertions. A skipped prerequisite is BLOCKED or NOT_RUN,
never PASS.

## Installed qualification matrix

### Q1 — release authenticity and exact identity

- **Execute:** common verification and capture commands above; verify the
  archive, bundle checksums, workflow/tag identity, OIDC issuer, Rekor proof,
  and exact tag commit before installation.
- **Require:** matching source/version/digest and hashes for installed `o3kd`,
  `o3k`, `o3k-compute`, and `o3k-network`; production `o3k` rejects
  `recovery-migrate-v2` and omits it from help.
- **rc.26 assets:** authentication **PASS** at tag object
  `b295a9a031ae2969497b6311ea87ee1ff421f676`, source
  `901af47b306aa779aed72ef61ef25184fabf24eb`, archive SHA-256
  `6d7d034aa2f5fdc8ad78dd237ec64605a8623d8042bf23ac420a678051a76685`.
  The Sigstore/provenance and digest checks passed. **rc.26 guest verifier:**
  FAIL (exit 2; required fixture missing at
  `bins/o3k/tests/fixtures/a10-release-verify.pub`); installation did not
  complete. These are separate outcomes: asset authentication PASS does not
  establish guest verifier, installed identity, or Q1/Q2 PASS.
- **rc.27:** authentication and installed identity NOT_RUN because no tag,
  release, or artifact exists yet. After explicit owner authorization and
  protected release workflow completion, repeat verification on the exact
  downloaded assets. Q1 remains BLOCKED until the installed binaries and
  manifest are captured on the qualified guests.

### Q2 — clean Debian 12 and Ubuntu 24.04 installation

- **Execute:** Q1 followed by the tagged installer on both newly provisioned
  guests; run health/readiness, canonical bootstrap, and supported public
  lifecycle smoke without adding the demo publisher.
- **Require:** real systemd, separate ext4 mounts, expected units/accounts,
  successful idempotent reinstall behavior where supported, and no foreign
  resource mutation.
- **Current:** E4 NOT_RUN. rc.26 guest verification failed before install;
  rc.27 is untagged and unpublished. PR #1213's successful isolated guest
  provisioning/cleanup is E3 infrastructure evidence only. Perform Q2 on both
  OSes only after rc.27 is authenticated and dedicated-host preflight passes.
  Overall **BLOCKED**.

### Q3 — C1/C1.1 policy, trust, revocation, and re-anchor

- **Execute:** using separately authorized offline fixture procedures, install
  signed first-install and migration policies, then exercise valid trust,
  expired/revoked/wrong signer, rollback, re-anchor, and restart cases through
  the installed production binaries. Keep private signing material outside the
  guests and evidence.
- **Require:** authentication before admission, exact policy/key/generation
  binding, fail-closed revocation and stale-generation behavior, and preserved
  ordinary v1 behavior when v2 is unselected.
- **Current:** E1/E3 historical coverage is not E4; installed cases NOT_RUN and
  approved custody fixtures BLOCKED. Overall **BLOCKED**.

### Q4 — recovery-designated startup denial before admission

- **Execute:** stage authorized selected-recovery fixtures, then start/restart
  `o3kd` and execution services while capturing store-open, listener, readiness,
  controller session, lease, reconciliation, and provider-dispatch observations.
- **Require:** denial before store/controller admission, no provider mutation,
  bounded secret-safe diagnostics, and terminal `INACTIVE_VERIFIED` remaining
  inert.
- **Current:** source denial tests exist; all 16 installed D8-A10 process lanes
  remain NOT_RUN. Overall **BLOCKED**.

### Q5 — selected-v2 signed journal consumer and fail-closed behavior

- **Execute:** supply explicitly authorized, isolated, signed journal fixtures;
  invoke only installed production consumers. Cover valid records, malformed or
  noncanonical records, wrong scope/signer/policy/release/installation/backend,
  broken prefix, duplicate/replayed records, and terminal records.
- **Require:** exact-forward authentication, prior-prefix fork rejection,
  bounded denial, and zero target/database/controller mutation.
- **Current:** E1 journal tests and the separate E3 publisher journey do not
  establish E4. Installed consumer cases NOT_RUN. Overall **BLOCKED**.

### Q6 — real systemd lifecycle and interruption

- **Execute:** `systemctl stop`, `start`, and `restart` for each installed unit;
  interrupt at each accepted durable phase, then restart and observe before any
  retry. Use guest `force-restart` only for the separately labelled guest lane:

  ```bash
  tests/pp6-qualification/host-env.py force-restart \
    --run-id "$RUN_ID" --guest debian12
  tests/pp6-qualification/host-env.py force-restart \
    --run-id "$RUN_ID" --guest ubuntu2404
  ```

- **Require:** stable identity, no duplicate resource or stale lease/epoch,
  deterministic recovery or bounded denial, and complete unit/socket/process
  evidence.
- **Current:** E4 NOT_RUN. Guest interruption is not E5. Overall **BLOCKED**.

### Q7 — D8 filesystem and journal crash boundaries

- **Execute:** at every write/file-fsync/rename/directory-fsync/readback boundary,
  inject the authorized interruption and inspect only the run-owned ext4 state
  and journal devices after restart.
- **Require:** only complete old or new authenticated bytes are accepted;
  partial writes, stale CAS, symlink/device/inode replacement, lock conflicts,
  and mixed generations fail closed.
- **Current:** E3 ext4 tests at earlier exact sources are not installed proof;
  E4 journal-v2 and D8-A10 cases NOT_RUN. Overall **BLOCKED**.

### Q8 — guest restart, separately labelled

- **Execute:** Q6 `force-restart` at each selected guest boundary on both OSes;
  preserve disks for examination and record `guest-force-poweroff-restart` in
  `injections.jsonl`.
- **Require:** recovery invariants without labelling the result physical host
  power-loss.
- **Current:** NOT_RUN; no guests exist. Overall **BLOCKED**.

### Q9 — actual physical host power-loss durability

- **Execute:** only after written authorization and a successful disposable-host
  safety rehearsal, use the authorized BMC/PDU to cut power at each selected
  persistence boundary, preserve the recovery/journal devices, restart under
  witness, and collect the same assertions as Q7.
- **Require:** independent power event and storage evidence, no unrelated
  workload exposure, and no substitution of VM destroy, SIGKILL, or fsync success
  for power-loss proof.
- **Current:** E5 NOT_RUN; hardware and authority BLOCKED. Overall **BLOCKED**.

### Q10 — replay, identity, digest, generation, and foreign-state negatives

- **Execute:** repeat every supported operation; then use wrong installation or
  principal identity, invalid archive/policy/journal digest, stale generation,
  removed/revoked trust, conflicting content, and foreign files/databases/
  services/guests/storage/network fixtures.
- **Require:** idempotent same-identity retry, conflicting-content preservation,
  rejection before mutation, no cross-tenant disclosure, zero unowned mutation,
  and secret-safe bounded errors.
- **Current:** E4 NOT_RUN; isolated foreign-state fixtures and custody BLOCKED.
  Overall **BLOCKED**.

### Q11 — evidence binding and final review

- **Execute:** emit one redacted machine-readable envelope per scenario with OS,
  kernel, systemd, release tag/source SHA, signed archive digest, installed
  executable hashes/inodes, harness SHA-256, filesystem/device/cache facts,
  backend/version, fixture/trust/generation IDs, exact commands, timestamps,
  results, and cleanup/foreign-state checks. Scan all retained output for
  secrets.
- **Require:** independent evidence review, zero actionable
  BLOCKER/HIGH/MEDIUM findings, and explicit final owner GO.
- **Current:** evidence collection NOT_RUN; independent reviewer and final GO
  BLOCKED. Overall **BLOCKED**.

Cleanup uses only the harness's ownership-checked path after evidence is
retained; failed or partial identity checks require manual inspection, never a
forced shortcut:

```bash
tests/pp6-qualification/host-env.py destroy --run-id "$RUN_ID"
```

## Remaining PP.6 acceptance outside the installed matrix

| Workstream | Current status at cited evidence | Required closure |
|---|---|---|
| SQLite backup/restore (#1084) | BLOCKED; artifact campaign at `a6b34f9aca12eec41f046157ad82dc23246dfd2e`, source-assembled host at `e76ee74104780ccb2dfeb3e19374c1d89f8f6dc8`; no authenticated restore | Authenticated exact-release restore, custody, crash/disk matrix, canonical parity |
| PostgreSQL 16 backup/restore (#1085) | Backup PARTIAL at `b180cf5aa7b8fd27baecc4a8a392fd6c140b661c` (22 PASS / 5 NOT-COVERED); restore NOT_RUN | Accepted restore protocol, isolated PG16 target, D4 writer exclusion, restore parity and all executable lanes |
| D7 fencing / D3 invalidation / D4 exclusion | BLOCKED | Independent source fencing, all-writer exclusion, replacement identity, stale credential/lease/epoch rejection before activation |
| PKI (#1087) | PARTIAL at `39da026b3f4abf1540e2f0c2f57df0ebcd8c32da`; installed lifecycle NOT_RUN | Issuer/custody authority and join/renew/expire/revoke/replace/re-enroll/restore journeys without private-key export |
| Upgrade/rollback/recovery (#1098) | Exact-artifact journey NOT_RUN | PP.6 compatibility gate and upgrade → rollback/restore → upgrade-again on both backends where claimed |
| Pressure/operator errors (#1089) | PARTIAL; destination-full and journal-v2 failure lanes NOT_RUN | Complete per-case invariants, foreign-state checks, retries, and evidence envelopes |
| Diagnostics/support bundle (#1088) | PARTIAL; SPEC-0051 remains proposed | Accepted bounded contract, read-only redacted bundle, authorization and success/failure secret scans |
| Documentation (#944) | PARTIAL | Runbooks derived only from passed evidence and explicit unsupported boundaries |
| Security/release acceptance (#975) | BLOCKED | Independent review, zero actionable B/H/M, final owner GO |

## Next actionable tasks

1. Immediate infrastructure task: provision the dedicated qualification host,
   authenticated guest images, approved custody/trust/revocation material, and
   independent D7 fencing required by each recovery lane. Then execute the
   applicable E4 checks against authenticated rc.27. Run Q9/E5 separately only
   after written authorization, a suitable bare-metal host, and authorized
   BMC/PDU control are available; their absence does not block E4 evidence.
   Record each OS and evidence tier independently, and do not mark a lane PASS
   before its own execution and evidence review.
2. Next safe Phase B/C engineering slice: add selected-v2 signed-journal
   negative/restart and protected-filesystem publication-failure evidence,
   while extending only read-only restore preflight or validation code. The
   SPEC-0050 contract is accepted; no further decision on that same contract is
   pending. Do not mutate a PostgreSQL target until a distinct disposable
   Phase C mutation authorization and every listed pre-mutation prerequisite
   are present. Any inactive materialization must stop at `INACTIVE_VERIFIED`
   and cannot satisfy the original #1086/#975 activation scope.
