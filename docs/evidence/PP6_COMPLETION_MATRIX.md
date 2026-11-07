# PP.6 completion matrix

**Historical snapshot:** protected `main` at `c454134e584288b49637b11592bb0b59351d022a` (2026-11-04), the merge-queue commit for PR #1215. PR #1215 reviewed head `2d2ebcc1fd5253727ba08581c8d5577efb8d7e7e`; its source implementation head was `3e9e53f867fd8b23bb629fd545e36443565ec4bd`. PRs #1212–#1215 are merged; #1212 merged at `c984175d4bd45437236fa8267c9a5b562f02e621`, #1214 at `ee54bacd9e8185089412c7cb1ffa3be5870b6c9b`, and #1215 at this snapshot. The immutable `v0.4.0-rc.26` release remains authenticated at tag object `b295a9a031ae2969497b6311ea87ee1ff421f676`, source `901af47b306aa779aed72ef61ef25184fabf24eb`, archive SHA-256 `6d7d034aa2f5fdc8ad78dd237ec64605a8623d8042bf23ac420a678051a76685`. Asset authentication passed, but the rc.26 packaged verifier failed during guest verification (exit 2: missing `bins/o3k/tests/fixtures/a10-release-verify.pub`) before installation. Do not conflate asset authenticity with guest verifier success or installed E4 evidence. PR #1214 fixes the self-containment defect. The statements in this dated snapshot that rc.27 was unpublished and Debian 12/Ubuntu 24.04 were the proposed targets are historical and superseded by the current status below. PR #1210's closure guard remains protected. This is a status/evidence projection for #975, not a new architecture, support, or release authority. #640 remains rollback/restore authority and #944 operator-documentation authority. Historical Stage 1 evidence remains in [`PP6_RC25_STAGE1_QUALIFICATION.md`](PP6_RC25_STAGE1_QUALIFICATION.md).

**Verdict:** PP.6 is **BLOCKED**. No full-profile GO or release acceptance is recorded. Every row marked PARTIAL, BLOCKED, or NOT_RUN below blocks the complete #975 GO verdict. The release-level zero actionable BLOCKER/HIGH/MEDIUM review and final owner decision have not occurred.

**Owner test-target direction (2026-11-05):** future PP.6 Linux guest
qualification uses Debian 13 and Ubuntu 24.04. Do not provision Debian 12 for
new tests. Historical Debian 12 runs and dated snapshot evidence below are
preserved as recorded; they are not Debian 13 evidence. This does not claim
Debian 13 installed-platform support.

## Current rc.27 E4 status (2026-11-07 after PR #1222)

**Status: PP.6 BLOCKED; #975 remains OPEN.** Protected `main` is
`4738320ab8afa2df8946aa017caa8c80cf1e3da1`, the protected merge commit for
PR #1222, with parent `32b5e209c724277c2fc77a1a58fb3a7543bbbbb9`. PR #1222
merged at `2026-11-07T15:50:35Z`; its exact reviewed head
`15811dcf4ce6c2af25de00660e5e335eb826ad70` was approved by `senolcolak`.
Exact-head CI `42358204722`, PostgreSQL pressure `42358204641`, and Mock
Cinder `42358204764` passed. Merge-group CI `42386624873`, PostgreSQL
pressure `42386624855`, and Mock Cinder `42386624846` passed on the protected
merge. No self-approval was used.

Protected harness SHA-256 is
`4eed08057f006d9503b199377aaad2e7e74e9a28a99e769d41e350a4df44d22f`.
Immutable rc.27 remains tag object `80cdab1568ef0972602214d0c4656ad70858c07e`,
source `9427e7668afa76bf1f043c9adabe1d616cf5924a`, release workflow run
`42044020384`, and archive SHA-256
`dea259144d16eb2cfa59169b5cf73e0e5df528663209e6b8bc34ea3d7da74f05`.
Sigstore/OIDC/transparency, provenance, signed manifest, published digests,
archive verification, and the self-contained A10 verifier passed; the A10
verifier confirmed `recovery-migrate-v2` is absent from the production
publisher. These are artifact-authentication results, not Q1.

The fresh read-only Ubuntu host preflight
`pp6-e4-preflight-20261107-ubuntu07-final` passed on the authorized nested-KVM
host; transcript SHA-256 is
`b11d783b3217f173b4644c3ea621fca30a35a3b41f38a60f35f7500469cdb623`.
Root/KVM access, nested virtualization, capacity, required commands, no
forwarding/default route, and no active qualification VM or run process were
verified. The official Ubuntu 24.04 image signature and manifest digest passed
with image SHA-256
`04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94`.

| Run | Ubuntu provisioning | Installer result | Q1 installed identity | Q2 |
|---|---|---|---|---|
| `pp6-e4-20261107-ubuntu05` | **FAIL** before VM creation; wrapper umask changed the harness-owned directory permissions and libvirt could not access the run disk | NOT_RUN | **FAIL**; no guest | NOT_RUN |
| `pp6-e4-20261107-ubuntu06` | PASS: cloud-init/NoCloud, static network, pinned SSH, systemd, account and separate ext4 mounts | **FAIL** at `apt-get update` (exit 100); the run-scoped mirror rejected backports and returned restricted-index mismatches against signed InRelease metadata | **FAIL**; no binaries or installed manifest | NOT_RUN |
| `pp6-e4-20261107-ubuntu07` | PASS: cloud-init/NoCloud, static network, pinned SSH, systemd, `o3k` account and separate ext4 mounts | **FAIL** at installer ownership setup. Authenticated rc.27 and A10 checks passed; then `mark_owned_dir` rejected populated unowned `DATA_DIR=/var/lib/o3k` because the harness has `state` and `journal` mountpoints there and no `.o3k-owned` marker. | **FAIL**; no installed binaries or manifest | NOT_RUN |

The ubuntu07 installer failure is retained verbatim; the first rejected
predicate and post-installer state are recorded under
`/var/lib/o3k-pp6-qualification/runs/pp6-e4-20261107-ubuntu07/evidence/`.
The evidence directory manifest is `evidence/SHA256SUMS`, SHA-256
`0125ba7873c13aeba144862ec50f9c34531da895009be3b05f74880d971072d1`; it
verifies every retained regular file in that directory. The installer log
SHA-256 is `96e2bfb4a0606dd3dc3c85a4d679b1dcfc237b1e40584befc3566e2f58ef9044`,
the installer result is `b1c5ff236e5b502122b563aa264ea7be0608a2e3f743f0f73f319d2a014fa466`,
the preinstall account record is
`893628a45c7eb721381b4555aded3c927cdead5901f4d44e0b64bafae993cef2`, and
the post-installer state is
`2b2573c583c2e193c72951269c28cf80227a7555ba8eb82711b87443f1f073e9`.
The run-owned VM, network, package mirror and
guest release server were cleaned up only after evidence collection. No
installer retry or guard bypass was performed. The current harness mount
layout and immutable installer ownership guard have an unresolved integration
conflict; an owner must select a supported storage layout/installer contract
before another qualification attempt.

**E1:** PR #1222's harness regression and CI passed on the exact reviewed
head; the merged protected harness is the identity above. **E2:** independent
review and all exact-head and protected merge checks passed. **E3:** Ubuntu
guest provisioning passed for ubuntu06 and ubuntu07; the installer failures
remain E4 blockers. **E4:** **FAIL/BLOCKED**; rc.27 artifact authentication
passed, but no installed release identity exists; Q1 has no PASS and Q2 is
NOT_RUN. **E5:** physical host power loss **NOT_RUN**. Guest reboot or
force-restart is not E5.

Debian 13 was not investigated further in this work. Historical runs
`pp6-e4-20261106-0194` and `pp6-e4-20261107-debian13-002` remain unchanged;
their boot observations do not establish a root cause. Do not provision
Debian 12 against current owner direction. The Debian 12 acceptance target
versus current Debian 13/Ubuntu 24.04 owner direction remains an explicit
unresolved acceptance-target conflict.

PP.6 full GO still requires its separate backup/restore, PKI, observability,
upgrade/recovery, resource-pressure, documentation, independent review, and
zero BLOCKER/HIGH/MEDIUM acceptance gates. No A10 publisher enablement,
production restore mutation, Araf, PP.7, or general Debian 13 support work is
authorized by this update.

## Historical rc.27 E4 status (2026-11-07 before PR #1222 merge; superseded above)

Protected `main` advanced from `48c88c674adfb61edcac7d3aa78780e968c54573`
through PR #1221 to merge commit `32b5e209c724277c2fc77a1a58fb3a7543bbbbb9`
(parent `48c88c674adfb61edcac7d3aa78780e968c54573`). PR #1221's exact
reviewed head was `5df40ce3db9dca643e936413cd288c2d649df122`; `senolcolak`
approved that head. Exact-head CI `42284063096`, Mock Cinder `42284063141`,
and PostgreSQL pressure `42284063089` passed; merge-queue CI `42290049783`,
Mock Cinder `42290049543`, and PostgreSQL pressure `42290049792` passed; the
post-merge CI `42294370899`, Mock Cinder `42294370799`, and closure guard
`42294376766` passed. PR #1221 is merged; this is the protected qualification
harness identity, not the release source or executable identity.

The merged harness SHA-256 is
`d94de11ec15fa484e40c944146aee39715ba8274935b70fc166bf9403ef6723d`.
Immutable rc.27 remains tag object `80cdab1568ef0972602214d0c4656ad70858c07e`,
source `9427e7668afa76bf1f043c9adabe1d616cf5924a`, authenticated archive
SHA-256 `dea259144d16eb2cfa59169b5cf73e0e5df528663209e6b8bc34ea3d7da74f05`,
release workflow run `42044020384` attempt 2. Keyless Sigstore/OIDC,
transparency, provenance, signed manifest and extracted archive verification
passed; the A10 packaged verifier confirmed production
`recovery-migrate-v2` publisher exclusion. These artifact checks are not
installed Q1/Q2 evidence.

**Ubuntu 24.04 is the priority lane.** Three independent guests booted and
passed the merged harness's cloud-init/NoCloud, static address, expected MAC,
host-key-pinned SSH, systemd, and distinct ext4 state/journal checks. All three
installer attempts failed before an installed executable identity was
produced:

- `pp6-e4-20261107-ubuntu01`: the published installer rejected a `file://`
  source URL. Initial SSH shell expansion also caused a separate auth mismatch;
  neither attempt installed O3K. Evidence is retained under
  `/var/lib/o3k-pp6-qualification/runs/pp6-e4-20261107-ubuntu01/evidence/`.
- `pp6-e4-20261107-ubuntu02`: release authenticity passed, then `apt-get
  update` failed exit 100 because restricted indexes disagreed with signed
  InRelease sizes. Evidence result JSON SHA-256
  `7e5ccb8d8fc58ef1e61574d83ea67118e412bddb59912a343fbc04f5e41d7887` is
  retained under its run evidence directory.
- `pp6-e4-20261107-ubuntu03`: release Sigstore/archive verification, archive
  digest, dependency install, and A10 publisher exclusion passed. The
  immutable installer then rejected the pre-created `o3k` account because the
  merged harness set its home to `/nonexistent` while the installer requires
  `/var/lib/o3k`; installer exit 1. No O3K executable or service unit was
  installed. Result JSON SHA-256
  `c53d68e7b77eda40dfb665cedaa5b1dfcc8565222914bacc4c93cabed9fad2a0`.

The narrow harness correction is PR #1222, exact head
`15811dcf4ce6c2af25de00660e5e335eb826ad70`, which sets the guest account home
to `/var/lib/o3k` and adds a regression test. As of this snapshot it is OPEN,
requested from `senolcolak`, has no review, is `REVIEW_REQUIRED` / `BLOCKED`,
and has not merged. Exact-head CI run `42358204722` (including Rust, still
IN_PROGRESS at update time; other reported jobs passed), Mock Cinder
`42358204764`, and PostgreSQL pressure `42358204641` are recorded separately.
Do not execute this changed harness until it has exact-head review, all
protected checks, and protected merge. Ubuntu installed E4 therefore remains
**FAIL**; Q1 = **FAIL / installed executable identity absent** and Q2 =
**NOT_RUN** for each attempted installer lane.

**Independent Debian 13 diagnosis:** fresh host preflight
`pp6-e4-dedicated-preflight-20261107-debian02` passed; transcript SHA-256
`359b093c58c7c11bb0ff0a062670b15ebf642b1d3eb902aaafe4a5a89c20f6be`. The
host was the authorized nested-KVM `o3k-pp6-local-runner`, root, 8 CPUs,
32,079,972 kB MemAvailable, 258,471,243,776 bytes free under
`/var/lib/libvirt`, `/dev/kvm` present, forwarding disabled, no production
route, no active guest/custom network, and required commands present. Existing
inactive libvirt pools all point to retained earlier PP6 run IDs. Debian cloud
image SHA-512 matched the official HTTPS manifest exactly; manifest SHA-256
`12d276e2c1befd925a35509659c8887cd931ece7aba9bd8597cf13322aa1d225`, image
SHA-512 `f46f0671a6e5bdec5291ab8972bae2f10e5408c2f64a74078f11efc2f06a436a9d0313ed50e0472542eeabf780e9f7c792ac0a314c6c20507fcd9fd81b468c3d`,
image SHA-256 `b2aca2bee42c7082fd6aba4a5bb1a89612087a405e99896920f3346f7b23b9d1`.
The cloud metadata path returned HTTP 404 for `SHA512SUMS.sign`; provenance
is the official HTTPS manifest and exact hash, not a detached signature.

Run `pp6-e4-20261107-debian13-001` is a pre-provision FAIL: the wrapper
created the run directory to capture stdout before invoking the harness, which
then correctly refused the existing path; it created no guest. The
independent `pp6-e4-20261107-debian13-002` provisioning attempt with merged
harness `32b5e209c724277c2fc77a1a58fb3a7543bbbbb9` / script SHA above failed
after the 600-second SSH bound at `192.168.195.20`. Its retained serial log
repeats GRUB's `Booting Debian GNU/Linux`; host interface counters show 0 TX
packets/bytes, the guest neighbor is FAILED, and cloud-init/guest journal were
unavailable over SSH. Captured domain/network XML and bounded QEMU/libvirt,
route, bridge and neighbor diagnostics do not establish a root cause. Evidence
is at `/var/lib/o3k-pp6-qualification/runs/pp6-e4-20261107-debian13-002/evidence/`;
`evidence.sha256` SHA-256 is
`f1ddd9e6ea9d06b0fbe49b70e4647f6bc86cd3b742ef5410f16457ad3600dc24`. The
guest/network were removed through ownership-checked cleanup with evidence
retained. Installer unsupported-platform rejection = **NOT_RUN**, since Debian
never reached SSH. Debian 13 is not substituted for the historical Debian 12
acceptance target; owner direction forbids new Debian 12 provisioning, so the
E4 OS-target conflict remains unresolved.

- **E1:** harness regression test passed 16/16 and Python compilation passed locally; exact
  #1222 Rust/CI run was still in progress at this snapshot.
- **E2:** #1221 exact-head, merge-queue and post-merge checks passed as listed;
  #1222 review and final protected checks remain pending.
- **E3:** Ubuntu guest provisioning passed in three runs; Debian 13
  provisioning failed. No E3 evidence is promoted to installed E4.
- **E4:** **FAIL/BLOCKED**. rc.27 authentication passed, but Ubuntu installer
  lanes did not install executables; Debian 13 boot failed. Q1 installed
  identity has no PASS; Q2 is NOT_RUN. Historical run
  `pp6-e4-20261106-0194` remains FAIL with its prior hashes and unresolved
  root cause.
- **E5:** physical host power loss **NOT_RUN**. Guest reboot or force-restart
  is not E5.

#975 remains OPEN and PP.6 remains BLOCKED. The separate release-level backup /
restore, PKI, observability, upgrade/recovery, resource-pressure,
documentation, independent review and zero BLOCKER/HIGH/MEDIUM owner-acceptance
gates remain outstanding. A10 publisher enablement, production restore
mutation, Araf, PP.7, and general Debian 13 support remain out of scope.

## Historical rc.27 E4 status (2026-11-06; superseded below)

### Independent-boot recovery update

The later isolated attempt `pp6-e4-20261106-0194`, using protected harness
`48c88c674adfb61edcac7d3aa78780e968c54573` and script SHA-256
`20c7cafb2aa3de8353241e433f1fed8eae1c3f7612a222f64cde4261e2d4515d`, also
failed during Debian 13 guest provisioning. Its result JSON SHA-256 is
`318f41009750970701764a7c6cf319b548bb8be050a4e41a4c0cfd6ec532c0af`; the
attempt transcript SHA-256 is
`8273941a26d4ea2791a8d9874e9a666a2a042ae9134745f00a3e0a6119ef6a85`; and
the retained QEMU log SHA-256 is
`4aeda397d28e90514f56b5f0975b26709270f1b1aef6c65f7792867a0932ab71`.
Debian 13 at `192.168.116.20` timed out on SSH. The bridge recorded 90 bytes
and one packet received, with zero transmitted bytes/packets; neighbor
resolution remained incomplete. QEMU's log shows the expected root disk at
boot index 1 and NIC MAC `52:54:00:ab:94:f9`, but does not show guest boot
progress. The VM's domain XML and serial transcript were not retained, and no
guest cloud-init/SSH diagnostics were available. Therefore firmware/kernel/
initramfs boot, NoCloud discovery, network application, and SSH host-key or
authentication causes remain unresolved; no root cause is established.
Ownership-checked cleanup passed and retained the evidence. Ubuntu 24.04 was
not attempted in that invocation, and Q1/Q2 remain NOT_RUN for both guests.

The qualification-only harness recovery change is being prepared for protected
review. It adds independent guest selection (Debian 13, Ubuntu 24.04, or both)
and bounded failure capture; it changes no application/release code and does
not change the immutable rc.27 identity or supported-platform policy. Until
that change passes exact-head review/checks and merges, no live-boot result is
claimed from it.

- **Published release:** `v0.4.0-rc.27`, annotated tag object
  `80cdab1568ef0972602214d0c4656ad70858c07e`, source
  `9427e7668afa76bf1f043c9adabe1d616cf5924a`, release workflow run
  `42044020384` PASS, archive SHA-256
  `dea259144d16eb2cfa59169b5cf73e0e5df528663209e6b8bc34ea3d7da74f05`.
  Independent Sigstore/OIDC/transparency/provenance, signed manifest, asset,
  and extracted-archive authentication passed; production
  `recovery-migrate-v2` is absent. This does not establish installed evidence.
- **Qualification harness used by run 0193:** protected main
  `c7f7bfb7e33608e36c0c29c83382f2793903af6d`, including merged PRs #1218 and
  #1219; script SHA-256
  `b49b90b67c67c2073465e8e578d9135e908f4319dd232f5b0ed60c54c7d86f39`.
  It selected Debian 13 and Ubuntu 24.04 but still waited for DHCP. The static-IP
  adaptation in this change addresses the qualification-node use case; it does
  not alter the release source SHA or release artifact.
- **Dedicated-host preflight:** PASS on authorized disposable nested-KVM host
  `o3k-pp6-local-runner`: x86_64, root access, 8 CPUs, 32 GiB available memory,
  241 GiB free storage, `/dev/kvm`, forwarding disabled, no default route, no
  unrelated VMs, and no active test network before provisioning. Initial
  transcript SHA-256 `e7ce0a861c04d40ddce32d88402cdfff9bacd1fdcc7fc67ebe90f8b04b502039`.
  The Trixie package fixture was started only after its isolated bridge existed
  and stopped after the failed run was cleaned. The earlier rejected `o3k-rust`
  preflight remains recorded as FAIL in the dated evidence below.
- **Provisioning run:** `pp6-e4-20261106-0193` failed while waiting for the
  Debian 13 guest at its DHCP-pinned SSH address: no DHCP lease appeared and the
  guest NIC recorded zero transmitted packets. The protected harness reported
  `guest SSH timeout for 52:54:00:64:62:e5`. The VM and isolated network were
  removed by ownership-checked cleanup; logs and result record remain at
  `/var/lib/o3k-pp6-qualification/runs/pp6-e4-20261106-0193/evidence/`.
  The result JSON SHA-256 is
  `b51078979f79b7cc934e8985e893b9618c774635af0d4d2d444fac3dcb1253c7`; the
  provisioning log SHA-256 is
  `c60d97258a51242b4083728e1169d69b50407315e63b3396b41a80dbcdc5b25e`.
- **E4:** FAIL at Debian 13 provisioning. Debian 13 Q1 = FAIL because required
  guest provisioning failed; Q2 = NOT_RUN. Ubuntu 24.04 Q1/Q2 = NOT_RUN because
  provisioning stopped before that guest. No installed-release assertion ran,
  and no new product defect is established. E5 remains separately NOT_RUN. No
  Debian 13 support claim is made.
- **Next run:** use the static-IP harness path: Debian `.20`, Ubuntu `.21`,
  cloud-init NoCloud network config matched by MAC, no libvirt DHCP range, and
  no guest default route. Require the address, route, host-key-pinned SSH, and
  separate ext4 identity checks to pass before installation. Keep run 0193 as
  FAIL; it is not reclassified by the harness change.
- **Per-OS Q1/Q2:** Debian 13 Q1 = FAIL / Q2 = NOT_RUN; Ubuntu 24.04 Q1 =
  NOT_RUN / Q2 = NOT_RUN.
- **Historical CI failures:** runs `41919177633` (backup preflight) and
  `42022349408` (P12.6 SQLite recovery) remain recorded as FAIL with unresolved
  causes. The owner accepted residual diagnostic uncertainty for release
  candidate qualification only; this is not a PASS, root-cause finding,
  production acceptance, independent security approval, or PP.6 GO.

The rc.27/harness identity and current host/E4 status supersede the dated
readiness statements below where they say rc.27 is unpublished, Debian 12 is a
future guest target, or no fresh host assessment has occurred. Historical run
records below are otherwise retained without reinterpretation.

## rc.27 preparation and qualification evidence

- PR #1212 reviewed head `dd959349157b5b181b4ac589526476fcc6302e93`, protected merge `c984175d4bd45437236fa8267c9a5b562f02e621`: signed journal restart tests; source and protected checks passed.
- PR #1213 reviewed head `b4315c7fe8f296893fd6a86c3c69ed177d26396b`, protected merge `3dc280a563bbd3d1f63e2180ad7deba6f78461c2`: explicit virtio `vda` root disk, JSON/YAML cloud-init, cloud-init completion wait, actual DHCP lease parsing, guest-root ext4 validation, `libvirt-qemu` disk-owner cleanup, and SSH host-key ownership marker. Nine unit tests and py_compile passed. Local run harness SHA-256 `f1a64595d6eafe74d55bd972cfad2102298151e98fd2a5c04fbf2f80168cc76d` successfully provisioned Debian 12 and Ubuntu 24.04, recorded separate ext4 state/journal disks and disabled forwarding, then cleaned run-owned VMs/network while retaining evidence at `/var/tmp/pp6-local-20261104/evidence`. It reported `NOT_INSTALLED`; classify as E3 infrastructure evidence, never installed E4.
- PR #1214 reviewed head `cb6dba632276830e022038ea399c7a43164e3bff`, protected merge `ee54bacd9e8185089412c7cb1ffa3be5870b6c9b`: self-contained packaged A10 verifier plus extracted-archive regression. It preserves archive corruption, content modification, A10 marker, test-key, publisher-symbol, missing/failing inspection-tool negatives, and production `recovery-migrate-v2` command exclusion. Protected checks passed.
- PR #1215 reviewed head `2d2ebcc1fd5253727ba08581c8d5577efb8d7e7e` merged through the protected queue as `c454134e584288b49637b11592bb0b59351d022a`; reviewer `senolcolak` approved that exact head. All PR checks passed on that head in CI run `41909388446`. Merge-queue CI run `41914575991`, Mock Cinder `41914576072`, and PostgreSQL tablespace `41914576122` all passed on the merge candidate, which is the final protected source commit. The code implementation head `3e9e53f867fd8b23bb629fd545e36443565ec4bd` passes formatting, workspace Clippy, workspace tests, 9 PP.6 harness tests, release-gate, bundle-integrity, worker-asset-sync, workflow/actionlint, 27 installer negatives, and A10 publisher exclusion. The root-only installer full-wrapper case was skipped because the runner is non-root. An extracted rc.27 packaging regression archive passes all 11 A10 positive/negative cases outside the checkout. This local regression archive reused authenticated rc.26 binaries only to validate packaging/verifier source; it is not an rc.27 build or release artifact and makes no source-to-binary identity claim. A direct optimized build on this host failed the explicit glibc baseline guard (host 2.39 exceeds Debian 12 2.36); the protected Debian 12 build remains mandatory. PR #1215's earlier heads failed the upgrade process matrix (69 passed / 7 failed) on Ubuntu 26.04, outside the supported Ubuntu 24.04/Debian 12 allowlist; a local Debian 12 fixture was added through a non-root-only path override, with a unit assertion that root cannot redirect platform identity. The process matrix passes locally 78/78 with CI-style database variables.
- Post-merge CI run `41919177633` is **FAIL**: `cargo-test` recorded `impostor_executor_is_rejected_by_listener` returning `source-unavailable` instead of `unauthorized-peer`. This is an `execute_inner()` source preflight result before any listener connection, not evidence of an authentication bypass. Its log does not identify which filesystem metadata lookup failed, so the underlying cause remains unresolved and is not called a proven test race. On exact protected source `c454134e584288b49637b11592bb0b59351d022a`, the focused all-feature library test passed 50 invocations and the full `o3k` library suite passed 475 tests with 6 ignored; PR #1216 CI also passed on its docs head. Those results show non-reproduction only. Keep the failed run visible and release readiness BLOCKED pending the required disposition or a reproducible fix; the assertion and fail-closed authorization behavior are unchanged.
- E4: **NOT_RUN**. rc.26 authenticated release assets but its guest verifier failed before install; rc.27 has not been tagged or published. E5 physical host power loss: **NOT_RUN**.

## A10.1 publisher milestone (PR #1198)

**A10.1 production publisher enablement: DISABLED AND NOT AUTHORIZED**

**A10.1 runtime migration: NO-GO; bounded contract implementation/testing is ACCEPTED**

**PP.6: INCOMPLETE**

Owner decisions at exact reviewed heads PR #1192 (`c8ab0a6f1b21bddc70ef46e34357f62ad64e6db4`) and PR #1193 (`16f41ad4c531abcccc2c1dbb9246333289b67849`) are ACCEPT. PR #1193 explicitly authorizes bounded A10.1 contract implementation and testing under SPEC-0050 §7.4, including the authenticated installation-state migration event as the durable v2 selector and fail-closed publication order. The PR #1192 owner decision is recorded at [comment #6504152604](https://github.com/o3kio/o3k/pull/1192#issuecomment-6504152604); the detailed PR #1193 decision is [comment #6541530386](https://github.com/o3kio/o3k/pull/1193#issuecomment-6541530386). PR #1210 merges the #975 closure guard. These decisions authorize bounded implementation/testing only. They do not authorize production publisher enablement, PostgreSQL target mutation, controller activation, independent security acceptance, or final PP.6 GO.

PR #1198 retains the signed migration publisher and its verifier improvements for source-built qualification. In ordinary production builds, the mutating publisher module, `o3k recovery-migrate-v2` CLI variant, and dispatch arm are excluded at compile time. The `a10-process-test-hooks` feature is rejected by a compile-time error when `debug_assertions` is disabled. The read-only v2 release-inventory and installed-executable digest verifier remains in standard builds and continues to gate startup admission.

Implemented in the PR candidate: externally signed migration publication; authenticated v2-selector verification; exact-forward continuation; source-built signed `NEVER_RECOVERED` migration and idempotent replay; authenticated staged-input retry; and source-built root process evidence. The ignored harness completed a real migration, idempotent replay, exact-forward retry, 20 process interruption boundaries, independent daemon/operator/upgrade/rollback/compute denial at 10 post-selector boundaries, and direct compute denial while D8 was held. It used explicitly selected binaries rebuilt from the same source tree after an earlier stale-artifact fixture failure; this is not installed-release, real-systemd, or power-loss evidence. The PR candidate is not a production migration capability.

Disabled: migration publication in standard production binaries and installed runtime migration. The packaging path checks externally supplied release binaries, the generated release bundle, and bundles at installation verification. A protected CI release guard builds the optimized default CLI, tests command absence, and requires optimized compilation with `a10-process-test-hooks` to fail.

Follow-up #1206 merged at `9512832ad79da3cc555739dfd94e5708598e2ca4` and #1207 at `bf04c8b61c95435df973502f35197bb74df22f78`; they correct v2 release-inventory and publisher provenance parsing for the authentic seven-entry signed `release-digests.txt`. Evidence is source/unit, protected CI, and qualification-only real-filesystem process evidence at those exact revisions, including the 20-boundary publisher journey recorded in [`PP6_PUBLISHER_PROVENANCE_COMPAT.md`](PP6_PUBLISHER_PROVENANCE_COMPAT.md). It is not authenticated installed-release evidence and does not enable the production publisher.

Still outstanding: complete D8-A10-01–16 installed consumer/startup-denial process qualification; real systemd guest policy/trust/journal and denial qualification; exact authenticated installed-release tests on clean Debian 13 and Ubuntu 24.04; protected ext4 power-loss durability evidence; and independent security/release acceptance. Publisher process testing remains in its separate qualification-only evidence class and must not be injected into or claimed for a production bundle. SIGKILL/process-restart evidence is not power-loss evidence. No installed-release production claim is made. These statements supersede the older A10.1 implementation-status wording in the historical snapshot rows below; they do not change SPEC-0050 requirements or close #1086/#975.

## A10 Phase B journal-v2 consumer (PR #1199)

PR #1199 is included in protected main `a10fc7a0ad6a0b35ba132b14e6e0ffc64ecced60` (it merged at `0a4f630c5a7a3765d792e770aff83e90d6a85123`) from reviewed head `0cbbfb8d4dca308940b7f1aa16ee28c27cf86b96`; its human approval and all ten ordinary PR checks were present, and the protected merge-group CI completed successfully before queue merge. The integration recovered the preserved `/home/ubuntu/o3k-a10-v2` work without modifying that worktree. The authenticated journal consumer accepts a private context only after the installed v2 selector, high-water, signed policy, release inventory, and current C1 trust/revocation checks pass. It binds every record to the selected policy digest, PostgreSQL 16, virtualized deployment, release identity, installation/site identity, inactive branch, operation/artifact, and target identity. Startup denies when a journal-v2 file is present, including terminal `INACTIVE_VERIFIED`. Append publication requires the candidate's complete prior signed record prefix to match byte-for-byte, preventing a same-operation chain fork. Publisher production enablement remains compile-time disabled; no target/database mutation or controller activation is implemented.

Evidence: **PASS, source/unit** — 12 journal-v2 unit tests, including exact prior-prefix fork rejection; **PASS, source/workspace** — formatting, Clippy, and workspace tests on the reviewed head; **PASS, protected CI** — ordinary PR checks and merge-group CI; **NOT_RUN** — selected-v2 installed-release journal process tests, the full Phase B write/fsync/rename/readback failure matrix, D8-A10-01–16 process evidence, actual systemd denial tests, and authenticated clean Debian 13/Ubuntu 24.04 release qualification. D8 `pp6_recovery_files` is privileged/ext4-gated and was not executed in the source workspace run. Passing protected CI is not installed-release, systemd, ext4 power-loss, independent review, or restore-activation evidence. These results do not close #1086 or #975.

## Installed-release qualification readiness

The existing release workflow is the required source of an immutable candidate: exact protected tag, approved `release` environment, Debian 12 build baseline, GitHub OIDC/Sigstore provenance, and verification of the published bundle. PR #1201 merged at protected source `8e3cfa4e1f0023e29217da709be3de6930a5e891` with aligned rc.25 package/installer/Helm/Docker pins and a tightened release-gate parser. The authenticated `v0.4.0-rc.25` prerelease exists at tag object `42de13cee64a37d69e900fd4272ff5e849a328b8`, with provenance bound to `aabce51fc1fdb63d98319f8d9a9b79419424d313`, release workflow run 41346503762 and Rekor log index 3636078640 after `release`-environment approval. It lacks #1206/#1207 and is not a substitute for current protected source. Offline signer custody remains unqualified.

Stage 1 preflight at exact protected source `8e3cfa4e1f0023e29217da709be3de6930a5e891` (PASS, source-built, recorded in [`PP6_RC25_STAGE1_QUALIFICATION.md`](PP6_RC25_STAGE1_QUALIFICATION.md)): the Debian 12 bookworm release build succeeds with the glibc 2.36 baseline proof; the bundle assembles and `verify-release-bundle.sh` passes, including the A10.1-publisher-absence check; the release-profile `o3k` rejects `recovery-migrate-v2`. PR #1203 merged at `6c1df09302970b720dae04424dac5052b61ad057`; #1205 merged the Stage 1 evidence at `aabce51fc1fdb63d98319f8d9a9b79419424d313`. PR #1208 merged at `901af47b306aa779aed72ef61ef25184fabf24eb` and prepared rc.26. Tag `v0.4.0-rc.26` (tag object `b295a9a031ae2969497b6311ea87ee1ff421f676`) points to that merge commit; release workflow run 41642704256 passed after environment approval, and the prerelease was published at 2026-11-03T13:37:42Z. Independent exact-tag verification passed the protected workflow/OIDC identity, Sigstore/Rekor proof, seven-entry signed digest manifest, archive and bundle integrity, glibc floor, source/version/upgrade-floor binding, and A10 production-publisher exclusion; published executables matched an independent Debian 12 rebuild byte-for-byte. This is authenticated release evidence only, not installed-release evidence.

The run-scoped Debian 12/Ubuntu 24.04 systemd/ext4 harness originated in PR #1200 at protected main `a10fc7a0ad6a0b35ba132b14e6e0ffc64ecced60` (reviewed head `4a84cb4a619b0af5a92f97dee76159b3590a1881`) and was repaired in #1213. The 2026-11-03 shared-host assessment remains historical; do not use that shared host. The #1213 dedicated local E3 run successfully provisioned and cleaned its owned guests/network, with retained evidence and `NOT_INSTALLED` status. A fresh read-only preflight is still required on the explicitly authorized disposable host after rc.27 authentication. `capture-installation` records a caller-supplied, previously verified identity; it does not itself verify Sigstore provenance. rc.26 assets authenticated and include #1206/#1207, but guest verification failed before installation. rc.27 release authenticity and E4 remain NOT_RUN.

## Acceptance and evidence matrix

| Requirement / issue | Existing implementation or PR | Exact protected source and evidence | Status | Remaining work | Missing infrastructure or human dependency | Blocks PP.6 GO? |
|---|---|---|---|---|---|---|
| #1084: consistent SQLite capture, exact manifest/inventory, encrypted authenticated artifact, safe staging/publication/replay | #1164 stream primitives ([`41451d1`](https://github.com/o3kio/o3k/commit/41451d1e52c7171ac148df91ef7ec44376ef0fd5)); #1167 controller-owned writer drain ([`2a481ca`](https://github.com/o3kio/o3k/commit/2a481ca7c085d3515c14e12dfe92ce4217c84775)); #1169 artifact/verify ([`35e0490`](https://github.com/o3kio/o3k/commit/35e049062b6af709141f54522692e8e0c8865661)); #1170 D9 reservation, D13 inventory, installed trust loader ([`70ad01b`](https://github.com/o3kio/o3k/commit/70ad01bdf29eeb8e3a02decd560c18c94e968c14)) | Protected `main` includes all four. [`ISSUE_1084_ARTIFACT_EVIDENCE.md`](ISSUE_1084_ARTIFACT_EVIDENCE.md), `FINAL-COMMIT-BINDING` campaign source `a6b34f9aca12eec41f046157ad82dc23246dfd2e`, reports 44 PASS / 1 NOT-COVERED and 19 handoff PASS / 7 documented; campaign-only/test-hook results are not installed-release results. | PARTIAL | Close the remaining artifact/schema/custody cases, validate full crash and disk-boundary behavior on the supported release, and publish evidence at the final exact release source. | Approved offline artifact/recovery signers and witnessed two-of-three custody; full ext4 bounded-volume run. | Yes |
| #1084: exact-source authenticated installation, supported installed service, end-to-end custody and restart/crash qualification | Historical installed-host path at #1170 used no authenticated release | [`ISSUE_1084_INSTALLED_ACCEPTANCE.md`](ISSUE_1084_INSTALLED_ACCEPTANCE.md) names source `e76ee74104780ccb2dfeb3e19374c1d89f8f6dc8`, Ubuntu 24.04 userland, `o3k-demo-v1`, and a locally assembled tarball/manifest. It explicitly says that run was not OIDC/Sigstore/Rekor-authenticated; only one signing-wait SIGKILL boundary was installed-tested. rc.26 release assets authenticated, but guest verification failed before install; rc.27 remains unpublished. No clean guest installation/capture has run. | BLOCKED | After explicit authorization and authenticated publication, install immutable rc.27 on clean Debian 13 and Ubuntu 24.04 systemd guests; capture exact manifest/executable identity and run the supported startup, bootstrap, service, configuration, restart and crash matrix. | Dedicated isolated host with root authorization; authenticated guest images; approved signers/custodians and trust/revocation distribution. The previously assessed shared development host is unsuitable; do not reuse it. A fresh read-only preflight is required on the explicitly authorized disposable host. | Yes |
| #1085: PG16 consistent dump, D4 writer exclusion, exact migration/catalog identity, replay and interruption | #1171 PostgreSQL 16 backend/D4/D10 ([`b50f537`](https://github.com/o3kio/o3k/commit/b50f537557bcc313a3663900b90572bd7b6f98f4)); #1172 isolated definition validation ([`07edaee`](https://github.com/o3kio/o3k/commit/07edaeea9995180925fb047f8fb5fa8e7af6611e)) | [`ISSUE_1085_POSTGRES_BACKUP_EVIDENCE.md`](ISSUE_1085_POSTGRES_BACKUP_EVIDENCE.md), documented rebased campaign revision `b180cf5aa7b8fd27baecc4a8a392fd6c140b661c` (PR final implementation head `2fe8b5550768a19f46475312b3ff1948459971d3`; no automatic evidence transfer between revisions), PG 16.15 disposable cluster, 22 PASS / 0 FAIL / 5 NOT-COVERED. Exact protected integration includes the implementation at `b50f537557bcc313a3663900b90572bd7b6f98f4`. | PARTIAL | Resolve each NOT-COVERED lane and produce qualifying exact-release evidence. Keep `case-r-managed-cluster` explicitly unsupported; it is not an implementation requirement or a PASS. The other four lanes require execution or the accepted signer amendment. Current evidence does not include restore. | PostgreSQL Option B accepted service/transport/trust-schema amendment, external non-exportable PKCS#11 HSM signer plus mTLS service/trust distribution; independently administered second-host ingress ACL; controllable postmaster reload failure and bounded full-disk filesystem. | Yes |
| #1085: reject foreign targets and demonstrate PostgreSQL restore parity/zero foreign mutation | Backup and preflight exist; no accepted real restore implementation/evidence | #1172 is definition validation/preflight only. #1085 acceptance requires a real isolated PostgreSQL target, concurrent-writer consistency and canonical parity; the #1085 evidence explicitly makes no restore/activation claim. | NOT_RUN | Implement and execute the separately authorized restore path, including fresh target checks, interruption, wrong-target negatives, canonical inventory parity, secret-safe diagnostics and foreign-state preservation. | Exact-head accepted restore protocol; isolated disposable PG16 target and full evidence harness. | Yes |
| #1086: fresh-host restore into explicitly owned empty paths/DB, signed durable intent, phase restart/crash handling | #1177/#1178/#1185/#1188 C1/C1.1 foundations; disabled A10.1 publisher PR #1198 at `e1d6d4e13ce7bbe2cc3353f8dc8e9d78d853cef6`; Phase B PR #1199 merged at `0a4f630c5a7a3765d792e770aff83e90d6a85123` from reviewed head `0cbbfb8d4dca308940b7f1aa16ee28c27cf86b96` | C1/C1.1 and the disabled publisher are protected. Merged Phase B adds authenticated selected-v2 journal verification, signed policy digest binding, exact-forward chain checks and startup denial; 12 source-level unit tests pass. Selected-generation process tests, complete negative/crash matrix and installed-release evidence are NOT_RUN. | BLOCKED | Qualify the selected-v2 consumer with a valid signed disposable fixture; execute all process/crash/restart negatives and exact authenticated installed-release qualification. Keep target mutation/controller activation separately gated by D4/D8/D9/D10/D12/D13 and preserve original #1086/#975 activation obligations. | New immutable signed release from exact reviewed source; clean Debian 13 and Ubuntu 24.04 systemd guests; verified ext4 paths and power-cut setup; offline signer custody and trust/revocation distribution; real PostgreSQL 16 only for separately authorized Phase C; protected CI and human review. | Yes |
| #1086 / original #975: controller activation after restore, old identity/lease/epoch invalidation, safe reconciliation | Original #1086 acceptance explicitly requires activation, fencing, canonical restore, then observe-before-retry reconciliation. Accepted A10.1 authorizes only inactive materialization. | SPEC-0050 §7.1 / §7.4 and ADR-0189 at protected `e14601645ba85bb039c41b31c85b7619cb522d67` keep these scopes separate. A10 `INACTIVE_VERIFIED` is terminal and must deny API readiness, leases, reconciliation, provider dispatch and activation. No protected source demonstrates the original activated-recovery sequence. | BLOCKED | Implement and prove the accepted activation path: independent D7 source fencing; D3 replacement of controller identity and stale credential/lease/epoch revocation; D4 exclusion of every source/target writer; boot-bound D8 handoff with one-use nonce and inherited guard; then canonical-state validation and observe-before-retry reconciliation before controller activation. Never extend A10 inactive records into activation. | Independently administered BMC/Redfish or equivalent D7 fencing and recovery host; exact trust/custody; source PG writer exclusion and installed boot-bound service handoff. | Yes |
| #1087: bounded issue, renew, expire, revoke, replace/re-enroll and restore trust continuity | #1181 added bounded PKI lifecycle predicates ([`39da026`](https://github.com/o3kio/o3k/commit/39da026b3f4abf1540e2f0c2f57df0ebcd8c32da)); existing `security.tls_identity` diagnostics are identity/fingerprint only | Protected source `39da026b3f4abf1540e2f0c2f57df0ebcd8c32da` adds predicates/tests, not a proven issuer lifecycle. #1088 signal inventory confirms renewal, expiry, revocation and replacement remain gated. No source-bound real installed lifecycle campaign is cited. | PARTIAL | Implement and prove issuer/key custody, renewal overlap, expiry rejection, revocation propagation, compromised/replaced old credential rejection, safe new enrollment, issuer-unavailable/interrupted-renewal/restart failures and trust continuity through supported restore. Scan all output for secrets. | Explicit issuer/trust/revocation authority and key-custody decision; installed disposable hosts and independent trust distribution; never export agent private keys. | Yes |
| #1088: accepted signal map, secret-safe diagnostics, read-only support bundle | #1130 diagnostics/error redaction ([`92d1803`](https://github.com/o3kio/o3k/commit/92d1803ff20c033311b9b43e5abee282721d95a0)); #1155 PostgreSQL diagnostics read-only evidence ([`959c7cf`](https://github.com/o3kio/o3k/commit/959c7cfa38e1a18db77529af78434bab4dddd208)); #1183 bounded failure responses ([`ff448e8`](https://github.com/o3kio/o3k/commit/ff448e81a80cddca4a655bb1e37a26801cb269b4)); #1129 diagnostics/failure tests ([`18152a9`](https://github.com/o3kio/o3k/commit/18152a9afb873138f0881ed59ae5ce5bfa58262b)) | [`ISSUE_1088_PP6_OPERATOR_SIGNALS.md`](ISSUE_1088_PP6_OPERATOR_SIGNALS.md) is an inventory, not acceptance. SPEC-0051 remains proposed; no exact-revision acceptance or support-bundle implementation is on protected `main`. Existing read-only diagnostics are narrower than the requested PP.6 bundle. | PARTIAL | Obtain exact-revision SPEC-0051 decision; implement only the bounded diagnostics and static-process-identity v1 projection authorized by that decision; prove authorization-before-read, bounds, redaction for success/failure and zero canonical/provider mutations; bind bundle schema/profile/backend. SPEC-0051 §7 excludes backup/restore, PKI and upgrade state without separate accepted authorities and narrow schema amendments; do not add those fields through this matrix. | Exact-revision technical decision by `senolcolak` under the accepted, explicitly non-independent ADR-0190 route before its expiry, plus applicable ADR-0099 release review. This does not satisfy independent security qualification. | Yes |
| #1089: full bounded store pressure, journal failure, interrupted recovery and operator-error matrix | #1129 failure/recovery coverage ([`18152a9`](https://github.com/o3kio/o3k/commit/18152a9afb873138f0881ed59ae5ce5bfa58262b)); #1138 SQLite FD pressure ([`d76b05b`](https://github.com/o3kio/o3k/commit/d76b05b80d8e7eb00f55466bb17c51470e240690)); #1140 bounded memory pressure ([`67dfefe`](https://github.com/o3kio/o3k/commit/67dfefef644646cbbb53fcd34ca65874fd770c03)); #1155 PostgreSQL connection-loss recovery ([`959c7cf`](https://github.com/o3kio/o3k/commit/959c7cfa38e1a18db77529af78434bab4dddd208)); #1184 evidence/runbook reconciliation ([`18c8780`](https://github.com/o3kio/o3k/commit/18c8780632383779582ac5482cde5dfb5c2be5ef)) | [`ISSUE_1089_PP6_FAILURE_MATRIX.md`](ISSUE_1089_PP6_FAILURE_MATRIX.md), refreshed by #1184 at protected `18c8780632383779582ac5482cde5dfb5c2be5ef`, records real backup destination full as NOT_RUN and partial foreign-state/evidence-envelope coverage. Protected C1/C1.1 journal-v1 implementation exists; persistence alone does not prove write/fsync/rename failure handling. Failure-injection proof for the A10 inactive journal-v2 path is not protected. Retain the original failure criterion for every supported journal path. Individual pressure passes do not close the whole matrix. | PARTIAL | Add the remaining mandatory full-disk destination, inactive-journal write/fsync/rename failure, interrupted restore/recovery, operator-error and exact-source evidence cases; prove state invariants and foreign-state preservation for each applicable failure/retry. Do not count store-only lanes as provider/foreign-state evidence. | Disposable bounded filesystem; execution of the merged #1193/#1199 journal-v2 failure-injection cases; backend-specific failure runner and retained evidence. | Yes |
| #1098: machine-readable compatibility matrix; exact-artifact upgrade → rollback/restore → upgrade-again | Existing bounded upgrade engine, including #1150 post-switch resume fix ([`9c11e11`](https://github.com/o3kio/o3k/commit/9c11e11c1c747d0410b869451a6bb7e1be9bc3cc)); #1127 documents current upgrade limits | Current `docs/compatibility/matrix.yaml` is general compatibility data, not the PP.6 release/schema transition gate. #1098 has no merged exact-artifact campaign. Existing SQLite engine rollback snapshots are not portable PP.6 restore evidence; no PG recovery journey is demonstrated. | PARTIAL | Add PP.6 profile/source/schema gate matrix; prove exact authenticated artifacts through install, prior-candidate upgrade, migration, every supported interruption, bounded rollback or restore-only outcome, and upgrade-again. Rejected paths must fail before mutation. Link #640/#944. | Requires accepted A10.1 and the merged #1193 publication-order clarification, #1084/#1085 artifacts, #1086 applicable recovery scope, complete #1089 scenarios, authenticated release artifacts, clean hosts and real PG16 for PG claims. | Yes |
| #944: accurate operator runbooks for install/join/drain/replace, backup/restore, PKI, diagnostics, upgrade/recovery and resource pressure | #1127 runbooks for install, diagnostics and upgrade boundary ([`448cb38`](https://github.com/o3kio/o3k/commit/448cb38ea435b7dfd35aadd96b24a4c34e7e565e)); #1184 documentation consolidation/pressure evidence ([`18c8780`](https://github.com/o3kio/o3k/commit/18c8780632383779582ac5482cde5dfb5c2be5ef)) | #944 remains open and is the authority. Merged docs state current limits; no truthful end-to-end backup/restore, PKI recovery, support bundle, or upgrade/restore journey can yet be documented as supported. | PARTIAL | Complete runbooks only from passed evidence for every required operation and unsupported boundary; link the compatibility matrix and evidence artifacts; avoid a second support-truth surface. | Depends on completion and owner acceptance of the corresponding #1084–#1089/#1098 gates. | Yes |
| #975 overall: exact release identity; supported OS/profile/backend claims; backup/restore; PKI; diagnostics; upgrade/rollback/crash; pressure safety; zero B/H/M; final owner decision | Work is distributed across the merged PRs above; no PP.6 release-candidate acceptance | Protected main is `c454134e584288b49637b11592bb0b59351d022a`, including PRs #1210–#1215. #975 remains OPEN. rc.26 asset authentication is PASS, its guest verifier failed before install, and rc.27 is untagged. Installed and operational evidence, open child workstreams, independent review and final owner acceptance remain incomplete. | BLOCKED | Complete all blocking child criteria, collect installed and operational exact-release evidence, obtain the independent reviews required by applicable release gates and the owner's explicit final acceptance; retain #975 open until then. | Dedicated clean OS hosts, offline signers/custodians, revocation distribution, independent D7 fencing, real PG16, ext4 recovery paths, SPEC-0051 decision and final reviewers. ADR-0190 is explicitly non-independent and cannot satisfy independent qualification. | Yes |

## Acceptance-criterion traceability

AC numbers below follow the bullet order in each linked issue’s **Acceptance criteria**, reviewed 2026-10-29. Each row is a separate obligation; the acceptance/evidence matrix above supplies its protected source, campaign reference, infrastructure dependency and remaining implementation detail. PASS is limited to the stated criterion and evidence tier. All other statuses block complete PP.6 GO. No partial subtest closes an entire criterion. #640 and #944 retain their wider scopes; this projection tracks their PP.6 obligations only.

| Issue / criterion | Obligation | Status | Evidence limit / remaining predicate |
|---|---|---|---|
| [#1084 AC1](https://github.com/o3kio/o3k/issues/1084) | Supported WAL/checkpoint and snapshot APIs | PASS | Disposable-state snapshot/WAL evidence in ISSUE_1084_ARTIFACT_EVIDENCE.md; this PASS is limited to capture tooling, not release qualification. |
| [#1084 AC2](https://github.com/o3kio/o3k/issues/1084) | Cross-file DB/config/release consistency | PARTIAL | D4 capture/handoff exists; complete installed-release interruption and custody proof remains. |
| [#1084 AC3](https://github.com/o3kio/o3k/issues/1084) | Exact release/profile/tool/schema/migration/inventory/digest identity | PARTIAL | rc.26 release identity authenticated but guest verification failed; rc.27 is not published. Installed profile/tool/schema/inventory capture and the no-table SPEC/schema conflict remain. |
| [#1084 AC4](https://github.com/o3kio/o3k/issues/1084) | Approved encryption/authentication and unsafe/duplicate/missing/untrusted rejection | PARTIAL | Artifact negative tests exist; required-member schema alignment and real custody/trust qualification remain. |
| [#1084 AC5](https://github.com/o3kio/o3k/issues/1084) | Private staging, integrity verification and atomic publication across crashes | PARTIAL | Publication tests and one installed signing-wait crash exist; full installed crash/disk matrix remains. |
| [#1084 AC6](https://github.com/o3kio/o3k/issues/1084) | Retry same identity; preserve conflicting content | PARTIAL | Campaign retry/conflict coverage exists; installed exact-release replay qualification remains. |
| [#1084 AC7](https://github.com/o3kio/o3k/issues/1084) | Failure-first consistency/integrity/corruption/interruption/redaction/foreign-state regressions | PARTIAL | 44 artifact PASS and 19 handoff PASS do not cover every required installed boundary. |
| [#1084 AC8](https://github.com/o3kio/o3k/issues/1084) | Disposable SQLite and exact source/harness/profile/schema/artifact binding | PARTIAL | Campaign reports bind these facts; final release evidence is missing. |
| [#1085 AC1](https://github.com/o3kio/o3k/issues/1085) | Transaction-consistent supported dump and restore tooling | PARTIAL | PG16 dump exists; real restore is NOT_RUN. |
| [#1085 AC2](https://github.com/o3kio/o3k/issues/1085) | Server/tool/DB/schema/extensions/ownership/migration validation | PARTIAL | Dump and isolated definition validation exist; restore-time validation remains. |
| [#1085 AC3](https://github.com/o3kio/o3k/issues/1085) | Configuration/trust capture under approved quiescence | PARTIAL | D4 campaign exists; independent ingress and Option B signer/trust qualification remain. |
| [#1085 AC4](https://github.com/o3kio/o3k/issues/1085) | Fresh empty owned target and all pre-mutation rejections | NOT_RUN | No real PG restore campaign; preflight alone does not satisfy target mutation safety. |
| [#1085 AC5](https://github.com/o3kio/o3k/issues/1085) | Concurrent writer consistent cut and canonical parity after restore | PARTIAL | Backup cut exercised; post-restore parity NOT_RUN. |
| [#1085 AC6](https://github.com/o3kio/o3k/issues/1085) | Real isolated exact supported PostgreSQL; no skipped PASS | PARTIAL | PG16.15 backup run exists; required restore and missing-infrastructure lanes remain pending. |
| [#1085 AC7](https://github.com/o3kio/o3k/issues/1085) | Interrupted dump/restore, corruption, migration mismatch, safe retry, secrets and foreign state | PARTIAL | Backup interruption coverage exists; restore cases and four executable NOT-COVERED backup lanes remain. |
| [#1085 AC8](https://github.com/o3kio/o3k/issues/1085) | Exact source/harness/server/tool/migration/profile/artifact evidence | PARTIAL | Backup campaign binding exists; final release and restore binding remain. |
| [#1086 AC1](https://github.com/o3kio/o3k/issues/1086) | Fresh owned targets and all compatibility/authentication/path rejections | BLOCKED | #1198 supplies the disabled A10.1 publisher and selected-v2 verifier; merged #1199 adds signed journal-v2 policy binding and startup denial. No PG target creation/mutation or installed qualification is evidenced. |
| [#1086 AC2](https://github.com/o3kio/o3k/issues/1086) | Durable signed identity/phase before side effects | PARTIAL | Merged Phase B has canonical request/record verification, protected journal publication, policy digest binding and 12 source-level unit tests; actual selected-generation signing/preflight process evidence and installed restart cases remain NOT_RUN. |
| [#1086 AC3](https://github.com/o3kio/o3k/issues/1086) | Restart/crash at every phase with idempotent resume or bounded denial | BLOCKED | Unit crash classification and generic D8 file crash boundaries exist, but installed process restart, journal write/fsync/rename/readback failure, power-loss, and the full D8-A10 matrix remain unqualified. |
| [#1086 AC4](https://github.com/o3kio/o3k/issues/1086) | Identity/old lease/epoch invalidation and source fencing before mutation | BLOCKED | Original activation obligation; requires separate D3/D7/D4/D8 path, not inactive-chain extension. |
| [#1086 AC5](https://github.com/o3kio/o3k/issues/1086) | Canonical resource/Operation/Placement/topology/BuildingBlock/IAM/audit restore and invariants | NOT_RUN | Inventory contracts/preflight do not prove canonical restore or pre-activation validation. |
| [#1086 AC6](https://github.com/o3kio/o3k/issues/1086) | Post-activation observe-before-retry and zero unowned provider mutation | BLOCKED | Outside A10 inactive scope; original criterion remains controlling. No scope amendment is accepted, and no additional decision is pending to restate the accepted original scope. |
| [#1086 AC7](https://github.com/o3kio/o3k/issues/1086) | Foreign DB/files/services/guests/storage/network preserved; external data excluded | PARTIAL | Exclusion is documented; real interrupted restore foreign-state proof remains. |
| [#1086 AC8](https://github.com/o3kio/o3k/issues/1086) | Both disposable SQLite and real PG, bound source/harness/backend/artifact | NOT_RUN | Neither complete restore journey is evidenced; PostgreSQL absence cannot be PASS. |
| [#1087 AC1](https://github.com/o3kio/o3k/issues/1087) | Custody/anchor/window/overlap/revocation/re-enrollment documented and tested first | PARTIAL | Lifecycle predicates exist; issuer/custody authority and complete operational contract remain. |
| [#1087 AC2](https://github.com/o3kio/o3k/issues/1087) | Join/renewal/expiry/revocation/replacement enrollment journey | NOT_RUN | No source-bound installed issuer lifecycle campaign. |
| [#1087 AC3](https://github.com/o3kio/o3k/issues/1087) | Former cert/key cannot reconnect after revocation/replacement | NOT_RUN | Requires actual trust propagation and reconnect negatives. |
| [#1087 AC4](https://github.com/o3kio/o3k/issues/1087) | Restore trust continuity without exporting agent private keys | BLOCKED | Depends on accepted restore and issuer/trust authority. |
| [#1087 AC5](https://github.com/o3kio/o3k/issues/1087) | Interrupted renewal/issuer outage/stale trust/revocation/re-enrollment restart failures | NOT_RUN | Required lifecycle failure campaign missing. |
| [#1087 AC6](https://github.com/o3kio/o3k/issues/1087) | Secret-safe diagnostics and evidence | PARTIAL | Existing diagnostic redaction is narrower than lifecycle output and retained evidence. |
| [#1087 AC7](https://github.com/o3kio/o3k/issues/1087) | Source/harness/profile/issuer/trust/lifecycle-fixture binding | NOT_RUN | No complete lifecycle evidence artifact. |
| [#1088 AC1](https://github.com/o3kio/o3k/issues/1088) | Required operator-signal inventory using accepted health identities | PARTIAL | ISSUE_1088_PP6_OPERATOR_SIGNALS.md inventories current and gated signals; missing authorities remain. |
| [#1088 AC2](https://github.com/o3kio/o3k/issues/1088) | Accepted diagnostics/doctor extensions; health/readiness/status distinction | PARTIAL | Existing accepted projections exist; SPEC-0051 exact-revision decision remains pending. |
| [#1088 AC3](https://github.com/o3kio/o3k/issues/1088) | Bounded correlations and actionable errors without secret payloads | PARTIAL | Existing diagnostic errors are bounded; proposed bundle still lacks accepted implementation. |
| [#1088 AC4](https://github.com/o3kio/o3k/issues/1088) | Success/failure/support/generated-output redaction tests | PARTIAL | Diagnostic tests exist; support-bundle tests absent. |
| [#1088 AC5](https://github.com/o3kio/o3k/issues/1088) | Healthy/degraded/unavailable/stale/unknown SQLite and PG conditions | PARTIAL | Store diagnostics coverage exists; complete claimed signal/bundle matrix absent. |
| [#1088 AC6](https://github.com/o3kio/o3k/issues/1088) | Read-only projection and zero canonical/provider mutations | PARTIAL | Diagnostic read-only evidence exists; bundle authorization/read-only proof absent. |
| [#1088 AC7](https://github.com/o3kio/o3k/issues/1088) | Source/profile/backend/diagnostic-schema binding | PARTIAL | Existing diagnostic evidence is narrower than the complete PP.6 support artifact. |
| [#1089 AC1](https://github.com/o3kio/o3k/issues/1089) | SQLite disk/WAL/lock/unavailable and real PG connection/service/resource pressure | PARTIAL | Failure matrix records existing lanes; exact complete backend case coverage remains. |
| [#1089 AC2](https://github.com/o3kio/o3k/issues/1089) | Destination full/unavailable, malformed input, replay, restart and unknown outcome | PARTIAL | Real destination-full NOT_RUN; interrupted recovery/operator-error cases remain. |
| [#1089 AC3](https://github.com/o3kio/o3k/issues/1089) | Each case: bounded error, canonical/operation invariants and safe retry/action | PARTIAL | Per-case assertion/evidence gaps remain; one passing pressure subtest is insufficient. |
| [#1089 AC4](https://github.com/o3kio/o3k/issues/1089) | Zero unowned mutation and foreign-state preservation during retry/interruption | PARTIAL | Some lanes are store-only with foreign/provider state not_exercised. |
| [#1089 AC5](https://github.com/o3kio/o3k/issues/1089) | Every run secret scan and source/harness/backend/version/profile/fixture binding | PARTIAL | Per-run envelopes and retained evidence remain incomplete. |
| [#1089 AC6](https://github.com/o3kio/o3k/issues/1089) | Required PostgreSQL unavailable means failure/pending, never skipped PASS | PARTIAL | Existing real PG lanes do not establish this for all remaining required cases. |
| [#1098 AC1](https://github.com/o3kio/o3k/issues/1098) | Machine-readable matrix rejects unsupported source/profile/schema/downgrade before mutation | PARTIAL | General compatibility data and bounded engine exist; PP.6 transition gate matrix missing. |
| [#1098 AC2](https://github.com/o3kio/o3k/issues/1098) | Every supported durable phase: interruption/restart or restore-only evidence | PARTIAL | Bounded upgrade resume exists; exact-artifact full phase campaign missing. |
| [#1098 AC3](https://github.com/o3kio/o3k/issues/1098) | Observe unknown outcomes before retry without duplicate mutation | PARTIAL | Existing engine primitives are narrower than the complete upgrade/restore journey. |
| [#1098 AC4](https://github.com/o3kio/o3k/issues/1098) | Separate SQLite/real PG claims and fail/pending unavailable PG | NOT_RUN | No complete PP.6 artifact journey for either claimed backend. |
| [#1098 AC5](https://github.com/o3kio/o3k/issues/1098) | Exact-artifact upgrade → rollback/restore → upgrade-again | NOT_RUN | Authenticated artifacts and applicable accepted recovery scope missing. |
| [#1098 AC6](https://github.com/o3kio/o3k/issues/1098) | Safe unsupported downgrade denial and no unsafe rollback claim | PARTIAL | Bounded engine has refusals; PP.6 compatibility matrix and artifact negatives missing. |
| [#1098 AC7](https://github.com/o3kio/o3k/issues/1098) | Secrets/cleanup/foreign state and required independent reviews at zero B/H/M | BLOCKED | Release-level journey/reviews absent; ADR-0190 is not independent qualification. |
| [#1098 AC8](https://github.com/o3kio/o3k/issues/1098) | Protected CI/human review and merged evidence linked from #640/#975 | PARTIAL | Individual PR reviews exist; final source-bound journey evidence and links remain. |
| [#975 AC1](https://github.com/o3kio/o3k/issues/975) | Control-plane backup/restore from exact release artifacts | BLOCKED | #1084/#1085/#1086 and authenticated-release gates remain. |
| [#975 AC2](https://github.com/o3kio/o3k/issues/975) | Certificate renewal/revocation/replacement journey | NOT_RUN | #1087 installed lifecycle remains. |
| [#975 AC3](https://github.com/o3kio/o3k/issues/975) | Trace observable failure without secret disclosure | PARTIAL | #1088/#1089 diagnostics and evidence completion remain. |
| [#975 AC4](https://github.com/o3kio/o3k/issues/975) | Useful redacted support bundle | BLOCKED | SPEC-0051 exact-revision decision and bounded implementation remain. |
| [#975 AC5](https://github.com/o3kio/o3k/issues/975) | Upgrade from prior PP candidate/release | NOT_RUN | #1098 exact-artifact journey remains. |
| [#975 AC6](https://github.com/o3kio/o3k/issues/975) | Deterministic supported-phase crash/restart | PARTIAL | #1086/#1089/#1098 complete installed phase matrices remain. |
| [#975 AC7](https://github.com/o3kio/o3k/issues/975) | Resource pressure fails safely | PARTIAL | #1089 remaining mandatory cases and invariants remain. |
| [#975 AC8](https://github.com/o3kio/o3k/issues/975) | Evidence-backed operator documentation | PARTIAL | #944 runbooks await the corresponding passed journeys. |
| [#975 AC9](https://github.com/o3kio/o3k/issues/975) | Final review: zero actionable BLOCKER/HIGH/MEDIUM | BLOCKED | Mandatory evidence and final owner/release review are absent. |

## Scope conflict: inactive materialization versus activated recovery

The original #975 goal and #1086 acceptance require **fresh-host restore activation**: old controller identity/leases must be invalidated, the source must be independently fenced, writers excluded, the restored controller handed off under a boot-bound guard, and reconciliation must observe unknown outcomes before it can dispatch mutations. The A10.1 amendment authorizes a separate **inactive-materialization-only** branch. Its terminal `INACTIVE_VERIFIED` state proves materialization/inventory only and must never grant controller, API, reconciliation, provider, or external mutation authority. Therefore A10 Phase C cannot satisfy or close the original #1086/#975 activation acceptance. The original activated-recovery scope remains controlling unless the owner explicitly amends it; no additional decision is pending to choose between the scopes. Full PP.6 remains blocked until the applicable implementation and evidence are complete.

## Review and decision references

The owner recorded ACCEPT on exact reviewed PR #1192 head `c8ab0a6f1b21bddc70ef46e34357f62ad64e6db4` ([comment #6504152604](https://github.com/o3kio/o3k/pull/1192#issuecomment-6504152604)). On exact reviewed PR #1193 head `16f41ad4c531abcccc2c1dbb9246333289b67849`, the owner explicitly ACCEPTED bounded A10.1 contract implementation and testing under SPEC-0050 §7.4 ([comment #6541530386](https://github.com/o3kio/o3k/pull/1193#issuecomment-6541530386)); it merged at `586fe87b2966223450114bee26b35fc72f08ba6e`. PR #1210 subsequently merged the #975 closure guard. These decisions are accepted authority for their bounded implementation/testing scope, not runtime evidence or independent security qualification. They do not authorize production publisher enablement, PostgreSQL target mutation, controller activation, independent security acceptance, or final PP.6 GO. ADR-0190's non-independent review disclosure remains applicable. The [narrow recovery-scope proposal](https://github.com/o3kio/o3k/issues/975#issuecomment-6500048071) remains a proposal and does not amend the original #975/#1086 acceptance.

## Exact next blocking predicates

1. **Resolved:** #1190 landed through the protected queue at `b6354aa8b298d2368e2bba0e979a405002569b5c` from approved head `5696ab80eae3b429178ce589784c401d694712de`. This fixes the fractional-TTL SQLite lease defect; it does not qualify PP.6 recovery.
2. **A10.1 contract accepted:** the exact-head #1192/#1193 decisions authorize bounded contract implementation and testing. They do not authorize production publisher enablement, target mutation, activation, independent security acceptance, or final PP.6 evidence.
3. **Original activated recovery remains controlling:** implement and evidence D3/D4/D7/D8 activation and observe-before-retry reconciliation, unless an explicit owner amendment is accepted. A10 inactive evidence cannot close #1086/#975.
4. **Installed qualification:** obtain the dedicated isolated host, authenticated clean Debian 13 and Ubuntu 24.04 guests, verified ext4 recovery/journal filesystems, authorized custody/trust/revocation material and required release/installer fixtures; then execute and retain E4 evidence separately from E5.
5. **Remaining PP.6 workstreams:** #1084 SQLite artifact/restore; #1085 PostgreSQL backup/restore; #1086 activated restore/fencing; #1087 PKI lifecycle; #1088 diagnostics/support bundle; #1089 pressure/failure behavior; #1098 upgrade/rollback; and #944 operator documentation remain open and block full #975 acceptance as itemized in the matrix above. Their gaps include implementation, executable evidence, infrastructure, and human/review authority as indicated per row; none is cleared by an accepted contract or merged PR alone.

No PP.7, Araf certification, or deferred PP.5 scale/soak campaign is included in this matrix.
