# PP.6 Stage 2 installed-release qualification matrix

**Status:** executable plan; PP.6 remains **BLOCKED**. **Status snapshot:**
protected `main` at `3dc280a563bbd3d1f63e2180ad7deba6f78461c2` (2026-11-04).
PRs #1212, #1213, and #1214 are merged; their exact reviewed heads and
protected merge identities are recorded below. The proposed successor is
`v0.4.0-rc.27`; no tag or GitHub Release exists, so its authenticated release
identity and installed qualification are NOT_RUN. **Previously authenticated
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

The proposed rc.27 source includes protected merges #1212–#1214, aligned
version pins, and candidate notes. It must pass source and protected checks,
exact-head human review, the accepted protected merge process, and release
bundle regressions before its source identity can be frozen. Tag creation and
publication remain stopped pending explicit owner release authorization.

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

The current protected-main snapshot reports 19 completed checks, all passing.
Candidate source commit `a3c3da404f302c74d7bf38af490e156f9c58a266` passes
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

The candidate PR still requires exact-head human review and its own protected
CI. The merged PR evidence and local packaging regression do not authorize
release publication.

## Candidate Q1/Q2 status by operating system

These are the proposed rc.27 installed-release lanes. No host preflight or guest
installation has been performed for this candidate in this preparation. The
prior rc.26 verifier failure is recorded separately above; its guest OS was
not identified in the retained evidence cited here.

| Operating system | Q1 authenticity and installed executable identity | Q2 clean install, service health, bootstrap, idempotence, foreign-state preservation |
|---|---|---|
| Debian 12 | **NOT_RUN / BLOCKED** — rc.27 has no authenticated release assets or installed identity | **NOT_RUN / BLOCKED** — no rc.27 installation |
| Ubuntu 24.04 | **NOT_RUN / BLOCKED** — rc.27 has no authenticated release assets or installed identity | **NOT_RUN / BLOCKED** — no rc.27 installation |

## Current evidence classification

| Tier / lane | Result |
|---|---|
| E1 source/unit | **PASS** at proposed source commit `a3c3da404f302c74d7bf38af490e156f9c58a266`: format, Clippy, workspace tests, harness unit tests, workflow validation, release gate, bundle integrity, installer negatives (27 pass; root-only wrapper skipped), publisher exclusion, and extracted packaging regression. The local archive reused authenticated rc.26 binaries and is not candidate release identity evidence. |
| E2 protected CI | **PASS** for the protected merges and current main snapshot. Candidate PR #1215 is incomplete: the Rust check failed twice in the upgrade process matrix; other reported PR checks pass. |
| E3 qualification-only process | **PASS** for #1213 local provisioning and ownership-checked cleanup; **PASS** for #1214's source-built extracted-bundle regression. Both are non-installed evidence. The current local rc.27 packaging regression is E1 package verification only, not an E3 guest process. |
| E4 authenticated installed release | **NOT_RUN / BLOCKED**: rc.26 verifier failure prevented installation; rc.27 is not published and no Q1/Q2 guest installation has run. |
| E5 physical host power loss | **NOT_RUN / BLOCKED**: requires separately authorized disposable bare-metal host and BMC/PDU control. |

## Critical dependencies and current verdict

1. **B0 — governance:** PASS for protected merges #1212–#1214 and the current
   protected-main CI snapshot. PR #1212 reviewed head
   `dd959349157b5b181b4ac589526476fcc6302e93`, merge
   `c984175d4bd45437236fa8267c9a5b562f02e621`; PR #1213 reviewed head
   `b4315c7fe8f296893fd6a86c3c69ed177d26396b`, merge
   `3dc280a563bbd3d1f63e2180ad7deba6f78461c2`; PR #1214 reviewed head
   `cb6dba632276830e022038ea399c7a43164e3bff`, merge
   `ee54bacd9e8185089412c7cb1ffa3be5870b6c9b`. #975 and #1086 remain OPEN,
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
