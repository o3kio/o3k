# PP.6 Stage 2 installed-release qualification matrix

**Status:** executable plan and read-only infrastructure assessment; PP.6 is
**BLOCKED**. **Document source:** protected `main`
`901af47b306aa779aed72ef61ef25184fabf24eb` (2026-11-03). **Host-preflight
source:** `bf04c8b61c95435df973502f35197bb74df22f78`; the qualification harness
is unchanged between those revisions.
**Authority:** #975 and #1086 retain their original acceptance criteria. A10.1
migration publication remains disabled in production; A10 Phase C PostgreSQL
target mutation and controller activation are not authorized. No PP.7 or Araf
work is included.

Published `v0.4.0-rc.25` (`42de13cee64a37d69e900fd4272ff5e849a328b8`) lacks
#1206/#1207 and cannot exercise the corrected signed-release provenance path.
The authenticated successor `v0.4.0-rc.26` now exists: tag object
`b295a9a031ae2969497b6311ea87ee1ff421f676` points to protected merge commit
`901af47b306aa779aed72ef61ef25184fabf24eb`; release workflow run 41642704256
passed after `release` environment approval and published the prerelease at
2026-11-03T13:37:42Z. Independent exact-tag verification passed the protected
workflow/OIDC identity, Sigstore/Rekor proof, seven-entry signed digest
manifest, archive and bundle integrity, source/version/upgrade-floor binding,
glibc floor, and production A10 publisher exclusion. This is release evidence
only; installed-release qualification remains blocked on the dedicated host.

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

## Critical dependencies and current verdict

1. **B0 — governance:** PASS; #975 was reopened after the non-acceptance
   closure. #1086 and the other PP.6 acceptance workstreams remain open.
2. **B1 — candidate and host:** the authenticated rc.26 candidate is PASS;
   provision the dedicated host below. All E4/E5 lanes remain blocked until the
   host exists.
3. **B2 — custody and fencing:** provide approved offline signer custody,
   trust/revocation distribution, independently administered D7 fencing, and
   witnessed BMC/PDU procedures. Test keys cannot substitute for these.
4. **B3 — restore implementation:** complete the accepted SQLite and
   PostgreSQL 16 restore paths, D4 source/target writer exclusion, canonical
   parity, interruption handling, and foreign-state negatives.
5. **B4 — activation decision:** preserve original activated recovery unless
   the owner explicitly amends #975/#1086. D3 identity/credential/lease/epoch
   invalidation and D8 boot-bound handoff remain required.
   `INACTIVE_VERIFIED` does not satisfy activation.
6. **B5 — remaining operations:** PKI lifecycle, exact-artifact
   upgrade/rollback/recovery, pressure lanes, diagnostics/support bundle, and
   evidence-backed runbooks.
7. **B6 — acceptance:** independent security/release review with zero
   actionable BLOCKER/HIGH/MEDIUM findings and final owner GO.

## Read-only host preflight

The harness is identical to protected `main`; its SHA-256 is
`0c5332ae5e1f9cc483b73738d5dc1fdfd4d9dc9321503f2e9e0e883b5e6f844c`.
`python3 -m unittest discover -s tests/pp6-qualification -p 'test_*.py' -v`
passed 7/7 at `bf04c8b61c95435df973502f35197bb74df22f78`; the harness is
unchanged at this document source. Only help, unit, and read-only host
commands ran. No forwarding, firewall, network, guest, route, disk, service,
package, or file changes were made.

| Requirement | Shared development runner observation | Status |
|---|---|---|
| Harness safety tests | 7/7 pass at `bf04c8b6` | PASS (E1 only) |
| KVM and libvirt tools | `/dev/kvm`; AMD-V; virsh 10.0.0; qemu-img 8.2.2; all required tools present | PASS, insufficient alone |
| CPU / memory / space | 16 CPUs; about 58.5 GiB available memory; 181 GiB free on shared ext4 | PASS, shared and insufficient alone |
| Forwarding disabled everywhere | IPv4 `ip_forward=1`; all inspected IPv4/IPv6 interface forwarding controls are `1` | **FAIL** |
| Dedicated, unrelated-workload-free host | Running `o3k-a10-systemd-qualification` VM, other libvirt networks, Docker containers, nginx, PostgreSQL, NFS and dnsmasq | **FAIL** |
| Trusted digest-pinned Debian 12 / Ubuntu 24.04 images | No qualification images supplied; nothing to verify | NOT_RUN |
| Authorized physical power control | No observable BMC/PDU authority or IPMI device; guest force-restart is not a substitute | **BLOCKED** |
| Guest provision/install/recovery/power tests | Prohibited on this host and not attempted | NOT_RUN |

## Exact dedicated-host provisioning specification

This is a provisioning request, not an observed host or a support claim:

- Disposable bare-metal x86_64 host, no nested-virtualization substitute for
  physical power tests; hardware AMD-V/Intel VT-x with EPT/NPT, KVM and libvirt.
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
- Independently administered BMC with Redfish or an authenticated managed PDU
  outlet, explicitly authorized for physical power cuts of only this host.
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
export RUN_ID=pp6-rc26-run01
export TAG=v0.4.0-rc.26
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
- **Current:** authenticated release identity **PASS** at `v0.4.0-rc.26` /
  `901af47b306aa779aed72ef61ef25184fabf24eb` (Sigstore/Rekor, seven-entry
  digest manifest, bundle, glibc floor, publisher exclusion, independent
  Debian rebuild parity). Installed E4 capture is NOT_RUN because no dedicated
  host is available. Overall **BLOCKED**.

### Q2 — clean Debian 12 and Ubuntu 24.04 installation

- **Execute:** Q1 followed by the tagged installer on both newly provisioned
  guests; run health/readiness, canonical bootstrap, and supported public
  lifecycle smoke without adding the demo publisher.
- **Require:** real systemd, separate ext4 mounts, expected units/accounts,
  successful idempotent reinstall behavior where supported, and no foreign
  resource mutation.
- **Current:** E4 NOT_RUN; authenticated candidate exists, but the dedicated
  host and clean guests are absent. Overall **BLOCKED**.

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
   approved custody/trust/revocation material, independent D7 fencing, and
   authorized BMC/PDU control, then execute Q1–Q11 against the authenticated
   rc.26 release. No installed or power-loss lane may be marked PASS before
   that execution.
2. Next implementation PR after an exact-head accepted restore protocol:
   #1085 PostgreSQL 16 fresh-empty-owned-target restore with pre-mutation
   rejections, D4 writer exclusion, canonical parity, interruption/negative
   coverage, and disposable target evidence. This does not authorize Phase C
   activation.
