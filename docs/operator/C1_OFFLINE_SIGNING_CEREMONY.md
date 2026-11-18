# C1 offline signing ceremony

This runbook describes how an operator installs a **C1-bearing** O3K release
(one whose release manifest carries `installation_policy_format`,
`installation_policy_path`, and `installation_policy_authority`). Normative
authority: SPEC-0050 §7.2 (`docs/specs/SPEC-0050-pp6-control-plane-backup-restore.md`),
ADR-0189, and ADR-0190. Where this document and those conflict, they win —
stop and report the conflict.

C1-bearing releases are fail-closed by design: `o3kd` and `o3k-compute`
refuse to start on the packaged path (`/usr/local` + `/var/lib/o3k`) until
authenticated installation policy, state, and trust documents are
provisioned. The installer never synthesizes these documents; they are
produced by the **offline signing ceremony** below.

## Roles and custody

- **Installation-policy authority key** (offline Ed25519): signs the
  installation policy and the genesis state. Its public key and key ID are
  baked into the release manifest by the protected release workflow
  (`O3K_C1_INSTALLATION_POLICY_KEY_ID` /
  `O3K_C1_INSTALLATION_POLICY_PUBLIC_KEY` on the approval-gated `release`
  environment). The private key never enters CI, the repository, or the
  target host.
- **Journal trust root** and **evidence trust root** (offline Ed25519):
  distinct roots that certify the journal and evidence signer keys inside
  the trust bundle.
- **Journal signer** and **evidence signer** (Ed25519): certified by the
  roots for the `restore_journal` and `recovery_evidence` purposes.

Offline root operations require two of three named custodians at the
offline signing workstation (SPEC-0050 preamble, "Accepted technical
contract" ceremony rules). Every key has a signed
non-secret custody record (PP.6 D2); physical storage locations and private
keys are excluded from the record and from this repository. All five keys
must be distinct; a signer key must never equal a root key, and the journal
side must never share key material with the evidence side. When exporting
the authority key for the release environment, confirm it is the 64-hex
**public** verifying key: a raw Ed25519 private seed has the same shape, and
publishing it would compromise the authority.

## Preconditions

1. An authenticated C1-bearing release archive, verified per
   `docs/RELEASE.md` (Sigstore bundle + `release-digests.txt`), extracted
   on the target host.
2. A clean Ubuntu 24.04 or Debian target with the libvirt profile
   prerequisites (`virsh`, `qemu-img`, `ip`, `/dev/kvm`) — the installer's
   preflight fails closed otherwise.
3. The TLS bootstrap completed:

   ```bash
   sudo ./packaging/bootstrap-certs.sh
   ```

4. The offline signing workstation holds the private keys and can exchange
   files with the target host over an operator-controlled channel.

The published one-line installer asset (`install.sh` / `get-o3k.sh`) has no
C1 flag passthrough: for a C1-bearing release it stops at the C1 journey
message by design. Run the bundle's `packaging/install.sh` directly as
shown below.

## Step 1 — prepare (on the target host)

```bash
sudo ./packaging/install.sh --profile libvirt --noninteractive \
  --prefix /usr/local --data-dir /var/lib/o3k \
  --config-dir /etc/o3k --log-dir /var/log/o3k \
  --c1-prepare-only [--c1-backend sqlite|postgresql]
```

This installs the release, creates the recovery directories
(`/var/lib/o3k-recovery-state/<installation_id>`, `root:o3k 0750`, and
`/var/lib/o3k-recovery/<installation_id>`, `o3k:o3k 0700`), and prints a
single-line `o3k-recovery-provisioning-v1` **unsigned** descriptor
(`authentication: "none"`). It does not enable or start services. Copy the
descriptor line to the offline workstation. The descriptor binds the
installation/site identity, the exact release identity, the data root and
recovery directory device/inode pairs, and the policy authority the release
manifest authenticates — re-check every one of these against your
expectations before signing.

## Step 2 — sign (on the offline workstation)

Two custodians display and confirm each document before signing
(SPEC-0050 preamble). Produce three canonical (RFC 8785 JCS) JSON
documents:

1. **`trust.json`** — an `o3k-recovery-trust-v1` bundle for the descriptor's
   installation/site/profile/backend: root-signed
   `o3k-journal-authority-v1` and `o3k-evidence-authority-v1` certificates
   (validity at most 90 days, `not_before <= now < not_after`) and
   root-signed `o3k-recovery-revocations-v1` documents (`sequence` 1,
   `next_update - issued_at <= 86400` seconds, `issued_at <= now <
   next_update`, empty revocation lists for a genesis bundle). The bundle's
   revocation sequence and digest fields must match the embedded signed
   revocation documents.
2. **`policy.json`** — a signed `o3k-installation-policy-v1` payload copied
   field-for-field from the descriptor (`target_device`/`target_inode` are
   the descriptor's `data_root_device`/`data_root_inode`), plus
   `policy_revision: 1`, `prior_policy_digest` of 64 zero hex characters
   (genesis), `trust_bundle_digest` = SHA-256 hex of the canonical
   `trust.json` bytes, the journal/evidence trust-root IDs and public keys
   exactly as carried by `trust.json`
   (`journal_trust_root_id`/`journal_trust_root_public_key`/
   `evidence_trust_root_id`/`evidence_trust_root_public_key`), and
   `signer_key_id` equal to the release manifest's
   `installation_policy_authority.key_id`. Sign with the
   installation-policy authority key; the envelope must name the same
   `key_id`.
3. **`state.json`** — a signed `o3k-installation-state-v1` genesis:
   `sequence: 0`, `state: "NEVER_RECOVERED"`, empty `prior_record_digest`,
   all optional digest/operation fields `null`, `policy_revision: 1`, and
   `policy_digest` = SHA-256 hex of the canonical signed `policy.json`
   bytes. Sign with the installation-policy authority key.

Envelope shape for signed documents: `{"payload": {...}, "envelope":
{"algorithm": "Ed25519", "signer_key_id": "...", "signature": "<128 hex>"}}`;
the signature covers the canonical payload bytes only. Signed files must be
byte-exact canonical JSON with no trailing whitespace.

**Freshness is operational from first designation, not ceremonial:** a
`NEVER_RECOVERED` genesis installation authenticates the installed trust
bundle digest-only at startup (policy-bound digest, durable high-water
signatures, scope, and monotonicity — tamper detection without freshness
gating, per SPEC-0050 §7.2.1 and the 2026-11-18 owner decision on #1225).
Once recovery has been designated, every service start re-verifies the trust
bundle's revocation freshness (`now < next_update`, at most 24 hours) and
certificate validity (at most 90 days). Plan the 24-hour revocation refresh
(`o3k recovery-trust-update --policy … --trust …`) and certificate rotation
before designating recovery on an installation.

## Step 3 — install (on the target host)

Transfer the three signed documents to the target as root-owned regular
files (no symlinks, mode `0600`, e.g. `/var/lib/o3k-c1-inputs/`), then:

```bash
sudo ./packaging/install.sh --profile libvirt --noninteractive \
  --prefix /usr/local --data-dir /var/lib/o3k \
  --config-dir /etc/o3k --log-dir /var/log/o3k \
  --c1-policy /var/lib/o3k-c1-inputs/policy.json \
  --c1-state  /var/lib/o3k-c1-inputs/state.json \
  --c1-trust  /var/lib/o3k-c1-inputs/trust.json
```

The installer verifies all three documents against the installed release
manifest (signature, key ID, release identity, profile, data root, trust
binding, genesis transition), installs the policy and trust bundle at
`/etc/o3k/installation-policy.json` and `/etc/o3k/recovery-trust.json`
(`root:o3k 0640`), writes the durable policy/state/trust checkpoints under
`/var/lib/o3k-recovery-state/<installation_id>/`, and only then enables and
starts `o3kd.service` and `o3k-compute.service`. Any verification failure
aborts the install before service enablement.

For a host that ran a pre-C1 installed release, add `--c1-migrate`; the
installer then additionally fails closed on any legacy recovery evidence.

**PostgreSQL backend:** with `--c1-backend postgresql`, set
`O3K_DATABASE_BACKEND=postgresql` and `O3K_DATABASE_URL` in
`/etc/o3k/o3kd.env` before the first service start; startup fails closed
when the configured backend disagrees with the signed policy.

## Step 4 — verify

```bash
systemctl is-active o3kd.service o3k-compute.service   # active / active
curl -fsS http://127.0.0.1:18080/healthz               # {"status":"ok"}
```

Expected fail-closed behavior (all must deny startup): missing or tampered
`/etc/o3k/installation-policy.json` or `/etc/o3k/recovery-trust.json`,
missing or tampered checkpoints under `/var/lib/o3k-recovery-state/`, or a
policy whose release identity does not match the installed release. On a
designated or previously recovered installation, a stale (older than 24
hours) revocation document also denies startup; a `NEVER_RECOVERED`
installation is not freshness-gated but still denies tampered trust
material.

## Reference implementation for qualification

`tests/pp6-c1-ceremony/` contains the qualification-only tooling
(throwaway keys, no custody controls) used to prove this journey on
disposable guests. It is never part of a release bundle and must never be
used with production key material.
