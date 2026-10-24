# PP.6 acceptance amendments — DRAFT ONLY

**Status: PROPOSED, NOT ACCEPTED.** This file is a review input for the PP.6
#1084 conformance work. It records only contract changes that require a human
decision. Nothing in this file changes the normative schema, ADR, SPEC,
compatibility profile, or the frozen D12 command surface, and no proposal below
has been applied to normative text.

Each proposal states the current text/reference, the proposed replacement, the
rationale, and the implementation alignment that would be required if it is
accepted. If a proposal is rejected, the implementation keeps the narrower
behavior described in its "current implementation" note.

---

## Proposal 1 — Allow a no-table repository (`minItems: 0`)

**Status: PROPOSED. Not accepted. Normative schema unchanged.**

Current normative shape:

- `contracts/control-plane-backup-v1.proposed.schema.json:453` —
  `repository_inventory_entry.sqlite_objects` has `"minItems": 1`.
- `contracts/control-plane-backup-v1.proposed.schema.json:461` —
  `repository_inventory_entry.postgres_objects` has `"minItems": 1`.
- `contracts/control-plane-backup-v1.proposed.schema.json:183` —
  the top-level `state_inventory` array also has `"minItems": 1` (at least one
  repository entry). This proposal does not change that; it only permits one
  registered repository to have zero catalog objects.

Current implementation conflict:

- `bins/o3k/src/backup.rs:2406` (`valid_objects`) returns `false` when
  `sqlite_objects` or `postgres_objects` is empty.
- `crates/o3k-store/src/state_inventory.rs:803-812` (`validate_objects`)
  returns `InvalidBaseline` when either object array is empty.
- The inventory generator currently derives objects from tables and does not
  emit an empty array for a family with no SQLite/PostgreSQL objects
  (`crates/o3k-store/src/state_inventory.rs:2181-2202`).

Proposed amendment:

1. Change both object arrays to `"minItems": 0` in the schema.
2. Keep `migration_ids` non-empty (`"minItems": 1`); a repository still has to
   bind to at least one migration identity.
3. In `valid_objects` (backup validation) and `validate_objects` (inventory
   baseline validation), accept an empty object array while still validating
   uniqueness and every present object.
4. In the generator, emit `[]` for a family whose SQLite/PostgreSQL side has no
   catalog objects instead of synthesizing an object.

Rationale: D13 requires an entry for every registered durable repository,
including repositories with zero state rows, and the schema description at
`contracts/control-plane-backup-v1.proposed.schema.json:182` says so explicitly.
The implementation currently avoids a no-table repository only because the
schema forbids representing it; `state_inventory` cannot describe a real
registered repository that owns no tables. A synthetic catalog object would
misstate the captured schema, so the schema, not the inventory, should change.

Human decisions required: whether a genuinely no-table repository is in the v1
supported set, and whether `migration_ids` must remain non-empty for it.

Current implementation until accepted: every emitted repository has at least
one SQLite and PostgreSQL object; a zero-object entry is rejected as
`schema-invalid` / `InvalidBaseline`.

---

## Proposal 2 — Make the installed/TestLab trust-document posture normative

**Status: PROPOSED. Not accepted. SPEC-0050 and ADR-0189 unchanged.**

Current normative text:

- `docs/specs/SPEC-0050-pp6-control-plane-backup-restore.md:662` — "Site/
  profile, database roles, trust and key handles come only from root-owned
  installation configuration."
- D12 repeats "Site/profile/key/database config is root-owned"
  (`docs/pp/PP6_TECHNICAL_CONTRACT_APPROVAL.md:39`).

Current implementation (this branch):

- Installed data directory (`/var/lib/o3k`, detected by
  `bins/o3k/src/backup_trust.rs:321` `load_for_data_dir`):
  trust document must be a regular non-symlink file owned by uid `0`, group
  `o3k` (resolved from the local account database; gid `0` is the only
  fallback when resolution is unavailable), mode exactly `0600` or `0640`, with
  no group/other write or execute. Any other posture fails closed as
  `trust-config-posture-invalid`
  (`bins/o3k/src/backup_trust.rs:216`, predicate at line 835).
- Non-installed/TestLab data directory: the documented override posture is
  preserved (owned by root or the effective uid, mode `0600`, or `0640` when
  the owning group is root or a process group, never group/other-writable or
  other-readable).
- The installer validates an existing operator document with the same
  installed/TestLab split and aborts before creating installation state
  (`packaging/install.sh:270`). It never creates or writes the document.
- The configuration directory must be a root-owned (installed) or invoking-user
  (TestLab) directory with no group/other write (`packaging/install.sh:310`).
  The installed `/etc/o3k` remains `root:root 0755`, not `root:o3k 0750`,
  because the libvirt compute identity traverses `/etc/o3k/tls`; `0755` still
  satisfies the documented non-writable mode.

Proposed amendment: add a normative paragraph to SPEC-0050 §8 (and the D12 note
in the approval record) stating:

- the installed `/var/lib/o3k` trust document is `root:o3k 0640` (service-user
  group read) or `root:o3k 0600` (root caller), never writable by group/other,
  never other-readable;
- a non-installed/TestLab document is owned by the invoking user with mode
  `0600` (or `0640` for a process group), matching the existing override;
- a service-user-owned document in the installed data directory is rejected as
  `trust-config-posture-invalid`;
- `/etc/o3k` is root-owned and not group/other-writable, and the installer
  validates both the directory and an existing document.

Rationale: the packaged service user is `o3k`, so `root:root 0600` cannot be
read by the service. The accepted evidence already describes the packaged
posture as `root:o3k 0640` and describes `0600` as the TestLab mode, but the
normative text says only "root-owned". Without this amendment the exact group
and mode remain an implementation choice rather than a contract requirement.

Human decisions required: confirm `o3k` as the normative group name; confirm
whether `0640` and `0600` are both normative for installed documents; and
decide whether `/etc/o3k` should be tightened from the existing non-writable
`root:root 0755` to `root:o3k 0750` (which would require a separate decision for
the compute identity's TLS traversal).

---

## Proposal 3 — Contract decision for a public-only verify mode

**Status: PROPOSED. Not accepted. The D12 CLI surface is unchanged.**

Current normative text and behavior:

- SPEC-0050 §8 lists exactly
  `o3k backup verify --artifact ABSOLUTE_FILE`
  (`docs/specs/SPEC-0050-pp6-control-plane-backup-restore.md:655-660`).
- D12 freezes the command set and forbids secrets in arguments/environment
  (`docs/pp/PP6_TECHNICAL_CONTRACT_APPROVAL.md:39`).
- The implemented `o3k backup verify` decrypts every member and therefore
  needs the X25519 recipient private key.
- The internal publication boundary
  `verify_signed_artifact_integrity` (`bins/o3k/src/backup.rs:1367`) already
  verifies canonical manifest encoding, schema, identity, trust/revocation, the
  Ed25519 signature and every member ciphertext digest **without any recipient
  private key**. This branch adds a unit test proving that path succeeds with no
  recipient key and rejects ciphertext and signature tampering
  (`bins/o3k/src/backup.rs:2864`).

Proposed amendment: if a supported public-authenticity command is wanted,
amend D12/SPEC-0050 to add either
`o3k backup verify --artifact ABSOLUTE_FILE --public-only` or a separate
subcommand with the same input plus an explicit "members not decrypted" result
shape and the same bounded JSON/exit-code contract. The exact flag spelling,
output fields, exit mapping, and whether the mode may run without a recovery
key are all human decisions.

If accepted, the implementation would expose the existing
`verify_signed_artifact_integrity` path; no cryptographic redesign is needed.

Current implementation until accepted: the CLI surface is unchanged, and no
public-only mode is advertised. The capability is covered internally only.

---

## Proposal 4 — D9 enforcement wording ("staging quota" vs. preflight/re-checks)

**Status: PROPOSED. Not accepted. The D9 numeric bounds are unchanged.**

Current normative text:

- `docs/pp/PP6_TECHNICAL_CONTRACT_APPROVAL.md:37` — reserve
  `max(2*S + 1 GiB, 6 GiB)`, "enforce as staging quota", cap 9 GiB.
- `docs/pp/PP6_BACKUP_RESTORE_DECISION_PACKET.md:88` and `:111` use the same
  "enforced staging quota" language.

Current implementation: the executor measures the allowlisted source after the
truncating checkpoint, computes the reservation, and re-checks free capacity
before capture, before finalize, and before publication. It fails closed with
`space-unavailable` (exit 3) and never truncates, but it is **not** a
filesystem quota: a concurrent writer can consume free space between checks.
This is recorded as a contract decision in
`docs/evidence/ISSUE_1084_ARTIFACT_EVIDENCE.md:868-874`.

Proposed amendment: replace "enforce as staging quota" in D9 with wording that
names the accepted mechanism, for example: "reserve the computed amount and
enforce it with a measured preflight capacity check plus re-checks before
capture, before finalize and before publication; never truncate the
reservation; concurrent writers are not excluded by a filesystem quota."

Rationale: "staging quota" describes a stronger mechanism than the
implementation provides. Either the wording should match the
preflight/re-check model, or v1 must implement an actual filesystem quota
(project quota, sparse-file reservation, or equivalent) and its failure-path
tests. That choice is a human decision, not an implementation detail.

Current implementation until accepted: preflight plus boundary re-checks; no
quota claim.

---

## Summary of status

| Proposal | Normative files that would change | Applied to normative files? |
| --- | --- | --- |
| 1. No-table repository `minItems: 0` | `contracts/control-plane-backup-v1.proposed.schema.json`; validators in `bins/o3k` and `crates/o3k-store` | No |
| 2. Installed/TestLab trust posture | `docs/specs/SPEC-0050-pp6-control-plane-backup-restore.md`; D12 note in `docs/pp/PP6_TECHNICAL_CONTRACT_APPROVAL.md` | No |
| 3. `--public-only` verify | `docs/specs/SPEC-0050-pp6-control-plane-backup-restore.md`; D12 in `docs/pp/PP6_TECHNICAL_CONTRACT_APPROVAL.md` | No |
| 4. D9 mechanism wording | `docs/pp/PP6_TECHNICAL_CONTRACT_APPROVAL.md`; `docs/pp/PP6_BACKUP_RESTORE_DECISION_PACKET.md` | No |
