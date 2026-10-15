# SPEC-0050 — PP.6 control-plane backup and restore

Status: Proposed — requires human architecture/security approval
Authority proposal: ADR-0189
Issue: #975, reusing #640
Profile scope: `o3k-demo-v1` SQLite where retained; `o3k-small-edge-v1`
PostgreSQL profile

This proposed specification adds recovery behavior not covered by the existing
local upgrade rollback contract. It does not amend PP.5 acceptance thresholds,
SPEC-0024 database support, SPEC-0008 operation semantics, or ADR-0167
deployment authority. The proposal is not implementation or acceptance
evidence.

## 1. Goals and exclusions

The backup captures authoritative O3K control-plane state so a compatible
fresh installation can reconstruct canonical identities, desired/observed
state, ownership, operations, Placement, topology, BuildingBlocks, IAM and
bootstrap state, then restart and reconcile safely.

The artifact does not contain tenant VM disks, hypervisor-local guest state,
external Cinder or other external storage payloads, provider caches, external
hosted service databases, or a second copy of provider authority. Those are
separate recovery domains. Restoring O3K mappings without recovering their
external data does not make the external workload data available.

No multi-region DR, multi-site replication, HA certification, or automatic
provider mutation is defined here.

## 2. Artifact identity and contents

The artifact has a versioned manifest conforming to the proposed
`contracts/control-plane-backup-v1.proposed.schema.json` and a set of content
members. Each member has a normalized relative path from a closed allowlist,
byte length, media type and cryptographic digest. Readers reject absolute
paths, empty or dot path segments, path traversal, duplicate names and names
outside the allowlist. The manifest binds:

- unique backup ID, installation/site ID, creation time and consistency point;
- O3K release version, exact source SHA, release artifact digest and product
  profile;
- store backend and server/tool version, schema version, applied migration
  versions and migration checksums;
- snapshot mechanism and whether the daemon/write path was quiesced;
- inventory of canonical resource and state families included;
- artifact member names, lengths and digests;
- encryption and detached authentication metadata, algorithm identifiers,
  key/trust identifiers and format version;
- explicit excluded external-state families.

The entire payload containing database/configuration/secret-bearing material
is encrypted. Public manifest fields are restricted to the minimum required
for inspection and contain no credentials, private key bytes, database URL,
provider payload, or user data. Content hashes alone are not tamper evidence
when the manifest can be replaced with the payload; an authenticated manifest
and trusted key identity are required. Exact encryption/signature algorithms,
key-wrapping, key rotation, and verification trust-store are approval items,
not chosen by this proposed contract. The authentication operation signs a
canonical encoding of the manifest with the `authentication.signature` field
omitted; the verifier must reject non-canonical encodings and duplicate JSON
keys before signature verification. This avoids a self-referential signature
field. The canonical encoding and format details remain subject to approval.

## 3. Consistency and backend behavior

### SQLite profile

Use the existing SQLite WAL/integrity policy and supported snapshot API:

1. prevent control-plane writes for the duration of the cross-file snapshot;
2. perform the documented WAL checkpoint;
3. create the DB snapshot with `VACUUM INTO` (or an equivalently supported
   SQLite online-backup API accepted by the implementation review);
4. validate the snapshot with SQLite integrity checks and the recorded schema
   and migration identity;
5. package config/bootstrap material from the same quiesced interval.

A live `.sqlite` file copy is never a supported snapshot method. If the
implementation cannot prove a stable quiescence point, it must reject the
backup rather than label an inconsistent multi-file capture as committed.

### PostgreSQL profile

Use the supported PostgreSQL version and a transaction-consistent database
dump (`pg_dump` custom/directory format or another approved native mechanism)
with a fresh target restore path. Record server version, dump tool version,
database/schema identity, extensions, role/ownership expectations and applied
migrations. Validate the restored database before activation. The production
lane uses a real isolated PostgreSQL instance and fails if the configured
database/tooling is unavailable. A skipped test is not a pass.

The PostgreSQL transaction snapshot is internally consistent. A coordinated
daemon quiescence is still required to align the database with O3K-owned
configuration and protected bootstrap/trust files. PostgreSQL support does not
imply HA or Kubernetes HA.

## 4. Sensitive material, IAM and PKI

All database payload and included sensitive files are encrypted before
publication. The encryption key is supplied or unlocked through an approved
operator-managed mechanism and is never stored in the artifact or adjacent to
it. Artifacts and temporary files use restrictive owner-only permissions;
diagnostics/evidence expose only safe key identifiers and verification result.

Canonical IAM principals/scopes, bootstrap/enrollment grants, agent
certificate fingerprints, revocation state, and CA public trust are included
as durable state when present in the store. Private agent keys remain on their
host and are never included. Recovery of the control-plane issuer private key
or a CA replacement/re-enrollment journey is unresolved until human security
review selects the supported custody and trust-transition model. Restore fails
closed if the trust material needed for the chosen recovery route is missing.

## 5. Backup publication and retry

The writer persists a durable backup operation identity before beginning. It
creates a private staging directory on the destination filesystem, writes and
fsyncs payload members, verifies digests/authentication and database
integrity, writes the manifest and commit marker, fsyncs the directory, then
atomically publishes the completed artifact. `COMMITTED` is visible only after
all checks and durable publication finish. A failed or interrupted staging
artifact is not selectable as a backup.

Retry uses the same operation/backup identity. It observes the existing
staging/final path and validates it before deciding whether to resume, return
the committed result, quarantine an incomplete artifact, or fail on a content
conflict. It does not overwrite an artifact with a different digest.

## 6. Fresh-host restore

Restore is an explicit operator action against a fresh O3K-owned installation
and explicitly selected target database/data directories. Before mutation, it
validates:

- trusted manifest authentication and all member digests;
- supported artifact format, O3K version and deployment profile;
- backend compatibility and schema/migration identity;
- destination ownership, emptiness and path safety;
- required decryption key and trust/issuer material availability;
- absence of an active conflicting controller or restore operation.

Restore stages decrypted files privately, validates them, and restores into an
empty O3K-owned database target. Nonempty/foreign data, wrong installation
identity, unknown profile/schema/version, or unavailable keys fail before
destructive mutation. It never deletes, imports, or reconciles external VM,
network, or storage objects during artifact restore.

Exact site identity preservation versus regeneration on host replacement is a
human decision. Controller runtime identity must not permit a stale process to
resume work after restore. Before API writes or provider dispatch resume, the
restored control plane must establish a current fencing epoch/lease and make
old ownership invalid. How the single-controller profiles perform that
transition is an ADR-0189 approval item. Normal post-activation reconciliation
uses SPEC-0008 observe-before-retry behavior and existing canonical authorities.

## 7. Restore state and crash recovery

Restore records durable progress outside the target DB in a protected,
target-specific journal. Proposed states are:

```text
PREFLIGHTED -> STAGING -> DATABASE_RESTORED -> FILES_RESTORED
-> FENCED -> STARTED -> RECONCILED -> COMMITTED
                         \-> FAILED_RECOVERABLE
```

The journal binds operation ID, backup ID/digest, source and target identities,
and phase. Every external side effect is preceded by durable intent. On restart,
the runner observes the target and repeats only idempotent steps; it never
assumes a timed-out command failed. A mismatch or ambiguous foreign-state
observation stops activation and reports a bounded recovery action. The
precise placement/location of the restore journal and the fencing phase is
subject to approval.

## 8. Operator interface

No native API is defined. Existing operator CLI conventions suggest an `o3k`
subcommand, but this proposal does not add or freeze a CLI contract. A later
approved interface decision must define backup create/verify/inspect and
restore preflight/execute behavior, required confirmation, status/error JSON,
exit codes, idempotency key, and secret-redaction rules. The contract must not
advertise restore support before profile-specific evidence passes.

## 9. Validation and acceptance

Before a PP.6 backup/restore claim, evidence is required for both persistence
profiles that are claimed:

- SQLite live-write/WAL consistency, restore and canonical inventory parity;
- real isolated PostgreSQL dump/restore under concurrent writes;
- fresh disposable host restoration and restart/reconciliation;
- crash/restart at every declared backup and restore phase;
- corruption, truncation, tamper/authentication, missing member, version,
  profile, backend, schema and migration mismatch rejection;
- safe retry and unknown outcome observation;
- issuer/trust/secret recovery and secret-safe output;
- foreign target and external provider state preservation;
- zero unowned mutations before and after reconciliation.

Every result binds source SHA, test/harness SHA, release artifact digest,
profile, backend/server/tool version, migration identity, backup digest,
destination/host identity, and machine-readable verdict. Required PostgreSQL
tests fail closed when PostgreSQL is absent or unreachable.

See `docs/pp/PP6_GAP_ANALYSIS.md` for the ordered executable matrix.
