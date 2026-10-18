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

Proposed amendments A1–A9 (2026-10-16), as further amended below for the
profile-specific signing mode, are listed in
[the decision packet](../pp/PP6_BACKUP_RESTORE_DECISION_PACKET.md#proposed-amendments-2026-10-16).
The refinements below incorporate the recommendations in
[review comment 6239123579](https://github.com/o3kio/o3k/issues/975#issuecomment-6239123579).
That review comment expressly records neither required role decision.
Subsequently, senolcolak [accepted the architecture proposal](https://github.com/o3kio/o3k/issues/975#issuecomment-6239984922)
at `610f914b4c25112f67798402db8b83c9caf0cf55`, responding to the
[exact-revision request](https://github.com/o3kio/o3k/issues/975#issuecomment-6239743723).
See [ADR-0189's separate role record](../adr/ADR-0189-pp6-control-plane-backup-and-restore.md#architecture-decision-recorded-2026-10-17).
Acceptance retains the proposal's unresolved conditions; it supplies no missing
values or evidence. On 2026-10-18, the authorized human accepted the bounded
interim review arrangement and selected PostgreSQL Option B and SQLite Option
A under ADR-0190, against reviewed revision
`d62853bed83b7d5e1b63118a2d17bd48dac2e2aa`; see its [decision
record](../adr/ADR-0190-pp6-interim-single-maintainer-review-gate.md#human-decision-recorded-2026-10-18).
This profile-mode selection does not accept this specification or schema, and
does not decide the concrete signer implementation or security lifecycle.
Those amendments require exact-revision technical/security review under the
accepted, non-independent interim route, whose durable decision URL and
protected integration remain pending. This specification and its artifact
schema remain **Proposed** and do not authorize implementation.

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
- encryption and authentication metadata, algorithm identifiers,
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
field. Each member's byte length and SHA-256 cover its ciphertext bytes;
authentication binds those values together with all manifest fields,
encryption parameters and format identity. After decryption, the consumer also
validates database integrity and any accepted plaintext digest. The
encryption/authentication algorithms,
nonce and key-wrapping rules, canonical encoding, trust store, and rotation
behavior remain security approval items. A consumer fails closed on any
algorithm or key not explicitly configured as supported; it never trusts an
artifact's key identifier by itself. The proposed schema does not yet define
the per-member nonce/tag/envelope fields; the human-approved cryptographic
profile must define those fields and their authenticated encoding before the
schema can be treated as an implementable contract.

The artifact reader validates archive structure before extraction. It rejects
duplicate member names, absolute paths, empty/dot/path-traversal segments,
symlinks, hard links, devices, FIFOs and unsupported sparse/compressed forms.
Extraction uses an owner-checked destination and no-follow file creation; it
never follows links from an archive. Member count, path depth, per-member size,
aggregate ciphertext/plaintext size, compression ratio and staging-space limits
must be selected before implementation. Exceeding any configured limit fails
before target mutation.

The revised D9/A7 recommendation is 64 members, depth 8, paths at most 1024
UTF-8 bytes, 1 GiB per member, 4 GiB aggregate plaintext, a 16 MiB manifest,
64 MiB format overhead and a 5 GiB complete artifact, without outer
compression. The 1 GiB member cap includes the entire SQLite snapshot or
PostgreSQL custom dump. Reserve `max(2 × measured source bytes + 1 GiB, 6 GiB)`
as an enforced staging quota; the proposed reserve cap is **9 GiB**, not
8 GiB, so a 4 GiB source can reserve its full computed need. Fail before
capture when the full reserve is unavailable or exceeds the cap; never lower
it to fit. Representative SQLite/PostgreSQL source, member, artifact and peak
temporary/encryption measurements are still required before accepting these
values. The proposed schema remains incomplete and cannot authorize runtime
use of these bounds or the cryptographic profile by itself.

JSON Schema validation is only the syntactic first pass. A semantic validator
also rejects duplicate member names and migration versions, requires the
backend-appropriate snapshot method, verifies the profile/backend combination,
and checks that the state inventory and members cover the complete
profile-required inventory. It validates identifiers using the approved
ASCII-safe canonical form and validates key identifiers only against an
operator-selected trust configuration, never by trusting the artifact's key
ID. The proposed manifest's `source_sha` is the exact 40-character Git commit
object ID; artifact and member digests are SHA-256 values.

For format v1, the same nine control-plane inventory families and five external
exclusion families are mandatory for both currently enumerated profiles.
Profile data that has no rows is represented by an empty valid payload rather
than omitting the family. Each member carries the top-level consistency
generation, and semantic validation requires exact equality. Duplicate member
names are rejected by an explicit name-set check; JSON Schema `uniqueItems`
alone is not sufficient because it compares complete objects.

## 3. Consistency and backend behavior

### Proposed common offline boundary

Stop every store-opening O3K process and hold an exclusive data-directory
startup/store-access lock through capture, profile-specific signing and
verified publication or safe abort. Every daemon, CLI and maintenance path opening the
store must participate before any store initialization, readiness, worker,
lease or provider activity. The current storage execution lock does not
implement this invariant. Tests must race ordinary CLI/store access and
supervisor restart against capture. Measure controller downtime, including
signing, and workload data-plane continuity independently for each profile.

### SQLite profile

Use the existing SQLite WAL/integrity policy and supported snapshot API:

1. prevent control-plane writes for the duration of the cross-file snapshot;
2. perform the documented WAL checkpoint;
3. create the DB snapshot with `VACUUM INTO` (or an equivalently supported
   SQLite online-backup API accepted by the implementation review);
4. validate the snapshot with SQLite integrity checks and the recorded schema
   and migration identity;
5. package config/bootstrap material from the same quiesced interval.

The quiescence protocol covers API writes and background workers, including
reconciliation/provider dispatch and lease renewal. It drains in-flight
Operations to a known boundary or records them as unresolved/unknown with
stable operation identity. Every captured member is bound to one quiescence
generation or equivalent consistency token. For PostgreSQL, the dump snapshot
is correlated with that generation. If database, config, bootstrap/trust and
release metadata cannot be proven to belong to the common cut, backup fails.
The mechanism for acquiring/releasing this quiescence is an architecture
approval item. A backup-specific generation is evidence metadata only; it does
not add a durable canonical authority. The implementation reuses accepted
Operation/controller coordination or keeps the token within the backup run.

A live `.sqlite` file copy is never a supported snapshot method. If the
implementation cannot prove a stable quiescence point, it must reject the
backup rather than label an inconsistent multi-file capture as committed.

### PostgreSQL profile

Use the supported PostgreSQL version and a transaction-consistent database
dump (`pg_dump` custom/directory format or another approved native mechanism)
with a fresh target restore path. Record server version, dump tool version,
database/schema identity, extensions, role/ownership expectations and applied
migrations. Validate the restored database before activation. Database dumps
do not restore cluster roles or global privileges. The restored target uses a
least-privilege role provisioned from trusted installation configuration,
unless security review accepts a separate allowlisted role mechanism;
artifact-supplied global roles, passwords and grants are never applied
implicitly. The production lane uses a real isolated PostgreSQL instance and
fails if the configured database/tooling is unavailable. A skipped test is
not a pass.

For human review, the bounded default recommendation is PostgreSQL 16 custom
format (`pg_dump -Fc`) as one opaque regular-file member, restored with the
matching supported `pg_restore` into a fresh empty database and configured to
stop on the first error. Stop-on-error does not make restore atomic. A known
partial restore error after target mutation enters `FAILED_RECOVERABLE`; an
unknown outcome enters `QUARANTINED`. The target remains inactive in both cases. It is
discarded and recreated or recovered only by an approved idempotent path.
Activation requires complete restore plus integrity, privilege, and migration
validation. The approved restore invocation must use `--no-owner` and
`--no-acl`, or a reviewed equivalent that demonstrably suppresses
artifact-controlled ownership and ACL application. If the supported tool path
cannot enforce that policy, restore fails before target mutation. Restore also
uses an installation-provisioned least-privilege database role and an
approved extension/object allowlist. The artifact must not mutate roles,
passwords, tablespaces, ownership, or ACLs beyond that approved policy. The
artifact does not provision cluster-global roles, passwords, tablespaces, or
grants. This is a recommendation only: the exact tool/version, extension,
object, role, and ownership policy remains subject to ADR-0189 approval and is
not an implementation contract yet.

The O3K artifact reader treats a PostgreSQL dump as opaque, integrity-checked
member bytes; it does not recursively extract PostgreSQL-native archive
members. A trusted, version-checked PostgreSQL tool consumes the member in its
native format under the selected resource limits. If directory format is
selected, each directory member is separately enumerated and authenticated by
the O3K manifest. Outer bundle path/link/device/archive defenses do not replace
validation of the native dump by PostgreSQL tools.

The PostgreSQL transaction snapshot is internally consistent. A coordinated
daemon quiescence is still required to align the database with O3K-owned
configuration and protected bootstrap/trust files. PostgreSQL support does not
imply HA or Kubernetes HA.

For the offline recommendation, preventing O3K writer-role login and proving
there are no remaining O3K writer sessions are mandatory independently of
local daemon shutdown or local locks. This must cover controllers on other
hosts and every permitted writer path. An uninspectable session set,
remaining writer, new writer connection or loss of exclusion prevents capture.
Exact privileges and the exclusion/recovery procedure remain approval items.

Before any archive SQL executes, run unfiltered `pg_restore --list` without
connecting to the target and validate the complete TOC against the trusted
exact-migration inventory through a version-pinned normalization/classification
policy. Account for every entry as an expected migration-owned object, expected
data entry, explicitly allowlisted PostgreSQL/tool-generated entry, or forbidden
entry. Pin that generated-entry allowlist and inventory mapping. Reject missing,
unknown, duplicate and forbidden entries rather than silently filtering them
into an apparently valid subset. Inert archive owner metadata cannot authorize
ownership SQL; `--no-owner` and `--no-acl` remain mandatory and do not waive
inventory validation. TOC
matching alone cannot validate executable function bodies, triggers or default
expressions under otherwise approved names. An approved pre-execution
definition policy is also required; post-restore catalog comparison cannot
undo code already executed. Then independently compare the restored catalog,
definitions, privileges and migration identity before activation. Exact grants,
inventory revision and definition-validation mechanism remain PENDING. The
PostgreSQL 16 [pg_restore documentation](https://www.postgresql.org/docs/16/app-pgrestore.html)
describes this distinction between archive listing and executable SQL.

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
Database restoration and activation are distinct: the restored database stays
inactive until the accepted PKI issuer/trust recovery or replacement and
re-enrollment checks pass.

The selected signing modes keep PostgreSQL online artifact signing restricted
to authenticated backup artifacts for the configured site/profile, while
SQLite small-edge/TestLab retains operator-assisted offline artifact signing
where supported. The online signing authority cannot authorize restore,
fencing, restore-journal transitions, or controller activation. Offline
recovery and restore-journal authority remain distinct from artifact signing;
issuer replacement and agent re-enrollment are proposed activation gates.
Private recovery and journal-signing keys never move to the controller, target,
or backup destination. The concrete PostgreSQL signer boundary, request
authentication, key custody, trust provisioning, rotation, revocation,
recovery, and failure behavior remain PENDING in ADR-0189 or its referenced
protected custody record. Public documents must not disclose secrets or
sensitive media locations.

## 5. Backup publication and retry

The writer persists a durable backup operation identity before beginning. If
exposed as a control-plane operation, it reuses canonical Operation authority;
otherwise its protected journal is procedural recovery metadata only, not a
cloud resource/lifecycle authority. It
creates a private staging directory on the destination filesystem, writes and
fsyncs payload members, verifies digests/authentication and database
integrity, writes the manifest and commit marker, fsyncs the directory, then
atomically publishes the completed artifact. `COMMITTED` is visible only after
all checks and durable publication finish. A failed or interrupted staging
artifact is not selectable as a backup.

Signing follows the selected profile mode. For PostgreSQL, an online signer
may authenticate only a completed backup artifact for its configured
site/profile; it has no authority for restore, fencing, restore-journal
transitions, or activation. For SQLite small-edge/TestLab where supported,
retain the Option A operator-assisted offline signature round-trip. In both
cases the exact authenticated manifest/member-digest input must be verified
before fsync and publication, and signing failure, cancellation, or a
mismatched response cannot publish a backup. Retain private encrypted staging
or safely abort; resume only the same request and immutable content after
re-proving exclusion. The capture exclusion and staging reservation remain in
force through verified publication or safe abort. Exact signer request,
transport, timeout, custody and recovery behavior remain PENDING; this
specification does not define or authorize their implementation.

Retry uses the same operation/backup identity. It observes the existing
staging/final path and validates it before deciding whether to resume, return
the committed result, quarantine an incomplete artifact, or fail on a content
conflict. It does not overwrite an artifact with a different digest.

Each durable side effect has a deterministic step identity bound to the backup
or restore operation and target. A timeout triggers observation of the step's
actual result before retry; publication, database restore, journal transition
and fencing are never repeated solely because the caller received no response.
The final destination and staging path are exclusively reserved and rechecked
immediately before publication to close preflight races.

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

Preflight acquires an exclusive reservation for the target and repeats
ownership and emptiness checks immediately before mutation. The approved
mechanism prevents another process/controller from populating the target
between those checks. The protected restore journal binds operation ID, source
artifact digest, target installation/database identity and phase; it is
authenticated, durably written, and is not canonical tenant or control-plane
state. Conflicting, missing, stale, replayed or tampered journals fail closed
and require explicit recovery rather than implicit restart.

Restore prefers streaming decrypted database content directly into the
reserved empty O3K-owned database target where the reviewed backend/tooling
path supports it safely. If plaintext staging is required, it must use a
private owner-only directory with no-follow creation, restrictive permissions
and umask, bounded lifetime and capacity, and crash cleanup or quarantine
whose completion can be verified. It must fail closed if the implementation
cannot prove the staging path is private or its cleanup disposition is safe.
Decrypted file members follow the same protected staging rules and are
validated before install. Nonempty/foreign data, wrong installation
identity, unknown profile/schema/version, or unavailable keys fail before
destructive mutation. It never deletes, imports, or reconciles external VM,
network, or storage objects during artifact restore.

Exact site identity preservation versus regeneration on host replacement is a
human decision. The approved identity map distinguishes stable site/resource
identities from host/controller runtime identities and credentials, specifies
credential regeneration and prevents accidental mutation of the source site.
Controller runtime identity must not permit a stale process to resume work
after restore. Before API writes or provider dispatch resume, the restored
control plane establishes current exclusive ownership/fencing and invalidates
old ownership. A local restore journal alone does not fence a surviving source
process. The single-controller fencing mechanism, including source-host stop
or out-of-band fencing behavior, is an ADR-0189 approval item. Normal
post-activation reconciliation uses SPEC-0008 observe-before-retry behavior
and existing canonical authorities.

The revised D7 recommendation selects independent Redfish/BMC power-off as the
initial backend. Observe from a trusted recovery host independent of the
source, validate per-site BMC TLS trust and source serial, and bind source,
site, target, actor, certificate fingerprint and timestamps in evidence signed
by the D2 offline Ed25519 journal/evidence key. The target recovery verifier
uses a separately installed non-revoked public key. Evidence must be at most
five minutes old and a fresh authenticated BMC power-off observation is required
before activation; a signature is not BMC hardware-signed telemetry or a
substitute for independent exclusion. Reject stale, replayed, altered,
unavailable or identity-mismatched evidence. No network-isolation backend is
implicitly approved. Demo/TestLab without independent fencing is limited to
capture and verify; fresh-host activation remains unsupported.

Point-in-time power-off evidence is insufficient for lasting exclusion. Before
activation, D3 issuer replacement and rejection of source credentials at every
agent/API/provider verifier, fresh target ownership epoch and PostgreSQL
target-only writer access must be proven. Retain independent source exclusion;
neither lease expiry nor a signed assertion permits the source to resume.

## 7. Restore state and crash recovery

Restore records durable progress outside the target DB in a protected,
target-specific journal. Proposed states are:

```text
PREFLIGHTED -> SOURCE_FENCED -> TARGET_RESERVED -> STAGING
-> DATABASE_RESTORED -> FILES_RESTORED -> TARGET_FENCED
-> STARTED -> RECONCILED -> COMMITTED
  safe abort before canonical mutation -> ABORTED
  known partial mutation before STARTED -> FAILED_RECOVERABLE (inactive)
  unknown outcome, lock loss or conflict -> QUARANTINED
  verified discard/recreation only -> DISCARDED
  failure after STARTED and before COMMITTED
    -> existing controller/Operation recovery; exact stop/fence transition
       requires ADR-0189 approval
```

The journal binds operation ID, backup ID/digest, source and target identities,
deterministic step IDs and phase. Every external side effect is preceded by
durable intent. On restart,
the runner observes the target and repeats only idempotent steps; it never
assumes a timed-out command failed. A mismatch or ambiguous foreign-state
observation stops activation and reports a bounded recovery action. The
precise placement/location of the restore journal and the fencing phase is
subject to approval.

The revised D8 recommendation uses a dedicated `o3k:o3k` directory (0700;
files 0600) outside the target database on verified local ext4, compatible with
the packaged service user. Reject network/overlay/ephemeral journal storage.
Create reserved files with `O_EXCL`/`O_NOFOLLOW` under an owner-checked
directory. The target-reservation lock and D4 startup/store-access lock are
distinct: retain reservation through terminal state and require a reviewed
continuous startup-guard handoff to the intended controller before `STARTED`.
No release-then-start race, unrelated supervisor startup or implicit bypass is
permitted. Exact handoff and crash behavior remain PENDING.

Each forward phase requires a detached offline Ed25519 journal/evidence-key
signature over the exact sequence, previous signed-record hash, request
nonce/ID, operation/artifact/site/source/target and phase. Persist the request
before transfer to the disconnected signing workstation and confirm its
displayed context there. Persist accepted records with file fsync, same-directory
atomic rename and parent-directory fsync. Lost responses retry only the exact
pending request; stale/replayed/forked/skipped transitions fail closed. A
successful restore needs roughly ten human signing round-trips, including
`STARTED`, `RECONCILED` and `COMMITTED` while the controller runs. Signing
attests journal bytes, not database integrity against a target-root attacker.

If signing is unavailable, separate unsigned `QUARANTINED` or pre-start
`FAILED_RECOVERABLE` stop markers may only deny progress. They are untrusted
forensic metadata outside the signed chain, not authenticated phase changes.
Presence blocks progress; absence proves nothing. They cannot authorize
mutation, activation, retry, deletion, discard or reuse. If owner/lock safety
prevents persistence, preserve the last signed state and pending request,
report the failure and require inspection rather than writing a conflicting
journal. Clearing a marker requires a fresh signed recovery disposition after
complete revalidation. Startup must not infer success from a missing marker,
free lock or old signed phase.

`FAILED_RECOVERABLE` is only the pre-activation state for known partial restore
outcomes after target mutation and before `STARTED`; unknown outcomes remain
`QUARANTINED`. Durable
journal state marks the target inactive and blocks API writes, provider
dispatch, and reuse by a new restore. Recovery requires verified
discard/recreation or a separately approved idempotent recovery path; phase
labels alone do not prove target integrity. A failure after `STARTED` must not
be relabeled as pre-activation quarantine: the controller must stop or fence
new dispatch, preserve canonical Operation state, and resolve unknown outcomes
through the accepted observe-before-retry behavior. The exact stop/fence and
restart transition is a human approval item in ADR-0189; the restore design
does not define an alternate Operation or lifecycle authority.

## 8. Operator interface

No native API is defined. Existing operator CLI conventions suggest an `o3k`
subcommand, but this proposal does not add or freeze a CLI contract. A later
approved interface decision must define backup create/verify/inspect and
restore preflight/execute behavior, required confirmation, status/error JSON,
exit codes, idempotency key, and secret-redaction rules. The contract must not
advertise restore support before profile-specific evidence passes.

D12/A8 recommend making that separately approved exact-release operator
invocation and #944 runbook explicit prerequisites for operational recovery
acceptance. Reject the proposed withdrawal/deferral of this dependency. This
specification accepts no command names, flags or exit codes. The release
binary, immutable artifact and supported invocation must be exercised together
on a fresh disposable host, including interrupted/lost-response retry.

## 9. Validation and acceptance

Before a PP.6 backup/restore claim, evidence is required for both persistence
profiles that are claimed:

- SQLite live-write/WAL consistency, restore and canonical inventory parity;
- real isolated PostgreSQL dump/restore with attempted concurrent writes
  rejected by the offline writer exclusion;
- fresh disposable host restoration and restart/reconciliation;
- crash/restart at every declared backup and restore phase, including retry
  after a lost response for each filesystem/database/fencing side effect;
- PostgreSQL restore failure after partial target writes and a lost restore
  result leave the database inactive/quarantined; unsafe reuse and activation
  are rejected, while discard/recreate or an approved idempotent recovery path
  is verified;
- failures after `STARTED` stop/fence new provider dispatch through the
  approved controller recovery path, preserve canonical in-flight Operation
  identities, and require observe-before-retry before provider mutation;
- PostgreSQL restore runs without artifact-controlled ownership/ACL changes,
  role/password/tablespace mutation, or unapproved extensions/object classes;
  the exact supported `pg_restore` invocation (or reviewed equivalent) is
  verified, and a tool path that cannot enforce the policy fails before target
  mutation; negative fixtures are rejected or the restricted restore role is
  proven unable to apply them;
- corruption, truncation, tamper/authentication, missing member, version,
  profile, backend, schema and migration mismatch rejection;
- archive duplicate-name, traversal, link/device entry, sparse-file, limit and
  decompression-bomb rejection before extraction;
- distinct duplicate-member-name rejection even when duplicate entries have
  otherwise different metadata, and per-member consistency-generation match;
- owner-only plaintext staging permissions, cleanup after normal and crash
  paths, and fail-closed behavior when safe cleanup cannot be established;
- opaque PostgreSQL custom/directory dump member handling with real isolated
  PostgreSQL restore and no recursive extraction by the O3K bundle reader;
- safe retry and unknown outcome observation;
- PostgreSQL role/privilege least-privilege restoration and rejection of
  artifact-supplied global privilege changes;
- issuer/trust/secret recovery and secret-safe output; database-restored but
  unactivated is not a successful control-plane restore;
- foreign target and external provider state preservation;
- race attempts that populate backup/restore targets after preflight but before
  publish/restore;
- zero unowned mutations before and after reconciliation.

The review amendments additionally require focused negative evidence for all
store-opening CLI/maintenance/startup paths and remote PostgreSQL writer
exclusion; offline signing timeout/request mismatch and interruption;
independent BMC/identity/freshness failure and old-source credential rejection;
service-user journal permissions, unsigned marker denial-only semantics,
startup-guard handoff and lost-lock/signing-response recovery; exact 4 GiB/9 GiB
capacity boundaries and the single database-member cap; pre-execution TOC and
same-name executable-definition drift; and the approved exact-release operator
invocation. These are required test cases, not tests executed or passed by
this proposed document revision.

Every result binds source SHA, test/harness SHA, release artifact digest,
profile, backend/server/tool version, migration identity, backup digest,
destination/host identity, and machine-readable verdict. Required PostgreSQL
tests fail closed when PostgreSQL is absent or unreachable.

Diagnostics, errors and evidence use bounded structured error codes and
allowlisted safe fields. They redact PostgreSQL URLs, credentials, tokens,
private keys, enrollment secrets, raw provider payloads, sensitive filesystem
paths, key-provider exception text and unfiltered exception chains. Secret
scans cover successful and failing backup/restore paths.

See `docs/pp/PP6_GAP_ANALYSIS.md` for the ordered executable matrix.
