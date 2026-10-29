# SPEC-0050 — PP.6 control-plane backup and restore

Status: Accepted technical contract at `9ce23ff81218e8e35d917ef6ee4478ae69e8f28e`, with accepted C1 merge `ea4f705efba72421f368903be71a0e792851813f` and A10 merge `ca8fe3033ace09cf7b7a43286522dbd3e6ad326a`;
implementation and release evidence remain gated
Authority proposal: ADR-0189
Issue: #975, reusing #640
Profile scope: `o3k-demo-v1` SQLite where retained; `o3k-small-edge-v1`
PostgreSQL profile

This accepted technical specification defines recovery behavior not covered by the existing
local upgrade rollback contract. It does not amend PP.5 acceptance thresholds,
SPEC-0024 database support, SPEC-0008 operation semantics, or ADR-0167
deployment authority. Technical contract acceptance is not implementation or
runtime acceptance evidence.

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
The profile-mode selection was followed by an exact-revision technical
decision. On 2026-10-18, the authorized reviewer recorded `accepted` on #975;
PR #1156 was approved at source revision
`9ce23ff81218e8e35d917ef6ee4478ae69e8f28e` after its final signer-authorization
test update. The tracking record limits acceptance to the technical conditions
for ADR-0189, this specification, and the matching artifact schema
(D2/D4/D7/D8/D9/D10/D12/D13). The review is non-independent under ADR-0190;
no independent security review is claimed. Acceptance does not cover later
contract revisions, SPEC-0051, runtime correctness, release readiness, or
production evidence. The implementation and evidence gates below remain
mandatory.

The consolidated D2/D4/D7/D8/D9/D10/D12/D13 decision request and
exact-revision record are in
[`PP6_TECHNICAL_CONTRACT_APPROVAL.md`](../pp/PP6_TECHNICAL_CONTRACT_APPROVAL.md).

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

The artifact has a versioned manifest conforming to the accepted-at-revision
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
is encrypted. Public manifest fields contain no credentials, private key
bytes, database URL, provider payload, or user data. Use a fresh 256-bit
CSPRNG content key per artifact and AES-256-GCM per member with a unique
96-bit CSPRNG nonce. RFC 8785 canonical JSON is the only accepted manifest
encoding; duplicate keys and non-canonical bytes are rejected. Member AAD
binds format version, profile, site, artifact ID, normalized member name and
plaintext length. RFC 9180 HPKE Base-mode X25519/HKDF-SHA256/AES-256-GCM wraps
the content key. HPKE `info` is
`O3K-PP6-ARTIFACT-KEY-WRAP-V1\0`; HPKE AAD is canonical JSON binding format,
profile, site, artifact ID and recipient key ID. Record recipient key ID,
`enc` and wrapped ciphertext in the manifest. Member digests cover ciphertext
and GCM tag. Ed25519 authenticates the canonical manifest without the
signature plus the ordered, length-prefixed ciphertext digests under the D1
domain prefix. Unknown algorithms, duplicate nonces, malformed encodings,
wrong key IDs, invalid signatures and bad tags fail before extraction.

PostgreSQL uses a dedicated signing service on a separate host or isolated
signing appliance. Its Ed25519 key is non-exportable in a PKCS#11 v3.0 HSM.
The service accepts mutually authenticated TLS 1.3 requests only from the
installed backup-client identity and only for the configured site and
`o3k-small-edge-v1` profile. A request binds exact canonical signature input,
artifact ID, manifest digest, key ID, site/profile, request ID, 256-bit nonce
and a 15-minute expiry. A durable replay ledger returns the original signature
only for the byte-identical request within that period; reuse of an ID/nonce
with different bytes or scope is denied. Expired or lost requests require a
new artifact ID and recapture after re-proving exclusion. The key supports only
the D1 backup-manifest domain, never restore, journal, fencing, release or
activation. There is no fallback key.

A distinct offline Ed25519 backup-trust root certifies online signing public
keys with exact RFC 8785 canonical JSON fields `key_id`, public key,
`purpose=backup_manifest`, exact site/profile, serial, validity and issuer.
The root also signs a monotonic revocation list carrying `sequence`,
`issued_at` and `next_update`. Online signing certificates are valid for at
most 90 days; the revocation list must be refreshed at least every 24 hours by the offline custodian process.
The trust root is not the HPKE recovery key, artifact key, journal/evidence key
or release key. Its public trust anchor and initial trust/revocation sequence
are pinned in the release-signed installation manifest. Verifiers fetch the
signed list from a trust-distribution endpoint administered separately from
the artifact signer before artifact acceptance and again before restore
activation. Two custodians issue and publish an emergency root-signed
revocation immediately after compromise. A list is valid for at most 24 hours;
the verifier durably remembers the highest accepted sequence and canonical-list
digest. Equal sequence is idempotent only for the same digest; different
content at that sequence is equivocation and fails closed. If the distribution
endpoint is unavailable, a cached list may be used only until `next_update`,
bounding but not eliminating worst-case stale-revocation exposure to 24 hours.
Missing, expired or lower-sequence state fails closed. Offline root
operations require two of three named custodians at the offline signing
workstation. New online keys are certified and installed before switch; old
and new keys verify for a 30-day overlap, after which the old key is retired.
A compromise causes immediate root-signed revocation, epoch increase and
fail-closed verification for that key. The signer is deployed in a separately administered security boundary;
its HSM backup and replacement use the same two-of-three custody. The online
service has no access to any offline private key.

SQLite uses a separate offline Ed25519 artifact key and operator-assisted
signing. Each request is displayed and confirmed by two of three named
custodians at the offline signing workstation. Recovery decryption and
restore-journal/evidence signing use different offline keys and key IDs, each
under the same two-of-three custody, never colocated with or derived from
artifact-signing keys. HPKE private-key rotation retains old offline recovery
keys for the complete configured artifact-retention period; destruction
requires a verified replacement/re-encryption campaign. Signer outage yields
a bounded error and no published artifact; only the exact immutable request
may be retried after re-proving capture exclusion. The signer never returns
or logs private key material. HSM model qualification and production custody
remain deployment evidence, not claims made by this protocol prototype.

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
as an enforced staging quota; the accepted reserve cap is **9 GiB**, not
8 GiB, so a 4 GiB source can reserve its full computed need. Fail before
capture when the full reserve is unavailable or exceeds the cap; never lower
it to fit. Representative SQLite/PostgreSQL source, member, artifact and peak
temporary/encryption measurements remain required before claiming the bounds
are met. The accepted schema defines the bounds and cryptographic profile; it
does not prove a runtime implementation enforces them.

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

For D13, a committed repository inventory has one row for every registered
durable store repository, including repositories with no tables. Rows map the
repository identifier to its SQLite and PostgreSQL data tables and one of the
nine manifest families. A separate catalog inventory covers every table,
view, sequence, index, constraint, function and trigger, with a normalized
definition digest. The baseline is generated from the store repository
registration plus both migration trees; it is reviewed and committed, never
auto-updated by CI. CI regenerates it and fails on any missing, extra or
unregistered repository/object. A real migrated database is queried through
SQLite `sqlite_schema` and PostgreSQL `pg_catalog`; generated system objects
are separately classified and cannot satisfy an application object entry.
Audit rows and empty repositories are explicitly represented. Backup fails if
the source catalog differs from the exact-release baseline; restore fails if
the resulting catalog or repository-to-family mapping differs.

## 3. Consistency and backend behavior

### Proposed common offline boundary

Stop every store-opening O3K process and hold an exclusive data-directory
startup/store-access lock through capture, profile-specific signing and
verified publication or safe abort. The lock is a lifetime `flock(LOCK_EX)`
acquired before store initialization, readiness, workers, lease renewal or
provider dispatch. Every `o3kd`, `o3k` store command and maintenance path uses
the same lock file. The lock file is opened with no-follow semantics, and its
directory, owner, device and inode are validated. The daemon retains the lock
for its process lifetime. Systemd restarts use the same mandatory path; a
failed lock acquisition prevents store open/readiness. Backup holds the lock
from after all local openers exit until verified publication or safe abort.
The current storage execution lock does not implement this invariant. A local
lock does not exclude a controller on another host. For PostgreSQL, a
separately provisioned O3K writer login is disabled transactionally before
capture using a distinct administrative control identity, and every session
for that login is terminated and verified absent from `pg_stat_activity`.
Capture uses a read-only dump role, `pg_dump -Fc` from the supported PostgreSQL
16 toolchain, and rejects unknown O3K writer roles, unrelated writers, or an
uninspectable session set. Restore never reuses the source writer credential.
Tests race every local opener and supervisor restart against capture and
attempt remote login/session retention. Measure downtime, including the
SQLite offline signing interval, and data-plane continuity separately.

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
A backup-specific generation is evidence metadata only; it does not add a
durable canonical authority. The implementation reuses accepted
Operation/controller coordination or keeps the token within the backup run.

A live `.sqlite` file copy is never a supported snapshot method. If the
implementation cannot prove a stable quiescence point, it must reject the
backup rather than label an inconsistent multi-file capture as committed.

### PostgreSQL profile

Use PostgreSQL 16 and a transaction-consistent custom-format database dump
(`pg_dump -Fc`) with a fresh target restore path. Record server version, dump tool version,
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
grants. These defaults were accepted at the exact revision recorded in ADR-0189.
Their runtime enforcement and evidence remain required; this contract decision
is not runtime or release acceptance.

The O3K artifact reader treats a PostgreSQL dump as opaque, integrity-checked
member bytes; it does not recursively extract PostgreSQL-native archive
members. A trusted, version-checked PostgreSQL tool consumes the member in its
native format under the selected resource limits. If directory format is
selected, each directory member is separately enumerated and authenticated by
the O3K manifest. Outer bundle path/link/device/archive defenses do not replace
validation of the native dump by PostgreSQL tools.

The PostgreSQL transaction snapshot is internally consistent. The approved D4
admission barrier and coordinated daemon quiescence align the database with
O3K-owned configuration and protected bootstrap/trust files. The PostgreSQL
barrier blocks every non-backup network path, disables O3K writer logins,
terminates existing sessions, and verifies that only the designated read-only
`o3k_backup_dump` session remains before the admin channel closes for capture. PostgreSQL support does not
imply HA or Kubernetes HA.

The PostgreSQL role matrix is fixed for v1. Installation provisions distinct
roles: `o3k_runtime` (application DML), `o3k_backup_dump` (LOGIN only during
capture), and `o3k_restore_owner` (LOGIN only during restore). None is
SUPERUSER, CREATEDB, CREATEROLE, REPLICATION, BYPASSRLS or an inherited member
of a privileged role. The dump role has CONNECT, USAGE on the application
schema, SELECT on each inventoried table, and SELECT on each inventoried
sequence; it has no write or DDL grants. The restore-owner role owns the
freshly created target database/schema and alone has CREATE there; it is
disabled after restore. Runtime has CONNECT, schema USAGE, table SELECT/INSERT/
UPDATE/DELETE and sequence USAGE/SELECT/UPDATE for the exact inventoried
objects; it has no database/schema CREATE, role, extension, or table-owner
privilege. Grants are generated from the approved migration inventory and
compared with `pg_catalog` before activation. RLS-enabled tables, non-public application schemas, user-defined views,
sequences, extensions, security-definer functions and unclassified roles are
rejected in v1. The exact PG16 migration baseline currently contains 77 public
tables, no app views/sequences/extensions, and exactly two non-security-definer
trigger functions (`o3k_validate_operation_resource_reference` and
`o3k_delete_generic_resource_operations`) with their two migration-created
triggers. Those functions/triggers, every table, all indexes and all
constraints are allowlisted by normalized definition digest. A descriptor is
RFC 8785 canonical JSON over catalog identity and behavior: ordered column
type/nullability/default/generated/identity metadata; `pg_get_indexdef`;
`pg_get_constraintdef` plus validation/deferred flags; `pg_get_functiondef`
plus language/volatility/security/config; `pg_get_triggerdef` plus enabled
state; and `pg_get_viewdef`/sequence parameters where applicable. Hash
canonical UTF-8 bytes with SHA-256. The baseline binds PostgreSQL major and all
migration-file SHA-256 values. Any additional callable object or definition
drift is rejected.

Before capture, the database-side writer-admission barrier is installed and
held for the whole dump. The approved D4 admission mechanism installs
first-match `pg_hba.conf` rules permitting only the backup-host address and
`o3k_backup_dump` for the O3K database, followed by explicit rejects for all
other network paths and `local all all reject`; an independently managed
database-host ingress ACL enforces the same source restriction. All O3K
writer-capable LOGIN roles are set `NOLOGIN`, pools are stopped, and all
pre-existing sessions are terminated except one already-open local control
session. The controller validates `pg_hba_file_rules`, reload completion, and
proves fresh Unix-socket, application and maintenance reconnects are denied.
The surviving local control session verifies no other database sessions exist,
then disconnects. Verify that it is gone and only the remote backup-host
`o3k_backup_dump` session exists before `pg_dump` starts. The policy generation and canonical configuration digest are
recorded. Firewall and HBA barriers remain active through the dump and
cross-file capture; restoration of the saved admission configuration occurs
only after verified publication or safe abort. The dump role is read-only and
is the only permitted connection during the capture interval. Revoke/reload failure, an unknown
role/membership, an uninspectable session, any new or surviving writer, or
loss of the admission barrier aborts capture. Managed PostgreSQL deployments
that cannot enforce an equivalent database-side admission barrier are
unsupported for backup. This closes the check-to-dump race; local `flock`
remains necessary for local processes but is never treated as remote-writer
exclusion. Restore uses matching PG16 `pg_restore --exit-on-error --no-owner
--no-acl` only against a newly created empty target.

Before any archive SQL executes, run unfiltered `pg_restore --list` without
connecting to the target and validate the complete TOC against the trusted
exact-migration inventory through a version-pinned normalization/classification
policy. Account for every entry as an expected migration-owned object, expected
data entry, explicitly allowlisted PostgreSQL/tool-generated entry, or forbidden
entry. Pin that generated-entry allowlist and inventory mapping. Reject missing,
unknown, duplicate and forbidden entries rather than silently filtering them
into an apparently valid subset. Inert archive owner metadata cannot authorize
ownership SQL; `--no-owner` and `--no-acl` remain mandatory and do not waive
inventory validation. TOC matching alone cannot validate executable function
bodies, triggers or default expressions under otherwise approved names. Before
actual-target restore, generate SQL from the archive with the pinned
PostgreSQL 16 tool and replay it in a disposable PostgreSQL 16 validation
instance isolated from network and host mounts, using the same unprivileged
restore role and resource limits. Compare its complete catalog, function
bodies, triggers, defaults, grants, migration identity and object inventory
to a clean database created from the exact release migrations. Reject any
definition or privilege drift before touching the selected target. The
validation instance is a parser/execution containment layer, not a substitute
for migration-derived exact inventory or actual-target verification. After
restore, independently compare the target catalog, definitions, privileges
and migration identity before activation. The PostgreSQL 16
[pg_restore documentation](https://www.postgresql.org/docs/16/app-pgrestore.html)
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
or backup destination. The PostgreSQL signer boundary, request authentication,
key custody, trust provisioning, rotation, revocation, recovery and failure
behavior are accepted as specified in the exact-revision technical approval
package. Their implementation and operational evidence remain mandatory.
Public documents must not disclose secrets or sensitive media locations.

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
force through verified publication or safe abort. The accepted signer
request, transport, timeout, custody and recovery contract is in the linked
exact-revision technical approval package. Runtime correctness, protected
integration of implementation changes, and end-to-end evidence remain gated;
contract acceptance is not runtime or release acceptance.

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

The initial supported independent fence is independently administered
Redfish/BMC power-off for the source host. The recovery operator uses a
separate recovery host, TLS 1.3 with configured per-site CA and exact source
serial verification, and an operator identity authorized for that BMC. The
operator records authenticated power state, BMC certificate fingerprint,
source/site/target IDs, actor, observation time and unique operation nonce.
A separate offline Ed25519 evidence key signs the record; the target has its
public key installed through the release-signed trust manifest. Evidence
expires after 300 seconds, is single-use for the bound target/operation, and
requires a live Redfish `PowerState=Off` observation immediately before
activation. A recovery-host fence monitor polls the BMC at least once per
second from the first signed fence record through `COMMITTED`; the independent
BMC management-network ACL is held in recovery-only mode throughout, and the
source BIOS is configured and tested to remain off after power restoration.
The initial signed fence record delegates a per-operation monitor verification
key. For every lease, the target issues a fresh unpredictable challenge; the
monitor signs a response binding that challenge, a strictly increasing
sequence, operation/source/site/target, current journal hash, authenticated
power-off observation and ACL state. The target accepts only its outstanding
unused challenge and exact expected sequence/hash, using its monotonic clock
for a two-second response lifetime. Every activation mutation and durable
`COMMITTED` transition requires a live response and held ACL; the challenge is
consumed atomically. A replayed challenge/sequence, prior journal hash, late
response, lost monitor or ACL denies activation and quarantines the target.
Loss of monitoring, BMC reachability, ACL state or power-off observation
immediately stops target provider dispatch and places the target in
`QUARANTINED`; no commit is accepted. The source remains BMC-powered-off
through commit; any power-on observation, TLS/serial mismatch, stale/replayed
nonce, absent BMC, or source credential accepted by any verifier blocks
activation and quarantines the target. Evidence is operator-attested to an authenticated BMC observation,
not hardware-signed telemetry. PostgreSQL activation additionally requires
target-only writer access and the source writer role disabled with zero
sessions. Profiles without independently administered BMC fencing (including
Demo/TestLab v1) support capture and verification only. No network fence is
implied.

**Historical conflict resolution (A10 accepted).** This
paragraph and the D7 profile table in
[`PP6_TECHNICAL_CONTRACT_APPROVAL.md`](../pp/PP6_TECHNICAL_CONTRACT_APPROVAL.md#d7-activation-capability-by-deployment-profile)
differ on whether a virtualized profile without independent BMC capability may
materialize an inactive target. Accepted amendment A10 (§7.1, owner decision
[6423776117](https://github.com/o3kio/o3k/issues/1086#issuecomment-6423776117))
resolves the difference by adding an explicit, signed, non-activating
inactive branch: a virtualized `o3k-small-edge-v1` target with PostgreSQL 16
may be materialized and verified only when a root-owned, release-signed
installation policy explicitly selects inactive materialization, and an
`INACTIVE_VERIFIED` record is terminal, denies operational open, and never
permits RELEASED or startup. For every profile outside that accepted scope
this paragraph's capture/verification-only rule still governs, and no
implementation may create an inactive restored target.

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

The recovery directory is a pre-provisioned `o3k:o3k` directory (0700) on
verified local ext4; journal, pending request, marker and lock files are 0600.
It is outside the target database and rejected on NFS, overlay, ephemeral or
unverified network storage. Files use `O_NOFOLLOW|O_CLOEXEC`; creation uses
`O_CREAT|O_EXCL`, with inode, owner and mode rechecked before use. Target
reservation and D4 startup/store-access guard are distinct. Reservation lasts
through terminal state. The startup guard is a lifetime `flock(LOCK_EX)` on a
file in the target data directory, acquired before store open, readiness,
workers, leases or provider dispatch. Each signed activation record binds the
current kernel boot ID and a fresh 256-bit launch nonce; the authorized `o3kd`
child atomically compare-and-consumes that nonce in the protected journal before
opening the store. A competing second consumer, reuse after consumption or
boot-ID change is rejected and requires a new signed recovery transition. The recovery launcher holds it and
passes the same open file description to the exact `o3kd` child across
`execve`; the child verifies inode, device, owner, mode and held lock before
opening the store. The ordinary systemd service uses the same guard and has
no bypass. After a crash, systemd may acquire the released OS lock but cannot
open the store unless a signed `STARTED` record, artifact, target and fresh
fence revalidate. The signed pending operation prevents another restore from
reusing the target. This local kernel lock does not fence PostgreSQL writers
or the source host.

Each forward phase requires a detached offline Ed25519 journal/evidence-key
signature over exact sequence, previous signed-record hash, request nonce/ID,
operation/artifact/site/source/target and phase. A pending request is
canonicalized, fsynced, copied to the disconnected signing tool, and displayed
there with all bound identities. Lost response retries only that byte-identical
request and nonce. Accepted records are written to a new 0600 same-directory
file, fsynced, atomically renamed, and followed by directory fsync. Before
signing `STARTED`, the launcher proves it holds the startup guard and has
completed target validation; it then obtains the exact detached signature binding boot ID and launch nonce,
and executes the pinned `o3kd` binary while inheriting the guard. The daemon
atomically consumes that nonce and verifies the signed record and fresh fence
before store open. If a crash occurs after signed `STARTED` but before
`execve`, systemd may acquire the guard and consume the same nonce only if it
is still unused and the boot ID is unchanged; a boot change or consumed nonce
fails closed and requires a new signed recovery transition. Stale/replayed/forked/skipped transitions fail closed. A successful
restore needs about ten offline signatures; reconciliation remains stopped or
stepwise until `COMMITTED`. Signatures attest journal bytes, not database
integrity against a target-root attacker.

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

### 7.1 Accepted amendment A10 isolated inactive materialization

Accepted for implementation/testing by owner decision [6423776117](https://github.com/o3kio/o3k/issues/1086#issuecomment-6423776117), reviewing PR #1176 head `b69b6b9b8abe913f1da4639cadb6df29509d4cde`, merged as `ca8fe3033ace09cf7b7a43286522dbd3e6ad326a`. This is not runtime, installed, production, or final PP.6 certification; the interim reviewer was explicitly non-independent.

#### 7.1.1 Purpose and profile scope

The accepted sequence requires `SOURCE_FENCED` before any target reservation,
which makes non-activating materialization unreachable without D7 evidence.
This proposal separates two different outcomes:

- **isolated inactive materialization** — restore and verify control-plane
  data into a target that has no operational controller authority; and
- **authorized controller activation** — let a controller with restored
  identity act on shared external resources.

The first outcome is proposed for one narrow profile only:

- deployment profile `o3k-small-edge-v1`;
- PostgreSQL 16 backend;
- virtualized deployment; and
- a root-owned, release-signed installation policy that explicitly selects
  inactive materialization, bound to profile, backend, deployment and release.

Physical `o3k-small-edge-v1` continues to use the accepted fenced activation
path and is out of scope for this amendment. SQLite `o3k-demo-v1` / TestLab
remains backup/verification-only; any SQLite inactive materialization is a
separate future profile extension. No new public API or endpoint is proposed;
the accepted host-local `o3k` CLI surface and confirmation/exit-code semantics
in §8 and the technical contract continue to apply.

The target may contain restored control-plane data, but it must have no
operational controller authority. It is a verified data image, not a running
cloud control plane.

#### 7.1.2 Legal state branch and transitions

An operation selects its branch when its journal is created, no later than the
`PREFLIGHTED` record, and the selection is fixed for the life of the journal
chain and is part of every signed record. An existing `v1` activation chain
cannot later select the inactive branch. The proposed inactive branch is:

```text
PREFLIGHTED
  -> TARGET_RESERVED_INACTIVE
  -> STAGING_INACTIVE
  -> DATABASE_RESTORED_INACTIVE
  -> FILES_RESTORED_INACTIVE
  -> INACTIVE_VERIFIED
```

The exact legal transitions are:

| From | To |
|---|---|
| `PREFLIGHTED` | `TARGET_RESERVED_INACTIVE`, `ABORTED` |
| `TARGET_RESERVED_INACTIVE` | `STAGING_INACTIVE`, `ABORTED`, `QUARANTINED` |
| `STAGING_INACTIVE` | `DATABASE_RESTORED_INACTIVE`, `FAILED_RECOVERABLE`, `QUARANTINED` |
| `DATABASE_RESTORED_INACTIVE` | `FILES_RESTORED_INACTIVE`, `FAILED_RECOVERABLE`, `QUARANTINED` |
| `FILES_RESTORED_INACTIVE` | `INACTIVE_VERIFIED`, `FAILED_RECOVERABLE`, `QUARANTINED` |
| `FAILED_RECOVERABLE` | `DISCARDED`, `QUARANTINED` |
| `QUARANTINED` | `DISCARDED` |

No other transition is legal. In particular:

- no inactive record may appear in an activation chain, and no activation
  record may appear in an inactive chain; mixing, switching or omitting the
  branch is a fork and fails closed;
- `INACTIVE_VERIFIED` has no forward transition; it is a terminal verified
  materialization result, not an activation state;
- no transition from any inactive phase or `INACTIVE_VERIFIED` to
  `SOURCE_FENCED`, `TARGET_RESERVED`, `STAGING`, `DATABASE_RESTORED`,
  `FILES_RESTORED`, `TARGET_FENCED`, `STARTED`, `RECONCILED` or `COMMITTED` is
  legal, including by relabeling, re-signing or journal editing;
- forward records may not skip a phase.

`INACTIVE_VERIFIED` means only that the permitted materialization and
verification steps passed. It must be distinguishable from `COMMITTED` in the
type system and on disk, must never set activation fields, and must never
imply that the source controller was fenced.

#### 7.1.3 Signing and journal binding

Every forward inactive transition, including `INACTIVE_VERIFIED`, requires the
accepted D8 detached offline Ed25519 journal signature over RFC 8785 canonical
bytes containing at least: journal format and branch, monotonic sequence,
previous signed-record hash, request ID and 256-bit request nonce, operation
ID, artifact SHA-256, site, source installation, target installation, target
device and inode, target database identity, and phase. The signed binding also
includes the deployment profile `o3k-small-edge-v1`, backend `postgresql`,
deployment `virtualized`, and the digest of the signed installation policy that
selected the inactive branch.

The `INACTIVE_VERIFIED` record additionally binds the verification result:
restored target database identity, artifact and release identity, migration
baseline digest, D10 catalog/definition digest, canonical repository inventory
parity digest, target installation ID, and `verification = passed`. A missing,
unknown or mismatched bound value fails closed.

Replay, sequence and retry rules are unchanged: a lost response retries the
exact persisted request bytes and nonce; a new nonce for an already requested
sequence is a fork; a replayed, forked, skipped or mixed-branch chain is
rejected; an unsigned failure marker may only deny progress. New phase names
require a new journal and signing-request format version
(`o3k-restore-journal-v2` / `o3k-restore-signing-request-v2`, or later). An
inactive operation uses that format from its first record; a `v1` chain is
never converted into it. Older readers must reject the unknown format or phase
rather than treat it as success.

#### 7.1.4 Mandatory inactive-target safeguards

An inactive materialization is permitted only when all of the following hold:

1. the target is fresh, empty at reservation, O3K-owned, exclusively reserved
   by the operation, and outside the source data path; the recovery journal is
   on verified local ext4 with owner-only permissions;
2. no existing operational controller or other store opener is present; the
   operation holds the lifetime exclusive startup/store-access guard and
   verifies that no operational listener, active lease, writer session or
   provider dispatch exists;
3. no automatic systemd or controller activation occurs: the `o3kd` unit is
   not enabled or started for the restore, and a controller start is denied
   while any authenticated inactive-branch chain exists, including
   `INACTIVE_VERIFIED`;
4. a denial-only quarantine marker is retained across crashes when safe signed
   journal persistence is impossible;
5. no operational API listener, readiness claim or provider dispatch occurs;
6. no restored lease or credential is accepted as current authority; restored
   rows are inert data until a separately accepted activation invalidates and
   replaces them with a fresh epoch;
7. the source database is not accessed for restoration; only the authenticated
   artifact is read;
8. no external VM, storage, network or provider resource is mutated;
9. exact artifact, release, schema, migration and canonical inventory
   verification passes before and after mutation;
10. D10 isolated PostgreSQL executable-definition and TOC validation passes
    before target SQL;
11. every irreversible target mutation is preceded by durable signed intent;
    and
12. failure ends in explicit verified cleanup or quarantine, never a blind
    destructive retry.

The mutations this branch may perform are limited to: creating and owning the
reserved fresh target database; restoring schema, data, files and metadata into
that target; writing the protected journal, staging and verification records;
and verified cleanup or quarantine. It must not start a controller, open an
operational API or listener, acquire or serve a lease, dispatch providers or
reconcile Operations, read the source database, mutate external VM/storage/
network/provider state, or write any activation phase or signed `STARTED`
record.

A journal phase label alone is never an adequate startup guard. Every
store-opening path — `o3kd`, ordinary systemd start, host-local CLI startup or
maintenance commands, upgrade/rollback, and any direct store opener — must take
the same lifetime exclusive guard and authenticate the journal before opening
the store. Operational/controller opening is denied unless the chain is the
activation branch with a valid signed `STARTED` record and a fresh fence. Any
inactive-branch chain, including `INACTIVE_VERIFIED`, denies operational open.
A missing marker, free lock or old phase label never permits startup. Read-only
diagnostics, if any, must use a separately bounded path that cannot serve the
API, acquire leases or dispatch providers.

#### 7.1.5 Crash and resume classification

| Failure point | Required classification and resume behavior |
|---|---|
| before the first signed request | `PREFLIGHTED`; retry idempotent preflight or `ABORTED`; target untouched |
| during signing-response delivery | prior state with pending intent; retry the exact persisted request and nonce only |
| during target reservation | `PREFLIGHTED` or `TARGET_RESERVED_INACTIVE`; revalidate identities; redo only if the target is still exactly empty, otherwise `QUARANTINED` |
| during artifact decryption or staging | `STAGING_INACTIVE`; remove disposable staging; target untouched |
| before the first target mutation | `TARGET_RESERVED_INACTIVE` / `STAGING_INACTIVE`; observe this exact target and verify emptiness before continuing |
| during `pg_restore` | known partial target mutation -> `FAILED_RECOVERABLE`; unknown outcome -> `QUARANTINED`; never blind-retry |
| after database mutation, before journal acknowledgement | observe and verify; record `DATABASE_RESTORED_INACTIVE` only on proven exact completion, otherwise `FAILED_RECOVERABLE` or `QUARANTINED` |
| during file or metadata restoration | `FAILED_RECOVERABLE` for known partial state; `QUARANTINED` for unknown or conflicting state |
| during journal file fsync, rename or directory fsync | authenticate the last durable chain; a valid new record resumes from it; an absent or unauthenticated record preserves prior state and requires observation |
| resume after `SIGKILL` | reacquire the reservation, revalidate target/journal identities, observe target state, and repeat only idempotent steps |
| conflicting artifact or operation identity | `ReplayOrFork`; `QUARANTINED`; no mutation |
| concurrent restore attempt | reservation busy; reject without mutation |
| systemd or controller restart | deny operational store open while any inactive chain exists |
| replayed or invalid fencing evidence | reject; the inactive branch neither needs nor accepts it as an activation authority |
| attempted `INACTIVE_VERIFIED` -> `STARTED` or any activation phase | `InvalidTransition`; no state change and no dispatch |

#### 7.1.6 Activation boundary and non-promotion rule

A target left at `INACTIVE_VERIFIED` has no controller authority. Future
activation requires a separately accepted procedure with independently proven
source fencing, D3 issuer replacement and old-credential rejection, D4
exclusive store access, fresh target ownership epoch, target-only PostgreSQL
writer access, and a fresh signed activation chain. It must revalidate the
artifact, target and verification evidence and must invalidate all restored
leases and credentials.

There is no `INACTIVE_VERIFIED -> STARTED` transition. A phase label, journal
edit, re-signing of an edited chain, or re-use of an inactive operation's
nonce does not promote a target. Promotion must be a new operation under the
separately accepted activation procedure, or a verified discard and recreation
followed by that procedure. The inactive chain is evidence of materialization
only and may never be cited as fencing, activation or recovery-completion
evidence.

#### 7.1.7 Deployment-profile decision table

| Profile | Backend | Deployment | Inactive materialization | Fenced activation | Notes |
|---|---|---|---|---|---|
| `o3k-small-edge-v1` | PostgreSQL 16 | physical | not permitted by A10 | accepted D7 path when configured | physical profiles continue to use the fenced sequence; a separate amendment would be required for physical inactive materialization |
| `o3k-small-edge-v1` | PostgreSQL 16 | virtualized | permitted to `INACTIVE_VERIFIED` only when signed policy selects it | disabled by default; requires a separately accepted independent fence | this amendment |
| `o3k-small-edge-v1` | PostgreSQL 16 | virtualized, policy not selected | not permitted | disabled | backup/verification only |
| `o3k-demo-v1` / TestLab | SQLite | any | not permitted | backup/verification only | separate future profile amendment required |

#### 7.1.8 Why materialization does not require source fencing

Inactive materialization writes only to an isolated target that has no
controller process, listener, lease, provider dispatch or external-resource
mutation. No unfenced second controller can become active, so the safety
property is “the target cannot act”, not “the source cannot act”. Source
access is not used, and the restored database is inert data.

Source fencing remains mandatory for activation because an activated
controller with restored identity could write to the same external resources
as a surviving source controller, reconcile operations, accept credentials, or
dispatch providers. A point-in-time power-off observation is insufficient for
that lasting exclusion. D7 plus D3/D4 is the accepted authority for the
activation boundary, and this amendment does not weaken it.

#### 7.1.9 Backward compatibility and installed releases

Existing `o3k-restore-journal-v1` chains remain readable under the accepted
activation contract. An inactive-branch operation uses the new journal and
signing-request format from its first record; a `v1` chain may not later select
the inactive branch and is never converted, rewritten or downgraded. The
branch is chosen once, at journal creation and no later than the
`PREFLIGHTED` record, within that operation's format version. Older binaries
and installed releases that predate the exact acceptance must reject the new
format, phase or branch field and must not perform inactive materialization. A
target carrying an inactive chain is not reusable by an activation operation
without the accepted discard/recreate or promotion procedure. A release may
implement the inactive branch only when its signed install policy and journal
format are both version-bound to the accepted amendment.

#### 7.1.10 Residual risks

- Restored control-plane data may contain credentials, keys, tokens or lease
  rows at rest. Inactive materialization gives them no runtime authority, but
  it does not remove the confidentiality exposure.
- A target-root attacker can alter the database or journal; signatures attest
  journal bytes, not database integrity against target root.
- An operator could run restored binaries directly. Ownership, absence of an
  operational listener, the startup guard, D3 re-enrollment and the separately
  accepted activation procedure reduce but do not fully sandbox this risk.
- Restored Operations, leases and credentials may be stale; a later activation
  must invalidate them before serving.
- Disk exhaustion and denial of service remain bounded-resource concerns.
- Human relabeling or misclassification is mitigated by typed branches, signed
  branch binding and an explicit transition allowlist, but review is still
  required.

#### 7.1.11 Acceptance gate

The owner-directed A10 decision is recorded at
[issue comment 6423776117](https://github.com/o3kio/o3k/issues/1086#issuecomment-6423776117)
for PR #1176 reviewed head `b69b6b9b8abe913f1da4639cadb6df29509d4cde`,
integrated as `ca8fe3033ace09cf7b7a43286522dbd3e6ad326a`, with matching ADR-0189
and PP6 technical-contract records. It authorizes implementation and testing
of this branch. It does not certify implementation, installed recovery,
production readiness, independent security qualification, source takeover, or
controller activation. All D7/D3/D4/D8 activation gates remain mandatory.

### 7.2 Accepted amendment C1: durable recovery designation and installed journal trust

Accepted for implementation/testing by owner decision [6423774720](https://github.com/o3kio/o3k/issues/1086#issuecomment-6423774720), reviewing PR #1179 head `0c0dfd4374cf0b972e2a8769ad4f9f38cea793a0`, merged as `ea4f705efba72421f368903be71a0e792851813f`. The interim reviewer was explicitly non-independent. C1 does not by itself authorize A10 or restore mutation, and does not certify runtime, installed, production, or final PP.6 evidence.

#### 7.2.1 Installation-bound designation

The packaged installation identity is an RFC 8785 canonical Ed25519-signed
`o3k-installation-policy-v1` document. Its signed payload contains stable
`installation_id`, `site_id`, profile, backend, exact release identity,
canonical data-root path, target device/inode, monotonic policy revision and
prior-policy digest, fixed policy path, trust-bundle path and digest,
recovery-state root path and device/inode, D8 journal-directory path and
device/inode, and installation-policy signer key ID. The signature
envelope names the algorithm and signer key ID and covers the canonical payload
excluding the envelope; duplicate, unknown, or non-canonical fields are
rejected. The policy is signed by the installation-policy authority whose
public key and allowed policy format are authenticated by the release-signed
release manifest. The policy also binds the journal/evidence trust-root public
keys and IDs. Its signing key is not used
for artifact, recovery-decryption, journal, evidence, or release signing.
At startup the policy is verified against the installed release manifest and
cross-checked against canonical O3K identity tokens and the target
data-directory device/inode. Policy revisions are monotonic, name the prior
revision digest, and are rejected on rollback, equivocation, or an unexpected
installation identity; the installed high-water revision is durable. The
release manifest identifies the fixed installed policy path so startup can
discover the policy without consulting recovery configuration or a mutable
installation prefix. The identity is not derived from
`restore.json`, a display name, or the installation prefix. A prefix change
does not move the recovery state or change the identity. Rebinding a data
directory or replacing an installation identity requires an explicit,
authenticated installer operation, a new signed installation-policy revision
linked to the previous policy digest, and explicit preservation or migration
of recovery state; path replacement alone never rebinds it. Rotation of the
policy-signing key requires a release-signed manifest that authenticates the
new key and format plus a monotonic next policy revision linked to the prior
policy digest. It cannot change `installation_id`, site, or target identity
without the separately authenticated rebind operation.

Every supported installation has a protected recovery-state record, including
one that has never entered recovery. The record is an RFC 8785 canonical
Ed25519-signed `o3k-installation-state-v1` document with `installation_id`,
`site_id`, profile, backend, policy revision and digest, target device/inode,
monotonic sequence, prior-record digest, state, and a signature envelope
naming the algorithm and signer key ID. Sequence zero is the
installation-policy-authority-signed `NEVER_RECOVERED` record, bound by the
signed policy. Every later state record is signed by the offline journal
authority under the exact installed journal purpose and scope; it binds the
prior record digest and is accepted only after signature, revocation, identity,
and anti-rollback checks. Equal sequence is idempotent only for the same
record digest. Missing or conflicting record state never reconstructs sequence
zero from the policy alone.

Before the first restore
mutation, the authorized recovery operator must durably transition it to
`RECOVERY_DESIGNATED`, binding the installation identity, target device/inode,
operation ID, artifact digest,
recovery-directory identity, and journal trust-bundle digest. The transition
is written as a new same-directory file, file-fsynced, atomically renamed,
followed by directory fsync, read back, and authenticated before any target
mutation. A failed or uncertain designation write prohibits restore execution
until an authenticated read determines the durable state. If the verified
prior `NEVER_RECOVERED` record remains and no target mutation occurred, ordinary
startup may proceed; any missing, ambiguous, or conflicting record denies
startup. A restore process must never infer designation success from a lost
write acknowledgement.

In the packaged Linux layout, the designation and anti-rollback high-water
state live at `/var/lib/o3k-recovery-state/<installation_id>/`, a separate
root-owned, `o3k`-group-readable directory (mode `0750`) with state files owned
by `root:o3k` (mode `0640`) on verified local ext4. It is outside both the
target data directory and installation prefix, and is not writable by the
`o3k` service identity. File creation uses no-follow and exclusive-create
semantics; before use, the directory and files have their owner, mode, device,
and inode rechecked. Atomic replacements use a new same-directory file, file
fsync, rename, and directory fsync. The D8 journal remains at
`/var/lib/o3k-recovery/<installation_id>/`: a pre-provisioned `o3k:o3k`
directory (mode `0700`) on verified local ext4, with journal, pending-request,
marker, and lock files mode `0600`. File creation is no-follow and exclusive;
owner, mode, device, and inode are rechecked before use, and journal
replacements follow the accepted D8 fsync/rename sequence. The signed
installation policy binds both paths; the signed designation and journal bind
the D8 directory identity. An alternate recovery-state root must meet the same
root ownership, group readability, exact modes, filesystem, no-follow,
exclusive-create, and owner/device/inode revalidation controls above. An
alternate journal directory must meet the exact D8 ownership, mode, filesystem,
no-follow/exclusive-create, owner/device/inode revalidation, and separation
controls. Filesystem write access alone does not authorize a designation or
quarantine transition; the signatures and actor restrictions below remain
mandatory. The root-authorized installer provisions both directories before
systemd can start `o3kd`.

The installed journal trust bundle lives at `/etc/o3k/recovery-trust.json` and
is root-owned, service-readable, and not service-writable. Its path and digest
are bound by the signed installation policy; an alternate path must satisfy
the same trust-bundle ownership, readability, no-follow, owner/mode/device/inode
revalidation, and separation checks. The release-signed release manifest
authenticates the installation-policy verification key; the signed
installation policy binds the trust roots, trust-bundle path and digest, and
recovery-state root. `restore.json` may supply validated operator parameters
but cannot designate, release, or clear
recovery state. Startup discovers the protected record from the authenticated
installation policy and stable state root before reading optional recovery
configuration, opening canonical state, creating a controller session, or
binding an API listener.

Missing, unreadable, malformed, replaced, stale, expired, or conflicting
installation policy, state record, target, or installation identity denies
startup. An installation that has never entered recovery starts only when its
authenticated `NEVER_RECOVERED` record verifies; it has no recovery-journal or
installed journal-trust dependency. A designated or previously recovered
installation also requires its current installed journal trust, revocation
state, and journal to verify. During recovery, only the authenticated journal
chain and designation can
describe progress; a journal phase label or unsigned marker cannot grant
startup. All store-opening maintenance commands apply the same check. The
lifetime store-access lock remains held from before the check through process
shutdown.

For an installation upgraded from a release that lacks this record, an
installer migration runs before systemd can start `o3kd`. It may initialize
`NEVER_RECOVERED` only after the installation identity and release verify and
legacy recovery configuration, directories, journals, and markers establish
that recovery was never entered. Any existing or ambiguous recovery state is
migrated to denial/quarantine and requires an authenticated recovery
disposition; the migration never infers `NEVER_RECOVERED` from missing
`restore.json` alone. New installations receive the initial state during
installation.

Only the root-authorized installer, acting with the installation-policy
authority, may initialize or rebind the stable installation policy. The
policy signature authenticates the initial `NEVER_RECOVERED` state, while the
release-signed release manifest authenticates the policy verification key. An
OS-authorized recovery operator may request a
designation transition, but every transition into or out of quarantine must
be signed by the offline journal authority and bind the exact prior record
digest and next sequence. `o3kd` and ordinary maintenance commands are
read-only consumers of designation state. A recovery may be released only by
a distinct signed `RELEASED` disposition after the exact operation reaches an
accepted terminal state, the target identity is rechecked, and the required
verification evidence is authenticated. The disposition binds the terminal
journal hash and evidence digest; it is atomically persisted and anti-rollback
checked before startup may proceed. A missing journal, missing designation,
unsigned marker removal, or operator-edited file cannot release quarantine.

#### 7.2.2 Privileged-target threat model and external anchor

Root-owned local files, filesystem permissions, signatures, and fsync ordering
protect against unprivileged users and service processes that lack write
access to the installation policy, recovery state, systemd unit, binaries, and
target. They do not protect against an attacker with privileged target-root
authority who can replace all trusted local state, roll back local files, or
run a modified controller binary. No claim may say otherwise.

For the current packaged `o3k-small-edge-v1` profile, a privileged target-root
attacker is outside the recovery security claim unless the deployment has the
qualified independent anchor below. Documentation and evidence must state
which posture applies; root-owned local state alone is not root-attacker
protection.

If defense against a privileged target-root attacker is required, the
installation must use an independently trusted, rollback-resistant anchor
outside that root's replacement authority (for example, a qualified TPM
monotonic state plus measured boot, or an independently administered remote
startup verifier). That anchor must bind the installation identity and the
highest designation/trust sequence and digest, deny startup on rollback or
anchor unavailability, and be independently qualified for the deployment.
Without such an anchor, this threat is explicitly out of scope and recovery
state is not protected from target root.

#### 7.2.3 Installed journal and evidence trust

The offline recovery trust root is separate from artifact-signing,
recovery-decryption, journal-signing, evidence-signing, and release-signing
keys. Each key has one purpose and distinct key ID. Private offline keys are
never provisioned to or loaded into `o3kd`, the restore target, or the online
artifact signer.

An installed trust bundle (`o3k-recovery-trust-v1`) contains distinct offline
journal and evidence trust roots, exact site and profile scope, their initial
signed revocation documents, and the highest accepted sequence and canonical
digest for each root. Its digest is authenticated by the installation policy.
Journal signer certificates
(`o3k-journal-authority-v1`) and evidence signer certificates
(`o3k-evidence-authority-v1`) are distinct RFC 8785 canonical Ed25519
documents containing `key_id`, public key, exact purpose (`restore_journal`
or `recovery_evidence`), exact site, installation, profile and backend,
serial, `not_before`, `not_after`, and issuer. A key or certificate with
unknown purpose, scope, issuer, or identity is rejected. Each certificate is
signed by its corresponding offline trust root over the RFC 8785 canonical
certificate payload. The signature envelope identifies the signature
algorithm and signer key ID; the verifier rejects duplicate or unknown fields
and non-canonical payloads. Certificate signature and scope are verified
before installing the certificate.

The offline trust root signs each RFC 8785 canonical Ed25519 revocation
document (`o3k-recovery-revocations-v1`) containing exact site and profile
scope, monotonic `sequence`, `issued_at`, `next_update`, and revoked certificate
serials and key IDs. Its SHA-256 digest covers the complete canonical signed
document. The installed verifier authenticates the signature, scope, validity,
and freshness, then durably records the highest sequence and digest before
using the document. Equal
sequence is idempotent only for an identical digest; lower sequence,
same-sequence equivocation, expired freshness, unavailable required trust
state, or clock rollback/unavailability fails closed. A cached document is
usable only through `next_update`. The installation's rollback-resistant
anchor, when required by §7.2.2, also protects the trust sequence and digest.
The journal and evidence signer certificates are valid for at most 90 days;
revocation state is refreshed at least every 24 hours. The verifier obtains
updates from a trust-distribution endpoint administered separately from the
artifact signer. A new signer is installed and verified before rotation; old
and new signers overlap for at most 30 days. Journal/evidence signer compromise
recovery uses an offline-root-signed revocation and increments the protected
sequence. Trust-root rotation or recovery uses a new monotonic installation-
policy revision, signed by the separate installation-policy authority, bound
to the authenticated release manifest, and linked to the prior policy digest;
it installs the replacement trust-bundle digest before the old root is retired.
If the installation-policy authority is compromised, local trust recovery is
not permitted; the installation must be re-provisioned through an independently
authorized release path.

Before a journal transition can authorize a state change or startup decision,
the verifier authenticates every journal signature against the installed
purpose- and scope-bound signer certificate and current signed revocation
state. Unknown, expired, or revoked authority never authorizes a transition;
ambiguity quarantines the installation. Trust rotation installs a new
root-authenticated bundle and validates its sequence before switching signers.
Compromise recovery requires an offline-root-signed revocation and an
authenticated, anti-rollback trust recovery disposition; local operator edits
or online artifact-signing keys cannot repair trust. The previous trust state
is preserved as evidence.

These protocol fields and provisioning behavior were explicitly accepted by
the owner-directed C1 decision at
[issue comment 6423774720](https://github.com/o3kio/o3k/issues/1086#issuecomment-6423774720),
for PR #1179 reviewed head `0c0dfd4374cf0b972e2a8769ad4f9f38cea793a0`,
integrated as `ea4f705efba72421f368903be71a0e792851813f`, with matching ADR-0189
and PP6 technical-contract records. This acceptance authorizes implementation
and testing, not implementation correctness, installed recovery, production
readiness, or independent security qualification. Implementations must not
infer trust from the artifact `backup_trust` document or caller-supplied
revocation lists. C1 does not authorize post-`PREFLIGHTED` journal phases;
those require the separately accepted A10/journal-v2 branch. Journal v1 remains
limited to its accepted `PREFLIGHTED` behavior.

### 7.3 Accepted amendment C1.1: authenticated installation-policy/trust re-anchor and journal checkpoint

Accepted for implementation/testing on 2026-10-27 by owner decision
[6440284521](https://github.com/o3kio/o3k/issues/1086#issuecomment-6440284521),
reviewing PR #1187 head `df52e28471fee99b09807135a3823c6f8bd5326e`, merged as
`4d9d5108f4995b270144c3b29ad54704a62e61c8`. This is owner-directed,
non-independent architecture/technical acceptance under ADR-0190, not runtime,
installed, production, or independent-security qualification. C1.1 changes no
accepted C1 or A10 technical parameter; it adds the rotation/recovery mechanism
for the trust that C1 installs.

#### 7.3.1 Conflict analysis and option comparison

Accepted C1 (§7.2.3) requires the verifier to authenticate journal signatures
against the installed purpose- and scope-bound signer certificate and current
signed revocation state, and limits old/new signer overlap to at most 30 days.
After a journal/evidence trust root retires, historical state and journal
records can no longer be re-verified under current trust unless retired
material is retained. Two options resolve this conflict:

- Option B — historical policy-chain verification: retain every retired root,
  certificate, and revocation document in the live trust bundle so all
  historical signatures keep verifying. This keeps retired roots in the live
  TCB, requires unbounded retention and expiry exceptions, and still needs a
  sealing re-anchor to bound the retained chain.
- Option A — explicit re-anchor: one installation-policy-authority-signed
  re-anchor record and one journal checkpoint carry the authenticated
  old-era tips forward; older signatures become audit-only material.

Option A is selected: it is smaller and safer (a bounded live TCB, no
retention or expiry exceptions, and the sealing re-anchor is the mechanism
itself). The rest of this subsection specifies Option A.

#### 7.3.2 New signed formats

The frozen v1 formats (`o3k-installation-policy-v1`,
`o3k-installation-state-v1`, `o3k-recovery-trust-v1`,
`o3k-journal-authority-v1`, `o3k-evidence-authority-v1`,
`o3k-recovery-revocations-v1`), journal v1, and the accepted A10 journal-v2
formats are unchanged. C1.1 adds three RFC 8785 canonical Ed25519 formats:

- `o3k-installation-reanchor-v1` — the re-anchor record R (§7.3.3);
- `o3k-restore-journal-checkpoint-v1` — the journal checkpoint C (§7.3.4);
- `o3k-recovery-revalidation-v1` — compromise-recovery revalidation evidence
  (§7.3.6), used only for compromise rotation.

All three use strict signature envelopes naming the algorithm and signer key
ID over the canonical payload excluding the envelope; unknown, duplicate, or
non-canonical fields and payloads are rejected, and every referenced digest is
the exact SHA-256 of the referenced canonical byte encoding.

#### 7.3.3 Re-anchor record R

R is a distinct record kind in the **same** `o3k-installation-state-v1`
sequence chain: it occupies the next state sequence number. It is not an
`o3k-installation-state-v1` disposition and not a journal phase transition,
and it changes no state value. It amends §7.2.1's uniformity rule that every
later state record is journal-authority-signed **only** by distinguishing
disposition records (still signed only by the offline journal authority) from
the new re-anchor kind. R is signed only by the release-manifest-authenticated
installation-policy authority; the journal authority never signs R.

The signed payload contains:

- `installation_id`, `site_id`, profile, and backend;
- `preserved_state` — the exact current state value, carried unchanged;
- `sequence` — exactly prior state sequence + 1;
- `prior_record_digest` — digest of the prior state tip;
- `prior_policy_revision` and `prior_policy_digest`, and
  `new_policy_revision` and `new_policy_digest`;
- `prior_trust_bundle_digest` and `new_trust_bundle_digest`;
- prior and new per-purpose (`restore_journal`, `recovery_evidence`)
  revocation high-waters, each binding root ID, sequence, and document digest;
- `checkpoint_digest` — digest of C; null only when `preserved_state` is
  `NEVER_RECOVERED`;
- `recovery_revalidation_digest` — null for routine rotation, required for
  compromise rotation;
- for preserved `RECOVERY_DESIGNATED`: operation ID, artifact digest, and
  recovery-directory identity; for preserved `RELEASED`: operation ID,
  artifact digest, recovery-directory identity, terminal journal hash, and
  terminal evidence digest;
- target device/inode;
- `signer_manifest_digest` — digest of the release-signed release manifest
  authenticating the R signing key.

The new policy revision must prior-link the old policy digest and preserve
installation, site, and target identity; rotation never rebinds them. Replay
with the same sequence and the same digest is idempotent; the same sequence
with a different digest is equivocation and is rejected, as is any lower or
stale sequence.

#### 7.3.4 Journal checkpoint C

C is signed by the **new** offline journal authority under the **new** current
trust. C1.1 authorizes checkpoints for journal v1 only; checkpointing an
accepted A10 journal-v2 chain is not designed here and requires separate
acceptance. C is not a phase and performs no phase transition. It occupies the
next journal sequence, with `prior_record_digest` equal to the old journal
tip, and binds:

- the prior checkpoint digest, when any prior checkpoint exists;
- the prior state tip S0 — the state record before R, **not** R itself, so C
  never forms a circle with R;
- the old journal tip;
- the journal directory path, device, and inode;
- operation ID and artifact digest;
- the unchanged phase;
- old and new journal certificate key IDs and serials;
- old and new per-purpose revocation high-waters;
- `rotation_reason` — exactly `routine` or `compromise`;
- the revalidation evidence digest, when `rotation_reason` is `compromise`.

R binds `digest(C)`; C never binds `digest(R)`. The immutable C is published
before R (§7.3.9); C alone grants no authority. All later journal records
chain after C. After R+C are durably published, older state and journal
signatures are audit-only: their authenticity is carried by the authenticated
state tip R and journal tip C, while current-era records continue to verify
individually under current trust. During the accepted at-most-30-day signer
overlap, the old era is cross-checked directly where possible; retired old
signers grant no new authorization after retirement. This bounded attestation
replaces historical per-signature verification under current trust and is an
explicit human security decision (§7.3.11).

#### 7.3.5 Requirements by preserved state

The C1 installation-state lifecycle remains exactly `NEVER_RECOVERED`,
`RECOVERY_DESIGNATED`, and `RELEASED`; C1.1 adds no state value and no
`QUARANTINED` installation state.

- `NEVER_RECOVERED`: R only, signed by the installation-policy authority; no
  journal dependency and no checkpoint (`checkpoint_digest` null).
- `RECOVERY_DESIGNATED` and `RELEASED`: R and C are both required, with C
  published first.

The preserved disposition, operation, artifact, target, recovery-directory
identity, and RELEASED terminal evidence are preserved exactly; R and C add
no state or phase change. No new `NEVER_RECOVERED` or `RELEASED`
self-transition is introduced. Rotation during quarantine preserves the
applicable one of the three state values unchanged, and preserves all
journal quarantine phases and unsigned denial markers byte-for-byte; removing
a marker still requires the accepted signed disposition that authorizes its
removal. An ambiguous migrated state without an authenticated old generation
cannot rotate: it must first receive an authenticated disposition under the
accepted C1 rules.

Pre-C1.1 verifiers reject unknown R and C records and deny startup. Rotation
is performed only after every verifier that reads the installation supports
C1.1, including an R-only rotation for a `NEVER_RECOVERED` installation.

#### 7.3.6 Routine rotation and compromise recovery

Routine rotation requires the outgoing trust to be fully verified at
quiescence: every required old-era signature verifies, and the outgoing
signer certificates are fresh and unrevoked under the current signed
revocation state. Compromise rotation starts with an offline-root-signed
revocation document and protected high-water sequence increase, and the
installation stays quarantined throughout. Compromise rotation then revokes
the old root by a revocation document signed by the **new** trust root, which
the new installation policy authenticates. Revocation blocks new
authorization by the old root from that point forward and does not
retroactively rewrite durable history; after R+C, old-era authenticity is
carried only by a routine C or by a compromise C plus its revalidation
evidence. All accepted fail-closed revocation behavior is preserved.

A C with `rotation_reason` = `compromise` requires an
`o3k-recovery-revalidation-v1` document signed by the **new**
recovery-evidence authority. The evidence carries a unique 256-bit nonce and
an accepted 300-second validity window from `issued_at` (`expires_at` =
`issued_at` + 300 seconds), and clock rollback or clock unavailability at
verification denies.
It binds: `installation_id`, `site_id`, profile, and backend; operation ID,
artifact digest, and target identity; old and new trust root IDs and
certificate key IDs/serials; the exact prior state, journal, and checkpoint
tips; old and new policy digests and trust bundle digests; the observed
target identity; `custody_record_digest` and a 2-of-3
`recovery_quorum_event_id`; `issued_at`/`expires_at`; and an explicit
statement that the exact tips were reviewed. To avoid circular digest
bindings, the evidence names only the prior tips it reviewed, while R and C
name the evidence digest; neither R nor C appears inside the evidence
payload.

The evidence authorizes exactly one R/C pair. Before that pair is accepted, a
durable consumption record is written binding the evidence digest, the exact
R digest, and the exact C digest; a byte-identical resume of that same pair
is allowed, and any second or different use is rejected. The evidence is
marked consumed only after the full authenticated publication of §7.3.9
completes; a crash before that point allows exact retry only. Missing, stale,
wrong-scope, or insufficient-custody evidence fails closed.

Revalidation never authorizes a phase change, `RELEASED`, or activation. If
prior `RELEASED` terminal evidence cannot be authenticated, rotation cannot
make startup succeed. Compromise of the installation-policy authority itself
still requires independent release-path re-provisioning; no local repair is
permitted.

#### 7.3.7 Revocation high-waters and trust freshness

Revocation high-waters are monotonic only within the same root; a root change
is bound explicitly by the old/new root IDs, sequences, and document digests
in R and C, and numeric sequences across different roots cannot be compared.
Unknown, revoked, or stale current-era signers are denied, and
revocation-distribution unavailability fails closed whenever fresh trust is
required, per the accepted C1 freshness rules.

#### 7.3.8 Quiescence and concurrency

Rotation quiesces all store openers using the existing `StoreAccessLock`
(accepted D4 lifetime exclusive lock) and requires that no unsigned or
in-flight journal signing request exists before the state and journal tips are
observed. Rotation may occur while the installation is quarantined, but it
cannot alter the quarantine disposition. `o3kd` and the service stay
read-only throughout; rotation grants no operational capability. R and C
signing requests use the accepted offline signing ceremony: each request
carries a fresh 256-bit request nonce, a retry returns the original exact
bytes only while the request remains valid, and presenting a new nonce for an
already requested record is a fork and is denied.

#### 7.3.9 Crash-safe publication and resume

Publication is ordered and crash-safe; the current checkpoint C is always
published before the current re-anchor R.

1. verify the old generation;
2. stage the immutable new policy, trust, and revocation records in the
   protected state root under distinct staged names that no published verifier
   reads;
3. persist the immutable C in the D8 journal directory;
4. persist R as an authenticated pending intent in the state root;
5. atomically publish, in order: the fixed policy file, then the policy
   high-water; the fixed trust bundle, then the trust high-water; the current
   journal tip C; and the current state record R; archiving the prior bytes;
6. re-read and authenticate the whole generation (final observation) before
   reporting success, marking any revalidation evidence consumed, or retiring
   old trust.

The policy high-water is exactly `{revision, digest}`; the trust high-water is
exactly `{bundle digest, per-root revocation sequence and digest}`. Every
step uses a same-directory temporary file, file fsync, rename, directory
fsync, and readback. A partial generation denies startup. The root installer
resumes only the exact signed R/C forward: it never infers success from a
lost acknowledgement, never performs unsigned repair, and never rolls back to
an operational old generation. Conflicting bytes or equivocation require
inspection. C without R, R without C where required, or any wrong, missing,
or mismatched policy, trust, state, or journal component fails closed. Old
trust is retired only after the full new generation is durably observed and
authenticated.

| Publication step | Crash semantics and resume rule |
|---|---|
| Staging | Staged bytes are inert: distinct staged names are never read by published verifiers. A crash restages from the signed R/C; staging alone never changes startup authority. |
| Fixed policy | After the rename, the new policy is the only current policy. A crash before its high-water re-reads the policy, verifies it against R's `new_policy_digest`, and continues forward; startup on the partial generation is denied. |
| Policy high-water | `{revision, digest}` makes the new revision durable and anti-rollback. Equal value is idempotent; any rollback or digest conflict fails closed and requires inspection. |
| Fixed trust | The new bundle is verified against R's `new_trust_bundle_digest`; a crash re-verifies and continues forward. |
| Trust high-water | `{bundle digest, per-root revocation sequence and digest}`. Equal sequence is idempotent only for the same digest; equivocation fails closed. |
| Current C | C is immutable at the journal tip and chains after the old tip. A crash re-authenticates the C bytes, chaining, and trust binding, then continues to R; byte-identical resume only. |
| Current R | R becomes the state tip only after C. A crash re-authenticates the R bytes, `sequence` = prior+1, and `checkpoint_digest`, then runs final observation. |
| Final observation | Re-reads and authenticates the whole generation. Success, revalidation-evidence consumption, and old-trust retirement happen only here; a crash repeats the exact forward observation. |

Revalidation-evidence consumption follows exact-retry semantics: if a crash
occurs before the consumption record is marked, the byte-identical R/C pair
may be resumed and re-accepted; any different bytes are a different use of
single-use evidence and are rejected.

#### 7.3.10 Filesystem controls and authority boundaries

Filesystem controls are unchanged: the state root remains `root:o3k` mode
`0750` with state files `0640`; the D8 journal directory remains `o3k:o3k`
mode `0700` with files `0600`; both stay on verified local ext4 with
canonical paths, no-follow/exclusive-create semantics, and
owner/mode/device/inode recheck; the fixed policy and trust files remain
root-owned, service-readable, and not service-writable.

Rotation alone never clears quarantine, consumes activation nonces, grants
sessions, leases, provider dispatch, an API listener, or activation, and does
not change the accepted D3, D4, D7, D8, or A10 contracts. Unsigned denial
markers are preserved byte-for-byte across rotation; removing one still
requires the accepted signed disposition that authorizes its removal.
Rotation is a root-authorized installer operation outside the accepted §8
recovery CLI; C1.1 accepts no new CLI.

#### 7.3.11 Accepted human decisions

Owner decision
[6440284521](https://github.com/o3kio/o3k/issues/1086#issuecomment-6440284521)
explicitly accepted all six choices:

1. R is signed only by the installation-policy authority.
2. C is signed by the new offline journal authority under new current trust.
3. Current-era verification plus the authenticated R/C tips replaces
   every-historical-signature verification under current trust.
4. The compromise revalidation authority, custody record, and 2-of-3
   recovery-quorum binding.
5. Quiescence rules and rotation during quarantine.
6. The 300-second revalidation-evidence validity window.

#### 7.3.12 Implementation evidence gate

The exact-revision acceptance authorizes implementation and testing only.
Implementation evidence must include these negative cases: replayed or reused
single-use revalidation evidence, including any second or different R/C pair;
equal-sequence equivocation of R or C; a crash before and after every
publication step in §7.3.9 with exact-forward resume only; unsigned denial
markers preserved byte-for-byte across rotation; a pre-C1.1 verifier rejecting
unknown R/C records and denying startup; stale, revoked, or unavailable
current trust failing closed; and rotation granting no activation. Passing
these tests does not replace the installed-candidate, real offline-signer,
supported-systemd-host, or independent-security gates.

### 7.4 Proposed amendment A10.1 — versioned signed installation policy

**Decision status: proposed; not accepted normative authority.** This narrow
contract correction resolves the mismatch between A10's required explicit
inactive-branch selection and C1's frozen `o3k-installation-policy-v1`, which
has no deployment field or A10 authorization field. The v1 schema, signature
meaning, fixed path, and current C1/C1.1 verifier behavior remain frozen.
Option A, a new signed policy format, is selected over a detached selection
extension: the release manifest can authenticate one exact policy format,
path, and signer, and one policy digest can bind the entire recovery identity.
A detached extension would create a second independently rotated authority
and a partial-publication state without reducing the required migration rules.

#### 7.4.1 `o3k-installation-policy-v2`

The new format is RFC 8785 canonical JSON in the existing strict Ed25519
envelope. Unknown, duplicate, missing, malformed, or non-canonical fields,
unknown enum values, a wrong signer, and any scope mismatch are rejected.
The payload requires every v1 identity, path, device/inode, trust-key,
revision, prior-policy-digest, and signer field, with unchanged meanings, and
adds the fields listed below. A v2 policy is only created by the explicit
v1-to-v2 migration in §7.4.2; there is no v2 genesis or direct-install
shortcut. A new installation first establishes the ordinary v1 policy and
state, then completes the same explicit migration before A10 can be selected.
Therefore `policy_revision` is at least 2 and is exactly the prior v1 policy
revision plus one. The proposed strict schema is
[`o3k-installation-policy-v2.proposed.schema.json`](../../contracts/o3k-installation-policy-v2.proposed.schema.json):

| Field | Required value and binding |
| --- | --- |
| `backend_version` | `16`; exact PostgreSQL major |
| `deployment` | `virtualized`; no default or inference |
| `restore_branch_authorization` | `inactive-materialization-only`; the only v2 value in this decision |
| `release_version` | Exact release version from the authenticated manifest |
| `source_commit` | Exact source commit from the authenticated manifest |
| `release_manifest_sha256` | SHA-256 of the exact installed, release-authenticated manifest bytes |

For this v2 authorization, `profile` is exactly `o3k-small-edge-v1`,
`backend` is exactly `postgresql`, and `release_identity` is the exact
`release_artifact_sha256` in the manifest. The policy binds the exact
installation and site IDs, target data-root device/inode, recovery-state
root device/inode, protected journal directory device/inode, trust-bundle
digest and purpose-separated public keys, and monotonic revision chain.
`signer_key_id` must equal the envelope key ID and the policy key authenticated
for v2 by the release manifest. There is no default to A10: v1, absent v2
selection, another profile/backend/deployment, unknown values, or any missing
binding denies A10 before journal access or target access.

The release-signed manifest retains its existing v1 authority fields with
their exact meaning and adds a strict `installation_policy_v2_authority`
object containing `format` (exactly `o3k-installation-policy-v2`), the fixed
policy path (`/etc/o3k/installation-policy.json`), `key_id`, and
`ed25519_public_key`. Both authority entries are part of the same
release-authenticated manifest. The v2 authority must use the existing
installation-policy purpose; this amendment creates no new trust root or
reuses the key for journal, evidence, artifact, decryption, or release
signing. A release that omits the v2 authority cannot provision v2 policy.
The authenticated installation-state chain, not the release manifest or
policy input, selects the active policy format: the initial verified
installation state selects v1, and only a fully verified
`o3k-installation-policy-migration-v1` event selects v2. A release manifest
authorizes the format-specific verifier, fixed path, and signer; it does not
change the active format. Thus a manifest containing both authority entries
does not make a v2 policy active before migration. A missing, conflicting, or
ambiguous state selector denies every consumer before listener or store access.
Installers and verifiers never select a format from policy input, mutable
configuration, or the presence of extra files.

#### 7.4.2 Format migration and compatibility

An installation with v1 policy remains operational under its supported v1
release and C1/C1.1 rules, with A10 unavailable. Migration to v2 is an
explicit root-installer operation, never an automatic upgrade side effect.
It preserves installation/site IDs, target identity, recovery state, trust
scope, protected recovery-state and journal paths/inodes, and the exact prior
policy bytes. It increments the existing policy revision by one and sets
`prior_policy_digest` to SHA-256 of those exact v1 bytes. A v2 migration
record, `o3k-installation-policy-migration-v1`, is a distinct signed event in
the existing monotonic installation-state sequence; it binds the prior and
new policy format/revision/digest, prior and new exact release-manifest
digest, prior and new exact release identity, state-chain sequence and prior
tip digest, preserved recovery state and target identity, and any required
C1.1 journal-v1 checkpoint digest. It is signed by the installation-policy
authority authenticated by the new release manifest. Both old and new policy
signatures and manifests must independently verify before migration. The
policy signer key ID and public key are held constant across this format
migration; key rotation remains a separate C1.1 operation. No migration
event changes `NEVER_RECOVERED`, `RECOVERY_DESIGNATED`, or `RELEASED`.

The migration payload has exactly these fields: `format`, `installation_id`,
`site_id`, `sequence`, `prior_record_digest`, `preserved_state`,
`prior_policy_format`, `prior_policy_revision`, `prior_policy_digest`,
`new_policy_format`, `new_policy_revision`, `new_policy_digest`,
`prior_release_manifest_sha256`, `new_release_manifest_sha256`,
`prior_release_identity`, `new_release_identity`, `target_device`,
`target_inode`, `trust_bundle_digest`, `checkpoint_digest`, and
`signer_manifest_digest`. `format` is exactly
`o3k-installation-policy-migration-v1`; `sequence` is exactly prior state
sequence + 1; `prior_record_digest` is the exact prior state tip digest;
`preserved_state` is unchanged; and `checkpoint_digest` is null only for
`NEVER_RECOVERED`. Other states require a verified C1.1 journal-v1 checkpoint
digest. All digests are lowercase SHA-256 of exact canonical signed bytes,
except release-manifest digests, which hash exact authenticated manifest
bytes. `signer_manifest_digest` equals `new_release_manifest_sha256`; the
migration event is verified with the policy signer authenticated by that new
manifest. The envelope uses the existing installation-policy signer,
algorithm, and strict canonical signature rules. The proposed migration schema is
[`o3k-installation-policy-migration-v1.proposed.schema.json`](../../contracts/o3k-installation-policy-migration-v1.proposed.schema.json).

For `NEVER_RECOVERED`, migration binds the authenticated state tip and has no
journal checkpoint. For `RECOVERY_DESIGNATED` or `RELEASED` with journal v1,
migration requires the accepted C1.1 checkpoint and preserves all existing
state, operation, artifact, quarantine, and denial-marker bindings. A
missing/ambiguous state or incomplete C1.1 generation denies migration. Any
existing journal-v2 chain, including terminal `INACTIVE_VERIFIED`, denies
policy migration and policy rotation: C1.1 does not authorize journal-v2
checkpointing. A journal-v2 chain binds the exact v2 policy digest for its
entire lifetime; recovery must finish under that digest or remain denied
until a separately accepted journal-v2 checkpoint/migration decision exists.

Policy revision and anti-rollback high-water continue across formats. The
format epoch is fixed: v1 is epoch `1` and v2 is epoch `2`; no other epoch or
format is accepted. The only allowed transition is epoch `1` to epoch `2`,
authorized by exactly one valid migration event. The migration record advances
the existing state sequence; the v2 policy revision is exactly prior revision
+ 1 and links the exact v1 policy digest. Durable high-water records the policy
format epoch, revision, and digest; once v2 is published, any v1 policy, lower
revision, equal-revision different digest,
missing migration event, or stale state tip is a downgrade/equivocation and
denies startup, maintenance, upgrade, and rollback. Publication of a partial
or mixed v1/v2 generation denies every consumer; only byte-identical
exact-forward completion of the already authenticated migration may resume.
The migration implementation must use the durable same-directory
fsync/rename/readback discipline and D8 recovery guard; this amendment does
not itself implement that publisher.

The process-held D8 `flock` coordinates live quiescence only. It is released
by the kernel when the migrator exits or the host reboots; it is not a durable
crash-denial mechanism. Crash denial is provided by the authenticated
installation-state chain and the order below. No unrecognized marker is
introduced. The migration event is the format selector and the durable
migration-start record.

The root migrator authenticates the complete v1 state, both policies and
release manifests, the exact migration event, and the v2-capable verifier.
Preparation is not migration: until D8 is acquired, no policy, high-water,
manifest, state-chain, or migration-staging bytes may be written. During
preparation, the migrator makes the installed `o3k-compute` executable
non-executable and durably reads back that mode, then stops and masks its
systemd unit. It verifies the unit is inactive and masked and that no process
with the installed executable's device/inode remains, including processes not
started by systemd. Failure of any check aborts before migration writes. This
closes new systemd and direct `execve` starts while quiescence is established;
it does not terminate an already-running process merely by changing mode. If
preparation crashes before D8 acquisition, the v1 selector and complete active
v1 policy generation are unchanged, so any process not yet stopped remains
only under ordinary v1 rules; no A10 migration has started. After verified
preparation, the migrator acquires the existing exclusive D8 guard, quiesces
listeners, controllers, workers, timers, and maintenance processes, and blocks
concurrent startup, upgrade, rollback, and maintenance while it holds the
guard. If D8 acquisition fails or the migrator crashes after verified
preparation but before selector publication, compute remains unavailable
until the exact authenticated v1 executable is restored under a verified v1
selector or the candidate replacement is completed. It writes and fsyncs new
inputs only under inactive staging names first. It must not change
the active release manifest, active policy, active policy high-water, active
verifier, or active state tip during staging. A crash in this stage releases
the flock, but the complete active v1 generation is byte-for-byte unchanged;
ordinary v1 startup remains safe and the staged migration can be retried or
removed by the authenticated v1 installer. No v2 staged file is an authority.

The first publication that changes the selected recovery format is an atomic
replacement of the existing `state.json` tip with the fully signed
`o3k-installation-policy-migration-v1` event. The migrator fsyncs the new file,
renames it in the protected state directory, fsyncs that directory, and reads
back and authenticates the exact event before changing any remaining active
recovery-generation file.
Until that directory fsync/readback succeeds, it performs no subsequent
recovery-generation publication. Before this selector publication, supported
executable files are replaced from the already authenticated exact release
candidate, one path at a time, using atomic same-directory replacement,
directory fsync, and digest/readback verification against that candidate.
The disabled compute path is atomically replaced with and verified against the
candidate binary before execute permission is restored; the service remains
masked until the candidate and its read-only selector gate are verified. If
the migrator crashes in this interval, compute remains unavailable and cannot
run the old ungated binary. Before selector publication, exact-forward resume
may finish the replacement, or restore the exact authenticated old binary
only after verifying the selector still selects v1. After selector
publication, that restoration is forbidden. The active release manifest,
policy, policy high-water and state tip remain v1 throughout executable
replacement. Every crash during that
replacement is therefore still governed by the unchanged v1 selector. A
crash before the selector rename leaves the old v1 state tip; a crash between
rename and
directory fsync can recover only the old tip or the complete new tip. In the
former case, the active v1 policy, high-water and release manifest remain
unchanged, and the installed executables are the authenticated dual-verifier
candidate. In the latter case, the selector is durable and migration has
started. There is no crash
image in which a v2 active policy or manifest exists with only the old v1
selector.

Once the migration event is durable, an old v1 `o3kd` or `o3k` verifier
rejects its unknown state-event format before canonical-store open. The
existing `o3k-compute` binary has no such verifier and cannot be relied upon
to reject the event; it must have been replaced at every supported installed
path before selector publication. Every v2 verifier selects v2 but must deny
unless the active v2 policy, exact new manifest, policy high-water,
state-chain digest/revision, and all installation bindings are present and
mutually authenticated. A v2 verifier may never fall back to v1 when it sees
the migration event. Thus the event itself is the durable
startup/maintenance/upgrade/rollback denial across migrator crash and reboot
for the required dual-verifier installed generation; the process-held flock
is not claimed to survive either.

Before publishing the selector, the migrator authenticates the exact release
candidate and each executable digest, then installs and verifies a v2-capable
verifier at every supported installed executable entry point:
`o3kd`, `o3k`, `o3k-compute`, maintenance commands, upgrade, and rollback.
These executables must continue to accept the unchanged v1 generation while
the selector still selects v1, and must reject an incomplete v2 generation
before any canonical-store open, listener readiness, lease acquisition,
reconciliation, cleanup, domain restoration, or provider dispatch once the
selector selects v2. In particular, the compute service is an independent
systemd unit; its startup cleanup and domain-restoration work are provider-side
effects and must run behind this same durable selector gate. Stopping it only
while the migrator holds flock is insufficient because systemd can restart it
after a crash.

The current `o3k-compute` service identity cannot read the installed C1
recovery state. The installed configuration must give the compute verifier
read-only access to the authenticated selector and verification inputs, or
provide an equivalently trusted in-process read path. It must not grant the
compute identity write access to recovery state, policy, trust, or journal
files. A systemd `ExecStartPre` check alone is insufficient because direct
execution of the installed binary must enforce the same gate.

The compute process must also remain quiescent while the migrator holds the
live D8 guard, including when systemd restarts it while v1 remains selected.
Before an authenticated control-plane session is established, it must defer
all provider-side effects, including startup cleanup and artifact pruning,
DHCP/network reconciliation, domain restoration, provider readiness and
command dispatch. The session is admissible only from an
`o3kd` instance that acquired the same D8 guard and passed its installed
selector and policy checks before accepting agents. During migration the
guard prevents that `o3kd` from starting; after a crash, a v1-selected
installation may resume only after a compliant `o3kd` obtains the guard, and
a v2-selected incomplete installation remains denied. Direct execution of
`o3k-compute` must enforce the same defer-and-deny behavior. Tests must prove
the read-only access boundary, absence of provider-side effects during live
migration, and denial before such effects after durable v2 selection.

If any supported path still contains a v1-only executable, the migrator must
not publish the selector. A crash while executable replacement is incomplete
leaves the active v1 generation unchanged; both old and new executables may
then operate only under v1 rules. After all installed paths are verified as
v2-capable, the migrator atomically publishes the v2 policy, policy
high-water, and new release manifest from the byte-identical staged inputs,
with file fsync, same-directory rename, directory fsync, authenticated
readback, and exact binding checks at each boundary. The migration event is
then the durable denial for every newly installed verifier, including the
compute service. While any required byte or verifier is absent or mixed, the
v2 verifier fails before the side effects listed above. Only after the
complete coherent generation and every boot, systemd, CLI operational,
maintenance, upgrade, rollback, and provider entry point have been read back
and shown to use the v2 verifier may the migrator release the D8 guard.
Systemd may restart a service after a crash; the verifier gate, rather than
systemd ordering or the flock, must deny unsafe startup.

After the migration event is durable, the only installer action permitted is
byte-identical exact-forward completion from the authenticated staged inputs
bound by that event. Missing, changed, unauthenticated, or conflicting input
leaves the installation denied and requires bounded operator recovery under
D8. The installer, upgrade CLI, rollback CLI, maintenance entry points, and
systemd startup must reject partial repair, old-verifier rollback, release
identity downgrade, and any rewrite of the authenticated event. Before the
event is durable, no migration has been selected and ordinary supported v1
operation/rollback rules continue to apply. This distinction is part of the
contract and is covered by the crash vectors below.

The crash outcomes are normative. “v1-only executable” means a protected
C1/C1.1 executable that cannot read the migration selector; “dual verifier”
means the future v2-capable executable required by this amendment, which
continues to accept the unchanged v1 generation until selection. The current
protected `o3kd`, `o3k`, and `o3k-compute` executables implement only v1
behavior, and `o3k-compute` does not currently read the installed recovery
state before startup cleanup or domain restoration. “Open” means canonical
store access. “Ready/dispatch” includes API readiness, lease acquisition,
compute-agent readiness, reconciliation, cleanup, domain restoration, or
provider dispatch.

| Crash boundary | Exact durable active bytes after recovery | v1 verifier | v2 verifier | Store open / ready / dispatch | Exact-forward installer | Rollback / repair / downgrade |
| --- | --- | --- | --- | --- | --- | --- |
| Before quiescence | Original v1 manifest, policy, high-water, state tip, binaries; no migration staging | May start under v1 rules | If installed, must select v1 and may start under v1 rules | Allowed under v1 rules | May prepare | Existing supported v1 rules |
| After quiescence, before staging | Same original v1 active generation | May start after flock release; v1 is unchanged | Selects v1; may start under v1 rules | Allowed under v1 rules | May prepare | Existing supported v1 rules |
| During inactive file writes, before staged file fsync | Same active v1 generation; staged temp bytes may be absent, truncated, or untrusted | May start v1; ignores inactive staging paths | Selects v1; ignores inactive staging paths | Allowed under v1 rules | Must revalidate/recreate all staging inputs | Existing supported v1 rules; staging cannot be authority |
| After staged file fsync/rename into inactive staging directory, before active selector | Same active v1 generation; exact staged signed inputs may exist | May start v1 | Selects v1; staged inputs do not select a format | Allowed under v1 rules | May authenticate and retry migration | Existing supported v1 rules; cannot consume staged v2 state as active |
| Preparation before D8 acquisition | Original v1 manifest, policy, high-water and state tip; no migration staging; compute mode may be disabled and unit masked; if preparation is interrupted before process quiescence, an already-running process may remain | v1-only processes may operate only under ordinary v1 rules; no migration has started | Selects v1 and may operate under ordinary v1 rules | Ordinary v1 behavior only; migration has not acquired D8 or written migration inputs | Abort preparation or complete quiescence; exact v1 executable may be restored while v1 selector is verified | Existing v1 rollback rules |
| During replacement of supported executables, before active selector | Original v1 manifest, policy, high-water and state tip; executable set may be mixed; verified preparation found no old compute process; old `o3k-compute` is masked and non-executable until the authenticated dual verifier replaces it | Any still-installed v1-only `o3kd`/`o3k` may operate only under v1 after the migrator releases D8; a replacement dual verifier selects v1 and follows unchanged v1 rules; compute remains unavailable until replaced | Selects v1; may operate only under v1 rules | v1 store operation may resume after crash; no compute cleanup, readiness, restoration, or dispatch until an admitted `o3kd` session | Finish replacement; exact old compute may be restored only if selector is verified still v1 | Existing v1 rollback rules only before selector publication; after selector, old binary restore is denied |
| Selector temp file written/fsynced, before `state.json` rename | Original active v1 state tip and all other active v1 bytes | May start v1 | Selects v1 | Allowed under v1 rules | May retry; ignores incomplete selector temp | Existing supported v1 rules |
| `state.json` renamed, before recovery-state directory fsync | After power loss, either original v1 tip or exact complete signed migration tip; all supported executables are already dual verifiers; no later active writes are allowed | If old tip survives: dual verifiers select v1 and may operate under unchanged v1 rules. If migration tip survives: dual verifiers select v2 and deny incomplete generation | If old tip survives: selects v1. If migration tip survives: selects v2 but denies incomplete generation | Only unchanged v1 state with dual verifiers may operate; migration-tip image must deny store, readiness, lease, reconciliation, cleanup, restoration, and dispatch | May retry from authenticated staged bytes only after reading and classifying recovered tip | Old-generation rollback only if old tip survived; event rewrite/rollback denied if new tip survived |
| Selector directory fsync/readback complete; before v2 active policy publication | Original v1 policy/high-water/manifest plus authenticated migration event in `state.json`; every supported executable is dual-verifier | Rejects unknown event before store or provider-side effects | Selects v2; denies because required v2 generation is incomplete | Denied: no store, readiness, lease, reconciliation, cleanup, domain restoration, or provider dispatch | May exact-forward from bytes bound by event | Old verifier rollback, event removal, partial repair, and downgrade denied |
| During active v2 policy replacement, before file and directory fsync/readback | Migration event plus either old policy bytes or complete v2 policy bytes; no later active step until verified | Rejects migration event before store or provider-side effects | Denies old policy/high-water mismatch or incomplete binding; may accept only if all required bindings already verify | Denied unless complete coherent generation already verifies; no intermediate step may expose readiness or provider side effects | Exact-forward only | Rollback/repair/downgrade denied |
| After v2 policy, before v2 high-water | Migration event, v2 policy, old v1 high-water | Rejects migration event | Denies high-water mismatch | Denied | Exact-forward only | Rollback/repair/downgrade denied |
| After v2 high-water, before new manifest | Migration event, v2 policy/high-water, old manifest | Rejects migration event | Denies exact-manifest mismatch | Denied | Exact-forward only | Rollback/repair/downgrade denied |
| Forbidden state: migration event durable and a v1-only executable remains at any supported path | This state must be unreachable; all executables were authenticated, atomically replaced, and read back before selector publication | A v1-only executable cannot be assumed to reject the selector; detect it and keep migration denied, with no supported service path started | Dual verifier selects v2 and denies until the coherent generation and all entry points verify | Denied, including compute cleanup/restoration and provider dispatch | Exact-forward only after replacing the stale path with the authenticated candidate binary | Refuse rollback, partial repair, and downgrade |
| Complete generation/readback, before guard release | Coherent v2 selector/policy/high-water/manifest, all installed paths verified v2-capable | Rejects migration event | Accepts v2 only under exact manifest and bindings | Permitted only according to v2 authorization; an inactive journal chain still denies activation | Migration is complete; no second selection | Any downgrade/re-anchor/rotation outside accepted contract denied |
| After guard release or reboot | Same complete authenticated v2 generation | Rejects migration event | Accepts v2; journal-chain terminal/quarantine rules still apply | Same as complete generation above; never grants activation through A10 | No migration replay needed | Any downgrade/rewrite denied |

The rows that mention a v2 verifier accepting are future requirements, not
claims about currently protected implementation. The matrix is falsified if
any entry point can open canonical state, report readiness, acquire a lease,
or dispatch a provider operation from an incomplete selected generation.


Deterministic negative contract vectors for the protected/implementation test
suites are:

| Vector | Recovered bytes | Expected result |
| --- | --- | --- |
| D8-A10-01 | Truncated or non-canonical selector temp; original active v1 state/policy/high-water/manifest | Ignore temp as authority; v1 only, no A10 selection |
| D8-A10-02 | Complete v2 policy exists only under inactive staging name; active state tip remains v1 | Neither verifier selects v2; v1 may operate under v1 rules |
| D8-A10-03 | Active v2 policy is observed without a valid migration event (constructed corruption/partial repair) | v1 rejects policy format; v2 rejects selector mismatch; deny before store |
| D8-A10-04 | Migration event survives rename-before-directory-fsync; v2 policy/high-water remain v1 | v1 rejects unknown event; v2 selects v2 and denies incomplete bindings |
| D8-A10-05 | Migration event durable; v2 policy absent, truncated, wrong signature, or wrong digest | Both verifier generations deny before store; installer cannot synthesize a different digest |
| D8-A10-06 | Migration event durable; v2 policy present but v1 high-water remains | v1 rejects event; v2 rejects high-water mismatch; exact-forward only |
| D8-A10-07 | Migration event durable; v2 policy/high-water present but old manifest remains | v1 rejects event; v2 rejects manifest digest/release binding; exact-forward only |
| D8-A10-08 | Migration event durable; old binary/rollback package starts | Supported paths contain only dual verifiers before selector publication; any rollback tool/package that would execute a v1-only verifier refuses before replacing files |
| D8-A10-09 | Migration event durable; event removed, rewritten, sequence regressed, or replaced with prior v1 tip | State-chain authentication/high-water fails; no store/readiness/lease/dispatch |
| D8-A10-10 | Crash/reboot between any two active publications; resume input differs by one byte or names another manifest | No partial repair; deny, preserve bytes, require bounded operator action |
| D8-A10-11 | Migration event durable; v2 verifier sees stale clock, expired/revoked signer, missing trust, or mismatched device/inode | Deny before store; clock rollback does not relax sequence/high-water |
| D8-A10-12 | Complete v2 policy with `INACTIVE_VERIFIED` journal tip | Deny controller/API readiness, lease acquisition, reconciliation, and provider dispatch |
| D8-A10-13 | Crash after migration selection while `o3k-compute` restarts and attempts startup cleanup/domain restoration | Its dual verifier denies before cleanup, restoration, agent readiness, or provider dispatch; a v1-only compute executable at a supported path makes selector publication invalid |
| D8-A10-14 | `o3k-compute` restarts while the migrator holds D8 and v1 remains selected | It remains unready and performs no cleanup, reconciliation, restoration, or dispatch until an authenticated session from a D8-admitted `o3kd` exists; during migration no such session can be admitted |
| D8-A10-15 | Preparation finds any process still executing the installed old `o3k-compute` inode after the path is made non-executable and the unit is masked | Abort before D8 acquisition or migration writes; do not publish selector; process remains governed only by unchanged v1 rules |
| D8-A10-16 | Crash during compute preparation, before D8 acquisition | No migration staging or active recovery bytes changed; v1 remains selected; any surviving process is only under ordinary v1 rules, and the masked/non-executable path prevents new old-binary starts |

These vectors are deterministic state fixtures, not current runtime evidence.
The implementation PR must turn each applicable vector into a failure-first
test across the installed startup, CLI, systemd, upgrade, rollback, and
maintenance entry points. Preparation tests must include an already-running
direct compute process, prove migration refuses while its executable inode is
live, and prove a crash before D8 acquisition leaves only unchanged v1
authority. The current v1 code can prove only its own fail-closed
handling of unknown policy/state formats; it cannot prove v2 selection or
resume behavior.

C1.1 `o3k-installation-reanchor-v1` remains a v1-to-v1 re-anchor and must
reject a changed policy format. It cannot verify or authorize v1-to-v2
migration; the new migration event does that explicitly after verifying both
release manifests and both policy signatures. C1.1 `o3k-restore-journal-
checkpoint-v1` remains a journal-v1 checkpoint only. This decision provides
no v2-to-v2 policy re-anchor or routine release-policy rotation. After v2
migration, a release update or rollback that would change the exact bound
release identity is denied until a separate policy-reanchor contract is
accepted. This restriction preserves the exact-release binding and is a
known availability/maintenance limitation.

#### 7.4.3 A10 journal binding and rotation

The initial signed A10 `PREFLIGHTED` journal-v2 record binds
`restore_branch=inactive`, installation ID, site ID, exact profile/backend/
backend-version/deployment, exact operation and artifact identities, target
identity, and SHA-256 of the exact canonical signed v2 policy document.
Every later record repeats or cryptographically inherits that policy digest
and the immutable branch. Missing/unsupported policy selection denies before
the journal can reserve a target. Policy rotation or release migration is
denied while any A10 journal-v2 chain exists; records may not be rebound to a
new policy. A later journal-v2 checkpoint or chain migration requires a
separate explicit normative decision. C1.1 checkpoint authority remains
limited to journal v1. No policy rotation is supported while any journal-v2
chain exists, and this decision defines no same-format v2 policy rotation.

#### 7.4.4 Required negative contract tests and residual risk

Contract tests must reject absent/unknown selection, v1-to-A10 fallback,
wrong profile/backend/major/deployment, altered release-manifest digest,
release-identity mismatch, wrong or mixed signing authority, missing recovery
or journal identity, stale/equal-conflicting policy revision, broken prior
digest, unsupported format/event, mixed or partial migration generations,
old-verifier startup, rollback to an old verifier, and policy rotation during
any journal-v2 chain. They must preserve ordinary v1 behavior when A10 is not
selected, preserve C1.1's journal-v1-only checkpoint boundary, and show that
neither policy selection nor `INACTIVE_VERIFIED` grants API readiness,
controller lease, reconciliation, provider dispatch, or activation.

The remaining risks are compromise of the release-signing or
installation-policy authority, root-level alteration of local state without
an independently trusted anti-rollback anchor, unavailable offline custody,
and interrupted migration. These remain fail-closed availability risks; this
proposal adds no local rollback defense beyond the accepted D8/C1.1 state and
high-water controls and grants no target-mutation authority. ADR-0190's
non-independent single-maintainer review disclosure remains applicable; this
proposal has not received an owner-directed technical decision. It is not
accepted until the owner records ACCEPT / AMEND / REJECT against the exact
reviewed PR head. The decision authorizes only contract work; runtime
implementation remains gated until that decision.

## 8. Operator interface

The accepted operator surface is host-local `o3k` CLI only; there is no HTTP
API. Commands run as the dedicated recovery operator through OS authorization
and never accept secrets in arguments or environment variables. The accepted
commands are:

```text
o3k backup create --destination ABSOLUTE_DIRECTORY --operation-id UUID
o3k backup verify --artifact ABSOLUTE_FILE
o3k restore preflight --artifact ABSOLUTE_FILE --target EMPTY_TARGET
o3k restore resume --operation-id UUID --confirm-artifact SHA256
```

Site/profile, database roles, trust and key handles come only from root-owned
installation configuration. `preflight` is read-only. `resume` requires an
authenticated signed journal, the existing TTY confirmation repeating artifact
digest and target installation ID, and revalidation and observation of the
same target bound to that operation, artifact and reservation. Before the first target mutation, that
target must still be fresh, empty and exclusively reserved. On a retry after a
mutation, the target may contain prior work only when observation attributes
each mutation to that same operation, artifact and target reservation; foreign
or conflicting state is quarantined. The runner resumes only when the previous
step is demonstrably complete or the next operation is demonstrably
idempotent. It never blindly repeats an operation with an unknown outcome. For the existing fenced
activation branch, `resume` continues to require fresh D7 source-fencing
evidence; this requirement is unchanged. For the proposed A10 inactive branch,
fresh D7 evidence is not required because that branch cannot activate, but the
release-signed installation policy selecting A10 and the branch-bound signed
journal are required. Non-interactive use requires a root-only one-use
confirmation file bound to that operation. Exit 0 means the requested local
step completed, 2 a rejected precondition, 3 a recoverable failure, and 4 an
unknown/quarantined outcome. Output is bounded JSON on stdout; stderr contains
only stable error codes and operation ID. No credentials, SQL, provider
payload or raw exception is emitted. The command names, confirmation mechanism
and exit-code semantics are unchanged. The #944 runbook and exact-release
tests must use these commands before recovery is claimed.

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

The current prototype at `tests/pp6_contract_decisions.py` exercises the
selected protocol constraints for reservation arithmetic, PostgreSQL signer
scope, cross-host writer exclusion, freshness and identity-bound fence
evidence, journal sequence/hash requirements, complete PostgreSQL TOC
classification, and repository inventory drift. Its tests deliberately model
policy predicates only: they do not implement cryptography, locks, Redfish,
PostgreSQL tooling or backup/restore runtime. PostgreSQL size measurements
remain as recorded in
[`PP6_POSTGRESQL16_SIZE_AND_POLICY_MEASUREMENT.md`](../pp/PP6_POSTGRESQL16_SIZE_AND_POLICY_MEASUREMENT.md):
the current empty migration fixtures were 1,175,552 bytes SQLite and
11,156,503 bytes PostgreSQL, with a 1,171,456-byte SQLite snapshot and
178,898-byte PostgreSQL custom dump. Those observations support the tool and
fixture path only; they do not establish production artifact or peak staging
sizes. Each backup preflight measures all allowlisted source bytes `S`,
reserves `max(2*S + 1 GiB, 6 GiB)`, and enforces that reservation as a staging
quota. It fails before capture if `S > 4 GiB`, the computed reserve exceeds
9 GiB, capacity is insufficient, any member exceeds 1 GiB, or the complete
artifact exceeds 5 GiB. It never truncates the computed reserve.

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
