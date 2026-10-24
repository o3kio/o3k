# SPEC-0050 — PP.6 control-plane backup and restore

Status: Accepted technical contract at `9ce23ff81218e8e35d917ef6ee4478ae69e8f28e`;
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
installation configuration. `preflight` is read-only. `resume` requires a
pre-provisioned empty target, fresh fence, signed journal, and TTY confirmation
repeating artifact digest and target installation ID. Non-interactive use
requires a root-only one-use confirmation file bound to that operation. Exit
0 means the requested local step completed, 2 a rejected precondition, 3 a
recoverable failure, and 4 an unknown/quarantined outcome. Output is bounded
JSON on stdout; stderr contains only stable error codes and operation ID. No
credentials, SQL, provider payload or raw exception is emitted. These exact
commands are part of the accepted contract but are not implemented or
supported yet. The #944 runbook and exact-release tests must use these
commands before recovery is claimed.

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
