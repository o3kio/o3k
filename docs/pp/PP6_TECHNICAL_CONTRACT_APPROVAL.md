# PP.6 technical contract decision package

**Status:** Accepted technical contract at
`9ce23ff81218e8e35d917ef6ee4478ae69e8f28e`; this record does not assert
runtime, release, or independent-security acceptance.
**Review authority:** `senolcolak`, interim architecture and security/technical
reviewer and named risk owner under accepted ADR-0190. This review is
non-independent. No independent security approval is claimed.
**Scope:** ADR-0189, SPEC-0050 and `control-plane-backup-v1.proposed.schema.json`
for D2/D4/D7/D8/D9/D10/D12/D13. ADR-0190 governance and mode selections are
settled and are not reopened here. SPEC-0051 has a distinct technical gate and
is unchanged.
**Implementation gate:** The exact-revision technical contract is accepted.
That decision permits implementation work against the accepted contract; it
does not certify runtime behavior, release readiness, or operational recovery.
Those claims still require the implementation and evidence gates in the
accepted documents and the governing release process.

The accepted request applied to the complete source revision containing this
document, ADR-0189, SPEC-0050, the manifest schema and prototype tests at
`9ce23ff81218e8e35d917ef6ee4478ae69e8f28e`. On 2026-10-18, `senolcolak`
recorded `accepted` on #975 and approved PR #1156 at that exact head after its
final signer-authorization test update. The issue tracking record
[summarizes the exact accepted scope and conditions](https://github.com/o3kio/o3k/issues/975#issuecomment-6254574622);
the PR was integrated as `d666497c174c7297aa5feb8438a56a0ad898008f`.
Approval and integration apply to that revision only. The PR approval by
itself is not treated as the technical decision.

## Accepted technical parameters

| Decision | Accepted exact-revision contract | Fail-closed condition |
|---|---|---|
| D2 — key hierarchy and signer | AES-256-GCM, one fresh 256-bit key per artifact, unique 96-bit per-member nonce, RFC 8785 canonical manifest/AAD, RFC 9180 HPKE Base X25519/HKDF-SHA256/AES-256-GCM recovery-key wrapping. Sign the D1 exact byte input with Ed25519: `ASCII("O3K-PP6-BACKUP-MANIFEST-V1\0") || u64be(manifest_length) || canonical_manifest_without_signature || concatenated_member_digests`; each path-sorted digest is `u32be(path_byte_length) || path_bytes || SHA256(ciphertext_and_tag)`. PostgreSQL uses an isolated remote signer with a non-exportable PKCS#11 v3.0 HSM key, mutually authenticated TLS 1.3, installed backup-client identity, configured site/profile allowlist, request ID, 256-bit nonce and 15-minute expiry. The separate offline Ed25519 trust root signs RFC 8785 canonical online-key certificates (`key_id`, public key, purpose=`backup_manifest`, exact site/profile, serial, validity, issuer) and a monotonic revocation list carrying `sequence`, `issued_at` and `next_update`. Online signer certificates are valid for at most 90 days; the signed revocation list must be refreshed at least every 24 hours by the offline custodian process. The root public key and initial trust/revocation sequence are pinned in the release-signed install trust manifest. Verifiers fetch the signed list from a trust-distribution endpoint administered separately from the artifact signer before artifact acceptance and again before restore activation. Two custodians issue and publish an emergency root-signed revocation immediately after compromise. A list is valid for at most 24 hours; the verifier remembers the highest accepted sequence and canonical-list digest durably; equal sequence is idempotent only for the same digest, and different content at that sequence is equivocation and fails closed. If the distribution endpoint is unavailable, a cached list may be used only until its 24-hour `next_update`; this bounds, but does not eliminate, the worst-case stale-revocation exposure to 24 hours. Offline, expired or lower-sequence state fails closed. Root operations (provision, rotate, revoke, recover) require two of three named custodians. Install new certificates before switch, retain old verification certificates for 30 days, and revoke compromise immediately. SQLite uses a separate offline artifact key with two-of-three operator-assisted signing. Recovery decryption and journal/evidence signing keys are distinct offline authorities under two-of-three custody. | No signer fallback; signer outage, wrong scope/key, malformed canonical bytes, nonce reuse, replay conflict, expired request, revoked key, unavailable custody or incomplete publication prevents success. Semantic validation rejects duplicate member names and duplicate AES-GCM nonces (JSON Schema whole-object `uniqueItems` cannot express those field-level uniqueness rules); aggregate plaintext, manifest, complete-artifact and staging limits are checked by bounded streaming accounting. Exact-byte retries return the original signature only within request expiry; after expiry, recapture with a new artifact ID and request. Online signer cannot sign restore, fence, journal, release or activation data. |
| D4 — capture boundary | Every `o3kd` startup/store-opening path takes one lifetime exclusive `flock` before opening the store, readiness, workers, leases or dispatch; backup owns it from quiesce through verified publish/abort. PostgreSQL uses a DB-side admission barrier: install first-match `pg_hba.conf` rules permitting only the backup-host address and `o3k_backup_dump` to the O3K database, followed by explicit rejects for all other network paths and `local all all reject`; enforce the same source restriction with the independently managed database-host ingress ACL; set every O3K writer-capable LOGIN role `NOLOGIN`; stop connection pools; terminate all pre-existing sessions except one already-open control session; validate `pg_hba_file_rules`, reload completion, and prove fresh Unix-socket, application and maintenance reconnects are denied. The surviving local control session verifies zero sessions other than itself, then closes; verify it is gone and only the remote `o3k_backup_dump` session exists before dump begins. The firewall/HBA barrier remains held through `pg_dump -Fc` and cross-file capture, and release restores the saved configuration only after verified publication or abort. The dump role has CONNECT, USAGE and SELECT only on inventoried objects. | The deployment is unsupported if it cannot enforce the DB-side admission barrier against every remote or Unix-socket writer path. A local `flock` never claims remote exclusion. Any active/uninspectable session, barrier loss, supervisor restart race, lock loss, unknown operation, or DB/config/identity/release generation mismatch aborts capture. API availability is interrupted; already-running data-plane workloads continue without controller mutations. |
| D7 — source fence | Physical `o3k-small-edge-v1`: independently administered Redfish/BMC power-off, queried by a separate recovery host over TLS 1.3 using a per-site CA and pinned BMC certificate fingerprint plus source serial. Signed evidence binds source/site/target/operation/authorized actor/fingerprint/evidence-key ID/observation time/unique nonce. The target pins the separate offline Ed25519 evidence public key in release-signed trust metadata. Evidence is valid for 300 seconds and single-use. A monitor polls at least once per second through commit, holds the recovery-only BMC management ACL and verifies the source remains off; BIOS stay-off behavior is tested. The monitor key is operation-scoped and delegated by the signed initial fence record. For each lease, the target sends a fresh challenge; the recovery host signs a response only after a fresh BMC-off observation and ACL check. The response binds source/site/target/operation, challenge, sequence and journal hash. The target uses its local monotonic clock and accepts the response for two seconds only. Each activation mutation and durable `COMMITTED` transition requires a current challenge response and held BMC ACL. The final commit fsync is rejected if heartbeat or lease expires; loss quarantines the target and stops dispatch. Immediately before activation, take a second authenticated power-off observation. | Missing, mismatched, unauthorized, stale/replayed evidence; monitor, ACL or BMC loss; any power-on observation; stale source credential acceptance; or PG source writer access prevents activation and quarantines the target. No independent BMC means capture/verification only, never restored-controller activation. Redfish evidence is operator-attested authenticated observation, not hardware-signed telemetry. |
| D8 — journal and handoff | `o3k:o3k` recovery directory mode 0700 on verified local ext4; files mode 0600; no-follow/exclusive creation and owner/inode recheck. Separate reservation lock retained through terminal state. Startup/store guard is lifetime exclusive `flock`; recovery launcher passes the same open file description to the pinned `o3kd` via `execve`. The signed `STARTED` record binds the current kernel boot ID and fresh 256-bit launch nonce; the child atomically compare-and-consumes the nonce in the protected journal before opening the store, persisting consumption with file fsync, same-directory rename and directory fsync. A reused nonce, competing second consumer, or changed boot ID is denied and requires a new signed transition. Each forward transition uses a separately offline-signed Ed25519 journal record with monotonic sequence, prior signed-record hash, operation/artifact/site/source/target/phase and request nonce. Persist by file fsync, same-directory rename, directory fsync. | Unsigned markers only deny progress. Lost response retries exact durable request only. A crash before/after handoff cannot authorize an unverified store open: systemd follows the same guard and revalidates signed STARTED record, target and fresh fence. Lock loss, fork/replay, conflicting journal or unsafe marker persistence quarantines and preserves prior state. |
| D9 — bounds | At most 64 members, depth 8, ASCII path 1024 bytes, 1 GiB plaintext/member (1 GiB plus the 16-byte GCM tag on disk), 4 GiB aggregate plaintext, 16 MiB manifest, 64 MiB overhead, 5 GiB complete artifact. Reserve `max(2*S + 1 GiB, 6 GiB)` where `S` is measured full allowlisted source size; enforce as staging quota; cap is 9 GiB. | Fail before capture if any source/member bound is exceeded, computed reservation exceeds 9 GiB or free capacity is insufficient. Never truncate reservation. Existing measurements are empty-schema fixtures only and do not waive per-run sizing or establish production maximums. |
| D10 — PostgreSQL roles and archive policy | PostgreSQL 16 only; `pg_dump -Fc`/matching `pg_restore --exit-on-error --no-owner --no-acl`. Role flags: `NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS`; runtime LOGIN, dump NOLOGIN except capture, restore-owner NOLOGIN except restore, and no role memberships. `o3k_runtime`: CONNECT, public-schema USAGE, DML on every exact-release migration-owned table; USAGE/SELECT/UPDATE on migration-owned sequences. `o3k_backup_dump`: CONNECT, schema USAGE, SELECT on every migration-owned table; USAGE/SELECT on migration-owned sequences; no DML/DDL. The current complete migration prototype has 77 public tables, zero app views/sequences/extensions, two non-security-definer functions and their two exact migration-created triggers (`o3k_validate_operation_resource_reference` / `operations_validate_resource_reference`; `o3k_delete_generic_resource_operations` / `resources_delete_generic_operations`). The normalized migration baseline covers every table, view, sequence, index, constraint, function and trigger descriptor. A descriptor is RFC 8785 canonical JSON over catalog identity and behavior: ordered column type/nullability/default/generated/identity metadata; `pg_get_indexdef`; `pg_get_constraintdef` plus validation/deferred flags; `pg_get_functiondef` plus language/volatility/security/config; `pg_get_triggerdef` plus enabled state; and `pg_get_viewdef`/sequence parameters when applicable. Hash canonical UTF-8 bytes with SHA-256; baseline also binds PostgreSQL major and all migration file SHA-256 values. No other callable object, RLS policy, foreign schema, extension, security-definer object, archive owner/ACL, role, password, tablespace or grant is allowed. `o3k_restore_owner` owns only the fresh target DB/schema, has CREATE there during restore, no source DB access, and is disabled before activation. | Before any target SQL, unfiltered TOC must exactly match the version-pinned migration-derived baseline. Validate catalog definitions, constraints, indexes, triggers, roles and grants against the exact-release baseline. The disposable PostgreSQL 16 prototype below verifies the current migrations and role matrix; release implementation must regenerate and compare the full definition/grant manifest before mutation. Unknown/missing/duplicate/forbidden TOC or any definition/grant drift rejects before target mutation. |
| D12 — operator surface | Host-local `o3k` CLI only; no HTTP API. Accepted commands: `o3k backup create --destination ABSOLUTE_DIRECTORY --operation-id UUID`; `o3k backup verify --artifact ABSOLUTE_FILE`; `o3k restore preflight --artifact ABSOLUTE_FILE --target EMPTY_TARGET`; `o3k restore resume --operation-id UUID --confirm-artifact SHA256`. Site/profile/key/database config is root-owned; secrets never appear in arguments/environment. Resume requires TTY confirmation repeating artifact digest and target ID, or one-use root-only operation-bound confirmation file. Exit codes: 0 complete, 2 rejected precondition, 3 recoverable failure, 4 unknown/quarantined. Bounded JSON stdout and stable redacted stderr errors. | The accepted contract defines the command surface; implementation and exact-release runbook verification are still required before operational recovery claims. These commands are not implemented or supported yet. |
| D13 — canonical state inventory | The authenticated schema carries one entry per registered durable repository, including those with zero rows, mapping repository ID/state family to its exact SQLite and PostgreSQL data tables plus migration IDs. A separate catalog inventory records every migration-owned table/view/sequence/index/constraint/function/trigger and normalized definition digest. The schema bounds repository entries to 512; exceeding this requires a format revision. Commit one generated baseline from store registrations and both migration trees; the baseline comparison, not JSON Schema alone, enforces unique repository IDs and exact coverage. Generate from store registrations and both migration trees; separately compare real migrated catalogs (`sqlite_schema`, `pg_catalog`) with explicit system-object classification. CI regenerates and fails on baseline drift; never auto-updates it. | Any unknown/missing repository or catalog object, extra object, migration mismatch or family gap fails before capture/activation. Include audit events and empty repositories. |

### D12 implementation status (interim, 2026-10-24)

D12's `create` and `verify` commands are implemented against the accepted
contract (`o3k backup create --destination --operation-id`,
`o3k backup verify --artifact`); this is accepted-contract implementation work,
**not** a supported operational-recovery claim. `restore preflight` and
`restore resume` are **not implemented**. Runtime evidence is limited to the
SQLite TestLab/portable path and is recorded in
[`docs/evidence/ISSUE_1084_ARTIFACT_EVIDENCE.md`](../evidence/ISSUE_1084_ARTIFACT_EVIDENCE.md);
#1084 remains open. This note does not change the accepted D12 text.

### D7 activation capability by deployment profile

| Deployment | Activation policy | Independent authority required |
|---|---|---|
| `o3k-small-edge-v1`, physical | Supported only when configured | Redfish/BMC administered outside O3K, independent recovery host, pinned CA/certificate and source serial, plus continuous fence lease. |
| `o3k-small-edge-v1`, virtualized | Inactive materialization is permitted only when the signed installation policy selects it; activation remains separately gated | Any activation requires independent hypervisor power control or network isolation outside both restored-controller credentials and its host. |
| `o3k-demo-v1` / TestLab | Backup and verification only; restored-controller activation disabled | A later profile-specific fencing contract and exact evidence are required before enabling activation. |

**Accepted amendment A10.** Owner decision
[6423776117](https://github.com/o3kio/o3k/issues/1086#issuecomment-6423776117)
accepted the exact amendment integrated as
`ca8fe3033ace09cf7b7a43286522dbd3e6ad326a` after review of PR #1176 head
`b69b6b9b8abe913f1da4639cadb6df29509d4cde`. The amendment adds a signed,
non-activating branch limited to virtualized PostgreSQL `o3k-small-edge-v1`
under a release-signed installation policy; see
[SPEC-0050 §7.1](../specs/SPEC-0050-pp6-control-plane-backup-restore.md#71-accepted-amendment-a10-isolated-inactive-materialization)
and the [accepted ADR-0189 amendment](../adr/ADR-0189-pp6-control-plane-backup-and-restore.md#accepted-amendment-a10-isolated-inactive-materialization).
The unchanged `restore resume` command revalidates and observes the same
target; emptiness is required before first mutation, not after the operation's
own partial mutation. Fresh D7 evidence remains required for activation
resumes, while the A10 inactive branch requires its signed installation policy
and prohibits activation transitions. This decision authorizes
implementation/testing only and does not certify installed recovery or
production evidence.

**Accepted amendment C1.** Owner decision
[6423774720](https://github.com/o3kio/o3k/issues/1086#issuecomment-6423774720)
accepted the amendment integrated as
`ea4f705efba72421f368903be71a0e792851813f` after review of PR #1179 head
`0c0dfd4374cf0b972e2a8769ad4f9f38cea793a0`. SPEC-0050 §7.2 and the matching
ADR-0189 amendment define an installation-bound recovery designation
discovered independently of `restore.json`, plus installed
journal/evidence signer trust and signed revocation state with durable
anti-rollback, freshness, rotation, and recovery rules. They also state that
local files cannot defend against a privileged target-root attacker; that
threat requires an independently trusted rollback-resistant anchor and startup
verifier or remains out of scope. The decision authorizes implementation and
testing, not runtime correctness, installed recovery, production readiness,
or independent security qualification.
Authenticated `NEVER_RECOVERED` installations have no journal-trust dependency;
recovery-designated or previously recovered installations do.
The accepted decision includes the installation-policy and state-record
canonical formats, signature envelopes, trust-document formats, purpose/scope
bindings, and 90-day certificate, 24-hour revocation-refresh, and 30-day
signer-overlap values. For the current packaged
`o3k-small-edge-v1` profile, privileged target-root attackers remain outside
the recovery security claim without a qualified independent anchor. C1 does
not authorize journal phases after `PREFLIGHTED`, accept A10, or authorize
restore target mutation.

**Accepted amendment C1.1.** Owner decision
[6440284521](https://github.com/o3kio/o3k/issues/1086#issuecomment-6440284521)
accepted SPEC-0050 §7.3 and the matching ADR-0189 amendment at PR #1187 head
`df52e28471fee99b09807135a3823c6f8bd5326e`, integrated as
`4d9d5108f4995b270144c3b29ad54704a62e61c8`. This owner-directed,
non-independent decision authorizes implementation/testing only. The amendment
adds an authenticated installation-policy/trust re-anchor and journal checkpoint
so an accepted-C1 installation can rotate or recover its installed
journal/evidence trust roots; see
[SPEC-0050 §7.3](../specs/SPEC-0050-pp6-control-plane-backup-restore.md#73-accepted-amendment-c11-authenticated-installation-policytrust-re-anchor-and-journal-checkpoint).
Conflict and option: accepted C1 verifies every historical journal/state
signature under current trust with at most a 30-day signer overlap, so retired
roots would otherwise stay in the live TCB with unbounded retention/expiry
exceptions, and a sealing re-anchor would still be needed; the proposal
selects the smaller, safer explicit re-anchor (Option A) over historical
policy-chain verification (Option B). A signed `o3k-installation-reanchor-v1`
record R extends the installation-state sequence — signed only by the
release-manifest-authenticated installation-policy authority, not a
disposition and not a phase — and a signed
`o3k-restore-journal-checkpoint-v1` record C extends the journal sequence
under the new trust and is published before R; C1.1 checkpoints journal v1
only, and A10 journal-v2 checkpointing requires separate acceptance.
`NEVER_RECOVERED` requires R only; `RECOVERY_DESIGNATED` and `RELEASED`
require R+C; the installation-state lifecycle remains exactly those three
values — C1.1 adds no `QUARANTINED` state — and rotation during quarantine
preserves the applicable one of the three plus all journal quarantine phases
and unsigned denial markers byte-for-byte, while an ambiguous migrated state
without an authenticated old generation cannot rotate and first needs an
authenticated disposition. Preserved disposition, operation, artifact, target,
recovery-directory identity, and `RELEASED` terminal journal hash and evidence
digest are unchanged, and no new `NEVER_RECOVERED`/`RELEASED` self-transition
is introduced. Compromise rotation revokes the old root by a revocation
signed by the new trust root authenticated by the new policy, blocking new
old-root authorization without retroactively rewriting durable history, and
requires `o3k-recovery-revalidation-v1` evidence under the new
recovery-evidence authority carrying a unique 256-bit nonce with an accepted
300-second validity that authorizes exactly one R/C
pair through a durable consumption record written before acceptance and
marked consumed only after full authenticated publication; byte-identical
resume of that pair is allowed, any second or different use is rejected, and
missing, stale, wrong-scope, or insufficient-custody evidence fails closed.
Pre-C1.1 verifiers reject unknown R/C records and deny startup, so rotation
happens only after every verifier supports C1.1, including R-only
`NEVER_RECOVERED` rotation. R/C signing requests use the accepted offline
ceremony with fresh 256-bit request nonces and exact-byte retry only. After
R+C, older signatures are audit-only carried by the authenticated tips while
current-era records verify individually; this bounded attestation replaces
historical per-signature verification and is an explicit human security
decision. Publication is crash-safe (staging under distinct staged names, then
fixed policy, policy high-water {revision, digest}, fixed trust, trust
high-water {bundle digest, per-root revocation sequence and digest}, current
C, current R, final observation; same-directory temp+fsync+rename+fsync+
readback every step), partial generations deny startup, and the installer
resumes only the exact signed R/C forward. Filesystem controls are unchanged,
unsigned denial markers are preserved byte-for-byte, and rotation alone never
clears quarantine, consumes nonces, grants sessions, leases, provider
dispatch, an API listener, or activation, or changes D3/D4/D7/D8/A10.
Rotation is a root-authorized installer operation outside the accepted §8
recovery CLI; C1.1 accepts no new CLI. The owner decision explicitly accepts
the policy-authority-only R signer; the new-journal-authority C; the
verification-posture change; the compromise revalidation authority/custody and
300-second validity; and quiescence/rotation during quarantine. Implementation
evidence must include replayed or reused single-use revalidation,
equal-sequence R/C equivocation, a crash at every publication step with
exact-forward resume only, byte-for-byte marker preservation, old-verifier
denial, stale trust, and no activation. The decision changes no accepted
D1–D13, C1, or A10 parameter and does not satisfy any runtime, installed,
production, or independent-security gate.

### D2 custody record

Every offline root, recovery, journal, and evidence key has a signed non-secret custody record containing `custody_record_id`, site/profile, purpose, key ID and fingerprint, algorithm, `2-of-3` threshold, three stable organization principal IDs, authorization-group version, creation/rotation/revocation times, approving record IDs, storage-provider/location classes, recovery-quorum event ID and expiry/re-review date. Provisioning, rotation, emergency revocation and recovery require two distinct authorized principals. Recovery quorum is bound to key ID, site/profile, operation ID and exact artifact/journal purpose. The custody authority signs the record. Physical storage addresses, private keys, tokens and credentials are excluded. A missing/expired/mismatched record fails closed.

## Prototype and evidence

`tests/pp6_contract_decisions.py` is a policy prototype with executable
negative tests for D2/D4/D7/D8/D9/D10/D13. It covers the selected PostgreSQL
online-HSM and SQLite offline-operator signing modes, PostgreSQL signer
purpose/site/profile/backend scope, certificate/revocation/expiry rejection,
exact retry and fresh monotonic revocation state, signer threshold
custody, local-lock insufficiency and PostgreSQL remote/Unix-socket session
admission, fence actor/fingerprint/key identity, freshness/TLS/power/ACL and
challenge/sequence/journal-hash lease state, boot-bound atomic single-use activation, signed
journal sequence/hash requirements, exact TOC and repository inventory, and D9
arithmetic. It models decisions only; it does not implement cryptography or
exercise production boundaries.

Validation on this proposed source revision:

```text
python3 tests/pp6_contract_decisions.py — 12 tests passed on the submitted
revision; the protected PR CI result is recorded separately.
```

The PostgreSQL catalog policy prototype passed on PostgreSQL 16.15 against all
36 committed PostgreSQL migrations at base SHA
`959c7cfa38e1a18db77529af78434bab4dddd208`: 77 tables, zero views/sequences/
application extensions, and the two migration-created trigger functions plus
their two triggers. The test used an automatically created and dropped
`pg_virtualenv` cluster; it did not modify the shared PostgreSQL service. This
is catalog/grant prototype evidence, not production backup, restore or
concurrent-writer acceptance.

The PostgreSQL 16 size harness evidence is
[`PP6_POSTGRESQL16_SIZE_AND_POLICY_MEASUREMENT.md`](PP6_POSTGRESQL16_SIZE_AND_POLICY_MEASUREMENT.md), source-bound to its recorded 2026-10-18 commit. It applied the then-current complete migrations: SQLite database 1,175,552 bytes / snapshot 1,171,456; PostgreSQL database 11,156,503 bytes / custom dump 178,898; PostgreSQL server/tool 16.15. These are empty-schema observations and do not certify production artifact size, encrypted output, peak staging, concurrent writer exclusion, restore, or recovery. No such claim is made.

The manifest schema is checked for JSON Schema Draft 2020-12 validity. The
schema includes exact algorithm IDs, HPKE fields, per-member nonce and
Ed25519 signature encoding. Prototype and schema validation do not prove
cryptographic correctness; implementation must use vetted RFC implementations
and independent known-answer, tamper, wrong-key, replay, rotation, revocation,
interruption and publication tests.

## Decision record fields

This table records the exact-revision decision and protected integration.
Implementation and evidence conditions remain gates; they do not reopen or
change the accepted contract. The review was non-independent and named
`senolcolak` as interim reviewer and risk owner under ADR-0190.

| Role | Decision | Exact source SHA | Conditions / findings | Date |
|---|---|---|---|---|
| Architecture + technical/security (interim, non-independent) | **ACCEPTED** | `9ce23ff81218e8e35d917ef6ee4478ae69e8f28e` | D2/D4/D7/D8/D9/D10/D12/D13 technical contract only; residual risk and implementation/evidence conditions remain; SPEC-0051 excluded | 2026-10-18 |
| Protected integration | **MERGED** | `d666497c174c7297aa5feb8438a56a0ad898008f` | PR #1156; integration does not enlarge exact-head acceptance | 2026-10-18 |
