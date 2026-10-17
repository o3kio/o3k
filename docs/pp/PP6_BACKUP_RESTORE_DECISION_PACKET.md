# PP.6 backup and restore decision record for approval

**Revision:** 2026-10-17
**Status:** Concrete recommendations submitted for explicit human decisions; none
are accepted. ADR-0189 and SPEC-0050 remain Proposed. This record does not
authorize production backup/restore or PKI implementation.

**Issue authority:** #975, #640, #1084–#1087, and #1098.
**Profiles:** single-site `o3k-demo-v1` with SQLite and
`o3k-small-edge-v1` with PostgreSQL 16. External VM disks, external storage
payloads, and external-hosted service databases remain outside this recovery
boundary. PP.5 campaigns, HA, multi-region recovery, and PP.7 remain out of
scope.

## Required approver and decision status

The requested reviewers are **senolcolak** for architecture and **zoorpha**
for security. However, zoorpha authored proposal PRs #1136 and #1137; review of
that material by its author cannot satisfy independent security acceptance.
The independent security authority remains **unassigned** until a qualified,
authorized reviewer independent of the material and implementation is named,
with their role and independence basis recorded. Both decisions remain
**PENDING**. A GitHub PR approval alone does not constitute contract acceptance.

[Review comment 6239123579](https://github.com/o3kio/o3k/issues/975#issuecomment-6239123579)
is attributed by GitHub to senolcolak and expressly describes itself as review
analysis, not either role's decision. Its body also contains a conflicting
account attribution. Neither attribution is used to infer acceptance. The
amendments below address its findings and still require separate decisions
against the exact amended source revision.

For every D and A below, “proposed disposition” is the recommendation to the
reviewer; “review status” remains **PENDING** until both role decisions are
recorded. The reviewer may accept, amend, reject, or withdraw a recommendation.
Any amended value must be written into ADR-0189 and SPEC-0050 before the
applicable implementation starts.

## D1–D13 — concrete recommendations

| ID | Proposed disposition and recommendation / implementation parameters | Security and operational impact | Authority, review status, unresolved dependency |
|---|---|---|---|
| D1 Artifact format and authenticity | **Amend.** Versioned regular-file container. Generate a fresh 256-bit CSPRNG content key per artifact; encrypt each allowlisted member with AES-256-GCM and a unique 96-bit CSPRNG nonce. Bind member name, plaintext length, format version, profile, site ID, and artifact ID as RFC 8785 canonical AAD. Sort members by UTF-8 path bytes and reject duplicate paths. Enforce nonce uniqueness per content key across the complete artifact and reject duplicate nonce fields before decryption. The Ed25519 signing key ID must resolve to a non-revoked public key pinned by the separately authenticated trust store. Signature input: `O3K-PP6-BACKUP-MANIFEST-V1\0 || u64be(manifest_length) || canonical_manifest_without_signature || concatenated_member_digests`; each digest entry is `u32be(path_byte_length) || path_bytes || SHA256(ciphertext_and_tag)` in UTF-8 path order. Use RFC 8785 canonical UTF-8 JSON and reject duplicate keys/noncanonical forms. HPKE Base mode RFC 9180 using X25519/HKDF-SHA256/AES-256-GCM wraps the content key to the operator recovery public key; `info` is UTF-8 `O3K-PP6-ARTIFACT-KEY-WRAP-V1\0`, and AAD is canonical JSON containing format version, profile, site ID, artifact ID, and recipient key ID. Record HPKE `enc` and wrapped ciphertext exactly as specified by RFC 9180; signature covers both and recipient key ID. Only structural metadata is cleartext; no tenant rows, credentials, provider payloads, or private keys. No outer compression. Reject unknown versions/algorithms, invalid signatures, bad tags, and malformed lengths before extraction. | Provides confidentiality and source authenticity without putting a secret or unspecified KMS dependency on the controller. Trust-root pinning and revocation are mandatory; AEAD/checksums alone do not establish provenance. | Architecture authority: senolcolak (PENDING); independent security authority: unassigned and must be a distinct person (PENDING). Review must accept exact serialization, signed inputs, HPKE context, and trust-root/revocation path. |
| D2 Key custody, recovery, rotation | **Amend.** Use operator-held asymmetric keys for both profiles. Generate distinct X25519 recipient, Ed25519 artifact-signing, and Ed25519 journal-signing key pairs on a disconnected, access-controlled Linux operator workstation. Keep private keys off controller hosts and backup destinations. Store two copies on separate offline removable media with ext4 inside LUKS2 AES-256-XTS volumes. Recommend cryptsetup Argon2id, 1 GiB memory, parallelism 4, and a 2-second format-time target for operator usability, not as a security threshold; record actual LUKS2 header parameters with `luksDump`. The KDF policy may raise but must never silently lower memory or parallelism. Label each XOR share with custodian ID and share index, include a printed SHA-256 corruption check, and independently verify the reconstructed passphrase by opening the volume before relying on it; the LUKS2 keyslot remains the authoritative verifier. Generate a 256-bit CSPRNG volume passphrase and split it into two equal XOR shares; separate named custodians hold one share each. Store Ed25519/X25519 keys as PKCS#8 DER inside the encrypted volume. Verify each pair against a separately held public-key fingerprint card. Recovery requires both custodians, read-only media mount, fingerprint verification, and a disposable restore drill before operational use. Pin recipient and verification public keys by key ID through separately authenticated installation. Retain old recipient private keys and signing public keys while any artifact under them remains in retention; revoke keys only through an explicit authenticated trust-store update. Missing keys/copies fail closed. Each backup requires a human offline detached-signature round-trip before publication; unattended/scheduled backup is unsupported in v1. Use the D1 exact signed input and the review-amendment interaction below. No KMS is required by v1. | Avoids cloud/KMS availability and account dependencies during disaster recovery. Dual-person offline custody adds operational work; loss of both media or either passphrase share makes artifacts unrecoverable. | Architecture authority: senolcolak (PENDING); independent security authority: unassigned and must be a distinct person (PENDING). Reviewer must approve Argon2id parameters, cryptsetup/workstation versions and compatibility procedure, custody locations, two-custodian control, retention/rotation, revocation, media integrity, and loss/recovery consequences. Custodian identities, protected storage locations, cryptsetup/workstation versions, rotation/retention schedule and finite signing deadline remain PENDING; approve a protected custody record referenced by ADR-0189 without publishing secrets or sensitive locations. Implementation may not choose or imply these values. |
| D3 PKI issuer and agent credentials | **Accept as written.** Never include controller issuer or agent private keys in artifacts. Replace the issuer during fresh-host restore, run a new trust ceremony, and re-enroll agents. Before activation, replace old issuer roots in every API, controller, agent, and provider trust path; invalidate cached trust material; preserve durable revocations; and prove a stale credential signed by the old issuer is rejected at each verifier. Regenerate controller runtime identity, sessions, and credentials. | Replacement avoids restoring a revoked credential to validity and avoids turning backup artifacts into fleet credentials. Re-enrollment creates a planned recovery outage and must be included in runbooks. | Architecture authority: senolcolak (PENDING); independent security authority: unassigned and must be a distinct person (PENDING). #1087 depends on accepted issuer replacement, revocation and re-enrollment behavior. |
| D4 Consistent capture boundary | **Amend.** v1 backup is offline for both profiles. Stop all store-opening O3K processes. Every process that opens the store, including `o3kd`, `o3k` CLI paths and maintenance tools, must honor the same exclusive data-directory startup/store-access lock before opening the store or starting readiness, workers, lease renewal or provider dispatch. Backup holds that lock through verified publication or safe abort. **This invariant is not implemented today; the storage execution lock is not a startup lock.** SQLite reuses the supported store snapshot API and WAL/integrity policy. PostgreSQL 16 uses `pg_dump -Fc`; preventing O3K writer-role login and proving zero remaining O3K writer sessions are mandatory, independently of local process shutdown and local locks, including controllers on other hosts. Require an exclusively O3K-owned database/schema and no unrelated writers. Bind database/files to one generation and discard staging on exclusion, generation or ownership failure. | The controller API is unavailable for capture and the human signing interval. A local lock cannot fence remote PostgreSQL writers. Workload data-plane continuity needs separate profile evidence. | Architecture authority: senolcolak (**PENDING**); independent security authority: unassigned (**PENDING**). Require startup/CLI/supervisor-race tests, mandatory PostgreSQL login/session exclusion, cross-file generation, measured duration and data-plane continuity before support claims. |
| D5 In-flight Operations | **Accept as written.** At shutdown, preserve canonical operation IDs and phases. Terminal operations remain terminal; nonterminal operations are recorded as unresolved and require observe-before-retry after restore. A timeout or shutdown does not become a failure classification and backup never replays a mutation. | Preserves idempotency and compensation authority; unresolved provider outcomes may require operator intervention. | Architecture authority: senolcolak (PENDING); independent security authority: unassigned and must be a distinct person (PENDING). Depends on D4 boundary and existing operation/reconciliation authority. |
| D6 Stable and regenerated identities | **Accept as written.** Preserve site/installation ID, canonical resource IDs, owner/security scopes, provider mappings, bootstrap principal identity, audit history, and revocation records. Regenerate controller process/session identity, leases, controller credentials, and host-local agent credentials. Never restore an active lease or private credential. | Stable resource identities preserve references; fresh controller and host credentials prevent a copied source from retaining authority. | Architecture authority: senolcolak (PENDING); independent security authority: unassigned and must be a distinct person (PENDING). Implementation requires a reviewed schema/migration map for every preserved and regenerated value. |
| D7 Source exclusion and target fencing | **Amend.** Recommend independently administered Redfish/BMC power-off as the initial fencing backend, before restored canonical mutation or provider/API action. An authorized recovery operator observes BMC HTTPS from a trusted recovery host independent of the source, validates the per-site TLS trust anchor and source serial, and transfers identity-bound evidence to the disconnected signer. Sign with the distinct D2 offline Ed25519 **journal/evidence key**, never the artifact or release key; the target recovery verifier uses its separately installed, non-revoked public trust anchor. Bind source/site/target, serial, BMC certificate fingerprint, actor and timestamps; require `PowerState=Off`, age at most five minutes, and a fresh authenticated BMC observation before activation. Signature alone is not independent fence evidence or BMC hardware-signed telemetry. Without a verified fence, stay inactive. | Redfish power state is point-in-time evidence. Retain independent source exclusion and require D3 issuer replacement, rejection of old source credentials at every verifier, fresh target ownership epoch and, for PostgreSQL, target-only writer access as durable activation gates. Do not release fencing merely because a lease expired. Without independent BMC, Demo/TestLab v1 is limited to capture/verify, with fresh-host activation unsupported. No network-fencing backend is implicitly supported. | Architecture authority: senolcolak (PENDING); independent security authority: unassigned (PENDING). Accept the Demo/TestLab limitation; name the operator/custodians, supported BMC/system identities and tested Redfish/TLS deployment. A network-isolation backend requires its own accepted mechanism/evidence. Neither a signed assertion nor two-person attestation substitutes for independent exclusion. |
| D8 Restore journal and reservation | **Amend; implementation remains blocked on exact signing and startup-handoff contracts.** Use a dedicated `o3k:o3k` recovery directory (0700; journal/requests/markers 0600) outside the target DB on Linux ext4 over local block storage, compatible with the packaged service user. Reject NFS, overlay/ephemeral and unverified network volumes. Create reserved files with `O_EXCL`/`O_NOFOLLOW` under an owner-checked directory and retain the exclusive target reservation through terminal state. Sign `O3K-PP6-RESTORE-JOURNAL-V1\0 || u64be(record_length) || RFC8785(record_without_signature)` with the separate D2 offline Ed25519 journal/evidence key; use unpadded base64url signatures. Sequence starts at 1, increases by one and chains prior signed-record SHA-256, artifact/site/source/target, operation/step and phase. Persist with file fsync, same-directory atomic rename and directory fsync. Legal phases: `PREFLIGHTED → SOURCE_FENCED → TARGET_RESERVED → STAGING → DATABASE_RESTORED → FILES_RESTORED → TARGET_FENCED → STARTED → RECONCILED → COMMITTED`; pre-mutation abort is `ABORTED`, known pre-start partial is `FAILED_RECOVERABLE`, unknown/lock-loss/conflict is `QUARANTINED`, and only verified discard/recreation permits `DISCARDED`. See review amendments below for signing, denial-only markers and separate reservation/startup locks. | Every forward phase requires an offline operator signature, roughly ten signing round-trips for a successful restore, including live-controller reconciliation/commit. Signatures attest the journal bytes; they do not protect the restored database from a target-root attacker. Unsigned failure markers can only deny progress and never authorize restore, activation, retry, discard or a forward transition. Foreign/nonempty state is preserved. | Architecture authority: senolcolak (PENDING); independent security authority: unassigned (PENDING). Confirm owner/path/kernel/filesystem, signing-tool and transfer contract, controlled startup handoff, finite signing deadline and stale-operation recovery role. No private key is copied to the target. Reacquiring a free OS lock does not authorize deletion/reuse of an old journal. |
| D9 Artifact bounds/publication | **Amend.** Closed regular-file allowlist; reject links, devices, sparse files, path traversal, duplicate names, and unknown members. No-follow private staging; atomic same-filesystem publication only after all members, metadata, signatures, and tags verify; no outer compression. Maximum 64 members, depth 8, path length 1024 UTF-8 bytes, 1 GiB/member, 4 GiB aggregate plaintext, 16 MiB manifest, 64 MiB total format overhead, and 5 GiB complete artifact. Preflight measures the complete allowlisted source set, rejects any member above 1 GiB or aggregate plaintext above 4 GiB, and reserves `max(2 × measured source bytes + 1 GiB, 5 GiB + 1 GiB)`. The 5 GiB artifact maximum is the conservative pre-capture upper bound; enforce the computed reservation as a staging quota so capture aborts before exceeding it. After serialization, verify exact complete artifact size is at most 5 GiB before publication. If the computed reserve exceeds 9 GiB or destination capacity is insufficient, fail before capture. Never cap a reservation below the computed need; reserve the full amount before capture or restore. | Limits archive abuse and disk exhaustion and prevents partial artifacts from appearing complete. Limits may constrain larger installations and require adequate free-space checks. | Architecture authority: senolcolak (PENDING); independent security authority: unassigned and must be a distinct person (PENDING). The reserve cap is raised to 9 GiB so the proposed 4 GiB aggregate can reserve its full computed need; neither value is accepted or measured. The 1 GiB member cap includes the whole SQLite snapshot and the whole PostgreSQL custom dump. Reviewer must confirm measured profile sizes and that the reserve formula can accommodate the encrypted artifact and temporary files; otherwise amend numeric values explicitly. |
| D10 PostgreSQL ownership/object policy | **Amend.** PostgreSQL 16 only; `pg_dump -Fc`, restore with matching `pg_restore --exit-on-error --no-owner --no-acl` into a fresh empty DB under an installation-provisioned non-superuser schema-owner role. Before executing any archive SQL, run unfiltered `pg_restore --list` without a database connection and classify every TOC entry using a version-pinned mapping to the trusted migration-derived inventory: expected migration-owned object, expected data entry, explicitly allowlisted PostgreSQL/tool-generated entry, or forbidden entry. Reject missing, unknown, duplicate or forbidden entries; pin the mapping/generated-entry allowlist and never use blanket metadata ignores. Inert owner metadata does not authorize ownership SQL or waive validation. TOC names alone cannot establish safe SQL definitions: the exact-release definition-validation policy must also be approved before execution. After restore, independently compare the live catalog, definitions, privileges and migration identity before activation. Inventory covers tables, sequences, indexes, constraints, defaults, views and migration-created functions/triggers, distinguishing server-generated catalog objects. Never restore cluster roles/globals, passwords, tablespaces, ACLs, owners or artifact grants; trusted installation policy reapplies grants. Extension allowlist is empty. | Pre-execution inventory validation prevents unlisted objects from executing before drift detection. An allowlisted function/trigger name can still hide changed code; post-restore inspection or restricted-role execution alone is not proof of safe pre-execution definitions. | Architecture authority: senolcolak (PENDING); independent security authority: unassigned (PENDING). Exact grants, migration/object inventory revision and executable-definition verification remain PENDING before #1085. |
| D11 Interruption and post-start failure | **Accept as written.** Before activation, known partial mutation is inactive `FAILED_RECOVERABLE`; unknown outcome, lock loss, or conflict is `QUARANTINED`. After startup, stop/fence dispatch on failure, preserve operation IDs, observe provider/repository state before retry, and use existing reconciliation authority. No in-place repair in v1; only verified discard/recreation reaches `DISCARDED`. Journal states are not canonical Operations or controller state. | Avoids duplicate provider mutations and protects canonical state under ambiguous outcomes. Some cases require explicit operator intervention and a newly reserved target. | Architecture authority: senolcolak (PENDING); independent security authority: unassigned and must be a distinct person (PENDING). Depends on D7–D8 and accepted restart/failure tests in disposable SQLite and PostgreSQL environments. |
| D12 Public interface | **Amend.** An approved, supported exact-release operator invocation and runbook are prerequisites for operational recovery acceptance. #1084–#1086 add no unapproved public CLI/API; separately contract target selection, destructive confirmation, operation/idempotency identity, status/errors, exit behavior, authorization and redaction before exposing an operator surface. This packet accepts no command names, flags or exit codes. | Internal implementation evidence alone cannot demonstrate supported operator recovery. Exact-release binary and immutable artifact must complete the documented fresh-host path, including interruption/lost-response retry and foreign-state preservation. | Architecture authority: senolcolak (PENDING); independent security authority: unassigned (PENDING). The invocation/interface contract and #944 runbook are explicit acceptance dependencies; do not defer their existence until after claiming recovery. |
| D13 Canonical inventory and compatibility | **Accept as written.** Restore one complete control-plane store image at exact release/schema/migration identity. Commit a machine-readable inventory mapping every durable repository registration to tables, including empty repositories and every `audit_events` row. Cover resource/ownership, operations/reconciliation, placement, topology, IAM/security scope, bootstrap/enrollment/revocation, and O3K-owned configuration/release metadata. Reject missing, extra, or unknown entries; schema or migration mismatch; missing trust; foreign/nonempty target; or unproven fencing before canonical mutation. Exclude external VM/storage payloads and provider-owned lifecycle. | Prevents selective restore from creating cross-repository inconsistency and avoids claiming recovery of externally owned state. | Architecture authority: senolcolak (PENDING); independent security authority: unassigned and must be a distinct person (PENDING). Inventory baseline must be generated from accepted migrations/store registrations and human accepted; CI drift check follows that baseline. |

## Proposed amendments (2026-10-16)

### A1–A9 — amendment dispositions

Each status below is a **proposed disposition**, not an accepted amendment.
Review status remains **PENDING** for architecture and security.

| ID | Proposed disposition | Concrete recommendation and security/operational impact | Authority and unresolved dependency |
|---|---|---|---|
| A1 (D4–D5) | **Accept with D4/D5 wording above.** | Offline capture with controller stopped and a newly implemented, tested exclusive startup lock is the v1 consistency barrier. It removes API availability during the capture window but avoids an unproven online barrier. It is not available until that startup invariant exists. | Architecture authority: senolcolak (PENDING); independent security authority: unassigned and must be a distinct person (PENDING). Require implemented lock exclusion, capture-duration, and data-plane-continuity evidence before operational acceptance. |
| A2 (D1–D2) | **Reject the amendment as proposed; replace it with the D1 HPKE recommendation.** | Do not allow provider-native opaque wrapping or an unspecified KMS. Use RFC 9180 HPKE X25519/HKDF-SHA256/AES-256-GCM with fixed encoding and signed context. This preserves portability and avoids provider-specific restore dependencies. | Architecture authority: senolcolak (PENDING); independent security authority: unassigned and must be a distinct person (PENDING). Approve exact envelope fields, HPKE info/AAD context, key IDs, and format version. |
| A3 (D2) | **Amend.** | Use the same operator-held asymmetric custody model for SQLite and PostgreSQL. Encrypt content and sign/authenticate metadata in both profiles; unsigned artifacts are prohibited. Offline private-key copies stay separate from controller and artifact. This avoids KMS dependency but creates key-custody and loss risk. | Architecture authority: senolcolak (PENDING); independent security authority: unassigned and must be a distinct person (PENDING). Approve two-person custody, copy locations/control, rotation, recovery drill and key-loss disposition. |
| A4 (D3) | **Reject.** | Do not preserve issuer continuity using a KMS/HSM. Replace issuer and re-enroll agents for both profiles. Keep revocation state durable and reject old-issuer credentials; this prevents revocation rollback and source issuance after recovery. | Architecture authority: senolcolak (PENDING); independent security authority: unassigned and must be a distinct person (PENDING). #1087 must use replacement/re-enrollment unless a later accepted ADR revises it. |
| A5 (D7) | **Reject.** | Two-person attestation cannot replace independent source exclusion. Require verifiable power/network fencing; if unavailable, keep restore inactive. This may delay recovery when a source is unreachable but avoids split brain. | Architecture authority: senolcolak (PENDING); independent security authority: unassigned and must be a distinct person (PENDING). Name each profile's fencing control and evidence source. |
| A6 (D8) | **Amend with D8.** | Authenticate every forward journal transition using the separate offline Ed25519 journal/evidence key. Permit separate unsigned failure markers only to stop progress; they are untrusted forensic metadata and cannot replace signed phase authorization. A marker cannot authorize activation, recovery, discard or reuse. | Architecture authority: senolcolak (PENDING); independent security authority: unassigned (PENDING). Approve service-user ownership, denial-only marker semantics, offline signing/transfer and crash behavior with D8. |
| A7 (D9) | **Amend.** | Use the exact D9 formula: `max(2 × measured source bytes + 1 GiB, 5 GiB + 1 GiB)`, where 5 GiB is the conservative pre-capture artifact bound and the reservation is also an enforced staging quota. If the computed reservation exceeds 9 GiB, capacity is insufficient, or exact serialized output exceeds 5 GiB, fail without publication; never cap below required capacity. This reserves the artifact maximum and source/temp working space. | Architecture authority: senolcolak (PENDING); independent security authority: unassigned and must be a distinct person (PENDING). Validate formula with measured SQLite/PostgreSQL artifacts and account for all temporary files. |
| A8 (D12) | **Reject the withdrawal/deferral of the interface dependency.** | A separately approved exact-release invocation/interface contract and operator runbook are required before operational recovery acceptance. Track that prerequisite under the existing #1084–#1086/#944 authority; this amendment neither opens a speculative command implementation nor approves command names, flags or exit codes. | Architecture authority: senolcolak (PENDING); independent security authority: unassigned (PENDING). Public CLI/API review is separate from backup internals; both acceptance and exact-artifact operator evidence remain required. |
| A9 (D13) | **Accept conditionally.** | Commit the human-approved inventory and add CI regeneration/comparison from migrations and store registrations. CI must fail on missing, extra, or unknown entries; generation must never silently update the approved baseline. This reduces inventory drift while keeping baseline changes under human control. | Architecture authority: senolcolak (PENDING); independent security authority: unassigned and must be a distinct person (PENDING). Inventory baseline first requires explicit D13 approval. |

## Review amendments awaiting separate decisions (2026-10-17)

These are revised recommendations responding to comment 6239123579, not
acceptance. Proposed dispositions for D1, D3, D5, D6, D11, D13, A1–A5 and A9
are unchanged. A7 follows the corrected D9 reserve cap; A6 and A8 follow the
D8/D12 amendments above.

- **D2 signing:** after capture/encryption, persist one bounded signing request
  identifying the D1 exact signature input, request nonce/ID, manifest digest,
  artifact/key and site identity. Transfer it through operator-controlled
  removable media to the disconnected exact-release signing utility; return a
  detached response. The workstation displays the context and requires human
  confirmation. The verifier checks the configured signing key, exact request,
  input and signature before fsync/publication. Timeout, cancellation or bad
  response safely aborts or retains private encrypted staging; never publish
  unsigned. Resume only the same persisted request and immutable bytes, with
  exclusion re-proven after any interruption. Keep the offline lock through
  signing and safe completion; account for signing in downtime and space.
  Tests: changed bytes/member, wrong nonce/key/digest, expired request, response
  loss and crashes before/after fsync/rename must not publish a partial backup.
- **D4 exclusion:** test every store-opening daemon, CLI and maintenance path,
  supervisor restart races and SQLite WAL cut. PostgreSQL tests must attempt
  remote writer login and retain an existing writer session to prove both are
  blocked before capture; a local lock is insufficient. Missing exclusion or
  inability to inspect sessions fails closed before capture.
- **D7 evidence:** the signer is the D2 offline journal/evidence key holder; the
  verifier is the exact-release target recovery process using a separately
  installed public key. BMC credentials never enter the record or artifact.
  Test TLS/serial/target mismatch, stale/replayed/altered evidence, absent BMC,
  power-on after observation, old-source credentials at every verifier and
  PostgreSQL source-writer reconnect. Reject activation when any check fails;
  preserve foreign state. Demo/TestLab without independent fencing stays
  capture/verify-only. D3 trust replacement is a durable activation condition,
  not permission to discard the independent source-exclusion proof.
- **D8 signing and failures:** keep one durable pending transition request with
  exact operation/artifact/target, nonce/ID, expected next sequence, previous
  signed hash and phase. The disconnected signing utility returns a detached
  response bound to that context; response loss permits exact-request retry
  only. Without signing availability, an owner-checked run may persist an
  unsigned denial-only `QUARANTINED` or pre-start `FAILED_RECOVERABLE` marker
  beside, never inside or replacing, the signed chain. Its presence stops
  progress; its absence proves nothing. It cannot change trusted phase or
  authorize mutation, recovery, activation, deletion or reuse. If safe marker
  persistence is impossible (including lost ownership/lock), preserve the last
  signed state/pending request, report the failure and require independent
  inspection; never write a conflicting journal or assume success. Clearing a
  marker requires a fresh authorized signed recovery disposition and complete
  revalidation. A post-`STARTED` failure stops/fences dispatch through existing
  Operation recovery and cannot become pre-start `FAILED_RECOVERABLE`.
  Keep the target reservation separate from the store/startup guard and hold
  it through terminal state. Before `STARTED`, require a reviewed continuous
  guard handoff to the intended controller; neither release-then-start nor an
  implicit lock bypass is allowed. The exact handoff and crash protocol remain
  PENDING, and must prove unrelated supervisor/CLI processes cannot enter.
  Tests: permission mismatch, absent signer, marker removal/tamper,
  unsigned-forward transition, stale/replayed/forked chain, competing restore,
  lost lock, lost response and each file/rename/directory-fsync boundary.
- **D9 arithmetic and measurements:** recommend raising the reservation cap
  from 8 GiB to **9 GiB**, retaining 4 GiB aggregate and the full formula.
  At 4 GiB, `2 × 4 GiB + 1 GiB = 9 GiB`; no reservation is truncated.
  Measure representative SQLite and PostgreSQL sources, the single database
  member, complete artifact and peak temporary/encryption use before accepting
  these bounds. If measured need exceeds the formula, amend it before approval.
  Tests: 4 GiB aggregate/9 GiB reservation, one byte above every bound, the
  1 GiB database-member boundary, low space and ENOSPC; no partial publication.
- **D10 inventory:** inspect the complete unfiltered `pg_restore --list` before
  target SQL execution, then verify the resulting catalog. Classify every entry
  using a version-pinned mapping: expected migration-owned object, expected
  data entry, explicitly allowlisted PostgreSQL/tool-generated entry, or
  forbidden entry. Pin the generated-entry allowlist and mapping; unknown,
  duplicate or missing entries fail, with no blanket metadata ignore rule.
  Inert archive owner metadata must not authorize ownership SQL; `--no-owner`
  and `--no-acl` remain mandatory and cannot waive inventory validation.
  TOC matching does not check
  function bodies, triggers/default expressions or arbitrary archive SQL;
  changed definitions under approved names must fail before execution under
  the separately approved exact-release definition policy. Exact grants and
  the inventory/definition baseline remain PENDING. Tests cover unknown TOC
  entries, same-name changed function/trigger/default definitions, malformed
  TOC, forbidden roles/ACLs/tablespaces/extensions, restricted-role restore and
  post-restore catalog drift. See the PostgreSQL 16
  [pg_restore documentation](https://www.postgresql.org/docs/16/app-pgrestore.html)
  for the TOC and executable-SQL trust boundary.
- **D12/A8 invocation:** require the separately accepted operator contract and
  #944 runbook before supported recovery. Do not approve speculative command
  names here. Exercise the exact release binary and exact immutable artifact,
  wrong site/release/schema/target, absent key, interruption/lost response,
  idempotent retry, bounded redacted errors and foreign-state preservation.

## Dependencies and implementation gate

The following decisions are independent blockers and must not be inferred from
other approvals:

1. **D8:** offline signing/transfer, service-user journal ownership, denial-only markers, controlled startup handoff, local ext4/kernel behavior and stale-operation recovery authority.
2. **D7:** exact fencing control, fresh verifiable evidence, source/target identity binding, and authorized actor for each profile; source-unreachable disposition.
3. **D9:** measured artifact sizes and accepted staging/free-space limits.
4. **D10:** exact least-privilege PostgreSQL grants, pre-execution TOC/definition
   policy and migration-derived object inventory.
5. **D2:** exact storage-encryption parameters/tool versions, offline custody, rotation, revocation, media integrity, and recovery procedure.
6. **D12:** approved operator path needed to exercise exact-release recovery.

No production backup/restore or security-sensitive PKI implementation may begin
until the relevant decisions above are explicitly accepted in ADR-0189 and
SPEC-0050. A reviewer must copy the accepted or amended values, both role
decisions, date, and exact source revision into those normative documents.
Implementation follows the existing issue order: #1084 SQLite artifact, #1085
PostgreSQL adapter, #1086 fresh-host recovery, then dependent #1087 PKI and #1098
upgrade/recovery work. This packet does not accept evidence, claim PP.6
completion, alter PP.5, or authorize PP.7.

### Approval record — intentionally incomplete

| Role | Named reviewer | Decision | Date | Exact revision reviewed |
|---|---|---|---|---|
| Architecture authority | senolcolak | **PENDING** | — | This packet revision and source commit to be recorded |
| Independent security authority | **Unassigned; must be distinct from architecture authority** | **PENDING** | — | This packet revision and source commit to be recorded |

The two role decisions must explicitly accept, amend, reject, or withdraw each
D1–D13 and A1–A9 recommendation. “Accepted in principle”, a code review alone,
or a decision deferred to implementation does not satisfy this gate.

## Current implementation status

No security-sensitive backup/restore or issuer-key implementation is authorized
while ADR-0189 and SPEC-0050 remain Proposed. Independent diagnostics and
disposable failure-matrix work may continue only under already accepted
contracts. PP.5 scale/soak and physical certification are not part of this
campaign.

Cryptographic references: [RFC 8785, JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785), [RFC 8032, EdDSA](https://www.rfc-editor.org/rfc/rfc8032), and [RFC 9180, Hybrid Public Key Encryption](https://www.rfc-editor.org/rfc/rfc9180). The proposed LUKS2/Argon2id settings should be checked against the [cryptsetup manual](https://gitlab.com/cryptsetup/cryptsetup/-/blob/6ac27f50ad42bb98f87858ccf35200ec2fe3e1ba/man/cryptsetup.8). These references describe proposed mechanisms; they do not constitute O3K architecture/security acceptance.
