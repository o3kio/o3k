# PP.6 backup and restore decision record for approval

**Revision:** 2026-10-18
**Status:** Historical decision packet. Architecture proposal acceptance,
interim review governance and signing modes are recorded below. The later
technical contract acceptance for ADR-0189, SPEC-0050 and the matching schema
at `9ce23ff81218e8e35d917ef6ee4478ae69e8f28e` is recorded in
[`PP6_TECHNICAL_CONTRACT_APPROVAL.md`](PP6_TECHNICAL_CONTRACT_APPROVAL.md).
That exact-revision decision does not accept SPEC-0051, runtime correctness,
release readiness, or production evidence.

**Issue authority:** #975, #640, #1084–#1087, and #1098.
**Profiles:** single-site `o3k-demo-v1` with SQLite and
`o3k-small-edge-v1` with PostgreSQL 16. External VM disks, external storage
payloads, and external-hosted service databases remain outside this recovery
boundary. PP.5 campaigns, HA, multi-region recovery, and PP.7 remain out of
scope.

## Reviewer governance and decision status

The interim reviewer arrangement is accepted by the human decision recorded
under ADR-0190: `senolcolak` is the human architecture and security/technical
reviewer and named risk owner for bounded PP.6 profiles through 2026-11-30 or
the PP.6 final decision, whichever occurs first. This is a non-independent
single-maintainer review; the accepted residual risk is that one reviewer may
miss a defect. The durable URL for this specific decision and protected
integration of ADR-0190 remain pending, so no contract promotion or runtime
gate may rely on this local record yet. Existing release-level human-review
requirements remain applicable. Each contract still requires a separate
exact-revision decision; this governance decision does not accept ADR-0189,
SPEC-0050, SPEC-0051, or runtime behavior. A GitHub PR approval alone does not
constitute contract acceptance.

[Review comment 6239123579](https://github.com/o3kio/o3k/issues/975#issuecomment-6239123579)
is attributed by GitHub to senolcolak and expressly describes itself as review
analysis, not either role's decision. Its body also contains a conflicting
account attribution. Neither attribution is used to infer acceptance. The
amendments below address its findings. The subsequent architecture decision
is recorded below; the exact-revision technical/security decision remains pending
against the exact amended source revision.

On 2026-10-17, senolcolak explicitly wrote **“accept”** in
[decision comment 6239984922](https://github.com/o3kio/o3k/issues/975#issuecomment-6239984922),
responding to [request 6239743723](https://github.com/o3kio/o3k/issues/975#issuecomment-6239743723).
That request identifies the amended D1–D13/A1–A9 backup proposal at
`610f914b4c25112f67798402db8b83c9caf0cf55`.
The [separate PR review](https://github.com/o3kio/o3k/pull/1143#pullrequestreview-5559773466)
corroborates the exact reviewed source; it is not the contract decision.

For every D and A below, **architecture proposal ACCEPTED** means acceptance
of the recommendation and its stated conditions at that revision. It does
not supply missing parameters, accept unexecuted evidence, waive conditional
gates, or constitute independent security or normative contract acceptance.
“Proposed disposition” preserves the accepted proposal's recommendation,
including which earlier amendments it rejects. Missing values and subsequent
amendments require explicit applicable reviewer decisions and must be recorded
in ADR-0189 and SPEC-0050 before the applicable implementation starts.
SPEC-0051's technical decisions remain separate and PENDING.

### Interim governance and signing mode decision (2026-10-18)

The authorized human accepted the interim review arrangement and selected
PostgreSQL Option B and SQLite Option A (where supported) against ADR-0190
revision `d62853bed83b7d5e1b63118a2d17bd48dac2e2aa`; see the [decision
record](../adr/ADR-0190-pp6-interim-single-maintainer-review-gate.md#human-decision-recorded-2026-10-18).
For PostgreSQL, online signing is limited to authenticated backup artifacts
for the configured site/profile and cannot authorize restore, fencing,
restore-journal transitions, or controller activation. Offline recovery and
restore-journal authority remain separate. This selects the mode and scope
only. Concrete signer implementation, custody, rotation, revocation, trust,
recovery, and negative tests remain subject to technical contract decisions.
The matching amendments to ADR-0189 and SPEC-0050 remain Proposed until their
separate exact-revision decisions are recorded; no runtime implementation is
authorized.

## D1–D13 — concrete recommendations

| ID | Proposed disposition and recommendation / implementation parameters | Security and operational impact | Authority, review status, unresolved dependency |
|---|---|---|---|
| D1 Artifact format and authenticity | **Amend.** Versioned regular-file container. Generate a fresh 256-bit CSPRNG content key per artifact; encrypt each allowlisted member with AES-256-GCM and a unique 96-bit CSPRNG nonce. Bind member name, plaintext length, format version, profile, site ID, and artifact ID as RFC 8785 canonical AAD. Sort members by UTF-8 path bytes and reject duplicate paths. Enforce nonce uniqueness per content key across the complete artifact and reject duplicate nonce fields before decryption. The Ed25519 signing key ID must resolve to a non-revoked public key pinned by the separately authenticated trust store. Signature input: `O3K-PP6-BACKUP-MANIFEST-V1\0 || u64be(manifest_length) || canonical_manifest_without_signature || concatenated_member_digests`; each digest entry is `u32be(path_byte_length) || path_bytes || SHA256(ciphertext_and_tag)` in UTF-8 path order. Use RFC 8785 canonical UTF-8 JSON and reject duplicate keys/noncanonical forms. HPKE Base mode RFC 9180 using X25519/HKDF-SHA256/AES-256-GCM wraps the content key to the operator recovery public key; `info` is UTF-8 `O3K-PP6-ARTIFACT-KEY-WRAP-V1\0`, and AAD is canonical JSON containing format version, profile, site ID, artifact ID, and recipient key ID. Record HPKE `enc` and wrapped ciphertext exactly as specified by RFC 9180; signature covers both and recipient key ID. Only structural metadata is cleartext; no tenant rows, credentials, provider payloads, or private keys. No outer compression. Reject unknown versions/algorithms, invalid signatures, bad tags, and malformed lengths before extraction. | Provides confidentiality and source authenticity without putting a secret or unspecified KMS dependency on the controller. Trust-root pinning and revocation are mandatory; AEAD/checksums alone do not establish provenance. | Architecture proposal: senolcolak (ACCEPTED; see approval record); interim security/technical reviewer: senolcolak under ADR-0190 (non-independent; exact-revision decision PENDING). Review must accept exact serialization, signed inputs, HPKE context, and trust-root/revocation path. |
| D2 Key custody, recovery, rotation | **Amend by profile.** PostgreSQL uses online signing only for authenticated backup artifacts for the configured site/profile; it cannot authorize restore, fencing, restore-journal transitions, or activation. SQLite small-edge/TestLab retains Option A offline artifact signing where supported. Offline recovery-key custody and restore-journal authority remain separately protected. No concrete online signer, key type/boundary, request protocol, custody location, trust provisioning, rotation/revocation schedule, or recovery mechanism is selected here. | Online signing removes the per-backup human round trip for PostgreSQL but adds a narrowly scoped online artifact-forgery risk. SQLite Option A retains operator availability and capture downtime constraints. Both modes fail closed on absent or invalid required signing authority; detailed failure semantics await the technical contract. | Human mode decision recorded under ADR-0190 at exact revision `d62853bed83b7d5e1b63118a2d17bd48dac2e2aa`. The concrete signer security contract and its negative tests remain PENDING; do not implement or claim backup runtime. |
| D3 PKI issuer and agent credentials | **Accept as written.** Never include controller issuer or agent private keys in artifacts. Replace the issuer during fresh-host restore, run a new trust ceremony, and re-enroll agents. Before activation, replace old issuer roots in every API, controller, agent, and provider trust path; invalidate cached trust material; preserve durable revocations; and prove a stale credential signed by the old issuer is rejected at each verifier. Regenerate controller runtime identity, sessions, and credentials. | Replacement avoids restoring a revoked credential to validity and avoids turning backup artifacts into fleet credentials. Re-enrollment creates a planned recovery outage and must be included in runbooks. | Architecture proposal: senolcolak (ACCEPTED; see approval record); interim security/technical reviewer: senolcolak under ADR-0190 (non-independent; exact-revision decision PENDING). #1087 depends on accepted issuer replacement, revocation and re-enrollment behavior. |
| D4 Consistent capture boundary | **Amend.** Capture is quiesced for both profiles. Stop all store-opening O3K processes. Every process that opens the store, including `o3kd`, `o3k` CLI paths and maintenance tools, must honor the same exclusive data-directory startup/store-access lock before opening the store or starting readiness, workers, lease renewal or provider dispatch. Backup holds that lock through verified publication or safe abort. **This invariant is not implemented today; the storage execution lock is not a startup lock.** SQLite reuses the supported store snapshot API and WAL/integrity policy; its selected Option A signature is operator-assisted offline. PostgreSQL 16 uses `pg_dump -Fc` and selected Option B online artifact signing; preventing O3K writer-role login and proving zero remaining O3K writer sessions are mandatory independently of local process shutdown and local locks, including controllers on other hosts. Require an exclusively O3K-owned database/schema and no unrelated writers. Bind database/files to one generation and discard staging on exclusion, generation or ownership failure. | The controller API remains unavailable during the capture interval. A local lock cannot fence remote PostgreSQL writers. Online artifact signing removes the offline signing trip but does not change the required capture exclusion. Workload data-plane continuity needs separate profile evidence. | Human mode decision recorded under ADR-0190. Require startup/CLI/supervisor-race tests, mandatory PostgreSQL login/session exclusion, cross-file generation, measured duration and data-plane continuity before support claims. |
| D5 In-flight Operations | **Accept as written.** At shutdown, preserve canonical operation IDs and phases. Terminal operations remain terminal; nonterminal operations are recorded as unresolved and require observe-before-retry after restore. A timeout or shutdown does not become a failure classification and backup never replays a mutation. | Preserves idempotency and compensation authority; unresolved provider outcomes may require operator intervention. | Architecture proposal: senolcolak (ACCEPTED; see approval record); interim security/technical reviewer: senolcolak under ADR-0190 (non-independent; exact-revision decision PENDING). Depends on D4 boundary and existing operation/reconciliation authority. |
| D6 Stable and regenerated identities | **Accept as written.** Preserve site/installation ID, canonical resource IDs, owner/security scopes, provider mappings, bootstrap principal identity, audit history, and revocation records. Regenerate controller process/session identity, leases, controller credentials, and host-local agent credentials. Never restore an active lease or private credential. | Stable resource identities preserve references; fresh controller and host credentials prevent a copied source from retaining authority. | Architecture proposal: senolcolak (ACCEPTED; see approval record); interim security/technical reviewer: senolcolak under ADR-0190 (non-independent; exact-revision decision PENDING). Implementation requires a reviewed schema/migration map for every preserved and regenerated value. |
| D7 Source exclusion and target fencing | **Amend.** Recommend independently administered Redfish/BMC power-off as the initial fencing backend, before restored canonical mutation or provider/API action. An authorized recovery operator observes BMC HTTPS from a trusted recovery host independent of the source, validates the per-site TLS trust anchor and source serial, and transfers identity-bound evidence to the disconnected signer. Sign with the distinct D2 offline Ed25519 **journal/evidence key**, never the artifact or release key; the target recovery verifier uses its separately installed, non-revoked public trust anchor. Bind source/site/target, serial, BMC certificate fingerprint, actor and timestamps; require `PowerState=Off`, age at most five minutes, and a fresh authenticated BMC observation before activation. Signature alone is not independent fence evidence or BMC hardware-signed telemetry. Without a verified fence, stay inactive. | Redfish power state is point-in-time evidence. Retain independent source exclusion and require D3 issuer replacement, rejection of old source credentials at every verifier, fresh target ownership epoch and, for PostgreSQL, target-only writer access as durable activation gates. Do not release fencing merely because a lease expired. Without independent BMC, Demo/TestLab v1 is limited to capture/verify, with fresh-host activation unsupported. No network-fencing backend is implicitly supported. | Architecture proposal: senolcolak (ACCEPTED; see approval record); interim security/technical reviewer: senolcolak under ADR-0190 (non-independent; exact-revision decision PENDING). Accept the Demo/TestLab limitation; name the operator/custodians, supported BMC/system identities and tested Redfish/TLS deployment. A network-isolation backend requires its own accepted mechanism/evidence. Neither a signed assertion nor two-person attestation substitutes for independent exclusion. |
| D8 Restore journal and reservation | **Amend; implementation remains blocked on exact signing and startup-handoff contracts.** Use a dedicated `o3k:o3k` recovery directory (0700; journal/requests/markers 0600) outside the target DB on Linux ext4 over local block storage, compatible with the packaged service user. Reject NFS, overlay/ephemeral and unverified network volumes. Create reserved files with `O_EXCL`/`O_NOFOLLOW` under an owner-checked directory and retain the exclusive target reservation through terminal state. Sign `O3K-PP6-RESTORE-JOURNAL-V1\0 || u64be(record_length) || RFC8785(record_without_signature)` with the separate D2 offline Ed25519 journal/evidence key; use unpadded base64url signatures. Sequence starts at 1, increases by one and chains prior signed-record SHA-256, artifact/site/source/target, operation/step and phase. Persist with file fsync, same-directory atomic rename and directory fsync. Legal phases: `PREFLIGHTED → SOURCE_FENCED → TARGET_RESERVED → STAGING → DATABASE_RESTORED → FILES_RESTORED → TARGET_FENCED → STARTED → RECONCILED → COMMITTED`; pre-mutation abort is `ABORTED`, known pre-start partial is `FAILED_RECOVERABLE`, unknown/lock-loss/conflict is `QUARANTINED`, and only verified discard/recreation permits `DISCARDED`. See review amendments below for signing, denial-only markers and separate reservation/startup locks. | Every forward phase requires an offline operator signature, roughly ten signing round-trips for a successful restore, including live-controller reconciliation/commit. Signatures attest the journal bytes; they do not protect the restored database from a target-root attacker. Unsigned failure markers can only deny progress and never authorize restore, activation, retry, discard or a forward transition. Foreign/nonempty state is preserved. | Architecture proposal: senolcolak (ACCEPTED; see approval record); interim security/technical reviewer: senolcolak under ADR-0190 (non-independent; exact-revision decision PENDING). Confirm owner/path/kernel/filesystem, signing-tool and transfer contract, controlled startup handoff, finite signing deadline and stale-operation recovery role. No private key is copied to the target. Reacquiring a free OS lock does not authorize deletion/reuse of an old journal. |
| D9 Artifact bounds/publication | **Amend.** Closed regular-file allowlist; reject links, devices, sparse files, path traversal, duplicate names, and unknown members. No-follow private staging; atomic same-filesystem publication only after all members, metadata, signatures, and tags verify; no outer compression. Maximum 64 members, depth 8, path length 1024 UTF-8 bytes, 1 GiB/member, 4 GiB aggregate plaintext, 16 MiB manifest, 64 MiB total format overhead, and 5 GiB complete artifact. Preflight measures the complete allowlisted source set, rejects any member above 1 GiB or aggregate plaintext above 4 GiB, and reserves `max(2 × measured source bytes + 1 GiB, 5 GiB + 1 GiB)`. The 5 GiB artifact maximum is the conservative pre-capture upper bound; enforce the computed reservation as a staging quota so capture aborts before exceeding it. After serialization, verify exact complete artifact size is at most 5 GiB before publication. If the computed reserve exceeds 9 GiB or destination capacity is insufficient, fail before capture. Never cap a reservation below the computed need; reserve the full amount before capture or restore. | Limits archive abuse and disk exhaustion and prevents partial artifacts from appearing complete. Limits may constrain larger installations and require adequate free-space checks. | Architecture proposal: senolcolak (ACCEPTED; see approval record); interim security/technical reviewer: senolcolak under ADR-0190 (non-independent; exact-revision decision PENDING). The reserve cap is raised to 9 GiB so the proposed 4 GiB aggregate can reserve its full computed need; architecture accepts these proposed bounds; measurements and the exact-revision non-independent security/technical decision under ADR-0190 remain pending; no independent security approval is claimed. The 1 GiB member cap includes the whole SQLite snapshot and the whole PostgreSQL custom dump. Reviewer must confirm measured profile sizes and that the reserve formula can accommodate the encrypted artifact and temporary files; otherwise amend numeric values explicitly. |
| D10 PostgreSQL ownership/object policy | **Amend.** PostgreSQL 16 only; `pg_dump -Fc`, restore with matching `pg_restore --exit-on-error --no-owner --no-acl` into a fresh empty DB under an installation-provisioned non-superuser schema-owner role. Before executing any archive SQL, run unfiltered `pg_restore --list` without a database connection and classify every TOC entry using a version-pinned mapping to the trusted migration-derived inventory: expected migration-owned object, expected data entry, explicitly allowlisted PostgreSQL/tool-generated entry, or forbidden entry. Reject missing, unknown, duplicate or forbidden entries; pin the mapping/generated-entry allowlist and never use blanket metadata ignores. Inert owner metadata does not authorize ownership SQL or waive validation. TOC names alone cannot establish safe SQL definitions: the exact-release definition-validation policy must also be approved before execution. After restore, independently compare the live catalog, definitions, privileges and migration identity before activation. Inventory covers tables, sequences, indexes, constraints, defaults, views and migration-created functions/triggers, distinguishing server-generated catalog objects. Never restore cluster roles/globals, passwords, tablespaces, ACLs, owners or artifact grants; trusted installation policy reapplies grants. Extension allowlist is empty. | Pre-execution inventory validation prevents unlisted objects from executing before drift detection. An allowlisted function/trigger name can still hide changed code; post-restore inspection or restricted-role execution alone is not proof of safe pre-execution definitions. | Architecture proposal: senolcolak (ACCEPTED; see approval record); interim security/technical reviewer: senolcolak under ADR-0190 (non-independent; exact-revision decision PENDING). Exact grants, migration/object inventory revision and executable-definition verification remain PENDING before #1085. |
| D11 Interruption and post-start failure | **Accept as written.** Before activation, known partial mutation is inactive `FAILED_RECOVERABLE`; unknown outcome, lock loss, or conflict is `QUARANTINED`. After startup, stop/fence dispatch on failure, preserve operation IDs, observe provider/repository state before retry, and use existing reconciliation authority. No in-place repair in v1; only verified discard/recreation reaches `DISCARDED`. Journal states are not canonical Operations or controller state. | Avoids duplicate provider mutations and protects canonical state under ambiguous outcomes. Some cases require explicit operator intervention and a newly reserved target. | Architecture proposal: senolcolak (ACCEPTED; see approval record); interim security/technical reviewer: senolcolak under ADR-0190 (non-independent; exact-revision decision PENDING). Depends on D7–D8 and accepted restart/failure tests in disposable SQLite and PostgreSQL environments. |
| D12 Public interface | **Amend.** An approved, supported exact-release operator invocation and runbook are prerequisites for operational recovery acceptance. #1084–#1086 add no unapproved public CLI/API; separately contract target selection, destructive confirmation, operation/idempotency identity, status/errors, exit behavior, authorization and redaction before exposing an operator surface. This packet accepts no command names, flags or exit codes. | Internal implementation evidence alone cannot demonstrate supported operator recovery. Exact-release binary and immutable artifact must complete the documented fresh-host path, including interruption/lost-response retry and foreign-state preservation. | Architecture proposal: senolcolak (ACCEPTED; see approval record); interim security/technical reviewer: senolcolak under ADR-0190 (non-independent; exact-revision decision PENDING). The invocation/interface contract and #944 runbook are explicit acceptance dependencies; do not defer their existence until after claiming recovery. |
| D13 Canonical inventory and compatibility | **Accept as written.** Restore one complete control-plane store image at exact release/schema/migration identity. Commit a machine-readable inventory mapping every durable repository registration to tables, including empty repositories and every `audit_events` row. Cover resource/ownership, operations/reconciliation, placement, topology, IAM/security scope, bootstrap/enrollment/revocation, and O3K-owned configuration/release metadata. Reject missing, extra, or unknown entries; schema or migration mismatch; missing trust; foreign/nonempty target; or unproven fencing before canonical mutation. Exclude external VM/storage payloads and provider-owned lifecycle. | Prevents selective restore from creating cross-repository inconsistency and avoids claiming recovery of externally owned state. | Architecture proposal: senolcolak (ACCEPTED; see approval record); interim security/technical reviewer: senolcolak under ADR-0190 (non-independent; exact-revision decision PENDING). Inventory baseline must be generated from accepted migrations/store registrations and human accepted; CI drift check follows that baseline. |

## Proposed amendments (2026-10-16)

### A1–A9 — amendment dispositions

Each status below preserves the **proposed disposition** accepted by architecture
at the recorded revision, including its conditions. The interim security/
technical review route is non-independent under ADR-0190; exact-revision
contract decisions and unresolved implementation conditions remain **PENDING**.

| ID | Proposed disposition | Concrete recommendation and security/operational impact | Authority and unresolved dependency |
|---|---|---|---|
| A1 (D4–D5) | **Accept with D4/D5 wording above.** | Offline capture with controller stopped and a newly implemented, tested exclusive startup lock is the v1 consistency barrier. It removes API availability during the capture window but avoids an unproven online barrier. It is not available until that startup invariant exists. | Architecture proposal: senolcolak (ACCEPTED; see approval record); interim security/technical reviewer: senolcolak under ADR-0190 (non-independent; exact-revision decision PENDING). Require implemented lock exclusion, capture-duration, and data-plane-continuity evidence before operational acceptance. |
| A2 (D1–D2) | **Reject the amendment as proposed; replace it with the D1 HPKE recommendation.** | Do not allow provider-native opaque wrapping or an unspecified KMS. Use RFC 9180 HPKE X25519/HKDF-SHA256/AES-256-GCM with fixed encoding and signed context. This preserves portability and avoids provider-specific restore dependencies. | Architecture proposal: senolcolak (ACCEPTED; see approval record); interim security/technical reviewer: senolcolak under ADR-0190 (non-independent; exact-revision decision PENDING). Approve exact envelope fields, HPKE info/AAD context, key IDs, and format version. |
| A3 (D2) | **Amend by profile.** | Encrypt payload and authenticate metadata in both profiles. PostgreSQL uses the selected bounded online artifact-signing mode; SQLite retains offline artifact signing where supported. Offline recovery and restore-journal authorities remain separate; their exact custody and recovery procedures remain unresolved. | Mode decision recorded under ADR-0190. Approve and implement the concrete signer/trust/custody lifecycle and failure tests through the separate exact-revision technical contract decision. |
| A4 (D3) | **Reject.** | Do not preserve issuer continuity using a KMS/HSM. Replace issuer and re-enroll agents for both profiles. Keep revocation state durable and reject old-issuer credentials; this prevents revocation rollback and source issuance after recovery. | Architecture proposal: senolcolak (ACCEPTED; see approval record); interim security/technical reviewer: senolcolak under ADR-0190 (non-independent; exact-revision decision PENDING). #1087 must use replacement/re-enrollment unless a later accepted ADR revises it. |
| A5 (D7) | **Reject.** | Two-person attestation cannot replace independent source exclusion. Require verifiable power/network fencing; if unavailable, keep restore inactive. This may delay recovery when a source is unreachable but avoids split brain. | Architecture proposal: senolcolak (ACCEPTED; see approval record); interim security/technical reviewer: senolcolak under ADR-0190 (non-independent; exact-revision decision PENDING). Name each profile's fencing control and evidence source. |
| A6 (D8) | **Amend with D8.** | Authenticate every forward journal transition using the separate offline Ed25519 journal/evidence key. Permit separate unsigned failure markers only to stop progress; they are untrusted forensic metadata and cannot replace signed phase authorization. A marker cannot authorize activation, recovery, discard or reuse. | Architecture proposal: senolcolak (ACCEPTED; see approval record); interim security/technical reviewer: senolcolak under ADR-0190 (non-independent; exact-revision decision PENDING). Approve service-user ownership, denial-only marker semantics, offline signing/transfer and crash behavior with D8. |
| A7 (D9) | **Amend.** | Use the exact D9 formula: `max(2 × measured source bytes + 1 GiB, 5 GiB + 1 GiB)`, where 5 GiB is the conservative pre-capture artifact bound and the reservation is also an enforced staging quota. If the computed reservation exceeds 9 GiB, capacity is insufficient, or exact serialized output exceeds 5 GiB, fail without publication; never cap below required capacity. This reserves the artifact maximum and source/temp working space. | Architecture proposal: senolcolak (ACCEPTED; see approval record); interim security/technical reviewer: senolcolak under ADR-0190 (non-independent; exact-revision decision PENDING). Validate formula with measured SQLite/PostgreSQL artifacts and account for all temporary files. |
| A8 (D12) | **Reject the withdrawal/deferral of the interface dependency.** | A separately approved exact-release invocation/interface contract and operator runbook are required before operational recovery acceptance. Track that prerequisite under the existing #1084–#1086/#944 authority; this amendment neither opens a speculative command implementation nor approves command names, flags or exit codes. | Architecture proposal: senolcolak (ACCEPTED; see approval record); interim security/technical reviewer: senolcolak under ADR-0190 (non-independent; exact-revision decision PENDING). Public CLI/API review is separate from backup internals; both acceptance and exact-artifact operator evidence remain required. |
| A9 (D13) | **Accept conditionally.** | Commit the human-approved inventory and add CI regeneration/comparison from migrations and store registrations. CI must fail on missing, extra, or unknown entries; generation must never silently update the approved baseline. This reduces inventory drift while keeping baseline changes under human control. | Architecture proposal: senolcolak (ACCEPTED; see approval record); interim security/technical reviewer: senolcolak under ADR-0190 (non-independent; exact-revision decision PENDING). Inventory baseline first requires explicit D13 approval. |

## Review amendments (2026-10-17)

These recommendations respond to review-analysis comment 6239123579, which
was not an acceptance. Architecture subsequently accepted the amended proposal
at the revision in the approval record. ADR-0190 now permits bounded, explicitly
non-independent security/technical review by `senolcolak`; the exact-revision
contract decision, durable decision URL and protected integration remain
pending, and no independent review is claimed. Proposed dispositions for D1, D3, D5, D6, D11, D13, A1–A5 and A9
are unchanged. A7 follows the corrected D9 reserve cap; A6 and A8 follow the
D8/D12 amendments above.

- **D2 signing:** apply profile-specific signing. PostgreSQL 16 uses the
  selected bounded online artifact signer only for authenticated backup
  artifacts bound to the configured site/profile; SQLite retains the Option A
  operator-assisted offline artifact-signing round trip where supported. In
  either profile, persist a bounded request bound to the exact D1 signature
  input, nonce/ID, manifest digest, artifact/key and site identity. Verify the
  configured key, exact request, input and signature before fsync/publication.
  Timeout, cancellation, wrong key, lost response or incomplete publication
  must fail closed; retry only the exact request and immutable bytes after
  re-proving exclusion. The PostgreSQL online authority cannot sign restore,
  fencing, journal transitions or activation. Offline recovery and journal
  authority remain separate. Tests: tampering, wrong key/digest, replay,
  key rotation/revocation, missing custody material, interrupted signing,
  signing response loss, and crashes before/after fsync/rename must never
  publish an unauthenticated or partial artifact. Concrete signer protocol,
  trust, custody and lifecycle decisions remain pending.
- **D4 exclusion:** test every store-opening daemon, CLI and maintenance path,
  supervisor restart races and SQLite WAL cut. PostgreSQL tests must attempt
  remote writer login, Unix-socket reconnect and an existing writer session
  to prove all are blocked before capture. The first-match HBA barrier rejects
  every local socket connection after one already-open control session is used
  to inspect and close out existing sessions; the barrier then proves that
  control session is gone and only the remote dump session remains. A local
  lock is insufficient. Missing exclusion or inability to inspect sessions
  fails closed before capture.
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

The consolidated technical defaults, prototype and exact-revision review
request are now submitted in
[`PP6_TECHNICAL_CONTRACT_APPROVAL.md`](PP6_TECHNICAL_CONTRACT_APPROVAL.md).
The remaining gate is the explicit technical decision against that exact
source revision and its protected integration; ADR-0190 governance and the
PostgreSQL Option B / SQLite Option A mode decisions are already settled and
are not repeated here. The prototype does not authorize runtime.

The following implementation-critical decisions have concrete defaults
submitted but are not yet technically accepted:

1. **D2:** validate proposed signer/HSM and trust/custody prototype assumptions against the actual protected deployment before runtime.
2. **D4/D7/D8:** implement and exercise local startup exclusion, independent BMC fencing, signed journal and controlled startup handoff; the Python model is policy-only.
3. **D9:** existing empty-schema size measurements do not establish production artifact/peak staging sizes; measure real source data before capture and retain the hard limits.
4. **D10/D13:** generate the migration/repository inventory and least-privilege grants from current store registrations, then validate against real isolated PostgreSQL 16 archive and catalogs.
5. **D12:** implement only after the command surface is accepted; verify the exact release command and runbook on disposable fresh hosts.

No production backup/restore or security-sensitive PKI implementation may begin
until the complete technical package is explicitly accepted in ADR-0189 and
SPEC-0050 at the exact revision. The reviewer must record decision, conditions,
date and full source revision in the normative documents and protected review.
Implementation follows the existing issue order: #1084 SQLite artifact, #1085
PostgreSQL adapter, #1086 fresh-host recovery, then dependent #1087 PKI and #1098
upgrade/recovery work. This packet does not accept evidence, claim PP.6
completion, alter PP.5, or authorize PP.7.

### Architecture proposal and interim governance records

| Role | Named reviewer | Decision | Date | Exact revision reviewed |
|---|---|---|---|---|
| Architecture authority | senolcolak | **Proposal ACCEPTED; stated conditions retained** ([decision](https://github.com/o3kio/o3k/issues/975#issuecomment-6239984922)) | 2026-10-17 | `610f914b4c25112f67798402db8b83c9caf0cf55` |
| Interim security/technical reviewer (non-independent) | senolcolak, named risk owner under ADR-0190 | Interim arrangement ACCEPTED; durable decision URL and protected integration PENDING | 2026-10-18 | ADR-0190 proposal `d62853bed83b7d5e1b63118a2d17bd48dac2e2aa`; this packet's contract decisions require separate exact-revision records |

Later technical amendments do not inherit acceptance from the recorded
revision; they require explicit applicable reviewer decisions.

Architecture proposal acceptance covers D1–D13/A1–A9 as amended at the recorded
revision. ADR-0190 permits only bounded, explicitly non-independent
security/technical decisions by `senolcolak`; it does not claim independent
security approval. The durable URL for the interim decision and protected
integration remain pending, and each contract still needs a separate
exact-revision decision. ADR-0099 release-level human review remains
applicable. Missing parameters and evidence require their own resolution
before normative acceptance. “Accepted in principle”, a code review alone, or
a decision deferred to implementation does not satisfy the implementation
gate.

## Current implementation status

No security-sensitive backup/restore or issuer-key implementation is authorized
while ADR-0189 and SPEC-0050 remain Proposed. Independent diagnostics and
disposable failure-matrix work may continue only under already accepted
contracts. PP.5 scale/soak and physical certification are not part of this
campaign.

Cryptographic references: [RFC 8785, JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785), [RFC 8032, EdDSA](https://www.rfc-editor.org/rfc/rfc8032), and [RFC 9180, Hybrid Public Key Encryption](https://www.rfc-editor.org/rfc/rfc9180). The proposed LUKS2/Argon2id settings should be checked against the [cryptsetup manual](https://gitlab.com/cryptsetup/cryptsetup/-/blob/6ac27f50ad42bb98f87858ccf35200ec2fe3e1ba/man/cryptsetup.8). These references describe proposed mechanisms; they do not constitute O3K architecture/security acceptance.
