# PP.6 backup and restore decision packet

Status: approval packet for #975, #640, and implementation issues #1084–#1086.
This packet proposes decisions; it does not accept ADR-0189 or SPEC-0050 and
does not authorize implementation. The reviewer must record an explicit
decision against each item below in ADR-0189 and update SPEC-0050 accordingly.

Profile: single-site `o3k-demo-v1` SQLite where retained and
`o3k-small-edge-v1` PostgreSQL 16. External VM disks, external storage payloads
and external-hosted service databases remain outside this recovery boundary.
PP.5 campaigns, HA, multi-region recovery and PP.7 remain outside scope.

## Decisions requested

| ID | Recommended decision | Alternatives and why they are rejected | Security and implementation consequence |
| --- | --- | --- | --- |
| D1 Artifact encryption and authentication | One versioned regular-file container; encrypt the complete payload with an operator-provided data key using an established AEAD and authenticate the canonical manifest and ciphertext digests with a separate backup signing key. Before implementation, reviewers must record exact algorithms, key sizes, nonce generation, envelope fields, canonical encoding, signature algorithm and verification rules in SPEC-0050. | Plaintext plus checksums does not protect confidentiality or authenticate provenance. Release-signing keys couple separate trust domains. A home-grown crypto format adds avoidable failure modes. | Unsupported algorithms, duplicate JSON keys, noncanonical encodings and unknown format versions fail before extraction. No implementation starts with crypto details left as a future choice. |
| D2 Key custody, recovery and rotation | Keep encryption, signing and journal-authentication keys outside the artifact and backup destination, under operator-managed protected custody. Provision trust roots independently. Define key identifiers, rotation overlap, revocation, retirement and recovery for each key class before implementation; retain decrypt capability for every retained artifact. | Adjacent key files make one theft expose both data and key. Deriving keys from installation IDs is not secret. Release keys broaden blast radius. | Loss of a decrypt key makes affected backups unusable; loss/revocation of trust roots prevents verification. Journal verification after host replacement must use an independently provisioned trust path. The approval record must define tested key recovery and rotation. |
| D3 Issuer private-key recovery | Never export agent private keys. Do not include issuer private keys in backup by default. Require an independently protected issuer recovery key or replace the issuer after restore and re-enroll hosts through the accepted enrollment flow. | Bundling issuer private keys turns every artifact into a fleet credential. Silent issuer regeneration strands existing hosts or risks accepting stale identities. | Restore preflight checks the chosen recovery route. Replacement invalidates old credentials and requires a bounded enrollment journey; no API/provider dispatch before trust readiness. Select custody, trust overlap and re-enrollment semantics. |
| D4 Cross-file consistency and quiescence | Hold the current controller's valid lease/epoch throughout the snapshot while mutating API admission, background workers and provider dispatch are paused; do not relinquish or renew into a new epoch during the cut. Bind every member to the same observed lease generation and quiescence generation. If lease validity or generation changes, abort and discard staging. Resume workers only after the snapshot is committed or safely aborted. | A DB snapshot plus separately copied files can represent different installations. Pausing workers without retaining stable fenced ownership allows another controller to take over during the cut. | The review must accept a concrete barrier implementation and crash behavior. A process crash releases/expirs ownership; no artifact from an incomplete barrier is committed. A backup-specific generation remains evidence metadata, not canonical state. |
| D5 In-flight Operations | Drain operations that can reach a stable terminal boundary. Preserve stable IDs and phases for remaining work only when the existing contract marks them unresolved/unknown and restore is required to observe before retry. Never classify timeout as failure or replay a mutation from backup creation. | Blindly snapshotting mid-dispatch can duplicate provider mutations; rejecting all nonterminal work can make ordinary backup unavailable indefinitely. | The manifest records the operation boundary without provider payloads. Restore starts with dispatch disabled, observes each unresolved operation, and uses existing Operation authority for retry/compensation. |
| D6 Installation/site and controller identity | Preserve installation/site ID, canonical resource IDs, ownership scopes, provider mappings and bootstrap identity records required by the accepted store contract. Regenerate controller process/session IDs, active leases, controller credentials and host-local agent credentials on fresh-host recovery. Agent public certificate fingerprints/revocation state are restored only as trust records; private keys remain host-local. | Regenerating site/resource IDs breaks durable references. Preserving controller or host credentials lets copied/surviving processes act with stale authority. | SPEC-0050 must enumerate exact stable and regenerated fields from the durable schemas before implementation. No restored lease/session is active. |
| D7 Old-controller fencing and activation | SQLite Demo/TestLab: require the source `o3kd` service stopped and its host powered off or isolated from provider/control networks under an operator-verified procedure before a fresh host can activate. PostgreSQL Small Edge: require an independently enforced source-host fence plus a fresh database-backed controller lease/epoch; lease expiry alone is insufficient. If proof is unavailable, target remains inactive. | Waiting only for lease expiry leaves split-brain risk during partitions. A local journal cannot fence a live source host. | Reviewers must accept the exact evidence and trusted actor that establish each profile's fence, including what happens when the source host is unreachable. No API write, provider dispatch or reconciliation occurs before both source exclusion and new ownership are proved. |
| D8 Restore journal and target reservation | Store an authenticated, owner-only journal outside the target DB on the target host, binding operation ID, artifact digest, target identity and phase. Authenticate it with a separately provisioned journal key/trust root whose custody, rotation and fresh-host recovery are defined by D2. Hold an exclusive OS-level reservation from preflight through activation and recheck ownership/emptiness while holding it. | A journal inside the DB disappears with partial DB restore. Unprotected shared journal can be forged. Preflight without reservation permits TOCTOU population. | Ambiguous, unverifiable or conflicting journal state fails closed. Journal loss after mutation requires quarantine and explicit discard/recovery. Define owner, permissions, atomic update/fsync behavior and recovery tooling. |
| D9 Archive and publication safety | Use a closed member allowlist in one regular-file artifact, no links/devices/sparse entries, no-follow private staging, atomic same-filesystem publication after fsync and full verification. Disable compression in v1. Before implementation, record numeric limits for member count, path depth, each member, aggregate ciphertext and plaintext, and staging reservation. Require free staging space for the configured maximum plus safety margin before starting. | General-purpose archive extraction expands path/link attacks and decompression bombs. Publishing before verification exposes partial artifacts. | Limit violations fail before target mutation. Retries validate the existing artifact and never overwrite different content. Exact numeric limits and reservation margin are acceptance blockers, not runtime tuning left to implementation. |
| D10 PostgreSQL role/object policy | Require PostgreSQL 16 custom format via `pg_dump -Fc`; restore with matching `pg_restore --exit-on-error --no-owner --no-acl` (or verified equivalent) into a newly provisioned empty database using an installation-provisioned least-privilege role. Maintain an explicit extension/object allowlist. Do not restore cluster roles/globals, passwords, ACLs, tablespaces or artifact-controlled ownership. | `PGDATA` copying lacks a portable consistency boundary. `pg_dumpall` crosses database/role authority. Default owner/ACL replay grants artifact-controlled privilege. | Real PostgreSQL lane must validate tool/server versions and prove rejected/blocked privileged objects cannot alter the target. Partial restore is quarantined, never activated. Define exact grants and extension list. |
| D11 Post-start failure and reconciliation | `FAILED_RECOVERABLE` is a restore-journal phase only, not an Operation or canonical controller state. Before controller startup, partial/unknown target mutation remains inactive and quarantined until verified discard/recreation or an explicitly approved idempotent recovery. After startup, use existing controller/Operation recovery: stop/fence new dispatch, retain canonical Operation IDs, observe before retry, and record bounded operator action. | Treating every failure as discardable can erase canonical outcomes after provider mutation. Blind retry can duplicate external resources. | Approval must specify journal transitions and restart behavior while preserving existing Operation authority. No parallel lifecycle state is created in the cloud database. |
| D12 Public interface | Keep #1084–#1086 internal and add no CLI/API in those slices. If PP.6 needs operator commands, review a separate `o3k backup`/`restore` contract defining preflight, explicit target, confirmations, idempotency, status/error JSON, exit codes and redaction. | An undocumented command makes recovery behavior and destructive boundaries ambiguous. A new API adds compatibility and authorization scope before needed. | No new public surface is authorized now. Documentation must describe only tested operator invocation after interface approval. |
| D13 Identity inventory and failure posture | Restore the complete accepted canonical store image, including all durable repositories and every row in the canonical `audit_events` authority; include resources, Operations, Placement, topology, BuildingBlocks, IAM/bootstrap/revocation state. Treat missing trust material, incompatible schema/migrations, unknown migration identity, foreign/nonempty target or unproven source fencing as pre-mutation failure. External payloads are excluded and disclosed. | Selective table restore can create invalid cross-repository state. Best-effort activation with incomplete trust or schema risks split authority. | Validate repository invariants before activation. Require fresh SQLite and real PostgreSQL parity evidence, interrupted-phase recovery, foreign-state preservation and secret scans. |

## Exact approval record requested

Architecture and security reviewers should add a dated record to ADR-0189 and
update SPEC-0050 with this wording only after all listed approval conditions
are resolved with concrete values and profile-specific mechanisms. The wording
must not be used while any condition remains open:

> **PP.6 backup/restore decision — accepted for bounded implementation.** We
> accept decisions D1–D13 in `docs/pp/PP6_BACKUP_RESTORE_DECISION_PACKET.md`
> as amended in this review record. The review record includes exact
> cryptographic algorithms/envelope/canonical encoding, key and journal-key
> custody/recovery/rotation, numeric archive and staging limits, the quiescence
> and lease state machine, profile-specific source fencing proofs, durable
> journal transitions, exact stable/regenerated identity inventory, the full
> `audit_events` inventory, PostgreSQL grants/extensions/object allowlist, and
> post-start recovery states. No unresolved condition is deferred to
> implementation. The accepted scope is single-site
> `o3k-demo-v1` SQLite where retained and `o3k-small-edge-v1` PostgreSQL 16.
> Implementation must preserve the specified authority boundaries and fail
> closed where authenticity, consistency, target ownership, schema/trust
> readiness or source fencing cannot be proven. This decision authorizes only
> the ordered implementation issues #1084, #1085 and #1086 after each issue's
> dependencies are met. It does not accept unexecuted evidence, claim PP.6
> completion, alter PP.5, or authorize PP.7.

The review record must name approvers, date, exact ADR/SPEC revision, each
amended decision ID, all exact values and mechanisms, and any evidence required
to show readiness. D1–D13 acceptance does not authorize implementation if any
cryptographic, key recovery, lease/fencing, numeric-limit, PostgreSQL privilege,
or recovery transition detail is still open. A PR merge or approval without
this decision record does not satisfy #1084–#1087's architecture/security gate.

## Current implementation status

No security-sensitive backup/restore or issuer-key implementation is authorized
while ADR-0189 and SPEC-0050 remain Proposed. Independent diagnostics and
disposable failure-matrix work may proceed under accepted contracts. No PP.5
scale/soak or physical campaign is included.
