# #1088 PP.6 operator signal inventory

Status: inventory for [#1088](https://github.com/o3kio/o3k/issues/1088),
recorded 2026-10-16. It maps each area #1088 names to the operator signals
that exist today and their gaps. It is not acceptance evidence and does not
close #1088.

Signal sources:

- **Diagnostics API**: the accepted SPEC-0045 native projection,
  `GET /o3k/v1/operator/diagnostics` plus `/services`, `/providers` and
  `/capacity`. System-scope `operator` role only, read-only.
- **Doctor**: `o3k doctor` checks, by check ID. These are read-only and
  host-local, with output defined by `contracts/o3k-doctor-output.schema.json`.

| Area | Diagnostics API | Doctor checks | Gaps |
| --- | --- | --- | --- |
| API surface | `services` lifecycle status (SPEC-0045 §5) | `control.healthz`, `control.readyz` (JSON `status` parsed), `cloud.api_discovery` | No request latency or error-rate signal: `o3kd` has no `/metrics` surface (ADR-0182 E2D-11). |
| Operations / reconciliation | Not projected: Operation/Audit correlation is a SPEC-0045 §9 non-goal | `controller.work_fencing` (work leases and fencing tokens) | No operation backlog, reconciliation lag or failure-rate signal. The durable Audit path (SPEC-0042) remains the correlation channel. |
| Store / backend | `summary.control_plane` from active `controller_sessions` leases | SQLite: `database.accessible`, `database.integrity` (`quick_check`), `database.wal_mode`, `database.permissions`. PostgreSQL: `database.accessible` (read-only `SELECT 1`), `database.integrity` (no failed `_sqlx_migrations` rows), `database.permissions`; `controller.session` and `controller.work_fencing` read both backends. | On PostgreSQL, `compute.*` placement checks and `cloud.testvm_status` are not applicable: they read the SQLite file only. |
| Placement | `providers` (availability and capacity per provider), `capacity` (aggregate dimensions) | `compute.placement_consistent`, `compute.agent_capabilities` (SQLite only) | No Placement signal from doctor on PostgreSQL. |
| Topology / BuildingBlocks | `summary.locations` (configured regions and availability domains) | None | No BuildingBlock signal in either source. |
| Agents | `providers` availability and observation time (`AgentNodeRegistry`) | `compute.agent_registered`, `compute.agent_epoch`, `services.compute_unit`, `libvirt.*`, `security.tls_identity`; `o3k-compute` serves its own `/metrics` | None beyond the metrics gap above. |
| Upgrade | None | `release.version`, `release.binary_set_consistent`, `release.binary_hashes`, `release.ownership_manifest`, `release.upgrade_state`, `release.backup_available` | `release.backup_available` covers the local upgrade rollback backup only, not PP.6 backup/restore. |
| Backup / restore | None | None | Gated: ADR-0189/SPEC-0050 are Proposed and #1084–#1086 have no implementation. |
| PKI | None | `security.tls_identity` (mounted identity and fingerprint) | Renewal, expiry, revocation and replacement state are gated on #1087. |
| Support bundle | Proposed SPEC-0051 (diagnostics and identity only in v1) | None | Not implemented; SPEC-0051 is Proposed. |

## Redaction state

- **Diagnostics:** errors carry only bounded categories and the caller's
  request ID (#1130).
- **Doctor database checks:** driver text is withheld for the `database.*`
  checks (#1101) and for every canonical row read, plus PostgreSQL
  reachability and migration queries (`pp6/decision-followups` branch).
- **`o3kd` configuration errors:** never echo a positional argument
  (`pp6/decision-followups` branch).
- **Covering tests:** each of the above has tests that feed a sentinel secret
  through the failure path and assert it is absent from output.

## Remaining work for #1088

1. An accepted metrics contract for `o3kd` (ADR-0182 E2D-11): API, Operation
   and reconciliation, lease and store signals.
2. PostgreSQL coverage for the Placement doctor checks, or a documented
   reason they stay SQLite-only.
3. BuildingBlock status in diagnostics.
4. Backup/restore and PKI signals, after ADR-0189/SPEC-0050 and #1087.
5. Implementing the SPEC-0051 support bundle once it is accepted.
