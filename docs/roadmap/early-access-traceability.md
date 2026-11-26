# Early Access roadmap traceability

Date: 2026-11-25  
Authority: [ADR-0191](../adr/ADR-0191-owner-directed-early-access-adoption-and-installation-trust.md)  
Acceptance contract: [SPEC-0052](../specs/SPEC-0052-early-access-profile-and-acceptance.md)  
Adoption epic: [#1241](https://github.com/o3kio/o3k/issues/1241)  
Status: issue transfer plan; no acceptance result is implied

This matrix replaces the PP.5/PP.6/PP.7 release dependency with the bounded EA
gate. It preserves the underlying issue status and existing evidence. “Pending”
and “not run” remain such until evidence is attached to the exact EA artifact.
Close PP parent issues only as `not_planned`/superseded after the EA epic and
this matrix are recorded; this is not certification. Do not close unresolved
defects to improve issue statistics.

## Parent issues

| Issue | Previous purpose/status | EA disposition | Follow-up and evidence treatment |
|---|---|---|---|
| #968 | Pilot decision; open, NO-GO due to C1 blocker #1225 and pending acceptance | Supersede as release root; replace with EA adoption epic | Preserve NO-GO history and outstanding evidence; no pilot/customer deployment before SPEC-0052 gate. |
| #974 | PP.5 production readiness; open, acceptance pending | Supersede as release prerequisite | Carry child work into EA blockers or future scalability; retain completed implementation and pending acceptance evidence. |
| #975 | PP.6 operational readiness; open/reopened | Supersede as release prerequisite | Carry recovery items to advanced DR and operational items to EA blockers/hardening; do not represent PP.6 certification. |
| #976 | PP.7 final certification; open | Supersede as mandatory release gate | S10/S20/K-min/K-full and comprehensive DR remain future milestones. Do not certify unrun suites. |

## PP.5 work

| Issue | Scope | Disposition |
|---|---|---|
| #1033, #1035 | Completed implementation children; parent acceptance remains pending | Preserve closed implementation state and evidence; exact-artifact/real-host acceptance remains an EA blocker only where it maps to SPEC-0052 checks. |
| #1036 | PostgreSQL failure behavior | EA release blocker: PostgreSQL 16 readiness/outage/restart and safe reconciliation. |
| #1037 | Five-host exact-artifact harness | Future scalability qualification. EA initially claims one to three hypervisors; five only after evidence and a separate owner claim decision. |
| #1038 | PP.5 failure/acceptance cases | Re-triage each extant failure against SPEC-0052. Critical security, data corruption, mandatory lifecycle, ownership, leak, foreign-state, or secret-redaction failures block EA; other PP-only failures move to their follow-up class. Keep defect issues open until resolved. |
| #1039 | S3/S10/S20/K-min/K-full scale/soak gates | Future scalability qualification; preserve runs/results and defer execution. |

## PP.6 work

| Issue | Scope | Disposition |
|---|---|---|
| #1084 | SQLite backup | Future operational hardening unless required by an existing advertised EA operation; EA rebuild guidance must make clear it does not recover controller/workload data. |
| #1085 | PostgreSQL backup/restore | Advanced disaster recovery; does not block EA clean rebuild, and no general DR claim is made. |
| #1086 | Restore activation/fencing | Advanced disaster recovery; C1 remains intact for recovery-qualified installs, while EA restore activation is rejected and that rejection is an EA blocker. |
| #1087 | PKI lifecycle | Basic TLS/agent identity validation and revocation/negative behavior are EA blockers; broader rotation/renewal lifecycle is future operational hardening. |
| #1088 | Diagnostics | Redacted, actionable operator diagnostics are an EA blocker; additional diagnostics are future operational hardening. |
| #1089 | Pressure/scale behavior | Future scalability qualification, except failures that violate an EA mandatory lifecycle or cause data/ownership/security harm. |
| #1098 | Upgrade/rollback | EA upgrade/rebuild policy and data-preservation guidance are blockers. General rollback/restore qualification is advanced disaster recovery or future operational hardening as scoped by the issue. |

Related existing work remains linked, not silently closed: #1225 (C1/pilot
blocker), #640 (rollback authority), and #944 (operator documentation) require
triage against ADR-0191/SPEC-0052. C1 recovery qualification remains a separate
supported path; an EA simplification must not weaken it.

## EA release blockers

The authoritative checklist is SPEC-0052 §8. At minimum, tracking must cover
the authenticated release artifact and manifest; fresh Ubuntu 24.04 install;
PostgreSQL 16 readiness; controller/compute health; single-host and three-host
VM lifecycle/placement; tenant network connectivity; storage create/attach/
detach/delete; restart/reconciliation; PostgreSQL outage/restart; host
join/drain/remove/replace; IAM/TLS/agent negative tests; EA recovery denial and
C1 cross-profile preservation; zero owned leaks and foreign mutations; redacted
diagnostics; and tested clean rebuild/data-protection guidance.

Every gate item remains `NOT_RUN` until evidence is generated against the exact
authenticated `v0.4.1` artifact and qualifying hosts. The current workspace has
no EA artifact. The available Ubuntu 24.04 host has an existing O3K footprint
(`/usr/local/share/o3k/release-manifest.json` identifies v0.4.0-rc.5), is not a
fresh target, has no `o3k-compute.service`, and has a shut-off libvirt guest; no
state was changed. It cannot stand in for fresh-host or lifecycle acceptance.
The current repository change is a roadmap/security design change, not artifact
acceptance.

| SPEC-0052 §8 check | Result | Missing qualifying evidence |
|---|---|---|
| 1. Artifact authentication/integrity | NOT_RUN | No EA artifact/manifest/SBOM/provenance/signature set. |
| 2. Fresh Ubuntu 24.04 installation | NOT_RUN | No authenticated EA installer and this host is not fresh. |
| 3. PostgreSQL 16 readiness | NOT_RUN | Local PostgreSQL responds, but no EA install/migration/least-privilege conformance run. |
| 4. Controller/compute health | NOT_RUN | Existing o3kd is inactive; compute service unit is absent. |
| 5. Single-host VM lifecycle | NOT_RUN | No accepted EA artifact or disposable lifecycle target. |
| 6. Three-host placement/lifecycle | NOT_RUN | No qualified three-host fleet. |
| 7. Tenant networking/connectivity | NOT_RUN | No EA tenant network campaign. |
| 8. Storage lifecycle | NOT_RUN | No EA storage campaign. |
| 9. Restart/reconciliation | NOT_RUN | No EA restart/reconciliation campaign. |
| 10. PostgreSQL outage/restart | NOT_RUN | No EA-bound fault campaign. |
| 11. Host join/drain/remove/replace | NOT_RUN | No qualified multi-host fleet. |
| 12. IAM/TLS/agent negative tests | NOT_RUN | No EA profile implementation or bound campaign. |
| 13. EA/C1 cross-profile security | NOT_RUN | EA admission and local trust are not implemented; independent review absent. |
| 14. Zero owned leaks/foreign mutations | NOT_RUN | No EA success/failure lifecycle campaign. |
| 15. Redacted diagnostics/docs | NOT_RUN | Operator workflow not run against EA; support path incomplete. |
| 16. Clean rebuild/data protection | NOT_RUN | No tested EA rebuild procedure/artifact. |

## Adoption and follow-up milestones

1. **EA blockers:** implementation, focused independent security review,
   authenticated artifact, bounded SPEC-0052 acceptance, owner GO.
2. **Known EA limitations:** single active controller, no HA/evacuation/live
   migration/enterprise SLA/general DR, initial 1–3 hosts, operator-managed
   infrastructure, replaceable non-critical workloads.
3. **Future operational hardening:** PKI lifecycle beyond the minimum EA
   identity checks, expanded diagnostics, backup/runbook improvements, upgrade
   reliability and support-process improvements.
4. **Future scalability qualification:** five-host evidence, S10/S20, K-min,
   K-full, capacity/endurance and wider deployment profiles.
5. **Advanced disaster recovery:** C1 restore activation/fencing, PostgreSQL
   restore and tenant workload recovery beyond clean rebuild.
6. **Future feature development:** customer-driven product capabilities that
   do not change or become unconditional prerequisites of the accepted EA
   profile; Araf tracks the accepted EA API baseline after its gate, with
   separate dashboard, Fabric, Volvisor, customer automation, diagnostics,
   recovery/scalability, and feature-request tracks.

## Governance actions

After the new adoption epic is created and this matrix is linked from it, the
PP parent issues may be closed with reason `not_planned` and an explicit comment
that they are superseded, not certified. A closure-guard workflow must not be
worked around; update it only through reviewed repository changes that encode
the new ADR-governed supersession semantics. Protect branch rules and keep
unresolved security findings visible.
