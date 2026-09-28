# P11 implementation prompt — supersession hold

Status: **Superseded by accepted P11 v3 architecture**

The detailed v1 implementation prompt that previously lived here targeted the
accepted ADR-0170/SPEC-0028 non-overlapping shared-routed-WireGuard profile.
The P11 v2 prompt that followed it is also historical. The accepted successor
is:

- `docs/adr/ADR-0186-stretched-l2-edge-fabric-vxlan-her.md`
- `docs/specs/SPEC-0049-stretched-l2-edge-fabric-v3.md`
- `contracts/edge-fabric-stretched-l2.md`
- issue #1050

## Do not continue privileged P11 fabric implementation from this file

ADR-0170/SPEC-0028 and the v2 successor are historical authorities for the
provider implementations and evidence that used them. New privileged work must
follow the v3 sources above; acceptance of v3 still creates no runtime or
real-host support claim until its implementation and evidence gates pass.

PR #703 has already merged a portable semantic endpoint-directory/planning
slice. That work should be preserved where compatible. New privileged
Geneve/WireGuard/realm-fabric work must be explicitly scoped to the v3 migration
and its evidence gates.

Do not use `docs/P11_REALM_OVERLAY_IMPLEMENTATION_PROMPT.md` for new work; it is
retained as a historical v2 record. Follow ADR-0186, SPEC-0049, and the
stretched-L2 contract instead of combining conflicting v2 and v3 rules.

Architecture text and prompt files do not create a product/support claim.
