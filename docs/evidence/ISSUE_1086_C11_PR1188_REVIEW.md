# PR #1188 C1/C1.1 review and regression evidence

Issue: #1086, parent #975. Reviewed baseline: `5990e481724d07879ea744a74c3f102cca8529c4`.
This review concerns the `o3k-small-edge-v1` recovery-only mechanisms and
`o3k-implemented` installer authority. It changes no OpenStack adapter, public
API, database schema, activation gate, A10 format, or product support claim.

## Authority and execution scope

Inputs were the repository's mandatory README, charter, clean implementation,
architecture, normative source index and test strategy; ADR-0189 C1/C1.1;
SPEC-0050 sections 7.2 and 7.3; the PP.6 technical-contract approval record;
and issue #1086 / PR #1188. No Go implementation or private implementation
material was consulted.

The bounded implementation plan began with `o3k`'s rotation planner,
installation snapshot and portable re-anchor tests. Reproduced defects widened
scope to trust verification/refresh, the existing upgrade/rollback quarantine
boundary and privileged filesystem journeys. `o3kd` remains a startup consumer.
No canonical store or provider is opened by rotation or trust refresh. D4
quiescence and exact-forward publication remain the recovery boundary.

## Findings corrected

1. A generic authentication failure could enter crash resume before any
   authenticated pending intent existed, bypassing outgoing-trust verification.
   Routine resume now requires the exact protected staged R. Conflicting pending
   pairs remain denied.
2. RELEASED crash resume discarded terminal journal/evidence bindings. Resume
   now preserves them, with the publication-boundary matrix covering both
   designated and RELEASED installations.
3. Exact routine replay after compromise attempted to consume the earlier
   compromise's evidence for the routine pair. Routine replay now leaves that
   consumption record unchanged.
4. Same-root signer rotation could roll back or equivocate revocation
   high-waters. Planning and historical generation authentication enforce the
   per-root ordering and reject rebinding a root key ID to another key.
5. A valid revocation refresh invalidated the R-to-trust binding at startup and
   in later rotations. R now retains its policy-authenticated immutable bundle
   binding while current authorization checks the refreshed high-water.
6. Exact R/C replay after refresh incorrectly compared its original bundle to
   the refreshed high-water. It now compares the immutable installed bundle
   and preserves the refreshed high-water without publication.
7. New policies could change protected state/journal device and inode bindings.
   Rotation now preserves those identities alongside the target identity.
8. Signer certificates could reuse trust-root public keys or cross-purpose root
   IDs. All root/signer purposes must remain distinct, comparing decoded keys.
9. Revocation refresh failed after its archive had already been written. An
   identical protected archive is now accepted; conflicting/unsafe archives
   fail closed. Refresh also retains D4 quiescence, rechecks policy under that
   lock, and reads inputs through bounded descriptor-anchored no-follow checks.
10. A designation after an R-only rotation was interpreted under the wrong
    era while walking past the authenticated R boundary. Current disposition
    verification now stops at the policy-bound, policy-authority-signed R.
11. Compromise recovery could not verify history after the outgoing signer was
    revoked. Historical verification now authenticates signatures, scope and
    revocation ordering without granting current authorization. This route
    requires a policy-signed R and fresh new-authority revalidation evidence;
    routine rotation and startup still deny revoked authority.
12. The refresh command rejected a root-signed update revoking the active
    signer, preventing the revocation step of compromise recovery. Publication
    now accepts fresh authenticated revocations while operational verification
    remains denied. Historical verification and revocation publication have
    separate internal modes; neither is exposed as a startup authority.
13. Upgrade checked quarantine before acquiring its retained store lock;
    rollback did not hold that lock over binary replacement. Both mutation
    paths now recheck quarantine under the retained lock. Automatic rollback
    releases the earlier publication guard before reacquiring its own lock.

Fail-before regressions reproduced the outgoing-verification bypass, routine
replay consumption failure, RELEASED resume failure, same-root high-water
rollback, refresh/startup and refreshed-replay failures, directory rebinding,
root/signer key confusion, archive-retry failure and revoked-history failure.
The existing privileged designate-after-rotation journey exposed the era
boundary failure. The upgrade switch-failure test now exercises real flock
reacquisition during automatic rollback.

## Validation

Final command results are recorded in the PR description after completion.
The portable re-anchor suite contains 40 tests, including 40 subprocess crash
cases (20 publication boundaries for each preserved recovery state). The
privileged ext4 suite contains five journeys, including actual signed active-
signer revocation publication, archive-crash retry and repeated refresh.
Additional unit tests deny forged historical certificates/revocations and
verify that revoked keys remain unavailable for current authorization.

## Limits

These are source-built, test-signed fixtures and local namespace-isolated ext4
mechanism evidence. They do not qualify an exact published installed candidate,
Debian-12 ABI compatibility, an approved offline signer/2-of-3 custody ceremony,
an independently administered trust-distribution endpoint, real power cuts,
clock rollback or independent security review. Terminal RELEASED operational
startup remains fail-closed. PR review/protected merge and production
qualification remain separate gates; #1086 and #975 remain open. A10 and full
PP.6 acceptance are not established by this work.
