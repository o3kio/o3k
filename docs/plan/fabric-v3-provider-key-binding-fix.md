# Fabric Gate A provider identity binding correction

Issue: demonstrated Gate A failure in PR #1076's harness lineage, run
`dc2f-gatea-20261014T123452Z`, phase `wireguard_identity_verify`.

Profile: nested three-host Fabric v3, execution-provider conformance under
ADR-0186, SPEC-0049, and the real-host acceptance evidence contract. O3K Network
remains canonical; the shared Fabric provider owns bounded Linux realization.
There is no OpenStack adapter, database, public API, product, or authority change.

The frozen product is `dc2f9ce11fecf3a1152e089e518aa1530744b00d`, tree
`f79da735797150d83c3dd8af1b651d5023ef0f9b`. Its production
`SharedFabricAdapter::open` uses `<backend-root>/fabric-provider`. The gate
incorrectly prepared keys directly under `<backend-root>`, and a regression
asserted that incorrect location. The historical failed result stays immutable;
it did not capture runtime keys/peers, so its exact comparison failure remains
unobserved.

Bounded execution scope:

- Correct `tests/fabric-v3-three-host-gate.sh` key preparation; retain fresh-root,
  root ownership, regular-file, mode-0600, and symlink checks.
- Capture each host's public runtime identity before comparison. Record host,
  exact operation, observer, exit code, and key/peer mismatch predicates.
- Add a public-identity evidence comparator and behavioral regressions in
  `tests/fabric-v3-three-host-gate-regression.py`; update the mistaken path test
  and bind it to the frozen production adapter's root mapping.
- Preserve all retirement, complete learned-FDB, DHCP, readiness, ownership,
  foreign-state, and supported cleanup assertions.

Provenance: repository source and the already pinned public `o3kio/fabric`
v0.2.0 (`b15c2cc977a9b53fcae805b9837e0781297d6e24`), specifically
`crates/fabric-linux/src/config.rs` and `keys.rs`, inspected for key-path and
existing-key adoption behavior. No implementation copied. No public Go input.

Tests first: reject the old directory binding; execute remote preparation and
verify real key derivation; exercise matching identity, wrong key, missing/extra
and duplicate peers, observation failures, and preserved failure evidence.
Local shell doubles do not prove protected-runner privileges or Linux runtime.
The authoritative integration evidence uses the frozen production helper on
fresh protected nested guests after green CI/review.

Validation: focused Fabric harness regressions, bash syntax, ShellCheck, diff
checks, mandatory workspace fmt/clippy/tests, normal PR CI. A runtime identity
failure widens diagnosis only when exact host/key/peer evidence supports it.
After a clean identity check, rerun fresh Gate A; PP.5 starts only after Gate A
passes. Every failed run stops and retains its original evidence; cleanup cannot
turn a failure into PASS.

Non-goals: product/provider redesign, acceptance weakening, private-key evidence,
manual runtime repair, PP.5 before Gate A PASS, or physical Fabric validation.

FABRIC PHYSICAL ACCEPTANCE: DEFERRED_BY_POLICY
