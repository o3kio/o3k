# PP.4 Core evidence

This directory is reserved for evidence from the dedicated PP.4 Core campaign.
It is deliberately separate from the historical Araf-oriented material under
`docs/evidence/pp4/`.

The immutable runtime candidate is `v0.4.0-rc.18` at source
`da00eeaa878956f438a62648f40c783e06a076d7` (archive SHA-256
`01d20d6676d4c56bb6630d9878a66a97d57a59cbeccf3934f4c12206ab5f8dcc`).

Status: **INCOMPLETE**. Public release integrity and exact-source CI are
green, and the campaign helper self-tests pass. The disposable smoke harness
reached public installation, release verification, canonical init/join,
BuildingBlock/compute readiness, TestLab image/network/keypair setup, and a
real TestLab libvirt guest boot. It then proved one native create through
`Operation=succeeded`, stable collision-safe port allocation (`192.0.2.3`
beside the compatibility port at `192.0.2.2`), a managed/running
`o3k-compute` libvirt domain, and guest console output. The required same-key
native replay returned HTTP 500 (`INTERNAL_ERROR`) after the first resource was
already active; this is a product/runtime idempotency defect in rc.18, not a
harness authentication failure. The exact redacted observation is recorded in
`rc18-native-replay-failure.json`.

Because the immutable candidate fails a mandatory PP.4 Core invariant, the
reverse compatibility workload, Horizon witness, Ubuntu full matrix, and
Debian full matrix were not run. No PP.4 Core certification or merge claim is
made. A runtime correction requires a successor public RC; rc.18 is retained
as a failed historical candidate.

The campaign attempts are retained as controller-local run directories under
`target/` and are not release evidence. They contain no credentials; temporary
credential files are created mode 0600 and removed by the VM harness trap.

## Successor: rc.19 cross-process replay proof

The rc.18 replay defect is corrected, and the successor candidate adds the
independent cross-process proof that the replay authority is durable rather
than process-local. The gate spawns two genuinely independent runtimes that
share only the durable store and requires them to converge on one canonical
identity with zero duplicate side effects. See
`rc19-cross-process-replay.json` for the gate, the durable invariants it
asserts, and the three convergence defects this proof exposed and corrected.
