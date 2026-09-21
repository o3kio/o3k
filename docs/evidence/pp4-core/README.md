# PP.4 Core evidence

This directory is reserved for evidence from the dedicated PP.4 Core campaign.
It is deliberately separate from the historical Araf-oriented material under
`docs/evidence/pp4/`.

The immutable runtime candidate is `v0.4.0-rc.18` at source
`da00eeaa878956f438a62648f40c783e06a076d7` (archive SHA-256
`01d20d6676d4c56bb6630d9878a66a97d57a59cbeccf3934f4c12206ab5f8dcc`).

Status: **INCOMPLETE**. Public release integrity and exact-source CI are
green, and the campaign helper self-tests pass. The disposable smoke harness
has reached public installation, release verification, canonical init/join,
BuildingBlock/compute readiness, TestLab image/network/keypair setup, and a
real TestLab libvirt guest boot. The native workload, reverse compatibility
workload, Horizon witness, Ubuntu full matrix, and Debian full matrix have not
yet produced complete auditable evidence. No PP.4 Core certification or merge
claim is made from these attempts.

The campaign attempts are retained as controller-local run directories under
`target/` and are not release evidence. They contain no credentials; temporary
credential files are created mode 0600 and removed by the VM harness trap.
