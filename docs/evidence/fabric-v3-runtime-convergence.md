# Fabric v3 runtime executor evidence

This record covers the runtime executor refactor on branch `fabric-v3-runtime`.
It does not certify the final PP.5 campaign.

Runtime candidate SHA exercised by the final validation: `5eaf8da224c60798671c3c3c42a1ff6729feaa34`.
Base protected `main`: `41fedbfdf982596f6932c5eb6b08e2c36f810067`.

## Authority and provenance

- O3K authority: ADR-0186, SPEC-0049, and `contracts/edge-fabric-stretched-l2.md`.
- Shared executor: `o3kio/fabric` tag `v0.1.5`, resolved at commit
  `bf99a9f2134ae44b5f485fa2efcb37b103c298a2`.
- The current PR #1054 head was fetched at
  `1cac7fee3cfc64c2d18b8f1187cdb17ed2a5f8e9`; it contains the phase 0/1
  dependency/conformance prerequisite. This implementation branch was kept
  separate from that PR, carries the pinned dependency and prerequisite
  behavior, and adds the production adapter. No PR was merged or rewritten.

The shared provider owns WireGuard, per-realm VXLAN, learning bridges, bounded
HER, provider ownership journaling, and substrate cleanup. O3K continues to own
AddressRealm identity, endpoint placement and generations, VNI bindings,
realm/TAP bridges, ingress source-host/VNI admission, anti-spoofing, policy,
public-address behavior, and O3K operation fencing/reconciliation.

## Implementation evidence

`o3k-network` now converts each accepted `NamespacedRoutedFabricPlan` into a
validated `fabric_plan::StretchedL2Plan` and invokes
`fabric_linux::LinuxFabricProvider<RealCommandRunner>` from a separate
`fabric-provider` ownership root. The provider-created consumer veth is
validated and attached to the O3K realm bridge. Provider-derived VXLAN names,
VNI, MTU, and HER membership are mirrored into O3K execution state; O3K's
authenticated ingress and endpoint anti-spoof rules remain in force. Geneve is
rejected during conversion and the production path never calls the legacy local
Geneve/VXLAN substrate.

## Validation

The following focused checks pass on the candidate:

```text
cargo check -p o3k-network --all-features
cargo test -p o3k-network --all-features
cargo test -p o3k-network --test fabric_conformance --all-features
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

The provider conformance suite exercises the pinned executor's replay,
generation, ownership, HER, MTU, cleanup, and foreign-state behavior. Adapter
tests cover V3 plan conversion, VNI and Geneve admission, peer preservation,
fencing generation, and MTU propagation.

## Host-independence scope

The strict independent-physical-host gate remains unperformed: these nested
compute guests share one physical underlay. On 2026-10-03 the user explicitly
authorized the nested environment as the approval environment and waived the
physical-independence blocker for this development validation. The nested gate
below is therefore reported as nested functional evidence under that waiver;
it is not represented as independent physical-host evidence.

The exercised profile is the accepted P11 v3 stretched-L2 fabric behavior
described below. It does not certify the full OpenStack Neutron networking
compatibility surface, production readiness, or PP.5. No such broader claim is
made. The compute guests ran Linux `6.8.0-139-generic`, libvirt `10.0.0`,
QEMU `8.2.2`, iproute2 `6.1.0`, and WireGuard tools `1.0.20210914`; QEMU
`8.2.2` was also installed on host-a for the guest-originated spoof probes.

The workspace run retained an unrelated focused PP.5 endpoint artifact at
`bins/o3kd/target/pp5/01a10135-abe5-77d1-9e8f-d8fba0e3fce4/pp5-1035-restart-evidence.json`
with SHA-256
`8fd54f379ff494a3698e6c388fca75b5f9b211df77dc318e63a3635d9ae670bb`; it is
not Fabric v3 evidence.

## Nested development-host validation

On 2026-10-03 the current development host provisioned three nested KVM
guests with `tests/pp5-small-edge-campaign/provision-hosts.sh`:

```text
run: fabric-v3-20261003-evidence2
host-a: 192.168.122.18
host-b: 192.168.122.4
host-c: 192.168.122.241
kernel: 6.8.0-139-generic
vCPU/memory: 2 / 1967 MiB per guest
/dev/kvm in guest: usable on all three
guest-to-guest reachability: passed
```

Provisioning evidence is retained at
`docs/evidence/artifacts/fabric-v3-20261003-evidence2/evidence.json` (SHA-256
`58bec87347d9a60eadf219ff643fb39471cc5d2a13ec3c77f1be38cbe5f3d90f`) and the
sanitized inventory at
`docs/evidence/artifacts/fabric-v3-20261003-evidence2/inventory.txt` (SHA-256
`5c30893fb2992bfa3bd91fee3304525def14eb202c0e36525d28109324878370`).

The provider smoke was executed on all three guests using the production
`fabric_linux::LinuxFabricProvider<RealCommandRunner>` adapter. Each guest
passed host transport address, per-realm VXLAN (`dstport 4789`, learning
enabled), isolated VXLAN/consumer-veth attachment, and topology cleanup.
The smoke used provider-generated names (`o3k-wg`, `o3k-x-*`, `o3k-b-*`, and
`o3k-p-*`) and confirmed no residual provider objects after each run.
The sanitized command output is retained at
`docs/evidence/artifacts/fabric-v3-20261003-evidence2/provider-smoke.txt`
(SHA-256
`ecbfa4ce0fc6d5d066c60a2d1ffdd80eb9a5fbad21a4067988b75400c463b0b6`).

The first host-b retry encountered the intended O3K fail-closed response after
an interrupted prior smoke left the durable TAP record with MAC
`02:29:48:24:12:14` while the kernel TAP reported a different MAC. No foreign
object was deleted. The recorded ownership journal was checked, the owned TAP
MAC was restored to the journal value, and the smoke was rerun successfully on
host-b and then repeated successfully on all three guests. This is retained as
a negative ownership-safety observation, not as a Fabric v3 pass claim.

The nested guests share this development host's physical libvirt underlay.
They therefore provide substrate and ownership evidence only; they do not
prove the required independent three-compute-host packet gate (real remote
ARP/MAC, DHCP broadcast, overlap isolation, authenticated WireGuard capture,
anti-spoof injection, MTU boundary, restart, and zero-leak cleanup).

## Nested three-host packet follow-up

The retained nested-host run `fabric-v3-gate-20261003` used three freshly
provisioned guests on the development host:

```text
host-a  192.168.122.118
host-b  192.168.122.134
host-c  192.168.122.196
```

The test-only helper
`crates/o3k-network/examples/fabric-regression-3host-helper.rs` encoded the
accepted fixture without changing canonical authority:

```text
Realm A: A1 10.0.0.10 / 02:00:00:00:a1:01 on host-a
          A2 10.0.0.20 / 02:00:00:00:a1:02 on host-b   VNI 101
Realm B: B1 10.0.0.10 / 02:00:00:00:b1:01 on host-c
          B2 10.0.0.20 / 02:00:00:00:b1:02 on host-b   VNI 102
```

`tests/fabric-v3-three-host-gate.sh` applied the production Linux adapter on
all three guests, attached disposable endpoint namespaces to the provider
bridges, and then replayed the same plans after deleting host-b's provider
WireGuard device. The run passed bidirectional A1↔A2 and B1↔B2 ICMP, with
neighbour tables learning the actual remote endpoint MACs, realm-scoped
DHCP-like broadcast delivery, and restart/reconciliation return. Cleanup
removed provider VXLAN, bridge, namespace, WireGuard, nftables, and endpoint
state while preserving the foreign `f3-foreign-can` bridge canary.

The exact corrected command output is retained in
`docs/evidence/artifacts/fabric-v3-three-host-gate-20261003/gate-output-corrected.txt`
(SHA-256 `2ba83ff4b4826a792a1aacf56b9625247ff9d807d14a1a94cdc148a9bb85dbab`).
The earlier `gate-output.txt` and `runtime-snapshot.txt` are retained as
diagnostic artifacts from the first helper revision; that revision over-created
realm state on hosts without a local endpoint and is not used for the corrected
result.
The corrected runtime snapshot at
`docs/evidence/artifacts/fabric-v3-three-host-gate-20261003/runtime-snapshot-corrected.txt`
records per-realm VXLAN (`dstport 4789`, learning enabled), VNI 101/102, HER
FDB membership, authenticated WireGuard peers with `/32` AllowedIPs, and
endpoint anti-spoof rules; its SHA-256 is
`857660f88943d3cd828f6af1c45855327e08eb938e4a05adf8902edd51e8a560`.
The physical-underlay capture contains only UDP/65001 WireGuard packets and
no decoded tenant IPv4 fields; its SHA-256 is
`9c28f2a37b0d7c6d183fedb3d4586ca4458ebd97a7f090210559d8fe5df46e7f`.
Host tool/kernel inventory is retained at
`docs/evidence/artifacts/fabric-v3-three-host-gate-20261003/host-inventory.txt`
(SHA-256 `e80ab93274284234800dedf11e2754f907f33a6fad8658731518a358895591f8`).

This is useful nested packet-path evidence, but all three guests still share
one physical libvirt underlay. The run therefore does not satisfy the required
independent three-compute-host gate. Direct injected wrong-MAC, wrong-IP, and
ARP-sender packets through a live guest TAP were not claimed; the snapshot
records the installed fail-closed nftables rules and counters. MTU boundary
success/oversize behavior and full unknown/stale-VNI traffic injection remain
portable/provider evidence rather than real-host claims.

## Disposable bridge gate tooling

`tests/fabric-v3-bridge-gate.sh` creates two logical host namespaces with
private provider mount namespaces, a veth underlay, the production provider
WireGuard/VXLAN bridges, two overlapping realm bridges, endpoint namespaces,
and a foreign canary. It is bounded to this development host and does not
claim independent compute-host evidence. The provider-only setup/cleanup mode
passed on this candidate:

```text
sudo FABRIC_V3_PROVIDER_ONLY=1 \
  FABRIC_V3_HELPER_BIN=$PWD/target/debug/examples/fabric-regression-helper \
  bash tests/fabric-v3-bridge-gate.sh
```

That run proved provider bridge/VXLAN/HER realization and cleanup while the
foreign canary survived. The full endpoint mode was also run after correcting
the helper's host-relative endpoint directory. WireGuard handshakes and
VXLAN ingress counters were observed, but the remote ARP request did not reach
the endpoint bridge, so the script failed closed at the A1-to-A2 packet gate.
This retained failure is diagnostic evidence only; it is not a Fabric v3
functional pass. `FABRIC_V3_KEEP=1` is available for bounded inspection and
must be followed by explicit removal of the listed disposable namespaces.

### Ingress admission correction and follow-up run

The first full bridge-gate run retained a real packet-path failure. The
provider and WireGuard transport were healthy, but an nftables `vxlan vni`
expression was evaluated at the WireGuard netdev ingress hook, before the
kernel had decapsulated the VXLAN frame. That rejected BUM and unknown-unicast
frames, so a remote ARP request never reached the endpoint bridge. A standalone
VXLAN-over-WireGuard reproduction isolated the failure to that pre-decap
match.

Commit `93b271540b5398e12e2b8b1378aec299bcb9814c4` changes admission to two
bounded stages. The WireGuard netdev rule authenticates the enrolled peer
source and assigns a deterministic mark. A bridge-forward rule then binds
that mark to the current realm VXLAN device and VNI after decapsulation. The
reconciliation fingerprints and owns both tables, rejects foreign markers,
and removes them only after ownership is proven. The netdev hook no longer
matches `vxlan vni` before decapsulation.

The corrected development-host runs were:

```text
provider-realization=passed
endpoint-bridges=not-run
provider-cleanup-and-foreign-canary=passed

provider-realization=passed
endpoint-bridges=passed
remote-arp-mac-and-icmp=passed
bounded-her-fdb=passed
provider-cleanup-and-foreign-canary=passed
```

The full run observed actual endpoint MAC learning for both overlapping
realms, bidirectional A1/A2 and B1/B2 ICMP with 0% loss, bounded HER entries,
and cleanup with the foreign canary preserved. This is a one-physical-host,
two-logical-host development gate. It is retained as focused packet-path
evidence and does not satisfy the independent three-compute-host requirement.
It does not claim DHCP broadcast, underlay capture, injected anti-spoof
rejections, MTU boundary behavior, restart/reconciliation return, or a
three-host zero-leak inventory.

## Nested three-compute functional gate rerun

Following the user's 2026-10-03 direction, physical-host approval is treated as
out of scope for this development approval and the nested environment is the
approved validation environment. Three nested compute hosts still share one
physical hypervisor/underlay; this waiver changes the approval scope and does
not change that evidence fact.

The rerun used Realm A (`a1000000-0000-0000-0000-000000000001`, VNI 101) with
A1 `10.0.0.10` on host-a and A2 `10.0.0.20` on host-b, and Realm B
(`b1000000-0000-0000-0000-000000000001`, VNI 102) with B1 `10.0.0.10` on
host-c and B2 `10.0.0.20` on host-b. Hosts were `192.168.122.118`,
`192.168.122.134`, and `192.168.122.196`. The test-only helper submits the
accepted canonical fixture through the production O3K Linux adapter; it does
not start the full O3K control-plane/agent process path.

The passing run output is retained in
`docs/evidence/artifacts/fabric-v3-nested-approval-20261003/gate-output-vni-counter-rerun.txt`.
It shows both directions of remote same-realm ARP resolving to the actual
endpoint MAC, A1↔A2 and B1↔B2 ping, DHCPDISCOVER broadcast reaching A2,
overlapping-address isolation (zero ARP frames at B2 during Realm A traffic),
and restart/reconcile returning connectivity. A valid unknown VNI 999 from an
enrolled peer reached the decrypted WireGuard boundary, incremented the
bounded pre-decap nftables rejection counter (`0→1`), and was absent at the
endpoint. A VNI 101 packet from authenticated host-c, which did not participate
in Realm A, incremented the same peer/VNI admission-drop counter (`1→2`) and
was absent at the endpoint. The test retained the generated nftables netdev
and bridge rules in the gate output. It also asserted that each injector's
peer `/32` route selected `o3k-wg`, while simultaneous physical-interface
captures saw UDP/65001 only and no cleartext UDP/4789.

For anti-spoof evidence, the gate boots a small disposable KVM guest on host-a
and attaches it to A1's actual provider TAP. Four guest-originated frames were
rejected by the matching O3K-owned nftables rules, with counter deltas:
wrong Ethernet source MAC `0→4`, wrong IPv4 source `0→1`, wrong ARP sender MAC
`0→3`, and wrong ARP sender IP `0→3`. The guest serial logs are retained in
the same artifact directory. The first two failed attempts are also preserved
there: those wrote to a TAP with no guest attached, and correctly failed to
produce a security counter delta. They are harness diagnostics, not product
regressions, and the passing evidence uses the actual QEMU guest path.

The MTU probe passed a 1390-byte IP packet (`ping -M do -s 1362`) and the next
byte produced an explicit local `message too long`/`mtu=1390` result. The
WireGuard underlay capture from the existing run records only host transport
addresses and UDP/65001, without decoded tenant addresses. During both
negative VNI probes, the same physical captures showed WireGuard UDP/65001 and
no cleartext UDP/4789. After provider and endpoint cleanup, inventory queries found no O3K-named VXLAN, bridge, provider
namespace, nftables table, route, or rule on the three guests; the foreign
`f3-foreign-can` bridge remained on host-a. The retained command output and
serial files have hashes listed in
`docs/evidence/artifacts/fabric-v3-nested-approval-20261003/SHA256SUMS`.

The final harness revision retains two earlier failed security-capture attempts
without treating them as evidence: one selected the remote IP string as a
capture interface, and the next did not fail closed when tcpdump could not
open that interface. The final passing rerun derives the underlay interface
from `ip route get`, requires tcpdump success and a captured WireGuard packet,
and asserts no UDP/4789 underlay frame. Its output, decrypted VXLAN capture,
empty endpoint capture, per-probe physical captures, and current QEMU serial
logs are retained and independently hashed. The independent source review
initially questioned bridge rule direction and injector routing, then withdrew
both findings after confirming the fabric-side veth versus VXLAN ingress
interfaces and the peer `/32` WireGuard route. No BLOCKER, HIGH, or MEDIUM
finding remains from that bounded review.

This is a pass for the user-approved nested functional gate. It is not an
independent physical-host result, full OpenStack Neutron network compatibility
certification, production-readiness claim, or PP.5 certification. The nested
test proves only the exercised P11 v3 fabric scenarios; broader OpenStack
network operations require their own accepted compatibility profile and
evidence.

## Final nested approval rerun and restart ownership correction

The user explicitly authorized nested development-host validation in place of
physical-host approval. On that basis, the three nested compute guests are the
approval environment for this implementation candidate. This waiver does not
make the guests physically independent: all three run on the same development
host and share its libvirt underlay. The latest pass is therefore a nested
functional approval, not a physically independent host result.

The final run used the same realm/endpoint/VNI matrix above. Host-a
(`192.168.122.118`) hosted A1, host-b (`192.168.122.134`) hosted A2 and B2,
and host-c (`192.168.122.196`) hosted B1. Realm A used VNI 101 and Realm B
used VNI 102. The helper installed plans through the production O3K Linux
adapter using a test-only canonical fixture; it did not start the full O3K
controller and network-agent service path. A disposable QEMU guest on host-a
transmitted the spoof probes through the actual provider TAP.

The restart test deleted host-b's provider WireGuard device. Linux also
removed its device-bound nftables ingress chain, while the durable provider
record still identified O3K ownership. The old replay path treated the now
empty named table as foreign and stopped. The fix records a random ownership
marker at the nftables table level and will rebuild a missing chain only when
that marker proves ownership; a table or object name alone is still
insufficient. Table-level markers are parsed only at table scope. The
regression test `nft_table_ownership_survives_device_bound_chain_removal` and
the nested process-death/replay scenario both pass. The source review found no
BLOCKER, HIGH, or MEDIUM finding for this correction. Retained command output
has random ownership marker values redacted; raw private keys, credentials,
and tokens are not retained.

The final gate output is
`docs/evidence/artifacts/fabric-v3-nested-approval-20261003/table-marker-r3/gate-output.txt`.
It records actual-MAC ARP in both directions for both realms, bidirectional
same-realm ping, DHCPDISCOVER broadcast to the remote endpoint, zero observed
cross-realm delivery for identical IPv4 addresses, and connectivity recovery
after replay. Spoof-counter deltas were wrong MAC `0→4`, wrong IPv4 source
`0→1`, ARP sender MAC `0→3`, and ARP sender IP `0→3`. Unknown VNI 999 from an
enrolled peer was dropped before VXLAN delivery (`0→1`); VNI 101 from the
enrolled but nonparticipating host-c was also dropped (`1→2`). Peer routes for
the injectors selected WireGuard, and physical-interface captures during
negative probes contained WireGuard UDP/65001, with no clear UDP/4789 tenant
datapath. A 1390-byte IP packet succeeded; a 1391-byte packet failed
explicitly with local `message too long` at MTU 1390. The provider cleanup
assertion reported that its foreign bridge canary survived. A later inventory
found no O3K-owned resources; the canary was no longer present then, so the
retained gate assertion is the evidence for survival during the cleanup
operation, not for persistence after the subsequent environment teardown.

Post-cleanup inventory on each nested host found no O3K provider namespace,
link, FDB entry, WireGuard device, nftables table, route/rule, TAP, or durable
configured network. The three inventories are retained beside the gate output.
They are scoped to the O3K provider's guest-kernel state and do not establish
absence of unrelated host state outside that inventory.

The candidate ran with Rust/Cargo 1.97.1, PostgreSQL 16.15 installed, host
Linux 6.8.0-139-generic, libvirt 10.0.0, QEMU 8.2.2, nested guest Linux
6.8.0-139-generic, iproute2 6.1.0, WireGuard tools 1.0.20210914, and
nftables 1.0.9. Exact environment and tool output are retained in
`table-marker-r3/candidate-environment.txt` and `atomic-rerun/host-*-versions.txt`.
Workspace tests completed successfully against the configured environment;
PostgreSQL-backed workspace tests passed. In addition, both relevant ignored
network lifecycle tests were run separately on fresh purpose-scoped disposable
PostgreSQL databases: `postgres_p13_f2_r1_reconstructs_and_recovers_realm_cleanup`
and `postgres_p13_f3_fresh_runtime_reconstructs_policy_and_zero_realm_network`.
Their outputs are retained as `table-marker-r3/postgres-network-realm-cleanup-retry.txt`
and `table-marker-r3/postgres-network-reconcile.txt`; the databases were
dropped after the tests. An initial malformed local socket URL attempt is
retained separately as diagnostic evidence and was corrected before these
passes. This task did not run the final PP.5 matrix.

The retained validation commands passed:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo test -p o3k-network --all-features
cargo test -p o3k-network --test fabric_conformance --all-features
bash tests/adr-governance.sh
bash tests/architecture-boundaries.sh
bash tests/traceability.sh
bash tests/maintainability-guards.sh
```

The gate and validation artifacts have a SHA-256 manifest at
`docs/evidence/artifacts/fabric-v3-nested-approval-20261003/SHA256SUMS`.
That manifest covers sanitized evidence; it deliberately excludes ephemeral
WireGuard private keys and redacts random nftables ownership markers.

The demonstrated profile remains the SPEC-0049 stretched-L2 fabric path. No
claim is made that the entire OpenStack Neutron networking surface works on
this fabric: the nested gate exercises the listed O3K fabric flows, not every
Neutron API, service extension, client behavior, or interoperability profile.
PP.5 final certification remains unclaimed.

## Historical cleanup failure — 2026-10-09

The fresh guest-control campaign for product
`e3f5ce764b4d7ee1bba34f645da8ec6c156bde99` ended at its first cleanup failure:
supported deletion removed server C and advanced the canonical A/B directory,
but host C still reported C's TAP in committed Fabric ownership after 120
seconds. The preserved evidence is
`/var/tmp/fabric-v3-minimal-three-host-20261009T024500Z-guestcontrol-14.tar.gz`
with SHA-256
`102f40389ad18c3047513dbec0f9c08fccae37dde186852acdf89bc21d101a96`.

The archive proves server C is absent, A/B plans use generation 5 and contain
only A/B, while C's ownership remains at generation 4 with C's endpoint TAP.
It does not contain C's post-delete Remove command record, admission/execution
status, or live TAP observation. Therefore the historical dispatch boundary
cannot be reconstructed from that bundle; the first *observed* divergence is
between canonical A/B convergence and C's retained provider ownership. The
source path constructs a host-targeted C Remove before A/B Apply. Inspection
also found that the node executor treated a successful Remove mutator as
terminal without requiring `observe_removed`, and the Linux provider discarded
ownership after deletion commands without reading back all owned live objects.

The successor fix keeps ownership until TAPs and Realm-scoped provider objects
are observed absent, makes Remove execution terminal only after a fresh
read-only absence observation, and tests both retained-live-state and complete
cleanup. This is a resolved implementation defect only after the successor's
workspace and fresh real-host campaign evidence pass. The preserved failed run
remains immutable and is not reinterpreted as a pass. Gate A and PP.5 remain
unclaimed.

## Candidate rerun on 2026-10-04

A final nested rerun completed successfully on source
`3a5cc25856c1e1a13ef41b721871c52ed2841fac` (`fabric-v3-runtime`, based on
`41fedbfdf982596f6932c5eb6b08e2c36f810067`). The successful gate exited 0.
The retained bundle is
`docs/evidence/artifacts/fabric-v3-nested-gate-20261004-3a5cc258/`; its
`SHA256SUMS` covers the sanitized command output, workspace logs, run metadata,
and post-cleanup inventories. The run used the same three nested guest identities
and topology described above, on one physical development host.

The rerun confirmed cross-host actual-MAC ARP and ping in both overlapping
realms, DHCPDISCOVER delivery, realm isolation, exact participating-peer HER,
WireGuard transport capture with no clear UDP/4789, the derived 1390-byte tenant
MTU boundary (1362-byte ICMP payload succeeds and 1363-byte payload is rejected
explicitly), TAP anti-spoof rejection counters, unknown/nonparticipating VNI
drops, connectivity recovery after deleting host-b's WireGuard device and
replaying, provider cleanup, and the foreign bridge canary assertion. The
production Linux adapter was exercised through a regression helper with a
test-only canonical fixture; the full `o3kd`/network-agent and OpenStack API
path were not part of this gate.

Two failed attempts remain retained alongside the pass. The first failed
because the test fixture placed the WireGuard key outside the provider's actual
`fabric-provider/` key path. After correcting that fixture, a second attempt
completed dataplane checks but its foreign-bridge comparison failed on dynamic
bridge timers. The harness now compares stable bridge identity fields, and the
candidate rerun passed. These were harness/evidence corrections; no production
network behavior was changed to turn either run green. Harness canaries were
removed by explicit test teardown after provider cleanup had verified their
survival. The guest disks are restored from pretest copies after evidence
capture; exact pretest disk hashes and final guest inventories are retained.

On this exact candidate, `cargo fmt --all -- --check`,
`cargo clippy --workspace --all-targets --all-features -- -D warnings`, and
`cargo test --workspace --all-features` all exited 0. This was workspace
validation only, not the final PP.5 campaign. The result supports the
user-approved nested functional gate; it does not prove physical host
independence, the full O3K process/API path, all OpenStack Neutron behavior,
production readiness, HA/SLA, or PP.5 final certification.
