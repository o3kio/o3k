# Fabric v3 nested development-host gate (2026-10-04)

Candidate: `3a5cc25856c1e1a13ef41b721871c52ed2841fac`, branch `fabric-v3-runtime`, based on protected main `41fedbfdf982596f6932c5eb6b08e2c36f810067`.

Result: the scripted Fabric v3 gate exited 0 on three nested Ubuntu/KVM guests hosted by one physical development machine. It exercises the production Linux fabric adapter through the regression helper and an actual KVM guest attached to the provider TAP. It does not start the full `o3kd`/network-agent or OpenStack API path, and all three compute guests share one physical host. It is nested functional evidence, not independent physical-host evidence or a full OpenStack networking claim.

The passing output records actual-MAC ARP and ping in both overlapping realms; DHCPDISCOVER broadcast; WireGuard-only underlay capture for the normal and negative probes; MTU boundary success and explicit oversize failure; all four TAP anti-spoof rejection counters; overlap isolation; unknown VNI rejection; rejection of a VNI sent by an authenticated peer not participating in that realm; replay after deleting host-b's WireGuard device; provider cleanup; and the foreign bridge canary assertion.

Two failed attempts are retained. The first exposed a test-fixture key-path mistake: public keys were generated from a directory above the shared provider's key path, so the peer identities did not match. The second passed dataplane and restart checks but failed because the canary comparator included dynamic bridge timers. The fixture was then seeded under `fabric-provider/`, and the comparator was narrowed to stable identity fields. No production networking behavior was changed for these harness corrections.

Post-cleanup inventories show no O3K links, namespaces, FDB entries, WireGuard devices/peers, nftables tables, or O3K routes/rules on the guests. The adapter intentionally retains its host-local WireGuard private identity and empty ownership manifests through provider teardown; these test-only guest files are removed when their backed-up VM disks are restored. No secret material is included in these artifacts.

The guest disks were restored from pretest copies whose hashes are recorded in `restore-verification.txt`; all three VMs were returned to running state, and each restored disk exactly matches its pretest SHA-256. The temporary controller SSH key directory was removed. Physical host independence, arbitrary scale, production readiness, HA/SLA, full OpenStack network parity, and PP.5 final certification are not claimed.

Evidence text captures are normalized to LF line endings with terminal whitespace removed; command content and exit results are retained. SHA256SUMS covers these normalized files.
