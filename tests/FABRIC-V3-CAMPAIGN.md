# Fabric v3 nested three-host campaign

The campaign driver is tests/fabric-v3-o3k-three-host-campaign.sh. It runs
against the frozen product SHA embedded in the driver and uses supported HTTP
lifecycle operations. Product, harness, and acceptance image identities are
recorded separately in the source-bound evidence bundle.

## Current workload control profile

The product-created guest exposes a file-backed serial device. The live domain
XML records it for observation; file-backed serial is not interactive and is
not used to issue packet commands.

The guest command path is a deterministic probe image built by
tests/fabric-v3-build-probe-image.sh from the pinned Ubuntu cloud image. It uses
SSH to the guest's IPv6 link-local address, scoped to that guest's local Realm
bridge on its compute host. The command path does not use tenant IPv4, VXLAN, or
WireGuard. The harness captures the local bridge and Fabric namespace paths to
prove that the control exchange remains local before packet testing.

The probe obtains its tenant IPv4 address through the normal O3K DHCP path. It
uses normal guest-generated IPv6 link-local addressing. The recipe does not
assign tenant addresses or add bypass routes. Its generated SHA-256, source
image checksum, build recipe revision, and tool versions are recorded per run.

## Gate order

```text
environment and source identity
compute management A/B/C
control-channel capability discovery
probe-image identity
agents and stable host identities
supported HTTP network/subnet/port/server lifecycle
A/B/C ACTIVE
live TAP attestation
DHCP DORA and canonical leases
local guest-control preflight A/B/C
ARP using canonical MAC
ICMP 6/6
TCP A->B and UDP A->C
WireGuard/VXLAN evidence
controller restart and traffic recovery
compute-agent restart and traffic recovery
C removal and A/B traffic
supported teardown
leak and foreign-state checks
```

The first failed required predicate stops the run. A command-channel failure is
HARNESS_GAP; it cannot be reclassified as a Fabric packet failure. A
cross-host packet failure is a dataplane failure only after all three guest
control channels, canonical DHCP addresses, and command start are proven.

The accepted channel semantics and required evidence are normative in
[the real-host acceptance evidence contract](../contracts/real-host-acceptance-evidence.md).
