# TestLab workflow

`tests/testlab.sh` runs a repeatable local fake-provider acceptance workflow:

```text
token → image upload → network/subnet → flavor → server → process restart
→ durable show/list → server delete → subnet/network/image cleanup → reset
```

It uses only the public HTTP API, creates a temporary data directory, never
prints the subject token, and writes a machine-readable result plus daemon
logs under `target/testlab-artifacts` (or `O3K_TESTLAB_ARTIFACT_DIR`). The
standard OpenStack CLI can use the same process with `OS_AUTH_URL`,
`OS_USERNAME=admin`, `OS_PASSWORD=password`, `OS_PROJECT_NAME=admin`, and
`OS_USER_DOMAIN_NAME=Default`.

The default `O3K_TESTLAB_PROFILE=fake` is executable in CI. The `cellhv`
profile is reserved for an environment that supplies `CELLHV_ENDPOINT` and
credentials; it fails clearly when that external environment is absent rather
than silently testing the fake provider.

## Nested Fabric control and packet paths

Fabric nested acceptance has three separate paths:

```text
compute management: runner -> nested compute host
workload control:   compute host -> its local workload guest
tenant Fabric:      guest -> remote guest through Fabric
```

Compute-host SSH is infrastructure control. Guest SSH over the canonical
tenant IPv4 is carried by the product dataplane and MUST NOT be the mandatory
command path for a networking acceptance test. A serial device is interactive
only when the live domain XML proves that it is PTY-backed and usable. A
file-backed serial device is an observation stream, not an interactive shell.

For the reference Fabric v3 nested profile, the reproducible CirrOS 0.6.3
acceptance image installs the campaign-owned public key and an explicit
key-only IPv6 Dropbear listener. SSH uses the guest-generated IPv6 link-local
address, scoped to the local Realm bridge on the compute host. The harness must
prove this channel is ready and stays off VXLAN/WireGuard before packet
predicates. See
[the real-host acceptance evidence contract](../contracts/real-host-acceptance-evidence.md)
and [the Fabric v3 campaign](../tests/FABRIC-V3-CAMPAIGN.md).
