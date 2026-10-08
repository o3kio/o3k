# Real-host acceptance evidence contract

Status: Accepted

Scope: privileged, nested, and real-host product acceptance campaigns.

This contract defines the minimum evidence needed to separate a product failure
from an unavailable test control path. A campaign records the product, harness,
and workload image as independent source-bound inputs.

## Control-channel capability discovery

Before creating tenant workloads, a campaign MUST inventory actual available
workload control mechanisms. Record for each mechanism whether it is present,
interactive, read-only, bidirectional, dependent on tenant DHCP, dependent on
the cross-host dataplane, and accepted for command control. Inspect the
product-created workload definition and verify the live domain before relying
on a mechanism. Do not assume a serial PTY, QEMU guest agent, vsock, guest SSH,
or management NIC exists.

An interactive serial channel is accepted only when the live domain exposes a
PTY-backed serial device. A file-backed serial device is a read-only evidence
stream and MUST NOT be treated as an interactive shell.

## Control-path and system-under-test separation

Every campaign MUST name its system under test, compute management path,
workload command/control path, and observation path. The command path SHOULD be
out-of-band. If no out-of-band workload command path exists, a host-local path
MAY be used only when it is independent of the cross-host predicate under test,
its dependency is documented, it is preflighted independently, and its failure
is distinguishable from product failure.

For Fabric v3, SSH over the canonical tenant IPv4 address MUST NOT be the
mandatory command channel for cross-host networking acceptance. A workload's
IPv6 link-local SSH address scoped to its local compute Realm bridge MAY be
used for cross-host packet tests only after proving that the path stays on that
compute host and does not use VXLAN or WireGuard. This local path is not evidence
of cross-host connectivity.

## No test-induced product mutation

A harness MUST NOT change product behavior solely to obtain a command channel.
Without separate product architecture approval, it MUST NOT add a test-only
NIC, change the serial backend, add guest-agent or vsock devices, change
firewall/policy, assign tenant addresses manually, add routes, or repair FDB,
HER, VXLAN, or WireGuard state.

## Deterministic workload image

When guest command execution is required, the gate SHOULD use a purpose-built,
reproducible acceptance image. Record its source, build recipe revision, SHA-256,
tool versions, and command-service version. Stock images with nondeterministic
management-service readiness MUST NOT be a mandatory control dependency. The
image MUST NOT contain production secrets or statically configure the tenant
address or bypass routes. For the current Fabric v3 nested campaign, the pinned
CirrOS 0.6.3 base image is transformed by the checked-in recipe to install the
campaign public key and explicit key-only IPv6 Dropbear policy. The generated
image is checked against the frozen product image-upload limit before use.

## Preflight before product predicates

Before the first product predicate, prove and record:

- management path readiness;
- workload command path readiness and locality;
- required guest tools;
- canonical workload state, including DHCP address where applicable;
- product SHA and tree;
- harness SHA and tree;
- probe image SHA-256 and recipe revision.

A failure before this boundary is `HARNESS_GAP` or `ENVIRONMENT_GAP`, not a
product dataplane failure. A packet failure may be classified as a product
dataplane failure only after the command channel, source and destination state,
and command start are independently proven.

## First failure and fresh runs

Stop at the first required failure. Preserve the run state and evidence, assign
one primary classification, and do not repair that run and later reinterpret it
as passing evidence. After a product, harness, or environment fix, start a new
run ID from an ownership-clean environment. Preserve prior evidence unchanged.

## Independent identities

Every campaign manifest MUST record:

```text
product_sha
product_tree
harness_sha
harness_tree
probe_image_sha256
probe_image_recipe_revision
```

These identities are independent. A harness or test-image change does not
create a new product candidate.
