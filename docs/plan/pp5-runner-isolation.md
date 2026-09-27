# PP.5 protected-runner isolation design

The current protected job remains on a persistent KVM/libvirt-capable host. A
campaign-wide atomic lock (`scripts/p15-7-campaign-lock.py`) serializes the
host-global resources that cannot safely be shared: libvirt, LVM, PostgreSQL
service state, firewall rules and correctness-critical ports. The lock is
acquired after exact-source checkout and before any prerequisite mutation; a
foreign lock is never removed.

The preferred follow-up is an ephemeral campaign runner VM:

```text
persistent KVM host
  -> fresh runner VM with /dev/kvm (nested virtualization) and libvirt access
  -> one PP.5 campaign
  -> immutable artifact upload
  -> runner VM destruction
```

The runner image must expose `/dev/kvm`, a CPU model with nested virtualization,
at least 8 vCPU/16 GiB RAM/120 GiB disposable storage, and a dedicated libvirt
namespace. GitHub registration should use a one-run ephemeral token injected
through the runner supervisor, never committed configuration. Campaign secrets
should be provided as short-lived environment/file descriptors and omitted from
artifacts and diagnostics. Destruction must be performed by the host supervisor
after artifact upload, with a timeout and an ownership check on the runner VM.

The physical host retains only its own supervisor state and foreign resources;
the campaign runner VM owns its checkout, PostgreSQL service, libvirt guests,
LVM allocations and firewall rules. No foreign host resource may be modified to
make room for a campaign. This design is intentionally documented rather than
implemented in #1046 because changing runner provisioning would expand the
certification scope; the lock and strict preflight are the bounded interim
controls.
