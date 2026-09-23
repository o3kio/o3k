# PP.5 Small Edge campaign — host provisioning → verify → teardown

This directory is the first installation step of a PP.5 "Small Edge" multi-host
campaign on a real host: it provisions **genuine nested-KVM libvirt guests**,
proves each one boots with working `/dev/kvm`, and tears them down leaving zero
owned residue.

Scope is deliberately bounded. It is a shell/virsh-only harness. No O3K Rust
code is built or run, and **no `cargo` command** is ever invoked here (the
shared `target/` directory is owned by a concurrent build). The point is to
stand up and validate real nested-KVM compute hosts as the substrate a later
campaign phase would install onto — nothing more.

## Usage

```sh
# Provision 5 hosts (writes inventory + evidence under runs/<RUN_ID>/)
bash tests/pp5-small-edge-campaign/provision-hosts.sh          # host count defaults to 5
O3K_PP5_HOST_COUNT=3 bash tests/pp5-small-edge-campaign/provision-hosts.sh

# Tear down exactly that run's domains/volumes/seeds and verify zero residue
O3K_PP5_RUN_ID=<RUN_ID> bash tests/pp5-small-edge-campaign/teardown-hosts.sh
```

A short unique `RUN_ID` is chosen automatically (a UTC timestamp + the shell
PID) unless you export `O3K_PP5_RUN_ID`. Every domain, disk and seed ISO the run
creates carries the exact prefix `o3k-pp5-<RUN_ID>-`, e.g.

```
o3k-pp5-0921231234-12345-host-a  … host-e
```

Both scripts print the `RUN_ID`; keep it to tear the run down.

### What provisioning does (per host)

- copies the cached read-only Ubuntu 24.04 cloud image into a per-VM COW disk
  (`qemu-img create -b` backing file — the base image is shared input and never
  modified or deleted);
- generates a per-VM ed25519 key and a per-VM cloud-init seed ISO with
  `genisoimage` (hostname, non-root user `o3k`, per-VM SSH key, `host-passthrough`
  CPU so nested KVM is exposed; cloud-localds is absent on this host, so the
  seed is made with `genisoimage`);
- defines and boots the domain with `virt-install --import` on the `default`
  network: 2 vCPU, 2 GiB RAM, 10 GiB disk;
- waits (bounded) for a DHCP lease, then for SSH, then asserts inside the guest
  that `/dev/kvm` is a readable character device and the CPU exposes `vmx`/`svm`
  (i.e. nested KVM is usable), and records `nproc`, memory and `uname -r`;
- writes a run-owned inventory, an ownership marker and an `evidence.json`.

The harness fails closed (`exit 1` with a clear message listing the failed
hosts) if any host cannot be provisioned, does not get an IP/SSH, or does not
reach the asserted KVM state. Run `teardown-hosts.sh` to reclaim that run.

## Ownership model

Every resource a run owns is identifiable by **exactly one mechanism**: its
`o3k-pp5-<RUN_ID>-` prefix.

- Domains: `virsh list --all` filtered by the prefix.
- Disks / seed ISOs: files in `/var/lib/libvirt/images` matching
  `o3k-pp5-<RUN_ID>-…`.
- The run root `tests/pp5-small-edge-campaign/runs/<RUN_ID>/` carries a
  `0600` ownership marker (`.o3k-pp5-owned`) recording the exact prefix, run id
  and start time.

Teardown **refuses to run** unless the ownership marker exists, matches the
requested `RUN_ID`, and the prefix matches. It then removes only names derived
from that prefix and asserts no owned domain or volume remains before declaring
success. The shared base image
`/var/lib/libvirt/images/noble-server-cloudimg-amd64.img` does not match the
prefix and is never a deletion candidate. The pre-existing `p14-*` domains are
never matched, listed as ours, or touched.

## Observed environment limitations

- **Docker port publishing is broken on this host** (containers run but `-p`
  publishes nothing). This harness therefore does not use Docker at all.
- **`cloud-localds` is missing.** The cloud-init seed ISO is built with
  `genisoimage` (`-volid cidata -joliet -rock`), which is the standard
  equivalent and is what the repository's other real-host harnesses use.

## Files

- `provision-hosts.sh` — provision, verify, record evidence (fail-closed).
- `teardown-hosts.sh` — remove exactly this run's residue (fail-closed on
  leftovers).
- `runs/<RUN_ID>/` — per-run inventory, keys and evidence, created at runtime.
