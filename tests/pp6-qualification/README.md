# PP.6 qualification guests

`host-env.py` provisions two run-scoped KVM/libvirt VMs from caller-supplied,
SHA-256-pinned Debian 13 and Ubuntu 24.04 cloud images. Debian 12 is not used
for new PP.6 qualification runs; its guest identity remains recognized only
for ownership-checked cleanup of existing runs. Each guest boots
systemd and receives separate local state and journal qcow2 disks formatted as
ext4. The run-specific libvirt network has forwarding disabled; it provides
host-to-guest SSH for setup and evidence collection only. These guests model
physical qualification nodes with static host-only addresses: the bridge uses
`192.168.<run-subnet>.1`, Debian 13 uses `.20`, and Ubuntu 24.04 uses `.21`.
The harness supplies cloud-init NoCloud `network-config` matched to each fixed
MAC, explicitly disables IPv4/IPv6 DHCP, and configures no gateway or default
route. The libvirt network has no DHCP range or forwarding. Guest address and
route checks run before the guest is accepted. This avoids depending on a DHCP
lease while preserving the isolated network. It does not install O3K or select
an installation policy.

The static network data uses cloud-init Networking Config Version 1, which
NoCloud supports and which can be rendered by Debian's ENI backend and the
Ubuntu image's configured backend. See the
[cloud-init Version 1 network configuration reference](https://docs.cloud-init.io/en/latest/reference/network-config-format-v1.html)
and [NoCloud datasource reference](https://docs.cloud-init.io/en/latest/reference/datasources/nocloud.html).

Run as root on a dedicated qualification host after checking that the supplied
images are trusted official cloud images and that no production credentials,
services, routes, or data are available to the guest:

```sh
O3K_PP6_QUAL_ROOT=/var/lib/o3k-pp6-qualification \
  tests/pp6-qualification/host-env.py provision \
  --run-id pp6-20261101-run01 \
  --debian-image /srv/qualification/debian-13.qcow2 \
  --debian-sha256 <official-image-sha256> \
  --ubuntu-image /srv/qualification/ubuntu-24.04.qcow2 \
  --ubuntu-sha256 <official-image-sha256>
```

The harness refuses an existing run ID, a symlink image, a digest mismatch,
less than 35 GiB free, fewer than eight host CPUs, fewer than 16 GiB available
memory, enabled host IPv4/IPv6 forwarding, or missing KVM/libvirt tools. Use a
dedicated qualification host with no production credentials, services, routes,
or data; the guest network has no external forwarding and the harness confirms
host IP forwarding is off. SSH is allowed only between the host and guests on
the run-specific network. These controls isolate guest network reachability;
they do not replace independent host hardening or firewall review.

It records guest OS, kernel, systemd, filesystem source/type/label, device,
inode, owner and mode, base-image digest, source SHA, and harness digest under
the run's `evidence/` directory. Once the authenticated release has been
installed, capture its identity on each guest:

```sh
tests/pp6-qualification/host-env.py capture-installation \
  --run-id pp6-20261101-run01 --guest debian13 \
  --source-sha <exact-tag-commit> --version <release-version-without-v> \
  --artifact-sha256 <archive-digest-from-verified-sigstore-manifest>
```

The capture requires the installed manifest to match the supplied source,
version, `libvirt` profile and digest, then hashes the four installed
executables and records their ownership, mode and inodes alongside the guest
OS, kernel, systemd and filesystem identities. This records the caller's
authenticated artifact identity; it does not perform Sigstore verification.
Verify the OIDC/Sigstore provenance and release bundle before supplying these
values. Set `O3K_PP6_SOURCE_SHA` when qualifying a detached source tree;
otherwise the checked-out Git HEAD is recorded. The private directory
contains run-only SSH user and host keys, disks and cloud-init seeds. The guest
host key is pinned into `known_hosts` from the host-generated public key; the
harness does not trust `ssh-keyscan` output.

```sh
tests/pp6-qualification/host-env.py force-restart \
  --run-id pp6-20261101-run01 --guest debian13
tests/pp6-qualification/host-env.py destroy --run-id pp6-20261101-run01
```

`force-restart` abruptly powers off and restarts the selected VM, and labels
that evidence as a guest-level interruption. It is not host power-loss
evidence. `destroy` verifies the run marker, run/private/evidence directory
inodes, every recorded file and domain disk, network interface, domain UUID,
network UUID and bridge identity, removes only that run's stopped VMs/network
and private files (including `seed/network-config`), and retains evidence. It
rejects a network definition that enables DHCP or forwarding. If provisioning
fails, resources are deliberately retained for inspection. Cleanup fails
closed when a partial run lacks the identity markers required for safe
removal; inspect and remove that partial run manually.

This infrastructure PR does not include an authenticated O3K candidate,
release installation, PostgreSQL 16 target, independent host power-cut
resource, or Phase B process verdict. PostgreSQL restore-target testing is a later,
separately authorized phase. Never pass production keys, release credentials,
database URLs, or control-plane state into these guests.
