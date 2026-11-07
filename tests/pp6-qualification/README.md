# PP.6 qualification guests

`host-env.py` provisions run-scoped KVM/libvirt VMs from caller-supplied,
SHA-256-pinned Debian 13 and Ubuntu 24.04 cloud images. By default it provisions
both guests; repeated `--guest` options select either one independently. Debian 12 is not used
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

## rc.27 clean-guest ownership contract

The immutable rc.27 installer owns its standard `/var/lib/o3k` path only when
that path is absent or carries its exact `.o3k-owned` marker. It refuses a
populated unmarked directory and recursively changes ownership of everything
under the marked path. The harness therefore creates the marker only after a
clean guest proves `/var/lib/o3k` did not exist, creates that directory itself,
records and rechecks its device/inode, and verifies that it is still empty.
This protocol has no path argument and cannot mark an arbitrary host path.
Existing directories, symlinks, unexpected files, or replacement directory
identities fail provisioning; no installer is run on those guests.

The harness formats only the two fresh qcow2 disks attached to the run-owned
guest as `/dev/vdb` and `/dev/vdc`. It verifies both mountpoints are empty
before mounting, requires distinct ext4 devices and expected labels, and
records the exact account as `o3k:o3k`, home `/var/lib/o3k`, shell
`/usr/sbin/nologin`. Systemd `RequiresMountsFor` and `BindsTo` drop-ins gate
both O3K services on the state and journal mounts. The fstab entries use
`nofail` so a missing disposable volume does not prevent host access; the
service dependency still prevents either O3K service from starting without
both mounts.

Before installation, `verify-install-ready` repeats these checks over
host-key-pinned SSH and retains the exact directory identities, mount source,
filesystem, labels, account, and systemd dependency evidence. After
installation, `capture-installation` also requires rc.27's expected resulting
layout: `/var/lib/o3k` is owned by `o3k:o3k-compute` mode `0711`; its immediate
state and journal mount directories are owned by the same account/group mode
`0700`. The two ext4 mount devices must remain distinct from each other and
from the guest root filesystem, and both installed services must be active.
The mounted filesystem roots are freshly formatted and empty before install,
so rc.27's recursive `chown` cannot adopt unknown guest state. O3K can write
inside the mounted filesystem roots because it owns those directories.

The focused `test_rc27_installer_guard.py` runs the actual authenticated rc.27
`packaging/install.sh` in temporary non-system paths. Run it only against the
already authenticated/extracted release bundle:

```sh
python3 tests/pp6-qualification/test_rc27_installer_guard.py \
  --release-root /srv/qualification/o3k-0.4.0-rc.27 \
  --evidence-dir /srv/qualification/evidence/rc27-installer-guard
```

It requires the published installer's independently recorded SHA-256 and
exercises a clean disposable marker, populated foreign data, an invalid
marker, and a symlink. The fixture uses `--profile fake` and temporary paths;
it verifies the real ownership guard, but is not installed E4 evidence.

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
  --guest debian13 --guest ubuntu2404 \
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

For an independent single-guest attempt, select only that guest and supply only
its image and digest, for example:

```sh
O3K_PP6_QUAL_ROOT=/var/lib/o3k-pp6-qualification \
  tests/pp6-qualification/host-env.py provision \
  --run-id pp6-20261101-ubuntu1 --guest ubuntu2404 \
  --ubuntu-image /srv/qualification/ubuntu-24.04.qcow2 \
  --ubuntu-sha256 <official-image-sha256>
```

Each complete evidence record includes the exact selected guest set and refuses
to validate a record whose guest identities differ from that set. On failure,
the harness retains bounded serial output, domain/network XML, bridge/interface,
route, neighbor and libvirt observations, and SSH/cloud-init diagnostics when
host-key-pinned SSH is available. Failed resources remain run-owned for
diagnosis and require the ownership-checked `destroy` command after evidence
review.

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
