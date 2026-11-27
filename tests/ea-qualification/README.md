# O3K Early Access qualification substrate

This directory owns the repeatable one- and three-host nested-KVM substrate
used by the EA qualification profile. It is deliberately separate from the PP.5 harness.
It verifies the pinned Ubuntu 24.04 cloud image, defines an isolated campaign
NAT network and directory storage pool, creates backed qcow2 overlays and
cloud-init seeds, then provisions the guests without building O3K source in
them. It injects a per-guest SSH host key before first boot and uses that
public key as a strict `known_hosts` pin.

```sh
cp tests/ea-qualification/ea-config.env.example tests/ea-qualification/ea-config.env
# Edit the campaign-owned names, UUIDs, paths, and pinned Ubuntu image digest.
bash tests/ea-qualification/ea-testlab.sh inventory
bash tests/ea-qualification/ea-testlab.sh provision 1
bash tests/ea-qualification/ea-testlab.sh ssh a 'hostnamectl --static'
bash tests/ea-qualification/ea-testlab.sh cleanup
```

Use `provision 1` for the single-host campaign and `provision 3` for the
three-host substrate. The NoCloud seed contains root-level `user-data` and
`meta-data` files, preserves the injected per-guest SSH host key, and must pass
strict host-key authentication plus an in-guest nested-KVM check before it
records a host as ready.

The default plan is controller-capable host A (4 vCPU/8 GiB) and compute hosts
B/C (4 vCPU/6 GiB), each with a 20 GiB sparse overlay under the campaign pool.
The network and pool UUIDs, disk image checksum, private SSH client key, and
guest host-key pins are campaign-specific. `cleanup` first verifies the marker,
network/pool UUIDs, each domain UUID, and the exact disk/seed paths before it
removes guest domains and their campaign files. It keeps the campaign pool,
network, and inventory evidence for inspection and repeat provisioning.

After provisioning, qualify the authenticated release artifact through its
public installer and Sigstore checks. The `ssh` action pins every connection;
never disable host-key checking or put credentials on the remote command line.
