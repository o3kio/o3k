# Early Access operator guide

This guide is for isolated qualification and, after the release gate, the
bounded O3K Early Access profile. The target is Ubuntu 24.04 LTS x86_64, one
active controller, PostgreSQL 16, KVM/libvirt, and one to three hypervisors.
The profile is for development, test, and selected replaceable non-critical
semi-production workloads. It does not claim HA, automatic evacuation, live
migration, enterprise SLA, general disaster recovery, or full production
certification.

## Release status and installation

`v0.4.1-rc.N` is qualification-only. Do not use it for customer workloads.
The current host must be fresh: the installer refuses existing O3K state,
recovery state, PostgreSQL clusters, and ambiguous service identities. Keep
the existing v0.4.0/C1 qualification environment separate.

After an authenticated candidate is published, the exact-artifact command is:

```sh
curl -fsSL https://github.com/o3kio/o3k/releases/download/v0.4.1-rc.1/install.sh | sudo sh -
```

The wrapper authenticates the release before extracting or executing bundled
files, then invokes canonical initialization and authenticated host join. It
does not compile O3K on the target. The signed manifest explicitly selects
`o3k-early-access-v1` / `early-access-v1` / `installation-local`; missing or
ambiguous selection fails closed. A rerun on the same installation preserves
its identity and credentials. Do not copy its trust or identity files to
another host.

## Hardware and prerequisites

- Ubuntu 24.04 LTS, x86_64, run the installer as root.
- KVM must be available and readable/writable by the installer.
- At least 1 GiB free on `/var` is required by the preflight check.
- Allow additional CPU, memory, and disk for the O3K controller, PostgreSQL,
  compute agent, guest images, and intended VM workloads. The profile does not
  define a validated fixed hardware SKU or capacity promise.
- Do not provide a host with an existing PostgreSQL cluster for automatic
  provisioning. The installer provisions PostgreSQL 16 only on a fresh host
  and refuses foreign or ambiguous database state.

## Database and readiness

The EA installer provisions PostgreSQL 16, creates the least-privilege `o3k`
role and database, applies migrations, and configures the local Unix-socket
connection. Verify PostgreSQL and service health after installation:

```sh
sudo pg_lsclusters
sudo -u postgres psql -d postgres -c 'SELECT version();'
sudo systemctl is-active postgresql o3kd o3k-compute
curl -fsS http://127.0.0.1:18080/readyz
curl -fsS http://127.0.0.1:9100/readyz
sudo o3k doctor
```

Readiness includes canonical controller and compute-agent state, not only
process liveness. If installation fails, use the reported failing stage and
the redacted checks below; retry only after understanding whether the failed
transaction left owned state that the installer can safely resume.

## Initial cloud and compute hosts

The first host is initialized by `o3k init` and enrolls its local compute
agent through authenticated `o3k join`. To add a host, use the supported host
enrollment workflow and verify the host appears as a canonical BuildingBlock
with fresh Placement inventory before scheduling workloads. Do not copy the
controller's installation-local trust material to compute hosts. Use the
administrator credentials and CLI configuration created by the installer;
keep them root-readable and out of logs and support reports.

The accepted profile permits one to three hypervisors. Add hosts only after
the single-host lifecycle is healthy. Drain and remove a host through the
supported control-plane lifecycle; do not assume automatic evacuation or
live migration. Prepare the host with its own O3K compute agent identity and
mTLS certificate, obtain a single-use join grant through the approved
controller enrollment flow, and invoke canonical `o3k join` with its token
provided through a root-owned mode-0600 `O3K_ENROLLMENT_TOKEN_FILE` (never
`--token`, which would expose it in the process command line). Supply the
agent ID, epoch, certificate path, and observed VCPU, memory-MB, and disk-GB
inventory. The command shape is:

```sh
sudo env \
  O3K_API_URL=https://controller.example/o3k/v1 \
  O3K_ENROLLMENT_TOKEN_FILE=/run/o3k/join-token \
  /usr/local/bin/o3k join \
    --agent-id compute-02 \
    --agent-epoch <current-agent-epoch> \
    --certificate /etc/o3k/tls/agent.pem \
    --vcpus <observed-vcpus> \
    --memory-mb <observed-memory-mb> \
    --disk-gb <configured-disk-gb>
sudo rm -f /run/o3k/join-token
```

The enrollment grant must be in a root-owned mode-0600 file; do not use the
`--token` option because process arguments can be visible to other local
users. Confirm the resulting BuildingBlock and fresh Placement inventory
through the control plane before it receives workloads. The installer only
automates the first local host; it does not copy installation-local trust to
new hosts.

## First VM, networking, and storage

Use the native O3K CLI/API and the operations already advertised by the
installation. Create a project and network, select an available image/flavor,
create a VM, and verify its state and console before treating the workload as
usable. Keep the first workload disposable until the SPEC-0052 acceptance
campaign is complete. Use only the documented networking and storage
capabilities shown by the active service catalog and product profile; do not
infer support for unadvertised OpenStack operations, advanced fabric behavior,
or external storage backends. A concrete public-API smoke sequence is in the
[CirrOS TestLab walkthrough](../cirros-walkthrough.md); use an image that you
have independently obtained and verified, and check that the operations are
advertised by the Early Access deployment before running that sequence.

For a lifecycle check, observe create, boot, connectivity, stop/start/reboot,
delete, and canonical cleanup. Verify that network ports, storage attachments,
and owned resources are removed after deletion. Guest disks and external
storage payloads are not protected by controller database procedures.

## Diagnostics and troubleshooting

Start with read-only observations:

```sh
sudo o3k doctor --json > doctor.json
sudo systemctl status --no-pager o3kd o3k-compute
sudo journalctl -u o3kd -u o3k-compute --since '15 minutes ago' --no-pager
```

Review output for secrets before sharing. Never share environment files,
tokens, private keys, database URLs, guest user-data, or unredacted provider
payloads. Do not retry a mutating operation solely because a request timed
out; inspect canonical operation/resource state first. For unresolved defects,
open an issue with O3K version, source SHA, artifact digest, host count, and
redacted diagnostics. Maintainer support is best-effort during Early Access;
there is no enterprise SLA.

## Workload data and clean rebuild

Protect guest disks and external storage with their own backend procedures
before onboarding any workload. O3K Early Access does not provide general
disaster recovery or restore controller state into an activated cloud. A clean
rebuild creates a new installation identity and does not restore workloads.

Before a destructive rebuild:

1. Stop admitting workloads and record resource IDs and external data mappings.
2. Back up guest disks and external storage using their supported procedures.
3. Verify those backups independently and retain access to required images,
   networks, and credentials.
4. Use the documented destructive rebuild procedure only after confirming the
   old O3K state is intentionally being abandoned.
5. Install on a genuinely clean host, initialize a new cloud, and reconcile
   external data only through supported O3K authority and lifecycle APIs.

Never delete foreign PostgreSQL clusters, networks, storage, or workload data
to make installation succeed. Missing, corrupt, copied, or mismatched local
trust blocks admission; it does not select another trust mode.
