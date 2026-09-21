# One-line O3K TestLab installer (alpha)

On a clean supported Linux VM, this is the entire install:

```sh
curl -sfL https://get.o3k.io | sudo sh -
```

`get.o3k.io` is only a convenience 302 redirect to the official GitHub
Release asset. The canonical direct alpha URL is:

```sh
curl -sfL https://github.com/o3kio/o3k/releases/download/v0.2.0-alpha.2/install.sh | sudo sh -
```

The future stable URL will be
`https://github.com/o3kio/o3k/releases/latest/download/install.sh` —
it is **not** the alpha source and must not be used before a stable release
exists.

The `install.sh` asset is the byte-identical export of
[`packaging/get-o3k.sh`](../packaging/get-o3k.sh), the single auditable
installer source in the repository. It is a small, auditable wrapper script
that downloads the certified release bundle from GitHub Releases, verifies
it, and drives the same packaging scripts a manual install uses — it is a
thin orchestrator, not a second implementation of installation, TLS,
accounts, or state ownership.

## Supported platforms

- Ubuntu 24.04 (noble) x86_64
- Debian 12 (bookworm) x86_64
- libvirt TestLab alpha profile (KVM execution)

Anything else fails with a clear message before any change is made. ARM,
RHEL/Fedora, other releases, and other profiles are not supported.

## What the wrapper does

1. refuses non-Linux, non-x86_64, non-Ubuntu-24.04/Debian-12 hosts, and
   non-root runs;
2. creates a private `mktemp -d` temp dir with trap cleanup — nothing is
   executed from unverified content;
3. resolves the version from the pin baked into the installer
   (`O3K_INSTALLER_VERSION=v0.4.0-rc.22` in the current source); precedence is the `O3K_VERSION`
   env override (dev/test only) > an optional endpoint-injected
   `O3K_PINNED_VERSION` first line > the baked pin. The installer never
   consults a channel service and never falls back to `main`/`latest`;
4. downloads `release-digests.txt`, its Sigstore bundle, and `provenance.json`
   before any archive or host mutation;
5. verifies the exact protected GitHub workflow/tag identity, OIDC issuer,
   pinned Fulcio chain, signed digest, and Rekor transparency proof using the
   embedded system-OpenSSL/Python consumer verifier;
6. apt-installs the certified dependency set (the only place the wrapper may
   install packages) and enables `libvirtd`;
7. downloads `o3k-<version>-linux-x86_64.tar.gz` and obtains its expected
   digest from the authenticated manifest. The separately published `.sha256`
   is checked only as convenience integrity data;
8. extracts safely (rejects absolute paths, `..` components, entries not
   under `./`, and any non-regular entry — symlinks, devices, fifos, and
   sockets — detected from the archive listing);
9. cross-checks extracted `manifest.json` against authenticated provenance,
   then runs the bundled `packaging/verify-release-bundle.sh`, then
   `packaging/preflight.sh --profile libvirt` — preflight failure aborts;
10. bootstraps mTLS identities only when the complete TLS set is absent —
   valid existing identities are never regenerated, and a partial set fails
   closed;
11. runs the bundled `packaging/install.sh --profile libvirt --noninteractive`
    with the verified binaries — the same layout and fences as a manual
    certified-bundle install;
12. waits for `o3kd` health (`127.0.0.1:18080/healthz`);
13. runs the canonical P15.6 bootstrap as orchestration only
    (`contracts/installer-v1.yaml` — the installer never fabricates
    topology, Placement providers, BuildingBlocks, CloudProfile state, agent
    identity, or readiness): canonical `o3k init`, executed as the `o3k`
    service account and authenticated by `O3K_BOOTSTRAP_SECRET` from
    `/etc/o3k/o3kd.env`, creates the CloudProfile and a one-time enrollment
    grant; authenticated `o3k join` then presents this host's mTLS agent
    certificate and creates exactly one local BuildingBlock with Placement
    inventory. The enrollment token is written to a root-owned 0600
    temporary file, parsed, and destroyed immediately — it is never printed;
14. starts `o3k-compute.service` and waits for the compute agent
    (`127.0.0.1:9100/readyz`), then canonical control-plane readiness
    (`127.0.0.1:18080/readyz`), then gates on `o3k doctor` reporting a
    healthy installation before any workload is created;
15. runs the bundled `packaging/bootstrap-testlab.sh`, which first verifies
    the canonical bootstrap state (read-only: bootstrap phase `ready` plus a
    ready BuildingBlock — it fails closed otherwise) and then uses **public
    OpenStack APIs only** to converge the bounded demo workload (CirrOS
    image, network, subnet, port, flavor, keypair, `test-vm`, console boot
    marker);
16. prints the cloud identity, BuildingBlock id, endpoint URLs, credential
    paths, and next commands — never secrets.

The TestLab bootstrap replaces the manual steps of
[`docs/cirros-walkthrough.md`](cirros-walkthrough.md) but produces the same
public-API resources.

## Pinned versions and overrides

Every published installer is pinned to its own release version (the baked
`O3K_INSTALLER_VERSION` constant in `packaging/get-o3k.sh`), so the plain
`curl | sudo sh -` form installs exactly `v0.4.0-rc.22` in the current source.
The rc.22 candidate contains the consumer trust repair and must be independently
round-tripped before fresh-host PP.4 evidence is accepted. The
installer never asks any endpoint which version to install.

Version resolution precedence:

1. `O3K_VERSION` environment variable (explicit dev/test override, highest
   precedence):

   ```sh
   curl -sfL https://get.o3k.io | sudo env O3K_VERSION=v0.4.0-rc.22 sh -
   ```

2. an optional `O3K_PINNED_VERSION="<version>"` first line, kept for the
   optional Worker's `/v<version>` endpoint paths
   ([`packaging/get-o3k-worker/`](../packaging/get-o3k-worker/README.md));
3. the baked `O3K_INSTALLER_VERSION` release pin.

There is no channel fetch and no fallback to `main`/`latest`: a version can
only resolve to an exact published release version.

## What is verified

Exactly this chain is verified before anything from the archive runs:

- the tagged GitHub Release asset over HTTPS (production URLs are pinned to
  HTTPS; HTTP is permitted only through the documented `O3K_RELEASE_BASE`
  dev/test override);
- the published SHA-256 of the tarball, checked **before** extraction;
- the bundle's own `SHA256SUMS` (exactly the regular bundle files) and the
  glibc baseline via the bundled `verify-release-bundle.sh`;
- the SSH-signed release tag is the authenticity anchor of the published
  release itself (v0.2.0-alpha.1 model: ssh-ed25519 signature on the tag).

The checksums are integrity checks, not an authenticity signature; see
[`docs/RELEASE.md`](RELEASE.md) for the signing position.

`packaging/channels.yaml` and the optional Worker remain for future
channel/version functionality only; they are **not** part of the trusted
installation path. The production `get.o3k.io` behavior is a Cloudflare
Redirect Rule (see
[`packaging/get-o3k-worker/cloudflare-redirect.md`](../packaging/get-o3k-worker/cloudflare-redirect.md));
release archives are served by GitHub Releases, not proxied through any
Cloudflare service.

## Credentials

After a successful install:

```text
/etc/o3k/admin-openrc    # mode 0600, ledger-owned
/etc/o3k/clouds.yaml     # mode 0600, ledger-owned
```

Use them exactly like any OpenStack client configuration:

```sh
source /etc/o3k/admin-openrc
openstack server list
openstack console log show test-vm
```

The admin password is generated by `packaging/install.sh` (the single source
of truth) and is never printed by the installer. The canonical bootstrap
secret (`O3K_BOOTSTRAP_SECRET` in `/etc/o3k/o3kd.env`) is generated by
`scripts/generate-passwords.sh` at install time, preserved verbatim on every
regeneration, and never printed. The TestLab keypair private
key is `/etc/o3k/testlab-key.pem` (mode 0600, ledger-owned).

## Shared-port catalog and client endpoint overrides

The native control plane serves the compatibility APIs on one shared port
(`http://127.0.0.1:18080`), and its service catalog advertises the image and
network services at that **bare catalog root**. The bare root responds with
the identity version document, so python-openstackclient version discovery
for image/network receives the identity document and aborts with *"The image
service for :RegionOne exists but does not have any supported versions"* —
the recorded v0.4.0-rc.1 fresh-host defect, reproduced on both Ubuntu 24.04
and Debian 12.

For that reason both client configurations pin the versioned service roots
explicitly instead of relying on catalog discovery:

- the generated `/etc/o3k/clouds.yaml` (mode 0600, written by
  `packaging/install.sh`) sets `image_endpoint_override:
  http://127.0.0.1:18080/v2` and `network_endpoint_override:
  http://127.0.0.1:18080/v2.0`;
- `packaging/bootstrap-testlab.sh` writes the same overrides into its own
  temporary 0600 `clouds.yaml` (`OS_CLIENT_CONFIG_FILE`), so every
  `openstack` invocation it makes uses one consistent client configuration;
- the protected canonical bootstrap
  ([`scripts/bootstrap-disposable-testlab.sh`](../scripts/bootstrap-disposable-testlab.sh))
  carries the same overrides.

This is a client-workaround for the shared-port catalog shape, not a second
endpoint authority: the advertised service roots remain the canonical
catalog URLs.

## Running it again (idempotency)

A second run converges instead of creating duplicates. The current installer
prints this marker sequence on both a fresh install and a re-run (modulo
apt/curl progress noise, and `created` instead of `already present` on the
per-resource lines of a first install):

```text
O3K v<version> already installed              # re-runs only
✓ O3K v<version> verified
✓ KVM available
✓ TLS identities preserved                    # fresh install: ✓ mTLS identities ready
✓ o3kd installed
✓ o3k-compute installed
✓ control plane ready
✓ canonical bootstrap initialized (CloudProfile + enrollment grant)
✓ canonical authenticated join complete (BuildingBlock <id>)
✓ compute agent ready
✓ control plane ready (canonical readiness)
✓ o3k doctor healthy
✓ canonical bootstrap state verified (phase ready, BuildingBlock ready)
✓ image cirros-0.6.3 already present
✓ flavor testlab-flavor already present (512 MB / 10 GB / 1 vCPU)
✓ network testlab-network already present
✓ subnet testlab-subnet already present (192.0.2.0/29)
✓ port testlab-port already present (192.0.2.2)
✓ keypair testlab-keypair already present
✓ server test-vm already present
✓ server test-vm ACTIVE with fixed IP 192.0.2.2 and config-drive
✓ console boot marker verified (cirros|login:)
TestLab resources already present
TestLab ready — try: openstack server list ; openstack console log show test-vm
```

The old `✓ compute agent connected` marker no longer exists: the compute
agent now starts only after the canonical authenticated join, and readiness
is reported by `✓ compute agent ready` plus `✓ control plane ready
(canonical readiness)` and the `✓ o3k doctor healthy` gate. The previously
recorded verbatim second-run output (from the passing Ubuntu 24.04 campaign
in
`target/real-host-workflow-artifacts/asr-022-cd15263/one-line-ubuntu-passed/rerun-output.txt`)
predates the canonical bootstrap and shows that older marker set; a
fresh-host campaign recording of the canonical output is pending under
PP.2 (#971), so treat the block above as the expected marker sequence of
the current installer, not verbatim campaign evidence.

After the TestLab bootstrap the installer prints a final summary:

```text
O3K is ready.

Cloud: single-node demo (o3k-demo-v1)
BuildingBlock: <id>
Endpoints:
  identity/image/network/compute/placement: http://127.0.0.1:18080
  native API: http://127.0.0.1:18080/o3k/v1
Credentials:
  /etc/o3k/admin-openrc
  /etc/o3k/clouds.yaml

Try:

  source /etc/o3k/admin-openrc
  openstack server list
  openstack console log show test-vm
  sudo o3k doctor
```

On Debian 12 the flavor line reads `✓ flavor testlab-flavor already present
(in use; spec verified when it was created)` instead, because its
python-openstackclient 6.0.0 cannot enumerate flavors; everything else is
identical.

No new admin password, TLS identities, users, services, networks, images, or
`test-vm` are created on re-run.

## Upgrade and rollback

The `o3k` operator CLI owns upgrades; the one-line installer never upgrades an
existing installation (see the fence below). After the first install, every
journey runs from the installed binary:

```sh
sudo o3k version                       # binary version + installed release version
sudo o3k upgrade --check               # read-only preflight verdict, no download
sudo o3k upgrade [--to vX.Y.Z] [--yes] [--json]
sudo o3k rollback [--yes] [--json]
```

`upgrade` resolves the target release (explicit `--to`, or the newest published
release in the same channel family) through the official GitHub Release
assets, verifies the published SHA-256 and the bundle's own `SHA256SUMS`
before anything is extracted, then runs the phase machine: preflight → backup
→ stop `o3k-compute` then `o3kd` → atomic binary replacement → start `o3kd`
then `o3k-compute` (the embedded migrator applies any pending migrations) →
doctor → commit. `upgrade --check` mutates nothing and downloads nothing.

Backups live under `/var/lib/o3k/backups/<backup-id>/` (directory 0700,
files 0600): the pre-upgrade SQLite snapshot (crash-consistent `VACUUM INTO`,
never a raw copy of a live WAL database), a copy of `/etc/o3k` configuration
(credentials and TLS are copied verbatim, never regenerated, never printed),
the installed release manifest/SHA256SUMS/ownership ledger, and `backup.json`
recording versions, binary hashes, the schema version, and the
migration-compatibility decision. Retention keeps the **last 2 backups** plus
the rollback-chain record `/var/lib/o3k/backups/backup-chain.json`; `rollback`
always selects the immediately previous successful upgrade snapshot from the
chain and only ever trusts O3K-created, hash-verified records.

Downgrade policy: `upgrade --to <older>` is refused explicitly, never silent.
Upgrades from a release older than the target's declared
`upgrade_from.min_version` fail closed with "unsupported upgrade path;
reinstall required". Migration compatibility is declared by the release
itself (`schema_version` in the bundle manifest, computed from
`crates/o3k-store/migrations/`): when the schema version is unchanged, rollback
is binaries-only (the backup stays as a safety net); when migrations ran,
rollback restores the pre-upgrade database snapshot together with the old
binary set. No migration is reversible, so a schema-changing rollback is
always a restore, never a down-migration.

Failure recovery: a failure in any phase aborts with no mutation before the
backup exists, restores the old binaries on a partial switch, or restores the
pre-upgrade database plus binaries after a migration failure. One automatic
rollback attempt runs per invocation; if the rollback itself fails, an
explicit `FAILED_UPGRADE` state records the backup id and prints the exact
next command (`sudo o3k upgrade` to resume or `sudo o3k rollback` to
recover). `sudo o3k doctor` remains the read-only post-upgrade validation
gate; the release checks (`release.binary_set_consistent`,
`release.backup_available`, `release.upgrade_state`) report mixed-version
installs, a missing backup on an otherwise healthy install, and interrupted
upgrade state.

Installer fence: `curl -sfL https://get.o3k.io | sudo sh -` never
auto-upgrades an existing install. On a host with an installed release, the
installer compares the resolved target version against
`/usr/local/share/o3k/release-manifest.json` **before any mutation**:

- same version → the normal idempotent convergence run;
- installed version newer → exit 1 with
  `installed vX is newer than requested vY; refusing implicit downgrade`
  (nothing downloaded, nothing mutated);
- installed version older → the verified release bundle (tarball + published
  `.sha256` + `install.sh`) is downloaded into `/var/lib/o3k/upgrade-download/`
  (mode 0700; a previous interrupted delegation is re-verified and reused,
  a tampered one fails closed) and the installer prints the exact next
  command — `sudo /var/lib/o3k/upgrade-download/o3k-<target>/bin/o3k upgrade`
  — then exits 0. Nothing is extracted or executed by the installer itself;
  extraction is the upgrade engine's job. After the first upgrade, the
  installed `o3k` binary provides `sudo o3k upgrade` for all future
  journeys.

## Uninstall, reset, purge

Uninstall preserves state by default:

```sh
sudo /usr/local/share/o3k/uninstall.sh
```

Reset preserves credentials and removes only contents of marked O3K-owned
data/log directories:

```sh
sudo /usr/local/share/o3k/reset.sh --yes
```

Purge destroys state and requires both flags:

```sh
sudo /usr/local/share/o3k/uninstall.sh --purge --yes
```

Purge fails closed unless every precondition holds: valid ownership
manifests, no O3K-owned live libvirt domain, no O3K-owned network link, no
O3K DHCP process, no unclassified foreign state, and digest-verified
configuration files. Foreign files and foreign state are always preserved.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `unsupported kernel/architecture/distribution` | Run on Ubuntu 24.04 or Debian 12 x86_64 only; other systems are refused by design. |
| `preflight failed (--profile libvirt ...)` | The host does not meet the certified TestLab requirements — usually missing `/dev/kvm` (enable nested KVM or run on a KVM-capable VM), missing libvirt, or insufficient disk. The wrapper aborts; nothing is installed. |
| `download failed: ...` | GitHub Releases was unreachable, or the release asset is missing (404). Check network/proxy access to `get.o3k.io` and `github.com`; retry converges. |
| `published SHA-256 verification failed` | The downloaded archive does not match the published checksum. The installer refuses to extract or execute anything — verify your proxy/network is not tampering, then retry. |
| `release archive is not a readable gzip tarball` / unsafe entry message | The download was truncated or the archive shape is invalid. Nothing is extracted; retry. |
| `release bundle verification failed` | The bundled `verify-release-bundle.sh` rejected the archive. Do not bypass it. |
| `partial TLS identity set under /etc/o3k/tls` | Some but not all of the 7 TLS files exist. The installer refuses to regenerate valid identities; complete the set manually or remove the partial set deliberately. Never use `--force`. |
| `installation failed; the host holds recoverable O3K-owned state` | The bundled installer failed (for example a foreign populated install path). The host holds O3K-owned recoverable state; re-running the installer converges safely. |
| `TestLab bootstrap failed` | The public-API bootstrap failed after a successful install — inspect `openstack` CLI output; re-running is safe and idempotent. |

Test coverage for these paths lives in
[`tests/installer-negative.sh`](../tests/installer-negative.sh) and
[`tests/packaging-safety.sh`](../tests/packaging-safety.sh).

## Not claimed

This is an **alpha TestLab installer**. It does not claim:

- production readiness or a supported production topology;
- HA of any kind (including Kubernetes HA);
- PostgreSQL persistence;
- full OpenStack service parity or API breadth beyond the accepted
  compatibility profiles;
- native Cinder/volume service;
- advanced networking, VM internet egress, or host-wide NAT;
- ARM, RHEL/Fedora, Ubuntu 26.04, or any platform beyond the two listed;
- anything on hosts that fail the certified preflight.

Alpha framing applies to the installer itself as much as to `v0.2.0-alpha.2`:
the real-VM campaigns (fresh Ubuntu 24.04 and Debian 12 installs, reboot
recovery, re-run, uninstall/reinstall/purge) and the live `get.o3k.io`
publication are release-gated evidence steps, tracked in
[`docs/plan/alpha-2-release.md`](plan/alpha-2-release.md) (the release-model
changes) and [`docs/plan/one-line-installer.md`](plan/one-line-installer.md)
(the original one-line installer milestone record).
