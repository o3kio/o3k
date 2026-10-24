# Installation and service health

This runbook covers the O3K TestLab one-line installation path and the
read-only health checks provided by the installed services. It applies to the
`libvirt` profile on Ubuntu 24.04 or Debian 12, x86_64. These are the supported
platform boundaries documented by the installer; other distributions,
architectures, and deployment profiles are outside this runbook.

The installer is the published `install.sh` release asset. It verifies the
release before extracting it, installs the control plane and compute agent,
waits for service readiness, and runs `o3k doctor`. Follow
[`docs/INSTALLER.md`](../INSTALLER.md) for the exact release verification and
bootstrap sequence.

## Install

On a clean supported host, run the published installer as root:

```sh
curl -sfL https://get.o3k.io | sudo sh -
```

This default path is not itself evidenced for the currently pinned release.
The fresh-host evidence recorded in
[`docs/status/current-state.yaml`](../status/current-state.yaml) covers PP.2
on the published `v0.4.0-rc.5` release assets (Ubuntu 24.04 and Debian 12,
`o3k-demo-v1` single-host scope). Later pinned release candidates are not yet
evidenced by a fresh-host campaign.

The installer is pinned to one release. It does not select a moving `latest`
channel or fall back to a source checkout. For a reproducible installation,
use the release-specific URL and record the installed release identity printed
by the installer.

After installation, the generated operator files are private:

```text
/etc/o3k/admin-openrc
/etc/o3k/clouds.yaml
```

Source one of these files only in the shell that needs the client credentials.
Do not paste their contents into logs, support reports, or issue comments.

## Check service health

The service units and endpoints are local, read-only observations:

```sh
sudo systemctl is-active o3kd.service
sudo systemctl is-active o3k-compute.service
curl -fsS http://127.0.0.1:18080/healthz
curl -fsS http://127.0.0.1:18080/readyz
curl -fsS http://127.0.0.1:9100/readyz
sudo o3k doctor
```

`healthz` reports process health. `readyz` reports whether the control plane
or compute agent is ready. `o3k doctor` combines read-only host, service,
database, identity, compute, libvirt, network, cloud, security, and release
checks. Its machine-readable shape is defined by
[`contracts/o3k-doctor-output.schema.json`](../../contracts/o3k-doctor-output.schema.json).

The doctor command never repairs the installation. It uses read-only database
access and state queries. Exit status `0` means healthy; status `1` means a
warning or unhealthy result; status `2` means a usage or internal error.
Inspect the reported check ID, summary, and recommended action before taking
an administrative action.

## First checks when a service is unavailable

Collect only bounded observations and review/redact them before sharing. In
particular, `systemctl status` includes recent journal lines, so its output
must be inspected for secrets or provider payloads before it leaves the host:

```sh
sudo systemctl status --no-pager o3kd.service o3k-compute.service
sudo o3k doctor --json > doctor.json
```

Review `doctor.json` for the failing check and remove it after sharing the
relevant redacted result. Do not include environment files, credentials,
private keys, tokens, database URLs, or unredacted provider payloads in a
diagnostic report.

If the control plane is unavailable, resolve that condition before treating
the compute agent's readiness result as meaningful. If the compute agent is
unavailable while the control plane is healthy, inspect the compute unit and
the agent readiness check; do not recreate guests or modify provider state as
a first response.

## Scope and limitations

This runbook documents the bounded libvirt TestLab installation and its
read-only health checks. It does not establish a production, HA, PostgreSQL,
Kubernetes, multi-region, or fixed-scale support claim. Control-plane backup
and restore, certificate lifecycle operations, and generalized upgrade or
rollback procedures require their own accepted contracts and evidence and are
therefore not procedural steps here.

The authoritative sources for architecture and claims remain
[`AGENTS.md`](../../AGENTS.md), [`docs/NORMATIVE_SOURCES.md`](../NORMATIVE_SOURCES.md),
the product profile, the installer contract, and the doctor output contract.
This page is explanatory documentation and does not change those authorities.
