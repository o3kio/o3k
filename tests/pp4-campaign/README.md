# PP.4 campaign harness (o3kio/o3k#973)

Fresh-host acceptance for the one-line O3K + Araf demo. A nested-KVM VM with
no repo and no bundle runs the **exact published installer**

```sh
curl -sfL https://github.com/o3kio/o3k/releases/download/<version>/install.sh | sudo sh -
```

and the harness then proves, with durable numbered evidence:

- success output, timing stamps T0–T5, verified release artifacts;
- real guest boot proof (libvirt domain + CirrOS console marker + DHCP lease);
- real browser E2E (Playwright over CDP into an in-VM Chromium with the demo
  CA imported into its trust store): tenant + operator journeys, real OIDC;
- cross-interface canonical-truth scenarios A–D (Araf native <-> OpenStack
  CLI on the SAME canonical resource IDs);
- supplemental OpenTofu smoke (unmodified terraform-provider-openstack 3.4.0,
  OpenTofu 1.12.6) against the same deployment, visible in Araf;
- failure/recovery matrix, host reboot recovery, same-version rerun
  convergence, uninstall/reinstall, purge/reinstall, foreign-state canaries;
- secret scans across browser and compatibility clients.

Usage:

```sh
# host, from repo root; needs /root/noble-server-cloudimg-amd64.img (Ubuntu) and
# target/asr-022-vms/debian-12-genericcloud-amd64.qcow2 (auto-downloaded if absent)
O3K_CAMPAIGN_VERSION=v0.4.0-rc.6 bash tests/pp4-campaign/host-run.sh ubuntu target/pp4-campaign/ubuntu
O3K_CAMPAIGN_VERSION=v0.4.0-rc.6 bash tests/pp4-campaign/host-run.sh debian target/pp4-campaign/debian
# optional Horizon witness (Ubuntu campaign, bounded, non-blocking):
O3K_PP4_HORIZON=1 bash tests/pp4-campaign/host-run.sh ubuntu ...
```

The campaign is always REAL-RELEASE (public GitHub assets). Evidence lands in
`<evidence-dir>/evidence-final`; `make-manifest.py` assembles the redacted
durable manifest. Raw logs stay gitignored; manifests are committed under
`docs/evidence/pp4/`.
