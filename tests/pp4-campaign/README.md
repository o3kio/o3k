# PP.4 campaign harness (o3kio/o3k#973)

Fresh-host acceptance for the one-line O3K + Araf demo. A nested-KVM VM with
no repo and no bundle runs the **exact published installer**

```sh
curl -sfL https://github.com/o3kio/o3k/releases/download/<version>/install.sh | sudo sh -
```

and the harness then proves, with durable numbered evidence:

- success output, timing stamps T0–T5, verified release artifacts (installed
  version **and** source commit must equal the campaign revision);
- the deployed Araf is the **pinned production tuple**: the tenant BFF container
  environment carries `ARAF_UPSTREAM_ADAPTER=o3k` + `ARAF_RUNTIME_PROFILE=production`
  (never fixture mode), the three Araf container image digests equal the pinned
  config/index digests, and the compose service set is exactly the seven expected
  services (evidence `10-araf-production-tuple.txt`);
- the demo OIDC federation is wired through the demo-owned
  `/etc/o3k/o3kd-araf-demo.env` (0600) pulled in by the demo-owned systemd
  drop-in `/etc/systemd/system/o3kd.service.d/araf-demo.conf`, and
  `/etc/o3k/o3kd.env` stays **byte-identical to the O3K install-time content
  ledger** across the demo stage and across uninstall → reinstall → purge
  cycles (evidence `12b*`/`12c`/`27b`);
- demo capacity is evidence, not assumption: `O3K_COMPUTE_MAX_DISK_GB` in
  `/etc/o3k/o3k-compute.env` equals the Placement `DISK_GB` inventory total and
  leaves room for another 10 GB VM (evidence `12d`);
- guest boot proof — exactly what is asserted is: a libvirt domain whose XML
  carries `server_id="<canonical uuid>"` **and** `managed_by="o3k-compute"` is
  `running`, plus the guest console marker (`cirros|login:`) from
  `openstack console log show`. The DHCP lease capture is opportunistic
  diagnostic evidence only (dnsmasq lease files are not part of the supported
  contract) and is never a pass condition;
- real browser E2E (Playwright over CDP into an in-VM Chromium driven from the
  host): tenant + operator journeys, real OIDC. The CDP SSH forward is
  re-established and re-verified after the reboot gate (the reboot drops it);
- cross-interface canonical-truth scenarios A–D (Araf native <-> OpenStack CLI
  on the SAME canonical resource IDs), including the server the console deleted
  through its advertised action being truthfully absent in the unmodified CLI;
- supplemental OpenTofu smoke (unmodified terraform-provider-openstack 3.4.0,
  OpenTofu 1.12.6) against the same deployment;
- failure/recovery matrix, host reboot recovery, same-version rerun
  convergence (identical BuildingBlock/CloudProfile/PlacementProvider id sets,
  identical server id set, unchanged pinned image digests, and no
  `refusing to overwrite operator-modified configuration file` abort),
  uninstall/reinstall, purge/reinstall, foreign-state canaries;
- secret scans across browser and compatibility clients.

## Verified scope — what this campaign does NOT claim

The demo profile is deliberately bounded. These are **observed, classified
gaps** (`PP4-GAP <id> <detail>` lines from the browser journeys +
`35-classified-gaps.txt` from phase1b), not failures:

| Classified gap | Verified behaviour |
| --- | --- |
| `native-vm-create` | No native-create gap is accepted. The schema-driven browser create must succeed; any failure is a campaign failure. |
| `compat-created-resource-not-canonical` | On a fresh VM the native `image.image` and `network.network` inventories are empty while the installer's `testlab-network` and the demo image exist through the compatibility (Neutron/Glance) APIs. Every native row that does exist is confirmed against the canonical `resources` ledger. |
| `native-list-name-projection` | The native **list** projection carries `spec: {}` for `compute.server`, so a collection row's label falls back to the canonical id: rows are identified by ID, never by name (the detail projection still carries the name). |
| `native-server-start-not-advertised` | `compute.server` discovery advertises only delete/update; the console offers no start/stop action, and a native start attempt is rejected. |
| `tofu-created-network-not-canonical` | The unmodified Terraform provider creates its network through the compatibility API, so it is CLI-visible but not a canonical, Araf-listed row. |
| `images-native-inventory=compat-only` / `network-compat-created-not-canonical` | The browser-side observations of the two inventory gaps above, with the exact row/compat counts. |
| `operator-global-operations-not-exposed` | The operator console's dedicated global operations list (`/api/v1/operator/operations`) is not implemented by upstream O3K on this profile; the canonical `/api/v1/operations` list the same surface serves carries the tenant tie-in. |

What the campaign **does** prove about the console lifecycle: the browser
creates a native server, phase1b verifies its canonical id, provider domain,
guest boot, and OpenStack visibility while it remains live, and the same id is
then deleted through the advertised `delete` action. The canonical Operation
reaches a terminal state and the resource is truthfully absent in the
unmodified CLI (`No Server found`) and the Araf live view (404). Deletes keep a
`DELETED` tombstone in the canonical ledger; the native `show` view conceals it
while the collection may still list it with a non-live status.

## Honesty rules enforced by the harness

The campaign only reports `PASS` when the numbered evidence supports it:

- every in-VM phase writes `<phase>-done` with `status=failed` on any crash, so
  the host fails fast instead of polling out its full budget, and pulls phase
  diagnostics on failure;
- a query that *fails* is never read as "the resource is gone": the absence and
  presence helpers distinguish a failed CLI/HTTP call (fail closed) from an
  empty result, and cross-interface identity is always the canonical id;
- the browser journeys must perform their mutations through the **real UI**.
  Araf rc.15 supplies the CSRF header itself; any `PP4-UI-CSRF-BRIDGE` marker
  or UI fallback fails the campaign. Both native create and delete go through
  the advertised form/action and confirmation modal;
- classified gaps are evidence: they are recorded with their observed counts and
  are never turned into a PASS for behaviour that did not happen;
- `make-manifest.py` is fail-closed: the Araf tuple, the O3K release identity
  (from `06-release-identity.txt`), the browser markers (including the
  console-deleted server id and the classified create-error class), the
  post-reboot gate, the classified-gap ledger
  with the profile's known gaps, and the full expected acceptance-case set of
  all three phases must be present, or the manifest is written as `FAIL` and the
  campaign exits non-zero.

Usage:

```sh
# host, from repo root; needs /root/noble-server-cloudimg-amd64.img (Ubuntu);
# the Debian cloud image is downloaded into target/pp4-campaign/vms/ if absent
O3K_CAMPAIGN_VERSION=<published-successor-version> \
  O3K_CAMPAIGN_SOURCE_SHA=<published-source-sha> \
  bash tests/pp4-campaign/host-run.sh ubuntu target/pp4-campaign/ubuntu
O3K_CAMPAIGN_VERSION=<published-successor-version> \
  O3K_CAMPAIGN_SOURCE_SHA=<published-source-sha> \
  bash tests/pp4-campaign/host-run.sh debian target/pp4-campaign/debian
# optional Horizon witness (Ubuntu campaign, bounded, non-blocking):
O3K_PP4_HORIZON=1 bash tests/pp4-campaign/host-run.sh ubuntu ...
```

The campaign is always REAL-RELEASE (public GitHub assets). Evidence lands in
`<evidence-dir>/evidence-final`; `make-manifest.py` assembles the redacted
durable manifest. Raw logs stay gitignored; manifests are committed under
`docs/evidence/pp4/`.
