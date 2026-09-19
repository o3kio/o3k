# PP.4 — One-line O3K + Araf demo

This is the PP.4 public demo path (o3kio/o3k#973). From a fresh supported
host (Ubuntu 24.04 or Debian 12, x86_64, hardware virtualization available):

```sh
curl -sfL https://github.com/o3kio/o3k/releases/download/v0.4.0-rc.8/install.sh | sudo sh -
```

(`https://get.o3k.io` is a convenience redirect to the same release asset.)

That single command:

1. verifies the published release archive against its published SHA-256
   **before** extracting or executing anything from it;
2. installs the prebuilt O3K release (no source checkout, no Rust toolchain,
   no Node.js build);
3. runs the canonical `o3k init` and authenticated `o3k join` (one local
   BuildingBlock with real Placement inventory);
4. waits for canonical readiness (`o3k doctor`);
5. creates the bounded o3k-demo-v1 workload (CirrOS image, TestLab flavor,
   bounded flat network, `test-vm` with guest boot proof);
6. deploys the pinned Araf compatibility tuple (digest-verified OCI images)
   and waits for Araf readiness;
7. prints exactly what you need next.

## What you get

```text
O3K demo ready

O3K:
  version: v0.4.0-rc.8
  source: <release commit sha>
Araf:
  version: v1.0.0-rc.12
  source: de64cc9193085116fa30ad51c04ccab24a013dd0

Tenant Console:   https://tenant.o3k.demo/
Operator Console: https://operator.o3k.demo/
O3K API:          https://api.o3k.demo/
```

Open the tenant console in a browser. The demo uses a locally minted CA, so
import it once into your browser trust store:

```sh
sudo cp /var/lib/o3k/araf-demo/tls/ca.crt /usr/local/share/ca-certificates/o3k-demo-ca.crt
sudo update-ca-certificates
```

Demo login: user `alice`. The generated password is deliberately **not**
printed; read it from the root-only credentials file:

```sh
sudo cat /var/lib/o3k/araf-demo/credentials.txt
```

## Day-two commands

```sh
# layered health (O3K readiness is independent of Araf)
sudo /usr/local/share/o3k/araf-demo/o3k-araf-demo.sh status
sudo o3k doctor

# OpenStack CLI compatibility witness (unmodified python-openstackclient)
source /etc/o3k/admin-openrc
openstack server list
openstack server create --image cirros-0.6.3 --flavor testlab-flavor \
  --nic net-id=$(openstack network show testlab-network -c id -f value) demo-vm
openstack console log show demo-vm        # guest boot marker
openstack server delete demo-vm

# tenant/operator surfaces (real OIDC via the demo IdP)
#   https://tenant.o3k.demo/    - project-scoped tenant console (Araf)
#   https://operator.o3k.demo/  - platform/operator console (Araf)
```

Everything above — Araf, the OpenStack CLI, and the native `o3k` CLI — reads
the **same canonical O3K cloud state**. Araf is the supported O3K dashboard;
the OpenStack-compatible API is a bounded projection used by external
ecosystem clients (CLI, optionally Horizon, OpenTofu).

## What the native console can and cannot do today

Verified on fresh Ubuntu 24.04 and Debian 12 hosts (see
`docs/evidence/pp4/`). This is the honest surface of `o3k-demo-v1`:

Works natively in Araf (real O3K native API, no fixtures):

- OIDC login, project scope selection, service catalog, capacity/usage,
  regions and deployment context, operations list/detail with canonical
  Operation states;
- **server inspection**: servers created by the demo (and by the OpenStack
  CLI) appear with their canonical UUID and truthful state;
- **server deletion through the console UI**: the advertised native
  `DeleteServer` action runs through the real console (confirmation modal,
  canonical Operation, truthful final state), and the resource is then absent
  from the OpenStack CLI too — the cross-interface proof;
- operator views: platform overview, installed services, provider/agent
  health, capacity, regions.

Not supported by this profile (truthful failures, recorded as classified
gaps — no fabricated data is ever shown):

- **creating anything from the console** (VM or network): the pinned Araf
  release cannot compile the JSON Schema 2020-12 create schemas O3K serves
  (its validator defaults to draft-07). The console surfaces an error and
  creates nothing. The upstream fix is prepared (o3kio/araf#118) and will
  ship in the next Araf candidate;
- **native VM creation even through the API**: the native create path needs
  the O3K network execution agent to resolve a port, and `o3k-demo-v1` ships
  that agent inactive by contract. Create VMs with the OpenStack CLI (above)
  and they appear in Araf immediately;
- **native image and flavor inventories**: the demo's CirrOS image and
  TestLab flavor exist through the OpenStack-compatible API only
  (`openstack image list`, `openstack flavor list`); the native image
  collection is empty and no flavor resource type is advertised;
- **canonical parity for compat-created networks and images**: a network
  created through the OpenStack-compatible API (including the installer's
  `testlab-network`) is not a canonical native resource, so it does not
  appear in the native network list. Servers *are* canonical in both
  directions — that is what the cross-interface tests prove;
- **operator global operations** (`/api/v1/operator/operations`) — not
  implemented by the production O3K adapter; the operator console states
  that truthfully.

## Uninstall / purge

```sh
# remove the Araf demo runtime (O3K keeps running; demo state preserved)
sudo /usr/local/share/o3k/araf-demo/o3k-araf-demo.sh uninstall

# remove ALL demo-owned state (containers, volumes, demo CA, IdP data, /etc/hosts entries)
sudo /usr/local/share/o3k/araf-demo/o3k-araf-demo.sh purge

# remove O3K itself (only when the demo stack is already removed)
sudo bash /usr/local/share/o3k/uninstall.sh --yes
```

Uninstall/purge touch only O3K/Araf-owned files, containers, volumes, and
networks. Foreign state (your other containers, VMs, networks, files) is
never touched; there is deliberately no `docker prune` anywhere.

## Honest boundaries (o3k-demo-v1)

- single host; not HA, not multi-node, not datacenter scale;
- no persistent volumes; guest roots are ephemeral;
- the demo IdP (Keycloak start-dev) is not a production identity system;
- native demo sessions are 1-hour tokens without renewal;
- OpenStack compatibility is a bounded, operation-level profile — not
  blanket OpenStack parity. Horizon is an optional external witness, not the
  O3K dashboard.

Campaign evidence (Ubuntu 24.04 and Debian 12, fresh hosts, public
artifacts): `docs/evidence/pp4/`.
