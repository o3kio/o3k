# PP.4 — One-line O3K + Araf demo

This is the PP.4 public demo path (o3kio/o3k#973). From a fresh supported
host (Ubuntu 24.04 or Debian 12, x86_64, hardware virtualization available):

```sh
curl -sfL https://github.com/o3kio/o3k/releases/download/v0.4.0-rc.7/install.sh | sudo sh -
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
  version: v0.4.0-rc.7
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

Everything above — Araf, the OpenStack CLI, and the native `o3k` CLI — sees
the **same canonical O3K resources**. Araf is the supported O3K dashboard;
the OpenStack-compatible API is a bounded projection used by external
ecosystem clients (CLI, optionally Horizon, OpenTofu).

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
