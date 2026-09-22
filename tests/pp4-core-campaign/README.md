# PP.4 Core campaign

This directory is the current PP.4 Core campaign path. It consumes only the
public immutable O3K release selected by the campaign (`v0.4.0-rc.22` for the
current candidate) and has no Araf dependency. The historical Araf-era scripts
remain under `tests/pp4-campaign/` and are not authoritative PP.4 Core
evidence.

The native helper uses the documented public project-scoped Keystone password
credential and exchanges the resulting durable user/project identity through
the native IAM token endpoint. It never scrapes the database, puts a bearer
credential in argv, or prints a credential.
Request JSON is written to a 0600 temporary file and sent as `--data-binary @file`
by the campaign driver.

Run the helper checks before provisioning a host:

```sh
python3 tests/pp4-core-campaign/test_native_client.py
python3 -m py_compile tests/pp4-core-campaign/native_client.py
bash -n tests/pp4-core-campaign/*.sh
```

The host driver must copy only these non-shipped campaign files into a fresh
Ubuntu 24.04 or Debian 12 VM, then install with the exact public command and
`O3K_SKIP_ARAF=1`. Runtime files must come from the public release. Evidence
must retain the release source SHA separately from the campaign harness SHA.

The first rc.18 real-KVM smoke reached native `Operation=succeeded`, guest
boot, and collision-safe port allocation, then exposed a mandatory product
defect: replaying the byte-equivalent create with the same idempotency key
returned HTTP 500 instead of the original canonical result. See
`docs/evidence/pp4-core/rc18-native-replay-failure.json`. Do not classify this
as a harness failure or continue to Horizon/full-distro certification until a
successor runtime candidate fixes it.

## Horizon witness boundary

`horizon-witness.sh` runs the pinned image
`quay.io/openstack.kolla/horizon:2026.1-ubuntu-noble` at OCI manifest digest
`sha256:723903d16317c53172f08c7f930b2c326f8b7fa16da98bf032e05ef287e0b048`
(Horizon `25.7.4.dev26`). Kolla rebuilds that tag continuously, so the digest —
not the tag — is the evidence identity, and
`docs/evidence/pp4/horizon-artifact.yaml` records when it was resolved. The
failed rc.22 campaign used the earlier Docker Hub
`openstackhelm/horizon:2024.1-ubuntu_jammy-20250523` pin; that remains
historical rc.22 evidence only and is never mixed with 2026.1 witness
evidence.

The image is unmodified: no fork, no source patch, no O3K-specific Horizon
code. Only ordinary configuration is supplied — endpoint, region, catalog,
session, `STATIC_ROOT`, `OPENSTACK_API_VERSIONS`, Kolla `config.json`, an
operator-supplied uWSGI ini, and the container runtime invocation.

Properties of that pinned image are harness assumptions, not O3K contracts, and
each one has already hidden a defect behind a misclassified failure:

- It **is** a Kolla image (`kolla_start` plus `/var/lib/kolla/config_files`), so
  it needs `KOLLA_CONFIG_STRATEGY` and a `config.json`, and its own
  `kolla_extend_start` collects static assets. Horizon settings are read through
  `openstack_dashboard/local/local_settings.py`, which the image ships as a
  symlink to `/etc/openstack-dashboard/local_settings.py` (with the `.py`
  suffix); a Kolla `dest` without that suffix is copied but never imported.
- The image ships no Apache; uWSGI serves the application, so the harness
  supplies the ini. Its default session backend is a per-process cache, so a
  session written by one uWSGI worker is invisible to the others and login
  appears to succeed while every later request is anonymous. Cookie-backed
  sessions are stateless across workers and are an ordinary Horizon setting.
- `OPENSTACK_API_VERSIONS['compute']` selects the **novaclient v2 client
  family**, not a Nova REST microversion. Upstream Horizon defaults it to `2`
  (`openstack_dashboard/defaults.py`), and Horizon's own API-version registry
  (`openstack_dashboard/api/base.py`) rejects any other value with
  `2.1 is not a supported API version for the compute service`. O3K
  legitimately exposes the bounded Nova v2.1 REST API while this setting stays
  `2`: the two are different layers and must not be conflated. Setting
  `compute: 2.1` here would be a harness defect, not an O3K defect.
- The O3K identity endpoint is loopback-bound (`O3K_LISTEN_ADDR`, for example
  `127.0.0.1:18080` for the libvirt profile). A bridge-networked container
  cannot reach it at any address, so the witness runs the container with host
  networking and reads the endpoint and region from `/etc/o3k/admin-openrc`
  instead of hardcoding them.

The login form is submitted with the values the rendered page actually
exposes: the `region` field value is an index into `AVAILABLE_REGIONS`, not a
region name, and `domain` is submitted only when the form renders it (it is
absent unless multi-domain support is enabled, in which case Horizon uses
`OPENSTACK_KEYSTONE_DEFAULT_DOMAIN`). The witness asserts the bounded
`o3k-demo-v1` journey only — HTTP readiness, login, project context, four
panels and visibility of the Core resources. It makes no blanket
Horizon/OpenStack parity claim, and the panels are informational while
resource visibility is required.
