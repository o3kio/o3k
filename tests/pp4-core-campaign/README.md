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
`docker.io/openstackhelm/horizon:2024.1-ubuntu_jammy-20250523` at digest
`sha256:53af8d4c6c6b4c9c339f535080e2b56c439f8b36c417a6eba8bbf16afeb04a2b`.
The image is unmodified: no fork, no source patch, no O3K-specific Horizon
code. Only ordinary configuration is supplied — endpoint, region, session and
`STATIC_ROOT` settings, an Apache/mod_wsgi vhost, and the container runtime
invocation.

Three properties of that pinned image are harness assumptions, not O3K
contracts, and each one has already hidden a defect behind a misclassified
failure:

- It is **not** a Kolla image. There is no `kolla_start` entrypoint and no
  `/var/lib/kolla/config_files` tree; `CMD` is `/bin/bash`. The container must
  be given the Apache command explicitly, and Horizon settings must be
  mounted at `openstack_dashboard/local/local_settings.py` inside the image's
  own virtualenv, which is the module `openstack_dashboard.settings` imports.
- Horizon's default `STATIC_ROOT` resolves inside the read-only virtualenv, so
  django-compressor raises `PermissionError` while rendering the login page.
  The witness disables compression and points `STATIC_ROOT` at a writable
  directory.
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
