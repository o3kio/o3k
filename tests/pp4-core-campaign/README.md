# PP.4 Core campaign

This directory is the current PP.4 Core campaign path. It consumes only the
public immutable O3K release selected by the campaign (`v0.4.0-rc.18` for the
current evidence) and has no Araf dependency. The historical Araf-era scripts
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
