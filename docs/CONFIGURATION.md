# O3K configuration

`o3kd` validates its complete configuration before opening a listening socket.
The default profile is local and safe: it listens on `127.0.0.1:8080`, uses
`./data`, JSON logs at the `info` level, and the stateful `fake` provider.

## Precedence

Values are merged in this order, from lowest to highest priority:

1. built-in defaults;
2. the optional TOML file selected by `--config` or `O3K_CONFIG`;
3. `O3K_*` environment variables;
4. command-line flags.

The `--config` flag takes precedence over `O3K_CONFIG` for selecting the file.
Unknown TOML keys and command-line options are rejected. Errors identify the
problem without printing secret values.

## Fields

| Setting | TOML key | Environment | CLI flag | Default |
| --- | --- | --- | --- | --- |
| Listen address | `listen_addr` | `O3K_LISTEN_ADDR` | `--listen-addr` | `127.0.0.1:8080` |
| Data directory | `data_dir` | `O3K_DATA_DIR` | `--data-dir` | `./data` |
| Log format | `log_format` | `O3K_LOG_FORMAT` | `--log-format` | `json` |
| Log filter | `log_filter` | `O3K_LOG_FILTER` | `--log-filter` | `info` |
| Provider | `provider` | `O3K_PROVIDER` | `--provider` | `fake` |
| CellHV endpoint | `cellhv_endpoint` | `O3K_CELLHV_ENDPOINT` | `--cellhv-endpoint` | required for `cellhv` |
| CellHV expected version | `cellhv_expected_version` | `O3K_CELLHV_EXPECTED_VERSION` | `--cellhv-expected-version` | required for `cellhv` |
| CellHV CA certificate | `cellhv_ca_certificate` | `O3K_CELLHV_CA_CERTIFICATE` | `--cellhv-ca-certificate` | unset |
| CellHV client certificate | `cellhv_client_certificate` | `O3K_CELLHV_CLIENT_CERTIFICATE` | `--cellhv-client-certificate` | unset |
| CellHV client key | `cellhv_client_key` | `O3K_CELLHV_CLIENT_KEY` | `--cellhv-client-key` | unset |
| Bootstrap secret | `bootstrap_secret` | `O3K_BOOTSTRAP_SECRET` | `--bootstrap-secret` | unset |
| Bootstrap password | `bootstrap_password` | `O3K_BOOTSTRAP_PASSWORD` | `--bootstrap-password` | unset |
| Token signing key | `token_signing_key` | `O3K_TOKEN_SIGNING_KEY` | `--token-signing-key` | unset |
| Compute control address | `compute_control_addr` | `O3K_COMPUTE_CONTROL_ADDR` | `--compute-control-addr` | `127.0.0.1:50051` |
| Compute server certificate | `compute_server_certificate` | `O3K_COMPUTE_SERVER_CERTIFICATE` | `--compute-server-certificate` | unset |
| Compute server private key | `compute_server_private_key` | `O3K_COMPUTE_SERVER_PRIVATE_KEY` | `--compute-server-private-key` | unset |
| Compute client CA | `compute_client_ca` | `O3K_COMPUTE_CLIENT_CA` | `--compute-client-ca` | unset |
| Authorized compute agents | `compute_authorized_agents` | `O3K_COMPUTE_AUTHORIZED_AGENTS` | `--compute-authorized-agents` | unset |

The host-local `o3k-compute` agent accepts `O3K_COMPUTE_MAX_DISK_GB` as an
explicit, operator-declared Placement disk-capacity bound. Its default is
`0`, which intentionally keeps the agent unschedulable until the operator
provides a trusted value; disk format support is not capacity evidence.
The packaged libvirt profile installs with `O3K_COMPUTE_MAX_DISK_GB=30` (room for the
installer-created TestLab VM plus at least two user VMs)
(`packaging/install.sh`); tune it per host before scheduling larger flavors.

The packaged libvirt profile also configures libvirtd unix-socket
authorization for the o3k service account: `packaging/install.sh` installs a
policykit-1 rule (`/etc/polkit-1/rules.d/50-o3k-libvirt.rules`) granting only
user `o3k` the `org.libvirt.unix.manage` action. Debian 12's libvirtd
defaults to `auth_unix_rw = "polkit"`, where the session-less service account
cannot authenticate; the rule is inert on hosts with an active
`auth_unix_rw = "none"` (Ubuntu 24.04).

`log_format` accepts `json` or `pretty`; `provider` accepts `fake`, `cellhv`, or
`agent`. The `agent` provider requires complete compute TLS configuration and
an authorized-agent mapping. TLS can also be enabled independently while the
`fake` provider is selected, which is useful for protected protocol tests.
Although `libvirt` remains a reserved profile value for packaging and release
tracking, `o3kd` rejects it before startup. The `agent` provider is the only
supported path to the host-local `o3k-compute` libvirt adapter; the daemon must
never construct or open a local libvirt adapter. Protected real-host execution
and guest-level acceptance remain evidence-gated follow-ups.
The CellHV profile now connects to the configured versioned endpoint; HTTPS
endpoints additionally require the CA, client certificate, and client key.
The default address must remain loopback unless an operator explicitly changes
it. Secrets have redacted `Debug` and `Display` representations and must not be
included in logs, errors, or command output.

The Keystone bootstrap token route is enabled only when both
`bootstrap_password` and a random `token_signing_key` (at least 32 bytes) are
configured. Keep both values outside the TOML file when possible, for example
in a protected environment or secret manager.

## Password generation and Kolla-Ansible reuse

Use `scripts/generate-passwords.sh` to create the protected environment file
idempotently. It preserves existing O3K values, generates separate strong
values for the bootstrap password and token signing key, and writes atomically
with mode `0600`. If `O3K_BOOTSTRAP_PASSWORD` is absent, an existing Kolla-
Ansible `keystone_admin_password` is reused from `/etc/kolla/passwords.yml`;
the Kolla file itself is never modified. Override paths for a deployment with
`--output` and `--kolla-password-file` or the corresponding `O3K_*` variables.
The generator rejects symlinked paths and malformed existing signing keys and
never prints secret values.

The compute control plane is disabled when all compute TLS settings are unset.
When enabled, all three certificate paths and at least one authorized-agent
mapping are required. `compute_authorized_agents` is a comma-separated list of
`agent_id=sha256(certificate-DER)` entries; the certificate URI SAN must also
be `urn:o3k:compute:agent:<agent_id>`. Partial or unlisted compute TLS
configuration fails validation before any listener opens.

Example:

```toml
listen_addr = "127.0.0.1:8080"
data_dir = "/var/lib/o3k"
log_format = "json"
log_filter = "info,o3k=debug"
provider = "fake"
```

Readiness is distinct from liveness: `/healthz` reports that the process is
alive, while `/readyz` returns `503` until startup completes and `200` only
when the process can accept requests.
