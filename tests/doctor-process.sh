#!/usr/bin/env bash
# doctor-process.sh — process-level test for the real `o3k` binary (issue #617).
#
# Deterministic, rootless, and offline: everything the binary could inspect is
# a private mktemp sandbox (config dir, data dir with a real WAL-mode SQLite
# fixture, prefix with ownership/release fixtures, loopback http shims for
# /healthz, /readyz, and POST /v3/auth/tokens, plus PATH shims for
# systemctl/virsh/ip/df/ps). No root is required by any check, so nothing is
# guarded behind EUID; the script SKIPs with an explicit message when a
# prerequisite is missing (mirroring tests/installer-negative.sh).
#
# Scope note (issue #617 plan, docs/plan/o3k-doctor.md): the doctor CLI reads
# /etc/o3k and /usr/local by default but honors the sandbox overrides
# O3K_DOCTOR_CONFIG_DIR / O3K_DOCTOR_DATA_DIR / O3K_DOCTOR_PREFIX (probed via
# `strings` on the built binary so this test never drifts from what actually
# shipped). With the overrides present, the sandbox below drives real
# negative classifications through the real binary; until then the negative
# matrix stays covered by the crate's own unit tests in bins/o3k.
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/o3k-doctor-process.XXXXXX")"
OUT_DIR="$WORK_DIR/outputs"
mkdir -p "$OUT_DIR"
SERVER_PIDS=()
PASS=0
FAIL=0
SKIP=0

cleanup() {
  local pid
  for pid in "${SERVER_PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  rm -rf -- "$WORK_DIR"
}
trap cleanup EXIT

record_pass() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
record_fail() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
record_skip() { SKIP=$((SKIP + 1)); printf 'skip %s\n' "$1"; }

for tool in python3 sha256sum mktemp grep; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    record_skip "doctor-process tests need $tool"
    printf 'doctor process tests: %d passed, %d failed, %d skipped\n' "$PASS" "$FAIL" "$SKIP"
    exit 0
  fi
done

free_port() {
  python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

# ------------------------------------------------------------- fixtures -----

# Fake sandbox laid out like a real installation, under WORK_DIR only.
SANDBOX_CONFIG="$WORK_DIR/etc-o3k"
SANDBOX_DATA="$WORK_DIR/data"
SANDBOX_PREFIX="$WORK_DIR/prefix"
SANDBOX_SHIM_BIN="$WORK_DIR/shim-bin"
mkdir -p "$SANDBOX_CONFIG" "$SANDBOX_DATA/compute/network" \
  "$SANDBOX_PREFIX/bin" "$SANDBOX_PREFIX/share/o3k" "$SANDBOX_SHIM_BIN"

CONTROL_PORT="$(free_port)"
COMPUTE_PORT="$(free_port)"
SENTINEL='SENTINEL_PW_7x9z'

# Config dir: env files and client credentials with sentinel secrets that must
# never appear in any output.
cat >"$SANDBOX_CONFIG/o3kd.env" <<EOF
O3K_LISTEN_ADDR=127.0.0.1:$CONTROL_PORT
O3K_BOOTSTRAP_PASSWORD=$SENTINEL
O3K_TOKEN_SIGNING_KEY=$SENTINEL
O3K_DATA_DIR=$SANDBOX_DATA
O3K_PROVIDER=agent
EOF
cat >"$SANDBOX_CONFIG/o3k-compute.env" <<EOF
O3K_COMPUTE_HEALTH_ADDR=127.0.0.1:$COMPUTE_PORT
O3K_COMPUTE_DATA_DIR=$SANDBOX_DATA/compute
O3K_COMPUTE_MAX_DISK_GB=10
EOF
cat >"$SANDBOX_CONFIG/admin-openrc" <<EOF
export OS_AUTH_URL=http://127.0.0.1:$CONTROL_PORT/v3
export OS_USERNAME=admin
export OS_PASSWORD=$SENTINEL
export OS_PROJECT_NAME=admin
export OS_USER_DOMAIN_NAME=Default
export OS_PROJECT_DOMAIN_NAME=Default
export OS_REGION_NAME=RegionOne
export OS_INTERFACE=public
export OS_IDENTITY_API_VERSION=3
EOF
cat >"$SANDBOX_CONFIG/clouds.yaml" <<EOF
clouds:
  o3k:
    auth:
      auth_url: http://127.0.0.1:$CONTROL_PORT/v3
      username: admin
      password: $SENTINEL
EOF
# A real installation keeps these 0600; the doctor's security check must
# observe the correct modes.
chmod 0600 "$SANDBOX_CONFIG/o3kd.env" "$SANDBOX_CONFIG/o3k-compute.env" \
  "$SANDBOX_CONFIG/admin-openrc" "$SANDBOX_CONFIG/clouds.yaml"

# Data dir: a real SQLite database in WAL mode with a couple of placement rows
# mirroring the o3k-store schema (crates/o3k-store/migrations/0017_placement.sql).
python3 - "$SANDBOX_DATA/o3k.sqlite" <<'PY'
import sqlite3
import sys

connection = sqlite3.connect(sys.argv[1])
connection.execute("PRAGMA journal_mode=WAL")
connection.executescript(
    """
    CREATE TABLE placement_providers (
        id TEXT PRIMARY KEY NOT NULL,
        node_id TEXT NOT NULL UNIQUE,
        state TEXT NOT NULL,
        generation INTEGER NOT NULL
    );
    CREATE TABLE placement_inventories (
        provider_id TEXT NOT NULL REFERENCES placement_providers(id) ON DELETE CASCADE,
        resource_class TEXT NOT NULL,
        total INTEGER NOT NULL,
        reserved INTEGER NOT NULL,
        allocation_ratio REAL NOT NULL,
        used INTEGER NOT NULL,
        PRIMARY KEY (provider_id, resource_class)
    );
    -- Minimal epoch-bearing tables mirroring 0004_observation_watermarks and
    -- 0006_agent_commands (only the columns the doctor queries).
    CREATE TABLE observation_watermarks (agent_epoch TEXT);
    CREATE TABLE agent_commands (agent_id TEXT, agent_epoch TEXT);
    -- Remaining tables the doctor queries read-only (empty fixtures):
    -- resources, network_ports, and the placement allocation tables.
    CREATE TABLE resources (
        id TEXT PRIMARY KEY NOT NULL,
        kind TEXT NOT NULL,
        desired_state TEXT NOT NULL,
        observed_state TEXT NOT NULL
    );
    CREATE TABLE network_ports (
        id TEXT PRIMARY KEY NOT NULL,
        binding_host TEXT,
        binding_state TEXT,
        status TEXT NOT NULL
    );
    CREATE TABLE placement_allocations (
        id TEXT PRIMARY KEY NOT NULL,
        provider_id TEXT NOT NULL,
        consumer_id TEXT NOT NULL
    );
    CREATE TABLE placement_allocation_resources (
        allocation_id TEXT NOT NULL,
        resource_class TEXT NOT NULL,
        amount INTEGER NOT NULL,
        PRIMARY KEY (allocation_id, resource_class)
    );
    """
)
connection.execute(
    "INSERT INTO placement_providers VALUES ('provider-1', 'node-1', 'active', 1)"
)
connection.execute(
    "INSERT INTO placement_inventories VALUES ('provider-1', 'VCPU', 8, 0, 1.0, 0)"
)
connection.execute(
    "INSERT INTO placement_inventories VALUES ('provider-1', 'MEMORY_MB', 16384, 0, 1.0, 0)"
)
connection.execute(
    "INSERT INTO placement_inventories VALUES ('provider-1', 'DISK_GB', 10, 0, 1.0, 0)"
)
# The persisted epoch must equal the compute shim's self-reported epoch below:
# the doctor's stale-epoch comparison passes only when both agree.
connection.execute(
    "INSERT INTO observation_watermarks (agent_epoch) VALUES ('epoch-sandbox')"
)
connection.commit()
connection.close()
PY
chmod 0600 "$SANDBOX_DATA/o3k.sqlite"

# A deliberately corrupt database fixture for the disposable negative drive:
# garbage bytes where o3k.sqlite belongs.
mkdir -p "$WORK_DIR/corrupt-data"
printf 'this is not a sqlite database\n' >"$WORK_DIR/corrupt-data/o3k.sqlite"
chmod 0600 "$WORK_DIR/corrupt-data/o3k.sqlite"
# Installation fixtures must already have their D8 lifetime lock. Doctor must
# never provision missing lock state just to run read-only diagnostics.
for data in "$SANDBOX_DATA" "$WORK_DIR/corrupt-data"; do
  chmod 0700 "$data"
  (umask 077; : >"$data/.o3k-store.lock")
done
mkdir -m 0700 "$WORK_DIR/no-lock-data"
# An empty prefix fixture: no ownership manifest, no release manifest.
mkdir -p "$WORK_DIR/empty-prefix"

# Network ownership fixture for the compute agent.
cat >"$SANDBOX_DATA/compute/network/ownership.json" <<'EOF'
{"bridge": {"name": "o3k-br0", "created_by_o3k": true}, "taps": {}}
EOF

# DHCP fixture: a pidfile pointing at a pid that cannot exist, plus its
# spawn-identity record — the doctor must classify this as a dead dnsmasq.
mkdir -p "$SANDBOX_DATA/compute/dhcp"
printf '999999\n' >"$SANDBOX_DATA/compute/dhcp/dnsmasq-00000000-0000-0000-0000-000000000000.pid"
printf '12345\n' >"$SANDBOX_DATA/compute/dhcp/dnsmasq-00000000-0000-0000-0000-000000000000.pid.owner"

# Prefix: fake .o3k-installed ownership manifest, release-manifest.json, and a
# SHA256SUMS whose o3kd hash is deliberately WRONG while the o3k and
# o3k-compute hashes are CORRECT (computed from the dummy binaries below) —
# the release check must distinguish them without ever printing the sentinel.
printf 'dummy o3kd binary\n' >"$SANDBOX_PREFIX/bin/o3kd"
printf 'dummy o3k binary\n' >"$SANDBOX_PREFIX/bin/o3k"
printf 'dummy o3k-compute binary\n' >"$SANDBOX_PREFIX/bin/o3k-compute"
cat >"$SANDBOX_PREFIX/share/o3k/.o3k-installed" <<EOF
o3k-installed-v1 prefix=$SANDBOX_PREFIX
bin/o3kd
bin/o3k
bin/o3k-compute
share/o3k/release-manifest.json
share/o3k/SHA256SUMS
EOF
printf '{"version":"0.3.0-alpha.1","profile":"libvirt"}\n' \
  >"$SANDBOX_PREFIX/share/o3k/release-manifest.json"
O3K_SHA256="$(sha256sum "$SANDBOX_PREFIX/bin/o3k" | awk '{print $1}')"
O3K_COMPUTE_SHA256="$(sha256sum "$SANDBOX_PREFIX/bin/o3k-compute" | awk '{print $1}')"
printf '%064d  %s\n' 0 "$SANDBOX_PREFIX/bin/o3kd" >"$SANDBOX_PREFIX/share/o3k/SHA256SUMS"
printf '%s  %s\n' "$O3K_SHA256" "$SANDBOX_PREFIX/bin/o3k" >>"$SANDBOX_PREFIX/share/o3k/SHA256SUMS"
printf '%s  %s\n' "$O3K_COMPUTE_SHA256" "$SANDBOX_PREFIX/bin/o3k-compute" >>"$SANDBOX_PREFIX/share/o3k/SHA256SUMS"

# PATH shims: read-only command fakes with the responses the doctor's checks
# need. Only consulted when the binary is driven against the sandbox; they
# never touch the host.
cat >"$SANDBOX_SHIM_BIN/systemctl" <<'EOF'
#!/usr/bin/env bash
# TEST FIXTURE — reports o3kd.service active and o3k-compute.service inactive.
case "$*" in
  *is-active*o3kd.service*) printf 'active\n'; exit 0 ;;
  *is-active*o3k-compute.service*) exit 3 ;;
esac
exit 0
EOF
cat >"$SANDBOX_SHIM_BIN/virsh" <<'EOF'
#!/usr/bin/env bash
# TEST FIXTURE — libvirt is unreachable for every caller (uri failure mode).
printf 'error: failed to connect to the hypervisor\n' >&2
exit 1
EOF
cat >"$SANDBOX_SHIM_BIN/ip" <<'EOF'
#!/usr/bin/env bash
# TEST FIXTURE — a stable minimal link listing with an orphan O3K TAP that
# has no ownership record (stale-TAP negative).
printf '1: lo: <LOOPBACK,UP,LOWER_UP>\n'
printf '2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP>\n'
printf '3: o3ktap-99999999: <BROADCAST,MULTICAST,UP,LOWER_UP>\n'
exit 0
EOF
cat >"$SANDBOX_SHIM_BIN/df" <<'EOF'
#!/usr/bin/env bash
# TEST FIXTURE — a stable minimal filesystem listing.
printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\n'
printf '/dev/root 1000000 100000 900000 11%% /\n'
exit 0
EOF
cat >"$SANDBOX_SHIM_BIN/ps" <<'EOF'
#!/usr/bin/env bash
# TEST FIXTURE — forwards to the real ps (/proc reads stay real).
exec /bin/ps "$@"
EOF
chmod 0755 "$SANDBOX_SHIM_BIN/systemctl" "$SANDBOX_SHIM_BIN/virsh" \
  "$SANDBOX_SHIM_BIN/ip" "$SANDBOX_SHIM_BIN/df" "$SANDBOX_SHIM_BIN/ps"

# Loopback shims: control plane (/healthz, /readyz, POST /v3/auth/tokens) and
# compute agent (/healthz, /readyz with the additive issue-#617 identity body).
python3 - "$CONTROL_PORT" <<'PY' &
import http.server
import sys

PORT = int(sys.argv[1])


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            body = b'{"status":"ok"}\n'
            self.send_response(200)
        elif self.path == "/readyz":
            body = b'{"status":"ready"}\n'
            self.send_response(200)
        else:
            body = b'{"error":{"message":"not found"}}\n'
            self.send_response(404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path == "/v3/auth/tokens":
            body = b'{"token":{"expires_at":"2099-01-01T00:00:00Z"}}\n'
            self.send_response(201)
            self.send_header("X-Subject-Token", "sandbox-token")
        else:
            body = b'{"error":{"message":"not found"}}\n'
            self.send_response(404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


http.server.HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
PY
SERVER_PIDS+=($!)

python3 - "$COMPUTE_PORT" <<'PY' &
import http.server
import sys

PORT = int(sys.argv[1])
READY = (
    b'{"status":"ready","agent_id":"compute-agent",'
    b'"agent_epoch":"epoch-sandbox","software_version":"0.3.0-alpha.1",'
    b'"capabilities":{"max_vcpus":8,"max_memory_mib":16384,"max_disk_gb":10}}\n'
)


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            body = b'{"status":"alive"}\n'
            self.send_response(200)
        elif self.path == "/readyz":
            body = READY
            self.send_response(200)
        else:
            body = b'{"error":{"message":"not found"}}\n'
            self.send_response(404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


http.server.HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
PY
SERVER_PIDS+=($!)

# -------------------------------------------------------------- assertions ---

# The fixture shims must actually answer on the loopback before any check
# could rely on them (python socket probe, no external network). Bounded
# retry: the servers need a moment to bind.
shims_ready=0
for _attempt in $(seq 1 100); do
  if python3 - "$CONTROL_PORT" "$COMPUTE_PORT" 2>/dev/null <<'PY'
import http.client
import sys

for port in (int(sys.argv[1]), int(sys.argv[2])):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    connection.request("GET", "/healthz")
    response = connection.getresponse()
    response.read()
    if response.status != 200:
        raise SystemExit(1)
PY
  then
    shims_ready=1
    break
  fi
  sleep 0.1
done
if [[ "$shims_ready" -eq 1 ]]; then
  record_pass "sandbox health shims answer GET /healthz on the loopback"
else
  record_fail "sandbox health shims did not answer GET /healthz"
fi

CARGO="${CARGO:-cargo}"
BIN="$ROOT_DIR/target/debug/o3k"
HAVE_CLI=0
if ! command -v "$CARGO" >/dev/null 2>&1; then
  record_skip "o3k build requires cargo (set CARGO=/path/to/cargo); skipping all binary assertions"
else
  if "$CARGO" build --manifest-path "$ROOT_DIR/Cargo.toml" -p o3k >"$OUT_DIR/cargo-build.log" 2>&1; then
    record_pass "cargo build -p o3k succeeded"
  else
    record_fail "cargo build -p o3k failed (see $OUT_DIR/cargo-build.log)"
  fi
  if [[ -x "$BIN" ]]; then
    # Capability probe: --version is the stable smoke test for the real CLI.
    if "$BIN" --version >"$OUT_DIR/version.out" 2>"$OUT_DIR/version.err"; then
      if grep -Eq '[0-9]+\.[0-9]+' "$OUT_DIR/version.out"; then
        record_pass "o3k --version exits 0 and prints a version"
      else
        record_fail "o3k --version printed no version string"
      fi
      HAVE_CLI=1
    else
      record_skip "o3k --version is not implemented yet (bins/o3k crate in progress); skipping CLI behavior assertions"
    fi
  else
    record_skip "o3k binary missing after build ($BIN); skipping CLI behavior assertions"
  fi
fi

if [[ "$HAVE_CLI" -eq 1 ]]; then
  # No-args invocation is a usage error: exit 2 with a non-empty stderr.
  set +e
  "$BIN" >"$OUT_DIR/noargs.out" 2>"$OUT_DIR/noargs.err"
  noargs_status=$?
  set -e
  if [[ "$noargs_status" -eq 2 && -s "$OUT_DIR/noargs.err" ]]; then
    record_pass "o3k without arguments exits 2 with a usage message"
  elif [[ "$noargs_status" -eq 0 ]]; then
    record_fail "o3k without arguments exited 0 (expected usage exit 2)"
  else
    record_fail "o3k without arguments exited unexpectedly (status $noargs_status; see $OUT_DIR/noargs.err)"
  fi

  # `o3k doctor --json` must emit the machine-readable output contract
  # (contracts/o3k-doctor-output.schema.json) even in a minimal environment:
  # a clean env (no O3K_* variables) and no guaranteed /etc/o3k. The exit code
  # reflects the diagnosed health (0 healthy / 1 warning-or-unhealthy), so
  # only the JSON shape is asserted.
  set +e
  env -i PATH="/usr/bin:/bin" HOME="${HOME:-/tmp}" "$BIN" doctor --json \
    >"$OUT_DIR/doctor.json" 2>"$OUT_DIR/doctor.err"
  doctor_status=$?
  set -e
  if python3 - "$OUT_DIR/doctor.json" <<'PY'
import json
import sys

document = json.load(open(sys.argv[1], encoding="utf-8"))
for key in ("version", "overall_status", "timestamp", "checks"):
    assert key in document, f"missing required key: {key}"
assert document["overall_status"] in ("healthy", "warning", "unhealthy")
assert isinstance(document["checks"], list)
assert isinstance(document["version"], str) and document["version"]
assert isinstance(document["timestamp"], str) and document["timestamp"]
PY
  then
    record_pass "o3k doctor --json emits the schema-required keys in a minimal environment"
  else
    record_fail "o3k doctor --json did not emit the required JSON contract (exit $doctor_status; see $OUT_DIR/doctor.json, $OUT_DIR/doctor.err)"
  fi
else
  record_skip "o3k doctor --json contract (CLI not implemented yet)"
fi

# Sandbox-driven classification: active only once the CLI carries the
# O3K_DOCTOR_* sandbox override env vars (probed in the built binary, not the
# sources, so this test never drifts from what actually shipped). The
# negative-matrix classifications below stay covered by the crate's unit
# tests when the overrides are absent.
if [[ -x "$BIN" ]] && command -v strings >/dev/null 2>&1 \
  && grep -q 'O3K_DOCTOR_' < <(strings "$BIN"); then
  run_sandbox() { # name data-dir prefix out-json
    local name="$1" data="$2" prefix="$3" out="$4" status
    set +e
    O3K_DOCTOR_CONFIG_DIR="$SANDBOX_CONFIG" \
      O3K_DOCTOR_DATA_DIR="$data" \
      O3K_DOCTOR_PREFIX="$prefix" \
      O3K_INSTALL_PREFIX="$prefix" \
      PATH="$SANDBOX_SHIM_BIN:$PATH" \
      "$BIN" doctor --json >"$out" 2>"$OUT_DIR/$name.err"
    status=$?
    set -e
    printf '%d' "$status" >"$OUT_DIR/$name.exit"
  }

  # Primary sandbox run: every fixture above is wired so the classifications
  # are deterministic — healthy control plane, identity, database and epoch,
  # and the targeted negatives (stopped compute unit, exhausted disk,
  # libvirt-unreachable domain listing, missing owned bridge, stale TAP,
  # dead dnsmasq, missing TLS identity, modified o3kd binary, no bootstrap
  # test-vm).
  run_sandbox sandbox "$SANDBOX_DATA" "$SANDBOX_PREFIX" "$OUT_DIR/doctor-sandbox.json"
  if python3 - "$OUT_DIR/doctor-sandbox.json" "$OUT_DIR/sandbox.exit" "$EUID" <<'PY'
import json
import sys

document = json.load(open(sys.argv[1], encoding="utf-8"))
assert set(("version", "overall_status", "timestamp", "checks")) <= set(document)
expected = {
    "services.o3kd_unit": "PASS",
    "services.compute_unit": "FAIL",
    "control.healthz": "PASS",
    "control.readyz": "PASS",
    "host.disk_space": "FAIL",
    "identity.configured": "PASS",
    "identity.authenticated": "PASS",
    "compute.agent_registered": "PASS",
    "compute.agent_epoch": "PASS",
    "compute.agent_capabilities": "PASS",
    "compute.placement_consistent": "PASS",
    "database.integrity": "PASS",
    "libvirt.domains_consistent": "FAIL",
    "network.bridge_state": "FAIL",
    "network.tap_state": "WARN",
    "network.dhcp_state": "FAIL",
    "network.ownership_records": "PASS",
    "security.config_permissions": "FAIL",
    "security.tls_identity": "FAIL",
    "release.version": "PASS",
    "release.binary_hashes": "FAIL",
    "release.binary_set_consistent": "FAIL",
    "release.backup_available": "WARN",
    "release.upgrade_state": "PASS",
    "cloud.api_discovery": "WARN",
    "cloud.testvm_status": "NOT_APPLICABLE",
}
if sys.argv[3] != "0":
    # The sudo-based identity checks are only deterministic unprivileged:
    # root's sudo secure_path bypasses the PATH shims. CI runs unprivileged.
    expected["libvirt.compute_access"] = "NOT_APPLICABLE"
    expected["libvirt.control_isolation"] = "NOT_APPLICABLE"
by_id = {check["id"]: check["status"] for check in document["checks"]}
assert len(document["checks"]) == 36, "sandbox must reach the full diagnostics engine"
mismatches = [
    f"{check_id}: expected {status}, got {by_id.get(check_id)!r}"
    for check_id, status in expected.items()
    if by_id.get(check_id) != status
]
assert not mismatches, "classification mismatches: " + "; ".join(mismatches)
assert document["overall_status"] == "unhealthy", document["overall_status"]
assert open(sys.argv[2], encoding="utf-8").read().strip() == "1", "unhealthy run must exit 1"
PY
  then
    record_pass "sandbox run classifies the targeted checks correctly (exit 1)"
  else
    record_fail "sandbox run misclassified checks (see $OUT_DIR/doctor-sandbox.json, $OUT_DIR/doctor-sandbox.err)"
  fi

  # Disposable corrupt-database fixture: garbage bytes at the data dir must
  # classify as an unreadable database, never crash.
  run_sandbox corrupt-db "$WORK_DIR/corrupt-data" "$SANDBOX_PREFIX" "$OUT_DIR/doctor-corrupt.json"
  if python3 - "$OUT_DIR/doctor-corrupt.json" <<'PY'
import json
import sys

document = json.load(open(sys.argv[1], encoding="utf-8"))
assert len(document["checks"]) == 36, "corrupt database must be probed under the guard"
by_id = {check["id"]: check["status"] for check in document["checks"]}
assert by_id.get("database.accessible") == "FAIL", by_id
PY
  then
    record_pass "corrupt SQLite fixture classifies as database failure"
  else
    record_fail "corrupt SQLite fixture was not classified (see $OUT_DIR/doctor-corrupt.json, $OUT_DIR/doctor-corrupt.err)"
  fi

  # Disposable missing-installer-manifest fixture: an empty prefix has no
  # ownership manifest and no release manifest.
  run_sandbox empty-prefix "$SANDBOX_DATA" "$WORK_DIR/empty-prefix" "$OUT_DIR/doctor-empty.json"
  if python3 - "$OUT_DIR/doctor-empty.json" <<'PY'
import json
import sys

document = json.load(open(sys.argv[1], encoding="utf-8"))
by_id = {check["id"]: check["status"] for check in document["checks"]}
assert by_id.get("release.ownership_manifest") == "FAIL", by_id
assert by_id.get("release.version") == "FAIL", by_id
PY
  then
    record_pass "missing installer manifest fixture classifies release failures"
  else
    record_fail "missing installer manifest fixture was not classified (see $OUT_DIR/doctor-empty.json, $OUT_DIR/doctor-empty.err)"
  fi

  # No lock is an admission failure, distinct from a corrupt database. Keep
  # this assertion separate so quarantine cannot falsely pass the cases above.
  run_sandbox no-lock "$WORK_DIR/no-lock-data" "$SANDBOX_PREFIX" "$OUT_DIR/doctor-no-lock.json"
  if python3 - "$OUT_DIR/doctor-no-lock.json" "$OUT_DIR/no-lock.exit" "$WORK_DIR/no-lock-data" <<'PY'
import json
import pathlib
import sys

document = json.load(open(sys.argv[1], encoding="utf-8"))
assert document["overall_status"] == "unhealthy"
assert len(document["checks"]) == 1, "unguarded diagnostic probes ran"
check = document["checks"][0]
assert check["id"] == "database.accessible" and check["status"] == "FAIL"
assert check["summary"] == "canonical store access denied: store-access lock unavailable"
assert pathlib.Path(sys.argv[2]).read_text().strip() == "1"
assert not any(pathlib.Path(sys.argv[3]).iterdir()), "doctor provisioned missing state"
PY
  then
    record_pass "missing lock denies probes without provisioning state"
  else
    record_fail "missing lock did not fail closed without provisioning state"
  fi
else
  record_skip "sandbox-driven classification (no O3K_DOCTOR_* overrides in the binary; negative matrix covered by bins/o3k unit tests)"
fi

# Secret-safety: no output may ever carry the sentinel that lives in the
# sandbox configuration.
if grep -rq "$SENTINEL" "$OUT_DIR"; then
  record_fail "a sentinel secret leaked into captured output"
  grep -rn "$SENTINEL" "$OUT_DIR" >&2 || true
else
  record_pass "no sentinel secret appears in any captured output"
fi

printf 'doctor process tests: %d passed, %d failed, %d skipped\n' "$PASS" "$FAIL" "$SKIP"
[[ $FAIL -eq 0 ]]
