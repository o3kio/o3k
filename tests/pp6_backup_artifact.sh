#!/usr/bin/env bash
# PP.6 / #1084 authenticated backup artifact — Slice F real-process campaign.
#
# This campaign exercises the operator-usable artifact lifecycle on real
# processes only: a real `o3kd` performs the authenticated store-lock handoff,
# a real `o3k backup create` captures the SQLite snapshot and stages the
# encrypted artifact, the harness plays the offline custodian (Ed25519 key that
# the binary never reads), and the same command verifies the detached response
# and publishes. `o3k backup verify` is the in-tree exact-release verifier.
#
# Every matrix row records: exit code, journal phase, marker presence, lock
# owner, artifact publication, and verification result. `NOT-COVERED` rows are
# reported explicitly and never counted as PASS. Crash injection uses the
# feature-gated hooks (build with o3kd/backup-test-hooks,o3k/backup-test-hooks)
# and the two-way executor barrier; synchronization is barriers and bounded
# polls, never unbounded sleeps.
#
# Offline signing approach: the signing request carries the exact D1 signing
# input as base64url. The harness decodes it and signs with
# `openssl pkeyutl -sign -rawin -inkey` (OpenSSL >= 3 supports Ed25519 raw
# signing); python3 `cryptography` is an automatic fallback. The signing key
# and the X25519 recipient key are generated inside the temporary campaign
# directory (0600) and are never passed to the binary that creates/verifies the
# artifact.
#
# The script is re-runnable and exits 0 only when every executed check passed.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for tool in cargo python3 curl sha256sum openssl xxd stat find; do
    command -v "$tool" >/dev/null 2>&1 || { echo "FATAL: missing required tool: $tool" >&2; exit 2; }
done
HAVE_SQLITE3=0
command -v sqlite3 >/dev/null 2>&1 && HAVE_SQLITE3=1
HAVE_PY_CRYPTO=0
python3 -c 'import cryptography' >/dev/null 2>&1 && HAVE_PY_CRYPTO=1
if ! openssl pkeyutl -help 2>&1 | grep -q -- '-rawin'; then
    [[ "$HAVE_PY_CRYPTO" == "1" ]] || { echo "FATAL: no Ed25519 raw-signing implementation (openssl rawin or python cryptography)" >&2; exit 2; }
fi

echo "== build: o3kd + o3k with backup-test-hooks =="
cargo build -p o3kd -p o3k --features o3kd/backup-test-hooks,o3k/backup-test-hooks 2>&1 | tail -2

WORK="$(mktemp -d "${TMPDIR:-/tmp}/o3k-pp6-artifact.XXXXXX")"
chmod 0700 "$WORK"
INSTALL="$WORK/install"
mkdir -p "$INSTALL/bin"
cp "$ROOT_DIR/target/debug/o3kd" "$INSTALL/bin/o3kd"
cp "$ROOT_DIR/target/debug/o3k" "$INSTALL/bin/o3k"
chmod 0700 "$INSTALL" "$INSTALL/bin"
O3KD_BIN="$INSTALL/bin/o3kd"
O3K_BIN="$INSTALL/bin/o3k"
HARNESS_SHA256="$(sha256sum "$ROOT_DIR/tests/pp6_backup_artifact.sh" | cut -d' ' -f1)"
O3K_BIN_SHA256="$(sha256sum "$O3K_BIN" | cut -d' ' -f1)"
O3KD_BIN_SHA256="$(sha256sum "$O3KD_BIN" | cut -d' ' -f1)"

# ---------------------------------------------------------------------------
# Offline custody fixture (never read by the artifact command)
# ---------------------------------------------------------------------------
BACKUP_SIGNING_KEY="$WORK/backup-signing-key.pem"
BACKUP_FOREIGN_KEY="$WORK/backup-foreign-signing-key.pem"
BACKUP_RECIPIENT_KEY="$WORK/backup-recipient.key"
openssl genpkey -algorithm ED25519 -out "$BACKUP_SIGNING_KEY" 2>/dev/null
openssl genpkey -algorithm ED25519 -out "$BACKUP_FOREIGN_KEY" 2>/dev/null
chmod 0600 "$BACKUP_SIGNING_KEY" "$BACKUP_FOREIGN_KEY"
# 32 raw bytes: the trust loader derives the X25519 public key from this file.
openssl rand -out "$BACKUP_RECIPIENT_KEY" 32
chmod 0600 "$BACKUP_RECIPIENT_KEY"
BACKUP_SIGNING_PUBLIC_HEX="$(openssl pkey -in "$BACKUP_SIGNING_KEY" -pubout -outform DER 2>/dev/null | tail -c 32 | xxd -p -c 64)"
# PKCS#8 DER for Ed25519 is 302e...0420 || seed; the last 32 bytes are the seed.
BACKUP_SIGNING_SEED_HEX="$(openssl pkey -in "$BACKUP_SIGNING_KEY" -outform DER 2>/dev/null | tail -c 32 | xxd -p -c 64)"
BACKUP_RECIPIENT_KEY_HEX="$(xxd -p -c 64 "$BACKUP_RECIPIENT_KEY")"

BOOTSTRAP_PASSWORD="pp6-artifact-disposable-password"
TOKEN_SIGNING_KEY="pp6-artifact-token-signing-key-012345678901234567890123"
NATIVE_CURSOR_KEY="pp6-artifact-native-cursor-key-0123456789abcdef"

MATRIX_TSV="$WORK/matrix.tsv"
: >"$MATRIX_TSV"
RESULTS=()
DAEMON_PIDS=()
PASS_COUNT=0
FAIL_COUNT=0
NOT_COVERED_COUNT=0

log() { printf '%s\n' "$*"; }
record() { # record <PASS|FAIL|NOT-COVERED> <case> <exit> <journal> <marker> <lock> <published> <verify> <detail>
    local status="$1" case_id="$2"
    local exit_code="${3:--}" journal="${4:--}" marker="${5:--}" lock="${6:--}"
    local published="${7:--}" verify="${8:--}" detail="${9:-}"
    RESULTS+=("$status|$case_id|$exit_code|$journal|$marker|$lock|$published|$verify|$detail")
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$status" "$case_id" "$exit_code" "$journal" "$marker" "$lock" "$published" "$verify" "$detail" >>"$MATRIX_TSV"
    case "$status" in
        PASS) PASS_COUNT=$((PASS_COUNT + 1)); log "PASS  [$case_id] $detail" ;;
        FAIL) FAIL_COUNT=$((FAIL_COUNT + 1)); log "FAIL  [$case_id] $detail" ;;
        NOT-COVERED) NOT_COVERED_COUNT=$((NOT_COVERED_COUNT + 1)); log "N/A   [$case_id] $detail" ;;
    esac
}

# Per-case assertion helper: sets CHECK_OK=0 on mismatch instead of aborting.
CHECK_OK=1
check() { # check <actual> <expected> <label>
    if [[ "$1" != "$2" ]]; then
        CHECK_OK=0
        log "  check failed: $3 (got '$1', want '$2')"
    fi
}
check_nonempty() { # check_nonempty <value> <label>
    if [[ -z "$1" ]]; then CHECK_OK=0; log "  check failed: $2 is empty"; fi
}

cleanup() {
    set +e
    for pid in ${DAEMON_PIDS[@]+"${DAEMON_PIDS[@]}"}; do
        [[ -n "$pid" ]] || continue
        kill -0 "$pid" 2>/dev/null || continue
        kill "$pid" 2>/dev/null
        for _ in $(seq 1 40); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
        kill -9 "$pid" 2>/dev/null
        wait "$pid" 2>/dev/null
    done
    rm -rf -- "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

free_port() {
    python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
}

daemon_pid() { cat "$WORK/$1.pid"; }
daemon_port() { cat "$WORK/$1.port"; }
daemon_log() { cat "$WORK/$1.dlog"; }

declare -A EXIT_STATUS=()
reap_exit() { # reap_exit <pid> [timeout-seconds]; sets EXIT_STATUS[pid]
    local pid="$1" deadline=$((SECONDS + ${2:-30}))
    while (( SECONDS < deadline )); do
        if ! kill -0 "$pid" 2>/dev/null; then
            if wait "$pid"; then EXIT_STATUS[$pid]=0; else EXIT_STATUS[$pid]=$?; fi
            return 0
        fi
        sleep 0.1
    done
    return 1
}

start_daemon() { # start_daemon <name> <data-dir> [extra env KEY=VALUE ...]
    local name="$1" data_dir="$2"; shift 2
    local port dlog
    port="$(free_port)"
    dlog="$WORK/$name.o3kd.log"
    env \
        O3K_BOOTSTRAP_PASSWORD="$BOOTSTRAP_PASSWORD" \
        O3K_TOKEN_SIGNING_KEY="$TOKEN_SIGNING_KEY" \
        O3K_NATIVE_CURSOR_HMAC_KEY="$NATIVE_CURSOR_KEY" \
        "$@" \
        "$O3KD_BIN" --listen-addr "127.0.0.1:$port" --data-dir "$data_dir" \
        --log-filter info --log-format json >"$dlog" 2>&1 &
    echo $! >"$WORK/$name.pid"
    DAEMON_PIDS+=("$!")
    echo "$port" >"$WORK/$name.port"
    echo "$dlog" >"$WORK/$name.dlog"
}

wait_ready() { # wait_ready <name> [timeout-seconds]
    local name="$1" deadline=$((SECONDS + ${2:-30})) port
    port="$(daemon_port "$name")"
    while (( SECONDS < deadline )); do
        kill -0 "$(daemon_pid "$name")" 2>/dev/null || return 1
        curl -fsS "http://127.0.0.1:$port/readyz" >/dev/null 2>&1 && return 0
        sleep 0.1
    done
    return 1
}

wait_log() { # wait_log <name> <substring> [timeout-seconds]
    local name="$1" needle="$2" deadline=$((SECONDS + ${3:-20}))
    while (( SECONDS < deadline )); do
        grep -qF "$needle" "$(daemon_log "$name")" 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

sigterm_expect_zero() { # sigterm_expect_zero <name>
    local name="$1" pid
    pid="$(daemon_pid "$name")"
    kill -TERM "$pid" 2>/dev/null || return 1
    reap_exit "$pid" 30 || return 1
    [[ "${EXIT_STATUS[$pid]}" == "0" ]]
}

wait_for_file() { # wait_for_file <path> [timeout-seconds]
    local path="$1" deadline=$((SECONDS + ${2:-30}))
    while (( SECONDS < deadline )); do
        [[ -e "$path" ]] && return 0
        sleep 0.05
    done
    return 1
}

latest_schema_version() {
    ls "$ROOT_DIR/crates/o3k-store/migrations" \
        | sed -E 's/^0*([0-9]+)_.*/\1/' | sort -n | tail -1
}
SCHEMA_VERSION="$(latest_schema_version)"

identity_hex() { # identity_hex <domain> <data-dir>
    python3 - "$1" "$2" <<'PY'
import hashlib, os, sys
domain, data_dir = sys.argv[1].encode(), sys.argv[2]
canonical = os.fsencode(os.path.realpath(data_dir))
print(hashlib.sha256(domain + b"\x00" + canonical).digest()[:16].hex())
PY
}

json_get() { # json_get <file> <top-level-key>
    python3 - "$1" "$2" <<'PY'
import json, sys
try:
    value = json.load(open(sys.argv[1]))
except Exception:
    print("")
    raise SystemExit(0)
field = value.get(sys.argv[2], "") if isinstance(value, dict) else ""
print(field if isinstance(field, str) else json.dumps(field))
PY
}

journal_phase() { # journal_phase <data-dir> <operation-id>
    python3 - "$1" "$2" <<'PY'
import json, os, sys
path = os.path.join(sys.argv[1], "backup-operations", f"{sys.argv[2]}.json")
try:
    print(json.load(open(path))["phase"])
except Exception:
    print("-")
PY
}

journal_sha256() { # journal_sha256 <data-dir> <operation-id>
    local path="$1/backup-operations/$2.json"
    [[ -f "$path" ]] && sha256sum "$path" | cut -d' ' -f1 || echo "-"
}

marker_count() { find "$1" -maxdepth 1 -name '.o3k-backup-in-progress-*' | wc -l; }

lock_owner() { # lock_owner <data-dir> -> held|free|absent
    python3 - "$1" <<'PY'
import fcntl, os, sys
path = os.path.join(sys.argv[1], ".o3k-store.lock")
try:
    fd = os.open(path, os.O_RDWR)
except FileNotFoundError:
    print("absent"); raise SystemExit(0)
try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
except OSError:
    print("held")
else:
    print("free")
finally:
    os.close(fd)
PY
}

published_path() { echo "$1/backup-$2.o3k"; }
is_published() { [[ -f "$(published_path "$1" "$2")" ]] && echo yes || echo no; }

artifact_sha() { sha256sum "$(published_path "$1" "$2")" | cut -d' ' -f1; }

new_op_id() { python3 -c 'import uuid; print(uuid.uuid4())'; }

# ---------------------------------------------------------------------------
# Trust document / installed release manifest fixtures
# ---------------------------------------------------------------------------
write_config() { # write_config <key> <data-dir> [normal|revoked|foreign-identity|alt-release]
    local key="$1" data_dir="$2" mode="${3:-normal}"
    local dir="$WORK/cfg-$key-$mode" site installation
    mkdir -p "$dir/install/share/o3k"
    chmod 0700 "$dir" "$dir/install" "$dir/install/share" "$dir/install/share/o3k"
    if [[ "$mode" == "foreign-identity" ]]; then
        site="$(identity_hex o3k-backup-site-identity-v1 "$WORK/foreign-$key")"
        installation="$(identity_hex o3k-backup-installation-identity-v1 "$WORK/foreign-$key")"
    else
        site="$(identity_hex o3k-backup-site-identity-v1 "$data_dir")"
        installation="$(identity_hex o3k-backup-installation-identity-v1 "$data_dir")"
    fi
    local revoked=false
    [[ "$mode" == "revoked" ]] && revoked=true
    local source_commit="0123456789abcdef0123456789abcdef01234567"
    [[ "$mode" == "alt-release" ]] && source_commit="fedcba9876543210fedcba9876543210fedcba98"
    python3 - "$dir/backup-trust.json" "$dir/install/share/o3k/release-manifest.json" \
        "$site" "$installation" "$BACKUP_SIGNING_PUBLIC_HEX" "$BACKUP_RECIPIENT_KEY" \
        "$revoked" "$source_commit" "$SCHEMA_VERSION" <<'PY'
import hashlib, json, sys
(trust_path, manifest_path, site, installation, public, recipient,
 revoked, source_commit, schema) = sys.argv[1:10]
public_bytes = bytes.fromhex(public)
trust = {
    "format": "o3k-backup-trust-v1",
    "site_id": site,
    "installation_id": installation,
    "profile_id": "o3k-demo-v1",
    "artifact_signing": {"key_id": "signing-1", "ed25519_public_key": public},
    "recipient": {"key_id": "recovery-1", "x25519_private_key_file": recipient},
    "revoked_key_ids": ["signing-1"] if revoked == "true" else [],
    "custody": {
        "record_id": "custody-1",
        "purpose": "artifact-signing",
        "key_fingerprint": hashlib.sha256(public_bytes).hexdigest(),
        "threshold": "2-of-3",
        "custodians": ["principal-a", "principal-b", "principal-c"],
        "storage_class": "offline-safe",
        "expires_at": "2035-01-01T00:00:00Z",
    },
}
with open(trust_path, "w") as handle:
    json.dump(trust, handle, indent=2)
manifest = {
    "version": "0.4.0",
    "profile": "demo",
    "profile_id": "o3k-demo-v1",
    "source_commit": source_commit,
    "release_artifact_sha256": "a" * 64,
    "schema_version": schema,
}
with open(manifest_path, "w") as handle:
    json.dump(manifest, handle)
PY
    chmod 0600 "$dir/backup-trust.json" "$dir/install/share/o3k/release-manifest.json"
    echo "$dir/backup-trust.json"
}

fresh_case_dirs() { # fresh_case_dirs <key> [mode] -> CASE_DATA CASE_DEST CASE_TRUST CASE_PREFIX
    local key="$1" mode="${2:-normal}"
    CASE_DATA="$WORK/$key-data"
    CASE_DEST="$WORK/$key-dest"
    mkdir -p "$CASE_DATA" "$CASE_DEST"
    chmod 0700 "$CASE_DATA" "$CASE_DEST"
    local trust
    trust="$(write_config "$key" "$CASE_DATA" "$mode")"
    CASE_TRUST="$trust"
    CASE_PREFIX="$WORK/cfg-$key-$mode/install"
}

# ---------------------------------------------------------------------------
# Command invocation
# ---------------------------------------------------------------------------
run_backup() { # run_backup <case-id> <data-dir> <dest-dir> <operation-id> [env KEY=VALUE ...]
    local case_id="$1" data_dir="$2" dest_dir="$3" op="$4"; shift 4
    set +e
    env O3K_DATA_DIR="$data_dir" \
        O3K_BACKUP_TRUST_CONFIG="$CASE_TRUST" \
        O3K_INSTALL_PREFIX="$CASE_PREFIX" \
        "$@" \
        "$O3K_BIN" backup create --destination "$dest_dir" --operation-id "$op" \
        >"$WORK/$case_id.backup.json" 2>"$WORK/$case_id.backup.stderr"
    echo $? >"$WORK/$case_id.backup.exit"
    set -e
}
backup_exit() { cat "$WORK/$1.backup.exit"; }
backup_status() { json_get "$WORK/$1.backup.json" status; }
backup_reason() { json_get "$WORK/$1.backup.json" reason; }
backup_stderr() { cat "$WORK/$1.backup.stderr"; }

run_verify() { # run_verify <case-id> <data-dir> <trust-config> <install-prefix> <artifact>
    local case_id="$1" data_dir="$2" trust="$3" prefix="$4" artifact="$5"
    set +e
    env O3K_DATA_DIR="$data_dir" \
        O3K_BACKUP_TRUST_CONFIG="$trust" \
        O3K_INSTALL_PREFIX="$prefix" \
        "$O3K_BIN" backup verify --artifact "$artifact" \
        >"$WORK/$case_id.verify.json" 2>"$WORK/$case_id.verify.stderr"
    echo $? >"$WORK/$case_id.verify.exit"
    set -e
}
verify_exit() { cat "$WORK/$1.verify.exit"; }
verify_status() { json_get "$WORK/$1.verify.json" status; }
verify_reason() { json_get "$WORK/$1.verify.json" reason; }

# ---------------------------------------------------------------------------
# Offline signing (the harness is the custodian)
# ---------------------------------------------------------------------------
decode_signing_input() { # decode_signing_input <staging-dir> -> $WORK/sign-input.bin $WORK/sign-meta.json
    local staging="$1"
    python3 - "$staging/signing-request.json" "$WORK/sign-input.bin" "$WORK/sign-meta.json" <<'PY'
import base64, hashlib, json, sys
request_path, input_path, meta_path = sys.argv[1:4]
raw = open(request_path, "rb").read()
request = json.loads(raw)
encoded = request["signing_input_base64url"]
data = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
assert hashlib.sha256(data).hexdigest() == request["signing_input_sha256"], "signing input digest mismatch"
open(input_path, "wb").write(data)
with open(meta_path, "w") as handle:
    json.dump({
        "request_sha256": hashlib.sha256(raw).hexdigest(),
        "key_id": request["key_id"],
        "expires_at": request["expires_at"],
    }, handle)
PY
}

sign_bytes() { # sign_bytes <key> <input> <signature-out>
    local key="$1" input="$2" out="$3"
    if openssl pkeyutl -sign -rawin -inkey "$key" -in "$input" -out "$out" 2>/dev/null \
        && [[ "$(stat -c %s "$out")" == "64" ]]; then
        return 0
    fi
    [[ "$HAVE_PY_CRYPTO" == "1" ]] || return 1
    python3 - "$key" "$input" "$out" <<'PY'
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
key = serialization.load_pem_private_key(open(sys.argv[1], "rb").read(), password=None)
assert isinstance(key, Ed25519PrivateKey)
open(sys.argv[3], "wb").write(key.sign(open(sys.argv[2], "rb").read()))
PY
}

write_response_file() { # write_response_file <staging> <signature> <meta> [key_id] [request_sha]
    local staging="$1" signature="$2" meta="$3" key_id="${4:-}" request_sha="${5:-}"
    python3 - "$signature" "$meta" "$staging/signing-response.json" "$key_id" "$request_sha" <<'PY'
import json, os, sys
signature_path, meta_path, response_path, key_id, request_sha = sys.argv[1:6]
meta = json.load(open(meta_path))
signature = open(signature_path, "rb").read()
if not key_id:
    key_id = meta["key_id"]
if not request_sha:
    request_sha = meta["request_sha256"]
response = {
    "format": "o3k-backup-signing-response-v1",
    "request_sha256": request_sha,
    "key_id": key_id,
    "signature": signature.hex(),
    "signed_at": "2026-10-24T12:30:00Z",
}
with open(response_path, "w") as handle:
    json.dump(response, handle)
os.chmod(response_path, 0o600)
PY
}

sign_request() { # sign_request <staging> [signing-key]
    local staging="$1" key="${2:-$BACKUP_SIGNING_KEY}"
    [[ -f "$staging/signing-request.json" ]] || { log "  missing signing request in $staging"; return 1; }
    decode_signing_input "$staging"
    sign_bytes "$key" "$WORK/sign-input.bin" "$WORK/sign-input.sig" || { log "  offline signing failed"; return 1; }
    write_response_file "$staging" "$WORK/sign-input.sig" "$WORK/sign-meta.json"
}

expire_signing_request() { # expire_signing_request <staging> <data-dir> <op>
    python3 - "$1/signing-request.json" "$2/backup-operations/$3.json" <<'PY'
import hashlib, json, sys
request_path, journal_path = sys.argv[1:3]
request = json.load(open(request_path))
request["expires_at"] = "2020-01-01T00:00:00Z"
raw = json.dumps(request, indent=2).encode()
open(request_path, "wb").write(raw)
journal = json.load(open(journal_path))
journal["request_sha256"] = hashlib.sha256(raw).hexdigest()
json.dump(journal, open(journal_path, "w"))
PY
}

mutate_response() { # mutate_response <staging> <python-expression using response dict>
    local staging="$1" expression="$2"
    python3 - "$staging/signing-response.json" "$expression" <<'PY'
import json, sys
path, expression = sys.argv[1:3]
response = json.load(open(path))
exec(expression)
json.dump(response, open(path, "w"))
PY
}

# ---------------------------------------------------------------------------
# Assertions on the produced artifact bytes (independent of the binary parser)
# ---------------------------------------------------------------------------
read_manifest_facts() { # read_manifest_facts <artifact> -> sqlite_version schema_version
    python3 - "$1" <<'PY'
import json, struct, sys
raw = open(sys.argv[1], "rb").read()
assert raw[:12] == b"O3KPP6BK\x00\x00\x00\x01", "artifact magic"
length = struct.unpack(">Q", raw[12:20])[0]
manifest = json.loads(raw[20:20 + length])
size = 20 + length + sum(8 + member["size_bytes"] for member in manifest["members"])
assert size == len(raw), f"artifact layout {size} != {len(raw)}"
print(manifest["store"]["server_version"])
print(manifest["store"]["schema_version"])
PY
}

assert_phase_one_contract() { # assert_phase_one_contract <case> <dest> <op> <data>
    local case_id="$1" dest="$2" op="$3" data_dir="$4"
    python3 - "$WORK/$case_id.backup.json" "$op" "$dest" "$data_dir" <<'PY'
import json, os, sys
payload = json.load(open(sys.argv[1]))
operation_id, dest, data_dir = sys.argv[2:5]
assert payload["status"] == "signing-required", payload
assert payload["operation_id"] == operation_id, payload
assert payload["expires_at"], payload
assert int(payload["artifact_size_bytes"]) > 0, payload
assert int(payload["source_bytes"]) > 0, payload
request = os.path.join(dest, f".o3k-backup-artifact-{operation_id}", "signing-request.json")
assert os.path.isfile(request), request
assert not os.path.exists(os.path.join(dest, f"backup-{operation_id}.o3k")), "phase 1 must not publish"
assert not os.path.exists(os.path.join(data_dir, f".o3k-backup-in-progress-{operation_id}")), "marker must be removed"
journal = json.load(open(os.path.join(data_dir, "backup-operations", f"{operation_id}.json")))
assert journal["phase"] == "staged", journal
assert journal["request_sha256"], journal
PY
}

settle_checkpoint() { # settle_checkpoint <data-dir>
    # The executor holds the exclusive store lock at the barrier; no process is
    # writing. Applying the remaining WAL frames here makes the measured main
    # database the exact bytes the executor will snapshot.
    if (( HAVE_SQLITE3 )); then
        sqlite3 "$1/o3k.sqlite" 'PRAGMA wal_checkpoint(TRUNCATE);' >/dev/null 2>&1 || true
    fi
}

sha256_file_or_missing() { [[ -f "$1" ]] && sha256sum "$1" | cut -d' ' -f1 || echo "-"; }

snapshot_tree() { # snapshot_tree <data-dir> <out>
    ( cd "$1" && find . -mindepth 1 -not -type d -printf '%y %P\n' | sort ) >"$2"
}

echo
echo "== Case 1: happy path (capture -> offline sign -> publish -> verify -> tamper) =="
fresh_case_dirs happy
HAPPY_DATA="$CASE_DATA"; HAPPY_DEST="$CASE_DEST"
HAPPY_TRUST="$CASE_TRUST"; HAPPY_PREFIX="$CASE_PREFIX"
HAPPY_OP="$(new_op_id)"
HAPPY_READY="$WORK/happy.ready"; HAPPY_GO="$WORK/happy.go"
rm -f "$HAPPY_READY" "$HAPPY_GO"
start_daemon happy "$CASE_DATA"
if ! wait_ready happy 30; then
    record FAIL case-1 "daemon not ready"
    exit 1
fi

# Barrier: the executor holds the store lock but has not opened the store yet.
run_backup happy "$CASE_DATA" "$CASE_DEST" "$HAPPY_OP" \
    O3K_BACKUP_TEST_BARRIER_READY_FILE="$HAPPY_READY" \
    O3K_BACKUP_TEST_BARRIER_WAIT_FILE="$HAPPY_GO" &
HAPPY_BPID=$!
if ! wait_for_file "$HAPPY_READY" 30; then
    record FAIL case-1 "executor barrier did not become ready"
    exit 1
fi
settle_checkpoint "$CASE_DATA"
HAPPY_BEFORE_DB_SHA="$(sha256_file_or_missing "$CASE_DATA/o3k.sqlite")"
HAPPY_TRUST_BYTES="$(stat -c %s "$CASE_TRUST")"
HAPPY_MANIFEST_BYTES="$(stat -c %s "$CASE_PREFIX/share/o3k/release-manifest.json")"
HAPPY_DB_BYTES="$(stat -c %s "$CASE_DATA/o3k.sqlite")"
HAPPY_EXPECTED_SOURCE=$((HAPPY_DB_BYTES + HAPPY_TRUST_BYTES + HAPPY_MANIFEST_BYTES))
snapshot_tree "$CASE_DATA" "$WORK/happy-before-tree.txt"
touch "$HAPPY_GO"
set +e
wait "$HAPPY_BPID"
set -e
HAPPY_DAEMON_PID="$(daemon_pid happy)"
reap_exit "$HAPPY_DAEMON_PID" 30 || true

C1_OK=1; CHECK_OK=1
check "$(backup_exit happy)" "3" "phase 1 exit"
check "$(backup_status happy)" "signing-required" "phase 1 status"
check "$(journal_phase "$CASE_DATA" "$HAPPY_OP")" "staged" "journal phase after phase 1"
check "$(marker_count "$CASE_DATA")" "0" "marker count after phase 1"
check "$(is_published "$CASE_DEST" "$HAPPY_OP")" "no" "phase 1 publication"
check "$(lock_owner "$CASE_DATA")" "free" "lock owner after phase 1"
if ! assert_phase_one_contract happy "$CASE_DEST" "$HAPPY_OP" "$CASE_DATA" 2>"$WORK/case-1.assert"; then
    CHECK_OK=0; log "  phase-1 contract: $(cat "$WORK/case-1.assert")"
fi
(( CHECK_OK )) || C1_OK=0
if (( C1_OK )); then
    record PASS case-1a "3" "staged" "0" "free" "no" "-" "phase 1 staged the artifact and exited 3 signing-required; nothing published"
else
    record FAIL case-1a "3?" "staged?" "$(marker_count "$CASE_DATA")" "$(lock_owner "$CASE_DATA")" "?" "-" "phase-1 contract failed"
fi

# D9 reservation (case 10) is computed from this same fixture.
C10_OK=1; CHECK_OK=1
PHASE1_SOURCE_BYTES="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["source_bytes"])' "$WORK/happy.backup.json")"
PHASE1_RESERVED_BYTES="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["reserved_bytes"])' "$WORK/happy.backup.json")"
EXPECTED_R="$(python3 -c "s=$HAPPY_EXPECTED_SOURCE; print(max(2*s + 1024**3, 6*1024**3))")"
check "$PHASE1_SOURCE_BYTES" "$HAPPY_EXPECTED_SOURCE" "D9 source_bytes measurement"
check "$PHASE1_RESERVED_BYTES" "$EXPECTED_R" "D9 reservation formula"
if (( PHASE1_RESERVED_BYTES > 9 * 1024 * 1024 * 1024 )); then CHECK_OK=0; log "  D9 reservation exceeds the 9 GiB cap"; fi
(( CHECK_OK )) || C10_OK=0
if (( C10_OK )); then
    record PASS case-10 "3" "staged" "0" "free" "no" "-" \
        "D9: source_bytes=$PHASE1_SOURCE_BYTES reserved_bytes=$PHASE1_RESERVED_BYTES = max(2S+1GiB,6GiB), no truncation"
else
    record FAIL case-10 "3" "staged" "0" "free" "no" "-" \
        "D9 mismatch: source=$PHASE1_SOURCE_BYTES reserved=$PHASE1_RESERVED_BYTES expected_S=$HAPPY_EXPECTED_SOURCE expected_R=$EXPECTED_R"
fi

# Permissions (case 8) while staging exists.
C8_OK=1; CHECK_OK=1
STAGING="$CASE_DEST/.o3k-backup-artifact-$HAPPY_OP"
check "$(stat -c %a "$STAGING")" "700" "staging directory mode"
while read -r mode path; do
    [[ "$mode" == "600" ]] || { CHECK_OK=0; log "  staged file mode $mode: $path"; }
done < <(find "$STAGING" -type f -printf '%m %p\n')
check "$(stat -c %a "$CASE_TRUST")" "600" "trust config mode"
check "$(stat -c %a "$BACKUP_SIGNING_KEY")" "600" "signing key mode"
check "$(stat -c %a "$BACKUP_RECIPIENT_KEY")" "600" "recipient key mode"
(( CHECK_OK )) || C8_OK=0

# Phase 2: the offline custodian signs, then the exact same command runs.
sign_request "$STAGING" || C1_OK=0
run_backup happy-complete "$CASE_DATA" "$CASE_DEST" "$HAPPY_OP"
C1_PHASE2_EXIT="$(backup_exit happy-complete)"
check "$C1_PHASE2_EXIT" "0" "phase 2 exit"
check "$(backup_status happy-complete)" "backup-published" "phase 2 status"
check "$(journal_phase "$CASE_DATA" "$HAPPY_OP")" "published" "journal phase after phase 2"
check "$(is_published "$CASE_DEST" "$HAPPY_OP")" "yes" "artifact published"
check "$(lock_owner "$CASE_DATA")" "free" "lock owner after phase 2"
[[ ! -e "$STAGING" ]] || { CHECK_OK=0; log "  staging still present after publication"; }
(( CHECK_OK )) || C1_OK=0

HAPPY_ARTIFACT="$(published_path "$CASE_DEST" "$HAPPY_OP")"
HAPPY_ARTIFACT_SHA="$(artifact_sha "$CASE_DEST" "$HAPPY_OP")"
PHASE2_SHA="$(json_get "$WORK/happy-complete.backup.json" sha256)"
check "$PHASE2_SHA" "$HAPPY_ARTIFACT_SHA" "phase-2 JSON digest equals artifact digest"
[[ "$(json_get "$WORK/happy-complete.backup.json" signature)" == "verified" ]] || { CHECK_OK=0; log "  phase-2 signature not verified"; }

run_verify case-1 "$CASE_DATA" "$CASE_TRUST" "$CASE_PREFIX" "$HAPPY_ARTIFACT"
check "$(verify_exit case-1)" "0" "verify exit"
check "$(verify_status case-1)" "verified" "verify status"
[[ "$(json_get "$WORK/case-1.verify.json" release_match)" == "true" ]] || { CHECK_OK=0; log "  verify release_match not true"; }
VERIFY_SHA="$(json_get "$WORK/case-1.verify.json" artifact_sha256)"
check "$VERIFY_SHA" "$HAPPY_ARTIFACT_SHA" "verify digest equals artifact digest"
SQLITE_VERSION="$(read_manifest_facts "$HAPPY_ARTIFACT" | sed -n '1p')"
MANIFEST_SCHEMA_VERSION="$(read_manifest_facts "$HAPPY_ARTIFACT" | sed -n '2p')"
check "$MANIFEST_SCHEMA_VERSION" "$SCHEMA_VERSION" "manifest schema version"
check_nonempty "$SQLITE_VERSION" "manifest sqlite_version"
(( CHECK_OK )) || C1_OK=0
if (( C1_OK )); then
    record PASS case-1b "$C1_PHASE2_EXIT" "published" "0" "free" "yes" "verified(exit=0)" \
        "offline detached signature verified; published $HAPPY_ARTIFACT_SHA; verify exit 0 release_match"
else
    record FAIL case-1b "$C1_PHASE2_EXIT" "$(journal_phase "$CASE_DATA" "$HAPPY_OP")" \
        "$(marker_count "$CASE_DATA")" "$(lock_owner "$CASE_DATA")" "$(is_published "$CASE_DEST" "$HAPPY_OP")" \
        "verify_exit=$(verify_exit case-1 2>/dev/null || echo '?')" "phase-2/verify contract failed"
fi

# Tamper: flip the last ciphertext byte of a copy; the signature covers the
# manifest (unchanged), so the member GCM tag is the failing boundary.
TAMPERED="$WORK/happy-tampered.o3k"
cp "$HAPPY_ARTIFACT" "$TAMPERED"
chmod 0600 "$TAMPERED"
python3 - "$TAMPERED" <<'PY'
import sys
path = sys.argv[1]
raw = bytearray(open(path, "rb").read())
raw[-1] ^= 0x01
open(path, "wb").write(raw)
PY
run_verify case-1-tamper "$CASE_DATA" "$CASE_TRUST" "$CASE_PREFIX" "$TAMPERED"
C1_TAMPER_EXIT="$(verify_exit case-1-tamper)"
C1_TAMPER_REASON="$(verify_reason case-1-tamper)"
CHECK_OK=1
check "$C1_TAMPER_EXIT" "2" "tampered verify exit"
check "$C1_TAMPER_REASON" "corrupt-artifact" "tampered verify reason"
(( CHECK_OK )) || C1_OK=0
if (( CHECK_OK )); then
    record PASS case-1c "$C1_TAMPER_EXIT" "published" "0" "free" "yes" "corrupt-artifact(exit=2)" \
        "single-byte ciphertext flip rejected as corrupt-artifact; published artifact untouched"
else
    record FAIL case-1c "$C1_TAMPER_EXIT" "published" "0" "free" "yes" "$C1_TAMPER_REASON" "tamper rejection failed"
fi

# ---------------------------------------------------------------------------
# Case 2: idempotent phase-1 re-run without a response
# ---------------------------------------------------------------------------
echo
echo "== Case 2: idempotent phase-1 re-run =="
fresh_case_dirs idem
IDEM_OP="$(new_op_id)"
start_daemon idem "$CASE_DATA"
if wait_ready idem 30; then
    run_backup idem "$CASE_DATA" "$CASE_DEST" "$IDEM_OP"
    IDEM_JOURNAL_BEFORE="$(journal_sha256 "$CASE_DATA" "$IDEM_OP")"
    IDEM_MEMBERS_BEFORE="$(find "$CASE_DEST/.o3k-backup-artifact-$IDEM_OP" -maxdepth 1 -name 'members-*' | wc -l)"
    IDEM_ARTIFACT_BEFORE="$(sha256sum "$CASE_DEST/.o3k-backup-artifact-$IDEM_OP"/members-*/artifact.unsigned | cut -d' ' -f1)"
    run_backup idem-rerun "$CASE_DATA" "$CASE_DEST" "$IDEM_OP"
    CHECK_OK=1
    check "$(backup_exit idem)" "3" "first phase-1 exit"
    check "$(backup_exit idem-rerun)" "3" "re-run exit"
    check "$(backup_status idem-rerun)" "signing-required" "re-run status"
    check "$(journal_sha256 "$CASE_DATA" "$IDEM_OP")" "$IDEM_JOURNAL_BEFORE" "journal unchanged by re-run"
    check "$(find "$CASE_DEST/.o3k-backup-artifact-$IDEM_OP" -maxdepth 1 -name 'members-*' | wc -l)" "$IDEM_MEMBERS_BEFORE" "no duplicate capture"
    check "$(sha256sum "$CASE_DEST/.o3k-backup-artifact-$IDEM_OP"/members-*/artifact.unsigned | cut -d' ' -f1)" \
        "$IDEM_ARTIFACT_BEFORE" "same staged artifact digest"
    check "$(is_published "$CASE_DEST" "$IDEM_OP")" "no" "nothing published"
    check "$(lock_owner "$CASE_DATA")" "free" "lock owner"
    reap_exit "$(daemon_pid idem)" 30 || true
    if (( CHECK_OK )); then
        record PASS case-2 "$(backup_exit idem-rerun)" "staged" "0" "free" "no" "-" \
            "second phase-1 run returned signing-required with an unchanged journal and no re-capture"
    else
        record FAIL case-2 "$(backup_exit idem-rerun)" "$(journal_phase "$CASE_DATA" "$IDEM_OP")" \
            "$(marker_count "$CASE_DATA")" "$(lock_owner "$CASE_DATA")" "$(is_published "$CASE_DEST" "$IDEM_OP")" "-" \
            "idempotent re-run contract failed"
    fi
else
    record FAIL case-2 "-" "-" "-" "-" "-" "-" "daemon not ready"
fi

# ---------------------------------------------------------------------------
# Case 3: duplicate after publication
# ---------------------------------------------------------------------------
echo
echo "== Case 3: duplicate after publication =="
CASE_DATA="$HAPPY_DATA"; CASE_DEST="$HAPPY_DEST"; CASE_TRUST="$HAPPY_TRUST"; CASE_PREFIX="$HAPPY_PREFIX"
run_backup happy-duplicate "$HAPPY_DATA" "$HAPPY_DEST" "$HAPPY_OP"
CHECK_OK=1
check "$(backup_exit happy-duplicate)" "2" "duplicate exit"
check "$(backup_reason happy-duplicate)" "operation-already-published" "duplicate reason"
check "$(journal_phase "$HAPPY_DATA" "$HAPPY_OP")" "published" "journal remains published"
check "$(is_published "$HAPPY_DEST" "$HAPPY_OP")" "yes" "exactly one published artifact"
check "$(find "$HAPPY_DEST" -maxdepth 1 -name "backup-$HAPPY_OP.o3k" | wc -l)" "1" "artifact count"
(( CHECK_OK )) && C3_OK=1 || C3_OK=0
if (( C3_OK )); then
    record PASS case-3 "$(backup_exit happy-duplicate)" "published" "0" "$(lock_owner "$HAPPY_DATA")" "yes" "-" \
        "re-run after publication rejected with operation-already-published; no second capture"
else
    record FAIL case-3 "$(backup_exit happy-duplicate)" "published" "0" "$(lock_owner "$HAPPY_DATA")" "yes" "-" \
        "duplicate-after-publication contract failed"
fi

# ---------------------------------------------------------------------------
# Case 4: signature rejection matrix
# ---------------------------------------------------------------------------
echo
echo "== Case 4: signature rejection matrix =="
reject_case() { # reject_case <suffix> <mutation> <expected-exit> <expected-reason>
    local suffix="$1" mutation="$2" expected_exit="$3" expected_reason="$4"
    local key="sig-$suffix"
    fresh_case_dirs "$key"
    local op; op="$(new_op_id)"
    start_daemon "$key" "$CASE_DATA"
    if ! wait_ready "$key" 30; then
        record FAIL "case-4$suffix" "-" "-" "-" "-" "-" "-" "daemon not ready"
        return
    fi
    run_backup "$key" "$CASE_DATA" "$CASE_DEST" "$op"
    local staging="$CASE_DEST/.o3k-backup-artifact-$op"
    local mutation_ok=1
    case "$mutation" in
        wrong-signature)
            decode_signing_input "$staging"
            sign_bytes "$BACKUP_FOREIGN_KEY" "$WORK/sign-input.bin" "$WORK/sign-input.sig"
            write_response_file "$staging" "$WORK/sign-input.sig" "$WORK/sign-meta.json"
            ;;
        wrong-key-id)
            sign_request "$staging"
            mutate_response "$staging" 'response["key_id"] = "signing-2"'
            ;;
        short-signature)
            sign_request "$staging"
            mutate_response "$staging" 'response["signature"] = response["signature"][:32]'
            ;;
        request-digest)
            sign_request "$staging"
            mutate_response "$staging" 'response["request_sha256"] = "e" * 64'
            ;;
        expired-request)
            expire_signing_request "$staging" "$CASE_DATA" "$op"
            sign_request "$staging"
            ;;
        *) mutation_ok=0 ;;
    esac
    if (( mutation_ok )); then
        run_backup "$key-complete" "$CASE_DATA" "$CASE_DEST" "$op"
        CHECK_OK=1
        check "$(backup_exit "$key")" "3" "phase 1 exit"
        check "$(backup_exit "$key-complete")" "$expected_exit" "rejection exit"
        check "$(backup_reason "$key-complete")" "$expected_reason" "rejection reason"
        check "$(is_published "$CASE_DEST" "$op")" "no" "nothing published"
        check "$(journal_phase "$CASE_DATA" "$op")" "staged" "journal remains staged"
        [[ -d "$staging" ]] || { CHECK_OK=0; log "  staging removed on rejection"; }
        check "$(marker_count "$CASE_DATA")" "0" "marker absent"
        check "$(lock_owner "$CASE_DATA")" "free" "lock owner"
    else
        CHECK_OK=0
    fi
    reap_exit "$(daemon_pid "$key")" 30 || true
    if (( CHECK_OK )); then
        record PASS "case-4$suffix" "$(backup_exit "$key-complete" 2>/dev/null || echo '?')" "staged" "0" "free" "no" \
            "$expected_reason(exit=$expected_exit)" "$mutation rejected; staging preserved, nothing published"
    else
        record FAIL "case-4$suffix" "$(backup_exit "$key-complete" 2>/dev/null || echo '?')" \
            "$(journal_phase "$CASE_DATA" "$op")" "$(marker_count "$CASE_DATA")" "$(lock_owner "$CASE_DATA")" \
            "$(is_published "$CASE_DEST" "$op")" "$(backup_reason "$key-complete" 2>/dev/null || echo '?')" \
            "$mutation rejection failed"
    fi
}
reject_case a wrong-signature 2 signature-invalid
reject_case b wrong-key-id 2 signing-response-mismatch
reject_case c short-signature 2 signing-response-invalid
reject_case d request-digest 2 signing-response-mismatch
reject_case e expired-request 3 signing-request-expired

# ---------------------------------------------------------------------------
# Case 5: crash injection around the new journal phases
# ---------------------------------------------------------------------------
echo
echo "== Case 5: journal-phase crash injection =="

# 5a: crash after journal `captured`.
fresh_case_dirs crash-captured
C5A_OP="$(new_op_id)"
start_daemon crash-captured "$CASE_DATA"
if wait_ready crash-captured 30; then
    run_backup crash-captured "$CASE_DATA" "$CASE_DEST" "$C5A_OP" O3K_BACKUP_TEST_EXIT_AFTER_JOURNAL_CAPTURED=1
    reap_exit "$(daemon_pid crash-captured)" 30 || true
    CHECK_OK=1
    check "$(backup_exit crash-captured)" "86" "hook exit"
    check "$(journal_phase "$CASE_DATA" "$C5A_OP")" "captured" "journal phase after crash"
    check "$(marker_count "$CASE_DATA")" "1" "marker still denies after captured crash"
    check "$(is_published "$CASE_DEST" "$C5A_OP")" "no" "nothing published"
    check "$(lock_owner "$CASE_DATA")" "free" "lock owner after executor death"
    run_backup crash-captured-retry "$CASE_DATA" "$CASE_DEST" "$C5A_OP"
    check "$(backup_exit crash-captured-retry)" "3" "retry exit"
    check "$(backup_reason crash-captured-retry)" "backup-operation-incomplete" "retry reason"
    check "$(journal_phase "$CASE_DATA" "$C5A_OP")" "captured" "journal unchanged by retry"
    if (( CHECK_OK )); then
        record PASS case-5a "$(backup_exit crash-captured)" "captured" "1" "free" "no" \
            "backup-operation-incomplete(exit=3)" "crash after captured: marker retained, retry refuses to recapture"
    else
        record FAIL case-5a "$(backup_exit crash-captured)" "$(journal_phase "$CASE_DATA" "$C5A_OP")" \
            "$(marker_count "$CASE_DATA")" "$(lock_owner "$CASE_DATA")" "$(is_published "$CASE_DEST" "$C5A_OP")" \
            "$(backup_reason crash-captured-retry 2>/dev/null || echo '?')" "captured-crash recovery failed"
    fi
else
    record FAIL case-5a "-" "-" "-" "-" "-" "-" "daemon not ready"
fi

# 5b: crash after journal `staged`, before marker removal; replay publishes.
fresh_case_dirs crash-staged
C5B_OP="$(new_op_id)"
start_daemon crash-staged "$CASE_DATA"
if wait_ready crash-staged 30; then
    run_backup crash-staged "$CASE_DATA" "$CASE_DEST" "$C5B_OP" O3K_BACKUP_TEST_EXIT_AFTER_JOURNAL_STAGED=1
    reap_exit "$(daemon_pid crash-staged)" 30 || true
    C5B_STAGING="$CASE_DEST/.o3k-backup-artifact-$C5B_OP"
    C5B_REQUEST_BEFORE="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["request_sha256"])' "$CASE_DATA/backup-operations/$C5B_OP.json")"
    CHECK_OK=1
    check "$(backup_exit crash-staged)" "87" "hook exit"
    check "$(journal_phase "$CASE_DATA" "$C5B_OP")" "staged" "journal phase after crash"
    check "$(marker_count "$CASE_DATA")" "1" "marker retained by the injected crash"
    check "$(is_published "$CASE_DEST" "$C5B_OP")" "no" "nothing published before replay"
    sign_request "$C5B_STAGING" || CHECK_OK=0
    run_backup crash-staged-replay "$CASE_DATA" "$CASE_DEST" "$C5B_OP"
    check "$(backup_exit crash-staged-replay)" "0" "replay exit"
    check "$(journal_phase "$CASE_DATA" "$C5B_OP")" "published" "journal after replay"
    check "$(is_published "$CASE_DEST" "$C5B_OP")" "yes" "artifact published by replay"
    check "$(find "$CASE_DEST" -maxdepth 1 -name "backup-$C5B_OP.o3k" | wc -l)" "1" "single artifact"
    # The staged request (and its digest) must be the same one phase 1 wrote:
    # the replay must not have captured again.
    check "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["request_sha256"])' "$CASE_DATA/backup-operations/$C5B_OP.json")" \
        "$C5B_REQUEST_BEFORE" "journal request digest preserved (no recapture)"
    check "$(marker_count "$CASE_DATA")" "1" "marker still present (phase 2 never owns it)"
    if (( CHECK_OK )); then
        record PASS case-5b "$(backup_exit crash-staged)" "published" "1" "free" "yes" "published(exit=0)" \
            "crash after staged: replay published from the staged request without recapture; marker remains for operator follow-up"
    else
        record FAIL case-5b "$(backup_exit crash-staged)" "$(journal_phase "$CASE_DATA" "$C5B_OP")" \
            "$(marker_count "$CASE_DATA")" "$(lock_owner "$CASE_DATA")" "$(is_published "$CASE_DEST" "$C5B_OP")" \
            "$(backup_exit crash-staged-replay 2>/dev/null || echo '?')" "staged-crash replay failed"
    fi
else
    record FAIL case-5b "-" "-" "-" "-" "-" "-" "daemon not ready"
fi

# 5c: crash after journal `publishing`, before the no-replace rename.
fresh_case_dirs crash-publishing
C5C_OP="$(new_op_id)"
start_daemon crash-publishing "$CASE_DATA"
if wait_ready crash-publishing 30; then
    run_backup crash-publishing "$CASE_DATA" "$CASE_DEST" "$C5C_OP"
    reap_exit "$(daemon_pid crash-publishing)" 30 || true
    sign_request "$CASE_DEST/.o3k-backup-artifact-$C5C_OP" || true
    run_backup crash-publishing-hook "$CASE_DATA" "$CASE_DEST" "$C5C_OP" O3K_BACKUP_TEST_EXIT_AFTER_JOURNAL_PUBLISHING=1
    CHECK_OK=1
    check "$(backup_exit crash-publishing-hook)" "88" "hook exit"
    check "$(journal_phase "$CASE_DATA" "$C5C_OP")" "publishing" "journal phase after crash"
    check "$(is_published "$CASE_DEST" "$C5C_OP")" "no" "nothing published before replay"
    run_backup crash-publishing-replay "$CASE_DATA" "$CASE_DEST" "$C5C_OP"
    check "$(backup_exit crash-publishing-replay)" "0" "replay exit"
    check "$(journal_phase "$CASE_DATA" "$C5C_OP")" "published" "journal after replay"
    check "$(is_published "$CASE_DEST" "$C5C_OP")" "yes" "artifact published"
    check "$(find "$CASE_DEST" -maxdepth 1 -name "backup-$C5C_OP.o3k" | wc -l)" "1" "single artifact"
    if (( CHECK_OK )); then
        record PASS case-5c "$(backup_exit crash-publishing-hook)" "published" "0" "free" "yes" "published(exit=0)" \
            "crash after publishing: replay observed the staged signed artifact and finished without a duplicate rename"
    else
        record FAIL case-5c "$(backup_exit crash-publishing-hook)" "$(journal_phase "$CASE_DATA" "$C5C_OP")" \
            "$(marker_count "$CASE_DATA")" "$(lock_owner "$CASE_DATA")" "$(is_published "$CASE_DEST" "$C5C_OP")" \
            "$(backup_exit crash-publishing-replay 2>/dev/null || echo '?')" "publishing-crash replay failed"
    fi
else
    record FAIL case-5c "-" "-" "-" "-" "-" "-" "daemon not ready"
fi

# 5d: crash after publication, before the success document.
fresh_case_dirs crash-postpublish
C5D_OP="$(new_op_id)"
start_daemon crash-postpublish "$CASE_DATA"
if wait_ready crash-postpublish 30; then
    run_backup crash-postpublish "$CASE_DATA" "$CASE_DEST" "$C5D_OP"
    reap_exit "$(daemon_pid crash-postpublish)" 30 || true
    sign_request "$CASE_DEST/.o3k-backup-artifact-$C5D_OP" || true
    run_backup crash-postpublish-hook "$CASE_DATA" "$CASE_DEST" "$C5D_OP" O3K_BACKUP_TEST_EXIT_AFTER_PUBLICATION=1
    CHECK_OK=1
    check "$(backup_exit crash-postpublish-hook)" "89" "hook exit"
    check "$(journal_phase "$CASE_DATA" "$C5D_OP")" "published" "journal phase after crash"
    check "$(is_published "$CASE_DEST" "$C5D_OP")" "yes" "artifact published before crash"
    run_backup crash-postpublish-retry "$CASE_DATA" "$CASE_DEST" "$C5D_OP"
    check "$(backup_exit crash-postpublish-retry)" "2" "retry exit"
    check "$(backup_reason crash-postpublish-retry)" "operation-already-published" "retry reason"
    check "$(find "$CASE_DEST" -maxdepth 1 -name "backup-$C5D_OP.o3k" | wc -l)" "1" "single artifact"
    if (( CHECK_OK )); then
        record PASS case-5d "$(backup_exit crash-postpublish-hook)" "published" "0" "free" "yes" \
            "operation-already-published(exit=2)" "crash after publication: exactly one artifact and a replay refuses duplication"
    else
        record FAIL case-5d "$(backup_exit crash-postpublish-hook)" "$(journal_phase "$CASE_DATA" "$C5D_OP")" \
            "$(marker_count "$CASE_DATA")" "$(lock_owner "$CASE_DATA")" "$(is_published "$CASE_DEST" "$C5D_OP")" \
            "$(backup_reason crash-postpublish-retry 2>/dev/null || echo '?')" "post-publication crash contract failed"
    fi
else
    record FAIL case-5d "-" "-" "-" "-" "-" "-" "daemon not ready"
fi

# ---------------------------------------------------------------------------
# Case 6: publication race with a pre-existing final artifact
# ---------------------------------------------------------------------------
echo
echo "== Case 6: publication collision =="
fresh_case_dirs collision
C6_OP="$(new_op_id)"
start_daemon collision "$CASE_DATA"
if wait_ready collision 30; then
    run_backup collision "$CASE_DATA" "$CASE_DEST" "$C6_OP"
    reap_exit "$(daemon_pid collision)" 30 || true
    sign_request "$CASE_DEST/.o3k-backup-artifact-$C6_OP" || true
    printf 'pre-existing artifact\n' >"$CASE_DEST/backup-$C6_OP.o3k"
    chmod 0600 "$CASE_DEST/backup-$C6_OP.o3k"
    run_backup collision-complete "$CASE_DATA" "$CASE_DEST" "$C6_OP"
    CHECK_OK=1
    check "$(backup_exit collision-complete)" "2" "collision exit"
    check "$(backup_reason collision-complete)" "artifact-destination-exists" "collision reason"
    check "$(cat "$CASE_DEST/backup-$C6_OP.o3k")" "pre-existing artifact" "pre-existing artifact untouched"
    [[ -d "$CASE_DEST/.o3k-backup-artifact-$C6_OP" ]] || { CHECK_OK=0; log "  staging removed on collision"; }
    check "$(journal_phase "$CASE_DATA" "$C6_OP")" "publishing" "journal preserves attempted publication"
    rm -f "$CASE_DEST/backup-$C6_OP.o3k"
    run_backup collision-retry "$CASE_DATA" "$CASE_DEST" "$C6_OP"
    check "$(backup_exit collision-retry)" "0" "retry after clearing collision"
    check "$(is_published "$CASE_DEST" "$C6_OP")" "yes" "artifact published after retry"
    run_verify collision-verify "$CASE_DATA" "$CASE_TRUST" "$CASE_PREFIX" "$(published_path "$CASE_DEST" "$C6_OP")"
    check "$(verify_exit collision-verify)" "0" "retry artifact verifies"
    if (( CHECK_OK )); then
        record PASS case-6 "$(backup_exit collision-complete)" "published" "0" "free" "yes" "verified(exit=0)" \
            "pre-existing final artifact never replaced (exit 2 artifact-destination-exists); staging kept; clearing the collision published on replay"
    else
        record FAIL case-6 "$(backup_exit collision-complete)" "$(journal_phase "$CASE_DATA" "$C6_OP")" \
            "$(marker_count "$CASE_DATA")" "$(lock_owner "$CASE_DATA")" "$(is_published "$CASE_DEST" "$C6_OP")" \
            "$(verify_exit collision-verify 2>/dev/null || echo '?')" "publication-collision contract failed"
    fi
else
    record FAIL case-6 "-" "-" "-" "-" "-" "-" "daemon not ready"
fi

# ---------------------------------------------------------------------------
# Case 7: destination swap after preflight (phase 2)
# ---------------------------------------------------------------------------
echo
echo "== Case 7: destination symlink swap before phase 2 =="
fresh_case_dirs swap
C7_OP="$(new_op_id)"
start_daemon swap "$CASE_DATA"
if wait_ready swap 30; then
    run_backup swap "$CASE_DATA" "$CASE_DEST" "$C7_OP"
    reap_exit "$(daemon_pid swap)" 30 || true
    sign_request "$CASE_DEST/.o3k-backup-artifact-$C7_OP" || true
    mv "$CASE_DEST" "$CASE_DEST.real"
    ln -s "$CASE_DEST.real" "$CASE_DEST"
    run_backup swap-complete "$CASE_DATA" "$CASE_DEST" "$C7_OP"
    CHECK_OK=1
    check "$(backup_exit swap-complete)" "2" "swapped-destination exit"
    check "$(backup_reason swap-complete)" "destination-symlink" "swapped-destination reason"
    check "$(find "$CASE_DEST.real" -maxdepth 1 -name 'backup-*.o3k' | wc -l)" "0" "nothing published through the symlink"
    [[ -d "$CASE_DEST.real/.o3k-backup-artifact-$C7_OP" ]] || { CHECK_OK=0; log "  staging lost on swap rejection"; }
    rm -f "$CASE_DEST"
    mv "$CASE_DEST.real" "$CASE_DEST"
    run_backup swap-retry "$CASE_DATA" "$CASE_DEST" "$C7_OP"
    check "$(backup_exit swap-retry)" "0" "retry after restoring the destination"
    check "$(is_published "$CASE_DEST" "$C7_OP")" "yes" "artifact published after restore"
    if (( CHECK_OK )); then
        record PASS case-7 "$(backup_exit swap-complete)" "staged" "0" "free" "no" "destination-symlink(exit=2)" \
            "destination replaced by a symlink before phase 2 fails closed (destination-symlink); nothing published outside; retry after restore succeeds"
    else
        record FAIL case-7 "$(backup_exit swap-complete)" "$(journal_phase "$CASE_DATA" "$C7_OP")" \
            "$(marker_count "$CASE_DATA")" "$(lock_owner "$CASE_DATA")" "$(is_published "$CASE_DEST" "$C7_OP")" \
            "$(backup_reason swap-complete 2>/dev/null || echo '?')" "destination-swap contract failed"
    fi
else
    record FAIL case-7 "-" "-" "-" "-" "-" "-" "daemon not ready"
fi

# ---------------------------------------------------------------------------
# Case 8: owner-only staging and no leftover plaintext after verify
# ---------------------------------------------------------------------------
echo
echo "== Case 8: owner-only staging and cleanup =="
CHECK_OK=1
(( C8_OK )) || { CHECK_OK=0; log "  phase-1 staging mode/file scan failed"; }
if [[ "$(stat -c %a "$BACKUP_SIGNING_KEY")" == "600" && "$(stat -c %a "$BACKUP_RECIPIENT_KEY")" == "600" && "$(stat -c %a "$HAPPY_TRUST")" == "600" ]]; then
    :
else
    CHECK_OK=0; log "  trust/key fixture modes are not 0600"
fi
# The happy staging directory was removed on publication; assert the published
# artifact itself is private and the verifier left none of its plaintext
# staging behind.
check "$(stat -c %a "$HAPPY_ARTIFACT")" "600" "published artifact mode"
check "$(find "$HAPPY_DATA" -maxdepth 1 -name '.o3k-verify-staging-*' | wc -l)" "0" "verify staging removed"
check "$(find "$HAPPY_DEST" -name '.o3k-backup-artifact-*' | wc -l)" "0" "artifact staging removed after publication"
if (( HAVE_SQLITE3 )); then
    # The verifier's staging is the only place decrypted plaintext existed.
    check "$(find "$HAPPY_DATA" -maxdepth 1 -name '.o3k-verify-*' -perm /004 | wc -l)" "0" "no world-readable plaintext staging"
fi
if (( CHECK_OK )); then
    record PASS case-8 "-" "-" "-" "free" "yes" "clean" \
        "staging 0700 / staged files 0600 / trust+keys 0600; verify removed its plaintext staging; published artifact 0600"
else
    record FAIL case-8 "-" "-" "-" "free" "yes" "-" "permission/cleanup contract failed"
fi

# ---------------------------------------------------------------------------
# Case 9: secret scan over all captured output and the published artifact
# ---------------------------------------------------------------------------
echo
echo "== Case 9: secret scan =="
SECRET_MATCHES_FILE="$WORK/secret-matches.txt"
: >"$SECRET_MATCHES_FILE"
scan_for() { # scan_for <needle> <label>
    local needle="$1" label="$2"
    local matches
    matches="$(grep -aF -l -- "$needle" "$WORK"/*.json "$WORK"/*.stderr "$WORK"/*.log "$WORK"/*.txt 2>/dev/null || true)"
    if [[ -n "$matches" ]]; then
        printf '%s: %s\n' "$label" "$matches" >>"$SECRET_MATCHES_FILE"
    fi
}
scan_for "$BACKUP_SIGNING_SEED_HEX" "private-seed-hex"
scan_for "$BACKUP_RECIPIENT_KEY_HEX" "recipient-key-hex"
scan_for "$BACKUP_SIGNING_KEY" "signing-key-path"
scan_for "$BACKUP_RECIPIENT_KEY" "recipient-key-path"
# The published artifact is ciphertext apart from the public manifest; key
# material and key paths must not appear anywhere in it.
if grep -aqF -- "$BACKUP_SIGNING_SEED_HEX" "$HAPPY_ARTIFACT" \
    || grep -aqF -- "$BACKUP_RECIPIENT_KEY_HEX" "$HAPPY_ARTIFACT" \
    || grep -aqF -- "$BACKUP_RECIPIENT_KEY" "$HAPPY_ARTIFACT" \
    || grep -aqF -- "$BACKUP_SIGNING_KEY" "$HAPPY_ARTIFACT"; then
    echo "published-artifact: key material or key path present" >>"$SECRET_MATCHES_FILE"
fi
if [[ ! -s "$SECRET_MATCHES_FILE" ]]; then
    record PASS case-9 "-" "-" "-" "free" "yes" "no-secrets" \
        "seed hex, recipient key hex, signing-key path and recipient-key path absent from every captured stdout/stderr/log and from the published artifact"
else
    record FAIL case-9 "-" "-" "-" "free" "yes" "-" "secret scan matched: $(tr '\n' ';' <"$SECRET_MATCHES_FILE")"
fi

# ---------------------------------------------------------------------------
# Case 11: replacement controller starts on a staged (non-terminal) journal
# ---------------------------------------------------------------------------
echo
echo "== Case 11: restart safety with a staged journal =="
fresh_case_dirs restart
C11_OP="$(new_op_id)"
start_daemon restart1 "$CASE_DATA"
if wait_ready restart1 30; then
    run_backup restart "$CASE_DATA" "$CASE_DEST" "$C11_OP"
    reap_exit "$(daemon_pid restart1)" 30 || true
    CHECK_OK=1
    check "$(backup_exit restart)" "3" "phase 1 exit"
    check "$(journal_phase "$CASE_DATA" "$C11_OP")" "staged" "journal staged before restart"
    start_daemon restart2 "$CASE_DATA"
    if wait_ready restart2 30; then
        wait_log restart2 "backup operation has not reached a terminal phase" 10 || { CHECK_OK=0; log "  daemon did not warn about the pending operation"; }
        sigterm_expect_zero restart2 || { CHECK_OK=0; log "  replacement daemon did not exit 0 on SIGTERM"; }
    else
        CHECK_OK=0; log "  replacement daemon not ready"
    fi
    sign_request "$CASE_DEST/.o3k-backup-artifact-$C11_OP" || CHECK_OK=0
    run_backup restart-complete "$CASE_DATA" "$CASE_DEST" "$C11_OP"
    check "$(backup_exit restart-complete)" "0" "phase 2 after restart"
    check "$(is_published "$CASE_DEST" "$C11_OP")" "yes" "artifact published after restart"
    run_verify restart-verify "$CASE_DATA" "$CASE_TRUST" "$CASE_PREFIX" "$(published_path "$CASE_DEST" "$C11_OP")"
    check "$(verify_exit restart-verify)" "0" "artifact verifies after restart"
    if (( CHECK_OK )); then
        record PASS case-11 "$(backup_exit restart)" "published" "0" "free" "yes" "verified(exit=0)" \
            "replacement o3kd started and reached ready with a staged journal (warn only), exited 0 on SIGTERM, and phase 2 still published"
    else
        record FAIL case-11 "$(backup_exit restart)" "$(journal_phase "$CASE_DATA" "$C11_OP")" \
            "$(marker_count "$CASE_DATA")" "$(lock_owner "$CASE_DATA")" "$(is_published "$CASE_DEST" "$C11_OP")" \
            "$(verify_exit restart-verify 2>/dev/null || echo '?')" "restart-safety contract failed"
    fi
else
    record FAIL case-11 "-" "-" "-" "-" "-" "-" "daemon not ready"
fi

# ---------------------------------------------------------------------------
# Case 12: verify rejection matrix
# ---------------------------------------------------------------------------
echo
echo "== Case 12: verify rejection matrix =="
FOREIGN_TRUST="$(write_config verify-foreign "$HAPPY_DATA" foreign-identity)"
ALT_PREFIX="$WORK/cfg-verify-alt-release-alt-release/install"
write_config verify-alt-release "$HAPPY_DATA" alt-release >/dev/null
REVOKED_TRUST="$(write_config verify-revoked "$HAPPY_DATA" revoked)"

run_verify verify-missing-trust "$HAPPY_DATA" "$WORK/absent-trust.json" "$HAPPY_PREFIX" "$HAPPY_ARTIFACT"
run_verify verify-identity "$HAPPY_DATA" "$FOREIGN_TRUST" "$HAPPY_PREFIX" "$HAPPY_ARTIFACT"
run_verify verify-release "$HAPPY_DATA" "$HAPPY_TRUST" "$ALT_PREFIX" "$HAPPY_ARTIFACT"
run_verify verify-revoked "$HAPPY_DATA" "$REVOKED_TRUST" "$HAPPY_PREFIX" "$HAPPY_ARTIFACT"
TRUNCATED="$WORK/happy-truncated.o3k"
head -c 100 "$HAPPY_ARTIFACT" >"$TRUNCATED"
chmod 0600 "$TRUNCATED"
run_verify verify-truncated "$HAPPY_DATA" "$HAPPY_TRUST" "$HAPPY_PREFIX" "$TRUNCATED"

verify_row() { # verify_row <suffix> <expected-exit> <expected-reason> <detail>
    local suffix="$1" expected_exit="$2" expected_reason="$3" detail="$4"
    CHECK_OK=1
    check "$(verify_exit "verify-$suffix")" "$expected_exit" "$suffix exit"
    check "$(verify_reason "verify-$suffix")" "$expected_reason" "$suffix reason"
    if (( CHECK_OK )); then
        record PASS "case-12$suffix" "-" "-" "-" "free" "yes" "$expected_reason(exit=$expected_exit)" "$detail"
    else
        record FAIL "case-12$suffix" "-" "-" "-" "free" "yes" \
            "exit=$(verify_exit "verify-$suffix" 2>/dev/null || echo '?') reason=$(verify_reason "verify-$suffix" 2>/dev/null || echo '?')" "$detail"
    fi
}
verify_row missing-trust 3 trust-config-unavailable "missing trust document is a recoverable configuration failure"
verify_row identity 2 identity-mismatch "trust document bound to another installation fails closed"
verify_row release 2 release-mismatch "artifact does not match the installed exact release"
verify_row revoked 2 revoked-signing-key "revoked artifact-signing key is rejected"
verify_row truncated 2 corrupt-artifact "truncated artifact is rejected"
record NOT-COVERED case-12oversize "-" "-" "-" "-" "-" "artifact-too-large" \
    "not feasible end-to-end: verify checks the manifest-bounded size only after a valid Ed25519 signature; producing a signed manifest declaring >5GiB would require reimplementing artifact assembly. Unit mapping covered by backup_verify::tests::reason_mapping_is_stable_for_every_failure_class"

# ---------------------------------------------------------------------------
# Case 13: zero unowned mutation of canonical state
# ---------------------------------------------------------------------------
echo
echo "== Case 13: canonical-state immutability =="
snapshot_tree "$HAPPY_DATA" "$WORK/happy-after-tree.txt"
HAPPY_AFTER_DB_SHA="$(sha256_file_or_missing "$HAPPY_DATA/o3k.sqlite")"
CHECK_OK=1
check "$HAPPY_AFTER_DB_SHA" "$HAPPY_BEFORE_DB_SHA" "source database byte-identical across capture+publication"
if ! python3 - "$WORK/happy-before-tree.txt" "$WORK/happy-after-tree.txt" "$HAPPY_OP" <<'PY'
import sys
before = set(line.strip() for line in open(sys.argv[1]) if line.strip())
after = set(line.strip() for line in open(sys.argv[2]) if line.strip())
operation_id = sys.argv[3]
allowed = {
    f"f backup-operations/{operation_id}.json",
    "f o3k.sqlite-wal",
    "f o3k.sqlite-shm",
    "f .o3k-store.lock",
    "s control/backup.sock",
}
unknown = sorted(entry for entry in after - before if entry not in allowed)
assert not unknown, f"unexpected canonical-state entries: {unknown}"
assert not any(".o3k-verify-staging-" in entry for entry in after), "verify staging left behind"
assert not any(".o3k-backup-in-progress-" in entry for entry in after), "marker left behind"
print(f"tree delta: {sorted(after - before)}")
PY
then
    CHECK_OK=0
fi
if (( CHECK_OK )); then
    record PASS case-13 "-" "published" "0" "free" "yes" "unchanged-source" \
        "source DB sha256 identical before/after ($HAPPY_BEFORE_DB_SHA); only the operation journal (and transient WAL/lock/socket) appeared in the data directory"
else
    record FAIL case-13 "-" "published" "0" "free" "yes" "-" \
        "canonical-state mutation detected: before=$HAPPY_BEFORE_DB_SHA after=$HAPPY_AFTER_DB_SHA"
fi

# ---------------------------------------------------------------------------
# Summary and machine-readable verdict
# ---------------------------------------------------------------------------
echo
echo "== Matrix summary =="
printf '%-11s %-16s %-5s %-11s %-7s %-6s %-10s %-28s %s\n' \
    RESULT CASE EXIT JOURNAL MARKER LOCK PUBLISHED VERIFY DETAIL
for row in "${RESULTS[@]}"; do
    IFS='|' read -r r c e j m l p v d <<<"$row"
    printf '%-11s %-16s %-5s %-11s %-7s %-6s %-10s %-28s %s\n' "$r" "$c" "$e" "$j" "$m" "$l" "$p" "$v" "$d"
done

SOURCE_SHA="$(git rev-parse HEAD)"
if [[ -n "$(git status --porcelain -- bins/o3k bins/o3kd crates/o3k-store tests/pp6_backup_artifact.sh docs/evidence/ISSUE_1084_ARTIFACT_EVIDENCE.md 2>/dev/null)" ]]; then
    WORKING_TREE_DIRTY_PY=True
else
    WORKING_TREE_DIRTY_PY=False
fi
HOST_IDENTITY_HASH="$(printf '%s\n%s\n' "$(hostname)" "$(uname -srm)" | sha256sum | cut -d' ' -f1)"
HAPPY_SITE_ID="$(identity_hex o3k-backup-site-identity-v1 "$WORK/happy-data")"
HAPPY_INSTALLATION_ID="$(identity_hex o3k-backup-installation-identity-v1 "$WORK/happy-data")"
mkdir -p "$(dirname "$WORK/verdict.json")"
python3 - "$WORK/verdict.json" "$MATRIX_TSV" <<PY
import json, sys
out, tsv = sys.argv[1:3]
rows = [line.rstrip("\n").split("\t") for line in open(tsv) if line.strip()]
counts = {"PASS": 0, "FAIL": 0, "NOT-COVERED": 0}
for row in rows:
    counts[row[0]] = counts.get(row[0], 0) + 1
verdict = {
    "issue": 1084,
    "slice": "F",
    "campaign": "tests/pp6_backup_artifact.sh",
    "source_sha": "$SOURCE_SHA",
    "working_tree_dirty": $WORKING_TREE_DIRTY_PY,
    "harness_sha256": "$HARNESS_SHA256",
    "o3k_binary_sha256": "$O3K_BIN_SHA256",
    "o3kd_binary_sha256": "$O3KD_BIN_SHA256",
    "rustc_version": "$(rustc --version)",
    "release_artifact_sha256": "a" * 64,
    "profile": "o3k-demo-v1",
    "sqlite_version": "$SQLITE_VERSION",
    "schema_version": int("$SCHEMA_VERSION"),
    "backup_id": "$HAPPY_OP",
    "backup_digest": "$HAPPY_ARTIFACT_SHA",
    "backup_size_bytes": $(stat -c %s "$HAPPY_ARTIFACT"),
    "host_identity_hash": "$HOST_IDENTITY_HASH",
    "backup_site_id": "$HAPPY_SITE_ID",
    "backup_installation_id": "$HAPPY_INSTALLATION_ID",
    "matrix": counts,
    "executed_rows": counts.get("PASS", 0) + counts.get("FAIL", 0),
    "passed_rows": counts.get("PASS", 0),
    "failed_rows": counts.get("FAIL", 0),
    "not_covered_rows": counts.get("NOT-COVERED", 0),
}
with open(out, "w") as handle:
    json.dump(verdict, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
echo
echo "== Machine-readable verdict =="
echo "O3K_PP6_VERDICT_JSON_BEGIN"
cat "$WORK/verdict.json"
echo "O3K_PP6_VERDICT_JSON_END"

echo
if (( FAIL_COUNT == 0 )); then
    echo "PP6-BACKUP-ARTIFACT PASS: $PASS_COUNT executed checks passed, $NOT_COVERED_COUNT not-covered rows, 0 failures"
    exit 0
else
    echo "PP6-BACKUP-ARTIFACT FAIL: $FAIL_COUNT failure(s), $PASS_COUNT passed" >&2
    exit 1
fi
