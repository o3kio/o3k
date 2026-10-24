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
# input as base64url. Before signing, the harness custodian compares the
# request's `recipient_public_key_sha256` with the trusted trust document and
# refuses a mismatch (the simulated two-of-three custody check). The harness
# decodes the accepted request and signs with `openssl pkeyutl -sign -rawin
# -inkey` (OpenSSL >= 3 supports Ed25519 raw signing); python3 `cryptography` is
# an automatic fallback. The response is written to a private temp file and
# renamed into place, so the executor never observes a partial response. The
# signing key and the X25519 recipient key are generated inside the temporary
# campaign directory (0600) and are never passed to the binary that
# creates/verifies the artifact.
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
BACKUP_SIGNING_PUBLIC_PEM="$WORK/backup-signing-public.pem"
BACKUP_FOREIGN_KEY="$WORK/backup-foreign-signing-key.pem"
BACKUP_RECIPIENT_PEM="$WORK/backup-recipient.pem"
BACKUP_SWAPPED_RECIPIENT_PEM="$WORK/backup-swapped-recipient.pem"
BACKUP_RECIPIENT_KEY="$WORK/backup-recipient.key"
SWAPPED_RECIPIENT_KEY="$WORK/backup-swapped-recipient.key"
openssl genpkey -algorithm ED25519 -out "$BACKUP_SIGNING_KEY" 2>/dev/null
openssl genpkey -algorithm ED25519 -out "$BACKUP_FOREIGN_KEY" 2>/dev/null
openssl pkey -in "$BACKUP_SIGNING_KEY" -pubout -out "$BACKUP_SIGNING_PUBLIC_PEM" 2>/dev/null
chmod 0600 "$BACKUP_SIGNING_KEY" "$BACKUP_FOREIGN_KEY"
chmod 0644 "$BACKUP_SIGNING_PUBLIC_PEM"
# X25519 keypairs: the raw 32-byte private half feeds the trust document, and
# the public half is the fingerprint the custodian compares in the request.
openssl genpkey -algorithm X25519 -out "$BACKUP_RECIPIENT_PEM" 2>/dev/null
openssl genpkey -algorithm X25519 -out "$BACKUP_SWAPPED_RECIPIENT_PEM" 2>/dev/null
chmod 0600 "$BACKUP_RECIPIENT_PEM" "$BACKUP_SWAPPED_RECIPIENT_PEM"
openssl pkey -in "$BACKUP_RECIPIENT_PEM" -outform DER 2>/dev/null | tail -c 32 >"$BACKUP_RECIPIENT_KEY"
openssl pkey -in "$BACKUP_SWAPPED_RECIPIENT_PEM" -outform DER 2>/dev/null | tail -c 32 >"$SWAPPED_RECIPIENT_KEY"
chmod 0600 "$BACKUP_RECIPIENT_KEY" "$SWAPPED_RECIPIENT_KEY"
BACKUP_RECIPIENT_PUBLIC_HEX="$(openssl pkey -in "$BACKUP_RECIPIENT_PEM" -pubout -outform DER 2>/dev/null | tail -c 32 | xxd -p -c 64)"
SWAPPED_RECIPIENT_PUBLIC_HEX="$(openssl pkey -in "$BACKUP_SWAPPED_RECIPIENT_PEM" -pubout -outform DER 2>/dev/null | tail -c 32 | xxd -p -c 64)"
recipient_fingerprint() { printf '%s' "$1" | xxd -r -p | sha256sum | cut -d' ' -f1; }
BACKUP_RECIPIENT_FP="$(recipient_fingerprint "$BACKUP_RECIPIENT_PUBLIC_HEX")"
SWAPPED_RECIPIENT_FP="$(recipient_fingerprint "$SWAPPED_RECIPIENT_PUBLIC_HEX")"
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

# Bounded reap: never block the harness on a child. The exit marker is written
# by the command wrapper before the child exits, and the loop is capped by a
# deadline, so there is no unbounded `wait`.
wait_bounded() { # wait_bounded <pid> <exit-marker> [timeout-seconds]
    local pid="$1" marker="$2" deadline=$((SECONDS + ${3:-30}))
    while (( SECONDS < deadline )); do
        if [[ -f "$marker" ]] || ! kill -0 "$pid" 2>/dev/null; then
            wait "$pid" 2>/dev/null || true
            return 0
        fi
        sleep 0.05
    done
    return 124
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
write_config() { # write_config <key> <data-dir> [normal|revoked|foreign-identity|alt-release|swapped-recipient] [recipient-key] [recipient-public-hex]
    local key="$1" data_dir="$2" mode="${3:-normal}"
    local recipient="${4:-$BACKUP_RECIPIENT_KEY}"
    local recipient_public="${5:-$BACKUP_RECIPIENT_PUBLIC_HEX}"
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
        "$site" "$installation" "$BACKUP_SIGNING_PUBLIC_HEX" "$recipient" \
        "$recipient_public" "$revoked" "$source_commit" "$SCHEMA_VERSION" <<'PY'
import hashlib, json, sys
(trust_path, manifest_path, site, installation, public, recipient,
 recipient_public, revoked, source_commit, schema) = sys.argv[1:11]
public_bytes = bytes.fromhex(public)
trust = {
    "format": "o3k-backup-trust-v1",
    "site_id": site,
    "installation_id": installation,
    "profile_id": "o3k-demo-v1",
    "artifact_signing": {"key_id": "signing-1", "ed25519_public_key": public},
    "recipient": {
        "key_id": "recovery-1",
        "x25519_private_key_file": recipient,
        "x25519_public_key": recipient_public,
    },
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
backup_pid() { cat "$WORK/$1.backup.pid"; }

# Option A: the capture process holds the store lock and the denial marker
# while it waits for the detached signature, so every flow that needs a
# signature runs `backup create` in the background and the harness acts as the
# offline custodian while it waits.
start_backup() { # start_backup <case-id> <data-dir> <dest-dir> <operation-id> [env KEY=VALUE ...]
    local case_id="$1" data_dir="$2" dest_dir="$3" op="$4"; shift 4
    (
        set +e
        env O3K_DATA_DIR="$data_dir" \
            O3K_BACKUP_TRUST_CONFIG="$CASE_TRUST" \
            O3K_INSTALL_PREFIX="$CASE_PREFIX" \
            "$@" \
            "$O3K_BIN" backup create --destination "$dest_dir" --operation-id "$op" \
            >"$WORK/$case_id.backup.json" 2>"$WORK/$case_id.backup.stderr"
        echo $? >"$WORK/$case_id.backup.exit"
    ) &
    echo $! >"$WORK/$case_id.backup.pid"
}

wait_backup() { # wait_backup <case-id> [timeout-seconds]
    local case_id="$1" deadline=$((SECONDS + ${2:-90})) pid
    pid="$(backup_pid "$case_id")"
    while (( SECONDS < deadline )); do
        if [[ -f "$WORK/$case_id.backup.exit" ]]; then
            wait "$pid" 2>/dev/null || true
            return 0
        fi
        if ! kill -0 "$pid" 2>/dev/null; then
            sleep 0.05
            if [[ -f "$WORK/$case_id.backup.exit" ]]; then
                wait "$pid" 2>/dev/null || true
                return 0
            fi
            return 1
        fi
        sleep 0.05
    done
    kill -9 "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    return 1
}

await_signing_request() { # await_signing_request <dest-dir> <operation-id> [timeout-seconds]
    wait_for_file "$1/.o3k-backup-artifact-$2/signing-request.json" "${3:-60}"
}

await_awaiting_signature_line() { # await_awaiting_signature_line <case-id> <operation-id> [timeout-seconds]
    local case_id="$1" operation_id="$2" deadline=$((SECONDS + ${3:-60}))
    while (( SECONDS < deadline )); do
        grep -qF "o3k backup create: awaiting-signature $operation_id" "$WORK/$case_id.backup.stderr" 2>/dev/null && return 0
        sleep 0.05
    done
    return 1
}

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
    # The executor creates the request before writing it, so poll until it
    # parses instead of failing on a partially written file.
    for _ in $(seq 1 100); do
        if python3 - "$staging/signing-request.json" "$WORK/sign-input.bin" "$WORK/sign-meta.json" <<'PY'
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
        "created_at": request["created_at"],
        "expires_at": request["expires_at"],
        "recipient_public_key_sha256": request["recipient_public_key_sha256"],
    }, handle)
PY
        then
            return 0
        fi
        sleep 0.05
    done
    log "  signing request never parsed"
    return 1
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
    # Write the response to a private temp name in the same directory and
    # rename it into place: the executor polls for `signing-response.json`, so
    # it must never observe a partially written response. (The product also
    # retries an unparsable response until the deadline as a second line of
    # defense.)
    python3 - "$signature" "$meta" "$staging" "$key_id" "$request_sha" <<'PY'
import json, os, sys, tempfile
signature_path, meta_path, staging, key_id, request_sha = sys.argv[1:6]
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
    # The response must be clock-consistent with the request: sign exactly at
    # the request's creation time (the inclusive lower bound).
    "signed_at": meta["created_at"],
}
descriptor, temporary = tempfile.mkstemp(prefix=".signing-response.tmp-", dir=staging)
try:
    with os.fdopen(descriptor, "w") as handle:
        json.dump(response, handle)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, 0o600)
    os.replace(temporary, os.path.join(staging, "signing-response.json"))
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
PY
}

trusted_recipient_fingerprint() { # trusted_recipient_fingerprint <trust-config>
    python3 - "$1" <<'PY'
import hashlib, json, sys
document = json.load(open(sys.argv[1]))
public = document.get("recipient", {}).get("x25519_public_key")
if not public:
    print("")
else:
    print(hashlib.sha256(bytes.fromhex(public)).hexdigest())
PY
}

sign_request() { # sign_request <staging> [signing-key] [trust-config]
    local staging="$1" key="${2:-$BACKUP_SIGNING_KEY}"
    local trust="${3:-${O3K_BACKUP_TRUST_CONFIG:-${CASE_TRUST:-}}}"
    [[ -f "$staging/signing-request.json" ]] || { log "  missing signing request in $staging"; return 1; }
    # Two-of-three custody check, simulated by the harness: the request's
    # recipient fingerprint must equal the trusted trust document's before the
    # helper signs. A request that was altered (or built for another recipient)
    # is refused here, never signed.
    local request_fp trusted_fp=""
    request_fp="$(json_get "$staging/signing-request.json" recipient_public_key_sha256)"
    if [[ -n "$trust" && -f "$trust" ]]; then
        trusted_fp="$(trusted_recipient_fingerprint "$trust")"
    fi
    if [[ -z "$trusted_fp" || "$request_fp" != "$trusted_fp" ]]; then
        log "  custodian refused the request: recipient fingerprint mismatch (request='$request_fp' trusted='$trusted_fp')"
        return 1
    fi
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

# Rebuild an artifact around a mutated manifest and sign it with the harness
# custody key. The mutation runs after the signature field is removed (exactly
# the D1 input the product signs over) and the member blocks are re-attached by
# name, so dropping a member also drops its bytes. Used to prove the
# classification of a *validly signed* artifact, which is the only way to reach
# the checks that run after signature verification.
resign_artifact() { # resign_artifact <source> <destination> <python-statement mutating manifest> [signing-key]
    local source="$1" destination="$2" mutation="$3" key="${4:-$BACKUP_SIGNING_KEY}"
    local stem
    stem="$WORK/resign-$(basename "${destination%.o3k}")"
    python3 - "$source" "$stem-d1.bin" "$stem-manifest.json" "$stem-blocks.bin" "$mutation" <<'PY'
import json, struct, sys
(artifact, d1_out, manifest_out, blocks_out, mutation) = sys.argv[1:6]
raw = open(artifact, "rb").read()
assert raw[:12] == b"O3KPP6BK\x00\x00\x00\x01", "artifact magic"
manifest_len = struct.unpack(">Q", raw[12:20])[0]
manifest_end = 20 + manifest_len
manifest = json.loads(raw[20:manifest_end])
offset = manifest_end
blocks_by_name = {}
for member in manifest["members"]:
    size = struct.unpack(">Q", raw[offset:offset + 8])[0]
    offset += 8
    blocks_by_name[member["name"]] = struct.pack(">Q", size) + raw[offset:offset + size]
    offset += size
assert offset == len(raw), "artifact layout"
manifest["authentication"].pop("signature", None)
exec(mutation)
canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
d1 = b"O3K-PP6-BACKUP-MANIFEST-V1\x00" + struct.pack(">Q", len(canonical)) + canonical
for member in manifest["members"]:
    name = member["name"].encode()
    d1 += struct.pack(">I", len(name)) + name + bytes.fromhex(member["sha256"])
open(d1_out, "wb").write(d1)
open(manifest_out, "w").write(json.dumps(manifest, sort_keys=True, separators=(",", ":")))
open(blocks_out, "wb").write(b"".join(blocks_by_name[m["name"]] for m in manifest["members"]))
PY
    sign_bytes "$key" "$stem-d1.bin" "$stem.sig" || { log "  re-sealing signature failed"; return 1; }
    python3 - "$stem-manifest.json" "$stem.sig" "$stem-blocks.bin" "$destination" <<'PY'
import base64, json, struct, sys
manifest_path, signature_path, blocks_path, artifact_path = sys.argv[1:5]
manifest = json.load(open(manifest_path))
signature = open(signature_path, "rb").read()
assert len(signature) == 64, "signature length"
manifest["authentication"]["signature"] = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
raw = b"O3KPP6BK\x00\x00\x00\x01" + struct.pack(">Q", len(canonical)) + canonical + open(blocks_path, "rb").read()
open(artifact_path, "wb").write(raw)
PY
    chmod 0600 "$destination"
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

settle_checkpoint() { # settle_checkpoint <data-dir>
    # The executor holds the exclusive store lock at the barrier; no process is
    # writing. Applying the remaining WAL frames here makes the measured main
    # database the exact bytes the executor will snapshot.
    if (( HAVE_SQLITE3 )); then
        sqlite3 "$1/o3k.sqlite" 'PRAGMA wal_checkpoint(TRUNCATE);' >/dev/null 2>&1 || true
    fi
}

# Independent verification of the published artifact, not using any product
# verifier code:
#   * parse the frozen artifact layout and re-canonicalize the manifest with a
#     local JCS implementation (checked byte-for-byte against the stored
#     canonical bytes);
#   * rebuild the exact D1 signing input and verify Ed25519 with OpenSSL;
#   * recompute SHA-256 over every member ciphertext+tag;
#   * when python `cryptography` is available, unwrap the HPKE X25519/HKDF-SHA256
#     content key, decrypt every AES-256-GCM member with its manifest AAD, and
#     bind `database/o3k.sqlite` to the signed capture record's snapshot digest,
#     the independently measured source hash, and the source catalog/migration
#     lineage.
independent_artifact_check() { # <artifact> <signing-public-pem> <recipient-key> <source-db>
    local artifact="$1" public_pem="$2" recipient_key="$3" source_db="$4"
    python3 - "$artifact" "$public_pem" "$recipient_key" "$source_db" <<'PY'
import base64
import hashlib
import hmac
import json
import os
import sqlite3
import struct
import subprocess
import sys
import tempfile

artifact, public_pem, recipient_key, source_db = sys.argv[1:5]

def b64d(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

def jcs(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

def sha256_file(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()

raw = open(artifact, "rb").read()
assert raw[:12] == b"O3KPP6BK\x00\x00\x00\x01", "artifact magic"
manifest_len = struct.unpack(">Q", raw[12:20])[0]
manifest_end = 20 + manifest_len
manifest_raw = raw[20:manifest_end]
manifest = json.loads(manifest_raw)
# This both validates our local JCS implementation against serde_jcs for this
# object and proves the bytes inside the artifact are canonical.
assert jcs(manifest) == manifest_raw, "stored manifest is not canonical JCS"

members = manifest["members"]
offset = manifest_end
blocks = []
for member in members:
    size = struct.unpack(">Q", raw[offset:offset + 8])[0]
    offset += 8
    block = raw[offset:offset + size]
    assert len(block) == size, f"truncated member {member['name']}"
    blocks.append(block)
    offset += size
assert offset == len(raw), "artifact has trailing or missing member bytes"

for member, block in zip(members, blocks):
    assert member["encrypted"] is True
    assert member["size_bytes"] == len(block)
    assert member["plaintext_size_bytes"] + 16 == len(block)
    assert hashlib.sha256(block).hexdigest() == member["sha256"], (
        f"independent member digest mismatch: {member['name']}"
    )

signature = b64d(manifest["authentication"]["signature"])
assert len(signature) == 64, "signature is not 64 bytes"
unsigned = json.loads(manifest_raw)
del unsigned["authentication"]["signature"]
canonical = jcs(unsigned)
d1 = b"O3K-PP6-BACKUP-MANIFEST-V1\x00" + struct.pack(">Q", len(canonical)) + canonical
for member in members:
    name = member["name"].encode()
    d1 += struct.pack(">I", len(name)) + name + bytes.fromhex(member["sha256"])

with tempfile.TemporaryDirectory() as tmp:
    d1_path = os.path.join(tmp, "d1.bin")
    sig_path = os.path.join(tmp, "signature.bin")
    with open(d1_path, "wb") as handle:
        handle.write(d1)
    with open(sig_path, "wb") as handle:
        handle.write(signature)
    verified = subprocess.run(
        ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", public_pem,
         "-rawin", "-in", d1_path, "-sigfile", sig_path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    assert verified.returncode == 0, (
        "independent Ed25519 verification failed: "
        + verified.stderr.decode(errors="replace")
    )

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    print(f"independent: signature=ok members={len(members)} decrypt=unavailable")
    raise SystemExit(0)

def i2osp(value, length):
    return value.to_bytes(length, "big")

def hkdf_extract(salt, ikm):
    return hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()

def hkdf_expand(prk, info, length):
    output = b""
    block = b""
    counter = 1
    while len(output) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        output += block
        counter += 1
    return output[:length]

def labeled_extract(suite, salt, label, ikm):
    return hkdf_extract(salt, b"HPKE-v1" + suite + label + ikm)

def labeled_expand(suite, prk, label, info, length):
    return hkdf_expand(
        prk, i2osp(length, 2) + b"HPKE-v1" + suite + label + info, length
    )

recipient_bytes = open(recipient_key, "rb").read()
assert len(recipient_bytes) == 32, "recipient key is not 32 raw bytes"
private = X25519PrivateKey.from_private_bytes(recipient_bytes)
recipient_public = private.public_key().public_bytes_raw()

key_wrapping = manifest["encryption"]["key_wrapping"]
enc = b64d(key_wrapping["enc"])
wrapped_key = b64d(key_wrapping["ciphertext"])
assert len(enc) == 32, "HPKE encapsulated key is not 32 bytes"

kem_suite = b"KEM" + i2osp(0x0020, 2)
hpke_suite = b"HPKE" + i2osp(0x0020, 2) + i2osp(0x0001, 2) + i2osp(0x0002, 2)
shared = private.exchange(X25519PublicKey.from_public_bytes(enc))
kem_context = enc + recipient_public
eae_prk = labeled_extract(kem_suite, b"", b"eae_prk", shared)
shared_secret = labeled_expand(kem_suite, eae_prk, b"shared_secret", kem_context, 32)
psk_id_hash = labeled_extract(hpke_suite, b"", b"psk_id_hash", b"")
info_hash = labeled_extract(hpke_suite, b"", b"info_hash", b"O3K-PP6-ARTIFACT-KEY-WRAP-V1\x00")
schedule_context = b"\x00" + psk_id_hash + info_hash
secret = labeled_extract(hpke_suite, shared_secret, b"secret", b"")
key = labeled_expand(hpke_suite, secret, b"key", schedule_context, 32)
base_nonce = labeled_expand(hpke_suite, secret, b"base_nonce", schedule_context, 12)

wrap_aad = jcs({
    "format_version": manifest["format_version"],
    "profile_id": manifest["source"]["profile_id"],
    "site_id": manifest["site_id"],
    "backup_id": manifest["backup_id"],
    "recipient_key_id": key_wrapping["recipient_key_id"],
})
content_key = AESGCM(key).decrypt(base_nonce, wrapped_key, wrap_aad)
assert len(content_key) == 32, "unwrapped content key is not 32 bytes"

plaintexts = {}
for member, block in zip(members, blocks):
    member_aad = jcs({
        "format_version": manifest["format_version"],
        "profile_id": manifest["source"]["profile_id"],
        "site_id": manifest["site_id"],
        "backup_id": manifest["backup_id"],
        "member_name": member["name"],
        "plaintext_size_bytes": member["plaintext_size_bytes"],
    })
    plaintext = AESGCM(content_key).decrypt(b64d(member["nonce"]), block, member_aad)
    assert len(plaintext) == member["plaintext_size_bytes"]
    plaintexts[member["name"]] = plaintext

capture = json.loads(plaintexts["metadata/capture.json"])
database = plaintexts["database/o3k.sqlite"]
database_sha = hashlib.sha256(database).hexdigest()
assert capture["snapshot_sha256"] == database_sha, "capture snapshot digest mismatch"

source_sha = sha256_file(source_db)
assert capture["source_db_sha256_before"] == source_sha, "source-before digest mismatch"
assert capture["source_db_sha256_after"] == source_sha, "source-after digest mismatch"

def catalog_rows(connection):
    return list(connection.execute(
        "SELECT type, name, tbl_name FROM sqlite_master "
        "WHERE type IN ('table', 'index', 'trigger') "
        "AND name NOT GLOB 'sqlite_*' ORDER BY type, name"
    ))

def migration_rows(connection):
    return list(connection.execute(
        "SELECT version, success, checksum FROM _sqlx_migrations ORDER BY version"
    ))

with tempfile.TemporaryDirectory() as tmp:
    snapshot_path = os.path.join(tmp, "snapshot.sqlite")
    with open(snapshot_path, "wb") as handle:
        handle.write(database)
    os.chmod(snapshot_path, 0o600)
    snapshot = sqlite3.connect(snapshot_path)
    source = sqlite3.connect(f"file:{source_db}?mode=ro", uri=True)
    try:
        assert catalog_rows(snapshot) == catalog_rows(source), (
            "decrypted snapshot catalog differs from the source database"
        )
        assert migration_rows(snapshot) == migration_rows(source), (
            "decrypted snapshot migrations differ from the source database"
        )
        integrity = snapshot.execute("PRAGMA integrity_check").fetchone()[0]
        assert integrity == "ok", f"decrypted snapshot integrity_check: {integrity}"
    finally:
        snapshot.close()
        source.close()

print(
    f"independent: signature=ok members={len(members)} decrypt=verified "
    f"db_sha256={database_sha}"
)
PY
}

sha256_file_or_missing() { [[ -f "$1" ]] && sha256sum "$1" | cut -d' ' -f1 || echo "-"; }

snapshot_tree() { # snapshot_tree <data-dir> <out>
    ( cd "$1" && find . -mindepth 1 -not -type d -printf '%y %P\n' | sort ) >"$2"
}

echo
echo "== Case 1: happy path (capture -> wait for signature -> publish -> verify -> tamper) =="
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
start_backup happy "$CASE_DATA" "$CASE_DEST" "$HAPPY_OP" \
    O3K_BACKUP_TEST_BARRIER_READY_FILE="$HAPPY_READY" \
    O3K_BACKUP_TEST_BARRIER_WAIT_FILE="$HAPPY_GO"
HAPPY_BPID="$(backup_pid happy)"
if ! wait_for_file "$HAPPY_READY" 30; then
    record FAIL case-1 "executor barrier did not become ready"
    exit 1
fi
settle_checkpoint "$CASE_DATA"
HAPPY_BEFORE_DB_SHA="$(sha256_file_or_missing "$CASE_DATA/o3k.sqlite")"
HAPPY_TRUST_BYTES="$(stat -c %s "$CASE_TRUST")"
HAPPY_MANIFEST_BYTES="$(stat -c %s "$CASE_PREFIX/share/o3k/release-manifest.json")"
HAPPY_DB_BYTES="$(stat -c %s "$CASE_DATA/o3k.sqlite")"
HAPPY_WAL_BYTES=0
[[ -f "$CASE_DATA/o3k.sqlite-wal" ]] && HAPPY_WAL_BYTES="$(stat -c %s "$CASE_DATA/o3k.sqlite-wal")"
# D9 source = checkpointed main DB + any remaining non-empty -wal sidecar + the
# two metadata members + the bounded capture/request metadata allowance. The
# harness truncating checkpoint above normally leaves the -wal absent or
# zero-length, so HAPPY_WAL_BYTES is normally 0; it is included in the expected
# sum so a non-empty sidecar is measured exactly the same way the product's
# `source_paths` measurement counts it.
HAPPY_EXPECTED_SOURCE=$((HAPPY_DB_BYTES + HAPPY_WAL_BYTES + HAPPY_TRUST_BYTES + HAPPY_MANIFEST_BYTES + 2 * 1024 * 1024))
snapshot_tree "$CASE_DATA" "$WORK/happy-before-tree.txt"
touch "$HAPPY_GO"

STAGING="$CASE_DEST/.o3k-backup-artifact-$HAPPY_OP"
C1_OK=1; CHECK_OK=1
if ! await_signing_request "$CASE_DEST" "$HAPPY_OP" 90; then
    CHECK_OK=0; log "  signing request never appeared"
fi
# Option A exclusion: while this process waits for the signature it still owns
# the store lock and the denial marker, and nothing is published.
check "$(journal_phase "$CASE_DATA" "$HAPPY_OP")" "staged" "journal phase during the wait"
check "$(marker_count "$CASE_DATA")" "1" "marker present during the wait"
check "$(lock_owner "$CASE_DATA")" "held" "store lock held during the wait"
check "$(is_published "$CASE_DEST" "$HAPPY_OP")" "no" "nothing published during the wait"
await_awaiting_signature_line happy "$HAPPY_OP" 30 || { CHECK_OK=0; log "  missing stable awaiting-signature stderr line"; }
C1_REQUEST_FP="$(json_get "$STAGING/signing-request.json" recipient_public_key_sha256)"
check "$C1_REQUEST_FP" "$BACKUP_RECIPIENT_FP" "signing request recipient public-key fingerprint"
(( CHECK_OK )) || C1_OK=0
if (( C1_OK )); then
    record PASS case-1a "wait" "staged" "1" "held" "no" "-" \
        "capture staged; the same process held the store lock and the denial marker while waiting for the detached signature (awaiting-signature line emitted)"
else
    record FAIL case-1a "wait?" "staged?" "$(marker_count "$CASE_DATA")" "$(lock_owner "$CASE_DATA")" "?" "-" "Option A wait contract failed"
fi

# Permissions (case 8 part 1) while staging exists.
C8_OK=1; CHECK_OK=1
check "$(stat -c %a "$STAGING")" "700" "staging directory mode"
while read -r mode path; do
    [[ "$mode" == "600" ]] || { CHECK_OK=0; log "  staged file mode $mode: $path"; }
done < <(find "$STAGING" -type f -printf '%m %p\n')
check "$(stat -c %a "$CASE_TRUST")" "600" "trust config mode"
check "$(stat -c %a "$BACKUP_SIGNING_KEY")" "600" "signing key mode"
check "$(stat -c %a "$BACKUP_RECIPIENT_KEY")" "600" "recipient key mode"
(( CHECK_OK )) || C8_OK=0

# The offline custodian signs; the waiting process verifies and publishes.
sign_request "$STAGING" || C1_OK=0
if ! wait_bounded "$HAPPY_BPID" "$WORK/happy.backup.exit" 90; then
    C1_OK=0
    log "  executor did not finish the signing wait within 90s"
    kill -9 "$HAPPY_BPID" 2>/dev/null || true
fi
wait_backup happy 5 || { C1_OK=0; log "  executor exit status was not recorded"; }
HAPPY_DAEMON_PID="$(daemon_pid happy)"
reap_exit "$HAPPY_DAEMON_PID" 30 || true

CHECK_OK=1
check "$(backup_exit happy)" "0" "phase-1 publication exit"
check "$(backup_status happy)" "backup-published" "phase-1 publication status"
check "$(journal_phase "$CASE_DATA" "$HAPPY_OP")" "published" "journal phase after publication"
check "$(marker_count "$CASE_DATA")" "0" "marker removed after publication"
check "$(is_published "$CASE_DEST" "$HAPPY_OP")" "yes" "artifact published"
check "$(lock_owner "$CASE_DATA")" "free" "lock released after publication"
[[ ! -e "$STAGING" ]] || { CHECK_OK=0; log "  staging still present after publication"; }
(( CHECK_OK )) || C1_OK=0

# D9 reservation (case 10) from the same run.
C10_OK=1; CHECK_OK=1
PHASE1_SOURCE_BYTES="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["source_bytes"])' "$WORK/happy.backup.json")"
PHASE1_RESERVED_BYTES="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["reserved_bytes"])' "$WORK/happy.backup.json")"
EXPECTED_R="$(python3 -c "s=$HAPPY_EXPECTED_SOURCE; print(max(2*s + 1024**3, 6*1024**3))")"
check "$PHASE1_SOURCE_BYTES" "$HAPPY_EXPECTED_SOURCE" "D9 source_bytes measurement"
check "$PHASE1_RESERVED_BYTES" "$EXPECTED_R" "D9 reservation formula"
if (( PHASE1_RESERVED_BYTES > 9 * 1024 * 1024 * 1024 )); then CHECK_OK=0; log "  D9 reservation exceeds the 9 GiB cap"; fi
(( CHECK_OK )) || C10_OK=0
if (( C10_OK )); then
    record PASS case-10 "0" "published" "0" "free" "yes" "-" \
        "D9: source_bytes=$PHASE1_SOURCE_BYTES (db + wal($HAPPY_WAL_BYTES) + trust + manifest + 2 MiB metadata bound) reserved_bytes=$PHASE1_RESERVED_BYTES = max(2S+1GiB,6GiB), no truncation"
else
    record FAIL case-10 "0" "published" "0" "free" "yes" "-" \
        "D9 mismatch: source=$PHASE1_SOURCE_BYTES reserved=$PHASE1_RESERVED_BYTES expected_S=$HAPPY_EXPECTED_SOURCE expected_R=$EXPECTED_R"
fi

HAPPY_ARTIFACT="$(published_path "$CASE_DEST" "$HAPPY_OP")"
HAPPY_ARTIFACT_SHA="$(artifact_sha "$CASE_DEST" "$HAPPY_OP")"
PHASE1_SHA_JSON="$(json_get "$WORK/happy.backup.json" sha256)"
check "$PHASE1_SHA_JSON" "$HAPPY_ARTIFACT_SHA" "published JSON digest equals artifact digest"
[[ "$(json_get "$WORK/happy.backup.json" signature)" == "verified" ]] || { CHECK_OK=0; log "  signature not reported verified"; }

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
    record PASS case-1b "$(backup_exit happy)" "published" "0" "free" "yes" "verified(exit=0)" \
        "offline detached signature verified in the waiting process; published $HAPPY_ARTIFACT_SHA; verify exit 0 release_match"
else
    record FAIL case-1b "$(backup_exit happy 2>/dev/null || echo '?')" "$(journal_phase "$CASE_DATA" "$HAPPY_OP")" \
        "$(marker_count "$CASE_DATA")" "$(lock_owner "$CASE_DATA")" "$(is_published "$CASE_DEST" "$HAPPY_OP")" \
        "verify_exit=$(verify_exit case-1 2>/dev/null || echo '?')" "publication/verify contract failed"
fi

# Independent verification, using no product verifier code: local JCS (checked
# against the stored canonical bytes), the exact D1 input, OpenSSL Ed25519,
# recomputed member digests, and HPKE/AES-GCM decryption bound to the signed
# capture record and the harness-measured source database.
if [[ "$HAVE_PY_CRYPTO" == "1" ]]; then C1_INDEP_DECRYPT="verified"; else C1_INDEP_DECRYPT="unavailable"; fi
CHECK_OK=1
if independent_artifact_check "$HAPPY_ARTIFACT" "$BACKUP_SIGNING_PUBLIC_PEM" \
    "$BACKUP_RECIPIENT_KEY" "$HAPPY_DATA/o3k.sqlite" \
    >"$WORK/case-1-independent.txt" 2>"$WORK/case-1-independent.err"; then
    C1_INDEP_DETAIL="$(cat "$WORK/case-1-independent.txt")"
    grep -q 'signature=ok' "$WORK/case-1-independent.txt" || CHECK_OK=0
    grep -q "decrypt=$C1_INDEP_DECRYPT" "$WORK/case-1-independent.txt" || CHECK_OK=0
else
    CHECK_OK=0
    C1_INDEP_DETAIL="$(tail -3 "$WORK/case-1-independent.err" | tr '\n' ' ')"
fi
(( CHECK_OK )) || log "  independent artifact verification failed: $C1_INDEP_DETAIL"
# The signature/D1/member-digest legs are always executed; the decryption leg
# is a separate row so an unavailable `cryptography` module can never turn into
# an implied decrypt PASS.
if (( CHECK_OK )); then
    record PASS case-1d "0" "published" "0" "free" "yes" "independent-signature+d1+members" \
        "$C1_INDEP_DETAIL"
    if [[ "$HAVE_PY_CRYPTO" == "1" ]]; then
        record PASS case-1d-decrypt "0" "published" "0" "free" "yes" "independent-hpke+aes-gcm-decrypt" \
            "$C1_INDEP_DETAIL"
    else
        record NOT-COVERED case-1d-decrypt "-" "published" "0" "free" "yes" "cryptography-unavailable" \
            "python cryptography is unavailable, so the independent HPKE/AES-256-GCM decryption and the capture-record/source-database binding were not executed; the signature, D1 and member-digest legs PASS in case-1d"
    fi
else
    record FAIL case-1d "0" "published" "0" "free" "yes" "independent-check-failed" \
        "$C1_INDEP_DETAIL"
fi

TAMPERED="$WORK/happy-tampered.o3k"
cp "$HAPPY_ARTIFACT" "$TAMPERED"
chmod 0600 "$TAMPERED"
python3 - "$TAMPERED" <<'PY'
import struct, sys
path = sys.argv[1]
raw = bytearray(open(path, "rb").read())
manifest_length = struct.unpack(">Q", raw[12:20])[0]
# First member block: 8-byte ciphertext length, then ciphertext+tag. Flip a
# byte inside the ciphertext body (not the trailing tag) so both AEAD and the
# independent digest must notice it.
ciphertext_body = 20 + manifest_length + 8
assert ciphertext_body + 8 < len(raw), "artifact is too small to tamper"
raw[ciphertext_body + 8] ^= 0x01
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
        "single-byte ciphertext-body flip rejected as corrupt-artifact; published artifact untouched"
else
    record FAIL case-1c "$C1_TAMPER_EXIT" "published" "0" "free" "yes" "$C1_TAMPER_REASON" "tamper rejection failed"
fi

# The independent member-digest check must also flag the same flipped byte.
CHECK_OK=1
if independent_artifact_check "$TAMPERED" "$BACKUP_SIGNING_PUBLIC_PEM" \
    "$BACKUP_RECIPIENT_KEY" "$HAPPY_DATA/o3k.sqlite" \
    >"$WORK/case-1-tamper-independent.txt" 2>"$WORK/case-1-tamper-independent.err"; then
    CHECK_OK=0
    log "  independent check accepted the tampered artifact"
fi
if (( CHECK_OK )); then
    record PASS case-1e "$C1_TAMPER_EXIT" "published" "0" "free" "yes" "independent-digest-mismatch" \
        "the independent member SHA-256 recomputation also rejects the flipped ciphertext byte"
else
    record FAIL case-1e "$C1_TAMPER_EXIT" "published" "0" "free" "yes" "-" \
        "independent digest check did not flag the tampered artifact"
fi

# ---------------------------------------------------------------------------
# Case 2: crash during the signing wait -> replay resumes without recapture
# ---------------------------------------------------------------------------
echo
echo "== Case 2: crash during the signing wait =="
fresh_case_dirs idem
IDEM_OP="$(new_op_id)"
start_daemon idem "$CASE_DATA"
if wait_ready idem 30; then
    # Hook 91 dies inside the wait, with the lock and marker held: exactly the
    # state a SIGKILL during the signing window leaves.
    start_backup idem "$CASE_DATA" "$CASE_DEST" "$IDEM_OP" O3K_BACKUP_TEST_EXIT_AWAITING_SIGNATURE=1
    IDEM_STAGING="$CASE_DEST/.o3k-backup-artifact-$IDEM_OP"
    await_signing_request "$CASE_DEST" "$IDEM_OP" 60 || true
    wait_backup idem 60 || true
    reap_exit "$(daemon_pid idem)" 30 || true
    IDEM_MEMBERS_BEFORE="$(find "$IDEM_STAGING" -maxdepth 1 -name 'members-*' | wc -l)"
    IDEM_REQUEST_BEFORE="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["request_sha256"])' "$CASE_DATA/backup-operations/$IDEM_OP.json")"
    CHECK_OK=1
    check "$(backup_exit idem)" "91" "hook exit"
    check "$(journal_phase "$CASE_DATA" "$IDEM_OP")" "staged" "journal survives the crash"
    check "$(marker_count "$CASE_DATA")" "1" "marker retained by the crash"
    check "$(lock_owner "$CASE_DATA")" "free" "kernel released the lock when the process died"
    check "$(is_published "$CASE_DEST" "$IDEM_OP")" "no" "nothing published"
    # A replacement controller must be DENIED while the marker exists.
    set +e
    env O3K_BOOTSTRAP_PASSWORD="$BOOTSTRAP_PASSWORD" O3K_TOKEN_SIGNING_KEY="$TOKEN_SIGNING_KEY" \
        O3K_NATIVE_CURSOR_HMAC_KEY="$NATIVE_CURSOR_KEY" \
        timeout 30 "$O3KD_BIN" --listen-addr "127.0.0.1:$(free_port)" --data-dir "$CASE_DATA" \
        --log-filter info --log-format json >"$WORK/case-2-restart.log" 2>&1
    IDEM_RESTART_STATUS=$?
    set -e
    check "$IDEM_RESTART_STATUS" "1" "restart after crash-during-wait refused"
    grep -q 'interrupted backup marker(s) present' "$WORK/case-2-restart.log" || { CHECK_OK=0; log "  restart did not report the interrupted marker"; }
    check "$(marker_count "$CASE_DATA")" "1" "marker still denies after the refused restart"
    # The re-run resumes the wait; the custodian signs while it waits.
    start_backup idem-resume "$CASE_DATA" "$CASE_DEST" "$IDEM_OP"
    await_signing_request "$CASE_DEST" "$IDEM_OP" 60 || CHECK_OK=0
    check "$(lock_owner "$CASE_DATA")" "held" "re-run holds the store lock while waiting"
    sign_request "$IDEM_STAGING" || CHECK_OK=0
    wait_backup idem-resume 90 || CHECK_OK=0
    check "$(backup_exit idem-resume)" "0" "resume exit"
    check "$(journal_phase "$CASE_DATA" "$IDEM_OP")" "published" "journal after resume"
    check "$(marker_count "$CASE_DATA")" "0" "marker removed after publication"
    check "$(is_published "$CASE_DEST" "$IDEM_OP")" "yes" "artifact published by the resume"
    check "$(find "$IDEM_STAGING" -maxdepth 1 -name 'members-*' 2>/dev/null | wc -l)" "0" "staging removed"
    # No recapture: the same request digest and the same staged artifact were
    # used (the artifact.unsigned digest is compared before publication).
    check "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["request_sha256"])' "$CASE_DATA/backup-operations/$IDEM_OP.json")" \
        "$IDEM_REQUEST_BEFORE" "journal request digest preserved (no recapture)"
    check "$IDEM_MEMBERS_BEFORE" "1" "single capture before the crash"
    start_daemon idem-after "$CASE_DATA"
    if wait_ready idem-after 30; then
        sigterm_expect_zero idem-after || CHECK_OK=0
    else
        CHECK_OK=0; log "  controller could not start after publication"
    fi
    if (( CHECK_OK )); then
        record PASS case-2 "$(backup_exit idem)" "published" "0" "free" "yes" "published(exit=0)" \
            "crash during the wait (hook 91) left the marker and the staged journal; the replacement controller was DENIED, the same command resumed the wait and published without recapture, then the controller started and exited 0 on SIGTERM"
    else
        record FAIL case-2 "$(backup_exit idem 2>/dev/null || echo '?')" "$(journal_phase "$CASE_DATA" "$IDEM_OP")" \
            "$(marker_count "$CASE_DATA")" "$(lock_owner "$CASE_DATA")" "$(is_published "$CASE_DEST" "$IDEM_OP")" \
            "-" "crash-during-wait resume contract failed"
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
check "$(backup_exit happy-duplicate)" "0" "published replay exit"
check "$(backup_status happy-duplicate)" "backup-published" "published replay status"
check "$(json_get "$WORK/happy-duplicate.backup.json" sha256)" "$HAPPY_ARTIFACT_SHA" "published replay digest"
check "$(journal_phase "$HAPPY_DATA" "$HAPPY_OP")" "published" "journal remains published"
check "$(is_published "$HAPPY_DEST" "$HAPPY_OP")" "yes" "exactly one published artifact"
check "$(find "$HAPPY_DEST" -maxdepth 1 -name "backup-$HAPPY_OP.o3k" | wc -l)" "1" "artifact count"
(( CHECK_OK )) && C3_OK=1 || C3_OK=0
if (( C3_OK )); then
    record PASS case-3 "$(backup_exit happy-duplicate)" "published" "0" "$(lock_owner "$HAPPY_DATA")" "yes" "-" \
        "published replay re-verified the destination and exited 0 idempotently; no second capture"
else
    record FAIL case-3 "$(backup_exit happy-duplicate)" "published" "0" "$(lock_owner "$HAPPY_DATA")" "yes" "-" \
        "idempotent published-replay contract failed"
fi

# ---------------------------------------------------------------------------
# Case 4: signature rejection matrix
# ---------------------------------------------------------------------------
echo
echo "== Case 4: signature rejection matrix =="
reject_case() { # reject_case <suffix> <mutation> <expected-exit> <expected-reason> [kept|aborted]
    local suffix="$1" mutation="$2" expected_exit="$3" expected_reason="$4"
    local staging_expectation="${5:-kept}"
    local key="sig-$suffix"
    fresh_case_dirs "$key"
    local op; op="$(new_op_id)"
    start_daemon "$key" "$CASE_DATA"
    if ! wait_ready "$key" 30; then
        record FAIL "case-4$suffix" "-" "-" "-" "-" "-" "-" "daemon not ready"
        return
    fi
    # The rejection is observed by the waiting process itself (Option A).
    if [[ "$mutation" == "expired-request" ]]; then
        start_backup "$key" "$CASE_DATA" "$CASE_DEST" "$op" O3K_BACKUP_TEST_AWAIT_TIMEOUT_SECONDS=1
    else
        start_backup "$key" "$CASE_DATA" "$CASE_DEST" "$op"
    fi
    local staging="$CASE_DEST/.o3k-backup-artifact-$op"
    local mutation_ok=1
    await_signing_request "$CASE_DEST" "$op" 90 || { mutation_ok=0; log "  signing request never appeared"; }
    if (( mutation_ok )); then
        case "$mutation" in
            wrong-signature)
                decode_signing_input "$staging"
                sign_bytes "$BACKUP_FOREIGN_KEY" "$WORK/sign-input.bin" "$WORK/sign-input.sig"
                write_response_file "$staging" "$WORK/sign-input.sig" "$WORK/sign-meta.json"
                ;;
            wrong-key-id)
                # Build the mutated response out of tree and move it in
                # atomically: the executor polls for the file, so it must never
                # observe the valid response between the two writes.
                mkdir -p "$WORK/response-staging"
                decode_signing_input "$staging"
                sign_bytes "$BACKUP_SIGNING_KEY" "$WORK/sign-input.bin" "$WORK/sign-input.sig"
                write_response_file "$WORK/response-staging" "$WORK/sign-input.sig" "$WORK/sign-meta.json"
                mutate_response "$WORK/response-staging" 'response["key_id"] = "signing-2"'
                mv "$WORK/response-staging/signing-response.json" "$staging/signing-response.json"
                ;;
            short-signature)
                mkdir -p "$WORK/response-staging"
                decode_signing_input "$staging"
                sign_bytes "$BACKUP_SIGNING_KEY" "$WORK/sign-input.bin" "$WORK/sign-input.sig"
                write_response_file "$WORK/response-staging" "$WORK/sign-input.sig" "$WORK/sign-meta.json"
                mutate_response "$WORK/response-staging" 'response["signature"] = response["signature"][:32]'
                mv "$WORK/response-staging/signing-response.json" "$staging/signing-response.json"
                ;;
            request-digest)
                mkdir -p "$WORK/response-staging"
                decode_signing_input "$staging"
                sign_bytes "$BACKUP_SIGNING_KEY" "$WORK/sign-input.bin" "$WORK/sign-input.sig"
                write_response_file "$WORK/response-staging" "$WORK/sign-input.sig" "$WORK/sign-meta.json"
                mutate_response "$WORK/response-staging" 'response["request_sha256"] = "e" * 64'
                mv "$WORK/response-staging/signing-response.json" "$staging/signing-response.json"
                ;;
            expired-request)
                # No response: the bounded wait expires and the executor must
                # perform the safe abort.
                ;;
            *) mutation_ok=0 ;;
        esac
    fi
    wait_backup "$key" 90 || { mutation_ok=0; log "  executor did not return"; }
    reap_exit "$(daemon_pid "$key")" 30 || true
    if (( mutation_ok )); then
        CHECK_OK=1
        check "$(backup_exit "$key")" "$expected_exit" "rejection exit"
        check "$(backup_reason "$key")" "$expected_reason" "rejection reason"
        check "$(is_published "$CASE_DEST" "$op")" "no" "nothing published"
        if [[ "$staging_expectation" == "aborted" ]]; then
            check "$(journal_phase "$CASE_DATA" "$op")" "aborted" "journal aborted by the safe abort"
            [[ ! -e "$staging" ]] || { CHECK_OK=0; log "  staging retained after the safe abort"; }
            check "$(marker_count "$CASE_DATA")" "0" "marker removed by the safe abort"
        else
            check "$(journal_phase "$CASE_DATA" "$op")" "staged" "journal remains staged"
            [[ -d "$staging" ]] || { CHECK_OK=0; log "  staging removed on rejection"; }
            check "$(marker_count "$CASE_DATA")" "1" "marker retained while publication is pending"
        fi
        check "$(lock_owner "$CASE_DATA")" "free" "lock owner"
    else
        CHECK_OK=0
    fi
    if (( CHECK_OK )); then
        local staging_detail="staging preserved, marker retained"
        [[ "$staging_expectation" == "aborted" ]] && staging_detail="safe abort removed staging and marker"
        local journal_phase_now
        journal_phase_now="$(journal_phase "$CASE_DATA" "$op")"
        local marker_now
        marker_now="$(marker_count "$CASE_DATA")"
        record PASS "case-4$suffix" "$(backup_exit "$key" 2>/dev/null || echo '?')" "$journal_phase_now" "$marker_now" "free" "no" \
            "$expected_reason(exit=$expected_exit)" "$mutation rejected; $staging_detail, nothing published"
    else
        record FAIL "case-4$suffix" "$(backup_exit "$key" 2>/dev/null || echo '?')" \
            "$(journal_phase "$CASE_DATA" "$op")" "$(marker_count "$CASE_DATA")" "$(lock_owner "$CASE_DATA")" \
            "$(is_published "$CASE_DEST" "$op")" "$(backup_reason "$key" 2>/dev/null || echo '?')" \
            "$mutation rejection failed"
    fi
}
reject_case a wrong-signature 2 signature-invalid
reject_case b wrong-key-id 2 signing-response-mismatch
reject_case c short-signature 2 signing-response-invalid
reject_case d request-digest 2 signing-response-mismatch
reject_case e expired-request 3 signing-request-expired aborted

# ---------------------------------------------------------------------------
# Case 14 (security review F1): a forged `publishing` journal must never
# authorise publication. The journal points at arbitrary unsigned bytes whose
# digest matches the record; the replay must still verify the signed artifact
# from scratch and refuse.
# ---------------------------------------------------------------------------
echo
echo "== Case 14: forged publishing journal cannot publish unsigned bytes =="
fresh_case_dirs forged-publishing
C14_OP="$(new_op_id)"
start_daemon forged-publishing "$CASE_DATA"
if wait_ready forged-publishing 30; then
    start_backup forged-publishing "$CASE_DATA" "$CASE_DEST" "$C14_OP" O3K_BACKUP_TEST_EXIT_AWAITING_SIGNATURE=1
    await_signing_request "$CASE_DEST" "$C14_OP" 60 || true
    wait_backup forged-publishing 60 || true
    reap_exit "$(daemon_pid forged-publishing)" 30 || true
    C14_STAGING="$CASE_DEST/.o3k-backup-artifact-$C14_OP"
    C14_MEMBERS="$(find "$C14_STAGING" -mindepth 1 -maxdepth 1 -type d -name 'members-*' | head -1)"
    if [[ -n "$C14_MEMBERS" && -f "$C14_MEMBERS/artifact.unsigned" ]]; then
        mv "$C14_MEMBERS/artifact.unsigned" "$C14_MEMBERS/artifact.partial"
    fi
    C14_SHA="$(sha256sum "$C14_MEMBERS/artifact.partial" 2>/dev/null | cut -d' ' -f1)"
    python3 - "$CASE_DATA/backup-operations/$C14_OP.json" "$C14_SHA" <<'PY'
import json, sys
path, digest = sys.argv[1:3]
journal = json.load(open(path))
journal["phase"] = "publishing"
journal["artifact_sha256"] = digest
json.dump(journal, open(path, "w"))
PY
    run_backup forged-publishing-replay "$CASE_DATA" "$CASE_DEST" "$C14_OP"
    CHECK_OK=1
    check "$(backup_exit forged-publishing-replay)" "2" "forged replay exit"
    check "$(backup_reason forged-publishing-replay)" "staged-artifact-invalid" "forged replay reason"
    check "$(is_published "$CASE_DEST" "$C14_OP")" "no" "forged replay published nothing"
    check "$(journal_phase "$CASE_DATA" "$C14_OP")" "publishing" "journal remains publishing"
    if (( CHECK_OK )); then
        record PASS case-14 "$(backup_exit forged-publishing-replay)" "publishing" "$(marker_count "$CASE_DATA")" "free" "no" \
            "staged-artifact-invalid(exit=2)" \
            "forged publishing journal with matching digest of unsigned bytes was re-verified and rejected; nothing published"
    else
        record FAIL case-14 "$(backup_exit forged-publishing-replay 2>/dev/null || echo '?')" \
            "$(journal_phase "$CASE_DATA" "$C14_OP")" "$(marker_count "$CASE_DATA")" "$(lock_owner "$CASE_DATA")" \
            "$(is_published "$CASE_DEST" "$C14_OP")" "$(backup_reason forged-publishing-replay 2>/dev/null || echo '?')" \
            "forged publishing replay was not rejected"
    fi
else
    record FAIL case-14 "-" "-" "-" "-" "-" "-" "daemon not ready"
fi

# ---------------------------------------------------------------------------
# Case 15 (security review F3): journal backup_id path traversal
# ---------------------------------------------------------------------------
echo
echo "== Case 15: forged journal backup_id cannot escape the destination =="
fresh_case_dirs forged-journal
C15_OP="$(new_op_id)"
start_daemon forged-journal "$CASE_DATA"
if wait_ready forged-journal 30; then
    start_backup forged-journal "$CASE_DATA" "$CASE_DEST" "$C15_OP" O3K_BACKUP_TEST_EXIT_AWAITING_SIGNATURE=1
    await_signing_request "$CASE_DEST" "$C15_OP" 60 || true
    wait_backup forged-journal 60 || true
    reap_exit "$(daemon_pid forged-journal)" 30 || true
    python3 - "$CASE_DATA/backup-operations/$C15_OP.json" <<'PY'
import json, sys
path = sys.argv[1]
journal = json.load(open(path))
journal["backup_id"] = "x/../../escaped"
json.dump(journal, open(path, "w"))
PY
    run_backup forged-journal-retry "$CASE_DATA" "$CASE_DEST" "$C15_OP"
    CHECK_OK=1
    check "$(backup_exit forged-journal-retry)" "2" "forged journal exit"
    check "$(backup_reason forged-journal-retry)" "backup-operation-journal-invalid" "forged journal reason"
    check "$(is_published "$CASE_DEST" "$C15_OP")" "no" "forged journal published nothing"
    check "$(find "$WORK" -maxdepth 3 -name '*escaped*' | wc -l)" "0" "no escaped path was created"
    if (( CHECK_OK )); then
        record PASS case-15 "$(backup_exit forged-journal-retry)" "staged" "$(marker_count "$CASE_DATA")" "free" "no" \
            "backup-operation-journal-invalid(exit=2)" \
            "backup_id=x/../../escaped is rejected by the journal identifier grammar; nothing written outside the destination"
    else
        record FAIL case-15 "$(backup_exit forged-journal-retry 2>/dev/null || echo '?')" \
            "$(journal_phase "$CASE_DATA" "$C15_OP")" "$(marker_count "$CASE_DATA")" "$(lock_owner "$CASE_DATA")" \
            "$(is_published "$CASE_DEST" "$C15_OP")" "$(backup_reason forged-journal-retry 2>/dev/null || echo '?')" \
            "forged backup_id traversal was not rejected"
    fi
else
    record FAIL case-15 "-" "-" "-" "-" "-" "-" "daemon not ready"
fi

# ---------------------------------------------------------------------------
# Case 16 (security review F4): a symlinked staged artifact is never published
# ---------------------------------------------------------------------------
echo
echo "== Case 16: symlinked staged artifact is rejected =="
fresh_case_dirs symlink-staged
C16_OP="$(new_op_id)"
start_daemon symlink-staged "$CASE_DATA"
if wait_ready symlink-staged 30; then
    start_backup symlink-staged "$CASE_DATA" "$CASE_DEST" "$C16_OP" O3K_BACKUP_TEST_EXIT_AWAITING_SIGNATURE=1
    await_signing_request "$CASE_DEST" "$C16_OP" 60 || true
    wait_backup symlink-staged 60 || true
    reap_exit "$(daemon_pid symlink-staged)" 30 || true
    C16_STAGING="$CASE_DEST/.o3k-backup-artifact-$C16_OP"
    C16_MEMBERS="$(find "$C16_STAGING" -mindepth 1 -maxdepth 1 -type d -name 'members-*' | head -1)"
    ln -s "$C16_MEMBERS/artifact.unsigned" "$C16_MEMBERS/artifact.partial"
    run_backup symlink-staged-replay "$CASE_DATA" "$CASE_DEST" "$C16_OP"
    CHECK_OK=1
    check "$(backup_exit symlink-staged-replay)" "2" "symlinked staging exit"
    check "$(backup_reason symlink-staged-replay)" "staged-artifact-invalid" "symlinked staging reason"
    check "$(is_published "$CASE_DEST" "$C16_OP")" "no" "symlinked staging published nothing"
    [[ -L "$C16_MEMBERS/artifact.partial" ]] || { CHECK_OK=0; log "  symlink fixture was altered"; }
    if (( CHECK_OK )); then
        record PASS case-16 "$(backup_exit symlink-staged-replay)" "staged" "$(marker_count "$CASE_DATA")" "free" "no" \
            "staged-artifact-invalid(exit=2)" \
            "O_NOFOLLOW/fstat rejects a symlinked artifact.partial even when its target content matches; nothing published"
    else
        record FAIL case-16 "$(backup_exit symlink-staged-replay 2>/dev/null || echo '?')" \
            "$(journal_phase "$CASE_DATA" "$C16_OP")" "$(marker_count "$CASE_DATA")" "$(lock_owner "$CASE_DATA")" \
            "$(is_published "$CASE_DEST" "$C16_OP")" "$(backup_reason symlink-staged-replay 2>/dev/null || echo '?')" \
            "symlinked staged artifact was not rejected"
    fi
else
    record FAIL case-16 "-" "-" "-" "-" "-" "-" "daemon not ready"
fi

# ---------------------------------------------------------------------------
# Case 17 (security review F7/F8/F17b): recipient substitution is visible in
# the signing request and rejected by phase 2 and the verifier.
# ---------------------------------------------------------------------------
echo
echo "== Case 17: recipient key substitution =="
fresh_case_dirs recipient-substitution
C17_OP="$(new_op_id)"
start_daemon recipient-substitution "$CASE_DATA"
if wait_ready recipient-substitution 30; then
    start_backup recipient-substitution "$CASE_DATA" "$CASE_DEST" "$C17_OP" O3K_BACKUP_TEST_EXIT_AWAITING_SIGNATURE=1
    await_signing_request "$CASE_DEST" "$C17_OP" 60 || true
    wait_backup recipient-substitution 60 || true
    reap_exit "$(daemon_pid recipient-substitution)" 30 || true
    C17_STAGING="$CASE_DEST/.o3k-backup-artifact-$C17_OP"
    C17_REQUEST_FP="$(json_get "$C17_STAGING/signing-request.json" recipient_public_key_sha256)"
    C17_TRUST="$CASE_TRUST"; C17_PREFIX="$CASE_PREFIX"
    SWAPPED_TRUST="$(write_config recipient-substitution "$CASE_DATA" swapped-recipient "$SWAPPED_RECIPIENT_KEY" "$SWAPPED_RECIPIENT_PUBLIC_HEX")"
    SWAPPED_PREFIX="$WORK/cfg-recipient-substitution-swapped-recipient/install"
    CASE_TRUST="$SWAPPED_TRUST"; CASE_PREFIX="$SWAPPED_PREFIX"
    run_backup recipient-substitution-swapped "$CASE_DATA" "$CASE_DEST" "$C17_OP"
    CASE_TRUST="$C17_TRUST"; CASE_PREFIX="$C17_PREFIX"
    CHECK_OK=1
    check_nonempty "$C17_REQUEST_FP" "request recipient fingerprint"
    check "$C17_REQUEST_FP" "$BACKUP_RECIPIENT_FP" "request exposes the configured recipient fingerprint"
    check "$(backup_exit recipient-substitution-swapped)" "2" "swapped recipient phase-2 exit"
    check "$(backup_reason recipient-substitution-swapped)" "signing-request-mismatch" "swapped recipient phase-2 reason"
    check "$(is_published "$CASE_DEST" "$C17_OP")" "no" "swapped recipient published nothing"
    check "$(marker_count "$CASE_DATA")" "1" "marker retained while publication is pending"
    sign_request "$C17_STAGING" || CHECK_OK=0
    start_backup recipient-substitution-complete "$CASE_DATA" "$CASE_DEST" "$C17_OP"
    wait_backup recipient-substitution-complete 90 || CHECK_OK=0
    check "$(backup_exit recipient-substitution-complete)" "0" "original recipient publishes"
    check "$(marker_count "$CASE_DATA")" "0" "marker removed after publication"
    run_verify recipient-substitution-swapped-verify "$CASE_DATA" "$SWAPPED_TRUST" "$SWAPPED_PREFIX" \
        "$(published_path "$CASE_DEST" "$C17_OP")"
    check "$(verify_exit recipient-substitution-swapped-verify)" "2" "swapped recipient verify exit"
    check "$(verify_reason recipient-substitution-swapped-verify)" "recipient-key-mismatch" "swapped recipient verify reason"
    if (( CHECK_OK )); then
        record PASS case-17 "$(backup_exit recipient-substitution-swapped)" "published" "0" "free" \
            "yes" "recipient-key-mismatch(exit=2)" \
            "request exposes recipient fingerprint $C17_REQUEST_FP; swapped recipient trust document is rejected by phase 2 and by verify, original recipient publishes and verifies"
    else
        record FAIL case-17 "$(backup_exit recipient-substitution-swapped 2>/dev/null || echo '?')" \
            "$(journal_phase "$CASE_DATA" "$C17_OP")" "$(marker_count "$CASE_DATA")" "$(lock_owner "$CASE_DATA")" \
            "$(is_published "$CASE_DEST" "$C17_OP")" "$(verify_reason recipient-substitution-swapped-verify 2>/dev/null || echo '?')" \
            "recipient substitution was not detected (request fingerprint $C17_REQUEST_FP)"
    fi
else
    record FAIL case-17 "-" "-" "-" "-" "-" "-" "daemon not ready"
fi

# ---------------------------------------------------------------------------
# Case 27 (security L11): the custodian helper must compare the request's
# recipient fingerprint with the trusted trust document before signing. An
# altered request is refused by the helper and independently rejected by the
# product's phase 2 (the journal digest is rebound so the fingerprint check,
# not the request-digest check, is decisive).
# ---------------------------------------------------------------------------
echo
echo "== Case 27: custodian refuses an altered recipient fingerprint =="
fresh_case_dirs custodian-fingerprint
C27_OP="$(new_op_id)"
start_daemon custodian-fingerprint "$CASE_DATA"
if wait_ready custodian-fingerprint 30; then
    start_backup custodian-fingerprint "$CASE_DATA" "$CASE_DEST" "$C27_OP" O3K_BACKUP_TEST_EXIT_AWAITING_SIGNATURE=1
    C27_STAGING="$CASE_DEST/.o3k-backup-artifact-$C27_OP"
    await_signing_request "$CASE_DEST" "$C27_OP" 60 || true
    wait_backup custodian-fingerprint 60 || true
    reap_exit "$(daemon_pid custodian-fingerprint)" 30 || true
    python3 - "$C27_STAGING/signing-request.json" "$CASE_DATA/backup-operations/$C27_OP.json" "$SWAPPED_RECIPIENT_FP" <<'PY'
import hashlib, json, sys
request_path, journal_path, altered = sys.argv[1:4]
request = json.load(open(request_path))
request["recipient_public_key_sha256"] = altered
raw = json.dumps(request, indent=2).encode()
open(request_path, "wb").write(raw)
journal = json.load(open(journal_path))
journal["request_sha256"] = hashlib.sha256(raw).hexdigest()
json.dump(journal, open(journal_path, "w"))
PY
    CHECK_OK=1
    C27_CUSTODIAN_RC=0
    sign_request "$C27_STAGING" >"$WORK/case-27-custodian.log" 2>&1 || C27_CUSTODIAN_RC=$?
    check "$C27_CUSTODIAN_RC" "1" "custodian helper refusal exit"
    grep -qF "custodian refused the request: recipient fingerprint mismatch" "$WORK/case-27-custodian.log" || {
        CHECK_OK=0; log "  custodian helper did not report the fingerprint refusal"
    }
    [[ ! -e "$C27_STAGING/signing-response.json" ]] || { CHECK_OK=0; log "  the custodian wrote a response for the altered request"; }
    run_backup custodian-fingerprint-replay "$CASE_DATA" "$CASE_DEST" "$C27_OP"
    check "$(backup_exit custodian-fingerprint-replay)" "2" "altered-request phase-2 exit"
    check "$(backup_reason custodian-fingerprint-replay)" "signing-request-mismatch" "altered-request phase-2 reason"
    check "$(is_published "$CASE_DEST" "$C27_OP")" "no" "altered request published nothing"
    check "$(marker_count "$CASE_DATA")" "1" "marker retained for inspection"
    [[ -d "$C27_STAGING" ]] || { CHECK_OK=0; log "  staging removed for the altered request"; }
    if (( CHECK_OK )); then
        record PASS case-27 "2" "staged" "1" "free" "no" \
            "custodian-refused+signing-request-mismatch(exit=2)" \
            "request recipient fingerprint altered to $SWAPPED_RECIPIENT_FP: the harness custodian refused to sign (exit $C27_CUSTODIAN_RC, no response written) and the product's phase 2 independently rejected the request as signing-request-mismatch (exit 2)"
    else
        record FAIL case-27 "$C27_CUSTODIAN_RC" "$(journal_phase "$CASE_DATA" "$C27_OP")" \
            "$(marker_count "$CASE_DATA")" "$(lock_owner "$CASE_DATA")" "$(is_published "$CASE_DEST" "$C27_OP")" \
            "$(backup_reason custodian-fingerprint-replay 2>/dev/null || echo '?')" "custodian fingerprint refusal was not enforced"
    fi
else
    record FAIL case-27 "-" "-" "-" "-" "-" "-" "daemon not ready"
fi

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
    start_backup crash-staged-replay "$CASE_DATA" "$CASE_DEST" "$C5B_OP"
    await_signing_request "$CASE_DEST" "$C5B_OP" 60 || CHECK_OK=0
    sign_request "$C5B_STAGING" || CHECK_OK=0
    wait_backup crash-staged-replay 90 || CHECK_OK=0
    check "$(backup_exit crash-staged-replay)" "0" "replay exit"
    check "$(journal_phase "$CASE_DATA" "$C5B_OP")" "published" "journal after replay"
    check "$(is_published "$CASE_DEST" "$C5B_OP")" "yes" "artifact published by replay"
    check "$(find "$CASE_DEST" -maxdepth 1 -name "backup-$C5B_OP.o3k" | wc -l)" "1" "single artifact"
    # The staged request (and its digest) must be the same one phase 1 wrote:
    # the replay must not have captured again.
    check "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["request_sha256"])' "$CASE_DATA/backup-operations/$C5B_OP.json")" \
        "$C5B_REQUEST_BEFORE" "journal request digest preserved (no recapture)"
    check "$(marker_count "$CASE_DATA")" "0" "marker removed by the replay after publication"
    if (( CHECK_OK )); then
        record PASS case-5b "$(backup_exit crash-staged)" "published" "0" "free" "yes" "published(exit=0)" \
            "crash after the staged journal: the replay resumed the signing wait, published from the staged request without recapture, and removed the marker"
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
    start_backup crash-publishing-hook "$CASE_DATA" "$CASE_DEST" "$C5C_OP" O3K_BACKUP_TEST_EXIT_AFTER_JOURNAL_PUBLISHING=1
    await_signing_request "$CASE_DEST" "$C5C_OP" 60 || true
    reap_exit "$(daemon_pid crash-publishing)" 30 || true
    sign_request "$CASE_DEST/.o3k-backup-artifact-$C5C_OP" || true
    wait_backup crash-publishing-hook 90 || true
    CHECK_OK=1
    check "$(backup_exit crash-publishing-hook)" "88" "hook exit"
    check "$(journal_phase "$CASE_DATA" "$C5C_OP")" "publishing" "journal phase after crash"
    check "$(marker_count "$CASE_DATA")" "1" "marker retained across the publishing crash"
    check "$(is_published "$CASE_DEST" "$C5C_OP")" "no" "nothing published before replay"
    run_backup crash-publishing-replay "$CASE_DATA" "$CASE_DEST" "$C5C_OP"
    check "$(backup_exit crash-publishing-replay)" "0" "replay exit"
    check "$(journal_phase "$CASE_DATA" "$C5C_OP")" "published" "journal after replay"
    check "$(is_published "$CASE_DEST" "$C5C_OP")" "yes" "artifact published"
    check "$(find "$CASE_DEST" -maxdepth 1 -name "backup-$C5C_OP.o3k" | wc -l)" "1" "single artifact"
    if (( CHECK_OK )); then
        record PASS case-5c "$(backup_exit crash-publishing-hook)" "published" "0" "free" "yes" "published(exit=0)" \
            "crash after publishing: replay observed the staged signed artifact, finished publication without a duplicate rename, and removed the marker"
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
    start_backup crash-postpublish-hook "$CASE_DATA" "$CASE_DEST" "$C5D_OP" O3K_BACKUP_TEST_EXIT_AFTER_PUBLICATION=1
    await_signing_request "$CASE_DEST" "$C5D_OP" 60 || true
    reap_exit "$(daemon_pid crash-postpublish)" 30 || true
    sign_request "$CASE_DEST/.o3k-backup-artifact-$C5D_OP" || true
    wait_backup crash-postpublish-hook 90 || true
    CHECK_OK=1
    check "$(backup_exit crash-postpublish-hook)" "89" "hook exit"
    check "$(journal_phase "$CASE_DATA" "$C5D_OP")" "published" "journal phase after crash"
    check "$(is_published "$CASE_DEST" "$C5D_OP")" "yes" "artifact published before crash"
    check "$(marker_count "$CASE_DATA")" "0" "marker removed before the post-publication crash"
    run_backup crash-postpublish-retry "$CASE_DATA" "$CASE_DEST" "$C5D_OP"
    check "$(backup_exit crash-postpublish-retry)" "0" "retry exit"
    check "$(backup_status crash-postpublish-retry)" "backup-published" "retry status"
    check "$(find "$CASE_DEST" -maxdepth 1 -name "backup-$C5D_OP.o3k" | wc -l)" "1" "single artifact"
    if (( CHECK_OK )); then
        record PASS case-5d "$(backup_exit crash-postpublish-hook)" "published" "0" "free" "yes" \
            "published-replay(exit=0)" "crash after publication: exactly one artifact and an idempotent replay exits 0"
    else
        record FAIL case-5d "$(backup_exit crash-postpublish-hook)" "$(journal_phase "$CASE_DATA" "$C5D_OP")" \
            "$(marker_count "$CASE_DATA")" "$(lock_owner "$CASE_DATA")" "$(is_published "$CASE_DEST" "$C5D_OP")" \
            "$(backup_reason crash-postpublish-retry 2>/dev/null || echo '?')" "post-publication crash contract failed"
    fi
else
    record FAIL case-5d "-" "-" "-" "-" "-" "-" "daemon not ready"
fi

# 5e: crash after finalize (artifact.unsigned removed, artifact.partial written)
# but before the journal `publishing` write. The retry lives in the `staged`
# phase and must detect + fully re-verify the signed artifact.
fresh_case_dirs crash-finalize
C5E_OP="$(new_op_id)"
start_daemon crash-finalize "$CASE_DATA"
if wait_ready crash-finalize 30; then
    start_backup crash-finalize-hook "$CASE_DATA" "$CASE_DEST" "$C5E_OP" O3K_BACKUP_TEST_EXIT_AFTER_FINALIZE=1
    await_signing_request "$CASE_DEST" "$C5E_OP" 60 || true
    reap_exit "$(daemon_pid crash-finalize)" 30 || true
    C5E_STAGING="$CASE_DEST/.o3k-backup-artifact-$C5E_OP"
    sign_request "$C5E_STAGING" || true
    wait_backup crash-finalize-hook 90 || true
    C5E_MEMBERS="$(find "$C5E_STAGING" -mindepth 1 -maxdepth 1 -type d -name 'members-*' | head -1)"
    CHECK_OK=1
    check "$(backup_exit crash-finalize-hook)" "90" "hook exit"
    check "$(journal_phase "$CASE_DATA" "$C5E_OP")" "staged" "journal stays staged across the finalize window"
    check "$(marker_count "$CASE_DATA")" "1" "marker retained across the finalize window"
    check "$(is_published "$CASE_DEST" "$C5E_OP")" "no" "nothing published before the retry"
    [[ ! -e "$C5E_MEMBERS/artifact.unsigned" ]] || { CHECK_OK=0; log "  unsigned artifact still present after finalize"; }
    [[ -f "$C5E_MEMBERS/artifact.partial" ]] || { CHECK_OK=0; log "  signed artifact missing after finalize"; }
    run_backup crash-finalize-replay "$CASE_DATA" "$CASE_DEST" "$C5E_OP"
    check "$(backup_exit crash-finalize-replay)" "0" "replay exit"
    check "$(journal_phase "$CASE_DATA" "$C5E_OP")" "published" "journal after replay"
    check "$(is_published "$CASE_DEST" "$C5E_OP")" "yes" "artifact published by the staged recovery"
    check "$(find "$CASE_DEST" -maxdepth 1 -name "backup-$C5E_OP.o3k" | wc -l)" "1" "single artifact"
    if (( CHECK_OK )); then
        record PASS case-5e "$(backup_exit crash-finalize-hook)" "published" "0" "free" "yes" "published(exit=0)" \
            "crash between finalize and the publishing journal: the staged retry detected artifact.partial, re-verified it in full and published"
    else
        record FAIL case-5e "$(backup_exit crash-finalize-hook 2>/dev/null || echo '?')" \
            "$(journal_phase "$CASE_DATA" "$C5E_OP")" "$(marker_count "$CASE_DATA")" "$(lock_owner "$CASE_DATA")" \
            "$(is_published "$CASE_DEST" "$C5E_OP")" "$(backup_exit crash-finalize-replay 2>/dev/null || echo '?')" \
            "finalize/journal crash-window recovery failed"
    fi
else
    record FAIL case-5e "-" "-" "-" "-" "-" "-" "daemon not ready"
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
    start_backup collision-complete "$CASE_DATA" "$CASE_DEST" "$C6_OP"
    await_signing_request "$CASE_DEST" "$C6_OP" 60 || true
    reap_exit "$(daemon_pid collision)" 30 || true
    # The collision appears while the executor is already waiting.
    printf 'pre-existing artifact\n' >"$CASE_DEST/backup-$C6_OP.o3k"
    chmod 0600 "$CASE_DEST/backup-$C6_OP.o3k"
    sign_request "$CASE_DEST/.o3k-backup-artifact-$C6_OP" || true
    wait_backup collision-complete 90 || true
    CHECK_OK=1
    check "$(backup_exit collision-complete)" "2" "collision exit"
    check "$(backup_reason collision-complete)" "artifact-destination-exists" "collision reason"
    check "$(cat "$CASE_DEST/backup-$C6_OP.o3k")" "pre-existing artifact" "pre-existing artifact untouched"
    [[ -d "$CASE_DEST/.o3k-backup-artifact-$C6_OP" ]] || { CHECK_OK=0; log "  staging removed on collision"; }
    check "$(journal_phase "$CASE_DATA" "$C6_OP")" "publishing" "journal preserves attempted publication"
    check "$(marker_count "$CASE_DATA")" "1" "marker retained after the failed publication"
    rm -f "$CASE_DEST/backup-$C6_OP.o3k"
    run_backup collision-retry "$CASE_DATA" "$CASE_DEST" "$C6_OP"
    check "$(backup_exit collision-retry)" "0" "retry after clearing collision"
    check "$(marker_count "$CASE_DATA")" "0" "marker removed by the successful retry"
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
    start_backup swap "$CASE_DATA" "$CASE_DEST" "$C7_OP" O3K_BACKUP_TEST_EXIT_AWAITING_SIGNATURE=1
    await_signing_request "$CASE_DEST" "$C7_OP" 60 || true
    wait_backup swap 60 || true
    reap_exit "$(daemon_pid swap)" 30 || true
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
    sign_request "$CASE_DEST/.o3k-backup-artifact-$C7_OP" || { CHECK_OK=0; log "  staging lost with the swap"; }
    start_backup swap-retry "$CASE_DATA" "$CASE_DEST" "$C7_OP"
    wait_backup swap-retry 90 || CHECK_OK=0
    check "$(backup_exit swap-retry)" "0" "retry after restoring the destination"
    check "$(is_published "$CASE_DEST" "$C7_OP")" "yes" "artifact published after restore"
    if (( CHECK_OK )); then
        record PASS case-7 "$(backup_exit swap-complete)" "published" "0" "free" "yes" "destination-symlink(exit=2)" \
            "destination replaced by a symlink before the resumed publication fails closed (destination-symlink); nothing published outside; retry after restore published"
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
# ---------------------------------------------------------------------------
# Case 11: a replacement controller is DENIED during the Option A signing wait
# ---------------------------------------------------------------------------
echo
echo "== Case 11: restart safety during the signing wait =="
fresh_case_dirs restart
C11_OP="$(new_op_id)"
start_daemon restart1 "$CASE_DATA"
if wait_ready restart1 30; then
    # The executor keeps the store lock and the marker for the whole wait.
    start_backup restart "$CASE_DATA" "$CASE_DEST" "$C11_OP"
    await_signing_request "$CASE_DEST" "$C11_OP" 60 || true
    reap_exit "$(daemon_pid restart1)" 30 || true
    CHECK_OK=1
    check "$(journal_phase "$CASE_DATA" "$C11_OP")" "staged" "journal staged during the wait"
    check "$(marker_count "$CASE_DATA")" "1" "denial marker present during the wait"
    check "$(lock_owner "$CASE_DATA")" "held" "store lock held during the wait"
    # A replacement controller must be refused: the marker denies startup and
    # the lock is still owned by the waiting executor.
    set +e
    env O3K_BOOTSTRAP_PASSWORD="$BOOTSTRAP_PASSWORD" O3K_TOKEN_SIGNING_KEY="$TOKEN_SIGNING_KEY" \
        O3K_NATIVE_CURSOR_HMAC_KEY="$NATIVE_CURSOR_KEY" \
        timeout 30 "$O3KD_BIN" --listen-addr "127.0.0.1:$(free_port)" --data-dir "$CASE_DATA" \
        --log-filter info --log-format json >"$WORK/case-11-restart.log" 2>&1
    C11_RESTART_STATUS=$?
    set -e
    check "$C11_RESTART_STATUS" "1" "restart during the wait refused"
    if grep -qF 'o3kd listening' "$WORK/case-11-restart.log"; then CHECK_OK=0; log "  replacement controller served while a signature was pending"; fi
    if ! grep -qE 'interrupted backup marker\(s\) present|O3K data-directory lifetime lock' "$WORK/case-11-restart.log"; then
        CHECK_OK=0; log "  restart refusal reason missing: $(tail -3 "$WORK/case-11-restart.log")"
    fi
    # The custodian signs; the same process publishes and releases the marker.
    sign_request "$CASE_DEST/.o3k-backup-artifact-$C11_OP" || CHECK_OK=0
    wait_backup restart 90 || CHECK_OK=0
    check "$(backup_exit restart)" "0" "publication exit"
    check "$(is_published "$CASE_DEST" "$C11_OP")" "yes" "artifact published"
    check "$(marker_count "$CASE_DATA")" "0" "marker removed after publication"
    run_verify restart-verify "$CASE_DATA" "$CASE_TRUST" "$CASE_PREFIX" "$(published_path "$CASE_DEST" "$C11_OP")"
    check "$(verify_exit restart-verify)" "0" "artifact verifies after publication"
    # Only after verified publication may a replacement controller start.
    start_daemon restart2 "$CASE_DATA"
    if wait_ready restart2 30; then
        sigterm_expect_zero restart2 || { CHECK_OK=0; log "  replacement daemon did not exit 0 on SIGTERM"; }
    else
        CHECK_OK=0; log "  replacement daemon not ready after publication: $(tail -3 "$(daemon_log restart2)")"
    fi
    if (( CHECK_OK )); then
        record PASS case-11 "$(backup_exit restart)" "published" "0" "free" "yes" "verified(exit=0)" \
            "a replacement o3kd was DENIED during the signing wait (exit $C11_RESTART_STATUS; marker/lock), the waiting process published after the signature, and only then did a controller reach ready and exit 0 on SIGTERM"
    else
        record FAIL case-11 "$(backup_exit restart 2>/dev/null || echo '?')" "$(journal_phase "$CASE_DATA" "$C11_OP")" \
            "$(marker_count "$CASE_DATA")" "$(lock_owner "$CASE_DATA")" "$(is_published "$CASE_DEST" "$C11_OP")" \
            "$(verify_exit restart-verify 2>/dev/null || echo '?')" "restart-safety contract failed (restart status $C11_RESTART_STATUS)"
    fi
else
    record FAIL case-11 "-" "-" "-" "-" "-" "-" "daemon not ready"
fi

# ---------------------------------------------------------------------------
# Case 18 (F37): a pre-existing symlink at the final name is a rejected
# precondition (exit 2 artifact-destination-exists), never exit 4.
# ---------------------------------------------------------------------------
echo
echo "== Case 18: symlink at the final publication name =="
fresh_case_dirs final-symlink
C18_OP="$(new_op_id)"
start_daemon final-symlink "$CASE_DATA"
if wait_ready final-symlink 30; then
    start_backup final-symlink "$CASE_DATA" "$CASE_DEST" "$C18_OP"
    await_signing_request "$CASE_DEST" "$C18_OP" 60 || true
    reap_exit "$(daemon_pid final-symlink)" 30 || true
    ln -s "$WORK/outside-target" "$CASE_DEST/backup-$C18_OP.o3k"
    sign_request "$CASE_DEST/.o3k-backup-artifact-$C18_OP" || true
    wait_backup final-symlink 90 || true
    CHECK_OK=1
    check "$(backup_exit final-symlink)" "2" "symlinked final name exit"
    check "$(backup_reason final-symlink)" "artifact-destination-exists" "symlinked final name reason"
    [[ -L "$CASE_DEST/backup-$C18_OP.o3k" ]] || { CHECK_OK=0; log "  the pre-existing symlink was replaced or removed"; }
    [[ ! -e "$WORK/outside-target" ]] || { CHECK_OK=0; log "  publication followed the symlink"; }
    check "$(marker_count "$CASE_DATA")" "1" "marker retained while publication is pending"
    # Clearing the entry lets the same request finish publication.
    rm -f "$CASE_DEST/backup-$C18_OP.o3k"
    run_backup final-symlink-retry "$CASE_DATA" "$CASE_DEST" "$C18_OP"
    check "$(backup_exit final-symlink-retry)" "0" "retry after clearing the symlink"
    check "$(marker_count "$CASE_DATA")" "0" "marker removed by the retry"
    if (( CHECK_OK )); then
        record PASS case-18 "$(backup_exit final-symlink)" "published" "0" "free" "yes" \
            "artifact-destination-exists(exit=2)" \
            "a symlink at the final name is a rejected precondition (exit 2, not an unknown outcome); the link is never followed or replaced; clearing it publishes on retry"
    else
        record FAIL case-18 "$(backup_exit final-symlink 2>/dev/null || echo '?')" \
            "$(journal_phase "$CASE_DATA" "$C18_OP")" "$(marker_count "$CASE_DATA")" "$(lock_owner "$CASE_DATA")" \
            "$(is_published "$CASE_DEST" "$C18_OP")" "$(backup_reason final-symlink 2>/dev/null || echo '?')" \
            "final-name symlink classification failed"
    fi
else
    record FAIL case-18 "-" "-" "-" "-" "-" "-" "daemon not ready"
fi

# ---------------------------------------------------------------------------
# Case 19 (M5): a stale empty artifact.partial from a failed finalize must not
# wedge the retry.
# ---------------------------------------------------------------------------
echo
echo "== Case 19: stale artifact.partial =="
fresh_case_dirs stale-partial
C19_OP="$(new_op_id)"
start_daemon stale-partial "$CASE_DATA"
if wait_ready stale-partial 30; then
    start_backup stale-partial "$CASE_DATA" "$CASE_DEST" "$C19_OP"
    await_signing_request "$CASE_DEST" "$C19_OP" 60 || true
    # `complete_staged` clears stale finalize debris before it emits the stable
    # awaiting-signature line. Inject after that cleanup, otherwise the executor
    # can remove the just-created file and race the chmod below.
    await_awaiting_signature_line stale-partial "$C19_OP" 30 || true
    reap_exit "$(daemon_pid stale-partial)" 30 || true
    C19_MEMBERS="$(find "$CASE_DEST/.o3k-backup-artifact-$C19_OP" -mindepth 1 -maxdepth 1 -type d -name 'members-*' | head -1)"
    C19_INJECT_OK=1
    if [[ -z "$C19_MEMBERS" ]]; then
        C19_INJECT_OK=0
        log "  stale-partial staging members directory is missing"
    else
        : >"$C19_MEMBERS/artifact.partial"
        chmod 0600 "$C19_MEMBERS/artifact.partial"
    fi
    sign_request "$CASE_DEST/.o3k-backup-artifact-$C19_OP" || true
    wait_backup stale-partial 90 || true
    CHECK_OK=$C19_INJECT_OK
    check "$(backup_exit stale-partial)" "0" "publication over a stale partial"
    check "$(is_published "$CASE_DEST" "$C19_OP")" "yes" "artifact published"
    check "$(journal_phase "$CASE_DATA" "$C19_OP")" "published" "journal published"
    check "$(find "$CASE_DEST" -maxdepth 1 -name "backup-$C19_OP.o3k" | wc -l)" "1" "exactly one artifact"
    if (( CHECK_OK )); then
        record PASS case-19 "$(backup_exit stale-partial)" "published" "0" "free" "yes" "published(exit=0)" \
            "an empty stale artifact.partial left by an earlier failed finalize is replaced atomically (temp + rename) and the retry publishes"
    else
        record FAIL case-19 "$(backup_exit stale-partial 2>/dev/null || echo '?')" \
            "$(journal_phase "$CASE_DATA" "$C19_OP")" "$(marker_count "$CASE_DATA")" "$(lock_owner "$CASE_DATA")" \
            "$(is_published "$CASE_DEST" "$C19_OP")" "-" "stale-partial retry failed"
    fi
else
    record FAIL case-19 "-" "-" "-" "-" "-" "-" "daemon not ready"
fi

# ---------------------------------------------------------------------------
# Case 20 (F2/P0-2): a crash after publication but before the `published`
# journal write, with the staging tree already gone, is recovered from the
# destination inode.
# ---------------------------------------------------------------------------
echo
echo "== Case 20: post-publication crash (staging gone) =="
C20_OP="$HAPPY_OP"
C20_SHA="$(artifact_sha "$HAPPY_DEST" "$C20_OP")"
CHECK_OK=1
python3 - "$HAPPY_DATA/backup-operations/$C20_OP.json" "$C20_SHA" <<'PY'
import json, sys
path, digest = sys.argv[1:3]
journal = json.load(open(path))
journal["phase"] = "publishing"
journal["artifact_sha256"] = digest
json.dump(journal, open(path, "w"))
PY
printf '{"operation_id":"%s"}\n' "$C20_OP" >"$HAPPY_DATA/.o3k-backup-in-progress-$C20_OP"
chmod 0600 "$HAPPY_DATA/.o3k-backup-in-progress-$C20_OP"
[[ ! -e "$HAPPY_DEST/.o3k-backup-artifact-$C20_OP" ]] || { CHECK_OK=0; log "  staging unexpectedly present"; }
CASE_DATA="$HAPPY_DATA"; CASE_DEST="$HAPPY_DEST"; CASE_TRUST="$HAPPY_TRUST"; CASE_PREFIX="$HAPPY_PREFIX"
run_backup post-rename-replay "$HAPPY_DATA" "$HAPPY_DEST" "$C20_OP"
check "$(backup_exit post-rename-replay)" "0" "post-rename replay exit"
check "$(backup_status post-rename-replay)" "backup-published" "post-rename replay status"
check "$(json_get "$WORK/post-rename-replay.backup.json" sha256)" "$C20_SHA" "post-rename replay digest"
check "$(journal_phase "$HAPPY_DATA" "$C20_OP")" "published" "journal marked published"
check "$(marker_count "$HAPPY_DATA")" "0" "marker removed by the replay"
check "$(find "$HAPPY_DEST" -maxdepth 1 -name "backup-$C20_OP.o3k" | wc -l)" "1" "single artifact"
if (( CHECK_OK )); then
    record PASS case-20 "$(backup_exit post-rename-replay)" "published" "0" "free" "yes" "published(exit=0)" \
        "publishing journal + missing staging: the destination inode is opened O_NOFOLLOW, must be a regular file and must hash to the journal digest; the replay classified publication complete and removed the marker"
else
    record FAIL case-20 "$(backup_exit post-rename-replay 2>/dev/null || echo '?')" \
        "$(journal_phase "$HAPPY_DATA" "$C20_OP")" "$(marker_count "$HAPPY_DATA")" "$(lock_owner "$HAPPY_DATA")" \
        "$(is_published "$HAPPY_DEST" "$C20_OP")" "-" "post-rename crash recovery failed"
fi

# ---------------------------------------------------------------------------
# Case 21 (F20): concurrent phase-2 invocations cannot interleave.
# ---------------------------------------------------------------------------
echo
echo "== Case 21: concurrent phase-2 invocations =="
fresh_case_dirs concurrent
C21_OP="$(new_op_id)"
start_daemon concurrent "$CASE_DATA"
if wait_ready concurrent 30; then
    start_backup concurrent-seed "$CASE_DATA" "$CASE_DEST" "$C21_OP" O3K_BACKUP_TEST_EXIT_AWAITING_SIGNATURE=1
    await_signing_request "$CASE_DEST" "$C21_OP" 60 || true
    wait_backup concurrent-seed 60 || true
    reap_exit "$(daemon_pid concurrent)" 30 || true
    sign_request "$CASE_DEST/.o3k-backup-artifact-$C21_OP" || true
    start_backup concurrent-a "$CASE_DATA" "$CASE_DEST" "$C21_OP"
    start_backup concurrent-b "$CASE_DATA" "$CASE_DEST" "$C21_OP"
    wait_backup concurrent-a 90 || true
    wait_backup concurrent-b 90 || true
    C21_A="$(backup_exit concurrent-a)"; C21_AR="$(backup_reason concurrent-a)"
    C21_B="$(backup_exit concurrent-b)"; C21_BR="$(backup_reason concurrent-b)"
    CHECK_OK=1
    C21_OK_COUNT=0; C21_REJECT_COUNT=0
    for pair in "$C21_A:$C21_AR" "$C21_B:$C21_BR"; do
        case "$pair" in
            0:*) C21_OK_COUNT=$((C21_OK_COUNT + 1)) ;;
            2:controller-active|3:operation-busy) C21_REJECT_COUNT=$((C21_REJECT_COUNT + 1)) ;;
            *) CHECK_OK=0; log "  unexpected concurrent outcome: $pair" ;;
        esac
    done
    check "$C21_OK_COUNT" "1" "exactly one phase 2 published"
    check "$C21_REJECT_COUNT" "1" "exactly one phase 2 rejected"
    check "$(is_published "$CASE_DEST" "$C21_OP")" "yes" "artifact published"
    check "$(find "$CASE_DEST" -maxdepth 1 -name "backup-$C21_OP.o3k" | wc -l)" "1" "single artifact"
    check "$(journal_phase "$CASE_DATA" "$C21_OP")" "published" "journal published"
    if (( CHECK_OK )); then
        record PASS case-21 "0/$C21_A/$C21_B" "published" "0" "free" "yes" "$C21_A:$C21_AR $C21_B:$C21_BR" \
            "two simultaneous replays: one published (exit 0) and the other was rejected before touching the tree (controller-active from the lifetime store lock, or operation-busy from the staging-dir operation lock)"
    else
        record FAIL case-21 "$C21_A/$C21_B" "$(journal_phase "$CASE_DATA" "$C21_OP")" \
            "$(marker_count "$CASE_DATA")" "$(lock_owner "$CASE_DATA")" "$(is_published "$CASE_DEST" "$C21_OP")" \
            "$C21_AR/$C21_BR" "concurrent phase-2 exclusion failed"
    fi
else
    record FAIL case-21 "-" "-" "-" "-" "-" "-" "daemon not ready"
fi

# ---------------------------------------------------------------------------
# Case 22 (P2): `create` validates configuration read-only before the handoff.
# ---------------------------------------------------------------------------
echo
echo "== Case 22: create rejects a missing configuration before the handoff =="
fresh_case_dirs missing-create-trust
C22_OP="$(new_op_id)"
C22_TRUST="$CASE_TRUST"; C22_PREFIX="$CASE_PREFIX"
CASE_TRUST="$WORK/absent-create-trust.json"
start_daemon missing-create-trust "$CASE_DATA"
if wait_ready missing-create-trust 30; then
    run_backup missing-create-trust "$CASE_DATA" "$CASE_DEST" "$C22_OP"
    CASE_TRUST="$C22_TRUST"; CASE_PREFIX="$C22_PREFIX"
    CHECK_OK=1
    check "$(backup_exit missing-create-trust)" "2" "missing trust exit"
    check "$(backup_reason missing-create-trust)" "trust-config-unavailable" "missing trust reason"
    check "$(marker_count "$CASE_DATA")" "0" "no marker was written"
    check "$(find "$CASE_DEST" -maxdepth 1 -name 'backup-*.o3k' | wc -l)" "0" "nothing published"
    # The daemon was never asked to hand off the lock, so it is still serving
    # and exits cleanly on SIGTERM.
    curl -fsS "http://127.0.0.1:$(daemon_port missing-create-trust)/readyz" >/dev/null 2>&1 || CHECK_OK=0
    sigterm_expect_zero missing-create-trust || CHECK_OK=0
    if (( CHECK_OK )); then
        record PASS case-22 "$(backup_exit missing-create-trust)" "-" "0" "free" "no" "trust-config-unavailable(exit=2)" \
            "read-only config preflight rejected the missing trust document (exit 2) before the handoff; the daemon stayed ready and exited 0 on SIGTERM"
    else
        record FAIL case-22 "$(backup_exit missing-create-trust 2>/dev/null || echo '?')" \
            "$(journal_phase "$CASE_DATA" "$C22_OP")" "$(marker_count "$CASE_DATA")" "$(lock_owner "$CASE_DATA")" \
            "$(is_published "$CASE_DEST" "$C22_OP")" "$(backup_reason missing-create-trust 2>/dev/null || echo '?')" \
            "create classification of missing configuration failed"
    fi
else
    record FAIL case-22 "-" "-" "-" "-" "-" "-" "daemon not ready"
fi

# ---------------------------------------------------------------------------
# Case 23 (M4/F9): a seeded non-terminal Operation makes the manifest say
# recorded_unknown instead of drained.
# ---------------------------------------------------------------------------
echo
echo "== Case 23: truthful in_flight_operations =="
if (( HAVE_SQLITE3 )); then
    fresh_case_dirs in-flight
    C23_OP="$(new_op_id)"
    start_daemon in-flight-seed "$CASE_DATA"
    if wait_ready in-flight-seed 30; then
        sigterm_expect_zero in-flight-seed || true
        C23_RESOURCE="$(new_op_id)"
        C23_OPERATION="$(new_op_id)"
        sqlite3 "$CASE_DATA/o3k.sqlite" <<SQL
INSERT INTO resources (id, kind, project_id, generation, observed_generation, desired_state, observed_state)
VALUES ('$C23_RESOURCE', 'network', 'project-1', 1, 1, '{}', '{}');
INSERT INTO operations (id, resource_id, kind, state)
VALUES ('$C23_OPERATION', '$C23_RESOURCE', 'create', 'running');
SQL
        start_daemon in-flight "$CASE_DATA"
        if wait_ready in-flight 30; then
            start_backup in-flight "$CASE_DATA" "$CASE_DEST" "$C23_OP"
            await_signing_request "$CASE_DEST" "$C23_OP" 60 || true
            reap_exit "$(daemon_pid in-flight)" 30 || true
            sign_request "$CASE_DEST/.o3k-backup-artifact-$C23_OP" || true
            wait_backup in-flight 90 || true
            if [[ "$(backup_exit in-flight)" == "0" ]]; then
                C23_CLASS="$(python3 - "$(published_path "$CASE_DEST" "$C23_OP")" <<'PY'
import json, struct, sys
raw = open(sys.argv[1], "rb").read()
length = struct.unpack(">Q", raw[12:20])[0]
manifest = json.loads(raw[20:20 + length])
print(manifest["consistency"]["in_flight_operations"])
PY
)"
            else
                C23_CLASS="-"
            fi
            CHECK_OK=1
            check "$(backup_exit in-flight)" "0" "seeded-operation publication exit"
            check "$C23_CLASS" "recorded_unknown" "manifest in_flight_operations"
            if (( CHECK_OK )); then
                record PASS case-23 "$(backup_exit in-flight)" "published" "0" "free" "yes" "recorded_unknown" \
                    "a seeded non-terminal Operation ($C23_OPERATION) makes the manifest record in_flight_operations=recorded_unknown instead of drained; the same identity is stored in the capture metadata member (unit: capture_records_in_flight_operation_identities)"
            else
                record FAIL case-23 "$(backup_exit in-flight 2>/dev/null || echo '?')" \
                    "$(journal_phase "$CASE_DATA" "$C23_OP")" "$(marker_count "$CASE_DATA")" "$(lock_owner "$CASE_DATA")" \
                    "$(is_published "$CASE_DEST" "$C23_OP")" "$C23_CLASS" "in_flight_operations classification failed"
            fi
        else
            record FAIL case-23 "-" "-" "-" "-" "-" "-" "daemon not ready after seeding"
        fi
    else
        record FAIL case-23 "-" "-" "-" "-" "-" "-" "seed daemon not ready"
    fi
else
    record NOT-COVERED case-23 "-" "-" "-" "-" "-" "recorded_unknown" \
        "sqlite3 is unavailable, so the harness cannot seed a non-terminal Operation; unit coverage: backup_artifact::tests::non_terminal_operations_are_recorded_as_unknown and backup_artifact::tests::capture_records_in_flight_operation_identities"
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
# Re-signing a mutated manifest is now feasible (`resign_artifact`), so the
# blocker is no longer tooling: the 5 GiB complete-size branch is unreachable
# for a *schema-valid* manifest. `validate_manifest` bounds each member's
# plaintext at 1 GiB and the total plaintext at 4 GiB, and the verifier runs
# that semantic validation before the complete-size check, so the largest
# declarable artifact is ~4 GiB + 16 MiB. A re-signed manifest that tries to
# declare more is rejected earlier as `schema-invalid` (member metadata /
# total-size bound) and the only path to `artifact-too-large` in
# `verify_artifact_stream` is an over-long declared manifest length, which is a
# malformed header rather than a signed artifact. Asserted by
# `backup::tests::the_complete_size_bound_is_unreachable_for_a_schema_valid_manifest`;
# the exact reason mapping is unit-covered by
# `backup_verify::tests::reason_mapping_is_stable_for_every_failure_class`
# (`ArtifactTooLarge` -> exit 2 `artifact-too-large`).
record NOT-COVERED case-12oversize "-" "-" "-" "-" "-" "artifact-too-large" \
    "not reachable end-to-end for a schema-valid manifest: per-member 1 GiB and 4 GiB total plaintext bounds keep the declarable complete size below the 5 GiB check, which therefore runs only for a synthetic header; re-signing a mutated manifest (resign_artifact) cannot produce the input. Unit: backup::tests::the_complete_size_bound_is_unreachable_for_a_schema_valid_manifest and backup_verify::tests::reason_mapping_is_stable_for_every_failure_class"

# ---------------------------------------------------------------------------
# Case 24: a validly signed manifest without a required member is rejected
# ---------------------------------------------------------------------------
echo
echo "== Case 24: required-member enforcement =="
MISSING_MEMBER="$WORK/happy-missing-member.o3k"
# The manifest is mutated *and re-signed* with the harness custody key, so the
# rejection cannot be explained by a broken signature: a validly signed
# artifact that lacks a required member is still exit 2 missing-required-member.
resign_artifact "$HAPPY_ARTIFACT" "$MISSING_MEMBER" \
    'manifest["members"] = [m for m in manifest["members"] if m["name"] != "metadata/capture.json"]'
run_verify verify-missing-member "$HAPPY_DATA" "$HAPPY_TRUST" "$HAPPY_PREFIX" "$MISSING_MEMBER"
CHECK_OK=1
check "$(verify_exit verify-missing-member)" "2" "missing-member exit"
check "$(verify_reason verify-missing-member)" "missing-required-member" "missing-member reason"
if (( CHECK_OK )); then
    record PASS case-24 "$(verify_exit verify-missing-member)" "published" "0" "free" "yes" \
        "missing-required-member(exit=2)" "a validly signed manifest (the mutated manifest was re-signed, so the D1 signature verifies) without metadata/capture.json is rejected by the required-member set: the classification is missing-required-member, not signature-invalid, and no member is decrypted"
else
    record FAIL case-24 "-" "-" "-" "-" "-" \
        "exit=$(verify_exit verify-missing-member 2>/dev/null || echo '?') reason=$(verify_reason verify-missing-member 2>/dev/null || echo '?')" \
        "required-member enforcement failed"
fi

# ---------------------------------------------------------------------------
# Case 25: the executor rejects a fake daemon that answers the handoff
# ---------------------------------------------------------------------------
echo
echo "== Case 25: daemon identity mismatch =="
C25_DATA="$WORK/c25-data"
C25_DEST="$WORK/c25-dest"
mkdir -p "$C25_DATA" "$C25_DEST"
chmod 0700 "$C25_DATA" "$C25_DEST"
# The read-only preflight runs before the fake daemon is contacted, so the
# fake data directory still needs a valid installation binding and a source
# file; the daemon-identity check then rejects the Python peer.
CASE_TRUST="$(write_config c25 "$C25_DATA" normal)"
CASE_PREFIX="$WORK/cfg-c25-normal/install"
: > "$C25_DATA/o3k.sqlite"
C25_OP="$(new_op_id)"
C25_READY="$WORK/c25.ready"
rm -f "$C25_READY"
python3 - "$C25_DATA" "$C25_READY" <<'PY' &
import os, socket, sys, time
data_dir, ready = sys.argv[1:3]
control = os.path.join(data_dir, "control")
os.makedirs(control, mode=0o700, exist_ok=True)
os.chmod(control, 0o700)
path = os.path.join(control, "backup.sock")
try:
    os.unlink(path)
except FileNotFoundError:
    pass
listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
listener.bind(path)
listener.listen(1)
open(ready, "w").close()
connection, _ = listener.accept()
connection.recv(64)
connection.sendall(b"O3KBKAC\0")
time.sleep(3)
connection.close()
listener.close()
PY
C25_SERVER=$!
wait_for_file "$C25_READY" 10 || true
run_backup daemon-identity "$C25_DATA" "$C25_DEST" "$C25_OP"
wait "$C25_SERVER" 2>/dev/null || true
CHECK_OK=1
check "$(backup_exit daemon-identity)" "2" "fake-daemon exit"
check "$(backup_reason daemon-identity)" "daemon-identity-mismatch" "fake-daemon reason"
if (( CHECK_OK )); then
    record PASS case-25 "$(backup_exit daemon-identity)" "-" "0" "free" "no" \
        "daemon-identity-mismatch(exit=2)" "a python process answering the authenticated handoff is rejected because its exe/uid is not the installed o3kd running as the data-dir owner"
else
    record FAIL case-25 "-" "-" "-" "-" "-" \
        "exit=$(backup_exit daemon-identity 2>/dev/null || echo '?') reason=$(backup_reason daemon-identity 2>/dev/null || echo '?')" \
        "fake-daemon rejection failed"
fi

# ---------------------------------------------------------------------------
# Case 26: a staged signed partial from another manifest/request is rejected
# ---------------------------------------------------------------------------
echo
echo "== Case 26: staged recovery binds the signed partial to the request =="
fresh_case_dirs signreqbind
C26_OP="$(new_op_id)"
start_daemon signreqbind "$CASE_DATA"
if wait_ready signreqbind 30; then
    start_backup signreqbind-hook "$CASE_DATA" "$CASE_DEST" "$C26_OP" O3K_BACKUP_TEST_EXIT_AFTER_FINALIZE=1
    await_signing_request "$CASE_DEST" "$C26_OP" 60 || true
    reap_exit "$(daemon_pid signreqbind)" 30 || true
    C26_STAGING="$CASE_DEST/.o3k-backup-artifact-$C26_OP"
    sign_request "$C26_STAGING" || true
    wait_backup signreqbind-hook 90 || true
    C26_PARTIAL="$(find "$C26_STAGING"/members-* -name artifact.partial -type f | head -1)"
    # Re-sign the same operation with a different manifest (changed created_at)
    # so the artifact remains validly signed but no longer matches the request.
    python3 - "$C26_PARTIAL" "$WORK/c26-d1.bin" "$WORK/c26-manifest.json" "$WORK/c26-blocks.bin" <<'PY'
import json, struct, sys
(artifact, d1_out, manifest_out, blocks_out) = sys.argv[1:5]
raw = open(artifact, "rb").read()
assert raw[:12] == b"O3KPP6BK\x00\x00\x00\x01"
manifest_len = struct.unpack(">Q", raw[12:20])[0]
manifest_end = 20 + manifest_len
manifest = json.loads(raw[20:manifest_end])
offset = manifest_end
blocks = bytearray()
for member in manifest["members"]:
    size = struct.unpack(">Q", raw[offset:offset + 8])[0]
    offset += 8
    blocks += struct.pack(">Q", size) + raw[offset:offset + size]
    offset += size
assert offset == len(raw)
manifest["created_at"] = "2020-01-01T00:00:00Z"
del manifest["authentication"]["signature"]
canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
d1 = b"O3K-PP6-BACKUP-MANIFEST-V1\x00" + struct.pack(">Q", len(canonical)) + canonical
for member in manifest["members"]:
    name = member["name"].encode()
    d1 += struct.pack(">I", len(name)) + name + bytes.fromhex(member["sha256"])
open(d1_out, "wb").write(d1)
open(manifest_out, "w").write(json.dumps(manifest, sort_keys=True, separators=(",", ":")))
open(blocks_out, "wb").write(blocks)
PY
    sign_bytes "$BACKUP_SIGNING_KEY" "$WORK/c26-d1.bin" "$WORK/c26.sig"
    python3 - "$WORK/c26-manifest.json" "$WORK/c26.sig" "$WORK/c26-blocks.bin" "$C26_PARTIAL" <<'PY'
import base64, json, struct, sys
manifest_path, signature_path, blocks_path, artifact_path = sys.argv[1:5]
manifest = json.load(open(manifest_path))
signature = open(signature_path, "rb").read()
manifest["authentication"]["signature"] = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
raw = b"O3KPP6BK\x00\x00\x00\x01" + struct.pack(">Q", len(canonical)) + canonical + open(blocks_path, "rb").read()
open(artifact_path, "wb").write(raw)
PY
    chmod 0600 "$C26_PARTIAL"
    run_backup signreqbind-replay "$CASE_DATA" "$CASE_DEST" "$C26_OP"
    CHECK_OK=1
    check "$(backup_exit signreqbind-replay)" "2" "mismatched-request exit"
    check "$(backup_reason signreqbind-replay)" "signing-request-mismatch" "mismatched-request reason"
    check "$(journal_phase "$CASE_DATA" "$C26_OP")" "staged" "journal stays staged"
    check "$(marker_count "$CASE_DATA")" "1" "marker kept for inspection"
    [[ -f "$C26_PARTIAL" ]] || { CHECK_OK=0; log "  signed partial was removed on mismatch"; }
    [[ -f "$C26_STAGING/signing-request.json" ]] || { CHECK_OK=0; log "  persisted request was removed on mismatch"; }
    if (( CHECK_OK )); then
        record PASS case-26 "$(backup_exit signreqbind-replay)" "staged" "1" "free" "no" \
            "signing-request-mismatch(exit=2)" "a validly signed partial re-signed over a different manifest is rejected before publication; the request and staging are kept"
    else
        record FAIL case-26 "-" "-" "-" "-" "-" \
            "exit=$(backup_exit signreqbind-replay 2>/dev/null || echo '?') reason=$(backup_reason signreqbind-replay 2>/dev/null || echo '?')" \
            "staged-request binding failed"
    fi
else
    record FAIL case-26 "-" "-" "-" "-" "-" "-" "daemon not ready"
fi

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
# Only tracked modifications count: unrelated untracked build/artifact
# directories in the working tree must not be reported as a dirty campaign
# (L8/F30).
if [[ -n "$(git status --porcelain --untracked-files=no -- bins/o3k bins/o3kd crates/o3k-store tests/pp6_backup_artifact.sh docs/evidence/ISSUE_1084_ARTIFACT_EVIDENCE.md 2>/dev/null)" ]]; then
    WORKING_TREE_DIRTY_PY=True
else
    WORKING_TREE_DIRTY_PY=False
fi
HOST_IDENTITY_HASH="$(printf '%s\n%s\n' "$(hostname)" "$(uname -srm)" | sha256sum | cut -d' ' -f1)"
HAPPY_SITE_ID="$(identity_hex o3k-backup-site-identity-v1 "$WORK/happy-data")"
HAPPY_INSTALLATION_ID="$(identity_hex o3k-backup-installation-identity-v1 "$WORK/happy-data")"
# Migration identity of the captured source: the release's declared
# schema_version and the SHA-256 of the highest applied SQLx checksum (the
# same `migration_checksum` mapping the artifact record uses).
MIGRATION_IDENTITY="$(python3 - "$HAPPY_DATA/o3k.sqlite" <<'PY'
import hashlib, sqlite3, sys
connection = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
try:
    row = connection.execute(
        "SELECT version, checksum FROM _sqlx_migrations ORDER BY version DESC LIMIT 1"
    ).fetchone()
finally:
    connection.close()
if row is None:
    print("-\t-")
else:
    print(f"{row[0]}\t{hashlib.sha256(row[1]).hexdigest()}")
PY
)"
MAX_MIGRATION_VERSION="$(printf '%s' "$MIGRATION_IDENTITY" | cut -f1)"
MAX_MIGRATION_CHECKSUM="$(printf '%s' "$MIGRATION_IDENTITY" | cut -f2)"
MAX_MIGRATION_VERSION_JSON=null
[[ "$MAX_MIGRATION_VERSION" =~ ^[0-9]+$ ]] && MAX_MIGRATION_VERSION_JSON="$MAX_MIGRATION_VERSION"
BASELINE_SQLITE_VERSION="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("sqlite_version", ""))' "$ROOT_DIR/crates/o3k-store/state_inventory_v1.json")"
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
    "max_migration_version": $MAX_MIGRATION_VERSION_JSON,
    "max_migration_checksum": "$MAX_MIGRATION_CHECKSUM",
    "state_inventory_sqlite_version": "$BASELINE_SQLITE_VERSION",
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
