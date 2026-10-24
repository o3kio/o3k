#!/usr/bin/env bash
# PP.6 / #1084 authenticated backup handoff — Slice D real-process campaign.
#
# Journey: real o3kd + real `o3k backup create` over the authenticated Unix
# control socket, concurrent API mutation workload, the accepted two-phase
# offline signing flow (phase 1 stages the unsigned artifact and exits 3
# `signing-required`; the harness plays the offline custodian and signs the D1
# input with a fixture Ed25519 key, writes signing-response.json, and re-runs
# the same command to publish), published-artifact verification, and bounded
# restart recovery.
#
# Failure-injection matrix: every executed case is deterministic — feature-
# gated crash hooks (cargo features o3kd/backup-test-hooks,o3k/backup-test-hooks),
# the two-way executor barrier, or kill signals. No sleeps as synchronization:
# the only sleeps are bounded readiness/deadline polls (wait_ready, wait_log,
# reap_exit, the case-b rejection-count poll, the case-i/j/k barrier polls)
# and the one-second workload ramp at journey start, which paces the
# concurrent mutation loop so the backup overlaps live traffic; no assertion
# depends on that ramp. Drain-internal classifications belonging to PR #1167
# are NOT faked here; they are mapped to their existing tests and reported as
# DOCUMENTED rows.
#
# The script is re-runnable and exits 0 only when every executed check passed.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for tool in cargo python3 curl sha256sum openssl xxd; do
    command -v "$tool" >/dev/null 2>&1 || { echo "FATAL: missing required tool: $tool" >&2; exit 2; }
done
HAVE_SQLITE3=0
command -v sqlite3 >/dev/null 2>&1 && HAVE_SQLITE3=1

echo "== build: o3kd + o3k with backup-test-hooks =="
cargo build -p o3kd -p o3k --features o3kd/backup-test-hooks,o3k/backup-test-hooks 2>&1 | tail -2

WORK="$(mktemp -d "${TMPDIR:-/tmp}/o3k-pp6-handoff.XXXXXX")"
chmod 0700 "$WORK"
INSTALL="$WORK/install"
mkdir -p "$INSTALL/bin"
cp "$ROOT_DIR/target/debug/o3kd" "$INSTALL/bin/o3kd"
cp "$ROOT_DIR/target/debug/o3k" "$INSTALL/bin/o3k"
chmod 0700 "$INSTALL" "$INSTALL/bin"
O3KD_BIN="$INSTALL/bin/o3kd"
O3K_BIN="$INSTALL/bin/o3k"

# Offline-custody fixture. The signing key stands in for the custody-held key
# on the (separate, offline) operator workstation: the executor never reads it.
BACKUP_SIGNING_KEY="$WORK/backup-signing-key.pem"
BACKUP_RECIPIENT_KEY="$WORK/backup-recipient.key"
openssl genpkey -algorithm ED25519 -out "$BACKUP_SIGNING_KEY" 2>/dev/null
chmod 0600 "$BACKUP_SIGNING_KEY"
openssl rand -out "$BACKUP_RECIPIENT_KEY" 32
chmod 0600 "$BACKUP_RECIPIENT_KEY"

BOOTSTRAP_PASSWORD="pp6-handoff-disposable-password"
TOKEN_SIGNING_KEY="pp6-handoff-token-signing-key-01234567890123456789012"
NATIVE_CURSOR_KEY="pp6-handoff-native-cursor-key-0123456789abcdef"

RESULTS=()
DAEMON_PIDS=()
WORKLOAD_PID=""
PASS_COUNT=0
FAIL_COUNT=0
DOC_COUNT=0

log() { printf '%s\n' "$*"; }
result() { # result <PASS|FAIL|DOCUMENTED> <case-id> <summary>
    RESULTS+=("$1|$2|$3")
    case "$1" in
        PASS) PASS_COUNT=$((PASS_COUNT + 1)); log "PASS  [$2] $3" ;;
        FAIL) FAIL_COUNT=$((FAIL_COUNT + 1)); log "FAIL  [$2] $3" ;;
        DOCUMENTED) DOC_COUNT=$((DOC_COUNT + 1)); log "DOC   [$2] $3" ;;
    esac
}

cleanup() {
    set +e
    if [[ -n "$WORKLOAD_PID" ]]; then kill "$WORKLOAD_PID" 2>/dev/null; wait "$WORKLOAD_PID" 2>/dev/null; fi
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
# INT/TERM re-raise as the conventional 130/143 statuses: the EXIT trap then
# runs cleanup exactly once and an interrupted run reports a deterministic
# status instead of continuing with an unclear exit code.
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

free_port() {
    python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
}

daemon_pid() { cat "$WORK/$1.pid"; }
daemon_port() { cat "$WORK/$1.port"; }
daemon_log() { cat "$WORK/$1.dlog"; }

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
        sleep 0.25
    done
    return 1
}

wait_log() { # wait_log <name> <substring> [timeout-seconds]
    local name="$1" needle="$2" deadline=$((SECONDS + ${3:-30}))
    while (( SECONDS < deadline )); do
        grep -qF "$needle" "$(daemon_log "$name")" 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

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

sigterm_expect_zero() { # sigterm_expect_zero <name>
    local name="$1" pid
    pid="$(daemon_pid "$name")"
    kill -TERM "$pid"
    reap_exit "$pid" 30 || return 1
    [[ "${EXIT_STATUS[$pid]}" == "0" ]]
}

get_token() { # get_token <port>
    local port="$1" headers
    headers="$WORK/auth-$RANDOM.headers"
    curl -fsS -D "$headers" -o /dev/null -H 'Content-Type: application/json' \
        -X POST "http://127.0.0.1:$port/v3/auth/tokens" \
        --data "{\"auth\":{\"identity\":{\"methods\":[\"password\"],\"password\":{\"user\":{\"name\":\"admin\",\"password\":\"${BOOTSTRAP_PASSWORD}\"}}},\"scope\":{\"project\":{\"name\":\"admin\"}}}}"
    awk 'tolower($1)=="x-subject-token:" {print $2}' "$headers" | tr -d '\r'
    rm -f "$headers"
}

create_network_code() { # create_network_code <port> <token> <name>
    curl -sS -o /dev/null -w '%{http_code}' -H "X-Auth-Token: $2" -H 'Content-Type: application/json' \
        -X POST "http://127.0.0.1:$1/v2.0/networks" --data "{\"network\":{\"name\":\"$3\"}}" 2>/dev/null
}

latest_schema_version() {
    ls "$ROOT_DIR/crates/o3k-store/migrations" \
        | sed -E 's/^0*([0-9]+)_.*/\1/' | sort -n | tail -1
}

identity_hex() { # identity_hex <domain> <data-dir>
    python3 - "$1" "$2" <<'PY'
import hashlib, os, sys
domain, data_dir = sys.argv[1].encode(), sys.argv[2]
canonical = os.fsencode(os.path.realpath(data_dir))
print(hashlib.sha256(domain + b"\x00" + canonical).digest()[:16].hex())
PY
}

write_backup_config() { # write_backup_config <case-key> <data-dir>
    # Writes the root-owned trust document and the installed release manifest
    # the executor requires, bound to this data directory's canonical identity.
    local key="$1" data_dir="$2" dir="$WORK/cfg-$1" site installation public fingerprint
    mkdir -p "$dir/install/share/o3k"
    chmod 0700 "$dir" "$dir/install" "$dir/install/share" "$dir/install/share/o3k"
    site="$(identity_hex o3k-backup-site-identity-v1 "$data_dir")"
    installation="$(identity_hex o3k-backup-installation-identity-v1 "$data_dir")"
    public="$(openssl pkey -in "$BACKUP_SIGNING_KEY" -pubout -outform DER 2>/dev/null \
        | tail -c 32 | xxd -p -c 64)"
    fingerprint="$(printf '%s' "$public" | xxd -r -p | sha256sum | cut -d' ' -f1)"
    python3 - "$dir/backup-trust.json" "$dir/install/share/o3k/release-manifest.json" \
        "$site" "$installation" "$public" "$fingerprint" "$BACKUP_RECIPIENT_KEY" \
        "$(latest_schema_version)" <<'PY'
import json, sys
trust_path, manifest_path, site, installation, public, fingerprint, recipient, schema = sys.argv[1:9]
trust = {
    "format": "o3k-backup-trust-v1",
    "site_id": site,
    "installation_id": installation,
    "profile_id": "o3k-demo-v1",
    "artifact_signing": {"key_id": "signing-1", "ed25519_public_key": public},
    "recipient": {"key_id": "recovery-1", "x25519_private_key_file": recipient},
    "revoked_key_ids": [],
    "custody": {
        "record_id": "custody-1",
        "purpose": "artifact-signing",
        "key_fingerprint": fingerprint,
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
    "source_commit": "0123456789abcdef0123456789abcdef01234567",
    "release_artifact_sha256": "a" * 64,
    "schema_version": schema,
}
with open(manifest_path, "w") as handle:
    json.dump(manifest, handle)
PY
    chmod 0600 "$dir/backup-trust.json" "$dir/install/share/o3k/release-manifest.json"
    CASE_TRUST_CONFIG="$dir/backup-trust.json"
    CASE_INSTALL_PREFIX="$dir/install"
}

sign_request() { # sign_request <operation-staging-dir>
    # Plays the offline custodian: signs the exact D1 signing input that the
    # request carries and writes the detached response next to the request.
    local staging="$1" request="$1/signing-request.json"
    [[ -f "$request" ]] || { echo "missing signing request: $request" >&2; return 1; }
    python3 - "$request" "$WORK/sign-input.bin" "$WORK/sign-meta.json" <<'PY'
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
    }, handle)
PY
    openssl pkeyutl -sign -rawin -inkey "$BACKUP_SIGNING_KEY" \
        -in "$WORK/sign-input.bin" -out "$WORK/sign-input.sig" 2>/dev/null
    python3 - "$WORK/sign-input.sig" "$WORK/sign-meta.json" "$staging/signing-response.json" <<'PY'
import json, os, sys
signature_path, meta_path, response_path = sys.argv[1:4]
meta = json.load(open(meta_path))
signature = open(signature_path, "rb").read()
assert len(signature) == 64, f"unexpected signature size {len(signature)}"
response = {
    "format": "o3k-backup-signing-response-v1",
    "request_sha256": meta["request_sha256"],
    "key_id": meta["key_id"],
    "signature": signature.hex(),
    # Clock-consistent with the request lifetime (host-clock based).
    "signed_at": meta["created_at"],
}
with open(response_path, "w") as handle:
    json.dump(response, handle)
os.chmod(response_path, 0o600)
PY
}

# This matrix exercises the handoff, the lock and phase separation; it is not
# the Option A signing-wait evidence (that is `tests/pp6_backup_artifact.sh`).
# The harness-only `O3K_BACKUP_TEST_STOP_AFTER_STAGING=1` therefore keeps
# phase 1 one-shot: it stages, reports `signing-required` and exits, so each row
# can observe the resulting state without a 24h wait. Phase 2 (the same command
# on a staged journal) ignores the hook and publishes normally.
run_backup() { # run_backup <case-id> <data-dir> <dest-dir> <operation-id> [executor env KEY=VALUE ...]
    local case_id="$1" data_dir="$2" dest_dir="$3" op="$4"; shift 4
    set +e
    env O3K_DATA_DIR="$data_dir" \
        O3K_BACKUP_TRUST_CONFIG="${CASE_TRUST_CONFIG:-$WORK/cfg-absent/backup-trust.json}" \
        O3K_INSTALL_PREFIX="${CASE_INSTALL_PREFIX:-$WORK/cfg-absent/install}" \
        O3K_BACKUP_TEST_STOP_AFTER_STAGING=1 \
        "$@" \
        "$O3K_BIN" backup create --destination "$dest_dir" --operation-id "$op" \
        >"$WORK/$case_id.backup.json" 2>"$WORK/$case_id.backup.stderr"
    echo $? >"$WORK/$case_id.backup.exit"
    set -e
}

complete_backup() { # complete_backup <case-id> <data-dir> <dest-dir> <operation-id> [env ...]
    # Phase 2: sign offline (fixture custodian), then re-run the exact request.
    local case_id="$1" data_dir="$2" dest_dir="$3" op="$4"; shift 4
    sign_request "$dest_dir/.o3k-backup-artifact-$op" || return 1
    run_backup "$case_id-complete" "$data_dir" "$dest_dir" "$op" "$@"
}
backup_exit() { cat "$WORK/$1.backup.exit"; }
backup_stderr() { cat "$WORK/$1.backup.stderr"; }

fresh_case_dirs() { # sets CASE_DATA, CASE_DEST and the case trust configuration
    CASE_DATA="$WORK/$1-data"
    CASE_DEST="$WORK/$1-dest"
    mkdir -p "$CASE_DATA" "$CASE_DEST"
    chmod 0700 "$CASE_DATA" "$CASE_DEST"
    write_backup_config "$1" "$CASE_DATA"
}

new_op_id() { python3 -c 'import uuid; print(uuid.uuid4())'; }

marker_count() { find "$1" -maxdepth 1 -name '.o3k-backup-in-progress-*' | wc -l; }

verify_published_artifact() { # verify_published_artifact <dest-dir> <operation-id> <data-dir>
    local dest="$1" op="$2" data_dir="$3"
    local final="$1/backup-$2.o3k"
    [[ -f "$final" ]] || { echo "missing published artifact: $final" >&2; return 1; }
    [[ ! -e "$dest/.o3k-backup-artifact-$op" ]] || { echo "staging dir still present" >&2; return 1; }
    [[ ! -e "$data_dir/.o3k-backup-in-progress-$op" ]] || { echo "marker still present" >&2; return 1; }
    python3 - "$final" "$op" "$data_dir" "$(latest_schema_version)" \
        "$(identity_hex o3k-backup-site-identity-v1 "$data_dir")" \
        "$(identity_hex o3k-backup-installation-identity-v1 "$data_dir")" <<'PY'
import hashlib, json, pathlib, struct, sys
artifact_path, operation_id, data_dir, schema_version, site_id, installation_id = sys.argv[1:7]
raw = pathlib.Path(artifact_path).read_bytes()
magic = b"O3KPP6BK\x00\x00\x00\x01"
assert raw[:12] == magic, "artifact magic mismatch"
length = struct.unpack(">Q", raw[12:20])[0]
manifest = json.loads(raw[20:20 + length])
size = 20 + length + sum(8 + member["size_bytes"] for member in manifest["members"])
assert size == len(raw), f"artifact layout mismatch ({size} != {len(raw)})"
assert manifest["format_version"] == "1"
assert manifest["backup_id"] == operation_id, manifest["backup_id"]
assert manifest["site_id"] == site_id and manifest["installation_id"] == installation_id
assert int(manifest["store"]["schema_version"]) == int(schema_version)
assert manifest["store"]["backend"] == "sqlite" and manifest["store"]["server_version"]
migrations = manifest["store"]["migrations"]
assert migrations and int(migrations[-1]["version"]) == int(schema_version)
assert all(len(migration["checksum"]) == 64 for migration in migrations)
assert manifest["consistency"]["method"] == "sqlite_vacuum_into"
assert manifest["consistency"]["in_flight_operations"] == "drained"
assert manifest["consistency"]["quiescence_generation"] == operation_id
assert manifest["source"]["source_sha"] == "0123456789abcdef0123456789abcdef01234567"
assert manifest["source"]["profile_id"] == "o3k-demo-v1"
assert manifest["authentication"]["algorithm"] == "Ed25519"
assert len(manifest["authentication"]["signature"]) == 86
assert manifest["encryption"]["algorithm"] == "AES-256-GCM"
assert [member["name"] for member in manifest["members"]] == [
    "database/o3k.sqlite",
    "metadata/capture.json",
    "release/release-manifest.json",
    "trust/backup-trust.json",
]
assert len(manifest["state_inventory"]) == 17
assert {entry["state_family"] for entry in manifest["state_inventory"]} == {
    "canonical_resources",
    "operations_and_reconciliation",
    "placement_allocations_and_provider_mappings",
    "topology_and_building_blocks",
    "iam_and_security_scope",
    "bootstrap_enrollment_and_revocation",
    "audit_and_governance",
    "o3k_owned_configuration",
    "release_and_install_metadata",
}
assert len(manifest["excluded_state"]) == 5
for member in manifest["members"]:
    assert member["plaintext_size_bytes"] + 16 == member["size_bytes"]
    assert len(member["sha256"]) == 64
print("published artifact manifest verified")
PY
}

verify_phase_one() { # verify_phase_one <case-id> <dest-dir> <operation-id> <data-dir>
    local case_id="$1" dest="$2" op="$3" data_dir="$4"
    python3 - "$WORK/$case_id.backup.json" "$op" "$dest" "$data_dir" <<'PY'
import json, os, sys
payload = json.load(open(sys.argv[1]))
operation_id, dest, data_dir = sys.argv[2:5]
assert payload["status"] == "signing-required", payload
assert payload["operation_id"] == operation_id
assert payload["expires_at"]
request = pathlib_path = os.path.join(dest, f".o3k-backup-artifact-{operation_id}", "signing-request.json")
assert os.path.isfile(request), request
assert not os.path.exists(os.path.join(dest, f"backup-{operation_id}.o3k")), "phase 1 must not publish"
assert not os.path.exists(os.path.join(data_dir, f".o3k-backup-in-progress-{operation_id}")), "marker must be removed after staging"
journal = json.load(open(os.path.join(data_dir, "backup-operations", f"{operation_id}.json")))
assert journal["phase"] == "staged", journal
assert journal["request_sha256"], journal
PY
}

log_daemon_tail() { tail -5 "$1" 2>/dev/null || true; }

echo
echo "== Section 1: authenticated handoff journey (real processes) =="
JOURNEY_DATA="$WORK/journey-data"
JOURNEY_DEST="$WORK/journey-dest"
mkdir -p "$JOURNEY_DATA" "$JOURNEY_DEST"
chmod 0700 "$JOURNEY_DATA" "$JOURNEY_DEST"
write_backup_config journey "$JOURNEY_DATA"
start_daemon journey "$JOURNEY_DATA"
if ! wait_ready journey 30; then
    result FAIL journey "o3kd not ready: $(log_daemon_tail "$(daemon_log journey)")"
    exit 1
fi
JPORT="$(daemon_port journey)"
JTOKEN="$(get_token "$JPORT")"
[[ -n "$JTOKEN" ]] || { result FAIL journey "no auth token"; exit 1; }
for i in 1 2 3; do
    code="$(create_network_code "$JPORT" "$JTOKEN" "pp6-seed-$i")"
    [[ "$code" == "201" || "$code" == "200" ]] || { result FAIL journey "seed network create failed: $code"; exit 1; }
done
log "journey: seeded 3 durable networks (pp6-seed-1..3) via POST /v2.0/networks (X-Subject-Token auth)"

# Concurrent mutation workload: create+delete networks until told to stop.
WORKLOAD_LOG="$WORK/workload.log"
: >"$WORKLOAD_LOG"
(
    n=0
    while [[ ! -f "$WORK/stop-workload" ]]; do
        n=$((n + 1))
        name="pp6-wl-$n-$BASHPID"
        ts="$(date +%s%N)"
        out="$WORK/wl-net-$BASHPID.json"
        if http_code="$(curl -sS -o "$out" -w '%{http_code}' -H "X-Auth-Token: $JTOKEN" -H 'Content-Type: application/json' \
            -X POST "http://127.0.0.1:$JPORT/v2.0/networks" --data "{\"network\":{\"name\":\"$name\"}}" 2>/dev/null)"; then
            :
        else
            http_code="conn-fail"
        fi
        if [[ "$http_code" == "201" || "$http_code" == "200" ]]; then
            nid="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["network"]["id"])' "$out" 2>/dev/null || true)"
            dcode="$(curl -sS -o /dev/null -w '%{http_code}' -H "X-Auth-Token: $JTOKEN" \
                -X DELETE "http://127.0.0.1:$JPORT/v2.0/networks/$nid" 2>/dev/null)" || dcode="conn-fail"
            printf '%s %s create=%s delete=%s\n' "$ts" "$name" "$http_code" "$dcode" >>"$WORKLOAD_LOG"
        else
            printf '%s %s create=%s\n' "$ts" "$name" "$http_code" >>"$WORKLOAD_LOG"
        fi
        sleep 0.05
    done
) &
WORKLOAD_PID=$!

sleep 1
JOP="$(new_op_id)"
run_backup journey "$JOURNEY_DATA" "$JOURNEY_DEST" "$JOP"
touch "$WORK/stop-workload"
wait "$WORKLOAD_PID" 2>/dev/null || true
WORKLOAD_PID=""

JOURNEY_OK=1
# (4) phase 1: capture staged, exit 3 signing-required, marker removed
if [[ "$(backup_exit journey)" == "3" ]] \
    && python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if (d.get("status")=="signing-required" and d.get("operation_id")==sys.argv[2] and d.get("signing_request")) else 1)' "$WORK/journey.backup.json" "$JOP"; then
    log "journey: backup create phase 1 exit 3 signing-required with bounded JSON contract"
else
    JOURNEY_OK=0
    log "journey: backup create phase 1 failed: exit=$(backup_exit journey) stderr=$(backup_stderr journey)"
fi
if (( JOURNEY_OK )); then
    if PHASE1_ERR="$(verify_phase_one journey "$JOURNEY_DEST" "$JOP" "$JOURNEY_DATA" 2>&1)"; then
        log "journey: phase 1 staged the unsigned artifact, wrote the signing request, removed the marker, journal=staged"
    else
        JOURNEY_OK=0
        log "journey: phase-1 verification failed: $PHASE1_ERR"
    fi
fi
# Phase 2: the offline custodian signs the D1 input (the harness holds a test
# key; the executor never reads it) and the same command publishes.
if (( JOURNEY_OK )); then
    complete_backup journey "$JOURNEY_DATA" "$JOURNEY_DEST" "$JOP"
    if [[ "$(backup_exit journey-complete)" == "0" ]] \
        && python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if (d.get("status")=="backup-published" and d.get("operation_id")==sys.argv[2] and d.get("signature")=="verified") else 1)' "$WORK/journey-complete.backup.json" "$JOP"; then
        log "journey: backup create phase 2 exit 0 backup-published (detached signature verified)"
    else
        JOURNEY_OK=0
        log "journey: backup create phase 2 failed: exit=$(backup_exit journey-complete) stderr=$(backup_stderr journey-complete)"
    fi
fi
# (5) mutation rejection observation across the backup window
if python3 - "$WORKLOAD_LOG" <<'PY'
import sys
lines = [l.split() for l in open(sys.argv[1]) if l.strip()]
successes = [int(l[0]) for l in lines if len(l) >= 3 and l[2].startswith("create=2")]
failures = [int(l[0]) for l in lines if len(l) >= 3 and ("create=conn-fail" in l[2] or "create=503" in l[2])]
assert successes, "workload saw no successful mutations before backup"
assert failures, "workload saw no rejected mutations during/after backup"
assert max(successes) < min(failures), "mutation succeeded after shutdown began"
print(f"workload evidence: {len(successes)} successes before shutdown, {len(failures)} rejections after")
PY
then
    log "journey: concurrent mutations deterministically rejected once shutdown began (conn-refused after listener close)"
else
    JOURNEY_OK=0
    log "journey: workload rejection evidence FAILED"
fi
log "journey: note — the admission-gate 503+Retry-After is not real-process observable here because o3kd begins the API exclusion after the axum serve ends; that gate is unit-covered (o3k-api backup_admission_tests)"
# (6) daemon exited 0 (SOURCE_EXIT after ack)
JPID="$(daemon_pid journey)"
if reap_exit "$JPID" 30 && [[ "${EXIT_STATUS[$JPID]}" == "0" ]]; then
    log "journey: daemon exited 0 after lock transfer (SOURCE_EXIT)"
else
    JOURNEY_OK=0
    log "journey: daemon did not exit 0: status=${EXIT_STATUS[$JPID]:-timeout} log: $(log_daemon_tail "$(daemon_log journey)")"
fi
# state machine log lines
if wait_log journey "backup handoff request accepted" 1 \
    && wait_log journey "store lock ownership transferred to the backup executor" 1 \
    && grep -qF "controller writers drained" "$(daemon_log journey)"; then
    log "journey: daemon log shows AUTHORIZED -> drain(WRITERS_DRAINED) -> LOCK_HANDOFF -> SOURCE_EXIT transitions"
else
    JOURNEY_OK=0
    log "journey: missing state-transition log lines"
fi
# (7)(8) published artifact: layout, manifest contract, identity binding
if (( JOURNEY_OK )); then
    if CAPTURE_ERR="$(verify_published_artifact "$JOURNEY_DEST" "$JOP" "$JOURNEY_DATA" 2>&1)"; then
        log "journey: published artifact verified (magic/layout, signed manifest, identity, migrations, state inventory)"
    else
        JOURNEY_OK=0
        log "journey: artifact verification failed: $CAPTURE_ERR"
    fi
else
    log "journey: artifact verification skipped (earlier journey failure)"
fi
# The staged snapshot member is the quiesced capture; its integrity was
# already proven by backup_to_file before the member was encrypted.
if (( JOURNEY_OK )) && (( HAVE_SQLITE3 )); then
    [[ "$(sqlite3 "$JOURNEY_DATA/o3k.sqlite" 'PRAGMA integrity_check;')" == "ok" ]] || JOURNEY_OK=0
    [[ -z "$(sqlite3 "$JOURNEY_DATA/o3k.sqlite" 'PRAGMA foreign_key_check;')" ]] || JOURNEY_OK=0
    [[ "$(sqlite3 "$JOURNEY_DATA/o3k.sqlite" 'SELECT count(*) FROM _sqlx_migrations;')" -gt 0 ]] || JOURNEY_OK=0
    log "journey: live store integrity_check/foreign_key_check/migrations ok after the artifact was published"
fi
# (10) bounded restart: marker was removed, daemon restarts, seeded state present, clean SIGTERM exit 0
if (( JOURNEY_OK )); then
    start_daemon journey2 "$JOURNEY_DATA"
    if wait_ready journey2 30; then
        J2PORT="$(daemon_port journey2)"
        J2TOKEN="$(get_token "$J2PORT")"
        NETLIST="$(curl -fsS -H "X-Auth-Token: $J2TOKEN" "http://127.0.0.1:$J2PORT/v2.0/networks")"
        if echo "$NETLIST" | grep -q 'pp6-seed-1' && echo "$NETLIST" | grep -q 'pp6-seed-3'; then
            log "journey: restart on same data dir OK; seeded networks present in canonical state"
        else
            JOURNEY_OK=0
            log "journey: seeded networks missing after restart"
        fi
        if sigterm_expect_zero journey2; then
            log "journey: restarted daemon SIGTERM exit 0"
        else
            JOURNEY_OK=0
            log "journey: restarted daemon did not exit 0 on SIGTERM"
        fi
    else
        JOURNEY_OK=0
        log "journey: restart on same data dir failed: $(log_daemon_tail "$(daemon_log journey2)")"
    fi
fi
if (( JOURNEY_OK )); then result PASS journey "authenticated handoff journey end-to-end (seed+workload+capture+offline-sign+publish+restart)"; else result FAIL journey "authenticated handoff journey"; fi

echo
echo "== Section 2: failure-injection matrix =="

# --- (a) Authentication failure: executor exe identity mismatch ----------------
fresh_case_dirs case-a
start_daemon case-a "$CASE_DATA"
if wait_ready case-a 30; then
    A_IMPOSTOR="$WORK/impostor-o3k"
    cp "$O3K_BIN" "$A_IMPOSTOR"
    chmod 0700 "$A_IMPOSTOR"
    AOP="$(new_op_id)"
    set +e
    env O3K_DATA_DIR="$CASE_DATA" "$A_IMPOSTOR" backup create --destination "$CASE_DEST" --operation-id "$AOP" \
        >"$WORK/case-a.backup.json" 2>"$WORK/case-a.backup.stderr"
    A_STATUS=$?
    set -e
    A_OK=1
    [[ "$A_STATUS" == "2" ]] || A_OK=0
    grep -q 'unauthorized-peer' "$WORK/case-a.backup.stderr" || A_OK=0
    grep -qF 'backup handoff request rejected during authentication' "$(daemon_log case-a)" || A_OK=0
    grep -q 'UnauthorizedPeer' "$(daemon_log case-a)" || A_OK=0
    curl -fsS "http://127.0.0.1:$(daemon_port case-a)/readyz" >/dev/null || A_OK=0
    if ! python3 - "$CASE_DATA" <<'PY'
import fcntl, os, sys
fd = os.open(os.path.join(sys.argv[1], ".o3k-store.lock"), os.O_RDWR)
try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
except OSError:
    sys.exit(0)  # lock still held by the daemon: expected
sys.exit("lock NOT held by daemon after rejected attempt")
PY
    then A_OK=0; fi
    sigterm_expect_zero case-a || A_OK=0
    if (( A_OK )); then
        result PASS case-a "exe-identity mismatch rejected (exit 2 unauthorized-peer); daemon healthy, lock held, SIGTERM exit 0"
    else
        result FAIL case-a "auth-failure case: status=$A_STATUS stderr=$(cat "$WORK/case-a.backup.stderr")"
    fi
else
    result FAIL case-a "daemon not ready"
fi

# --- (b) Malformed operation request -------------------------------------------
fresh_case_dirs case-b
start_daemon case-b "$CASE_DATA"
if wait_ready case-b 30; then
    B_OK=1
    if ! python3 - "$CASE_DATA" <<'PY'
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(10)
s.connect(f"{sys.argv[1]}/control/backup.sock")
s.sendall(b"\x00" * 64)
resp = s.recv(8)
assert resp[:7] == b"O3KBKRJ", resp
assert resp[7] == 2, resp  # reason 2 = Malformed
print("garbage frame rejected in-band as Malformed")
PY
    then B_OK=0; fi
    python3 - "$CASE_DATA" <<'PY'
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(f"{sys.argv[1]}/control/backup.sock")
s.close()
print("zero-length request sent")
PY
    # Bounded poll for the accept thread's zero-length rejection (count 2 =
    # garbage frame + zero-length frame) instead of a fixed sleep, which can
    # race the async log write under load.
    B_REJ_COUNT=0
    B_DEADLINE=$((SECONDS + 10))
    while (( SECONDS < B_DEADLINE )); do
        B_REJ_COUNT="$(grep -cF 'backup handoff request rejected during authentication' "$(daemon_log case-b)" || true)"
        if (( B_REJ_COUNT >= 2 )); then break; fi
        sleep 0.1
    done
    [[ "$B_REJ_COUNT" -ge 2 ]] || B_OK=0
    grep -q 'Malformed' "$(daemon_log case-b)" || B_OK=0
    curl -fsS "http://127.0.0.1:$(daemon_port case-b)/readyz" >/dev/null || B_OK=0
    sigterm_expect_zero case-b || B_OK=0
    if (( B_OK )); then
        result PASS case-b "garbage + zero-length frames rejected in-band (Malformed, reason byte 2); daemon unaffected, SIGTERM exit 0"
    else
        result FAIL case-b "malformed-request handling broken (reject count: ${B_REJ_COUNT:-0})"
    fi
else
    result FAIL case-b "daemon not ready"
fi

# --- (c) Duplicate / concurrent attempts ---------------------------------------
fresh_case_dirs case-c
start_daemon case-c "$CASE_DATA"
if wait_ready case-c 30; then
    COP1="$(new_op_id)"
    COP2="$(new_op_id)"
    (
        set +e
        env O3K_DATA_DIR="$CASE_DATA" \
            O3K_BACKUP_TRUST_CONFIG="$CASE_TRUST_CONFIG" \
            O3K_INSTALL_PREFIX="$CASE_INSTALL_PREFIX" \
            O3K_BACKUP_TEST_STOP_AFTER_STAGING=1 \
            "$O3K_BIN" backup create --destination "$CASE_DEST" --operation-id "$COP1" \
            >"$WORK/case-c-w1.json" 2>"$WORK/case-c-w1.stderr"
        echo $? >"$WORK/case-c-w1.exit"
    ) &
    C_PID1=$!
    C_OK=1
    wait_log case-c 'backup handoff request accepted' 15 || C_OK=0
    run_backup case-c "$CASE_DATA" "$CASE_DEST" "$COP2"
    wait "$C_PID1" 2>/dev/null || true
    C_W1="$(cat "$WORK/case-c-w1.exit")"
    C_W2="$(backup_exit case-c)"
    # Phase 1 of the winner ends at `signing-required` (exit 3): the artifact is
    # staged but unsigned, so the custody key is never needed by the executor.
    [[ "$C_W1" == "3" ]] || C_OK=0
    python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if (d.get("status")=="signing-required" and d.get("operation_id")==sys.argv[2]) else 1)' "$WORK/case-c-w1.json" "$COP1" || C_OK=0
    # Exit 2 is required either way. When the second connect lands inside the
    # drain window, the daemon's post-accept loop answers in-band with the
    # O3KBKRJ AlreadyActive frame (backup-already-active); when it lands after
    # the daemon has exited (the idle-daemon drain is only tens of ms), the
    # stale control socket refuses the connection (controller-unavailable).
    # Both reject the second attempt while exactly one winner captures.
    [[ "$C_W2" == "2" ]] || C_OK=0
    grep -qE 'backup-already-active|controller-unavailable' "$WORK/case-c.backup.stderr" || C_OK=0
    CPID="$(daemon_pid case-c)"
    reap_exit "$CPID" 30 || C_OK=0
    [[ "${EXIT_STATUS[$CPID]}" == "0" ]] || C_OK=0
    # Phase 2 (offline signature) publishes without a controller.
    complete_backup case-c-w1 "$CASE_DATA" "$CASE_DEST" "$COP1" || C_OK=0
    [[ "$(backup_exit case-c-w1-complete)" == "0" ]] || C_OK=0
    verify_published_artifact "$CASE_DEST" "$COP1" "$CASE_DATA" >/dev/null 2>&1 || C_OK=0
    if (( C_OK )); then
        result PASS case-c "concurrent attempts: exactly one accepted and staged (op $COP1 phase 1 exit 3), second exit 2 ($(cat "$WORK/case-c.backup.stderr" | grep -oE 'backup-already-active|controller-unavailable')) — in-band O3KBKRJ AlreadyActive during the drain window, stale-socket refusal after process exit; offline signature published the winner (exit 0)"
    else
        result FAIL case-c "concurrent-attempt accounting broken: winner=$C_W1 loser=$C_W2 complete=$(backup_exit case-c-w1-complete 2>/dev/null || echo '?') $(cat "$WORK/case-c.backup.stderr")"
    fi
else
    result FAIL case-c "daemon not ready"
fi

# --- (c2) duplicate operation id across a daemon restart (daemon hook 98) ------
fresh_case_dirs case-c2
# The daemon-side hook must be in the DAEMON environment: accepted, then dies
# after the drain proof, before any descriptor transfer.
start_daemon case-c2 "$CASE_DATA" O3K_BACKUP_TEST_EXIT_BEFORE_HANDOFF=1
if wait_ready case-c2 30; then
    C2OP="$(new_op_id)"
    run_backup case-c2 "$CASE_DATA" "$CASE_DEST" "$C2OP"
    C2PID="$(daemon_pid case-c2)"
    C2_OK=1
    [[ "$(backup_exit case-c2)" == "3" ]] || C2_OK=0
    grep -q 'handoff-receive-failed' "$WORK/case-c2.backup.stderr" || C2_OK=0
    reap_exit "$C2PID" 30 || C2_OK=0
    [[ "${EXIT_STATUS[$C2PID]}" == "98" ]] || C2_OK=0
    [[ "$(marker_count "$CASE_DATA")" == "0" ]] || C2_OK=0
    [[ ! -d "$CASE_DEST/.o3k-backup-artifact-$C2OP" ]] || C2_OK=0
    [[ ! -e "$CASE_DEST/backup-$C2OP.o3k" ]] || C2_OK=0
    # restart: a fresh daemon has no accepted ids, so the same operation id is accepted
    start_daemon case-c2b "$CASE_DATA"
    if wait_ready case-c2b 30; then
        run_backup case-c2b "$CASE_DATA" "$CASE_DEST" "$C2OP"
        [[ "$(backup_exit case-c2b)" == "3" ]] || C2_OK=0
        complete_backup case-c2b "$CASE_DATA" "$CASE_DEST" "$C2OP" || C2_OK=0
        [[ "$(backup_exit case-c2b-complete)" == "0" ]] || C2_OK=0
        verify_published_artifact "$CASE_DEST" "$C2OP" "$CASE_DATA" >/dev/null 2>&1 || C2_OK=0
        C2BPID="$(daemon_pid case-c2b)"
        reap_exit "$C2BPID" 30 || C2_OK=0
        [[ "${EXIT_STATUS[$C2BPID]}" == "0" ]] || C2_OK=0
    else
        C2_OK=0
    fi
    if (( C2_OK )); then
        result PASS case-c2 "daemon hook 98: executor exit 3 (handoff-receive-failed), daemon exit 98, no marker/artifact; same op id accepted after restart, staged and published after the offline signature — duplicate detection is per-daemon-lifetime and the aborted op never transferred the lock (cross-restart replay residual risk recorded in evidence doc)"
    else
        result FAIL case-c2 "duplicate-op orchestration failed: first=$(backup_exit case-c2) second=$(backup_exit case-c2b 2>/dev/null || echo '?') complete=$(backup_exit case-c2b-complete 2>/dev/null || echo '?')"
    fi
else
    result FAIL case-c2 "daemon not ready"
fi

# --- (d) Drain-internal classifications (DOCUMENTED, never faked) --------------
result DOCUMENTED case-d "API drain timeout -> o3k-api backup_admission_tests::backup_admission_times_out_when_an_api_request_does_not_drain; 503+Retry-After gate semantics -> exclusive_backup_admission_keeps_liveness_and_rejects_other_requests"
result DOCUMENTED case-d "network lease cleanup failure -> bins/o3kd composition/network.rs: failed_real_relinquishment_blocks_network_drain, failed_relinquishment_cannot_be_counted_as_drained, cancelled_realm_cleanup_is_owned_by_registry"
result DOCUMENTED case-d "storage renewal failure -> bins/o3kd composition/storage.rs: failed_storage_renewal_is_not_repolled_or_unlocked, cancelled_acquisition_is_recorded_and_keeps_execution_lock, storage_end_waits_for_in_flight_database_renewal"
result DOCUMENTED case-d "unknown provider outcome -> crates/o3k-reconciler storage_workflow.rs: unknown_provider_outcome_requires_observe_before_retry; crates/o3k-reconciler tests: unknown_outcome_is_observed_without_duplicate_create"
result DOCUMENTED case-d "SQLite rollback pending -> crates/o3k-store tests: terminal_writer_drain_joins_cancelled_sqlite_transaction_and_rejects_new_writes; bins/o3kd drain_tests: cancelled_controller_session_drain_retains_lifetime_lock"
result DOCUMENTED case-d "configured network+storage worker drain -> bins/o3kd/tests/shutdown.rs: configured_network_and_storage_workers_drain_in_real_daemon"

# --- (e) Receiver crash before descriptor receipt (executor hook 95) -----------
fresh_case_dirs case-e
start_daemon case-e "$CASE_DATA"
if wait_ready case-e 30; then
    EOP="$(new_op_id)"
    run_backup case-e "$CASE_DATA" "$CASE_DEST" "$EOP" O3K_BACKUP_TEST_EXIT_BEFORE_RECEIVE=1
    E_OK=1
    [[ "$(backup_exit case-e)" == "95" ]] || E_OK=0
    EPID="$(daemon_pid case-e)"
    reap_exit "$EPID" 30 || E_OK=0
    [[ "${EXIT_STATUS[$EPID]}" != "0" ]] || E_OK=0
    grep -qE 'store lock handoff failed|exiting without lock transfer' "$(daemon_log case-e)" || E_OK=0
    [[ "$(marker_count "$CASE_DATA")" == "0" ]] || E_OK=0
    [[ ! -d "$CASE_DEST/.o3k-backup-artifact-$EOP" ]] || E_OK=0
    [[ ! -e "$CASE_DEST/backup-$EOP.o3k" ]] || E_OK=0
    start_daemon case-e2 "$CASE_DATA"
    if wait_ready case-e2 30; then
        sigterm_expect_zero case-e2 || E_OK=0
    else
        E_OK=0
    fi
    if (( E_OK )); then
        result PASS case-e "receiver crash before receipt: executor exit 95, daemon exit ${EXIT_STATUS[$EPID]} (handoff failed, lock retained until process exit), no marker/artifact, restart ok"
    else
        result FAIL case-e "hook-95 case broken: executor exit=$(backup_exit case-e) daemon exit=${EXIT_STATUS[$EPID]:-?}"
    fi
else
    result FAIL case-e "daemon not ready"
fi

# --- (f) Receiver crash after receipt + ack (executor hook 94) -----------------
fresh_case_dirs case-f
start_daemon case-f "$CASE_DATA"
if wait_ready case-f 30; then
    FOP="$(new_op_id)"
    run_backup case-f "$CASE_DATA" "$CASE_DEST" "$FOP" O3K_BACKUP_TEST_EXIT_AFTER_RECEIVE=1
    F_OK=1
    [[ "$(backup_exit case-f)" == "94" ]] || F_OK=0
    FPID="$(daemon_pid case-f)"
    reap_exit "$FPID" 30 || F_OK=0
    [[ "${EXIT_STATUS[$FPID]}" == "0" ]] || F_OK=0
    [[ "$(marker_count "$CASE_DATA")" == "0" ]] || F_OK=0
    [[ ! -d "$CASE_DEST/.o3k-backup-artifact-$FOP" ]] || F_OK=0
    [[ ! -e "$CASE_DEST/backup-$FOP.o3k" ]] || F_OK=0
    start_daemon case-f2 "$CASE_DATA"
    if wait_ready case-f2 30; then
        sigterm_expect_zero case-f2 || F_OK=0
    else
        F_OK=0
    fi
    if (( F_OK )); then
        result PASS case-f "receiver crash after receipt+ack: executor exit 94 (ack completed), daemon SOURCE_EXIT 0, no marker/artifact, restart ok (executor death released the transferred lock)"
    else
        result FAIL case-f "hook-94 case broken: executor exit=$(backup_exit case-f) daemon exit=${EXIT_STATUS[$FPID]:-?}"
    fi
else
    result FAIL case-f "daemon not ready"
fi

# --- (g) Sender crash after send, before ack read (daemon hooks 96+sleep) ------
fresh_case_dirs case-g
# The post-send sleep keeps the daemon alive long enough for the executor's
# acknowledgement to land, making the after-send crash deterministic (without
# it, ack-write vs process teardown would be a microsecond race).
start_daemon case-g "$CASE_DATA" \
    O3K_HANDOFF_TEST_SLEEP_AFTER_SEND_MS=300 \
    O3K_HANDOFF_TEST_EXIT_AFTER_SEND_BEFORE_ACK_READ=1
if wait_ready case-g 30; then
    GOP="$(new_op_id)"
    run_backup case-g "$CASE_DATA" "$CASE_DEST" "$GOP"
    G_OK=1
    [[ "$(backup_exit case-g)" == "3" ]] || G_OK=0
    complete_backup case-g "$CASE_DATA" "$CASE_DEST" "$GOP" || G_OK=0
    [[ "$(backup_exit case-g-complete)" == "0" ]] || G_OK=0
    verify_published_artifact "$CASE_DEST" "$GOP" "$CASE_DATA" >/dev/null 2>&1 || G_OK=0
    GPID="$(daemon_pid case-g)"
    reap_exit "$GPID" 30 || G_OK=0
    [[ "${EXIT_STATUS[$GPID]}" == "96" ]] || G_OK=0
    [[ "$(marker_count "$CASE_DATA")" == "0" ]] || G_OK=0
    start_daemon case-g2 "$CASE_DATA"
    if wait_ready case-g2 30; then
        sigterm_expect_zero case-g2 || G_OK=0
    else
        G_OK=0
    fi
    if (( G_OK )); then
        result PASS case-g "sender crash after send before ack read: daemon exit 96, executor still completed phase 1 (exit 3, ownership continuity through sender loss), offline signature published the artifact (exit 0), marker removed, restart ok"
    else
        result FAIL case-g "hook-96 case broken: executor exit=$(backup_exit case-g) complete=$(backup_exit case-g-complete 2>/dev/null || echo '?') daemon exit=${EXIT_STATUS[$GPID]:-?}"
    fi
else
    result FAIL case-g "daemon not ready"
fi

# --- (h) Lost acknowledgement (executor hook 97) --------------------------------
fresh_case_dirs case-h
start_daemon case-h "$CASE_DATA"
if wait_ready case-h 30; then
    HOP="$(new_op_id)"
    run_backup case-h "$CASE_DATA" "$CASE_DEST" "$HOP" O3K_HANDOFF_TEST_EXIT_BEFORE_ACK=1
    H_OK=1
    [[ "$(backup_exit case-h)" == "97" ]] || H_OK=0
    HPID="$(daemon_pid case-h)"
    reap_exit "$HPID" 30 || H_OK=0
    [[ "${EXIT_STATUS[$HPID]}" != "0" ]] || H_OK=0
    if grep -qF 'store lock ownership transferred' "$(daemon_log case-h)"; then H_OK=0; fi
    grep -qF 'store lock handoff failed' "$(daemon_log case-h)" || H_OK=0
    [[ "$(marker_count "$CASE_DATA")" == "0" ]] || H_OK=0
    [[ ! -d "$CASE_DEST/.o3k-backup-artifact-$HOP" ]] || H_OK=0
    [[ ! -e "$CASE_DEST/backup-$HOP.o3k" ]] || H_OK=0
    start_daemon case-h2 "$CASE_DATA"
    if wait_ready case-h2 30; then
        sigterm_expect_zero case-h2 || H_OK=0
    else
        H_OK=0
    fi
    if (( H_OK )); then
        result PASS case-h "lost acknowledgement: executor exit 97, daemon exit ${EXIT_STATUS[$HPID]} (never 0; no success status emitted; UnknownOutcome fail-closed), no marker/artifact, restart ok"
    else
        result FAIL case-h "hook-97 case broken: executor exit=$(backup_exit case-h) daemon exit=${EXIT_STATUS[$HPID]:-?}"
    fi
else
    result FAIL case-h "daemon not ready"
fi

# --- (i) SIGKILL of the daemon after the transfer, at the last point it exists -
# The daemon-side barrier holds the process alive after the lock handoff
# completed (ack already received) so the SIGKILL lands while the sender still
# exists. The strictly-mid-transfer kill (between descriptor send and ack read)
# is case-g's hook 96 (_exit is descriptor-equivalent to SIGKILL).
fresh_case_dirs case-i
DREADY="$WORK/case-i.dready"; DGO="$WORK/case-i.dgo"
rm -f "$DREADY" "$DGO"
start_daemon case-i "$CASE_DATA" \
    O3K_BACKUP_TEST_DAEMON_BARRIER_READY_FILE="$DREADY" \
    O3K_BACKUP_TEST_DAEMON_BARRIER_WAIT_FILE="$DGO"
if wait_ready case-i 30; then
    IOP="$(new_op_id)"
    run_backup case-i "$CASE_DATA" "$CASE_DEST" "$IOP" &
    I_BPID=$!
    I_OK=1
    I_DEADLINE=$((SECONDS + 40))
    while [[ ! -f "$DREADY" ]]; do
        if (( SECONDS >= I_DEADLINE )); then I_OK=0; break; fi
        sleep 0.1
    done
    if (( I_OK )); then
        IPID="$(daemon_pid case-i)"
        kill -0 "$IPID" 2>/dev/null || I_OK=0   # daemon must still be alive here
        kill -9 "$IPID" 2>/dev/null || true
        reap_exit "$IPID" 10 || true
        [[ "${EXIT_STATUS[$IPID]}" == "137" ]] || I_OK=0
        touch "$DGO"
        wait "$I_BPID" 2>/dev/null || true
        [[ "$(backup_exit case-i)" == "3" ]] || I_OK=0
        complete_backup case-i "$CASE_DATA" "$CASE_DEST" "$IOP" || I_OK=0
        [[ "$(backup_exit case-i-complete)" == "0" ]] || I_OK=0
        if CAPTURE_ERR="$(verify_published_artifact "$CASE_DEST" "$IOP" "$CASE_DATA" 2>&1)"; then :; else I_OK=0; log "case-i artifact: $CAPTURE_ERR"; fi
        [[ "$(marker_count "$CASE_DATA")" == "0" ]] || I_OK=0
        start_daemon case-i2 "$CASE_DATA"
        if wait_ready case-i2 30; then
            sigterm_expect_zero case-i2 || I_OK=0
        else
            I_OK=0
        fi
    fi
    if (( I_OK )); then
        result PASS case-i "SIGKILL after transfer while the sender still exists: daemon exit 137, executor completed phase 1 (exit 3; capture does not depend on sender survival), offline signature published the artifact (exit 0), marker removed, restart ok"
    else
        result FAIL case-i "SIGKILL case broken: executor exit=$(backup_exit case-i) complete=$(backup_exit case-i-complete 2>/dev/null || echo '?') daemon exit=${EXIT_STATUS[$IPID]:-?}"
    fi
else
    result FAIL case-i "daemon not ready"
fi

# --- (j) Supervisor restart while the executor owns the lock --------------------
fresh_case_dirs case-j
start_daemon case-j "$CASE_DATA"
if wait_ready case-j 30; then
    JOP2="$(new_op_id)"
    READY="$WORK/case-j.ready"; GO="$WORK/case-j.go"
    rm -f "$READY" "$GO"
    run_backup case-j "$CASE_DATA" "$CASE_DEST" "$JOP2" \
        O3K_BACKUP_TEST_BARRIER_READY_FILE="$READY" O3K_BACKUP_TEST_BARRIER_WAIT_FILE="$GO" &
    J_BPID=$!
    J_OK=1
    J_DEADLINE=$((SECONDS + 40))
    while [[ ! -f "$READY" ]]; do
        if (( SECONDS >= J_DEADLINE )); then J_OK=0; break; fi
        sleep 0.1
    done
    if (( J_OK )); then
        # Bounded: a competitor that blocks instead of failing at the store
        # lock must fail this case, not hang the harness until CI timeout
        # (124 = killed by timeout).
        set +e
        env O3K_BOOTSTRAP_PASSWORD="$BOOTSTRAP_PASSWORD" O3K_TOKEN_SIGNING_KEY="$TOKEN_SIGNING_KEY" \
            O3K_NATIVE_CURSOR_HMAC_KEY="$NATIVE_CURSOR_KEY" \
            timeout 30 "$O3KD_BIN" --listen-addr "127.0.0.1:$(free_port)" --data-dir "$CASE_DATA" \
            --log-filter info --log-format json >"$WORK/case-j-competitor.log" 2>&1
        J_COMP_STATUS=$?
        set -e
        [[ "$J_COMP_STATUS" != "124" ]] || J_OK=0
        [[ "$J_COMP_STATUS" != "0" ]] || J_OK=0
        grep -q 'O3K data-directory lifetime lock' "$WORK/case-j-competitor.log" || J_OK=0
        if grep -qF 'o3kd listening' "$WORK/case-j-competitor.log"; then J_OK=0; fi
        touch "$GO"
        wait "$J_BPID" 2>/dev/null || true
        [[ "$(backup_exit case-j)" == "3" ]] || J_OK=0
        # The daemon must reach SOURCE_EXIT 0 after the lock transfer; a hang
        # here must fail the case, not pass silently.
        JP="$(daemon_pid case-j)"
        reap_exit "$JP" 30 && [[ "${EXIT_STATUS[$JP]}" == 0 ]] || J_OK=0
        complete_backup case-j "$CASE_DATA" "$CASE_DEST" "$JOP2" || J_OK=0
        [[ "$(backup_exit case-j-complete)" == "0" ]] || J_OK=0
        verify_published_artifact "$CASE_DEST" "$JOP2" "$CASE_DATA" >/dev/null 2>&1 || J_OK=0
    fi
    if (( J_OK )); then
        result PASS case-j "supervisor restart during executor ownership: competing o3kd exit $J_COMP_STATUS at the store lock, never served (packaging/o3kd.service systemd units use this same binary/startup path), then capture was staged and the offline signature published it"
    else
        result FAIL case-j "competing-controller case broken"
    fi
else
    result FAIL case-j "daemon not ready"
fi

# --- (k) Third-party store opener while the executor owns the lock --------------
fresh_case_dirs case-k
start_daemon case-k "$CASE_DATA"
if wait_ready case-k 30; then
    KOP="$(new_op_id)"
    READY="$WORK/case-k.ready"; GO="$WORK/case-k.go"
    rm -f "$READY" "$GO"
    run_backup case-k "$CASE_DATA" "$CASE_DEST" "$KOP" \
        O3K_BACKUP_TEST_BARRIER_READY_FILE="$READY" O3K_BACKUP_TEST_BARRIER_WAIT_FILE="$GO" &
    K_BPID=$!
    K_OK=1
    K_DEADLINE=$((SECONDS + 40))
    while [[ ! -f "$READY" ]]; do
        if (( SECONDS >= K_DEADLINE )); then K_OK=0; break; fi
        sleep 0.1
    done
    if (( K_OK )); then
        if ! python3 - "$CASE_DATA" >"$WORK/case-k.flock.txt" 2>&1 <<'PY'
import fcntl, os, sys
data_dir = sys.argv[1]
fd = os.open(os.path.join(data_dir, ".o3k-store.lock"), os.O_RDWR)
print("open(.o3k-store.lock) succeeded (the lock is advisory; open itself is not blocked)")
try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
except OSError as e:
    print(f"flock(LOCK_EX|LOCK_NB) on lock file correctly refused: {e}")
else:
    sys.exit("flock unexpectedly acquired while executor owns the lock")
dir_fd = os.open(data_dir, os.O_RDONLY)
try:
    fcntl.flock(dir_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
except OSError as e:
    print(f"flock(LOCK_EX|LOCK_NB) on data directory correctly refused: {e}")
else:
    sys.exit("directory flock unexpectedly acquired while executor owns the lock")
PY
        then K_OK=0; fi
        touch "$GO"
        wait "$K_BPID" 2>/dev/null || true
        [[ "$(backup_exit case-k)" == "3" ]] || K_OK=0
        KP="$(daemon_pid case-k)"
        reap_exit "$KP" 30 && [[ "${EXIT_STATUS[$KP]}" == 0 ]] || K_OK=0
        complete_backup case-k "$CASE_DATA" "$CASE_DEST" "$KOP" || K_OK=0
        [[ "$(backup_exit case-k-complete)" == "0" ]] || K_OK=0
        verify_published_artifact "$CASE_DEST" "$KOP" "$CASE_DATA" >/dev/null 2>&1 || K_OK=0
    fi
    if (( K_OK )); then
        result PASS case-k "third-party opener excluded: nonblocking exclusive flock refused on both the lock file and the data directory while the executor owns the lock ($(head -1 "$WORK/case-k.flock.txt" 2>/dev/null))"
    else
        result FAIL case-k "third-party opener not excluded: $(cat "$WORK/case-k.flock.txt" 2>/dev/null)"
    fi
else
    result FAIL case-k "daemon not ready"
fi

# --- (l) Interrupted staging and publication collision --------------------------
# l1: marker kept after staging (skip cleanup) -> restart MUST REFUSE -> clear ->
# offline signature publishes -> restart ok
fresh_case_dirs case-l1
start_daemon case-l1 "$CASE_DATA"
if wait_ready case-l1 30; then
    LOP1="$(new_op_id)"
    run_backup case-l1 "$CASE_DATA" "$CASE_DEST" "$LOP1" O3K_BACKUP_TEST_SKIP_MARKER_CLEANUP=1
    L1_OK=1
    [[ "$(backup_exit case-l1)" == "3" ]] || L1_OK=0
    [[ -f "$CASE_DEST/.o3k-backup-artifact-$LOP1/signing-request.json" ]] || L1_OK=0
    [[ ! -e "$CASE_DEST/backup-$LOP1.o3k" ]] || L1_OK=0
    [[ "$(marker_count "$CASE_DATA")" == "1" ]] || L1_OK=0
    L1PID="$(daemon_pid case-l1)"
    reap_exit "$L1PID" 30 && [[ "${EXIT_STATUS[$L1PID]}" == 0 ]] || L1_OK=0
    # Bounded: a restart attempt that blocks on the interrupted-backup marker
    # instead of exiting must fail this case, not hang the harness until CI
    # timeout (124 = killed by timeout).
    set +e
    env O3K_BOOTSTRAP_PASSWORD="$BOOTSTRAP_PASSWORD" O3K_TOKEN_SIGNING_KEY="$TOKEN_SIGNING_KEY" \
        O3K_NATIVE_CURSOR_HMAC_KEY="$NATIVE_CURSOR_KEY" \
        timeout 30 "$O3KD_BIN" --listen-addr "127.0.0.1:$(free_port)" --data-dir "$CASE_DATA" \
        --log-filter info --log-format json >"$WORK/case-l1-restart.log" 2>&1
    L1R_STATUS=$?
    set -e
    [[ "$L1R_STATUS" != "124" ]] || L1_OK=0
    [[ "$L1R_STATUS" != "0" ]] || L1_OK=0
    grep -q 'interrupted backup marker(s) present' "$WORK/case-l1-restart.log" || L1_OK=0
    rm -f "$CASE_DATA"/.o3k-backup-in-progress-*
    complete_backup case-l1 "$CASE_DATA" "$CASE_DEST" "$LOP1" || L1_OK=0
    [[ "$(backup_exit case-l1-complete)" == "0" ]] || L1_OK=0
    verify_published_artifact "$CASE_DEST" "$LOP1" "$CASE_DATA" >/dev/null 2>&1 || L1_OK=0
    start_daemon case-l1b "$CASE_DATA"
    if wait_ready case-l1b 30; then
        sigterm_expect_zero case-l1b || L1_OK=0
    else
        L1_OK=0
    fi
    if (( L1_OK )); then
        result PASS case-l1 "interrupted marker kept after staging (skip-cleanup hook): restart refused exit $L1R_STATUS with the interrupted-backup error; after operator marker removal the offline signature published the artifact (exit 0) and restart+SIGTERM ok"
    else
        result FAIL case-l1 "marker-denial restart broken (complete=$(backup_exit case-l1-complete 2>/dev/null || echo '?'))"
    fi
else
    result FAIL case-l1 "daemon not ready"
fi

# l2: publication collision -> exit 2, nothing replaced, staging kept, journal
# stays publishing; after the collision is cleared the retry publishes without
# needing the signature again.
fresh_case_dirs case-l2
start_daemon case-l2 "$CASE_DATA"
if wait_ready case-l2 30; then
    LOP2="$(new_op_id)"
    run_backup case-l2 "$CASE_DATA" "$CASE_DEST" "$LOP2"
    L2_OK=1
    [[ "$(backup_exit case-l2)" == "3" ]] || L2_OK=0
    [[ -f "$CASE_DEST/.o3k-backup-artifact-$LOP2/signing-request.json" ]] || L2_OK=0
    L2PID="$(daemon_pid case-l2)"
    reap_exit "$L2PID" 30 && [[ "${EXIT_STATUS[$L2PID]}" == 0 ]] || L2_OK=0
    # A pre-existing final artifact must never be replaced.
    printf 'pre-existing artifact\n' >"$CASE_DEST/backup-$LOP2.o3k"
    chmod 0600 "$CASE_DEST/backup-$LOP2.o3k"
    complete_backup case-l2 "$CASE_DATA" "$CASE_DEST" "$LOP2" || L2_OK=0
    [[ "$(backup_exit case-l2-complete)" == "2" ]] || L2_OK=0
    grep -q 'artifact-destination-exists' "$WORK/case-l2-complete.backup.stderr" || L2_OK=0
    [[ "$(cat "$CASE_DEST/backup-$LOP2.o3k")" == "pre-existing artifact" ]] || L2_OK=0
    # Staging is preserved and the journal records the attempted publication.
    [[ -d "$CASE_DEST/.o3k-backup-artifact-$LOP2" ]] || L2_OK=0
    python3 - "$CASE_DATA/backup-operations/$LOP2.json" "$LOP2" <<'PY'
import json, sys
journal = json.load(open(sys.argv[1]))
assert journal["operation_id"] == sys.argv[2]
assert journal["phase"] == "publishing", journal
assert journal["artifact_sha256"], journal
PY
    [[ $? == 0 ]] || L2_OK=0
    # Clearing the collision lets the same request finish publication.
    rm -f "$CASE_DEST/backup-$LOP2.o3k"
    run_backup case-l2b "$CASE_DATA" "$CASE_DEST" "$LOP2"
    [[ "$(backup_exit case-l2b)" == "0" ]] || L2_OK=0
    verify_published_artifact "$CASE_DEST" "$LOP2" "$CASE_DATA" >/dev/null 2>&1 || L2_OK=0
    start_daemon case-l2b "$CASE_DATA"
    if wait_ready case-l2b 30; then
        sigterm_expect_zero case-l2b || L2_OK=0
    else
        L2_OK=0
    fi
    if (( L2_OK )); then
        result PASS case-l2 "publication collision: phase 2 exit 2 artifact-destination-exists, pre-existing artifact untouched, staging and journal preserved (phase publishing), nothing published; after clearing the collision the retry published (exit 0) and restart ok"
    else
        result FAIL case-l2 "publication-collision case broken: phase1=$(backup_exit case-l2) phase2=$(backup_exit case-l2-complete 2>/dev/null || echo '?') retry=$(backup_exit case-l2b 2>/dev/null || echo '?') stderr=$(backup_stderr case-l2-complete 2>/dev/null || true)"
    fi
else
    result FAIL case-l2 "daemon not ready"
fi

# --- (m) Source mutation during capture (DOCUMENTED, not real-process reproducible)
result DOCUMENTED case-m "source mutation during capture is not reproducible real-process: the transferred flock excludes all writers while the executor holds the only lock descriptors, and backup_to_file additionally holds a BEGIN IMMEDIATE writer exclusion (crates/o3k-store/src/sqlite/core.rs). The residual path is enforced by the SHA-256 before/after check in bins/o3k/src/backup_create.rs (exit 4 unknown); unit coverage: backup_snapshot_holds_writer_exclusion_until_snapshot_finishes, backup_writer_exclusion_blocks_external_sqlite_writers"

# --- (n) Auth-reject reason spot checks -----------------------------------------
fresh_case_dirs case-n1
start_daemon case-n1 "$CASE_DATA"
if wait_ready case-n1 30; then
    # n1: executor pointed at a COPY of the data dir (different installation binding)
    N_COPY="$WORK/case-n1-copy"
    mkdir -p "$N_COPY/control" "$WORK/case-n1-dest"
    chmod 0700 "$N_COPY" "$N_COPY/control" "$WORK/case-n1-dest"
    cp "$CASE_DATA/o3k.sqlite" "$N_COPY/o3k.sqlite"
    NOP1="$(new_op_id)"
    set +e
    env O3K_DATA_DIR="$N_COPY" "$O3K_BIN" backup create --destination "$WORK/case-n1-dest" --operation-id "$NOP1" \
        >"$WORK/case-n1.backup.json" 2>"$WORK/case-n1.backup.stderr"
    N1_STATUS=$?
    set -e
    N1_OK=1
    [[ "$N1_STATUS" == "2" ]] || N1_OK=0
    grep -q 'controller-unavailable' "$WORK/case-n1.backup.stderr" || N1_OK=0
    if (( N1_OK )); then
        result PASS case-n1 "wrong installation binding (data-dir copy): exit 2 controller-unavailable (no live control socket in the copy); in-band identity-mismatch is unit-covered by rejects_wrong_installation_or_site_token — both sides derive tokens from the same canonical dir, so a real mismatch cannot reach a live daemon"
    else
        result FAIL case-n1 "copy-dir case: status=$N1_STATUS stderr=$(cat "$WORK/case-n1.backup.stderr")"
    fi
    # n3: second daemon instance on the same data dir fails at the store lock first.
    # Bounded: it must fail there, not block (124 = killed by timeout).
    set +e
    env O3K_BOOTSTRAP_PASSWORD="$BOOTSTRAP_PASSWORD" O3K_TOKEN_SIGNING_KEY="$TOKEN_SIGNING_KEY" \
        O3K_NATIVE_CURSOR_HMAC_KEY="$NATIVE_CURSOR_KEY" \
        timeout 30 "$O3KD_BIN" --listen-addr "127.0.0.1:$(free_port)" --data-dir "$CASE_DATA" \
        --log-filter info --log-format json >"$WORK/case-n3.log" 2>&1
    N3_STATUS=$?
    set -e
    N3_OK=1
    [[ "$N3_STATUS" != "124" ]] || N3_OK=0
    [[ "$N3_STATUS" != "0" ]] || N3_OK=0
    grep -q 'O3K data-directory lifetime lock' "$WORK/case-n3.log" || N3_OK=0
    if (( N3_OK )); then
        result PASS case-n3 "second daemon on same data dir: exit $N3_STATUS at the store lock before the control socket bind while the first daemon lives"
    else
        result FAIL case-n3 "second-daemon case: status=$N3_STATUS"
    fi
    # n4: stale control socket replacement after SIGKILL
    N4_OK=1
    N1PID="$(daemon_pid case-n1)"
    kill -9 "$N1PID" 2>/dev/null || true
    reap_exit "$N1PID" 10 || true
    [[ "${EXIT_STATUS[$N1PID]}" == "137" ]] || N4_OK=0
    if [[ -S "$CASE_DATA/control/backup.sock" ]]; then N4_SOCK=1; else N4_SOCK=0; fi
    start_daemon case-n4 "$CASE_DATA"
    if wait_ready case-n4 30; then
        sigterm_expect_zero case-n4 || N4_OK=0
    else
        N4_OK=0
    fi
    if (( N4_OK )); then
        result PASS case-n4 "stale control socket after SIGKILL (present: $N4_SOCK): replacement daemon reached ready + SIGTERM exit 0 (what this case asserts); the owner/type check + rebind itself is unit-covered (bind_refuses_non_socket_at_socket_path, stale_socket_file_is_replaced_at_bind)"
    else
        result FAIL case-n4 "stale-socket replacement broken"
    fi
else
    result FAIL case-n1 "daemon not ready"
fi

echo
echo "== Matrix summary =="
printf '%-12s %-11s %s\n' CASE RESULT DETAIL
for row in "${RESULTS[@]}"; do
    IFS='|' read -r r c d <<<"$row"
    printf '%-12s %-11s %s\n' "$c" "$r" "$d"
done
echo
if (( FAIL_COUNT == 0 )); then
    echo "PP6-BACKUP-HANDOFF PASS: $PASS_COUNT executed checks passed, $DOC_COUNT documented-coverage rows, 0 failures"
    exit 0
else
    echo "PP6-BACKUP-HANDOFF FAIL: $FAIL_COUNT failure(s), $PASS_COUNT passed" >&2
    exit 1
fi
