#!/usr/bin/env bash
# PP.6 / #1085 PostgreSQL 16 control-plane backup campaign.
#
# Runs only inside a disposable `pg_virtualenv` PostgreSQL 16 cluster. The
# campaign fails (never skips) when PG16 tooling is absent. It exercises the
# real D4 writer-exclusion barrier, `pg_dump`, complete unfiltered TOC
# classification, the existing encrypted/Ed25519-signed artifact flow, and
# PostgreSQL artifact verification.
#
# Evidence rows record PASS, FAIL or an explicit NOT-COVERED reason. Unit-level
# TOC/barrier classification is executed from the Rust test suite and counted
# only on a zero exit. Cases needing a second host, an independent firewall or
# a managed PostgreSQL control plane are reported as NOT-COVERED.
set -euo pipefail

if [[ "${PP6_PG16_BACKUP_INNER:-0}" != 1 ]]; then
    exec env PP6_PG16_BACKUP_INNER=1 pg_virtualenv "$0"
fi

if [[ "${PGVERSION:-}" != 16 ]]; then
    printf 'FATAL: expected PostgreSQL 16, got %s\n' "${PGVERSION:-unset}" >&2
    exit 2
fi
for tool in psql pg_dump pg_restore createdb dropdb openssl xxd sha256sum python3 cargo; do
    command -v "$tool" >/dev/null 2>&1 || {
        printf 'FATAL: missing required PostgreSQL 16 tool: %s\n' "$tool" >&2
        exit 2
    }
done
pg_dump --version | grep -q ' 16\.' || { echo 'FATAL: pg_dump is not PostgreSQL 16' >&2; exit 2; }
pg_restore --version | grep -q ' 16\.' || { echo 'FATAL: pg_restore is not PostgreSQL 16' >&2; exit 2; }

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "== build: o3k with backup-test-hooks =="
CARGO_TARGET_DIR="$ROOT_DIR/target" cargo build -p o3k --features o3k/backup-test-hooks 2>&1 | tail -2
O3K_BIN="$ROOT_DIR/target/debug/o3k"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/o3k-pp6-pg16.XXXXXX")"
chmod 0700 "$WORK"
DATA="$WORK/data"; DEST_ROOT="$WORK/dest"; CFG="$WORK/cfg"; PREFIX="$WORK/install"
mkdir -p "$DATA" "$DEST_ROOT" "$CFG" "$PREFIX/share/o3k" "$PREFIX/etc/o3k"
chmod -R 0700 "$WORK"

HBA="$(psql -X -qAt -c 'show hba_file')"
PGDATA_DIR="$(psql -X -qAt -c 'show data_directory')"
PRISTINE_HBA="$WORK/pg_hba.pristine"
cp "$HBA" "$PRISTINE_HBA"
SAVED="$HBA.o3k-pp6-saved"
SAVED_DIGEST="$HBA.o3k-pp6-saved.sha256"

# ---------------------------------------------------------------------------
# Matrix bookkeeping
# ---------------------------------------------------------------------------
PASS_COUNT=0; FAIL_COUNT=0; NA_COUNT=0
record() { # record <PASS|FAIL|NOT-COVERED> <case> <detail>
    case "$1" in
        PASS) PASS_COUNT=$((PASS_COUNT + 1)); printf 'PASS  [%s] %s\n' "$2" "$3" ;;
        FAIL) FAIL_COUNT=$((FAIL_COUNT + 1)); printf 'FAIL  [%s] %s\n' "$2" "$3" ;;
        *)    NA_COUNT=$((NA_COUNT + 1)); printf 'N/A   [%s] %s\n' "$2" "$3" ;;
    esac
}

cleanup() {
    set +e
    if [[ -f "$PRISTINE_HBA" ]]; then cp "$PRISTINE_HBA" "$HBA"; fi
    rm -f "$SAVED" "$SAVED_DIGEST"
    signal_reload || true
    for db in ${DBS[@]+"${DBS[@]}"}; do dropdb --if-exists "$db" >/dev/null 2>&1; done
    psql -X -q -v ON_ERROR_STOP=0 -c 'DROP ROLE IF EXISTS o3k_rogue' >/dev/null 2>&1
    psql -X -q -v ON_ERROR_STOP=0 -c 'DROP ROLE IF EXISTS o3k_rogue2' >/dev/null 2>&1
    rm -rf -- "$WORK"
}
DBS=()
trap cleanup EXIT

signal_reload() {
    local pid
    pid="$(head -1 "$PGDATA_DIR/postmaster.pid" 2>/dev/null || true)"
    [[ -n "$pid" ]] && kill -HUP "$pid" 2>/dev/null
}

json_get() { python3 - "$1" "$2" <<'PY'
import json, sys
try:
    print(json.load(open(sys.argv[1])).get(sys.argv[2], ""))
except Exception:
    print("")
PY
}

new_op() { python3 -c 'import uuid; print(uuid.uuid4())'; }
new_db() {
    echo "o3k_pp6_$1_$$_${RANDOM}${RANDOM}"
}

# ---------------------------------------------------------------------------
# Custody fixture (the binary never reads the signing/recipient private keys)
# ---------------------------------------------------------------------------
SIGN_KEY="$WORK/signing.pem"; FOREIGN_KEY="$WORK/foreign.pem"
REC_KEY="$WORK/recipient.key"; REC_PEM="$WORK/recipient.pem"
openssl genpkey -algorithm ED25519 -out "$SIGN_KEY" 2>/dev/null
openssl genpkey -algorithm ED25519 -out "$FOREIGN_KEY" 2>/dev/null
openssl pkey -in "$SIGN_KEY" -pubout -outform DER 2>/dev/null | tail -c 32 | xxd -p -c 64 > "$WORK/signing.hex"
openssl genpkey -algorithm X25519 -out "$REC_PEM" 2>/dev/null
openssl pkey -in "$REC_PEM" -outform DER 2>/dev/null | tail -c 32 > "$REC_KEY"
openssl pkey -in "$REC_PEM" -pubout -outform DER 2>/dev/null | tail -c 32 | xxd -p -c 64 > "$WORK/recipient.hex"
chmod 0600 "$SIGN_KEY" "$FOREIGN_KEY" "$REC_KEY"
SIGN_PUBLIC="$(cat "$WORK/signing.hex")"
REC_PUBLIC="$(cat "$WORK/recipient.hex")"

identity_hex() { python3 - "$1" "$2" <<'PY'
import hashlib, os, sys
print(hashlib.sha256(sys.argv[1].encode() + b"\x00" + os.fsencode(os.path.realpath(sys.argv[2]))).digest()[:16].hex())
PY
}
SITE="$(identity_hex o3k-backup-site-identity-v1 "$DATA")"
INSTALLATION="$(identity_hex o3k-backup-installation-identity-v1 "$DATA")"

write_trust() { # write_trust <path> [site] [installation]
    local path="$1" site="${2:-$SITE}" installation="${3:-$INSTALLATION}"
    python3 - "$path" "$site" "$installation" "$SIGN_PUBLIC" "$REC_KEY" "$REC_PUBLIC" <<'PY'
import hashlib, json, sys
path, site, installation, public, recipient_key, recipient_public = sys.argv[1:7]
public_bytes = bytes.fromhex(public)
json.dump({
    "format": "o3k-backup-trust-v1",
    "site_id": site,
    "installation_id": installation,
    "profile_id": "o3k-small-edge-v1",
    "artifact_signing": {"key_id": "signing-1", "ed25519_public_key": public},
    "recipient": {
        "key_id": "recovery-1",
        "x25519_private_key_file": recipient_key,
        "x25519_public_key": recipient_public,
    },
    "revoked_key_ids": [],
    "custody": {
        "record_id": "custody-1",
        "purpose": "artifact-signing",
        "key_fingerprint": hashlib.sha256(public_bytes).hexdigest(),
        "threshold": "2-of-3",
        "custodians": ["a", "b", "c"],
        "storage_class": "offline-safe",
        "expires_at": "2035-01-01T00:00:00Z",
    },
}, open(path, "w"))
PY
    chmod 0600 "$path"
}
TRUST="$WORK/trust.json"
write_trust "$TRUST"

write_release() { # write_release <schema-version>
    python3 - "$PREFIX/share/o3k/release-manifest.json" "${1:-36}" <<'PY'
import json, sys
json.dump({
    "version": "0.4.0",
    "profile": "small-edge",
    "profile_id": "o3k-small-edge-v1",
    "source_commit": "0123456789abcdef0123456789abcdef01234567",
    "release_artifact_sha256": "a" * 64,
    "schema_version": int(sys.argv[2]),
}, open(sys.argv[1], "w"))
PY
    chmod 0600 "$PREFIX/share/o3k/release-manifest.json"
}
write_release 36

write_pg_config() { # write_pg_config <db> <path>
    python3 - "$1" "$2" "$HBA" "$PGDATA_DIR" "${PGPORT:-5432}" <<'PY'
import json, sys
db, path, hba, data, port = sys.argv[1:6]
json.dump({
    "control_database_url": f"postgres://ubuntu@%2Ftmp:{port}/{db}",
    "dump_database_url": f"postgres://o3k_backup_dump@127.0.0.1:{port}/{db}",
    "probe_database_urls": [
        f"postgres://o3k_runtime@127.0.0.1:{port}/{db}",
        f"postgres://o3k_runtime@%2Ftmp:{port}/{db}",
        f"postgres://o3k_runtime@127.0.0.1:{port}/postgres",
    ],
    "database": db,
    "backup_host": "127.0.0.1",
    "dump_role": "o3k_backup_dump",
    "writer_roles": ["o3k_runtime"],
    "restore_role": "o3k_restore_owner",
    "control_role": "ubuntu",
    "dump_auth_method": "trust",
    "hba_path": hba,
    "data_directory": data,
}, open(path, "w"))
PY
    chmod 0600 "$2"
}

# ---------------------------------------------------------------------------
# Database/role fixture
# ---------------------------------------------------------------------------
ensure_roles() {
    psql -X -q -v ON_ERROR_STOP=1 <<'SQL'
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'o3k_runtime') THEN
    CREATE ROLE o3k_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'o3k_backup_dump') THEN
    CREATE ROLE o3k_backup_dump NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'o3k_restore_owner') THEN
    CREATE ROLE o3k_restore_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
  END IF;
END $$;
ALTER ROLE o3k_runtime LOGIN;
ALTER ROLE o3k_backup_dump NOLOGIN;
ALTER ROLE o3k_restore_owner NOLOGIN;
SQL
}

prepare_db() { # prepare_db <name> -> echoes database name
    local db="$1"
    ensure_roles
    createdb "$db"
    DBS+=("$db")
    for migration in "$ROOT_DIR"/crates/o3k-store/migrations_postgres/*.sql; do
        psql -X -q -v ON_ERROR_STOP=1 -d "$db" -f "$migration" >/dev/null 2>&1
    done
    psql -X -q -v ON_ERROR_STOP=1 -d "$db" <<'SQL'
CREATE TABLE IF NOT EXISTS _sqlx_migrations (
    version BIGINT PRIMARY KEY,
    description TEXT NOT NULL,
    installed_on TIMESTAMPTZ NOT NULL DEFAULT now(),
    success BOOLEAN NOT NULL,
    checksum BYTEA NOT NULL,
    execution_time BIGINT NOT NULL
);
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO o3k_runtime, o3k_backup_dump, o3k_restore_owner;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO o3k_runtime;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO o3k_backup_dump;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO o3k_runtime;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO o3k_backup_dump;
SQL
    python3 - "$db" "$ROOT_DIR" <<'PY'
import hashlib, os, subprocess, sys
db, root = sys.argv[1:3]
directory = os.path.join(root, "crates/o3k-store/migrations_postgres")
for name in sorted(x for x in os.listdir(directory) if x.endswith(".sql")):
    version = int(name.split("_")[0])
    raw = open(os.path.join(directory, name), "rb").read()
    checksum = hashlib.sha384(raw).hexdigest()
    subprocess.run([
        "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", db, "-c",
        f"INSERT INTO _sqlx_migrations(version,description,success,checksum,execution_time) "
        f"VALUES ({version},'{name[:-4]}',true,'\\x{checksum}',0)",
    ], check=True)
PY
    echo "$db"
}

reset_barrier_state() {
    cp "$PRISTINE_HBA" "$HBA"
    rm -f "$SAVED" "$SAVED_DIGEST"
    signal_reload
    sleep 0.2
}

controls_connect() { # controls_connect <db>
    psql -X -qAt "postgres://ubuntu@%2Ftmp:${PGPORT:-5432}/$1" -c 'select 1' >/dev/null 2>&1
}

common_env() { # common_env <db> <pg-config> [extra key=value ...]
    local db="$1" pgcfg="$2"; shift 2
    env \
        O3K_DATA_DIR="$DATA" \
        O3K_DATABASE_BACKEND=postgres \
        O3K_CONFIG_DIR="$CFG" \
        O3K_BACKUP_TRUST_CONFIG="$TRUST" \
        O3K_INSTALL_PREFIX="$PREFIX" \
        O3K_PG_BACKUP_CONFIG="$pgcfg" \
        "$@"
}

start_create() { # start_create <case> <db> <dest> <op> [extra key=value ...]
    local case_id="$1" db="$2" dest="$3" op="$4"; shift 4
    local pgcfg="$WORK/$case_id.pg.json"
    write_pg_config "$db" "$pgcfg"
    common_env "$db" "$pgcfg" "$@" "$O3K_BIN" backup create \
        --destination "$dest" --operation-id "$op" \
        >"$WORK/$case_id.create.json" 2>"$WORK/$case_id.create.err" &
    echo $!
}

wait_request() { # wait_request <dest> <op> [seconds]
    local request="$1/.o3k-backup-artifact-$2/signing-request.json"
    local deadline=$((SECONDS + ${3:-60}))
    while (( SECONDS < deadline )); do
        [[ -f "$request" ]] && return 0
        sleep 0.05
    done
    return 1
}

sign_request() { # sign_request <dest> <op> [signing-key]
    local staging="$1/.o3k-backup-artifact-$2" key="${3:-$SIGN_KEY}"
    python3 - "$staging/signing-request.json" "$WORK/sign.bin" "$WORK/sign.meta" <<'PY'
import base64, hashlib, json, sys
request = json.load(open(sys.argv[1]))
encoded = request["signing_input_base64url"]
data = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
assert hashlib.sha256(data).hexdigest() == request["signing_input_sha256"]
open(sys.argv[2], "wb").write(data)
json.dump({
    "request_sha256": hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest(),
    "key_id": request["key_id"],
    "created_at": request["created_at"],
}, open(sys.argv[3], "w"))
PY
    openssl pkeyutl -sign -rawin -inkey "$key" -in "$WORK/sign.bin" -out "$WORK/sign.sig" 2>/dev/null
    python3 - "$WORK/sign.sig" "$WORK/sign.meta" "$staging" <<'PY'
import json, os, sys
signature = open(sys.argv[1], "rb").read()
meta = json.load(open(sys.argv[2]))
staging = sys.argv[3]
response = {
    "format": "o3k-backup-signing-response-v1",
    "request_sha256": meta["request_sha256"],
    "key_id": meta["key_id"],
    "signature": signature.hex(),
    "signed_at": meta["created_at"],
}
temporary = os.path.join(staging, ".response.tmp")
with open(temporary, "w") as handle:
    json.dump(response, handle)
    handle.flush()
    os.fsync(handle.fileno())
os.chmod(temporary, 0o600)
os.replace(temporary, os.path.join(staging, "signing-response.json"))
PY
}

wait_pid() { # wait_pid <pid> -> exit code in WAIT_RC
    set +e
    wait "$1"
    WAIT_RC=$?
    set -e
}

assert_no_artifact() { # assert_no_artifact <dest>
    ! compgen -G "$1/backup-*.o3k" >/dev/null
}

# ---------------------------------------------------------------------------
# Case A: real capture, publication, verification and writer exclusion
# ---------------------------------------------------------------------------
case_happy() {
    local db dest op pgcfg pid rc
    db="$(new_db happy)"; dest="$WORK/happy-dest"; mkdir -p "$dest"; chmod 700 "$dest"
    pgcfg="$WORK/happy.pg.json"
    prepare_db "$db" >/dev/null
    reset_barrier_state
    write_pg_config "$db" "$pgcfg"
    op="$(new_op)"
    common_env "$db" "$pgcfg" "$O3K_BIN" backup create --destination "$dest" --operation-id "$op" \
        >"$WORK/happy.create.json" 2>"$WORK/happy.create.err" &
    pid=$!
    if ! wait_request "$dest" "$op" 90; then
        kill "$pid" 2>/dev/null || true
        record FAIL case-a-happy "no signing request"
        return
    fi
    local denied=0
    psql -X -qAt "postgres://o3k_runtime@127.0.0.1:${PGPORT:-5432}/$db" -c 'select 1' >/dev/null 2>&1 || denied=$((denied + 1))
    psql -X -qAt "postgres://o3k_runtime@%2Ftmp:${PGPORT:-5432}/$db" -c 'select 1' >/dev/null 2>&1 || denied=$((denied + 1))
    psql -X -qAt "postgres://o3k_runtime@127.0.0.1:${PGPORT:-5432}/postgres" -c 'select 1' >/dev/null 2>&1 || denied=$((denied + 1))
    if [[ "$denied" == 3 ]]; then
        record PASS case-b-reconnect-denied "TCP application, Unix-socket and maintenance reconnects denied during the barrier"
    else
        record FAIL case-b-reconnect-denied "only $denied/3 fresh writer reconnects were denied"
    fi
    sign_request "$dest" "$op"
    wait_pid "$pid"; rc=$WAIT_RC
    if [[ "$rc" == 0 && -f "$dest/backup-$op.o3k" ]]; then
        record PASS case-a-happy "capture + offline signing + publication rc=0"
    else
        record FAIL case-a-happy "rc=$rc reason=$(json_get "$WORK/happy.create.json" reason)"
        return
    fi
    if [[ ! -e "$SAVED" && ! -e "$SAVED_DIGEST" ]] && controls_connect "$db"; then
        record PASS case-e-admission-restored "saved admission removed and control role reconnects after publication"
    else
        record FAIL case-e-admission-restored "admission was not restored after publication"
    fi
    local pgcfg_path="$pgcfg"
    common_env "$db" "$pgcfg_path" "$O3K_BIN" backup verify --artifact "$dest/backup-$op.o3k" \
        >"$WORK/happy.verify.json" 2>"$WORK/happy.verify.err"
    if [[ "$(json_get "$WORK/happy.verify.json" status)" == verified ]] \
        && python3 - "$WORK/happy.verify.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1]))
names = {member["name"] for member in value["members"]}
assert value["manifest"]["store_backend"] == "postgresql"
assert names == {"database/o3k.dump", "metadata/capture.json", "release/release-manifest.json", "trust/backup-trust.json"}, names
PY
    then
        record PASS case-a-verify "PostgreSQL artifact verified with the database/o3k.dump member"
    else
        record FAIL case-a-verify "verify failed: $(json_get "$WORK/happy.verify.json" reason)"
    fi
    # Replay: same operation id is idempotent.
    common_env "$db" "$pgcfg_path" "$O3K_BIN" backup create --destination "$dest" --operation-id "$op" \
        >"$WORK/replay.json" 2>"$WORK/replay.err" || true
    if [[ "$(json_get "$WORK/replay.json" status)" == backup-published ]]; then
        record PASS case-l-replay "published operation replay is idempotent"
    else
        record FAIL case-l-replay "replay was not idempotent: $(json_get "$WORK/replay.json" reason)"
    fi
    printf 'x' >> "$dest/backup-$op.o3k"
    set +e
    common_env "$db" "$pgcfg_path" "$O3K_BIN" backup create --destination "$dest" --operation-id "$op" \
        >"$WORK/replay-conflict.json" 2>"$WORK/replay-conflict.err"
    local conflict_rc=$?
    set -e
    conflict_reason="$(json_get "$WORK/replay-conflict.json" reason)"
    if [[ "$conflict_rc" == 2 && ( "$conflict_reason" == artifact-destination-exists || "$conflict_reason" == published-artifact-changed ) ]]; then
        record PASS case-l-replay-conflict "changed published bytes are rejected (replay conflict)"
    else
        record FAIL case-l-replay-conflict "rc=$conflict_rc reason=$(json_get "$WORK/replay-conflict.json" reason)"
    fi
}

# ---------------------------------------------------------------------------
# Case C: a retained writer session is terminated by the barrier
# ---------------------------------------------------------------------------
case_retained_writer() {
    local db dest op pgcfg pid psql_pid rc
    db="$(new_db retained)"; dest="$WORK/retained-dest"; mkdir -p "$dest"; chmod 700 "$dest"
    pgcfg="$WORK/retained.pg.json"
    prepare_db "$db" >/dev/null
    reset_barrier_state
    write_pg_config "$db" "$pgcfg"
    psql -X -qAt "postgres://ubuntu@%2Ftmp:${PGPORT:-5432}/$db" -c 'select pg_sleep(120)' >/dev/null 2>"$WORK/retained.psql" &
    psql_pid=$!
    sleep 0.5
    op="$(new_op)"
    common_env "$db" "$pgcfg" "$O3K_BIN" backup create --destination "$dest" --operation-id "$op" \
        >"$WORK/retained.create.json" 2>"$WORK/retained.create.err" &
    pid=$!
    if ! wait_request "$dest" "$op" 90; then
        kill "$pid" "$psql_pid" 2>/dev/null || true
        record FAIL case-c-retained-writer "no signing request"
        return
    fi
    set +e
    wait "$psql_pid"
    local psql_rc=$?
    set -e
    if [[ "$psql_rc" != 0 ]]; then
        record PASS case-c-retained-writer "retained writer session was terminated"
    else
        record FAIL case-c-retained-writer "retained writer session survived the barrier"
    fi
    sign_request "$dest" "$op"
    wait_pid "$pid"; rc=$WAIT_RC
    [[ "$rc" == 0 ]] || record FAIL case-c-retained-writer "capture rc=$rc"
}

# ---------------------------------------------------------------------------
# Case D: safe abort restores admission
# ---------------------------------------------------------------------------
case_safe_abort() {
    local db dest op pgcfg rc
    db="$(new_db abort)"; dest="$WORK/abort-dest"; mkdir -p "$dest"; chmod 700 "$dest"
    pgcfg="$WORK/abort.pg.json"
    prepare_db "$db" >/dev/null
    reset_barrier_state
    write_pg_config "$db" "$pgcfg"
    op="$(new_op)"
    set +e
    common_env "$db" "$pgcfg" O3K_BACKUP_TEST_STOP_AFTER_STAGING=1 \
        "$O3K_BIN" backup create --destination "$dest" --operation-id "$op" \
        >"$WORK/abort.json" 2>"$WORK/abort.err"
    rc=$?
    set -e
    if [[ "$rc" == 3 && "$(json_get "$WORK/abort.json" status)" == signing-required ]] \
        && [[ ! -e "$SAVED" ]] && controls_connect "$db"; then
        record PASS case-d-safe-abort "staged capture aborted safely and admission was restored"
    else
        record FAIL case-d-safe-abort "rc=$rc status=$(json_get "$WORK/abort.json" status)"
    fi
}

# ---------------------------------------------------------------------------
# Case E: barrier loss aborts the capture
# ---------------------------------------------------------------------------
case_barrier_loss() {
    local db dest op pgcfg pid rc
    db="$(new_db loss)"; dest="$WORK/loss-dest"; mkdir -p "$dest"; chmod 700 "$dest"
    pgcfg="$WORK/loss.pg.json"
    prepare_db "$db" >/dev/null
    reset_barrier_state
    write_pg_config "$db" "$pgcfg"
    op="$(new_op)"
    rm -f "$WORK/barrier.ready" "$WORK/barrier.release"
    common_env "$db" "$pgcfg" \
        O3K_BACKUP_TEST_BARRIER_READY_FILE="$WORK/barrier.ready" \
        O3K_BACKUP_TEST_BARRIER_RELEASE_FILE="$WORK/barrier.release" \
        "$O3K_BIN" backup create --destination "$dest" --operation-id "$op" \
        >"$WORK/loss.json" 2>"$WORK/loss.err" &
    pid=$!
    for _ in $(seq 1 600); do [[ -f "$WORK/barrier.ready" ]] && break; sleep 0.05; done
    if [[ ! -f "$WORK/barrier.ready" ]]; then
        kill "$pid" 2>/dev/null || true
        record FAIL case-f-barrier-loss "barrier pause was never reached"
        return
    fi
    cp "$PRISTINE_HBA" "$HBA"
    signal_reload
    sleep 0.3
    touch "$WORK/barrier.release"
    wait_pid "$pid"; rc=$WAIT_RC
    if [[ "$rc" == 2 ]] && assert_no_artifact "$dest"; then
        record PASS case-f-barrier-loss "changed pg_hba.conf aborted capture before publication"
    else
        record FAIL case-f-barrier-loss "rc=$rc artifact=$(compgen -G "$dest/backup-*.o3k" || true)"
    fi
    reset_barrier_state
}

# ---------------------------------------------------------------------------
# Case F: interrupted dump is quarantined and admission recovers
# ---------------------------------------------------------------------------
case_interrupted_dump() {
    local db dest op pgcfg pid rc retry
    db="$(new_db crash)"; dest="$WORK/crash-dest"; mkdir -p "$dest"; chmod 700 "$dest"
    pgcfg="$WORK/crash.pg.json"
    prepare_db "$db" >/dev/null
    reset_barrier_state
    write_pg_config "$db" "$pgcfg"
    op="$(new_op)"
    set +e
    common_env "$db" "$pgcfg" O3K_BACKUP_TEST_EXIT_AFTER_DUMP=1 \
        "$O3K_BIN" backup create --destination "$dest" --operation-id "$op" \
        >"$WORK/crash.json" 2>"$WORK/crash.err"
    rc=$?
    set -e
    if [[ "$rc" != 88 || ! -e "$SAVED" ]]; then
        record FAIL case-g-interrupted-dump "expected hard exit 88 with saved admission, got rc=$rc"
        reset_barrier_state
        return
    fi
    if assert_no_artifact "$dest"; then
        record PASS case-g-interrupted-dump "interrupted dump is not published"
    else
        record FAIL case-g-interrupted-dump "interrupted dump published an artifact"
    fi
    set +e
    common_env "$db" "$pgcfg" O3K_BACKUP_TEST_STOP_AFTER_STAGING=1 \
        "$O3K_BIN" backup create --destination "$dest" --operation-id "$(new_op)" \
        >"$WORK/crash-retry.json" 2>"$WORK/crash-retry.err"
    retry=$?
    set -e
    if [[ "$retry" == 3 && ! -e "$SAVED" ]] && controls_connect "$db"; then
        record PASS case-g-admission-crash-recovery "next invocation restored admission after the crash"
    else
        record FAIL case-g-admission-crash-recovery "retry rc=$retry saved=$([[ -e "$SAVED" ]] && echo yes || echo no)"
    fi
}

# ---------------------------------------------------------------------------
# Case G/H/I/J: metadata, role and signature rejection
# ---------------------------------------------------------------------------
case_rejections() {
    local db dest op pgcfg rc reason
    prepare_case() {
        db="$(new_db reject)"; dest="$WORK/reject-dest-$1"; mkdir -p "$dest"; chmod 700 "$dest"
        pgcfg="$WORK/reject-$1.pg.json"
        prepare_db "$db" >/dev/null
        reset_barrier_state
        write_pg_config "$db" "$pgcfg"
        op="$(new_op)"
    }
    run_expect_reject() { # <case> <expected-reason> [env ...]
        local case_id="$1" expected="$2"; shift 2
        set +e
        common_env "$db" "$pgcfg" "$@" "$O3K_BIN" backup create --destination "$dest" --operation-id "$op" \
            >"$WORK/$case_id.json" 2>"$WORK/$case_id.err"
        rc=$?
        set -e
        reason="$(json_get "$WORK/$case_id.json" reason)"
        if [[ "$rc" == 2 && "$reason" == "$expected" ]] && assert_no_artifact "$dest"; then
            record PASS "$case_id" "rejected rc=2 reason=$expected"
        else
            record FAIL "$case_id" "rc=$rc reason=$reason expected=$expected"
        fi
    }

    prepare_case migration
    write_release 35
    run_expect_reject case-h-migration-mismatch migration-schema-mismatch O3K_BACKUP_TEST_STOP_AFTER_STAGING=1
    write_release 36

    prepare_case rogue
    psql -X -q -v ON_ERROR_STOP=1 -c 'DROP ROLE IF EXISTS o3k_rogue; CREATE ROLE o3k_rogue LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS' >/dev/null
    run_expect_reject case-i-unknown-role unexpected-login-role O3K_BACKUP_TEST_STOP_AFTER_STAGING=1
    psql -X -q -c 'DROP ROLE IF EXISTS o3k_rogue' >/dev/null

    prepare_case privileged
    psql -X -q -v ON_ERROR_STOP=1 -c 'CREATE ROLE o3k_rogue2 LOGIN SUPERUSER' >/dev/null
    run_expect_reject case-j-unexpected-login unexpected-login-role O3K_BACKUP_TEST_STOP_AFTER_STAGING=1
    psql -X -q -c 'DROP ROLE IF EXISTS o3k_rogue2' >/dev/null

    prepare_case privileged_expected
    psql -X -q -v ON_ERROR_STOP=1 -c 'ALTER ROLE o3k_runtime SUPERUSER' >/dev/null
    run_expect_reject case-j2-writer-privileged writer-role-privileged O3K_BACKUP_TEST_STOP_AFTER_STAGING=1
    psql -X -q -v ON_ERROR_STOP=1 -c 'ALTER ROLE o3k_runtime NOSUPERUSER LOGIN' >/dev/null

    prepare_case membership
    psql -X -q -v ON_ERROR_STOP=1 -c 'CREATE ROLE o3k_rogue2 NOLOGIN; GRANT o3k_rogue2 TO o3k_runtime' >/dev/null
    run_expect_reject case-k-role-membership o3k-role-membership-rejected O3K_BACKUP_TEST_STOP_AFTER_STAGING=1
    psql -X -q -c 'REVOKE o3k_rogue2 FROM o3k_runtime; DROP ROLE IF EXISTS o3k_rogue2' >/dev/null

    prepare_case foreign
    write_trust "$WORK/foreign-trust.json" "00000000000000000000000000000000" "11111111111111111111111111111111"
    local saved_trust="$TRUST"
    TRUST="$WORK/foreign-trust.json"
    run_expect_reject case-l-wrong-site identity-mismatch O3K_BACKUP_TEST_STOP_AFTER_STAGING=1
    TRUST="$saved_trust"

    # Invalid signature: the harness signs with a key the trust document does
    # not name.
    prepare_case signature
    local pid
    common_env "$db" "$pgcfg" "$O3K_BIN" backup create --destination "$dest" --operation-id "$op" \
        >"$WORK/signature.json" 2>"$WORK/signature.err" &
    pid=$!
    if wait_request "$dest" "$op" 90; then
        sign_request "$dest" "$op" "$FOREIGN_KEY"
        wait_pid "$pid"
        reason="$(json_get "$WORK/signature.json" reason)"
        if [[ "$WAIT_RC" == 2 && ( "$reason" == artifact-finalize-failed || "$reason" == signature-invalid ) ]] && assert_no_artifact "$dest"; then
            record PASS case-m-invalid-signature "foreign signature rejected before publication"
        else
            record FAIL case-m-invalid-signature "rc=$WAIT_RC reason=$reason"
        fi
    else
        kill "$pid" 2>/dev/null || true
        record FAIL case-m-invalid-signature "no signing request"
    fi
}

# ---------------------------------------------------------------------------
# Case N: crate-level barrier/catalog/TOC SQL tests
# ---------------------------------------------------------------------------
case_unit_tests() {
    if CARGO_TARGET_DIR="$ROOT_DIR/target" cargo test -p o3k --lib backup_pg \
        >"$WORK/unit-o3k.log" 2>&1; then
        record PASS case-n-toc-classifier "complete TOC classification unit matrix passed"
    else
        record FAIL case-n-toc-classifier "see $WORK/unit-o3k.log"
    fi
    if CARGO_TARGET_DIR="$ROOT_DIR/target" cargo test -p o3k-store --lib postgres::backup \
        >"$WORK/unit-store.log" 2>&1; then
        record PASS case-n-barrier-sql "barrier policy/catalog unit matrix passed"
    else
        record FAIL case-n-barrier-sql "see $WORK/unit-store.log"
    fi
    if python3 tests/pp6_contract_decisions.py >"$WORK/unit-decisions.log" 2>&1; then
        record PASS case-n-contract-prototypes "D4/D10 contract decision prototypes passed"
    else
        record FAIL case-n-contract-prototypes "see $WORK/unit-decisions.log"
    fi
    local db
    db="$(new_db ignored)"
    prepare_db "$db" >/dev/null
    if O3K_PP6_PG_TEST_URL="postgres://ubuntu@%2Ftmp:${PGPORT:-5432}/$db" \
        O3K_PP6_SCHEMA_VERSION=36 O3K_PP6_CONTROL_ROLE=ubuntu \
        CARGO_TARGET_DIR="$ROOT_DIR/target" \
        cargo test -p o3k-store --test postgres_backup_barrier -- --ignored --nocapture \
        >"$WORK/unit-barrier-sql.log" 2>&1; then
        record PASS case-n-barrier-sql-live "real PG16 role/barrier/catalog SQL suite passed"
    else
        record FAIL case-n-barrier-sql-live "see $WORK/unit-barrier-sql.log"
    fi
}

echo "== PostgreSQL 16 PP.6 backup campaign =="
case_unit_tests
case_happy
case_retained_writer
case_safe_abort
case_barrier_loss
case_interrupted_dump
case_rejections

record NOT-COVERED case-o-reload-incomplete "requires a controllable postmaster that silently ignores SIGHUP; reload timeout is asserted by code path, not injected here"
record NOT-COVERED case-p-disk-full "requires a bounded filesystem/quota smaller than the 6 GiB reservation; D9 boundaries are covered by backup_reservation unit tests"
record NOT-COVERED case-q-second-host "requires a second host and an independently administered database-host ingress ACL/firewall"
record NOT-COVERED case-r-managed-cluster "managed PostgreSQL without an enforceable database-side admission barrier is unsupported; no managed-cluster evidence is claimed"
record NOT-COVERED case-s-hsm "PostgreSQL Option B online HSM signer is blocked on a contract amendment and external HSM custody; this slice uses the detached-signature seam"

printf '\nPASS=%d FAIL=%d NOT-COVERED=%d\n' "$PASS_COUNT" "$FAIL_COUNT" "$NA_COUNT"
[[ "$FAIL_COUNT" == 0 ]]
