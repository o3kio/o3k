#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
run_id="${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}-$$"
work_root="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/o3k-pp6-pgwal-${run_id}"
evidence_output="${O3K_PG_WAL_EVIDENCE_OUTPUT:-${root_dir}/target/pp6/postgres-wal-pressure-evidence.json}"
container_name="o3k-pp6-pgwal-${run_id//[^a-zA-Z0-9_.-]/-}"
pgdata="/tmp/o3k-pp6-pgwal-data"
container_id=""
run_state="running"
cleanup_state="not_run"
server_version="unknown"
image_id="unknown"
panic_observed="false"
crash_recovery_observed="false"
recovery_observed="false"
baseline_observed="false"
post_restart_write_observed="false"
server_unavailable_observed="false"
successful_pressure_rows="0"
wal_free_before_bytes="0"
wal_free_after_bytes="0"
recovery_mode="not_observed"
ready_at_start=""
unavailable_at=""
readiness_at_reserve_release="unknown"
postmaster_at_reserve_release="unknown"
ready_at_recovery=""
secrets_scan_status="not_run"
resource_id=""
operation_id=""
post_restart_resource_id=""
observed_sqlstate=""
runtime_log=""
source_commit="$(git -C "$root_dir" rev-parse HEAD)"
source_tree="$(git -C "$root_dir" rev-parse HEAD^{tree})"
started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
port=""

mkdir -p "$(dirname "$evidence_output")"

write_evidence() {
  local disposition="$1"
  python3 - "$evidence_output" "$root_dir" "$source_commit" "$source_tree" \
    "$run_id" "$started_at" "$server_version" "$image_id" "$port" \
    "$panic_observed" "$crash_recovery_observed" "$recovery_observed" "$baseline_observed" \
    "$post_restart_write_observed" "$cleanup_state" "$resource_id" \
    "$operation_id" "$post_restart_resource_id" "$observed_sqlstate" \
    "$successful_pressure_rows" "$server_unavailable_observed" "$wal_free_before_bytes" \
    "$wal_free_after_bytes" "$recovery_mode" "$ready_at_start" "$unavailable_at" \
    "$readiness_at_reserve_release" "$postmaster_at_reserve_release" "$ready_at_recovery" \
    "$secrets_scan_status" "$disposition" <<'PY'
import datetime, json, os, platform, subprocess, sys
(
    path, root, source_commit, source_tree, run_id, started_at, server_version,
    image_id, port, panic_observed, crash_recovery_observed, recovery_observed, baseline_observed,
    post_restart_write_observed, cleanup_state, resource_id, operation_id,
    post_restart_resource_id, observed_sqlstate, successful_pressure_rows,
    server_unavailable_observed, wal_free_before_bytes, wal_free_after_bytes,
    recovery_mode, ready_at_start, unavailable_at, readiness_at_reserve_release,
    postmaster_at_reserve_release, ready_at_recovery, secrets_scan_status, disposition,
) = sys.argv[1:]

def command(*args):
    try:
        return subprocess.check_output(args, cwd=root, text=True).strip()
    except Exception:
        return "unavailable"

document = {
    "artifact_type": "o3k-pp6-postgres-wal-pressure",
    "schema_version": 1,
    "disposition": disposition,
    "issue": 1089,
    "profile": "o3k-small-edge-v1",
    "authority": "o3k-implemented durable store; no provider boundary invoked",
    "source": {"commit": source_commit, "tree": source_tree},
    "harness": {
        "path": "tests/postgres-wal-pressure.sh",
        "sha256": command("sha256sum", "tests/postgres-wal-pressure.sh").split()[0],
        "run_id": run_id,
    },
    "environment": {
        "os": platform.platform(),
        "architecture": platform.machine(),
        "rustc": command("rustc", "--version"),
        "postgres_image": "postgres:16.4",
        "postgres_image_id": image_id,
        "postgres_server_version": server_version,
        "wal_filesystem": "run-owned 96 MiB container tmpfs",
    },
    "fault_injection": {
        "mechanism": "bounded WAL tmpfs plus run-owned reserve file; failed archive command prevents WAL recycling",
        "max_wal_size": "64MB",
        "checkpoint_timeout": "1h",
        "max_pressure_rows": 12000,
        "maximum_payload_bytes_per_row": 2200,
        "observed_sqlstate": observed_sqlstate,
        "successful_pressure_rows": int(successful_pressure_rows),
        "wal_tmpfs_free_bytes_before_pressure": int(wal_free_before_bytes),
        "wal_tmpfs_free_bytes_after_failure": int(wal_free_after_bytes),
        "reserve_bytes": 50331648,
        "reserve_verified": int(wal_free_before_bytes) > 0,
        "database_panic_after_enospc": panic_observed == "true",
        "pg_isready_failed_while_reserve_held": server_unavailable_observed == "true",
        "crash_recovery_log_observed": crash_recovery_observed == "true",
        "recovery_mode": recovery_mode,
        "initial_ready_at_epoch_ms": int(ready_at_start or 0),
        "unavailable_observed_at_epoch_ms": int(unavailable_at or 0),
        "readiness_at_reserve_release": readiness_at_reserve_release,
        "postmaster_at_reserve_release": postmaster_at_reserve_release,
        "ready_after_recovery_at_epoch_ms": int(ready_at_recovery or 0),
    },
    "observations": {
        "baseline_resource_id": resource_id,
        "baseline_operation_id": operation_id,
        "baseline_rows_recovered": baseline_observed == "true",
        "primary_recovered_after_restart": recovery_observed == "true",
        "post_restart_resource_id": post_restart_resource_id,
        "post_restart_canonical_write_readback": post_restart_write_observed == "true",
    },
    "foreign_state": {
        "status": "not_exercised",
        "reason": "isolated store-only lane invokes no provider or external-state operations",
    },
    "secrets": {"scan": secrets_scan_status, "scope": "evidence JSON and captured test output"},
    "cleanup": {"status": cleanup_state, "container": "exact run-owned labeled container"},
    "started_at": started_at,
    "finished_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
}

os.makedirs(os.path.dirname(path), exist_ok=True)
with open(path, "w", encoding="utf-8") as output:
    json.dump(document, output, indent=2, sort_keys=True)
    output.write("\n")
PY
}

cleanup() {
  local status=$?
  local cleanup_status=0
  trap - EXIT
  if [[ -n "$runtime_log" && -f "$runtime_log" ]] && grep -Eiq 'postgres://[^ ]+:[^@ ]+@|password[=:][A-Za-z0-9+/=]{8,}|token[=:][A-Za-z0-9._-]{8,}|private[_ -]?key' "$runtime_log"; then
    echo "secret scan failed for captured harness output" >&2
    secrets_scan_status="failed"
    cleanup_status=1
    run_state="failed"
  elif [[ -n "$runtime_log" && -f "$runtime_log" ]]; then
    secrets_scan_status="passed"
  fi
  if [[ -n "$container_id" ]]; then
    local label source_label owner_label
    label="$(docker inspect --format '{{ index .Config.Labels "o3k.pp6.run" }}' "$container_id" 2>/dev/null || true)"
    source_label="$(docker inspect --format '{{ index .Config.Labels "o3k.pp6.source" }}' "$container_id" 2>/dev/null || true)"
    owner_label="$(docker inspect --format '{{ index .Config.Labels "o3k.pp6.owner" }}' "$container_id" 2>/dev/null || true)"
    if [[ "$label" == "$run_id" && "$source_label" == "$source_commit" && "$owner_label" == "postgres-wal-pressure.sh" ]]; then
      docker rm --force "$container_id" >/dev/null || cleanup_status=1
    else
      echo "refusing cleanup: container ownership label did not match" >&2
      cleanup_status=1
    fi
  fi
  if docker ps -aq --filter "label=o3k.pp6.run=$run_id" | grep -q .; then
    echo "run-owned PostgreSQL container remains after cleanup" >&2
    cleanup_status=1
  fi
  if [[ -d "$work_root" ]]; then rm -rf -- "$work_root" || cleanup_status=1; fi
  if [[ "$cleanup_status" -eq 0 ]]; then cleanup_state="passed"; else cleanup_state="failed"; status=1; fi
  if [[ "$status" -eq 0 && "$run_state" == "running" ]]; then run_state="passed"; fi
  if [[ "$status" -ne 0 && "$run_state" == "running" ]]; then run_state="failed"; fi
  write_evidence "$run_state"
  if [[ "$secrets_scan_status" == "passed" ]] && grep -Eiq '(postgres://[^ ]*:[^@ ]+@|password[=:][^[:space:]]+|token[=:][^[:space:]]+|private[_ -]?key)' "$evidence_output"; then
    echo "secret scan failed for generated evidence" >&2
    secrets_scan_status="failed"
    run_state="failed"
    status=1
    write_evidence "$run_state"
  fi
  if [[ "$run_state" == "passed" ]]; then
    if ! python3 "$root_dir/scripts/validate_postgres_wal_pressure_evidence.py" "$evidence_output"; then
      status=1
      run_state="failed"
      write_evidence "$run_state"
      echo "PostgreSQL WAL pressure evidence: failed validation ($evidence_output)" >&2
    fi
    if [[ "$status" -eq 0 ]]; then echo "PostgreSQL WAL pressure evidence: PASS ($evidence_output)"; fi
  else
    echo "PostgreSQL WAL pressure evidence: $run_state ($evidence_output)" >&2
  fi
  exit "$status"
}

run_store_phase() {
  local phase_log="$work_root/${O3K_PG_WAL_PHASE}.log"
  if ! cargo test --locked -p o3k-store --test postgres_wal_pressure --all-features -- \
    --ignored --exact postgres_wal_pressure_and_restart_recovery --nocapture \
    2>&1 | tee "$phase_log" | tee -a "$runtime_log"; then
    return 1
  fi
  if ! grep -Eq '^test result: ok\. 1 passed; 0 failed; 0 ignored;' "$phase_log"; then
    echo "required PostgreSQL WAL test did not execute exactly once in phase $O3K_PG_WAL_PHASE" >&2
    return 1
  fi
}
trap cleanup EXIT

if ! command -v docker >/dev/null || ! docker info >/dev/null 2>&1; then
  echo "Docker with disposable container support is required; no PASS evidence will be emitted" >&2
  exit 1
fi
mkdir -m 700 "$work_root"
runtime_log="$work_root/harness.log"
resource_id="$(python3 -c 'import uuid; print(uuid.uuid4())')"
operation_id="$(python3 -c 'import uuid; print(uuid.uuid4())')"
post_restart_resource_id="$(python3 -c 'import uuid; print(uuid.uuid4())')"
port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"

docker pull postgres:16.4 >/dev/null
image_id="$(docker image inspect --format '{{.Id}}' postgres:16.4)"
container_id="$(docker run --detach --name "$container_name" \
  --label "o3k.pp6.run=$run_id" \
  --label "o3k.pp6.source=$source_commit" \
  --label "o3k.pp6.owner=postgres-wal-pressure.sh" \
  --label "o3k.pp6.phase=wal-pressure" \
  --network host \
  --tmpfs /wal:rw,size=96m,uid=999,gid=999,mode=0700 \
  --entrypoint tail postgres:16.4 -f /dev/null)"

docker exec --user postgres "$container_id" initdb -D "$pgdata" --waldir=/wal \
  --username=o3k --auth-local=trust --auth-host=trust >/dev/null
if ! docker exec --user postgres "$container_id" pg_ctl -D "$pgdata" \
  -l "$pgdata/server.log" \
  -o "-h 127.0.0.1 -p $port -c archive_mode=on -c archive_command=/bin/false -c max_wal_size=64MB -c min_wal_size=32MB -c checkpoint_timeout=1h -c full_page_writes=on -c fsync=on -c synchronous_commit=on" \
  start >/dev/null; then
  docker exec --user postgres "$container_id" cat "$pgdata/server.log" >&2 || true
  exit 1
fi
for _ in $(seq 1 60); do
  if docker exec --user postgres "$container_id" pg_isready -h 127.0.0.1 -p "$port" -U o3k -d postgres >/dev/null 2>&1; then break; fi
  sleep 1
done
docker exec --user postgres "$container_id" pg_isready -h 127.0.0.1 -p "$port" -U o3k -d postgres >/dev/null
ready_at_start="$(date +%s%3N)"
server_version="$(docker exec --user postgres "$container_id" psql -h 127.0.0.1 -p "$port" -U o3k -d postgres -Atqc 'SHOW server_version')"
[[ "$server_version" == 16.4* ]] || { echo "expected PostgreSQL 16.4, got $server_version" >&2; exit 1; }
wal_link="$(docker exec --user postgres "$container_id" readlink "$pgdata/pg_wal")"
[[ "$wal_link" == /wal ]] || { echo "pg_wal is not mounted on the isolated WAL tmpfs" >&2; exit 1; }
for _ in $(seq 1 60); do
  if python3 - "$port" <<'PY'
import socket, sys
try:
    with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=1):
        pass
except OSError:
    raise SystemExit(1)
PY
  then break; fi
  sleep 1
done
python3 - "$port" <<'PY'
import socket, sys
with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=1):
    pass
PY

export O3K_DATABASE_URL="postgres://o3k@127.0.0.1:${port}/postgres?sslmode=disable"
export O3K_PG_WAL_PHASE=setup
export O3K_PG_WAL_RESOURCE_ID="$resource_id"
export O3K_PG_WAL_OPERATION_ID="$operation_id"
export O3K_PG_WAL_MAX_ROWS=12000
run_store_phase

# Leave enough headroom for PostgreSQL's current WAL plus one segment, then
# consume bounded space so archive failures prevent old WAL from recycling.
docker exec --user postgres "$container_id" sh -c 'dd if=/dev/zero of=/wal/.o3k-run-reserve bs=1M count=48 conv=fsync status=none'
reserve_metadata="$(docker exec --user postgres "$container_id" stat -c '%s %u:%g %a' /wal/.o3k-run-reserve)"
[[ "$reserve_metadata" == "50331648 999:999 644" ]] || { echo "WAL reserve ownership, mode, or size is invalid: $reserve_metadata" >&2; exit 1; }
wal_free_before_bytes="$(docker exec --user postgres "$container_id" df -B1 --output=avail /wal | tail -n 1 | tr -d '[:space:]')"
[[ "$wal_free_before_bytes" =~ ^[0-9]+$ ]] && (( wal_free_before_bytes > 0 && wal_free_before_bytes <= 83886080 )) || { echo "unexpected WAL tmpfs free space after reserving capacity: $wal_free_before_bytes" >&2; exit 1; }
archive_mode="$(docker exec --user postgres "$container_id" psql -h 127.0.0.1 -p "$port" -U o3k -d postgres -Atqc 'SHOW archive_mode')"
archive_command="$(docker exec --user postgres "$container_id" psql -h 127.0.0.1 -p "$port" -U o3k -d postgres -Atqc 'SHOW archive_command')"
[[ "$archive_mode" == on && "$archive_command" == /bin/false ]] || { echo "WAL archive failure injection is not active" >&2; exit 1; }
docker exec --user postgres "$container_id" psql -h 127.0.0.1 -p "$port" -U o3k -d postgres -Atqc 'SELECT pg_switch_wal()' >/dev/null
for _ in $(seq 1 45); do
  failed_archives="$(docker exec --user postgres "$container_id" psql -h 127.0.0.1 -p "$port" -U o3k -d postgres -Atqc 'SELECT failed_count FROM pg_stat_archiver' 2>/dev/null || true)"
  [[ "${failed_archives:-0}" =~ ^[0-9]+$ ]] && (( failed_archives > 0 )) && break
  sleep 1
done
[[ "${failed_archives:-0}" =~ ^[0-9]+$ ]] && (( failed_archives > 0 )) || { echo "archive command failure was not observed" >&2; exit 1; }
export O3K_PG_WAL_PHASE=pressure
run_store_phase

docker exec --user postgres "$container_id" psql -h 127.0.0.1 -p "$port" -U o3k -d postgres -Atqc 'SELECT pg_switch_wal()' >/dev/null 2>&1 || true
# Hold the reserved space until the server has stopped, then verify PostgreSQL
# itself reported ENOSPC/PANIC before any capacity is released.
if ! docker exec --user postgres "$container_id" sh -c "grep -Eiq 'PANIC:.*pg_wal/.*No space left on device' '$pgdata/server.log'"; then
  docker exec --user postgres "$container_id" tail -n 40 "$pgdata/server.log" >&2 || true
  echo "PostgreSQL did not log ENOSPC/PANIC evidence" >&2
  exit 1
fi
panic_observed="true"
observed_sqlstate="$(sed -n 's/^WAL pressure stopped after PostgreSQL SQLSTATE \([0-9][0-9]*\);.*/\1/p' "$runtime_log" | tail -n 1)"
[[ "$observed_sqlstate" == 53100 ]] || { echo "expected a PostgreSQL disk-full SQLSTATE" >&2; exit 1; }
successful_pressure_rows="$(sed -n 's/^WAL pressure stopped after PostgreSQL SQLSTATE 53100; successful_rows=//p' "$runtime_log" | tail -n 1)"
[[ "$successful_pressure_rows" =~ ^[0-9]+$ ]] && (( successful_pressure_rows > 0 && successful_pressure_rows <= 12000 )) || { echo "pressure failure occurred without bounded successful writes" >&2; exit 1; }
wal_free_after_bytes="$(docker exec --user postgres "$container_id" df -B1 --output=avail /wal | tail -n 1 | tr -d '[:space:]')"
[[ "$wal_free_after_bytes" =~ ^[0-9]+$ ]] && (( wal_free_after_bytes <= 8388608 )) || { echo "WAL tmpfs was not exhausted: $wal_free_after_bytes bytes remain" >&2; exit 1; }

for _ in $(seq 1 30); do
  if ! docker exec --user postgres "$container_id" pg_isready -h 127.0.0.1 -p "$port" -U o3k -d postgres >/dev/null 2>&1; then
    server_unavailable_observed="true"
    unavailable_at="$(date +%s%3N)"
    break
  fi
  sleep 1
done
[[ "$server_unavailable_observed" == true ]] || { echo "PostgreSQL remained available during WAL exhaustion" >&2; exit 1; }

# Capture postmaster and readiness state immediately before releasing reserved
# capacity to distinguish PostgreSQL restart recovery from harness restart.
if docker exec --user postgres "$container_id" pg_ctl -D "$pgdata" status >/dev/null 2>&1; then
  postmaster_at_reserve_release="running"
else
  postmaster_at_reserve_release="stopped"
fi
if docker exec --user postgres "$container_id" pg_isready -h 127.0.0.1 -p "$port" -U o3k -d postgres >/dev/null 2>&1; then
  readiness_at_reserve_release="ready"
else
  readiness_at_reserve_release="unavailable"
fi

# PostgreSQL may recover automatically after its PANIC restart. Remove only
# the run-owned reserve after proving the server logged ENOSPC. Then verify
# PostgreSQL's crash recovery and the O3K store's durable canonical rows.
docker exec --user postgres "$container_id" rm -f /wal/.o3k-run-reserve
if [[ "$postmaster_at_reserve_release" == stopped ]]; then
  recovery_mode="harness_restart"
  if ! docker exec --user postgres "$container_id" pg_ctl -D "$pgdata" \
    -l "$pgdata/server.log" \
    -o "-h 127.0.0.1 -p $port -c archive_mode=on -c archive_command=/bin/false -c max_wal_size=64MB -c min_wal_size=32MB -c checkpoint_timeout=1h -c full_page_writes=on -c fsync=on -c synchronous_commit=on" \
    start >/dev/null; then
    docker exec --user postgres "$container_id" tail -n 60 "$pgdata/server.log" >&2 || true
    echo "PostgreSQL restart after WAL exhaustion failed" >&2
    exit 1
  fi
else
  recovery_mode="postgres_automatic_restart"
fi
for _ in $(seq 1 30); do
  if docker exec --user postgres "$container_id" pg_isready -h 127.0.0.1 -p "$port" -U o3k -d postgres >/dev/null 2>&1; then break; fi
  sleep 1
done
if ! docker exec --user postgres "$container_id" pg_isready -h 127.0.0.1 -p "$port" -U o3k -d postgres >/dev/null 2>&1; then
  if [[ "$recovery_mode" == postgres_automatic_restart ]] && ! docker exec --user postgres "$container_id" pg_ctl -D "$pgdata" status >/dev/null 2>&1; then
    recovery_mode="postgres_automatic_then_harness_restart"
    if ! docker exec --user postgres "$container_id" pg_ctl -D "$pgdata" \
      -l "$pgdata/server.log" \
      -o "-h 127.0.0.1 -p $port -c archive_mode=on -c archive_command=/bin/false -c max_wal_size=64MB -c min_wal_size=32MB -c checkpoint_timeout=1h -c full_page_writes=on -c fsync=on -c synchronous_commit=on" \
      start >/dev/null; then
      docker exec --user postgres "$container_id" tail -n 60 "$pgdata/server.log" >&2 || true
      echo "PostgreSQL harness restart after automatic recovery failure did not start" >&2
      exit 1
    fi
    for _ in $(seq 1 60); do
      if docker exec --user postgres "$container_id" pg_isready -h 127.0.0.1 -p "$port" -U o3k -d postgres >/dev/null 2>&1; then break; fi
      sleep 1
    done
  fi
  if ! docker exec --user postgres "$container_id" pg_isready -h 127.0.0.1 -p "$port" -U o3k -d postgres >/dev/null 2>&1; then
    docker exec --user postgres "$container_id" tail -n 60 "$pgdata/server.log" >&2 || true
    echo "PostgreSQL did not become ready after WAL recovery" >&2
    exit 1
  fi
fi
ready_at_recovery="$(date +%s%3N)"
if ! docker exec --user postgres "$container_id" sh -c "grep -Eiq 'database system was interrupted|redo starts at' '$pgdata/server.log'"; then
  docker exec --user postgres "$container_id" tail -n 60 "$pgdata/server.log" >&2 || true
  echo "PostgreSQL crash recovery was not observed after WAL PANIC" >&2
  exit 1
fi
crash_recovery_observed="true"
recovery_observed="true"
export O3K_PG_WAL_PHASE=recovery
export O3K_PG_WAL_POST_RESTART_RESOURCE_ID="$post_restart_resource_id"
run_store_phase
baseline_observed="true"
post_restart_write_observed="true"
