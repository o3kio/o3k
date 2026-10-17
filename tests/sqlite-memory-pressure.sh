#!/usr/bin/env bash
set -euo pipefail

out="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/pp6-sqlite-memory-pressure.json"
mkdir -p "$(dirname "$out")"
docker_cgroup_version=""
if command -v docker >/dev/null; then
  docker_cgroup_version="$(docker info --format '{{.CgroupVersion}}' 2>/dev/null || true)"
fi
if [[ "$docker_cgroup_version" != "2" && "$docker_cgroup_version" != "cgroup2" ]]; then
  source_commit="$(git rev-parse HEAD)"; source_tree="$(git rev-parse HEAD^{tree})"
  cat >"$out" <<EOF
{"schema":"o3k.pp6.sqlite-memory-pressure.v1","case":"sqlite-memory-pressure","harness":"sqlite_memory_pressure_kills_only_child_and_replays_operation","source_commit":"$source_commit","source_tree":"$source_tree","execution_commit":"$source_commit","execution_tree":"$source_tree","profile":"o3k-demo-v1","disposition":"NOT_RUN","reason":"Docker or cgroup v2 capability unavailable","foreign_state":{"status":"not_exercised","reason":"setup did not run"}}
EOF
  python3 - "$out" <<'PY'
import json, sys
p=sys.argv[1]; d=json.load(open(p)); d["disposition"]="INFRASTRUCTURE_BLOCKED"; d["secret_scan"]={"status":"pending","scope":"validator scans full artifact"}; json.dump(d,open(p,"w"),sort_keys=True); open(p,"a").write("\n")
PY
  echo "INFRASTRUCTURE_BLOCKED: Docker or cgroup v2 capability unavailable; wrote $out"
  exit 0
fi
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
container="o3k-pp6-memory-${RANDOM}-${RANDOM}"
container_active=0
target_dir="$(mktemp -d)"
mkdir -p "$target_dir/shared"
cleanup_resources() {
  local s=0
  if (( container_active )); then
    if ! docker inspect "$container" >/dev/null 2>&1; then
      s=1
    elif ! docker rm -f "$container" >/dev/null 2>&1; then
      s=1
    else
      container_active=0
    fi
  fi
  rm -f "$target_dir/shared/sqlite-version" "$target_dir/shared/allocation-phase" || s=1
  rm -rf "$target_dir" || s=1
  return "$s"
}
cleanup() {
  local s=$?
  trap - EXIT
  cleanup_resources || s=1
  rm -f "$out.provisional" || s=1
  exit "$s"
}
trap cleanup EXIT
image_id="$(docker image inspect rust:1.97.1-bookworm --format '{{.Id}}' 2>/dev/null || true)"
if [[ -z "$image_id" ]]; then
  container_active=0
  source_commit="$(git rev-parse HEAD)"; source_tree="$(git rev-parse HEAD^{tree})"
  printf '%s\n' "{\"schema\":\"o3k.pp6.sqlite-memory-pressure.v1\",\"case\":\"sqlite-memory-pressure\",\"harness\":\"sqlite_memory_pressure_kills_only_child_and_replays_operation\",\"source_commit\":\"$source_commit\",\"source_tree\":\"$source_tree\",\"execution_commit\":\"$source_commit\",\"execution_tree\":\"$source_tree\",\"profile\":\"o3k-demo-v1\",\"disposition\":\"INFRASTRUCTURE_BLOCKED\",\"reason\":\"pinned image unavailable\",\"foreign_state\":{\"status\":\"not_exercised\",\"reason\":\"setup did not run\"},\"secret_scan\":{\"status\":\"pending\",\"scope\":\"validator scans full artifact\"}}" > "$out"
  exit 0
fi
blocked() {
  local reason="$1" source_commit source_tree
  source_commit="$(git rev-parse HEAD)"; source_tree="$(git rev-parse HEAD^{tree})"
  printf '%s\n' "{\"schema\":\"o3k.pp6.sqlite-memory-pressure.v1\",\"case\":\"sqlite-memory-pressure\",\"harness\":\"sqlite_memory_pressure_kills_only_child_and_replays_operation\",\"source_commit\":\"$source_commit\",\"source_tree\":\"$source_tree\",\"execution_commit\":\"$source_commit\",\"execution_tree\":\"$source_tree\",\"profile\":\"o3k-demo-v1\",\"disposition\":\"INFRASTRUCTURE_BLOCKED\",\"reason\":\"$reason\",\"foreign_state\":{\"status\":\"not_exercised\",\"reason\":\"setup did not run\"},\"secret_scan\":{\"status\":\"pending\",\"scope\":\"validator scans full artifact\"}}" > "$out.provisional"
  python3 - "$out.provisional" <<'PY'
import json,sys
json.load(open(sys.argv[1]))
PY
  mv -- "$out.provisional" "$out"
  exit 0
}
docker run --rm --name "${container}-builder" -v "$root:/o3k" -v "$target_dir:/o3k/target" -w /o3k "$image_id" \
  cargo test --locked -p o3k-store --test sqlite_memory_pressure --all-features --no-run
host_bin="$(find "$target_dir/debug/deps" -maxdepth 1 -type f -name 'sqlite_memory_pressure-*' ! -name '*.d' | head -n 1)"
[[ -x "$host_bin" ]] || { echo 'FAIL: unable to build memory-pressure test binary' >&2; exit 1; }
# Setup and recovery run in bounded disposable harness containers. The allocator
# runs in a separate child container, so its OOM boundary cannot kill either
# recovery invocation or the runner-side evidence publisher.
binary="/o3k/target/debug/deps/$(basename "$host_bin")"
db_path=/shared/run.sqlite
run_harness() {
  local mode="$1"
  timeout 60s docker run --rm --memory=1g --memory-swap=1g \
    -v "$target_dir:/o3k/target:ro" -v "$target_dir/shared:/shared" "$image_id" \
    env O3K_MEMORY_PRESSURE_MODE="$mode" O3K_MEMORY_PRESSURE_DB="$db_path" \
      O3K_MEMORY_PRESSURE_VERSION_PATH=/shared/sqlite-version \
      O3K_MEMORY_PRESSURE_PHASE_PATH=/shared/allocation-phase \
      "$binary" --ignored --exact sqlite_memory_pressure_kills_only_child_and_replays_operation --nocapture
}
run_harness setup
if ! docker run -d --name "$container" --memory=256m --memory-swap=256m \
  -v "$target_dir:/o3k/target:ro" -v "$target_dir/shared:/shared" "$image_id" \
  sleep 120 >/dev/null; then
  docker rm -f "$container" >/dev/null 2>&1 || true
  exit 1
fi
container_active=1
before_events="$(docker exec "$container" cat /sys/fs/cgroup/memory.events)"
docker_id="$(docker inspect --format '{{.Id}}' "$container")"
[[ "$(docker exec "$container" cat /sys/fs/cgroup/memory.max)" == 268435456 ]] || blocked 'memory.max not enforced'
[[ "$(docker exec "$container" cat /sys/fs/cgroup/memory.swap.max)" == 0 ]] || blocked 'memory.swap.max not enforced'
set +e
timeout 60s docker exec "$container" env O3K_MEMORY_PRESSURE_MODE=allocate \
  O3K_MEMORY_PRESSURE_DB="$db_path" O3K_MEMORY_PRESSURE_PHASE_PATH=/shared/allocation-phase \
  "$binary" --ignored --exact sqlite_memory_pressure_kills_only_child_and_replays_operation --nocapture
child_status=$?
set -e
[[ "$child_status" == 137 ]] || { echo "FAIL: expected allocator SIGKILL status 137; got $child_status" >&2; exit 1; }
[[ -f "$target_dir/shared/allocation-phase" ]] || blocked 'allocation phase marker missing'
events="$(docker exec "$container" cat /sys/fs/cgroup/memory.events 2>/dev/null || true)"
before_oom="$(awk '$1 == "oom_kill" {print $2}' <<<"$before_events")"
after_oom="$(awk '$1 == "oom_kill" {print $2}' <<<"$events")"
[[ "$before_oom" =~ ^[0-9]+$ && "$after_oom" =~ ^[0-9]+$ && $((after_oom-before_oom)) == 1 ]] || { echo "FAIL: expected oom_kill delta 1; before=$before_events after=$events" >&2; exit 1; }
run_harness recover
source_commit="$(git rev-parse HEAD)"
source_tree="$(git rev-parse HEAD^{tree})"
sqlite_version="$(cat "$target_dir/shared/sqlite-version" 2>/dev/null || true)"
[[ -n "$sqlite_version" ]] || { echo 'FAIL: test did not report SQLite runtime version' >&2; exit 1; }
rust_version="$(docker run --rm "$image_id" rustc --version)"
execution_commit="$source_commit"
execution_tree="$source_tree"
if ! docker rm "$container" >/dev/null; then
  echo 'FAIL: container cleanup failed' >&2
  exit 1
fi
container_active=0
if ! cleanup_resources; then
  echo 'FAIL: temporary resource cleanup failed before PASS publication' >&2
  exit 1
fi
provisional="$out.provisional"
cat >"$provisional" <<EOF
{"schema":"o3k.pp6.sqlite-memory-pressure.v1","case":"sqlite-memory-pressure","harness":"sqlite_memory_pressure_kills_only_child_and_replays_operation","source_commit":"$source_commit","source_tree":"$source_tree","execution_commit":"$execution_commit","execution_tree":"$execution_tree","profile":"o3k-demo-v1","sqlite_version":"$sqlite_version","rust_version":"$rust_version","container_id":"$docker_id","image_id":"$image_id","cgroup_memory_max":"268435456","swap_max":"0","timeout_seconds":60,"child_exit_status":$child_status,"oom_kill_count":$((after_oom-before_oom)),"child_only":true,"canonical_retry":"store-only-terminal-transition","foreign_state":{"status":"not_exercised","reason":"store-only lane invokes no provider or external-state operations"},"secret_scan":"PASS","cleanup":"PASS","scope":"store-only; provider retry and foreign state not exercised","disposition":"PASS"}
EOF
python3 - "$provisional" <<'PY'
import json, re, sys
p=sys.argv[1]; s=open(p).read();
if re.search(r'postgres(?:ql)?://[^/\s:@"]+:[^@\s"]+@|BEGIN [A-Z ]*PRIVATE KEY|"(?:password|secret|token)"\s*:\s*"[^" ]+"', s, re.I): raise SystemExit('raw artifact secret scan failed')
PY
mv -- "$provisional" "$out"
echo "wrote $out"
