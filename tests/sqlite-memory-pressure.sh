#!/usr/bin/env bash
set -euo pipefail

out="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/pp6-sqlite-memory-pressure.json"
mkdir -p "$(dirname "$out")"
if ! command -v docker >/dev/null || ! docker info --format '{{.CgroupVersion}}' 2>/dev/null | grep -qx cgroup2; then
  source_commit="$(git rev-parse HEAD)"; source_tree="$(git rev-parse HEAD^{tree})"
  cat >"$out" <<EOF
{"schema":"o3k.pp6.sqlite-memory-pressure.v1","case":"sqlite-memory-pressure","harness":"sqlite_memory_pressure_kills_only_child_and_replays_operation","source_commit":"$source_commit","source_tree":"$source_tree","execution_commit":"$source_commit","execution_tree":"$source_tree","profile":"o3k-demo-v1","disposition":"NOT_RUN","reason":"Docker or cgroup v2 capability unavailable","foreign_state":{"status":"not_exercised","reason":"setup did not run"}}
EOF
  echo "NOT_RUN: Docker or cgroup v2 capability unavailable; wrote $out"
  exit 0
fi
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
container="o3k-pp6-memory-${RANDOM}-${RANDOM}"
version_file="$(dirname "$out")/.sqlite-version.$$"
cleanup() { docker rm -f "$container" >/dev/null 2>&1 || true; }
trap cleanup EXIT
host_bin="$(find "$root/target/debug/deps" -maxdepth 1 -type f -name 'sqlite_memory_pressure-*' ! -name '*.d' | head -n 1)"
if [[ ! -x "$host_bin" ]]; then
  docker run --rm --name "${container}-builder" -v "$root:/o3k" -w /o3k rust:1.85-bookworm \
    cargo test --locked -p o3k-store --test sqlite_memory_pressure --all-features --no-run
  host_bin="$(find "$root/target/debug/deps" -maxdepth 1 -type f -name 'sqlite_memory_pressure-*' ! -name '*.d' | head -n 1)"
fi
[[ -x "$host_bin" ]] || { echo 'FAIL: unable to build memory-pressure test binary' >&2; exit 1; }
docker run -d --name "$container" --memory=256m --memory-swap=256m --memory-swappiness=0 \
  -v "$root:/o3k:ro" -v "$(dirname "$out"):/evidence" -w /o3k rust:1.85-bookworm \
  sleep 120 >/dev/null
before_events="$(docker exec "$container" cat /sys/fs/cgroup/memory.events)"
docker_id="$(docker inspect --format '{{.Id}}' "$container")"
timeout 60s docker exec "$container" env O3K_MEMORY_PRESSURE_VERSION_PATH="/evidence/.sqlite-version.$$" \
  "$host_bin" --exact sqlite_memory_pressure_kills_only_child_and_replays_operation --nocapture
events="$(docker exec "$container" cat /sys/fs/cgroup/memory.events 2>/dev/null || true)"
before_oom="$(awk '$1 == "oom_kill" {print $2}' <<<"$before_events")"
after_oom="$(awk '$1 == "oom_kill" {print $2}' <<<"$events")"
[[ "$before_oom" =~ ^[0-9]+$ && "$after_oom" =~ ^[0-9]+$ && $((after_oom-before_oom)) == 1 ]] || { echo "FAIL: expected oom_kill delta 1; before=$before_events after=$events" >&2; exit 1; }
source_commit="$(git rev-parse HEAD)"
source_tree="$(git rev-parse HEAD^{tree})"
sqlite_version="$(cat "$version_file" 2>/dev/null || true)"
[[ -n "$sqlite_version" ]] || { echo 'FAIL: test did not report SQLite runtime version' >&2; exit 1; }
image_id="$(docker image inspect rust:1.85-bookworm --format '{{.Id}}')"
execution_commit="$source_commit"
execution_tree="$source_tree"
if ! docker rm "$container" >/dev/null; then
  echo 'FAIL: container cleanup failed' >&2
  exit 1
fi
trap - EXIT
cat >"$out" <<EOF
{"schema":"o3k.pp6.sqlite-memory-pressure.v1","case":"sqlite-memory-pressure","harness":"sqlite_memory_pressure_kills_only_child_and_replays_operation","source_commit":"$source_commit","source_tree":"$source_tree","execution_commit":"$execution_commit","execution_tree":"$execution_tree","profile":"o3k-demo-v1","sqlite_version":"$sqlite_version","container_id":"$docker_id","image_id":"$image_id","cgroup_memory_max":"268435456","swap_max":"0","timeout_seconds":60,"oom_kill_count":$((after_oom-before_oom)),"child_only":true,"canonical_retry":"store-only-terminal-transition","foreign_state":{"status":"not_exercised","reason":"store-only lane invokes no provider or external-state operations"},"secret_scan":"not_exercised","cleanup":"PASS","disposition":"PASS"}
EOF
echo "wrote $out"
rm -f "$version_file"
