#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT
state="$tmp/state"
samples="$tmp/samples.jsonl"
events="$tmp/events.jsonl"
touch "$samples" "$events"
printf 'prior-sample\n' >"$samples"
printf 'prior-event\n' >"$events"
marker="$tmp/hook-ran"
hook="$tmp/fake-hook"
cat >"$hook" <<EOF
#!/usr/bin/env bash
touch '$marker'
EOF
chmod +x "$hook"

for spec in 'K-min:10:7200' 'K-full:20:43200'; do
  IFS=: read -r tier scale duration <<<"$spec"
  status=0
  output="$(env O3K_PP5_SAMPLE_CMD="$hook" O3K_PP5_CREATE_CMD="$hook" \
      O3K_PP5_DELETE_CMD="$hook" O3K_PP5_CLEANUP_CMD="$hook" \
      O3K_PP5_EVENT_CMD="$hook" \
      bash "$ROOT/scripts/pp5_soak.sh" --tier "$tier" --scale "$scale" \
      --duration-seconds "$duration" --state-dir "$state" --samples "$samples" \
      --events "$events" 2>&1)" || status=$?
  [[ "$status" == 3 ]] || { echo "$tier did not stop at policy boundary (exit $status)" >&2; exit 1; }
  grep -Fq 'status=DEFERRED_BY_POLICY' <<<"$output"
  grep -Fq 'no campaign or evidence state was changed' <<<"$output"
done

for spec in 'K-min:9:7200' 'K-min:10:7199' 'K-full:20:43199' 'K-full:19:43200'; do
  IFS=: read -r tier scale duration <<<"$spec"
  if bash "$ROOT/scripts/pp5_soak.sh" --tier "$tier" --scale "$scale" \
      --duration-seconds "$duration" --state-dir "$state" --samples "$samples" \
      --events "$events" >"$tmp/invalid-out" 2>&1; then
    echo "$tier accepted wrong scale or duration" >&2
    exit 1
  fi
  grep -Fq 'classification=EVIDENCE_GAP' "$tmp/invalid-out"
done

test ! -e "$state"
test ! -e "$marker"
test "$(cat "$samples")" = prior-sample
test "$(cat "$events")" = prior-event
echo "PP.5 soak guards passed"
