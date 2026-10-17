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
  env O3K_PP5_SAMPLE_CMD="$hook" O3K_PP5_CREATE_CMD="$hook" \
      O3K_PP5_DELETE_CMD="$hook" O3K_PP5_CLEANUP_CMD="$hook" \
      O3K_PP5_EVENT_CMD="$hook" \
      bash "$ROOT/scripts/pp5_soak.sh" --tier "$tier" --scale "$scale" \
      --duration-seconds "$duration" --state-dir "$state" --samples "$samples" \
      --events "$events" >"$tmp/status-$tier.json" 2>"$tmp/diagnostic-$tier.txt" || status=$?
  [[ "$status" == 3 ]] || { echo "$tier did not stop at policy boundary (exit $status)" >&2; exit 1; }
  grep -Fq 'status=DEFERRED_BY_POLICY' "$tmp/diagnostic-$tier.txt"
  grep -Fq 'no campaign or evidence state was changed' "$tmp/diagnostic-$tier.txt"
  python3 - "$tmp/status-$tier.json" "$tier" <<'PY'
import json
import pathlib
import sys

record = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert record == {
    "record_type": "o3k.pp5-lane-disposition.v1",
    "lane": sys.argv[2],
    "status": "DEFERRED_BY_POLICY",
    "acceptance_result": "NOT_RUN",
    "evidence_produced": False,
    "state_mutated": False,
}
PY
  if python3 "$ROOT/scripts/validate_pp5_evidence.py" "$tmp/status-$tier.json" \
      >"$tmp/validator-$tier.out" 2>&1; then
    echo "$tier deferred disposition was accepted as PP.5 evidence" >&2
    exit 1
  fi
  grep -Fq 'PP.5 evidence validation FAILED' "$tmp/validator-$tier.out"
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
  ! grep -Fq 'o3k.pp5-lane-disposition.v1' "$tmp/invalid-out"
done

test ! -e "$state"
test ! -e "$marker"
test "$(cat "$samples")" = prior-sample
test "$(cat "$events")" = prior-event
echo "PP.5 soak guards passed"
