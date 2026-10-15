#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT_DIR/scripts/pp5_scale_tier.sh"
tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT
test -x "$SCRIPT"

malicious_hook="$tmp/should-not-run"
cat >"$tmp/journey" <<EOF
#!/usr/bin/env bash
touch '$malicious_hook'
EOF
chmod +x "$tmp/journey"

for pair in S3:3 S10:10 S20:20; do
  tier="${pair%%:*}"
  hosts="${pair##*:}"
  status=0
  env -i PATH="$PATH" O3K_PP5_SCALE_JOURNEY="$tmp/journey" \
    O3K_PP5_EVIDENCE_ROOT="$tmp/evidence-$tier" \
    "$SCRIPT" --tier "$tier" --hosts "$hosts" >"$tmp/status-$tier.json" \
    2>"$tmp/diagnostic-$tier.txt" || status=$?
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
  if python3 "$ROOT_DIR/scripts/validate_pp5_evidence.py" "$tmp/status-$tier.json" \
      >"$tmp/validator-$tier.out" 2>&1; then
    echo "$tier deferred disposition was accepted as PP.5 evidence" >&2
    exit 1
  fi
  grep -Fq 'PP.5 evidence validation FAILED' "$tmp/validator-$tier.out"
  test ! -e "$tmp/evidence-$tier"
done

for pair in S3:2 S10:11 S20:19; do
  tier="${pair%%:*}"
  hosts="${pair##*:}"
  if "$SCRIPT" --tier "$tier" --hosts "$hosts" >"$tmp/out" 2>&1; then
    echo "$tier accepted wrong host count $hosts" >&2
    exit 1
  fi
  grep -Fq "requires exactly" "$tmp/out"
  ! grep -Fq 'o3k.pp5-lane-disposition.v1' "$tmp/out"
done

test ! -e "$malicious_hook"
echo "PP.5 scale tier guards passed"
