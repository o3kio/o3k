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
  if output="$(env -i PATH="$PATH" O3K_PP5_SCALE_JOURNEY="$tmp/journey" \
    O3K_PP5_EVIDENCE_ROOT="$tmp/evidence-$tier" \
    "$SCRIPT" --tier "$tier" --hosts "$hosts" 2>&1)"; then
    echo "unsupported $tier producer unexpectedly passed" >&2
    exit 1
  fi
  grep -Fq 'classification=EVIDENCE_GAP' <<<"$output"
  grep -Fq 'no TestLab or evidence state was changed' <<<"$output"
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
done

test ! -e "$malicious_hook"
echo "PP.5 scale tier guards passed"
