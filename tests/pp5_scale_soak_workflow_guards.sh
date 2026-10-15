#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CANONICAL="${ROOT_DIR}/.github/workflows/real-host-validation.yml"
UNSAFE="${ROOT_DIR}/.github/workflows/pp5-scale-soak.yml"

test -f "${CANONICAL}"
test ! -e "${UNSAFE}"

python3 - "${CANONICAL}" <<'PY'
import pathlib
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")

# Scale/soak lanes remain unavailable until the canonical workflow can produce
# the strict artifact and own the complete setup/cleanup lifecycle.
assert "pp5-scale-soak.yml" not in text
assert "scripts/pp5_scale_tier.sh" not in text
assert "scripts/pp5_soak.sh" not in text
assert "K-full" not in text

# Scale/soak acceptance remains disabled until the canonical lane owns a real
# producer. Guard both the dispatch choices and the pre-mutation allowlist so
# adding only one half of a lane cannot accidentally expose it.
inputs = text[text.index("inputs:"):text.index("permissions:")]
selection_start = text.index("Validate PP.5 lane selection")
selection_end = text.index("Acquire protected campaign lock", selection_start)
selection = text[selection_start:selection_end]
for lane in ("S3", "S10", "S20", "K-min", "K-full"):
    assert f"- {lane}" not in inputs, f"unsupported lane became a dispatch option: {lane}"
    assert lane not in selection, f"unsupported lane entered the pre-mutation allowlist: {lane}"
for lane in ("s3-scale", "s10-scale", "s20-scale", "k-min", "k-full"):
    assert lane not in inputs and lane not in selection, f"unsupported lane became selectable: {lane}"

# Unsupported lane values must fail before TestLab mutation.
selection = text.index("Validate PP.5 lane selection")
bootstrap = text.index("Bootstrap disposable TestLab")
assert selection < bootstrap
assert "unsupported PP.5 lane" in text[selection:bootstrap]
PY

echo "PP.5 scale/soak workflow guards: PASS"
