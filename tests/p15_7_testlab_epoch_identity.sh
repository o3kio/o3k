#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
JOURNEY="$ROOT_DIR/scripts/p15-7-real-host-journey.sh"

# The public P15.7 run identity and the disposable TestLab epoch identity are
# separate: the latter owns the suffixed state root and ownership marker.
python3 - "$JOURNEY" <<'PY'
import pathlib
import re
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
assert 'TESTLAB_RUN_ID="${O3K_TESTLAB_RUN_ID:-$RUN_ID}"' in source
assert 'STATE_ROOT="${O3K_TESTLAB_STATE_ROOT:-/var/lib/o3k-testlab/$TESTLAB_RUN_ID}"' in source
assert '[[ "$TESTLAB_RUN_ID" =~ ^([0-9]+|local-[0-9]+)(-(generic|pp5))?$ ]]' in source

helper = re.search(r"(?ms)^observe_protected_testlab_state\(\) \{\n(.*?)^\}", source)
assert helper is not None, "protected TestLab observer helper is missing"
body = helper.group(1)
assert '"$TESTLAB_RUN_ID"' in body
assert '"$STATE_ROOT"' in body
assert '"$SOURCE_SHA"' in body
assert 'scripts/pp5-protected-state-observer.py' in body
assert source.count('scripts/pp5-protected-state-observer.py') == 1, \
    "journey observer calls must stay centralized"
assert source.count('observe_protected_testlab_state bootstrap-agent-id') == 3
assert source.count('observe_protected_testlab_state verify-marker') == 1
PY

# Test the real failure classifier extracted from the journey. This mismatch is
# a harness epoch/ownership error, not an unknown product failure.
# shellcheck disable=SC1090
source <(sed -n '/^classify_failure() {/,/^}/p' "$JOURNEY")
[[ "$(classify_failure 'TestLab ownership marker failed privileged verification')" == harness_gap ]]
[[ "$(classify_failure 'required journey agent identity unavailable for s1-boundary: block-a')" == harness_gap ]]

# Boundary tiers use only the agent identities included by their exact
# topology. S1 has no child agent; S2 has one; scale/recovery lanes use the
# full child set required by their journey.
agent_requirements="$(sed -n '/^required_child_agent_ids() {/,/^}/p' "$JOURNEY")"
[[ -n "$agent_requirements" ]] || { echo "journey child-agent requirements helper is missing" >&2; exit 1; }
# shellcheck disable=SC1090
source <(printf '%s\n' "$agent_requirements")
[[ "$(required_child_agent_ids s1-boundary)" == "" ]]
[[ "$(required_child_agent_ids s2-boundary)" == "block-a" ]]
for lane in s5-scale 1035-crash-recovery host-maintenance integrated; do
  [[ "$(required_child_agent_ids "$lane")" == $'block-a\nblock-b\nblock-c\nblock-d\nblock-e' ]]
done
if required_child_agent_ids unsupported-lane >/dev/null; then
  echo "unsupported lane returned child-agent requirements" >&2
  exit 1
fi

python3 - "$JOURNEY" <<'PY'
import pathlib, sys
source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
assert 'for required_agent in "${REQUIRED_CHILD_AGENT_IDS[@]}"; do' in source
assert 'for agent_id in "${REQUIRED_CHILD_AGENT_IDS[@]}"; do' in source
assert 'canonical capacity/replacement identities unavailable' not in source
PY

echo "P15.7 TestLab epoch identity guards PASS"
