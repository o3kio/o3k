#!/usr/bin/env bash
set -Eeuo pipefail
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/var/tmp}/o3k-p15-7-dispatch.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT
cat >"$work/gh" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "${O3K_FAKE_GH_RUNS:-[]}"
SH
chmod +x "$work/gh"
sha=0123456789abcdef0123456789abcdef01234567
if ! PATH="$work:$PATH" O3K_FAKE_GH_RUNS='[{"databaseId":123,"status":"in_progress","headSha":"abc","event":"workflow_dispatch"}]' \
  bash "$root_dir/scripts/p15-7-protected-dispatch-guard.sh" "$sha" >/dev/null 2>&1; then :; else
  echo "active duplicate dispatch was accepted" >&2; exit 1
fi
if PATH="$work:$PATH" O3K_FAKE_GH_RUNS='[{"databaseId":124,"status":"waiting","headSha":"abc","event":"workflow_dispatch"}]' \
  bash "$root_dir/scripts/p15-7-protected-dispatch-guard.sh" "$sha" >/dev/null 2>&1; then
  echo "waiting duplicate dispatch was accepted" >&2; exit 1
fi
PATH="$work:$PATH" O3K_FAKE_GH_RUNS='[]' bash "$root_dir/scripts/p15-7-protected-dispatch-guard.sh" "$sha" >/dev/null
echo "P15.7 dispatch guard tests passed"
