#!/usr/bin/env bash
set -Eeuo pipefail

# Exercise the repository-owned read-only GET retry boundary without starting
# TestLab. The journey is intentionally sourced only for these two functions;
# all authority, VM, and mutation setup remains outside this cheap regression.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/o3k-p15-7-api-read.XXXXXX")"
trap 'rm -rf -- "$WORK_DIR"' EXIT
mkdir -p "$WORK_DIR/bin" "$WORK_DIR/work" "$WORK_DIR/artifacts"

cat >"$WORK_DIR/bin/curl" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
output=""
while (($#)); do
  if [[ "$1" == --output ]]; then
    output="$2"; shift 2
  else
    shift
  fi
done
[[ -n "$output" ]]
counter_file="${O3K_FAKE_CURL_COUNTER:?}"
count=0
[[ -f "$counter_file" ]] && count="$(<"$counter_file")"
count=$((count + 1))
printf '%s\n' "$count" >"$counter_file"
case "${O3K_FAKE_CURL_MODE:-transient}" in
  transient)
    if ((count < 3)); then
      printf '{"error":"transient"}\n' >"$output"
      printf '500'
    else
      printf '{"ok":true}\n' >"$output"
      printf '200'
    fi
    ;;
  client_error)
    printf '{"error":"not-found"}\n' >"$output"
    printf '404'
    ;;
  persistent)
    printf '{"error":"still-unavailable","secret":"must-not-be-stored"}\n' >"$output"
    printf '503'
    ;;
  *)
    echo "unknown fake curl mode" >&2
    exit 2
    ;;
esac
SH
chmod 0700 "$WORK_DIR/bin/curl"

# Extract only the contiguous function definitions; this keeps the regression
# coupled to the production implementation while avoiding execution of its
# expensive top-level preflight.
sed -n '/^write_api_read_failure_evidence() {/,/^record_scale_checkpoint() {/p' \
  "$ROOT_DIR/scripts/p15-7-real-host-journey.sh" | sed '$d' >"$WORK_DIR/functions.sh"

export PATH="$WORK_DIR/bin:$PATH"
export ARTIFACT_DIR="$WORK_DIR/artifacts"
export WORK_ROOT="$WORK_DIR/work"
export API=http://127.0.0.1:1/o3k/v1
export OPERATOR_CURL_CONFIG="$WORK_DIR/work/curl.conf"
export RUN_ID=api-read-guard
export SOURCE_SHA=0123456789abcdef0123456789abcdef01234567
export P15_7_API_READ_ATTEMPTS=3
export P15_7_API_READ_DELAY_SECONDS=0
export P15_7_API_READ_TIMEOUT_SECONDS=1
export TRANSIENT_EVENTS_FILE="$ARTIFACT_DIR/transient.jsonl"
export O3K_FAKE_CURL_COUNTER="$WORK_DIR/counter"
: >"$OPERATOR_CURL_CONFIG"

refresh_operator_authority() { :; }
record_transient() {
  printf '%s|%s|%s|%s\n' "$1" "$2" "$3" "${4:-}" >>"$TRANSIENT_EVENTS_FILE"
}
source "$WORK_DIR/functions.sh"

export O3K_FAKE_CURL_MODE=transient
printf '0\n' >"$O3K_FAKE_CURL_COUNTER"
[[ "$(api_get /operator/diagnostics/providers transient-read)" == '{"ok":true}' ]]
[[ "$(<"$O3K_FAKE_CURL_COUNTER")" == 3 ]]
[[ "$(wc -l <"$TRANSIENT_EVENTS_FILE")" == 2 ]]
[[ ! -e "$ARTIFACT_DIR/p15-7-api-read-failure-transient-read-01.json" ]]

export O3K_FAKE_CURL_MODE=client_error
printf '0\n' >"$O3K_FAKE_CURL_COUNTER"
if api_get /operator/diagnostics/providers client-error-read >/dev/null; then
  echo "4xx API read unexpectedly retried/succeeded" >&2
  exit 1
fi
[[ "$(<"$O3K_FAKE_CURL_COUNTER")" == 1 ]]
python3 - "$ARTIFACT_DIR/p15-7-api-read-failure-client-error-read-01.json" <<'PY'
import json, pathlib, sys
doc = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert doc["http_status"] == "404"
assert doc["attempts"] == 1
PY

export O3K_FAKE_CURL_MODE=persistent
printf '0\n' >"$O3K_FAKE_CURL_COUNTER"
if api_get /operator/diagnostics/providers persistent-read >/dev/null; then
  echo "persistent 5xx API read unexpectedly succeeded" >&2
  exit 1
fi
[[ "$(<"$O3K_FAKE_CURL_COUNTER")" == 3 ]]
python3 - "$ARTIFACT_DIR/p15-7-api-read-failure-persistent-read-01.json" <<'PY'
import json, pathlib, sys
doc = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert doc["http_status"] == "503"
assert doc["attempts"] == 3
assert doc["response"]["bytes"] > 0
assert "must-not-be-stored" not in pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
PY

# A repeated phase label must preserve the first diagnostic rather than
# replacing it. Both response and transport files are represented only by
# hashes, even when they contain credential-shaped text.
first_artifact="$ARTIFACT_DIR/p15-7-api-read-failure-persistent-read-01.json"
printf '%s\n' '{"secret":"second-response"}' >"$WORK_DIR/second-body"
printf '%s\n' 'Authorization: Bearer second-secret' >"$WORK_DIR/second-error"
first_digest="$(sha256sum "$first_artifact" | cut -d' ' -f1)"
write_api_read_failure_evidence persistent-read /operator/diagnostics/providers 4 0 503 \
  "$WORK_DIR/second-body" "$WORK_DIR/second-error"
[[ "$(sha256sum "$first_artifact" | cut -d' ' -f1)" == "$first_digest" ]]
[[ -f "$ARTIFACT_DIR/p15-7-api-read-failure-persistent-read-02.json" ]]
if rg -n 'second-response|second-secret' "$ARTIFACT_DIR"; then
  echo "secret-shaped retry diagnostics leaked into API failure artifacts" >&2
  exit 1
fi

echo "P15.7 API read retry guards PASS"
