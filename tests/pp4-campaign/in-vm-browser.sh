#!/usr/bin/env bash
# PP.4 campaign — launch a real Chromium (headless shell) INSIDE the VM with
# the demo CA imported into its NSS profile, exposing CDP on 127.0.0.1:9223.
# The host runner forwards the port and drives it with Playwright.
#
# Usage: sudo bash in-vm-browser.sh <browser-dir> <evidence-dir>
set -Eeuo pipefail
BROWSER_DIR="${1:?browser dir}"
EVID="${2:?evidence dir}"
CHROME="$BROWSER_DIR/chrome/chrome-headless-shell"
PROFILE="$BROWSER_DIR/profile"
READY="$EVID/browser-ready"
rm -f "$READY"

[ -x "$CHROME" ] || { echo "chromium missing at $CHROME" >&2; exit 1; }
[ -f /var/lib/o3k/araf-demo/tls/ca.crt ] || { echo "demo CA missing" >&2; exit 1; }

# A previous incarnation (pre-reboot or a failed attempt) can leave chromium
# processes holding the CDP port, the profile singleton AND the NSS database
# lock (certutil then blocks forever). Clear them before touching either.
pkill -f chrome-headless-shell >/dev/null 2>&1 || true
sleep 2
rm -f "${HOME:-/root}/.pki/nssdb/"*.lock 2>/dev/null || true
rm -f "$PROFILE/SingletonLock" "$PROFILE/SingletonSocket" 2>/dev/null || true

# Test-tooling libraries for the headless shell (campaign-only; not part of
# the product install).
export DEBIAN_FRONTEND=noninteractive
apt-get install -y -qq libnss3 libnspr4 libnss3-tools libgbm1 >/dev/null 2>&1 || true

if ! ldd "$CHROME" 2>/dev/null | grep -q 'not found'; then :; else
  ldd "$CHROME" | grep 'not found' || true
  echo "chromium has missing libraries" >&2
  exit 1
fi

# Fresh profile with the demo CA as a trust anchor (browser trust evidence).
# Chromium on Linux consults the per-user NSS database (~/.pki/nssdb), NOT the
# --user-data-dir profile, so the trust anchor must be imported there; the
# profile-dir import is kept as a belt-and-braces copy.
#
# Every certutil call is bounded and non-interactive: re-initialising an
# existing NSS database whose password is not empty prompts for it forever with
# stdin at /dev/null (this hung the post-reboot relaunch). An unusable database
# is recreated instead.
CA_FILE=/var/lib/o3k/araf-demo/tls/ca.crt
trust_nssdb() { # DIR
  local dir="$1"
  mkdir -p "$dir"
  if ! timeout 20 certutil -d "sql:$dir" -L </dev/null >/dev/null 2>&1; then
    rm -rf "$dir"
    mkdir -p "$dir"
    timeout 30 certutil -d "sql:$dir" -N --empty-password </dev/null >/dev/null 2>&1 || true
  fi
  timeout 30 certutil -d "sql:$dir" -A -t "C,," -n o3k-demo-ca -i "$CA_FILE" \
    </dev/null >/dev/null 2>&1 || true
  timeout 20 certutil -d "sql:$dir" -L -n o3k-demo-ca </dev/null >/dev/null 2>&1 \
    || { echo "demo CA could not be imported into $dir" >&2; exit 1; }
}
NSSDB="${HOME:-/root}/.pki/nssdb"
trust_nssdb "$NSSDB"
certutil -d "sql:$NSSDB" -L > "$EVID/browser-nssdb-anchors.txt" 2>&1 || true
rm -rf "$PROFILE"
trust_nssdb "$PROFILE"

launch_chrome() {
nohup "$CHROME" \
  --remote-debugging-address=127.0.0.1 \
  --remote-debugging-port=9223 \
  --user-data-dir="$PROFILE" \
  --no-sandbox --disable-gpu --disable-dev-shm-usage \
  --no-first-run --disable-extensions \
  about:blank >>"$EVID/browser-chrome.log" 2>&1 &
echo $! > "$EVID/browser-chrome.pid"
}

: >"$EVID/browser-chrome.log"
attempt=1
while [ "$attempt" -le 3 ]; do
  launch_chrome
  for i in $(seq 1 45); do
    if curl -sf http://127.0.0.1:9223/json/version >/dev/null 2>&1; then
      echo "ready" > "$READY"
      exit 0
    fi
    sleep 1
  done
  echo "chromium attempt $attempt did not expose CDP; retrying" >&2
  pkill -f chrome-headless-shell >/dev/null 2>&1 || true
  sleep 3
  attempt=$((attempt + 1))
done
echo "chromium did not expose CDP after 3 attempts" >&2
exit 1
