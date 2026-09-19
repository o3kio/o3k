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
rm -rf "$PROFILE"
mkdir -p "$PROFILE"
certutil -d "sql:$PROFILE" -N --empty-password >/dev/null 2>&1
certutil -d "sql:$PROFILE" -A -t "C,," -n o3k-demo-ca \
  -i /var/lib/o3k/araf-demo/tls/ca.crt >/dev/null

nohup "$CHROME" \
  --remote-debugging-address=127.0.0.1 \
  --remote-debugging-port=9223 \
  --user-data-dir="$PROFILE" \
  --no-sandbox --disable-gpu --disable-dev-shm-usage \
  --no-first-run --disable-extensions \
  about:blank >"$EVID/browser-chrome.log" 2>&1 &
echo $! > "$EVID/browser-chrome.pid"

for i in $(seq 1 60); do
  if curl -sf http://127.0.0.1:9223/json/version >/dev/null 2>&1; then
    echo "ready" > "$READY"
    exit 0
  fi
  sleep 1
done
echo "chromium did not expose CDP" >&2
exit 1
