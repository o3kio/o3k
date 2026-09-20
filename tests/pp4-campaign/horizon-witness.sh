#!/usr/bin/env bash
# PP.4 OPTIONAL Horizon compatibility witness (unmodified upstream Horizon).
#
# Role: external OpenStack ecosystem witness — explicitly NOT the O3K
# dashboard (that is Araf). Horizon runs unmodified (only normal OpenStack
# endpoint/auth configuration) and consumes the bounded Keystone/Nova/
# Neutron/Glance subset of o3k-demo-v1. Whatever the bounded profile
# supports is exercised; whatever it lacks must fail truthfully and is
# CLASSIFIED as an O3K compatibility gap here — never patched around.
#
# The script is non-blocking for the campaign: it always exits 0 and records
# PASS/FAIL/GAP per bounded-journey step into 30-horizon-summary.txt.
#
# Usage: bash horizon-witness.sh <evidence-dir>
set -Eeuo pipefail
EVID="${1:?evidence dir}"
source /etc/o3k/admin-openrc
SUMMARY="$EVID/30-horizon-summary.txt"
: > "$SUMMARY"
note() { echo "$*" | tee -a "$SUMMARY"; }
step() { # step NAME -> records PASS/FAIL/GAP
  local name="$1" result="$2" detail="${3:-}"
  printf '%s: %s %s\n' "$name" "$result" "$detail" | tee -a "$SUMMARY"
}

HORIZON_IMAGE="${O3K_PP4_HORIZON_IMAGE:-quay.io/openstack.kolla/horizon:2024.1}"
KEYSTONE="http://172.17.0.1:18090/v3"
ADMIN_PW="${OS_PASSWORD:?admin password required}"
CONF=/var/lib/o3k/horizon-witness
NAME=pp4-horizon-witness
SECRET_TMP="$(mktemp -d "${TMPDIR:-/tmp}/pp4-horizon.XXXXXX")"
cleanup_secret_files() {
  rm -f "$SECRET_TMP/login.secrets" "$SECRET_TMP/login.form"
  rmdir "$SECRET_TMP" 2>/dev/null || true
}
trap cleanup_secret_files EXIT

note "witness: unmodified $HORIZON_IMAGE"
note "keystone endpoint (via demo api-relay): $KEYSTONE"

if docker ps -a --format '{{.Names}}' | grep -q "^${NAME}$"; then
  docker rm -f "$NAME" >/dev/null 2>&1 || true
fi

docker pull -q "$HORIZON_IMAGE" >/dev/null || { step image PULL-FAIL; note "RESULT: WITNESS-SKIPPED"; exit 0; }
step image PRESENT "$HORIZON_IMAGE"

mkdir -p "$CONF"
cat > "$CONF/config.json" <<'EOF'
{
  "command": "/usr/sbin/apache2ctl -DFOREGROUND",
  "config_files": [
    {
      "source": "/var/lib/kolla/config_files/src/local_settings",
      "dest": "/etc/openstack-dashboard/local_settings",
      "owner": "horizon",
      "perm": "0644"
    }
  ]
}
EOF
cat > "$CONF/local_settings" <<EOF
import os
DEBUG = False
ALLOWED_HOSTS = ["*"]
WEBROOT = '/'
OPENSTACK_API_VERSIONS = {"identity": 3, "image": 2, "volume": 3, "compute": 2.1}
OPENSTACK_HOST = "172.17.0.1"
OPENSTACK_KEYSTONE_URL = "$KEYSTONE"
OPENSTACK_KEYSTONE_DEFAULT_ROLE = "admin"
OPENSTACK_ENDPOINT_TYPE = "publicURL"
SECRET_KEY = "$(openssl rand -hex 32)"
CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
HORIZON_CONFIG = {
    "help_url": "http://docs.openstack.org",
    "exceptions": {"recoverable": [], "not_found": [], "unauthorized": []},
}
EOF
chmod 755 "$CONF" "$CONF/config.json" "$CONF/local_settings"

docker run -d --name "$NAME" --restart no \
  -e KOLLA_CONFIG_STRATEGY=COPY_ALWAYS \
  -e KEYSTONE_ADMIN_PASSWORD="$ADMIN_PW" \
  -p 127.0.0.1:18091:80 \
  -v "$CONF:/var/lib/kolla/config_files/src:ro" \
  "$HORIZON_IMAGE" >"$EVID/30-horizon-run.txt" 2>&1 || { step boot FAIL "docker run rejected"; note "RESULT: WITNESS-FAIL"; exit 0; }

READY=0
for i in $(seq 1 90); do
  if curl -sf -o /dev/null http://127.0.0.1:18091/ 2>/dev/null; then READY=1; break; fi
  sleep 2
done
if [ "$READY" != 1 ]; then
  docker logs "$NAME" >"$EVID/30-horizon-docker-logs.txt" 2>&1 || true
  step boot FAIL "http never came up"
  note "RESULT: WITNESS-FAIL (see 30-horizon-docker-logs.txt)"
  exit 0
fi
step boot PASS "http://127.0.0.1:18091/"

JAR="$EVID/30-horizon-jar.txt"; rm -f "$JAR"
HTML="$EVID/30-horizon-login.html"
curl -s -c "$JAR" -b "$JAR" http://127.0.0.1:18091/auth/login/ -o "$HTML" || true
CSRF="$(grep -oE 'name="csrfmiddlewaretoken" value="[^"]+"' "$HTML" | head -1 | sed -E 's/.*value="([^"]+)".*/\1/')"
if [ -z "$CSRF" ]; then
  step login GAP "no Django CSRF token on login page (see 30-horizon-login.html)"
  note "RESULT: WITNESS-GAP-AT-LOGIN"
  exit 0
fi
LOGIN_RESP="$EVID/30-horizon-login-post.txt"
LOGIN_FORM="$SECRET_TMP/login.form"
printf '%s\n%s\n' "$CSRF" "$ADMIN_PW" > "$SECRET_TMP/login.secrets"
chmod 600 "$SECRET_TMP/login.secrets"
python3 - "$SECRET_TMP/login.secrets" "$LOGIN_FORM" <<'PY'
import sys
from urllib.parse import urlencode
csrf, password = open(sys.argv[1], encoding="utf-8").read().splitlines()
path = sys.argv[2]
with open(path, "wb") as handle:
    handle.write(urlencode({"csrfmiddlewaretoken": csrf, "username": "admin",
                            "password": password, "domain": "Default",
                            "region": "RegionOne"}).encode())
PY
curl -s -c "$JAR" -b "$JAR" -o "$LOGIN_RESP" -w '%{http_code}' \
  -e http://127.0.0.1:18091/auth/login/ \
  --data-binary "@$LOGIN_FORM" \
  http://127.0.0.1:18091/auth/login/ | tee -a "$SUMMARY" >/dev/null
rm -f "$LOGIN_FORM" "$SECRET_TMP/login.secrets"
IDENTITY_OUT="$(curl -s -b "$JAR" http://127.0.0.1:18091/identity/ 2>/dev/null)"
if grep -q 'Log Out' "$LOGIN_RESP" 2>/dev/null || grep -q 'Log Out' <<<"$IDENTITY_OUT"; then
  step login PASS "Keystone-backed Django session"
else
  step login FAIL "session not established (Keystone auth or catalog gap)"
  note "RESULT: WITNESS-FAIL-AT-LOGIN"
  exit 0
fi

probe_panel() { # name url must_contain_regex
  local name="$1" url="$2" want="$3"
  local out="$EVID/30-horizon-${name}.html"
  code="$(curl -s -b "$JAR" -o "$out" -w '%{http_code}' "http://127.0.0.1:18091$url")"
  if [ "$code" = 200 ] && grep -qE "$want" "$out"; then
    step "$name" PASS
  elif [ "$code" = 200 ]; then
    step "$name" GAP "HTTP 200 but expected content absent (truthful partial render?)"
  else
    step "$name" GAP "HTTP $code (missing endpoint or panel dependency)"
  fi
}

probe_panel project-home "/identity/" "Project"
probe_panel images "/project/images/" "cirros|Images|No items"
probe_panel networks "/project/networks/" "testlab-network|Networks|No items"
probe_panel instances "/project/instances/" "test-vm|Instances|No items"

note "RESULT: witness executed bounded journey panels; GAP entries are O3K compatibility classifications, not Horizon patches"
exit 0
