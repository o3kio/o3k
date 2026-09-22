#!/usr/bin/env bash
# Bounded external Horizon witness for PP.4 Core.
#
# The witness runs the pinned, unmodified OpenStack Horizon 2026.1 image and
# deploys it exactly the way its own Kolla packaging expects: a Kolla
# config.json, an operator-supplied uWSGI configuration, and ordinary
# endpoint/region/session settings. There is no fork, no source patch and no
# O3K-specific Horizon code.
#
# Three properties of the pinned image are harness assumptions, not O3K
# contracts, and each one has already hidden a defect behind a misclassified
# failure:
#
# - It is a genuine Kolla image (`kolla_start` + `/var/lib/kolla/config_files`),
#   so it needs KOLLA_CONFIG_STRATEGY and a config.json; and its own
#   `kolla_extend_start` collects static assets, so the witness does not have
#   to work around Horizon's STATIC_ROOT.
# - Horizon settings are read through
#   `openstack_dashboard/local/local_settings.py`, which this image ships as a
#   symlink to `/etc/openstack-dashboard/local_settings.py` (with the `.py`
#   suffix). A Kolla `dest` of `/etc/openstack-dashboard/local_settings` is
#   copied but never imported.
# - The O3K identity endpoint is loopback-bound (`O3K_LISTEN_ADDR`, for example
#   `127.0.0.1:18080` for the libvirt profile). A bridge-networked container
#   cannot reach it at any address, so the witness runs the container with host
#   networking and reads the endpoint and region from `/etc/o3k/admin-openrc`
#   instead of hardcoding them.
#
# Docker access is host test infrastructure, not a product dependency.
# shellcheck disable=SC1090,SC1091,SC2024,SC2034,SC2154
set -Eeuo pipefail
EVID=${1:?evidence directory}; REQUIRED=${O3K_PP4_HORIZON_REQUIRED:-0}
WORKDIR="$(mktemp -d /tmp/pp4-horizon.XXXXXX)"
cleanup(){ rm -rf -- "$WORKDIR"; }
trap cleanup EXIT
OPENRC="$WORKDIR/admin-openrc"; sudo cp /etc/o3k/admin-openrc "$OPENRC"; sudo chown "$(id -u):$(id -g)" "$OPENRC"; chmod 600 "$OPENRC"; source "$OPENRC"
IMAGE="quay.io/openstack.kolla/horizon:2026.1-ubuntu-noble@sha256:723903d16317c53172f08c7f930b2c326f8b7fa16da98bf032e05ef287e0b048"
# Paths inside the pinned image's own virtualenv layout; not an O3K contract.
VENV=/var/lib/kolla/venv
SITE=$VENV/lib/python3.12/site-packages/openstack_dashboard
PORT=18091
NAME=pp4-horizon-witness; CONF="$WORKDIR/config"; JAR="$EVID/horizon.jar"
DOCKER=(sudo docker)
summary(){ printf '%s\n' "$*" | tee -a "$EVID/horizon-summary.txt"; }
# uWSGI in this image logs to stdout, so `docker logs` carries the real
# failure; capture it together with bounded, non-secret container state before
# the witness gives up, otherwise a failed run cannot be classified.
capture_diagnostics(){
  "${DOCKER[@]}" inspect "$NAME" --format \
    'running={{.State.Running}} status={{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}} restarts={{.RestartCount}} error={{.State.Error}}' \
    >"$EVID/horizon-container-state.txt" 2>&1 || true
  "${DOCKER[@]}" logs "$NAME" >"$EVID/horizon-docker.log" 2>&1 || true
}
fail(){ summary "RESULT: FAIL $1"; capture_diagnostics; [[ "$REQUIRED" == 1 ]] && exit 1 || exit 0; }
optional(){ summary "RESULT: $1"; [[ "$REQUIRED" == 1 ]] && exit 1 || exit 0; }
if ! command -v docker >/dev/null 2>&1; then optional 'NOT_APPLICABLE_OPTIONAL docker-unavailable'; fi
sudo systemctl start docker >/dev/null 2>&1 || fail docker-unavailable
"${DOCKER[@]}" rm -f "$NAME" >/dev/null 2>&1 || true
"${DOCKER[@]}" pull -q "$IMAGE" >"$EVID/horizon-pull.txt" 2>&1 || fail image-pull
printf 'image=%s\n' "$IMAGE" >"$EVID/horizon-image.txt"
"${DOCKER[@]}" image inspect "$IMAGE" --format 'id={{.Id}} repo_digests={{.RepoDigests}}' >"$EVID/horizon-image-id.txt" 2>&1 || true
# The Keystone endpoint and region come from the installed client credential
# file, never from a hardcoded witness guess.
[[ "${OS_AUTH_URL:-}" =~ ^https?://[A-Za-z0-9._:-]+/v3/?$ ]] || fail identity-endpoint-unusable
[[ "${OS_REGION_NAME:-}" =~ ^[A-Za-z0-9._-]+$ ]] || fail identity-region-unusable
KEYSTONE_URL="${OS_AUTH_URL%/}"; REGION="$OS_REGION_NAME"
mkdir -p "$CONF"
cat >"$CONF/config.json" <<EOF
{"command":"$VENV/bin/uwsgi --ini /var/lib/kolla/config_files/horizon.ini",
 "config_files":[{"source":"/var/lib/kolla/config_files/local_settings","dest":"/etc/openstack-dashboard/local_settings.py","owner":"horizon","perm":"0640"}]}
EOF
cat >"$CONF/horizon.ini" <<EOF
[uwsgi]
http-socket = 0.0.0.0:$PORT
chdir = $SITE
wsgi-file = $SITE/wsgi.py
pythonpath = $VENV/lib/python3.12/site-packages
master = true
processes = 4
threads = 4
enable-threads = true
uid = horizon
gid = kolla
buffer-size = 65535
EOF
cat >"$CONF/local_settings" <<EOF
import os
DEBUG = False
ALLOWED_HOSTS = ['*']
WEBROOT = '/'
# Local witness session key for the unmodified image; not a credential.
SECRET_KEY = 'pp4-core-witness-local-session-key'
STATIC_ROOT = '/var/lib/kolla/static'
# Upstream Horizon defaults (openstack_dashboard/defaults.py). 'compute' selects
# the novaclient v2 family; it is not a Nova REST microversion. A value of 2.1
# here is rejected by Horizon's own API-version registry
# (openstack_dashboard/api/base.py) as an unsupported compute version.
OPENSTACK_API_VERSIONS = {'identity': 3, 'image': 2, 'volume': 3, 'compute': 2}
OPENSTACK_HOST = '127.0.0.1'
OPENSTACK_KEYSTONE_URL = '$KEYSTONE_URL'
OPENSTACK_KEYSTONE_DEFAULT_ROLE = 'admin'
OPENSTACK_ENDPOINT_TYPE = 'publicURL'
# Pin the region instead of relying on unauthenticated version discovery, so
# the session region matches the region O3K advertises in its catalog.
AVAILABLE_REGIONS = [(OPENSTACK_KEYSTONE_URL, '$REGION')]
# The image's default session backend is a per-process cache, so a session
# written by one uWSGI worker is invisible to the others and login appears to
# succeed while every later request is anonymous. Cookie-backed sessions are
# stateless across workers and are an ordinary, supported Horizon setting.
SESSION_ENGINE = 'django.contrib.sessions.backends.signed_cookies'
CACHES = {'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}}
EOF
chmod 0644 "$CONF/config.json" "$CONF/horizon.ini" "$CONF/local_settings"
"${DOCKER[@]}" run -d --name "$NAME" --restart no --network host \
  -e KOLLA_CONFIG_STRATEGY=COPY_ALWAYS \
  -v "$CONF:/var/lib/kolla/config_files:ro" \
  "$IMAGE" >"$EVID/horizon-run.txt" 2>&1 || fail container-start
ready=0
for _ in $(seq 1 60); do
  curl -sf "http://127.0.0.1:$PORT/" >/dev/null 2>&1 && ready=1 && break
  "${DOCKER[@]}" inspect "$NAME" --format '{{.State.Running}}' 2>/dev/null | grep -q true || break
  sleep 2
done
(( ready == 1 )) || fail http-readiness
summary 'image: PASS'; summary 'boot: PASS'
summary 'keystone_endpoint='"$KEYSTONE_URL"
summary 'region='"$REGION"
curl -s -c "$JAR" "http://127.0.0.1:$PORT/auth/login/" -o "$EVID/horizon-login.html" || true
cat >"$WORKDIR/form.py" <<'PY'
import re, sys
from urllib.parse import urlencode
html_path, out_path = sys.argv[1], sys.argv[2]
password = sys.stdin.readline().rstrip("\n")
with open(html_path, encoding="utf-8", errors="replace") as handle:
    page = handle.read()


def value_of(name):
    for pattern in (r'name="%s"[^>]*\bvalue="([^"]*)"',
                    r'\bvalue="([^"]*)"[^>]*name="%s"'):
        found = re.search(pattern % re.escape(name), page)
        if found:
            return found.group(1)
    return ""


csrf = value_of("csrfmiddlewaretoken")
if not csrf:
    sys.exit("csrf token missing from rendered login form")
# Submit exactly the fields the rendered form exposes: the region value is an
# index into AVAILABLE_REGIONS, not a region name, and the domain field only
# exists when multi-domain support is enabled.
data = {"csrfmiddlewaretoken": csrf, "username": "admin", "password": password}
for name in ("region", "domain"):
    if re.search(r'name="%s"' % re.escape(name), page):
        data[name] = value_of(name)
with open(out_path, "w", encoding="utf-8") as handle:
    handle.write(urlencode(data))
PY
chmod 700 "$WORKDIR/form.py"
printf '%s\n' "$OS_PASSWORD" | python3 "$WORKDIR/form.py" "$EVID/horizon-login.html" "$WORKDIR/form" || fail login-form-extraction
chmod 600 "$WORKDIR/form"
login_code=$(curl -s -b "$JAR" -c "$JAR" -e "http://127.0.0.1:$PORT/auth/login/" \
  --data-binary "@$WORKDIR/form" "http://127.0.0.1:$PORT/auth/login/" \
  -o "$EVID/horizon-login-response.html" -w '%{http_code}' || true)
rm -f "$WORKDIR/form" "$WORKDIR/form.py"
summary "login POST: HTTP-$login_code"
# A successful form login redirects; the authenticated project page is what
# proves the Keystone session, the project context and the catalog scope.
project_code=$(curl -s -b "$JAR" -c "$JAR" "http://127.0.0.1:$PORT/project/" \
  -o "$EVID/horizon-project.html" -w '%{http_code}' || true)
summary "project context: HTTP-$project_code"
# An authenticated session renders the dashboard with a sign-out affordance and
# a panel title; an unauthenticated request is redirected to the login page.
# The affordance label differs between Horizon series ("Log Out" before 2026.1,
# "Sign Out" from 2026.1), so accept both rather than pin a version's wording.
if ! grep -qiE 'sign out|log out' "$EVID/horizon-project.html"; then fail login-session; fi
if grep -qiE '<title>[^<]*login' "$EVID/horizon-project.html"; then fail login-session; fi
summary 'login: PASS'
summary 'project context: PASS'
for panel in /identity/ /project/images/ /project/networks/ /project/instances/; do
  code=$(curl -s -b "$JAR" -o "$EVID/horizon-${panel//\//_}.html" -w '%{http_code}' "http://127.0.0.1:$PORT$panel")
  if [[ "$code" == 200 ]]; then summary "panel $panel: PASS"; else summary "panel $panel: NOT_PROVEN HTTP-$code"; fi
done
# A panel can answer 200 and still leave the client reporting a recoverable
# error, which is a real O3K compatibility signal rather than a cosmetic one.
# Two such signals are asserted rather than tolerated:
# - the client's pagination guard, which fires when a collection ignores
#   `limit`/`marker` and re-serves the page instead of ending the traversal;
# - the client's API-version registry, which rejects a configured version it
#   does not support.
# Other recoverable messages (for example a missing optional read such as
# /limits) are recorded in the log and classified rather than asserted here.
"${DOCKER[@]}" logs "$NAME" >"$EVID/horizon-docker.log" 2>&1 || true
if grep -q 'Endless pagination loop detected' "$EVID/horizon-docker.log"; then
  fail pagination-loop-detected
fi
if grep -q 'is not a supported API version' "$EVID/horizon-docker.log"; then
  fail client-api-version-mismatch
fi
summary 'client pagination guard: PASS'
summary 'client compute API selector: PASS'
summary 'native_resource_identity='"${O3K_PP4_NATIVE_ID:-unknown}"; summary 'compatibility_resource_identity='"${O3K_PP4_COMPAT_ID:-unknown}"
if grep -RqiE 'pp4-native|pp4-openstack|'"${O3K_PP4_NATIVE_ID:-nomatch}"'|'"${O3K_PP4_COMPAT_ID:-nomatch}" "$EVID"/horizon-*.html; then
  summary 'resource observation: PASS expected Core resources visible in Horizon response'
else
  summary 'resource observation: NOT_PROVEN expected Core resource names/IDs absent from Horizon response'
  [[ "$REQUIRED" == 1 ]] && exit 1 || exit 0
fi
summary 'RESULT: PASS bounded Horizon witness'
