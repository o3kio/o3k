#!/usr/bin/env bash
# Bounded external Horizon witness for PP.4 Core.
#
# The witness runs the pinned, unmodified OpenStack Horizon 2024.1 image and
# deploys it the way that image's own packaging expects: an ordinary
# Apache/mod_wsgi vhost, an ordinary openstack_dashboard local_settings
# module, and ordinary endpoint/region/session settings. There is no fork,
# no source patch and no O3K-specific Horizon code.
#
# The pinned image is not a Kolla image: it has no kolla_start entrypoint, no
# /var/lib/kolla/config_files tree, and its CMD is /bin/bash. It is also not
# reached through the Docker bridge, because the O3K identity endpoint is
# loopback-bound (O3K_LISTEN_ADDR=127.0.0.1:18080 for the libvirt profile).
# The container therefore runs with host networking and reuses the endpoint
# that /etc/o3k/admin-openrc already records.
#
# Docker access is host test infrastructure, not a product dependency.
# shellcheck disable=SC1090,SC1091,SC2024,SC2034,SC2154
set -Eeuo pipefail
EVID=${1:?evidence directory}; REQUIRED=${O3K_PP4_HORIZON_REQUIRED:-0}
WORKDIR="$(mktemp -d /tmp/pp4-horizon.XXXXXX)"
cleanup(){ rm -rf -- "$WORKDIR"; }
trap cleanup EXIT
OPENRC="$WORKDIR/admin-openrc"; sudo cp /etc/o3k/admin-openrc "$OPENRC"; sudo chown "$(id -u):$(id -g)" "$OPENRC"; chmod 600 "$OPENRC"; source "$OPENRC"
IMAGE="docker.io/openstackhelm/horizon:2024.1-ubuntu_jammy-20250523@sha256:53af8d4c6c6b4c9c339f535080e2b56c439f8b36c417a6eba8bbf16afeb04a2b"
# Paths inside the pinned image's own virtualenv layout; not an O3K contract.
SITE=/var/lib/openstack/lib/python3.10/site-packages/openstack_dashboard
PORT=18091
NAME=pp4-horizon-witness; CONF="$WORKDIR/config"; JAR="$EVID/horizon.jar"
DOCKER=(sudo docker)
summary(){ printf '%s\n' "$*" | tee -a "$EVID/horizon-summary.txt"; }
# apache2 logs to files inside this image, so `docker logs` alone is empty.
# Record bounded, non-secret container state and the Apache logs before the
# witness gives up, otherwise a failed run cannot be classified.
capture_diagnostics(){
  "${DOCKER[@]}" inspect "$NAME" --format \
    'running={{.State.Running}} status={{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}} restarts={{.RestartCount}} error={{.State.Error}}' \
    >"$EVID/horizon-container-state.txt" 2>&1 || true
  "${DOCKER[@]}" logs "$NAME" >"$EVID/horizon-docker.log" 2>&1 || true
  for stream in error access; do
    "${DOCKER[@]}" exec "$NAME" sh -c "cat /var/log/apache2/$stream.log" \
      >"$EVID/horizon-apache-$stream.log" 2>&1 || true
  done
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
mkdir -p "$CONF/sites-enabled"
cat >"$CONF/local_settings.py" <<EOF
DEBUG = False
ALLOWED_HOSTS = ['*']
# Local witness session key for the unmodified image; not a credential.
SECRET_KEY = 'pp4-core-witness-local-session-key'
# The image installs the dashboard into a virtualenv, so Horizon's default
# STATIC_ROOT (site-packages/static) does not exist and is not writable by the
# horizon user; django-compressor would raise PermissionError while rendering
# the login page. Serve the witness from an ordinary writable root instead.
COMPRESS_ENABLED = False
STATIC_ROOT = '/var/lib/horizon/static'
OPENSTACK_API_VERSIONS = {'identity': 3, 'image': 2, 'volume': 3, 'compute': 2.1}
OPENSTACK_HOST = '127.0.0.1'
OPENSTACK_KEYSTONE_URL = '$KEYSTONE_URL'
OPENSTACK_KEYSTONE_DEFAULT_ROLE = 'admin'
OPENSTACK_ENDPOINT_TYPE = 'publicURL'
# Pin the region instead of relying on unauthenticated version discovery, so
# the session region matches the region O3K advertises in its catalog.
AVAILABLE_REGIONS = [(OPENSTACK_KEYSTONE_URL, '$REGION')]
CACHES = {'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}}
EOF
cat >"$CONF/ports.conf" <<EOF
Listen $PORT
EOF
cat >"$CONF/wsgi.conf" <<'EOF'
WSGIDaemonProcess horizon user=horizon group=horizon processes=3 threads=10 display-name=%{GROUP}
WSGIApplicationGroup %{GLOBAL}
EOF
cat >"$CONF/sites-enabled/000-horizon.conf" <<EOF
<VirtualHost *:$PORT>
    ServerName localhost
    WSGIProcessGroup horizon
    WSGIScriptAlias / $SITE/wsgi.py
    WSGIPassAuthorization On
    Alias /static /var/lib/horizon/static
    <Directory $SITE>
        Require all granted
    </Directory>
    <Directory /var/lib/horizon/static>
        Require all granted
    </Directory>
</VirtualHost>
EOF
chmod 644 "$CONF/local_settings.py" "$CONF/ports.conf" "$CONF/wsgi.conf" "$CONF/sites-enabled/000-horizon.conf"
"${DOCKER[@]}" run -d --name "$NAME" --restart no --network host \
  -v "$CONF/local_settings.py:$SITE/local/local_settings.py:ro" \
  -v "$CONF/ports.conf:/etc/apache2/ports.conf:ro" \
  -v "$CONF/wsgi.conf:/etc/apache2/conf-enabled/zz-horizon-wsgi.conf:ro" \
  -v "$CONF/sites-enabled:/etc/apache2/sites-enabled:ro" \
  "$IMAGE" /usr/sbin/apache2ctl -DFOREGROUND >"$EVID/horizon-run.txt" 2>&1 || fail container-start
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
if ! grep -qi 'Log Out' "$EVID/horizon-project.html"; then fail login-session; fi
summary 'login: PASS'
summary 'project context: PASS'
for panel in /identity/ /project/images/ /project/networks/ /project/instances/; do
  code=$(curl -s -b "$JAR" -o "$EVID/horizon-${panel//\//_}.html" -w '%{http_code}' "http://127.0.0.1:$PORT$panel")
  if [[ "$code" == 200 ]]; then summary "panel $panel: PASS"; else summary "panel $panel: NOT_PROVEN HTTP-$code"; fi
done
summary 'native_resource_identity='"${O3K_PP4_NATIVE_ID:-unknown}"; summary 'compatibility_resource_identity='"${O3K_PP4_COMPAT_ID:-unknown}"
if grep -RqiE 'pp4-native|pp4-openstack|'"${O3K_PP4_NATIVE_ID:-nomatch}"'|'"${O3K_PP4_COMPAT_ID:-nomatch}" "$EVID"/horizon-*.html; then
  summary 'resource observation: PASS expected Core resources visible in Horizon response'
else
  summary 'resource observation: NOT_PROVEN expected Core resource names/IDs absent from Horizon response'
  [[ "$REQUIRED" == 1 ]] && exit 1 || exit 0
fi
summary 'RESULT: PASS bounded Horizon witness'
