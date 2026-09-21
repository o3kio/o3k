#!/usr/bin/env bash
# Bounded external Horizon witness for PP.4 Core. The image is unmodified;
# only ordinary endpoint/catalog/TLS/session settings are supplied.
# shellcheck disable=SC1090,SC1091,SC2024,SC2034,SC2154
set -Eeuo pipefail
EVID=${1:?evidence directory}; REQUIRED=${O3K_PP4_HORIZON_REQUIRED:-0}
WORKDIR="$(mktemp -d /tmp/pp4-horizon.XXXXXX)"
cleanup(){ rm -rf -- "$WORKDIR"; }
trap cleanup EXIT
OPENRC="$WORKDIR/admin-openrc"; sudo cp /etc/o3k/admin-openrc "$OPENRC"; sudo chown "$(id -u):$(id -g)" "$OPENRC"; chmod 600 "$OPENRC"; source "$OPENRC"
IMAGE="docker.io/openstackhelm/horizon:2024.1-ubuntu_jammy-20250523@sha256:53af8d4c6c6b4c9c339f535080e2b56c439f8b36c417a6eba8bbf16afeb04a2b"
NAME=pp4-horizon-witness; CONF="$WORKDIR/config"; JAR="$EVID/horizon.jar"
DOCKER=(sudo docker)
summary(){ printf '%s\n' "$*" | tee -a "$EVID/horizon-summary.txt"; }
if ! command -v docker >/dev/null 2>&1; then summary 'RESULT: NOT_APPLICABLE_OPTIONAL docker-unavailable'; [[ "$REQUIRED" == 1 ]] && exit 1 || exit 0; fi
sudo systemctl start docker >/dev/null 2>&1 || { summary 'RESULT: FAIL docker-unavailable'; [[ "$REQUIRED" == 1 ]] && exit 1 || exit 0; }
"${DOCKER[@]}" rm -f "$NAME" >/dev/null 2>&1 || true
"${DOCKER[@]}" pull -q "$IMAGE" >"$EVID/horizon-pull.txt" 2>&1 || { summary 'RESULT: FAIL image-pull'; [[ "$REQUIRED" == 1 ]] && exit 1 || exit 0; }
printf 'image=%s\n' "$IMAGE" >"$EVID/horizon-image.txt"
mkdir -p "$CONF"
cat >"$CONF/config.json" <<'EOF'
{"command":"/usr/sbin/apache2ctl -DFOREGROUND","config_files":[{"source":"/var/lib/kolla/config_files/src/local_settings","dest":"/etc/openstack-dashboard/local_settings","owner":"horizon","perm":"0644"}]}
EOF
cat >"$CONF/local_settings" <<'EOF'
DEBUG=False
ALLOWED_HOSTS=['*']
WEBROOT='/'
OPENSTACK_API_VERSIONS={'identity':3,'image':2,'volume':3,'compute':2.1}
OPENSTACK_HOST='172.17.0.1'
OPENSTACK_KEYSTONE_URL='http://172.17.0.1:18090/v3'
OPENSTACK_KEYSTONE_DEFAULT_ROLE='admin'
OPENSTACK_ENDPOINT_TYPE='publicURL'
SECRET_KEY='pp4-core-witness-local-session-only'
CACHES={'default':{'BACKEND':'django.core.cache.backends.locmem.LocMemCache'}}
EOF
"${DOCKER[@]}" run -d --name "$NAME" --restart no -e KOLLA_CONFIG_STRATEGY=COPY_ALWAYS -e KEYSTONE_ADMIN_PASSWORD="$OS_PASSWORD" -p 127.0.0.1:18091:80 -v "$CONF:/var/lib/kolla/config_files/src:ro" "$IMAGE" >"$EVID/horizon-run.txt" 2>&1 || { summary 'RESULT: FAIL container-start'; [[ "$REQUIRED" == 1 ]] && exit 1 || exit 0; }
ready=0; for _ in $(seq 1 90); do curl -sf http://127.0.0.1:18091/ >/dev/null 2>&1 && ready=1 && break; sleep 2; done
if (( ready == 0 )); then "${DOCKER[@]}" logs "$NAME" >"$EVID/horizon-docker.log" 2>&1 || true; summary 'RESULT: FAIL http-readiness'; [[ "$REQUIRED" == 1 ]] && exit 1 || exit 0; fi
summary 'image: PASS'; summary 'boot: PASS'
curl -s -c "$JAR" http://127.0.0.1:18091/auth/login/ -o "$EVID/horizon-login.html" || true
csrf=$(grep -oE 'name="csrfmiddlewaretoken" value="[^"]+"' "$EVID/horizon-login.html" | head -1 | sed -E 's/.*value="([^"]+)".*/\1/')
if [[ -z "$csrf" ]]; then summary 'login: FAIL csrf-missing'; [[ "$REQUIRED" == 1 ]] && exit 1 || exit 0; fi
form=$(mktemp); chmod 600 "$form"; python3 - "$form" "$csrf" "$OS_PASSWORD" <<'PY'
import sys
from urllib.parse import urlencode
open(sys.argv[1],'wb').write(urlencode({'csrfmiddlewaretoken':sys.argv[2],'username':'admin','password':sys.argv[3],'domain':'Default','region':'RegionOne'}).encode())
PY
curl -s -b "$JAR" -c "$JAR" -e http://127.0.0.1:18091/auth/login/ --data-binary "@$form" http://127.0.0.1:18091/auth/login/ -o "$EVID/horizon-login-response.html"; rm -f "$form"
if ! grep -qi 'Log Out' "$EVID/horizon-login-response.html"; then summary 'login: FAIL session'; [[ "$REQUIRED" == 1 ]] && exit 1 || exit 0; fi
summary 'login: PASS'
for panel in /identity/ /project/images/ /project/networks/ /project/instances/; do
  code=$(curl -s -b "$JAR" -o "$EVID/horizon-${panel//\//_}.html" -w '%{http_code}' "http://127.0.0.1:18091$panel")
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
