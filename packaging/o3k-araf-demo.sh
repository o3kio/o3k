#!/usr/bin/env bash
# o3k-araf-demo.sh — PP.3 (#972) demo-profile Araf deployment orchestration.
#
# Deploys the digest-pinned Araf compatibility tuple from
# contracts/araf-compatibility-v1.yaml (pp3_tuple) onto a single-node
# o3k-demo-v1 host. Orchestration only: this script never fabricates O3K
# topology, Placement, BuildingBlock, CloudProfile, agent, or readiness
# state, and it never authorizes anything. O3K readiness stays independent
# of Araf availability.
#
# Subcommands:
#   install     preflight -> docker -> demo CA -> compose stack -> o3kd OIDC
#               federation enable -> health gates (idempotent / convergent)
#   verify      real OIDC login (tenant + operator) through the production
#               Araf profile against the real O3K native API
#   status      per-layer health: o3kd (independent), idp, BFFs, consoles
#   start|stop  compose start/stop (O3K runtime untouched)
#   uninstall   remove runtime wiring (containers, network, o3kd federation
#               block); preserve state dir for convergent reinstall
#   purge       uninstall + state dir, session volumes, /etc/hosts entries
#
# Lifecycle safety: reset != uninstall != purge. Only resources carrying the
# o3k-araf-demo ownership markers are removed; foreign containers, images,
# volumes, networks, files, and processes are never touched.
#
# Secrets: generated once into $STATE_DIR (0700, files 0600), never printed,
# never passed on argv of logged commands beyond the local host.
set -Eeuo pipefail
umask 077

# ---------------------------------------------------------------------------
# Pinned compatibility tuple (must match contracts/araf-compatibility-v1.yaml
# pp3_tuple; tests/pp3-araf-demo-contract.sh enforces drift).
# ---------------------------------------------------------------------------
ARAF_VERSION="v1.0.0-rc.12"
ARAF_SOURCE_SHA="de64cc9193085116fa30ad51c04ccab24a013dd0"
O3K_TUPLE_VERSION="v0.4.0-rc.5"
O3K_TUPLE_SOURCE_SHA="145b0149fd82f44a4b76f30f7b4fd272ca6ef60d"

ARAF_BFF_IMAGE="ghcr.io/o3kio/araf-bff"
ARAF_BFF_DIGEST="sha256:bc717ecdbbbf3ea673efe168c90419936677d644aa0ae25af4eb84906cd744ba"
ARAF_BFF_CONFIG_DIGEST="sha256:a22458df7ced503bbda9e69e45ec559b5881a63d8f8849ef24721bb8918c5edc"
ARAF_BFF_TAR_SHA256="42d46d01f823cf02c1edb03ce352d6b9b1dc7a349235c4b6f28dee3ad3f21d1e"
ARAF_TENANT_CONSOLE_IMAGE="ghcr.io/o3kio/araf-tenant-console"
ARAF_TENANT_CONSOLE_DIGEST="sha256:25f5fe41927f68db3dafd49597c6b8cb4520bca2dd45ec131d1372474ef3e5e5"
ARAF_TENANT_CONSOLE_CONFIG_DIGEST="sha256:34901700540686c1a5ff13c7b02ba96180170d4c83f9bf170def7917df2eb068"
ARAF_TENANT_CONSOLE_TAR_SHA256="f9fa6de50d01d96dce0db5ac9bff52d83b4212943f14a5354e7890f09ce9b066"
ARAF_OPERATOR_CONSOLE_IMAGE="ghcr.io/o3kio/araf-operator-console"
ARAF_OPERATOR_CONSOLE_DIGEST="sha256:cbbad76033eced4d4290c9848e0665a23c30bd4a7c647077ba0cf03150666b18"
ARAF_OPERATOR_CONSOLE_CONFIG_DIGEST="sha256:c9b4c88b56293e12bb569ced7020da3eda349d094351a3944c881888147cac9b"
ARAF_OPERATOR_CONSOLE_TAR_SHA256="cc7bd68c58ea01ce7b7eb70213b58f495876a06945f38521378e406fd1377c1d"
# Local tag for the digest-verified images; compose never pulls (pull_policy
# never) so this tag names only content whose config digest was verified
# against the pinned tuple after docker load.
LOCAL_IMAGE_TAG="o3k-demo-${ARAF_VERSION}"
ARAF_RELEASE_BASE="https://github.com/o3kio/araf/releases/download/${ARAF_VERSION}"
KEYCLOAK_IMAGE="quay.io/keycloak/keycloak"
KEYCLOAK_DIGEST="sha256:82c5b7a110456dbd42b86ea572e728878549954cc8bd03cd65410d75328095d2"
NGINX_IMAGE="docker.io/nginxinc/nginx-unprivileged"
NGINX_DIGEST="sha256:dcc9bf9c084901dddbbce305130a7295c5637b6a8fce3e29cf678d86336982e4"

COMPOSE_MIN="2.24"
DOCKER_MIN="24.0"

# ---------------------------------------------------------------------------
DEMO_HOSTS="tenant.o3k.demo operator.o3k.demo idp.o3k.demo api.o3k.demo"
ISSUER_REALM="o3k-demo"
ISSUER_URL="https://idp.o3k.demo/realms/${ISSUER_REALM}"
O3K_API_URL="https://api.o3k.demo"
TRUST_ID="araf-demo-idp"
O3K_AUDIENCE="o3k"
ADMIN_PROJECT_ID="eba29e2d-53de-461d-ae91-ede7402713cb"
ALICE_ID="00000000-0000-4000-8000-0000000000a1"

STATE_DIR="${O3K_ARAF_DEMO_STATE_DIR:-/var/lib/o3k/araf-demo}"
TLS_DIR="${STATE_DIR}/tls"
COMPOSE_PROJECT="o3k-araf-demo"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/araf-demo/compose.yaml"
O3KD_ENV="/etc/o3k/o3kd.env"
HOSTS_MARKER="# o3k-araf-demo"
ENV_BEGIN="# BEGIN o3k-araf-demo (PP.3)"
ENV_END="# END o3k-araf-demo"
O3KD_READY_URL="http://127.0.0.1:18080/readyz"

log() { printf '[o3k-araf-demo] %s\n' "$*"; }
die() { printf '[o3k-araf-demo] ERROR: %s\n' "$*" >&2; exit 1; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"; }

compose() {
  O3K_ARAF_DEMO_STATE_DIR="${STATE_DIR}" \
    docker compose -p "${COMPOSE_PROJECT}" --env-file "${STATE_DIR}/araf-demo.env" \
    -f "${COMPOSE_FILE}" "$@"
}

# ---------------------------------------------------------------------------
# Preflight — every unsupported-environment check runs before any mutation.
# ---------------------------------------------------------------------------
preflight() {
  [ "$(id -u)" -eq 0 ] || die "must run as root"
  need_cmd curl; need_cmd openssl; need_cmd python3; need_cmd ss

  # Frozen PP.3 target: Ubuntu 24.04 x86_64. Fail closed elsewhere.
  [ -r /etc/os-release ] || die "cannot identify OS"
  # shellcheck disable=SC1091
  . /etc/os-release
  if [ "${ID}" != "ubuntu" ] || [ "${VERSION_ID}" != "24.04" ]; then
    die "unsupported target ${ID:-?} ${VERSION_ID:-?}; PP.3 demo tuple is frozen for ubuntu-24.04 x86_64 only"
  fi
  [ "$(uname -m)" = "x86_64" ] || die "unsupported architecture $(uname -m)"

  # The O3K demo release must already be installed canonically (PP.2 path).
  [ -f "${O3KD_ENV}" ] || die "O3K demo install not found (${O3KD_ENV}); run the one-line installer first"
  command -v o3k >/dev/null 2>&1 || die "o3k CLI not found; run the one-line installer first"

  # Port 443 on loopback must be free (or already ours).
  if ss -ltn | awk '{print $4}' | grep -qE '(^|:|\])443$'; then
    compose ps tls-proxy >/dev/null 2>&1 && return 0
    die "127.0.0.1:443 already in use by a foreign process"
  fi
}

ensure_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    log "installing docker.io via apt (contract-accepted prerequisite)"
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends docker.io >/dev/null
  fi
  if ! docker compose version >/dev/null 2>&1; then
    log "installing docker-compose-v2 via apt (contract-accepted prerequisite)"
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends docker-compose-v2 >/dev/null
  fi
  systemctl enable --now docker >/dev/null 2>&1 || die "cannot start docker service"
  local dv cv
  dv="$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo 0)"
  cv="$(docker compose version --short 2>/dev/null || echo 0)"
  python3 - "${dv}" "${cv}" "${DOCKER_MIN}" "${COMPOSE_MIN}" <<'PY' || die "docker/compose below minimum"
import sys
def parse(v):
    return tuple(int(p) for p in v.split(".")[:2] if p.isdigit()) or (0,)
dv, cv, dmin, cmin = sys.argv[1:5]
sys.exit(0 if parse(dv) >= parse(dmin) and parse(cv) >= parse(cmin) else 1)
PY
}

# ---------------------------------------------------------------------------
# State, CA, secrets
# ---------------------------------------------------------------------------
gen_secret() { openssl rand -base64 32 | tr -d '=+/' | head -c 40; }

ensure_secrets() {
  local f="${STATE_DIR}/secrets.env"
  if [ -f "${f}" ]; then
    # shellcheck disable=SC1090
    . "${f}"
    return 0
  fi
  log "generating demo secrets (stored ${f}, mode 0600, never printed)"
  ARAF_SESSION_STORE_KEY="$(openssl rand -base64 32)"
  TENANT_CLIENT_SECRET="$(gen_secret)"
  OPERATOR_CLIENT_SECRET="$(gen_secret)"
  KEYCLOAK_ADMIN_PASSWORD="$(gen_secret)"
  ALICE_PASSWORD="$(gen_secret)"
  FEDERATED_BINDING_ID="$(python3 -c 'import uuid;print(uuid.uuid4())')"
  OPERATOR_ASSIGNMENT_ID="$(python3 -c 'import uuid;print(uuid.uuid4())')"
  {
    printf 'ARAF_SESSION_STORE_KEY=%q\n' "${ARAF_SESSION_STORE_KEY}"
    printf 'TENANT_CLIENT_SECRET=%q\n' "${TENANT_CLIENT_SECRET}"
    printf 'OPERATOR_CLIENT_SECRET=%q\n' "${OPERATOR_CLIENT_SECRET}"
    printf 'KEYCLOAK_ADMIN_PASSWORD=%q\n' "${KEYCLOAK_ADMIN_PASSWORD}"
    printf 'ALICE_PASSWORD=%q\n' "${ALICE_PASSWORD}"
    printf 'FEDERATED_BINDING_ID=%q\n' "${FEDERATED_BINDING_ID}"
    printf 'OPERATOR_ASSIGNMENT_ID=%q\n' "${OPERATOR_ASSIGNMENT_ID}"
  } > "${f}"
  chmod 600 "${f}"
}

ensure_ca() {
  if [ ! -f "${TLS_DIR}/ca.crt" ] || [ ! -f "${TLS_DIR}/server.crt" ]; then
  log "minting local demo CA and server certificate (loopback only, not publicly trusted)"
  mkdir -p "${TLS_DIR}"
  local cnf="${TLS_DIR}/server.cnf"
  cat > "${cnf}" <<'EOF'
[req]
distinguished_name = dn
req_extensions = ext
[dn]
[ext]
subjectAltName = DNS:tenant.o3k.demo,DNS:operator.o3k.demo,DNS:idp.o3k.demo,DNS:api.o3k.demo,DNS:localhost,IP:127.0.0.1
EOF
  openssl ecparam -genkey -name prime256v1 -out "${TLS_DIR}/ca.key" 2>/dev/null
  openssl req -x509 -new -sha256 -key "${TLS_DIR}/ca.key" -days 3650 \
    -subj "/CN=O3K Araf Demo Local CA" -out "${TLS_DIR}/ca.crt" 2>/dev/null
  openssl ecparam -genkey -name prime256v1 -out "${TLS_DIR}/server.key" 2>/dev/null
  openssl req -new -sha256 -key "${TLS_DIR}/server.key" -subj "/CN=o3k-araf-demo" \
    -config "${cnf}" -out "${TLS_DIR}/server.csr" 2>/dev/null
  openssl x509 -req -sha256 -in "${TLS_DIR}/server.csr" -CA "${TLS_DIR}/ca.crt" \
    -CAkey "${TLS_DIR}/ca.key" -CAcreateserial -days 825 -extfile "${cnf}" \
    -extensions ext -out "${TLS_DIR}/server.crt" 2>/dev/null
  rm -f "${cnf}" "${TLS_DIR}/server.csr"
  chmod 600 "${TLS_DIR}"/* 2>/dev/null || true
  chmod 644 "${TLS_DIR}/ca.crt"
  # The tls-proxy container runs as uid 101 (nginx-unprivileged, non-root);
  # the state dir itself is 0700 root, so these remain host-local.
  chmod 644 "${TLS_DIR}/server.crt" "${TLS_DIR}/server.key"
  fi
  # Trust bundle (system roots + demo CA) for container mounts; rebuilt if stale.
  cat /etc/ssl/certs/ca-certificates.crt "${TLS_DIR}/ca.crt" > "${TLS_DIR}/combined-ca.crt"
  chmod 644 "${TLS_DIR}/combined-ca.crt"
}

render_env_file() {
  local f="${STATE_DIR}/araf-demo.env"
  cat > "${f}" <<EOF
ARAF_BFF_IMAGE=${ARAF_BFF_IMAGE}
ARAF_TENANT_CONSOLE_IMAGE=${ARAF_TENANT_CONSOLE_IMAGE}
ARAF_OPERATOR_CONSOLE_IMAGE=${ARAF_OPERATOR_CONSOLE_IMAGE}
LOCAL_IMAGE_TAG=${LOCAL_IMAGE_TAG}
KEYCLOAK_IMAGE=${KEYCLOAK_IMAGE}
KEYCLOAK_DIGEST=${KEYCLOAK_DIGEST}
NGINX_IMAGE=${NGINX_IMAGE}
NGINX_DIGEST=${NGINX_DIGEST}
ARAF_UPSTREAM_ADAPTER=o3k
O3K_URL=${O3K_API_URL}
ARAF_TENANT_PUBLIC_URL=https://tenant.o3k.demo
ARAF_OPERATOR_PUBLIC_URL=https://operator.o3k.demo
ARAF_TENANT_OIDC_CLIENT_ID=tenant-console
ARAF_TENANT_OIDC_CLIENT_SECRET=${TENANT_CLIENT_SECRET}
ARAF_TENANT_OIDC_ISSUER_URL=${ISSUER_URL}
ARAF_TENANT_OIDC_REDIRECT_URI=https://tenant.o3k.demo/api/v1/auth/callback
ARAF_OPERATOR_OIDC_CLIENT_ID=operator-console
ARAF_OPERATOR_OIDC_CLIENT_SECRET=${OPERATOR_CLIENT_SECRET}
ARAF_OPERATOR_OIDC_ISSUER_URL=${ISSUER_URL}
ARAF_OPERATOR_OIDC_REDIRECT_URI=https://operator.o3k.demo/api/v1/auth/callback
ARAF_SESSION_STORE_KEY=${ARAF_SESSION_STORE_KEY}
KEYCLOAK_ADMIN_PASSWORD=${KEYCLOAK_ADMIN_PASSWORD}
TENANT_CLIENT_SECRET=${TENANT_CLIENT_SECRET}
OPERATOR_CLIENT_SECRET=${OPERATOR_CLIENT_SECRET}
EOF
  chmod 600 "${f}"
}

render_realm() {
  # Render both realm files with Keycloak-format PBKDF2-SHA256 credential
  # JSON (never plaintext). Keycloak's bootstrap-admin env path does not
  # create the admin user when --import-realm is used, so the master realm
  # admin is seeded by the master-realm.json import instead.
  python3 - "${SCRIPT_DIR}/araf-demo/realm.json" \
    "${SCRIPT_DIR}/araf-demo/master-realm.json" \
    "${STATE_DIR}/realm.json" "${STATE_DIR}/master-realm.json" \
    "${ALICE_PASSWORD}" "${KEYCLOAK_ADMIN_PASSWORD}" <<'PY'
import base64, hashlib, json, os, sys

realm_src, master_src, realm_dst, master_dst, alice_pw, admin_pw = sys.argv[1:7]

def kc_password_credential(password, iterations=27500):
    salt = os.urandom(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return {
        "type": "password",
        "secretData": json.dumps({
            "value": base64.b64encode(derived).decode(),
            "salt": base64.b64encode(salt).decode(),
            "additionalParameters": {},
        }),
        "credentialData": json.dumps({
            "hashIterations": iterations,
            "algorithm": "pbkdf2-sha256",
            "additionalParameters": {},
        }),
    }

alice_cred = json.dumps(kc_password_credential(alice_pw))
admin_cred = json.dumps(kc_password_credential(admin_pw))

text = open(realm_src, encoding="utf-8").read()
text = text.replace("@ALICE_CREDENTIAL_JSON@", alice_cred)
open(realm_dst, "w", encoding="utf-8").write(text)

text = open(master_src, encoding="utf-8").read()
text = text.replace("@ADMIN_CREDENTIAL_JSON@", admin_cred)
open(master_dst, "w", encoding="utf-8").write(text)
PY
  # The rendered master realm contains a password hash: keep it 0600.
  chmod 644 "${STATE_DIR}/realm.json"
  chmod 600 "${STATE_DIR}/master-realm.json"
}

# ---------------------------------------------------------------------------
# Araf images: consumed as digest-pinned OCI tarballs from the published Araf
# GitHub Release (ghcr packages require pull auth; see tuple
# artifact_distribution). Tarball sha256 pins integrity; the image config
# digest pins content identity after docker load. Never pulled by tag.
# ---------------------------------------------------------------------------
image_identity_matches() { # image_ref expected_config_digest expected_index_digest
  local actual
  actual="$(docker image inspect -f '{{.Id}}' "$1" 2>/dev/null || true)"
  # Classic store: image ID == config digest. Containerd store: image ID ==
  # platform/index digest. Both are tuple-pinned values.
  [ "${actual}" = "$2" ] || [ "${actual}" = "$3" ]
}

ensure_one_araf_image() { # component image tarball_sha256 config_digest index_digest
  local component="$1" image="$2" tar_sha="$3" config_digest="$4" index_digest="$5"
  local tag="${image}:${LOCAL_IMAGE_TAG}"
  if docker image inspect "${tag}" >/dev/null 2>&1 \
    && image_identity_matches "${tag}" "${config_digest}" "${index_digest}"; then
    log "${component}: digest-verified image already present"
    return 0
  fi
  local tar="${STATE_DIR}/araf-${component}-${ARAF_VERSION}.oci.tar"
  if [ ! -f "${tar}" ] || ! echo "${tar_sha}  ${tar}" | sha256sum -c - >/dev/null 2>&1; then
    log "${component}: fetching pinned OCI tarball from Araf release ${ARAF_VERSION}"
    curl -fsSL -o "${tar}" "${ARAF_RELEASE_BASE}/araf-${component}-${ARAF_VERSION}.oci.tar" \
      || die "${component}: tarball download failed"
  fi
  echo "${tar_sha}  ${tar}" | sha256sum -c - >/dev/null \
    || die "${component}: tarball sha256 mismatch (release asset replaced?)"
  local loaded
  loaded="$(docker load -i "${tar}" 2>&1 | sed -n 's/^Loaded image\( ID\)\?: //p' | head -1)"
  [ -n "${loaded}" ] || die "${component}: docker load failed"
  image_identity_matches "${loaded}" "${config_digest}" "${index_digest}" \
    || die "${component}: digest mismatch after load (tarball does not match pinned tuple)"
  docker tag "${loaded}" "${tag}" >/dev/null
  log "${component}: loaded and digest verified"
}

ensure_araf_images() {
  ensure_one_araf_image "bff" "${ARAF_BFF_IMAGE}" "${ARAF_BFF_TAR_SHA256}" "${ARAF_BFF_CONFIG_DIGEST}" "${ARAF_BFF_DIGEST}"
  ensure_one_araf_image "tenant-console" "${ARAF_TENANT_CONSOLE_IMAGE}" "${ARAF_TENANT_CONSOLE_TAR_SHA256}" "${ARAF_TENANT_CONSOLE_CONFIG_DIGEST}" "${ARAF_TENANT_CONSOLE_DIGEST}"
  ensure_one_araf_image "operator-console" "${ARAF_OPERATOR_CONSOLE_IMAGE}" "${ARAF_OPERATOR_CONSOLE_TAR_SHA256}" "${ARAF_OPERATOR_CONSOLE_CONFIG_DIGEST}" "${ARAF_OPERATOR_CONSOLE_DIGEST}"
  log "pulling digest-pinned infrastructure images"
  docker pull -q "${KEYCLOAK_IMAGE}@${KEYCLOAK_DIGEST}" >/dev/null
  docker pull -q "${NGINX_IMAGE}@${NGINX_DIGEST}" >/dev/null
  docker image inspect "${KEYCLOAK_IMAGE}@${KEYCLOAK_DIGEST}" "${NGINX_IMAGE}@${NGINX_DIGEST}" >/dev/null \
    || die "infrastructure image digest mismatch after pull"
}


# ---------------------------------------------------------------------------
# /etc/hosts and o3kd federation wiring (marker-managed, convergent)
# ---------------------------------------------------------------------------
ensure_hosts() {
  local missing=0 h
  for h in ${DEMO_HOSTS}; do
    grep -qE "^127\.0\.0\.1\s+.*\b${h}\b" /etc/hosts || missing=1
  done
  [ "${missing}" -eq 0 ] && return 0
  log "adding loopback demo hostnames to /etc/hosts (${HOSTS_MARKER})"
  for h in ${DEMO_HOSTS}; do
    printf '127.0.0.1 %s %s\n' "${h}" "${HOSTS_MARKER}" >> /etc/hosts
  done
}

remove_hosts() {
  [ -f /etc/hosts ] || return 0
  local tmp
  tmp="$(mktemp)"
  grep -v " ${HOSTS_MARKER}$" /etc/hosts > "${tmp}" || true
  cat "${tmp}" > /etc/hosts
  rm -f "${tmp}"
}

o3kd_block_content() {
  cat <<EOF
${ENV_BEGIN}
O3K_OIDC_TRUST_ID=${TRUST_ID}
O3K_OIDC_ISSUER=${ISSUER_URL}
O3K_OIDC_AUDIENCE=${O3K_AUDIENCE}
O3K_OIDC_DISCOVERY_URL=${ISSUER_URL}/.well-known/openid-configuration
O3K_TESTLAB_FEDERATED_SUBJECT=${ALICE_ID}
O3K_TESTLAB_FEDERATED_PRINCIPAL_ID=bootstrap-user
O3K_TESTLAB_FEDERATED_BINDING_ID=${FEDERATED_BINDING_ID}
O3K_TESTLAB_OPERATOR_ASSIGNMENT_ID=${OPERATOR_ASSIGNMENT_ID}
SSL_CERT_FILE=${TLS_DIR}/combined-ca.crt
${ENV_END}
EOF
}

ensure_o3kd_federation() {
  local desired current
  desired="$(o3kd_block_content)"
  current="$(sed -n "/^${ENV_BEGIN}/,/^${ENV_END}/p" "${O3KD_ENV}" 2>/dev/null || true)"
  if [ "${current}" = "${desired}" ]; then
    log "o3kd OIDC federation block already present; no restart needed"
    return 0
  fi
  log "enabling o3kd OIDC federation (managed env block + service restart)"
  local tmp
  tmp="$(mktemp)"
  sed "/^${ENV_BEGIN}/,/^${ENV_END}/d" "${O3KD_ENV}" | sed -e :a -e '/^\n*$/{$d;N;ba' -e '}' > "${tmp}"
  printf '\n%s\n' "${desired}" >> "${tmp}"
  cat "${tmp}" > "${O3KD_ENV}"
  rm -f "${tmp}"
  systemctl restart o3kd
  wait_url "${O3KD_READY_URL}" "o3kd readiness after federation enable"
}

remove_o3kd_federation() {
  if ! grep -q "^${ENV_BEGIN}" "${O3KD_ENV}" 2>/dev/null; then
    return 0
  fi
  log "removing o3kd OIDC federation block (service restart)"
  local tmp
  tmp="$(mktemp)"
  sed "/^${ENV_BEGIN}/,/^${ENV_END}/d" "${O3KD_ENV}" > "${tmp}"
  cat "${tmp}" > "${O3KD_ENV}"
  rm -f "${tmp}"
  systemctl restart o3kd
  wait_url "${O3KD_READY_URL}" "o3kd readiness after federation removal"
}

wait_url() {
  local url="$1" what="$2" i
  for i in $(seq 1 90); do
    if curl -sf --cacert "${TLS_DIR}/ca.crt" "${url}" >/dev/null 2>&1 || curl -sf "${url}" >/dev/null 2>&1; then
      log "${what}: OK"
      return 0
    fi
    sleep 2
  done
  die "${what}: timed out (${url})"
}

# ---------------------------------------------------------------------------
# Keycloak admin API helpers (master realm admin-cli; never logged)
# ---------------------------------------------------------------------------
kc_token() {
  curl -sf --cacert "${TLS_DIR}/ca.crt" -X POST \
    "https://idp.o3k.demo/realms/master/protocol/openid-connect/token" \
    -d grant_type=password -d client_id=admin-cli \
    -d username=admin -d password="${KEYCLOAK_ADMIN_PASSWORD}" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])'
}

kc_api() { # kc_api METHOD PATH [JSON_BODY]
  local method="$1" path="$2" body="${3:-}" tok
  tok="$(kc_token)"
  if [ -n "${body}" ]; then
    curl -sf --cacert "${TLS_DIR}/ca.crt" -X "${method}" \
      -H "Authorization: Bearer ${tok}" -H 'Content-Type: application/json' \
      -d "${body}" "https://idp.o3k.demo${path}" >/dev/null
  else
    curl -sf --cacert "${TLS_DIR}/ca.crt" -X "${method}" \
      -H "Authorization: Bearer ${tok}" "https://idp.o3k.demo${path}" >/dev/null
  fi
}

ensure_alice() {
  local existing
  existing="$(curl -sf --cacert "${TLS_DIR}/ca.crt" \
    -H "Authorization: Bearer $(kc_token)" \
    "https://idp.o3k.demo/admin/realms/${ISSUER_REALM}/users?username=alice" \
    | python3 -c 'import json,sys; u=json.load(sys.stdin); print(u[0]["id"] if u else "")')"
  if [ -z "${existing}" ]; then
    log "creating demo user alice (fixed subject ${ALICE_ID})"
    kc_api POST "/admin/realms/${ISSUER_REALM}/users" \
      "{\"id\":\"${ALICE_ID}\",\"username\":\"alice\",\"enabled\":true}"
  elif [ "${existing}" != "${ALICE_ID}" ]; then
    die "keycloak user alice has unexpected subject ${existing}"
  fi
  kc_api PUT "/admin/realms/${ISSUER_REALM}/users/${ALICE_ID}/reset-password" \
    '{"type":"password","value":"'"${ALICE_PASSWORD}"'","temporary":false}'
}

# ---------------------------------------------------------------------------
# install / status / start / stop / uninstall / purge
# ---------------------------------------------------------------------------
cmd_install() {
  preflight
  ensure_docker
  mkdir -p "${STATE_DIR}" "${TLS_DIR}"
  chmod 700 "${STATE_DIR}"
  ensure_secrets
  ensure_ca
  cp "${SCRIPT_DIR}/araf-demo/nginx.conf" "${STATE_DIR}/nginx.conf"
  chmod 644 "${STATE_DIR}/nginx.conf"
  : > "${STATE_DIR}/nginx-default-blank.conf"
  chmod 644 "${STATE_DIR}/nginx-default-blank.conf"
  render_env_file
  render_realm
  ensure_hosts
  ensure_araf_images
  log "starting Araf demo stack (${COMPOSE_PROJECT})"
  compose up -d
  wait_url "https://idp.o3k.demo/demo-healthz" "idp health"
  ensure_alice
  # Federation enabled only after the IdP is healthy: o3kd fetches OIDC
  # discovery/JWKS from the demo IdP at startup.
  ensure_o3kd_federation
  wait_url "http://127.0.0.1:8080/readyz" "tenant BFF readiness"
  wait_url "http://127.0.0.1:8081/readyz" "operator BFF readiness"
  wait_url "https://tenant.o3k.demo/" "tenant console via TLS proxy"
  wait_url "https://operator.o3k.demo/" "operator console via TLS proxy"
  wait_url "${O3KD_READY_URL}" "o3kd readiness (independent of Araf)"
  cat <<EOF
[o3k-araf-demo] install OK
  tuple: O3K ${O3K_TUPLE_VERSION} + Araf ${ARAF_VERSION} (${ARAF_SOURCE_SHA})
  tenant console:  https://tenant.o3k.demo/   (trust ${TLS_DIR}/ca.crt)
  operator console: https://operator.o3k.demo/
  state dir: ${STATE_DIR}
  next: $0 verify | $0 status
EOF
}

layer() { # layer NAME OK|DOWN
  printf '  %-28s %s\n' "$1" "$2"
}

probe() { curl -sf --cacert "${TLS_DIR}/ca.crt" "$1" >/dev/null 2>&1; }

cmd_status() {
  [ -f "${STATE_DIR}/secrets.env" ] || die "not installed"
  ensure_secrets
  log "layered status (O3K readiness is independent of Araf)"
  layer "o3kd (canonical)" "$(curl -sf "${O3KD_READY_URL}" >/dev/null 2>&1 && echo ready || echo NOT-READY)"
  layer "demo IdP" "$(probe https://idp.o3k.demo/demo-healthz && echo ready || echo down)"
  layer "tenant BFF" "$(curl -sf http://127.0.0.1:8080/readyz >/dev/null 2>&1 && echo ready || echo down)"
  layer "operator BFF" "$(curl -sf http://127.0.0.1:8081/readyz >/dev/null 2>&1 && echo ready || echo down)"
  layer "tenant console" "$(probe https://tenant.o3k.demo/ && echo ready || echo down)"
  layer "operator console" "$(probe https://operator.o3k.demo/ && echo ready || echo down)"
  layer "BFF->O3K dependency" "$(curl -sf "${O3KD_READY_URL}" >/dev/null 2>&1 && probe https://idp.o3k.demo/demo-healthz && echo reachable || echo degraded)"
}

cmd_start() {
  [ -f "${STATE_DIR}/secrets.env" ] || die "not installed"
  compose start
}

cmd_stop() {
  [ -f "${STATE_DIR}/secrets.env" ] || die "not installed"
  compose stop
}

cmd_uninstall() {
  local assume_yes="${1:-}"
  [ -f "${STATE_DIR}/secrets.env" ] || { log "not installed; nothing to do"; return 0; }
  if [ "${assume_yes}" != "--yes" ]; then
    printf 'Uninstall removes the Araf demo runtime (containers, network, o3kd federation block)\n' >&2
    printf 'but preserves %s for convergent reinstall. Continue? [type yes] ' "${STATE_DIR}" >&2
    read -r r; [ "${r}" = "yes" ] || die "aborted"
  fi
  compose down --remove-orphans 2>/dev/null || true
  remove_o3kd_federation
  log "uninstall OK (state preserved in ${STATE_DIR})"
}

cmd_purge() {
  local assume_yes="${1:-}"
  if [ "${assume_yes}" != "--yes" ]; then
    printf 'PURGE removes ALL Araf demo state including secrets, sessions, demo CA,\n' >&2
    printf '/etc/hosts entries and the o3kd federation block. This cannot be undone. [type purge] ' >&2
    read -r r; [ "${r}" = "purge" ] || die "aborted"
  fi
  if [ -f "${STATE_DIR}/secrets.env" ]; then
    compose down -v --remove-orphans 2>/dev/null || true
    remove_o3kd_federation
  fi
  case "${STATE_DIR}" in
    /var/lib/o3k/araf-demo|/var/lib/o3k/araf-demo/*) rm -rf "${STATE_DIR}" ;;
    *) die "refusing to purge unexpected state dir ${STATE_DIR}" ;;
  esac
  remove_hosts
  if docker volume ls --format '{{.Name}}' | grep -q "^${COMPOSE_PROJECT}_"; then
    die "ownership fencing failure: ${COMPOSE_PROJECT}_* volumes remain"
  fi
  log "purge OK; foreign containers/images/volumes untouched"
}

# ---------------------------------------------------------------------------
# verify — real OIDC login (PKCE) through the production Araf profile against
# the real O3K native API. No fixture, no shortcut, no token in the jar.
# ---------------------------------------------------------------------------
browser_login() { # browser_login SURFACE(tenant|operator) -> sets COOKIE/CSRF/WORK
  local surface="$1" port host cookie_name
  case "${surface}" in
    tenant) host="tenant.o3k.demo" ;;
    operator) host="operator.o3k.demo" ;;
    *) die "bad surface" ;;
  esac
  WORK="$(mktemp -d)"
  local jar="${WORK}/jar" headers="${WORK}/headers" html="${WORK}/auth.html" kc_headers="${WORK}/kc.headers"
  curl -sf --cacert "${TLS_DIR}/ca.crt" -D "${headers}" -o /dev/null \
    "https://${host}/api/v1/auth/login"
  local auth_url
  auth_url="$(sed -n 's/^Location: //Ip' "${headers}" | tr -d '\r' | head -1)"
  [ -n "${auth_url}" ] || die "${surface}: no OIDC redirect from BFF"
  curl -sf --cacert "${TLS_DIR}/ca.crt" -c "${jar}" -b "${jar}" "${auth_url}" -o "${html}"
  local form_action
  form_action="$(python3 - "${html}" "${auth_url}" <<'PY'
import re, sys
from urllib.parse import urljoin
html = open(sys.argv[1], encoding="utf-8").read()
m = re.search(r'<form[^>]+action=["\x27]([^"\x27]+)', html, re.IGNORECASE)
if not m:
    raise SystemExit("keycloak login form action missing")
print(urljoin(sys.argv[2], m.group(1).replace("&amp;", "&")))
PY
)"
  curl -sf --cacert "${TLS_DIR}/ca.crt" -D "${kc_headers}" -o /dev/null \
    -c "${jar}" -b "${jar}" -X POST "${form_action}" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode username=alice \
    --data-urlencode "password=${ALICE_PASSWORD}" \
    --data-urlencode credentialId=
  local callback
  callback="$(sed -n 's/^Location: //Ip' "${kc_headers}" | tr -d '\r' | head -1)"
  [ -n "${callback}" ] || die "${surface}: keycloak did not redirect to Araf callback"
  local cb_headers="${WORK}/cb.headers"
  local status
  status="$(curl -s --cacert "${TLS_DIR}/ca.crt" -o /dev/null -w '%{http_code}' -D "${cb_headers}" \
    -c "${jar}" -b "${jar}" "${callback}")"
  case "${status}" in 302|303) ;; *) die "${surface}: Araf callback rejected (status ${status})" ;; esac
  cookie_name="araf_${surface}_session"
  COOKIE="${cookie_name}=$(sed -n "s/^Set-Cookie: ${cookie_name}=\([^;]*\).*/\1/Ip" "${cb_headers}" | head -1)"
  CSRF="araf_csrf=$(sed -n 's/^Set-Cookie: araf_csrf=\([^;]*\).*/\1/Ip' "${cb_headers}" | head -1)"
  [ "${COOKIE}" != "${cookie_name}=" ] || die "${surface}: session cookie missing"
  [ "${CSRF}" != "araf_csrf=" ] || die "${surface}: csrf cookie missing"
  curl -sf --cacert "${TLS_DIR}/ca.crt" -H "cookie: ${COOKIE}; ${CSRF}" \
    "https://${host}/api/v1/auth/session" | grep -q '"authenticated":true' \
    || die "${surface}: session not authenticated"
  if grep -Eiq 'access_token|refresh_token|id_token' "${jar}"; then
    die "${surface}: token material leaked into browser jar"
  fi
}

cmd_verify() {
  [ -f "${STATE_DIR}/secrets.env" ] || die "not installed"
  ensure_secrets
  log "verify: real OIDC tenant login -> federated native token -> real O3K API"
  browser_login tenant
  local scopes
  scopes="$(curl -sf --cacert "${TLS_DIR}/ca.crt" -H "cookie: ${COOKIE}; ${CSRF}" \
    https://tenant.o3k.demo/api/v1/auth/scopes)"
  echo "${scopes}" | grep -q "${ADMIN_PROJECT_ID}" \
    || die "tenant: O3K admin project not offered by scope discovery"
  curl -sf --cacert "${TLS_DIR}/ca.crt" -H "cookie: ${COOKIE}; ${CSRF}" \
    -H "x-csrf-token: ${CSRF#araf_csrf=}" -H 'content-type: application/json' \
    -X POST https://tenant.o3k.demo/api/v1/auth/scope \
    -d "{\"project_id\":\"${ADMIN_PROJECT_ID}\"}" >/dev/null
  curl -sf --cacert "${TLS_DIR}/ca.crt" -H "cookie: ${COOKIE}; ${CSRF}" \
    https://tenant.o3k.demo/api/v1/context >/dev/null
  curl -sf --cacert "${TLS_DIR}/ca.crt" -H "cookie: ${COOKIE}; ${CSRF}" \
    https://tenant.o3k.demo/api/v1/resources/compute.server >/dev/null
  curl -sf --cacert "${TLS_DIR}/ca.crt" -H "cookie: ${COOKIE}; ${CSRF}" \
    -H "x-csrf-token: ${CSRF#araf_csrf=}" -X POST \
    https://tenant.o3k.demo/api/v1/auth/logout >/dev/null
  log "verify: tenant surface reached real O3K native API"
  rm -rf "${WORK}"

  log "verify: real OIDC operator login -> system-scope native token"
  browser_login operator
  curl -sf --cacert "${TLS_DIR}/ca.crt" -H "cookie: ${COOKIE}; ${CSRF}" \
    https://operator.o3k.demo/api/v1/operator/profile >/dev/null
  curl -sf --cacert "${TLS_DIR}/ca.crt" -H "cookie: ${COOKIE}; ${CSRF}" \
    https://operator.o3k.demo/api/v1/operator/platform/overview >/dev/null
  curl -sf --cacert "${TLS_DIR}/ca.crt" -H "cookie: ${COOKIE}; ${CSRF}" \
    -H "x-csrf-token: ${CSRF#araf_csrf=}" -X POST \
    https://operator.o3k.demo/api/v1/auth/logout >/dev/null
  log "verify: operator surface reached real O3K native API"
  rm -rf "${WORK}"
  echo "PP.3 verify: PASS"
}

usage() {
  cat <<EOF
usage: $0 {install|verify|status|start|stop|uninstall [--yes]|purge [--yes]}
EOF
  exit 2
}

case "${1:-}" in
  install) cmd_install ;;
  verify) cmd_verify ;;
  status) cmd_status ;;
  start) cmd_start ;;
  stop) cmd_stop ;;
  uninstall) cmd_uninstall "${2:-}" ;;
  purge) cmd_purge "${2:-}" ;;
  *) usage ;;
esac
