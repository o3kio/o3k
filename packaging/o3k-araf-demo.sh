#!/usr/bin/env bash
# o3k-araf-demo.sh — PP.4 (#973) one-line-installer Araf demo deployment.
#
# Deploys the digest-pinned Araf compatibility tuple from
# contracts/araf-compatibility-v1.yaml (pp3_tuple/pp4_tuple) onto a single-node
# o3k-demo-v1 host as the final stage of the public one-line installer
# (packaging/get-o3k.sh), and supports convergent post-reboot reruns from the
# installed copy under /usr/local/share/o3k/araf-demo/. Browser-ready demo:
# the operator imports the locally minted demo CA and uses the tenant/operator
# consoles. Targets: Ubuntu 24.04 and Debian 12, x86_64 — Debian 12 installs
# the pinned upstream static Docker because bookworm's docker.io (20.10) is
# below the Docker>=24.0 contract minimum. Orchestration only: this script
# never fabricates O3K topology, Placement, BuildingBlock, CloudProfile, agent,
# or readiness state, and it never authorizes anything. O3K readiness stays
# independent of Araf availability.
#
# Subcommands:
#   install     preflight -> docker -> demo CA -> compose stack -> o3kd OIDC
#               federation enable -> health gates -> credentials file
#               (idempotent / convergent); appends the T3 timing stamp to
#               $PP4_TIMESTAMPS_FILE (installer timing ledger) when set
#   verify      real OIDC login (tenant + operator) through the production
#               Araf profile against the real O3K native API
#   tuple       print the pinned demo tuple: Araf constants plus the O3K
#               version/source commit read fail-closed from the installed
#               release manifest /usr/local/share/o3k/release-manifest.json
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
# never passed on argv of logged commands beyond the local host. The operator
# credentials file (credentials.txt, 0600) is written during install; only its
# path — never its contents — is printed.
set -Eeuo pipefail
umask 077

# ---------------------------------------------------------------------------
# Pinned compatibility tuple (Araf constants must match
# contracts/araf-compatibility-v1.yaml pp3_tuple/pp4_tuple;
# tests/pp4-araf-demo-contract.sh enforces drift). The O3K side of the tuple
# is NOT self-referential: version is pinned here, and the source commit is
# read fail-closed from the installed release manifest at install/tuple time.
# ---------------------------------------------------------------------------
ARAF_VERSION="v1.0.0-rc.12"
ARAF_SOURCE_SHA="de64cc9193085116fa30ad51c04ccab24a013dd0"
O3K_TUPLE_VERSION="v0.4.0-rc.8"

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
# Debian 12 (bookworm) apt ships docker.io 20.10 — below the Docker>=24.0
# contract minimum — so the Debian demo path installs the pinned upstream
# static binaries under /usr/local instead. download.docker.com does not
# publish a sidecar digest for the static tarball, so the pinned sha256 below
# was recorded from the tarball fetched from the pinned URL on 2026-09-19 and
# is verified before every install/use. The compose plugin publishes a
# .sha256 asset; the pinned digest matches the published file and the
# downloaded binary (verified 2026-09-19).
DOCKER_STATIC_VERSION="28.5.2"
DOCKER_STATIC_SHA256="ea90cfd12e1eeb12aa1c971741adb8bd4ed88e2a574eaac13f5029a1dbc6300d"
DOCKER_STATIC_BASE="https://download.docker.com/linux/static/stable/x86_64"
COMPOSE_PLUGIN_VERSION="v2.39.4"
COMPOSE_PLUGIN_SHA256="7af95166a730b87e172d4fc9aefea8725d3c6c7327d59149267b452114ddb7d4"
COMPOSE_PLUGIN_BASE="https://github.com/docker/compose/releases/download"

# ---------------------------------------------------------------------------
DEMO_HOSTS="tenant.o3k.demo operator.o3k.demo idp.o3k.demo api.o3k.demo"
ISSUER_REALM="o3k-demo"
ISSUER_URL="https://idp.o3k.demo/realms/${ISSUER_REALM}"
O3K_API_URL="https://api.o3k.demo"
TRUST_ID="araf-demo-idp"
O3K_AUDIENCE="o3k"
ADMIN_PROJECT_ID="eba29e2d-53de-461d-ae91-ede7402713cb"
ALICE_SUBJECT=""

STATE_DIR="${O3K_ARAF_DEMO_STATE_DIR:-/var/lib/o3k/araf-demo}"
TLS_DIR="${STATE_DIR}/tls"
COMPOSE_PROJECT="o3k-araf-demo"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/araf-demo/compose.yaml"
O3KD_ENV="/etc/o3k/o3kd.env"
O3K_RELEASE_MANIFEST="/usr/local/share/o3k/release-manifest.json"
# The demo never edits /etc/o3k/o3kd.env: O3K's installer keeps an install-time
# content ledger for that file and refuses to re-run when it was modified, so a
# demo-managed block in it would break one-line-installer convergence. The
# federation wiring lives in its own environment file, pulled in by a systemd
# drop-in that O3K's unit does not own.
O3KD_DROPIN_DIR="/etc/systemd/system/o3kd.service.d"
O3KD_DROPIN="${O3KD_DROPIN_DIR}/araf-demo.conf"
O3KD_DEMO_ENV="/etc/o3k/o3kd-araf-demo.env"
HOSTS_MARKER="# o3k-araf-demo"
ENV_BEGIN="# BEGIN o3k-araf-demo (PP.4)"
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

assert_compose_ownership() {
  # Compose scopes cleanup by project/service names.  A pre-existing foreign
  # resource can therefore collide even without --remove-orphans.  Every
  # resource in this project must carry the demo ownership label before any
  # start, stop, or purge operation is allowed.
  local kind id owner
  while read -r kind id; do
    [ -n "${id}" ] || continue
    owner="$(case "${kind}" in
      container) docker inspect -f '{{index .Config.Labels "o3k.io/pp-owner"}}' "${id}" 2>/dev/null || true ;;
      volume) docker volume inspect -f '{{index .Labels "o3k.io/pp-owner"}}' "${id}" 2>/dev/null || true ;;
      network) docker network inspect -f '{{index .Labels "o3k.io/pp-owner"}}' "${id}" 2>/dev/null || true ;;
    esac)"
    [ "${owner}" = "o3k-araf-demo" ] \
      || die "ownership fencing failure: ${kind} ${id} in Compose project ${COMPOSE_PROJECT} is not owned by o3k-araf-demo"
  done < <(
    docker ps -aq --filter "label=com.docker.compose.project=${COMPOSE_PROJECT}" \
      | awk '{print "container\t" $1}'
    docker volume ls -q --filter "label=com.docker.compose.project=${COMPOSE_PROJECT}" \
      | awk '{print "volume\t" $1}'
    docker network ls -q --filter "label=com.docker.compose.project=${COMPOSE_PROJECT}" \
      | awk '{print "network\t" $1}'
  )
}

# ---------------------------------------------------------------------------
# Preflight — every unsupported-environment check runs before any mutation.
# ---------------------------------------------------------------------------
preflight() {
  [ "$(id -u)" -eq 0 ] || die "must run as root"
  need_cmd curl; need_cmd openssl; need_cmd python3; need_cmd ss

  # PP.4 targets: Ubuntu 24.04 or Debian 12, x86_64. Fail closed elsewhere.
  [ -r /etc/os-release ] || die "cannot identify OS"
  # shellcheck disable=SC1091
  . /etc/os-release
  case "${ID}:${VERSION_ID}" in
    ubuntu:24.04|debian:12) ;;
    *)
      die "unsupported target ${ID:-?} ${VERSION_ID:-?}; PP.4 demo tuple is frozen for ubuntu-24.04 x86_64 and debian-12 x86_64 only"
      ;;
  esac
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

# Docker provisioning is target-specific:
#   Ubuntu 24.04 — apt docker.io + docker-compose-v2 (both >= the contract
#     minimums on noble).
#   Debian 12    — bookworm's docker.io is 20.10 (< Docker>=24.0 contract
#     minimum), so install the pinned upstream static tarball under
#     /usr/local/lib/o3k/docker-static/<VER>/bin with /usr/local/bin
#     symlinks, a minimal systemd unit, and the pinned compose plugin.
# Both paths converge on the same version-minimum gate below.
ensure_docker() {
  case "${ID}:${VERSION_ID}" in
    ubuntu:24.04)
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
      ;;
    debian:12)
      ensure_docker_static
      ensure_compose_plugin
      ;;
  esac
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

# Idempotency: skip the download entirely when the versioned dir already
# holds every binary and its recorded sha256 verifies.
static_docker_present() {
  local bindir="$1" b
  [ -f "${bindir}/SHA256SUMS" ] || return 1
  for b in docker dockerd containerd containerd-shim-runc-v2 runc ctr docker-init docker-proxy; do
    [ -x "${bindir}/${b}" ] || return 1
  done
  ( cd "${bindir}" && sha256sum -c --quiet SHA256SUMS >/dev/null 2>&1 )
}

ensure_docker_static() {
  local root="/usr/local/lib/o3k/docker-static"
  local bindir="${root}/${DOCKER_STATIC_VERSION}/bin"
  if static_docker_present "${bindir}"; then
    log "pinned Docker static ${DOCKER_STATIC_VERSION} already installed and verified"
  else
    log "installing pinned Docker static ${DOCKER_STATIC_VERSION} (Debian 12 apt docker.io is below the ${DOCKER_MIN} contract minimum)"
    # dockerd's bridge/NAT rules are delegated to the host iptables binary.
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends iptables ca-certificates >/dev/null
    local tmp
    tmp="$(mktemp -d)"
    curl -fsSL -o "${tmp}/docker.tgz" "${DOCKER_STATIC_BASE}/docker-${DOCKER_STATIC_VERSION}.tgz" \
      || { rm -rf "${tmp}"; die "docker static tarball download failed (${DOCKER_STATIC_BASE}/docker-${DOCKER_STATIC_VERSION}.tgz)"; }
    echo "${DOCKER_STATIC_SHA256}  ${tmp}/docker.tgz" | sha256sum -c - >/dev/null \
      || { rm -rf "${tmp}"; die "docker static tarball sha256 mismatch (pin ${DOCKER_STATIC_SHA256}; upstream replaced the tarball?)"; }
    tar -xzf "${tmp}/docker.tgz" -C "${tmp}" \
      || { rm -rf "${tmp}"; die "docker static tarball extraction failed"; }
    mkdir -p "${bindir}"
    local b
    for b in docker dockerd containerd containerd-shim-runc-v2 runc ctr docker-init docker-proxy; do
      [ -f "${tmp}/docker/${b}" ] || { rm -rf "${tmp}"; die "docker static tarball is missing ${b}"; }
      install -m 0755 "${tmp}/docker/${b}" "${bindir}/${b}"
    done
    rm -rf "${tmp}"
    ( cd "${bindir}" && sha256sum docker dockerd containerd containerd-shim-runc-v2 runc ctr docker-init docker-proxy > SHA256SUMS )
  fi
  local b
  for b in docker dockerd containerd containerd-shim-runc-v2 runc ctr docker-init docker-proxy; do
    ln -sfn "${bindir}/${b}" "/usr/local/bin/${b}"
  done
  # A distro docker.io (bookworm: 20.10, below the contract minimum) ships its
  # own units at /lib/systemd/system. Refuse to mix the two silently: stop and
  # disable them so the pinned static engine is the one that runs, then restart
  # so the version gate below measures the engine the demo will actually use.
  if [ -f /lib/systemd/system/docker.service ] || [ -f /lib/systemd/system/docker.socket ]; then
    log "disabling distro docker units in favour of the pinned static engine"
    systemctl disable --now docker.socket >/dev/null 2>&1 || true
    systemctl disable --now docker >/dev/null 2>&1 || true
  fi
  local unit_tmp
  unit_tmp="$(mktemp)"
  cat > "${unit_tmp}" <<'EOF'
[Unit]
Description=Docker Application Container Engine (O3K demo pinned static)
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/local/bin/dockerd
ExecReload=/bin/kill -s HUP $MAINPID
KillMode=process
Delegate=yes
Restart=always
StartLimitBurst=3
StartLimitIntervalSec=10s
LimitNOFILE=infinity
LimitNPROC=infinity
LimitCORE=infinity
TasksMax=infinity
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF
  if ! cmp -s "${unit_tmp}" /etc/systemd/system/docker.service; then
    install -m 0644 "${unit_tmp}" /etc/systemd/system/docker.service
    DOCKER_UNIT_CHANGED=1
  fi
  rm -f "${unit_tmp}"
  systemctl daemon-reload
  if [ "${DOCKER_UNIT_CHANGED:-0}" = "1" ] || ! systemctl is-active --quiet docker; then
    systemctl restart docker >/dev/null 2>&1 || systemctl start docker
  fi
  # Prove the running daemon is the pinned engine, not a distro leftover.
  local running
  running="$(readlink -f "/proc/$(pgrep -x dockerd | head -1)/exe" 2>/dev/null || true)"
  case "${running}" in
    "${bindir}/dockerd") ;;
    *) die "the running docker daemon is not the pinned static engine (${running:-none}); remove the distro docker.io package and re-run" ;;
  esac
}

ensure_compose_plugin() {
  local plugin_dir="/usr/local/libexec/docker/cli-plugins"
  local plugin="${plugin_dir}/docker-compose"
  if [ -f "${plugin}" ] && echo "${COMPOSE_PLUGIN_SHA256}  ${plugin}" | sha256sum -c - >/dev/null 2>&1; then
    log "pinned docker-compose plugin ${COMPOSE_PLUGIN_VERSION} already installed"
    return 0
  fi
  log "installing pinned docker-compose plugin ${COMPOSE_PLUGIN_VERSION}"
  local tmp
  tmp="$(mktemp -d)"
  curl -fsSL -o "${tmp}/docker-compose" \
    "${COMPOSE_PLUGIN_BASE}/${COMPOSE_PLUGIN_VERSION}/docker-compose-linux-x86_64" \
    || { rm -rf "${tmp}"; die "compose plugin download failed"; }
  curl -fsSL -o "${tmp}/docker-compose.sha256" \
    "${COMPOSE_PLUGIN_BASE}/${COMPOSE_PLUGIN_VERSION}/docker-compose-linux-x86_64.sha256" \
    || { rm -rf "${tmp}"; die "compose plugin published sha256 download failed"; }
  local published
  published="$(awk 'NR==1{print $1}' "${tmp}/docker-compose.sha256")"
  printf '%s' "${published}" | grep -Eq '^[0-9a-f]{64}$' \
    || { rm -rf "${tmp}"; die "compose plugin published sha256 is malformed"; }
  [ "${published}" = "${COMPOSE_PLUGIN_SHA256}" ] \
    || { rm -rf "${tmp}"; die "compose plugin published sha256 does not match the pinned constant (upstream replaced the asset?)"; }
  echo "${COMPOSE_PLUGIN_SHA256}  ${tmp}/docker-compose" | sha256sum -c - >/dev/null \
    || { rm -rf "${tmp}"; die "compose plugin sha256 mismatch after download"; }
  mkdir -p "${plugin_dir}"
  install -m 0755 "${tmp}/docker-compose" "${plugin}"
  rm -rf "${tmp}"
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
  ALICE_SUBJECT=""
  persist_secrets
}

persist_secrets() {
  local f="${STATE_DIR}/secrets.env"
  {
    printf 'ARAF_SESSION_STORE_KEY=%q\n' "${ARAF_SESSION_STORE_KEY}"
    printf 'TENANT_CLIENT_SECRET=%q\n' "${TENANT_CLIENT_SECRET}"
    printf 'OPERATOR_CLIENT_SECRET=%q\n' "${OPERATOR_CLIENT_SECRET}"
    printf 'KEYCLOAK_ADMIN_PASSWORD=%q\n' "${KEYCLOAK_ADMIN_PASSWORD}"
    printf 'ALICE_PASSWORD=%q\n' "${ALICE_PASSWORD}"
    printf 'FEDERATED_BINDING_ID=%q\n' "${FEDERATED_BINDING_ID}"
    printf 'OPERATOR_ASSIGNMENT_ID=%q\n' "${OPERATOR_ASSIGNMENT_ID}"
    printf 'ALICE_SUBJECT=%q\n' "${ALICE_SUBJECT:-}"
  } > "${f}"
  chmod 600 "${f}"
}

ensure_ca() {
  if [ ! -f "${TLS_DIR}/ca.crt" ] || [ ! -f "${TLS_DIR}/server.crt" ] || [ ! -f "${TLS_DIR}/server.key" ]; then
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
  # Realm secrets arrive via Keycloak env substitution (${VAR}); the file on
  # disk stays placeholder-only, so it can be readable by the idp container.
  # Demo users are provisioned through the admin API after boot (proven
  # pattern; imported credential metadata varies across Keycloak versions).
  cp "${SCRIPT_DIR}/araf-demo/realm.json" "${STATE_DIR}/realm.json"
  chmod 644 "${STATE_DIR}/realm.json"
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
  # Refuse a collision before docker load: the OCI archive may carry its own
  # tags, and loading it could overwrite a foreign local verification tag
  # before the post-load ownership check below can run.
  if docker image inspect "${tag}" >/dev/null 2>&1; then
    die "${component}: local verification tag ${tag} already names a different image; refusing to overwrite foreign state"
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
  # Never displace an image tag that is not the tuple-verified image.  A valid
  # archive may itself carry the local verification tag; accept that tag only
  # when it resolves to the verified identity.  Refusing every tag introduced
  # during load would reject a valid release archive.
  if docker image inspect "${tag}" >/dev/null 2>&1; then
    image_identity_matches "${tag}" "${config_digest}" "${index_digest}" \
      || die "${component}: local verification tag ${tag} appeared during load with a foreign identity; refusing to overwrite foreign state"
  else
    docker tag "${loaded}" "${tag}" >/dev/null
  fi
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
  local h added=0
  for h in ${DEMO_HOSTS}; do
    if grep -qE "^127\.0\.0\.1\s+.*\b${h}\b" /etc/hosts; then
      continue
    fi
    if [ "${added}" -eq 0 ]; then
      log "adding loopback demo hostnames to /etc/hosts (${HOSTS_MARKER})"
    fi
    printf '127.0.0.1 %s %s\n' "${h}" "${HOSTS_MARKER}" >> /etc/hosts
    added=$((added + 1))
  done
  return 0
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
O3K_TESTLAB_FEDERATED_SUBJECT=${ALICE_SUBJECT}
O3K_TESTLAB_FEDERATED_PRINCIPAL_ID=bootstrap-user
O3K_TESTLAB_FEDERATED_BINDING_ID=${FEDERATED_BINDING_ID}
O3K_TESTLAB_OPERATOR_ASSIGNMENT_ID=${OPERATOR_ASSIGNMENT_ID}
SSL_CERT_FILE=${TLS_DIR}/combined-ca.crt
${ENV_END}
EOF
}

o3kd_dropin_content() {
  cat <<EOF
# Managed by o3k-araf-demo (PP.4 #973); do not edit.
# The demo OIDC federation is kept out of /etc/o3k/o3kd.env because that file
# is O3K-install-owned (content ledger) and must stay byte-identical for
# one-line-installer convergence.
[Service]
EnvironmentFile=-${O3KD_DEMO_ENV}
EOF
}

# Legacy (PP.3) migration: strip the managed block the old mechanism appended
# to /etc/o3k/o3kd.env, restoring the file the installer's ledger expects.
legacy_strip_o3kd_env_block() {
  grep -q "^${ENV_BEGIN}" "${O3KD_ENV}" 2>/dev/null || return 0
  log "migrating legacy o3kd.env federation block to the managed drop-in"
  python3 - "${O3KD_ENV}" "${ENV_BEGIN}" "${ENV_END}" <<'PY' || die "legacy federation block removal failed"
import sys

path, begin, end = (value.strip() for value in sys.argv[1:4])
with open(path, encoding="utf-8") as handle:
    lines = handle.read().splitlines()
out, skipping = [], False
for line in lines:
    if line.strip() == begin:
        skipping = True
        continue
    if skipping and line.strip() == end:
        skipping = False
        continue
    if not skipping:
        out.append(line)
# the legacy writer appended "\n<block>\n" at EOF; drop the blank line it added
while out and not out[-1].strip():
    out.pop()
with open(path, "w", encoding="utf-8") as handle:
    handle.write("".join(f"{line}\n" for line in out))
PY
}

# Reconcile the managed operator-assignment id with the durable o3kd state:
# the assignment (principal + role) already exists after the first enable, and
# o3kd conflict-fails if the id changes. Read-only; canonical state wins.
reconcile_operator_assignment_id() {
  [ -f /var/lib/o3k/o3k.sqlite ] || return 0
  local durable
  durable="$(python3 - <<'PY' 2>/dev/null || true
import sqlite3
try:
    c = sqlite3.connect("file:/var/lib/o3k/o3k.sqlite?mode=ro", uri=True)
    row = c.execute(
        "select id from operator_assignments where user_id='bootstrap-user' order by id limit 1"
    ).fetchone()
    print(row[0] if row else "")
except Exception:
    print("")
PY
)"
  if [ -n "${durable}" ] && [ "${durable}" != "${OPERATOR_ASSIGNMENT_ID}" ]; then
    log "adopting durable operator assignment id ${durable}"
    OPERATOR_ASSIGNMENT_ID="${durable}"
    persist_secrets
  fi
}

ensure_o3kd_federation() {
  local desired current dropin_desired dropin_current
  desired="$(o3kd_block_content)"
  dropin_desired="$(o3kd_dropin_content)"
  current="$(cat "${O3KD_DEMO_ENV}" 2>/dev/null || true)"
  dropin_current="$(cat "${O3KD_DROPIN}" 2>/dev/null || true)"
  if [ "${current}" = "${desired}" ] && [ "${dropin_current}" = "${dropin_desired}" ]; then
    if systemctl is-active --quiet o3kd; then
      log "o3kd OIDC federation drop-in already present; no restart needed"
      return 0
    fi
    log "o3kd OIDC federation drop-in present; o3kd is down, restarting"
    systemctl restart o3kd
    wait_url "${O3KD_READY_URL}" "o3kd readiness after restart"
    return 0
  fi
  log "enabling o3kd OIDC federation (managed systemd drop-in; O3K config files untouched)"
  mkdir -p "${O3KD_DROPIN_DIR}"
  printf '%s\n' "${dropin_desired}" > "${O3KD_DROPIN}"
  chmod 644 "${O3KD_DROPIN}"
  ( umask 077 && printf '%s\n' "${desired}" > "${O3KD_DEMO_ENV}" )
  chmod 600 "${O3KD_DEMO_ENV}"
  systemctl daemon-reload
  systemctl restart o3kd
  wait_url "${O3KD_READY_URL}" "o3kd readiness after federation enable"
}

# Snapshot/restore around the federation enable: a failed enable must never
# leave the control plane down or half-configured.
FEDERATION_ROLLBACK_DIR="${STATE_DIR}/.federation-rollback"
snapshot_federation_state() {
  rm -rf "${FEDERATION_ROLLBACK_DIR}"
  mkdir -p "${FEDERATION_ROLLBACK_DIR}"
  chmod 700 "${FEDERATION_ROLLBACK_DIR}"
  [ -f "${O3KD_DEMO_ENV}" ] && cp -a "${O3KD_DEMO_ENV}" "${FEDERATION_ROLLBACK_DIR}/env.present" || touch "${FEDERATION_ROLLBACK_DIR}/env.absent"
  [ -f "${O3KD_DROPIN}" ] && cp -a "${O3KD_DROPIN}" "${FEDERATION_ROLLBACK_DIR}/dropin.present" || touch "${FEDERATION_ROLLBACK_DIR}/dropin.absent"
  return 0
}

restore_federation_state() {
  if [ -f "${FEDERATION_ROLLBACK_DIR}/env.present" ]; then
    cp -a "${FEDERATION_ROLLBACK_DIR}/env.present" "${O3KD_DEMO_ENV}"
  else
    rm -f "${O3KD_DEMO_ENV}"
  fi
  if [ -f "${FEDERATION_ROLLBACK_DIR}/dropin.present" ]; then
    cp -a "${FEDERATION_ROLLBACK_DIR}/dropin.present" "${O3KD_DROPIN}"
  else
    rm -f "${O3KD_DROPIN}"
    rmdir "${O3KD_DROPIN_DIR}" 2>/dev/null || true
  fi
  systemctl daemon-reload
  systemctl restart o3kd || true
  if wait_url_soft "${O3KD_READY_URL}" 45; then
    return 0
  fi
  # The rollback itself could not restore readiness: say so truthfully.
  die "o3kd did not reach readiness after rolling the demo federation drop-in back; inspect: journalctl -u o3kd -n 100"
}

remove_o3kd_federation() {
  local removed=0
  if [ -f "${O3KD_DEMO_ENV}" ]; then rm -f "${O3KD_DEMO_ENV}"; removed=1; fi
  if [ -f "${O3KD_DROPIN}" ]; then
    rm -f "${O3KD_DROPIN}"
    rmdir "${O3KD_DROPIN_DIR}" 2>/dev/null || true
    removed=1
  fi
  legacy_strip_o3kd_env_block && removed=1
  [ "${removed}" -eq 1 ] || return 0
  log "removing o3kd OIDC federation drop-in (service restart)"
  systemctl daemon-reload
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

# Same probe, bounded attempts, returns 1 instead of exiting: used where the
# caller must recover (federation rollback) rather than abort.
wait_url_soft() {
  local url="$1" attempts="${2:-30}" i
  for i in $(seq 1 "${attempts}"); do
    if curl -sf --cacert "${TLS_DIR}/ca.crt" "${url}" >/dev/null 2>&1 || curl -sf "${url}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  return 1
}

# ---------------------------------------------------------------------------
# Keycloak admin API helpers (master realm admin-cli; never logged)
# ---------------------------------------------------------------------------
kc_token() {
  # The password travels through a 0600 temp file (curl form field `@file`),
  # never through argv (/proc/<pid>/cmdline is world-readable). Bounded retry:
  # the IdP may still be finishing realm import when the first call lands.
  local pw_file attempt status body tok=""
  pw_file="$(mktemp)"
  chmod 600 "${pw_file}"
  printf '%s' "${KEYCLOAK_ADMIN_PASSWORD}" > "${pw_file}"
  for attempt in 1 2 3 4 5; do
    set +e
    status="$(curl -s --cacert "${TLS_DIR}/ca.crt" -o "${pw_file}.resp" -w '%{http_code}' -X POST \
      "https://idp.o3k.demo/realms/master/protocol/openid-connect/token" \
      -d grant_type=password -d client_id=admin-cli \
      -d username=admin --data-urlencode "password@${pw_file}")"
    set -e
    if [ "${status}" = 200 ]; then
      tok="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("access_token",""))' < "${pw_file}.resp" 2>/dev/null || true)"
      [ -n "${tok}" ] && break
    fi
    sleep 3
  done
  rm -f "${pw_file}" "${pw_file}.resp"
  if [ -z "${tok}" ]; then
    die "demo IdP admin token request did not succeed (last HTTP ${status}) — inspect: docker logs o3k-araf-demo-idp-1"
  fi
  printf '%s\n' "${tok}"
}

kc_api() { # kc_api METHOD PATH [JSON_BODY] — bounded retry, fail closed loudly
  local method="$1" path="$2" body="${3:-}" attempt="1" status="" tok body_file="" resp_file
  tok="$(kc_token)"
  resp_file="$(mktemp)"
  if [ -n "${body}" ]; then
    body_file="$(mktemp)"
    chmod 600 "${body_file}"
    printf '%s' "${body}" > "${body_file}"
  fi
  while [ "${attempt}" -le 5 ]; do
    set +e
    if [ -n "${body_file}" ]; then
      status="$(curl -s --cacert "${TLS_DIR}/ca.crt" -o "${resp_file}" -w '%{http_code}' -X "${method}" \
        -H "Authorization: Bearer ${tok}" -H 'Content-Type: application/json' \
        --data "@${body_file}" "https://idp.o3k.demo${path}")"
    else
      status="$(curl -s --cacert "${TLS_DIR}/ca.crt" -o "${resp_file}" -w '%{http_code}' -X "${method}" \
        -H "Authorization: Bearer ${tok}" "https://idp.o3k.demo${path}")"
    fi
    set -e
    case "${status}" in
      2*) rm -f "${body_file}" "${resp_file}"; return 0 ;;
    esac
    sleep 3
    attempt=$((attempt + 1))
  done
  # Fail closed with the observed status (never the request body or secrets).
  log "keycloak admin call failed: ${method} ${path} -> HTTP ${status}"
  if [ -s "${resp_file}" ]; then
    log "keycloak response (first 200 bytes): $(head -c 200 "${resp_file}" | tr -d '\n')"
  fi
  rm -f "${body_file}" "${resp_file}"
  die "demo IdP admin API call did not succeed: ${method} ${path} (HTTP ${status})"
}

# Retrying read of the demo user id (single source: the IdP assigns it).
kc_user_id() { # kc_user_id USERNAME -> prints the id or nothing
  local username="$1" attempt tok id=""
  for attempt in 1 2 3 4 5; do
    tok="$(kc_token)"
    id="$(curl -s --cacert "${TLS_DIR}/ca.crt" \
      -H "Authorization: Bearer ${tok}" \
      "https://idp.o3k.demo/admin/realms/${ISSUER_REALM}/users?username=${username}" \
      | python3 -c 'import json,sys
try:
    users = json.load(sys.stdin)
except Exception:
    users = []
print(users[0]["id"] if users else "")' 2>/dev/null || true)"
    [ -n "${id}" ] && break
    sleep 3
  done
  printf '%s' "${id}"
}

ensure_alice() {
  # Keycloak assigns the user id server-side, so the federated subject is
  # whatever id this IdP instance gave alice. Capture it and feed the o3kd
  # federation block from it; convergent across IdP re-creation (fresh demo
  # IdP database -> new subject -> managed block is rewritten + o3kd upserts
  # the new binding idempotently).
  local existing
  existing="$(kc_user_id alice)"
  if [ -z "${existing}" ]; then
    log "creating demo user alice"
    kc_api POST "/admin/realms/${ISSUER_REALM}/users" \
      '{"username":"alice","enabled":true,"firstName":"Alice","lastName":"Demo","email":"alice@o3k.demo","emailVerified":true}'
    existing="$(kc_user_id alice)"
  else
    # Converge profile fields: without them Keycloak's default VERIFY_PROFILE
    # required action intercepts the first login.
    kc_api PUT "/admin/realms/${ISSUER_REALM}/users/${existing}" \
      '{"username":"alice","enabled":true,"firstName":"Alice","lastName":"Demo","email":"alice@o3k.demo","emailVerified":true}'
  fi
  [ -n "${existing}" ] || die "keycloak user alice missing after provisioning"
  local block_subject
  # The federated subject recorded by the last enable lives in the demo-owned
  # env file (legacy PP.3 installs kept it in o3kd.env; read both). Both files
  # are optional at this point — the demo env file is written later by
  # ensure_o3kd_federation — so the lookups must never fail the script
  # (`set -e` + `pipefail` would abort on sed's exit status otherwise).
  block_subject=""
  if [ -f "${O3KD_DEMO_ENV}" ]; then
    block_subject="$(sed -n 's/^O3K_TESTLAB_FEDERATED_SUBJECT=//p' "${O3KD_DEMO_ENV}" | head -1 || true)"
  fi
  if [ -z "${block_subject}" ] && [ -f "${O3KD_ENV}" ]; then
    block_subject="$(sed -n 's/^O3K_TESTLAB_FEDERATED_SUBJECT=//p' "${O3KD_ENV}" | head -1 || true)"
  fi
  if [ -n "${block_subject}" ] && [ "${block_subject}" != "${existing}" ]; then
    # The demo IdP was recreated and assigned alice a new subject. o3kd's
    # TestLab federated hook conflict-fails when a binding id is reused with
    # a different identity, so rotate the binding id; previous binding rows
    # stay as inert history (documented LOW). The operator assignment id is
    # identity-stable (principal + role) and is NEVER rotated.
    log "alice subject changed (${block_subject} -> ${existing}); rotating federated binding identity"
    FEDERATED_BINDING_ID="$(python3 -c 'import uuid;print(uuid.uuid4())')"
  fi
  ALICE_SUBJECT="${existing}"
  persist_secrets
  log "demo user alice subject: ${ALICE_SUBJECT}"
  kc_api PUT "/admin/realms/${ISSUER_REALM}/users/${ALICE_SUBJECT}/reset-password" \
    '{"type":"password","value":"'"${ALICE_PASSWORD}"'","temporary":false}'
}

# ---------------------------------------------------------------------------
# O3K tuple side, read fail-closed from the installed release manifest (the
# published bundle manifest.json is the runtime authority; this script never
# carries its own source SHA). Prints O3K_VERSION=<v> / O3K_SOURCE_SHA=<sha>;
# exits 1 with a clear stderr message on missing/unreadable/mismatched input.
# ---------------------------------------------------------------------------
read_o3k_tuple() {
  python3 - "${O3K_RELEASE_MANIFEST}" "${O3K_TUPLE_VERSION}" <<'PY'
import json
import sys

path, expected = sys.argv[1], sys.argv[2]
try:
    with open(path, encoding="utf-8") as handle:
        document = json.load(handle)
except (OSError, ValueError):
    print("O3K tuple unavailable: installed release manifest is missing or "
          "unreadable: %s" % path, file=sys.stderr)
    sys.exit(1)
version = document.get("version") if isinstance(document, dict) else None
sha = document.get("source_commit") if isinstance(document, dict) else None
if not isinstance(version, str) or not version.strip():
    print("O3K tuple unavailable: installed release manifest declares no "
          "version: %s" % path, file=sys.stderr)
    sys.exit(1)
if not isinstance(sha, str) or not sha.strip():
    print("O3K tuple unavailable: installed release manifest declares no "
          "source_commit: %s" % path, file=sys.stderr)
    sys.exit(1)
strip_v = lambda text: text[1:] if text.startswith("v") else text
if strip_v(version.strip()) != strip_v(expected):
    print("O3K tuple unavailable: installed release %s does not match the "
          "pinned demo tuple %s" % (version.strip(), expected), file=sys.stderr)
    sys.exit(1)
print("O3K_VERSION=%s" % version.strip())
print("O3K_SOURCE_SHA=%s" % sha.strip())
PY
}

cmd_tuple() {
  local lines
  lines="$(read_o3k_tuple)" \
    || die "cannot build the demo tuple from the installed release manifest (${O3K_RELEASE_MANIFEST}); run the one-line installer first"
  printf 'ARAF_VERSION=%s\n' "${ARAF_VERSION}"
  printf 'ARAF_SOURCE_SHA=%s\n' "${ARAF_SOURCE_SHA}"
  printf 'ARAF_BFF_DIGEST=%s\n' "${ARAF_BFF_DIGEST}"
  printf '%s\n' "${lines}"
}

# ---------------------------------------------------------------------------
# PP.4 timing stamp + operator credentials file
# ---------------------------------------------------------------------------
pp4_record_t3() {
  local epoch iso target
  epoch="$(date +%s)"
  iso="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  target="${PP4_TIMESTAMPS_FILE:-}"
  if [ -n "${target}" ] && [ ! -e "${target}" ]; then
    ( umask 077 && : >> "${target}" ) 2>/dev/null || target=""
  fi
  if [ -n "${target}" ] && [ -w "${target}" ]; then
    printf 'T3=%s\nT3_ISO=%s\n' "${epoch}" "${iso}" >> "${target}" || true
  else
    printf 'T3=%s\nT3_ISO=%s\n' "${epoch}" "${iso}" >> "${STATE_DIR}/timestamps.env"
    chmod 600 "${STATE_DIR}/timestamps.env"
  fi
}

# Operator-facing credentials file: written root 0600, contents NEVER printed
# (only the path appears in the install summary).
write_credentials_file() {
  local f="${STATE_DIR}/credentials.txt"
  {
    printf 'O3K Araf demo credentials\n'
    printf 'username: alice\n'
    printf 'password: %s\n' "${ALICE_PASSWORD}"
    printf 'demo CA: %s\n' "${TLS_DIR}/ca.crt"
    printf 'tenant console:   https://tenant.o3k.demo/\n'
    printf 'operator console: https://operator.o3k.demo/\n'
    printf 'O3K API:          https://api.o3k.demo/\n'
    printf 'note: this file is root-only (mode 0600); the installer and the\n'
    printf 'demo script print its path but never its contents.\n'
  } > "${f}"
  chmod 600 "${f}"
}

# ---------------------------------------------------------------------------
# install / status / start / stop / uninstall / purge
# ---------------------------------------------------------------------------
cmd_install() {
  preflight
  # Fail closed on the O3K side of the tuple BEFORE any mutation: the
  # installed release manifest must exist, be readable, and declare the pinned
  # tuple version. The source commit comes from the manifest (this script is
  # copied into the release bundle, so it must never carry its own SHA).
  read_o3k_tuple >/dev/null \
    || die "installed O3K release manifest is missing/unreadable or does not match pinned tuple ${O3K_TUPLE_VERSION} (${O3K_RELEASE_MANIFEST})"
  ensure_docker
  mkdir -p "${STATE_DIR}" "${TLS_DIR}"
  chmod 700 "${STATE_DIR}"
  # o3kd runs as the o3k user and must read the TLS trust bundle for OIDC
  # discovery; grant traverse-only group access, files keep their own modes
  # (secrets stay 0600 root).
  if id o3k >/dev/null 2>&1; then
    chgrp o3k "${STATE_DIR}" "${TLS_DIR}" 2>/dev/null || true
    chmod 710 "${STATE_DIR}" "${TLS_DIR}"
  fi
  ensure_secrets
  ensure_ca
  cp "${SCRIPT_DIR}/araf-demo/nginx.conf" "${STATE_DIR}/nginx.conf"
  chmod 644 "${STATE_DIR}/nginx.conf"
  cp "${SCRIPT_DIR}/araf-demo/api-relay.conf" "${STATE_DIR}/api-relay.conf"
  chmod 644 "${STATE_DIR}/api-relay.conf"
  : > "${STATE_DIR}/nginx-default-blank.conf"
  chmod 644 "${STATE_DIR}/nginx-default-blank.conf"
  # Bind-mounted config changes need an explicit restart: track a content
  # hash so a convergent re-run restarts nothing and a real config change
  # recreates the nginx containers.
  local cfg_hash cfg_hash_file
  cfg_hash="$(cat "${SCRIPT_DIR}/araf-demo/nginx.conf" "${SCRIPT_DIR}/araf-demo/api-relay.conf" | sha256sum | cut -d' ' -f1)"
  cfg_hash_file="${STATE_DIR}/.nginx-config-hash"
  NGINX_CONFIG_CHANGED=0
  if [ ! -f "${cfg_hash_file}" ] || [ "$(cat "${cfg_hash_file}")" != "${cfg_hash}" ]; then
    NGINX_CONFIG_CHANGED=1
  fi
  printf '%s\n' "${cfg_hash}" > "${cfg_hash_file}"
  render_env_file
  render_realm
  ensure_hosts
  ensure_araf_images
  assert_compose_ownership
  log "starting Araf demo stack (${COMPOSE_PROJECT})"
  compose up -d
  if [ "${NGINX_CONFIG_CHANGED:-0}" = "1" ]; then
    log "nginx config changed; recreating tls-proxy and api-relay"
    compose up -d --force-recreate tls-proxy api-relay
  fi
  wait_url "https://idp.o3k.demo/demo-healthz" "idp health"
  ensure_alice
  reconcile_operator_assignment_id
  # Federation enabled only after the IdP is healthy: o3kd fetches OIDC
  # discovery/JWKS from the demo IdP at startup. The enable is wrapped in a
  # snapshot/rollback: a failed enable must not leave the control plane down.
  snapshot_federation_state
  if ! ( ensure_o3kd_federation ); then
    log "o3kd federation enable failed; restoring the previous state"
    restore_federation_state
    die "o3kd did not become ready with the demo federation drop-in; the previous state was restored and O3K is healthy again"
  fi
  wait_url "http://127.0.0.1:8080/readyz" "tenant BFF readiness"
  wait_url "http://127.0.0.1:8081/readyz" "operator BFF readiness"
  wait_url "https://tenant.o3k.demo/" "tenant console via TLS proxy"
  wait_url "https://operator.o3k.demo/" "operator console via TLS proxy"
  wait_url "${O3KD_READY_URL}" "o3kd readiness (independent of Araf)"
  pp4_record_t3
  write_credentials_file
  local tuple_lines o3k_manifest_version o3k_manifest_sha
  tuple_lines="$(read_o3k_tuple)" \
    || die "installed O3K release manifest is missing/unreadable or does not match pinned tuple ${O3K_TUPLE_VERSION} (${O3K_RELEASE_MANIFEST})"
  o3k_manifest_version="$(printf '%s\n' "${tuple_lines}" | sed -n 's/^O3K_VERSION=//p')"
  o3k_manifest_sha="$(printf '%s\n' "${tuple_lines}" | sed -n 's/^O3K_SOURCE_SHA=//p')"
  [ -n "${o3k_manifest_version}" ] && [ -n "${o3k_manifest_sha}" ] \
    || die "installed O3K release manifest tuple fields are empty (${O3K_RELEASE_MANIFEST})"
  cat <<EOF
[o3k-araf-demo] install OK
  tuple: O3K ${o3k_manifest_version} (${o3k_manifest_sha}) + Araf ${ARAF_VERSION} (${ARAF_SOURCE_SHA})
  tenant console:   https://tenant.o3k.demo/   (trust ${TLS_DIR}/ca.crt)
  operator console: https://operator.o3k.demo/
  O3K API:          https://api.o3k.demo/
  CLI config:       /etc/o3k/clouds.yaml, /etc/o3k/admin-openrc
  demo login:       alice  (credentials file: ${STATE_DIR}/credentials.txt, root 0600)
  next: o3k-araf-demo verify | o3k-araf-demo status
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
  assert_compose_ownership
  compose start
}

cmd_stop() {
  [ -f "${STATE_DIR}/secrets.env" ] || die "not installed"
  assert_compose_ownership
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
  assert_compose_ownership
  # Do not use --remove-orphans: containers in this Compose project that are
  # not part of our declared service set may belong to another workload.
  compose down 2>/dev/null || true
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
    assert_compose_ownership
    # Do not use --remove-orphans; purge may remove only this stack's declared
    # containers and its owned volumes, never an unrelated project orphan.
    compose down -v 2>/dev/null || true
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
  local pw_file
  pw_file="$(mktemp)"
  chmod 600 "${pw_file}"
  printf '%s' "${ALICE_PASSWORD}" > "${pw_file}"
  curl -sf --cacert "${TLS_DIR}/ca.crt" -D "${kc_headers}" -o /dev/null \
    -c "${jar}" -b "${jar}" -X POST "${form_action}" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode username=alice \
    --data-urlencode "password@${pw_file}" \
    --data-urlencode credentialId=
  local curl_rc=$?
  rm -f "${pw_file}"
  [ "${curl_rc}" -eq 0 ] || die "${surface}: keycloak login submit failed"
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
  echo "PP.4 verify: PASS"
}

usage() {
  cat <<EOF
usage: $0 {install|verify|tuple|status|start|stop|uninstall [--yes]|purge [--yes]}
EOF
  exit 2
}

case "${1:-}" in
  install) cmd_install ;;
  verify) cmd_verify ;;
  tuple) cmd_tuple ;;
  status) cmd_status ;;
  start) cmd_start ;;
  stop) cmd_stop ;;
  uninstall) cmd_uninstall "${2:-}" ;;
  purge) cmd_purge "${2:-}" ;;
  *) usage ;;
esac
