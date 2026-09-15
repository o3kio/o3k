#!/usr/bin/env bash
set -Eeuo pipefail

# Self-contained P15.7 TestLab authority.  Keycloak is only a disposable OIDC
# provider fixture; O3K remains the authority for bindings, assignments and
# native tokens.  The fixture deliberately shares the P12-IAM.7 provider
# contract (Keycloak 25.0.6, RS256, discovery/JWKS, real access tokens).

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_ID="${GITHUB_RUN_ID:-local-$$}"
SOURCE_SHA="${O3K_P15_7_SOURCE_SHA:-${GITHUB_SHA:-}}"
MODE="${O3K_P15_7_AUTHORITY_MODE:-testlab-keycloak}"
STATE_ROOT="${O3K_P15_7_KEYCLOAK_STATE_ROOT:-${RUNNER_TEMP:-/tmp}/o3k-p15-7-keycloak-${RUN_ID}}"
IMAGE="quay.io/keycloak/keycloak:25.0.6@sha256:82c5b7a110456dbd42b86ea572e728878549954cc8bd03cd65410d75328095d2"
# Keep the P12-IAM.7 evidence sources visible and pinned as the single real
# provider contract; this P15 fixture does not introduce a second IAM path.
P12_REAL_IDP_HARNESS="$ROOT_DIR/tests/p12-iam-7-real-idp.sh"
P12_REAL_OIDC_TEST="$ROOT_DIR/bins/o3kd/tests/p12_iam_7_real_oidc.rs"
CONTAINER="o3k-p15-7-keycloak-${RUN_ID}"
PORT_FILE="$STATE_ROOT/port"
ENV_FILE="$STATE_ROOT/provider.env"
TOKEN_FILE="$STATE_ROOT/oidc-operator.token"
OPERATOR_PASSWORD_FILE="$STATE_ROOT/operator-password"
REALM_FILE="$STATE_ROOT/realm.json"
OWNER_FILE="$STATE_ROOT/.o3k-owned"
RUN_MARKER="$STATE_ROOT/.o3k-keycloak-owned"
UMASK_OLD=""

die() { echo "P15.7 Keycloak authority: $*" >&2; exit 1; }
[[ "$MODE" == testlab-keycloak || "$MODE" == external-oidc ]] || die "invalid authority mode"
[[ "$RUN_ID" =~ ^[A-Za-z0-9._-]+$ ]] || die "unsafe run id"
[[ "$SOURCE_SHA" =~ ^[0-9a-fA-F]{40}$ || -z "$SOURCE_SHA" ]] || die "invalid source SHA"
[[ -f "$P12_REAL_IDP_HARNESS" && -f "$P12_REAL_OIDC_TEST" ]] || die "accepted P12-IAM.7 machinery is unavailable"

if [[ "$MODE" == external-oidc ]]; then
  # External certification is intentionally not coupled to the TestLab fixture.
  [[ "${1:-}" == external-oidc || "${1:-}" == "" ]] || die "external mode does not manage Keycloak"
  exit 0
fi

for command in docker curl python3; do command -v "$command" >/dev/null 2>&1 || die "missing command: $command"; done
[[ "$STATE_ROOT" == /* && "$STATE_ROOT" != *..* && ! -L "$STATE_ROOT" ]] || die "unsafe state root"
mkdir -p -- "$STATE_ROOT"
chmod 0700 -- "$STATE_ROOT"

write_marker() {
  printf 'o3k-p15-7-keycloak-container-v1\nrun=%s\nsource_sha=%s\n' "$RUN_ID" "$SOURCE_SHA" >"$RUN_MARKER"
  chmod 0600 -- "$RUN_MARKER"
}

write_owner_marker() {
  printf 'o3k-p15-7-keycloak-owned-v1\nrun=%s\nsource_sha=%s\n' "$RUN_ID" "$SOURCE_SHA" >"$OWNER_FILE"
  chmod 0600 -- "$OWNER_FILE"
}

secure_remove() {
  local path
  for path in "$@"; do
    [[ -e "$path" || -L "$path" ]] || continue
    if command -v shred >/dev/null 2>&1 && [[ ! -L "$path" ]]; then
      shred --remove --zero --force "$path" >/dev/null 2>&1 || rm -f -- "$path"
    else
      rm -f -- "$path"
    fi
  done
}

pick_port() {
  python3 - <<'PY'
import socket
sock = socket.socket()
sock.bind(("127.0.0.1", 0))
print(sock.getsockname()[1])
sock.close()
PY
}

start() {
  [[ ! -e "$OWNER_FILE" && ! -e "$RUN_MARKER" ]] || die "run-owned Keycloak state already exists"
  local port admin_password operator_password
  write_owner_marker
  port="$(pick_port)"
  admin_password="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
  operator_password="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
  umask 077
  local env_tmp realm_tmp
  env_tmp="$(mktemp "$STATE_ROOT/env.XXXXXX")"
  realm_tmp="$(mktemp "$STATE_ROOT/realm.XXXXXX")"
  chmod 0600 "$env_tmp" "$realm_tmp"
  # Docker reads credentials from this 0600 file.  They never occur in the
  # docker argv, process list, logs, or workflow output.
  printf 'KEYCLOAK_ADMIN=p15-7-admin\nKEYCLOAK_ADMIN_PASSWORD=%s\n' "$admin_password" >"$env_tmp"
  printf '%s\n' "$operator_password" >"$OPERATOR_PASSWORD_FILE"
  chmod 0600 "$OPERATOR_PASSWORD_FILE"
  python3 - "$realm_tmp" "$OPERATOR_PASSWORD_FILE" <<'PY'
import json, sys
path, password_path = sys.argv[1:]
with open(password_path, encoding="utf-8") as stream:
    password = stream.read().strip()
realm = {
  "realm": "o3k-p15-7", "enabled": True,
  "clients": [{"clientId": "o3k-test", "enabled": True,
                "publicClient": True, "directAccessGrantsEnabled": True,
                "standardFlowEnabled": False, "protocol": "openid-connect",
                "protocolMappers": [{"name": "o3k-audience", "protocol": "openid-connect",
                                      "protocolMapper": "oidc-audience-mapper",
                                      "config": {"included.client.audience": "o3k",
                                                 "id.token.claim": "false", "access.token.claim": "true"}}]}],
  "users": [{"username": "operator", "firstName": "O3K", "lastName": "Operator",
              "enabled": True, "emailVerified": True, "requiredActions": [],
              "credentials": [{"type": "password", "value": password, "temporary": False}]}]
}
with open(path, "w", encoding="utf-8") as stream:
    json.dump(realm, stream)
PY
  printf '%s\n' "$port" >"$PORT_FILE"
  chmod 0600 "$PORT_FILE"
  mv -f -- "$realm_tmp" "$REALM_FILE"
  if ! docker run --detach --name "$CONTAINER" --network host \
    --label o3k.owner=o3k --label o3k.component=p15-7-keycloak \
    --label o3k.phase=p15-7 --label "o3k.run_id=$RUN_ID" \
    --label "o3k.source_sha=$SOURCE_SHA" \
    --env-file "$env_tmp" -e "KC_HTTP_PORT=$port" \
    -e "KC_HOSTNAME=http://127.0.0.1:$port" -e KC_HOSTNAME_STRICT=false \
    -v "$REALM_FILE:/opt/keycloak/data/import/p15-7-realm.json:ro" \
    "$IMAGE" start-dev --http-port="$port" --import-realm >/dev/null; then
    secure_remove "$env_tmp" "$realm_tmp"
    die "Keycloak container failed to start"
  fi
  secure_remove "$env_tmp"
  write_marker
  for _ in $(seq 1 90); do
    if curl --fail --silent --show-error --connect-timeout 2 --max-time 5 \
      "http://127.0.0.1:$port/realms/o3k-p15-7/.well-known/openid-configuration" \
      -o "$STATE_ROOT/discovery.json"; then break; fi
    sleep 1
  done
  [[ -s "$STATE_ROOT/discovery.json" ]] || die "Keycloak discovery unavailable"
  local issuer discovery
  issuer="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["issuer"])' "$STATE_ROOT/discovery.json")"
  discovery="http://127.0.0.1:$port/realms/o3k-p15-7/.well-known/openid-configuration"
  acquire_operator_token
  cat >"$ENV_FILE" <<EOF
O3K_P15_7_AUTHORITY_MODE=testlab-keycloak
O3K_P15_7_KEYCLOAK_STATE_ROOT=$STATE_ROOT
O3K_P15_7_KEYCLOAK_CONTAINER=$CONTAINER
O3K_P15_7_KEYCLOAK_PORT=$port
O3K_OIDC_TRUST_ID=p15-7-keycloak
O3K_OIDC_ISSUER=$issuer
O3K_OIDC_AUDIENCE=o3k
O3K_OIDC_DISCOVERY_URL=$discovery
O3K_OIDC_ALLOW_INSECURE_LOCAL=true
EOF
  chmod 0600 "$ENV_FILE"
  # The subject is the stable durable binding key.  Keep it out of the shell
  # command line and derive it from the signed token payload.
  python3 - "$TOKEN_FILE" "$ENV_FILE" <<'PY'
import base64, json, pathlib, sys
token = pathlib.Path(sys.argv[1]).read_text().strip()
payload = json.loads(base64.urlsafe_b64decode(token.split('.')[1] + '=' * (-len(token.split('.')[1]) % 4)))
subject = payload.get('sub')
if not isinstance(subject, str) or not subject: raise SystemExit('operator subject missing')
with open(sys.argv[2], 'a', encoding='utf-8') as stream:
    stream.write('O3K_TESTLAB_FEDERATED_SUBJECT=' + subject + '\n')
    stream.write('O3K_TESTLAB_FEDERATED_PRINCIPAL_ID=bootstrap-user\n')
    stream.write('O3K_TESTLAB_FEDERATED_BINDING_ID=p15-7-keycloak-operator\n')
    stream.write('O3K_TESTLAB_OPERATOR_ASSIGNMENT_ID=p15-7-keycloak-operator-console\n')
PY
  chmod 0600 "$ENV_FILE"
  printf '%s\n' "$issuer" >"$STATE_ROOT/issuer"
  chmod 0600 "$STATE_ROOT/issuer"
}

acquire_operator_token() {
  [[ -f "$PORT_FILE" && -f "$OPERATOR_PASSWORD_FILE" ]] || die "operator credential is unavailable"
  local port request_cfg response_file password
  port="$(<"$PORT_FILE")"
  password="$(<"$OPERATOR_PASSWORD_FILE")"
  request_cfg="$(mktemp "$STATE_ROOT/curl.XXXXXX")"
  response_file="$(mktemp "$STATE_ROOT/oauth-response.XXXXXX")"
  chmod 0600 "$request_cfg" "$response_file"
  # Password grant is only a fixture login for the real human operator.  The
  # generated credential remains in a 0600 curl config, never in argv/logs.
  printf 'url = "http://127.0.0.1:%s/realms/o3k-p15-7/protocol/openid-connect/token"\nrequest = "POST"\nheader = "Content-Type: application/x-www-form-urlencoded"\ndata = "grant_type=password&client_id=o3k-test&username=operator&password=%s"\n' "$port" "$password" >"$request_cfg"
  curl --fail --silent --show-error --config "$request_cfg" -o "$response_file" \
    || die "operator OAuth token acquisition failed"
  secure_remove "$TOKEN_FILE"
  python3 - "$response_file" "$TOKEN_FILE" <<'PY'
import json, os, pathlib, sys
token = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")).get("access_token")
if not isinstance(token, str) or token.count(".") != 2:
    raise SystemExit("Keycloak did not return a signed OAuth access token")
fd = os.open(sys.argv[2], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
try: os.write(fd, (token + "\n").encode())
finally: os.close(fd)
PY
  chmod 0600 "$TOKEN_FILE"
  secure_remove "$request_cfg" "$response_file"
}

exchange() {
  [[ -f "$ENV_FILE" && -f "$TOKEN_FILE" ]] || die "Keycloak authority is not started"
  # Always obtain a fresh short-lived provider token immediately before the
  # native exchange.  Renewal is another canonical federation exchange, never
  # an extended token lifetime or a locally minted O3K bearer token.
  acquire_operator_token
  local api="${O3K_P15_7_NATIVE_API_URL:-${O3K_API_URL:-http://127.0.0.1:${O3K_TESTLAB_PORT:-28080}/o3k/v1}}"
  local token request response native
  token="$(<"$TOKEN_FILE")"
  request="$(mktemp "$STATE_ROOT/exchange.XXXXXX")"; response="$(mktemp "$STATE_ROOT/native.XXXXXX")"
  chmod 0600 "$request" "$response"
  printf '{"auth":{"method":"federated","federated":{"access_token":"%s","scope":{"kind":"system"}}}}\n' "$token" >"$request"
  curl --fail --silent --show-error --proto '=http,https' --max-time 20 \
    -H 'Content-Type: application/json' --data-binary "@$request" \
    "$api/identity/tokens" -o "$response" || die "native federated exchange failed"
  native="$(python3 - "$response" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding='utf-8'))['token']['id']
if not isinstance(value, str) or not value: raise SystemExit('native token missing')
print(value)
PY
)"
  local output="${O3K_P15_7_AUTHORITY_OUTPUT_FILE:-${RUNNER_TEMP:-/tmp}/o3k-p15-7-authority-${RUN_ID}.json}"
  (umask 077; printf '%s\n' "$native" >"$output")
  chmod 0600 "$output"
  secure_remove "$request" "$response"
}

cleanup() {
  [[ -f "$OWNER_FILE" && ! -L "$OWNER_FILE" ]] || return 0
  grep -Fqx 'o3k-p15-7-keycloak-owned-v1' "$OWNER_FILE" || die "invalid Keycloak ownership ledger"
  grep -Fqx "run=$RUN_ID" "$OWNER_FILE" || die "Keycloak ownership run mismatch"
  grep -Fqx "source_sha=$SOURCE_SHA" "$OWNER_FILE" || die "Keycloak ownership source mismatch"
  if [[ -f "$RUN_MARKER" && ! -L "$RUN_MARKER" ]]; then
    grep -Fqx 'o3k-p15-7-keycloak-container-v1' "$RUN_MARKER" || die "invalid Keycloak container ledger"
    grep -Fqx "run=$RUN_ID" "$RUN_MARKER" || die "Keycloak container run mismatch"
    grep -Fqx "source_sha=$SOURCE_SHA" "$RUN_MARKER" || die "Keycloak container source mismatch"
    local owner component phase run_id source
    owner="$(docker inspect -f '{{index .Config.Labels "o3k.owner"}}' "$CONTAINER" 2>/dev/null || true)"
    component="$(docker inspect -f '{{index .Config.Labels "o3k.component"}}' "$CONTAINER" 2>/dev/null || true)"
    phase="$(docker inspect -f '{{index .Config.Labels "o3k.phase"}}' "$CONTAINER" 2>/dev/null || true)"
    run_id="$(docker inspect -f '{{index .Config.Labels "o3k.run_id"}}' "$CONTAINER" 2>/dev/null || true)"
    source="$(docker inspect -f '{{index .Config.Labels "o3k.source_sha"}}' "$CONTAINER" 2>/dev/null || true)"
    [[ "$owner" == o3k && "$component" == p15-7-keycloak && "$phase" == p15-7 \
      && "$run_id" == "$RUN_ID" && "$source" == "$SOURCE_SHA" ]] \
      || die "refusing to remove ambiguous or foreign Keycloak container"
    docker rm --force "$CONTAINER" >/dev/null
  elif docker inspect "$CONTAINER" >/dev/null 2>&1; then
    # A same-name container without our container ledger is ambiguous. Never
    # remove it, even though this run's state ledger is otherwise valid.
    die "refusing to remove ambiguous or foreign Keycloak container"
  fi
  if command -v shred >/dev/null 2>&1; then
    find "$STATE_ROOT" -type f -exec shred --remove --zero --force {} + >/dev/null 2>&1 || true
  fi
  rm -rf -- "$STATE_ROOT"
}

case "${1:-start}" in
  start) start ;;
  exchange) exchange ;;
  cleanup) cleanup ;;
  *) die "usage: $0 start|exchange|cleanup" ;;
esac
