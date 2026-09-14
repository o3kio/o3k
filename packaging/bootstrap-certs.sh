#!/usr/bin/env bash
set -Eeuo pipefail

OUTPUT_DIR=/etc/o3k/tls
SERVER_NAME=o3k-control-plane
AGENT_ID=compute-agent
EXTRA_AGENT_IDS=()
FORCE=0
append_extra_agent_id() {
  local extra_id="$1"
  [[ "$extra_id" =~ ^[A-Za-z0-9._-]+$ && ${#extra_id} -le 128 ]] \
    || { echo "extra agent id contains unsupported characters" >&2; exit 2; }
  EXTRA_AGENT_IDS+=("$extra_id")
}
while (($#)); do
  case "$1" in
    --output-dir) OUTPUT_DIR="${2:?missing output directory}"; shift 2;;
    --server-name) SERVER_NAME="${2:?missing server name}"; shift 2;;
    --agent-id) AGENT_ID="${2:?missing agent id}"; shift 2;;
    --extra-agent-id) append_extra_agent_id "${2:?missing extra agent id}"; shift 2;;
    --extra-agent-ids)
      IFS=',' read -r -a extra_ids <<<"${2:?missing extra agent ids}"
      for extra_id in "${extra_ids[@]}"; do append_extra_agent_id "$extra_id"; done
      shift 2
      ;;
    --force) FORCE=1; shift;;
    *) echo "unknown option: $1" >&2; exit 2;;
  esac
done
[[ "$OUTPUT_DIR" == /* && "$OUTPUT_DIR" != / ]] || { echo "output directory must be an absolute non-root path" >&2; exit 2; }
[[ "$SERVER_NAME" =~ ^[A-Za-z0-9.-]+$ ]] || { echo "server name contains unsupported characters" >&2; exit 2; }
[[ "$AGENT_ID" =~ ^[A-Za-z0-9._-]+$ && ${#AGENT_ID} -le 128 ]] || { echo "agent id contains unsupported characters" >&2; exit 2; }
for extra_id in "${EXTRA_AGENT_IDS[@]}"; do
  [[ "$extra_id" != "$AGENT_ID" ]] || { echo "duplicate agent id: $extra_id" >&2; exit 2; }
done
command -v openssl >/dev/null 2>&1 || { echo "openssl is required" >&2; exit 1; }
validate_no_symlink_path() {
  local path="$1" current=/ component
  while IFS= read -r component; do
    [[ -n "$component" ]] || continue
    case "$component" in
      .|..) echo "output directory contains an unsafe path component: $path" >&2; exit 2;;
    esac
    current="$current/$component"
    [[ ! -L "$current" ]] || { echo "refusing symlink certificate path: $path" >&2; exit 2; }
  done < <(tr '/' '\n' <<< "${path#/}")
  if [[ -e "$path" && ! -d "$path" ]]; then
    echo "certificate output path is not a directory: $path" >&2
    exit 2
  fi
}
validate_no_symlink_path "$OUTPUT_DIR"
[[ $FORCE -eq 1 || ! -e "$OUTPUT_DIR/ca.pem" ]] || { echo "certificates already exist; use --force to replace" >&2; exit 2; }
PARENT_DIR="$(dirname "$OUTPUT_DIR")"
install -d -m 0750 "$PARENT_DIR"
if [[ -e "$PARENT_DIR/.o3k-owned" ]]; then
  grep -Fqx "o3k-owned-v1 path=$PARENT_DIR" "$PARENT_DIR/.o3k-owned" || { echo "refusing unrecognized parent ownership marker" >&2; exit 2; }
elif [[ -n "$(find "$PARENT_DIR" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
  echo "refusing to claim populated unowned parent directory: $PARENT_DIR" >&2
  exit 2
else
  printf 'o3k-owned-v1 path=%s\n' "$PARENT_DIR" >"$PARENT_DIR/.o3k-owned"
  chmod 0640 "$PARENT_DIR/.o3k-owned"
fi
install -d -m 0750 "$OUTPUT_DIR"
TMP_DIR="$(mktemp -d "$OUTPUT_DIR/.tmp.XXXXXX")"
trap 'rm -rf -- "$TMP_DIR"' EXIT
umask 077
openssl genpkey -algorithm ED25519 -out "$TMP_DIR/ca-key.pem" >/dev/null 2>&1
openssl req -x509 -new -key "$TMP_DIR/ca-key.pem" -out "$TMP_DIR/ca.pem" -days 365 -subj "/CN=O3K TestLab CA" >/dev/null 2>&1
openssl genpkey -algorithm ED25519 -out "$TMP_DIR/server-key.pem" >/dev/null 2>&1
openssl req -new -key "$TMP_DIR/server-key.pem" -out "$TMP_DIR/server.csr" -subj "/CN=$SERVER_NAME" >/dev/null 2>&1
cat >"$TMP_DIR/server.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:$SERVER_NAME,IP:127.0.0.1
EOF
openssl x509 -req -in "$TMP_DIR/server.csr" -CA "$TMP_DIR/ca.pem" -CAkey "$TMP_DIR/ca-key.pem" -CAcreateserial -out "$TMP_DIR/server.pem" -days 365 -extfile "$TMP_DIR/server.ext" >/dev/null 2>&1
openssl genpkey -algorithm ED25519 -out "$TMP_DIR/agent-key.pem" >/dev/null 2>&1
openssl req -new -key "$TMP_DIR/agent-key.pem" -out "$TMP_DIR/agent.csr" -subj "/CN=$AGENT_ID" >/dev/null 2>&1
cat >"$TMP_DIR/agent.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectAltName=URI:urn:o3k:compute:agent:$AGENT_ID
EOF
openssl x509 -req -in "$TMP_DIR/agent.csr" -CA "$TMP_DIR/ca.pem" -CAkey "$TMP_DIR/ca-key.pem" -CAcreateserial -out "$TMP_DIR/agent.pem" -days 365 -extfile "$TMP_DIR/agent.ext" >/dev/null 2>&1
for extra_id in "${EXTRA_AGENT_IDS[@]}"; do
  extra_dir="$TMP_DIR/agents/$extra_id"
  install -d -m 0750 "$extra_dir"
  openssl genpkey -algorithm ED25519 -out "$extra_dir/agent-key.pem" >/dev/null 2>&1
  openssl req -new -key "$extra_dir/agent-key.pem" -out "$extra_dir/agent.csr" -subj "/CN=$extra_id" >/dev/null 2>&1
  cat >"$extra_dir/agent.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectAltName=URI:urn:o3k:compute:agent:$extra_id
EOF
  openssl x509 -req -in "$extra_dir/agent.csr" -CA "$TMP_DIR/ca.pem" -CAkey "$TMP_DIR/ca-key.pem" -CAcreateserial -out "$extra_dir/agent.pem" -days 365 -extfile "$extra_dir/agent.ext" >/dev/null 2>&1
done
for file in ca.pem server.pem server-key.pem agent.pem agent-key.pem; do install -m 0640 "$TMP_DIR/$file" "$OUTPUT_DIR/$file"; done
printf '%s\n' "$AGENT_ID" >"$OUTPUT_DIR/agent-id"
openssl x509 -in "$OUTPUT_DIR/agent.pem" -outform DER | sha256sum | awk '{print $1}' >"$OUTPUT_DIR/agent-fingerprint"
chmod 0640 "$OUTPUT_DIR/agent-id" "$OUTPUT_DIR/agent-fingerprint"
for extra_id in "${EXTRA_AGENT_IDS[@]}"; do
  extra_dir="$OUTPUT_DIR/agents/$extra_id"
  install -d -m 0750 "$extra_dir"
  install -m 0640 "$TMP_DIR/agents/$extra_id/agent.pem" "$extra_dir/agent.pem"
  install -m 0640 "$TMP_DIR/agents/$extra_id/agent-key.pem" "$extra_dir/agent-key.pem"
  printf '%s\n' "$extra_id" >"$extra_dir/agent-id"
  openssl x509 -in "$extra_dir/agent.pem" -outform DER | sha256sum | awk '{print $1}' >"$extra_dir/agent-fingerprint"
  chmod 0640 "$extra_dir/agent-id" "$extra_dir/agent-fingerprint"
done
for extra_id in "${EXTRA_AGENT_IDS[@]}"; do
  for extra_file in agent.pem agent-key.pem agent-id agent-fingerprint; do
    [[ -f "$OUTPUT_DIR/agents/$extra_id/$extra_file" && ! -L "$OUTPUT_DIR/agents/$extra_id/$extra_file" ]] \
      || { echo "extra agent certificate generation incomplete: $extra_id/$extra_file" >&2; exit 1; }
  done
done
if getent group o3k >/dev/null 2>&1; then chgrp o3k "$OUTPUT_DIR" "$OUTPUT_DIR"/*; fi
rm -f -- "$OUTPUT_DIR/ca-key.pem" "$OUTPUT_DIR/agent.csr" "$OUTPUT_DIR/ca.srl"
echo "generated O3K TestLab CA, server, and agent certificates under $OUTPUT_DIR for $SERVER_NAME agent=$AGENT_ID"
