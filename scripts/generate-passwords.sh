#!/usr/bin/env bash
set -Eeuo pipefail

# Idempotently create O3K credentials.  The registry is deliberately small and
# explicit so new modules can add a named secret without copying generation
# logic into another installer.
OUTPUT_FILE="${O3K_PASSWORD_FILE:-/etc/o3k/o3kd.env}"
KOLLA_PASSWORD_FILE="${O3K_KOLLA_PASSWORD_FILE:-/etc/kolla/passwords.yml}"

usage() {
  printf 'usage: %s [--output PATH] [--kolla-password-file PATH]\n' "${0##*/}" >&2
}

while (($#)); do
  case "$1" in
    --output) (($# >= 2)) || { usage; exit 2; }; OUTPUT_FILE=$2; shift 2 ;;
    --kolla-password-file) (($# >= 2)) || { usage; exit 2; }; KOLLA_PASSWORD_FILE=$2; shift 2 ;;
    --help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done

die() { printf 'password generation failed: %s\n' "$1" >&2; exit 2; }
[[ "$OUTPUT_FILE" = /* && "$KOLLA_PASSWORD_FILE" = /* ]] || die "paths must be absolute"

parent="${OUTPUT_FILE%/*}"
[[ -n "$parent" && -d "$parent" && ! -L "$parent" ]] || die "output parent is missing or symlinked"
canonical_parent="$(realpath -e -- "$parent")" || die "cannot resolve output parent"
[[ "$canonical_parent" == "$parent" ]] || die "output parent must not contain symlink or dot components"
[[ -w "$parent" ]] || die "output parent is not writable"
if [[ -e "$OUTPUT_FILE" || -L "$OUTPUT_FILE" ]]; then
  [[ -f "$OUTPUT_FILE" && ! -L "$OUTPUT_FILE" ]] || die "output is not a regular file"
  owner="$(stat -c '%u' -- "$OUTPUT_FILE")"
  [[ "$owner" == "$EUID" || ( "$EUID" == 0 && "$owner" == 0 ) ]] || die "output is not owned by the invoking account"
fi

lock_file="${OUTPUT_FILE}.lock"
umask 077
exec 9>"$lock_file"
flock -n 9 || die "another password generation is in progress"

normalize_scalar() {
  python3 -c '
import ast, json, shlex, sys
value = sys.stdin.read().rstrip("\r\n")
quote = None
escaped = False
for index, character in enumerate(value):
    if quote == chr(34) and escaped:
        escaped = False
    elif quote == chr(34) and character == chr(92):
        escaped = True
    elif character in (chr(34), chr(39)):
        quote = None if quote == character else character if quote is None else quote
    elif quote is None and character == chr(35) and index > 0 and value[index - 1].isspace():
        value = value[:index].rstrip()
        break
if len(value) >= 2 and value[0] == value[-1] == chr(34):
    value = json.loads(value)
elif len(value) >= 2 and value[0] == value[-1] == chr(39):
    value = ast.literal_eval(value)
elif chr(92) in value:
    parts = shlex.split(value, posix=True)
    if len(parts) == 1:
        value = parts[0]
print(value, end="")
'
}

read_env_value() {
  local key="$1"
  [[ -f "$OUTPUT_FILE" ]] || return 0
  awk -F= -v key="$key" '$1 == key {sub(/^[^=]*=/, ""); print; exit}' "$OUTPUT_FILE" | normalize_scalar
}

read_kolla_admin_password() {
  if [[ -e "$KOLLA_PASSWORD_FILE" || -L "$KOLLA_PASSWORD_FILE" ]]; then
    [[ -f "$KOLLA_PASSWORD_FILE" && ! -L "$KOLLA_PASSWORD_FILE" ]] || die "Kolla password file is not a regular file"
  else
    return 0
  fi
  [[ -r "$KOLLA_PASSWORD_FILE" ]] || return 0
  awk '$1 == "keystone_admin_password:" {sub(/^[^:]*:[[:space:]]*/, ""); print; exit}' \
    "$KOLLA_PASSWORD_FILE" | normalize_scalar
}

bootstrap="$(read_env_value O3K_BOOTSTRAP_PASSWORD)"
if [[ -z "$bootstrap" ]]; then bootstrap="$(read_kolla_admin_password)"; fi
if [[ -z "$bootstrap" ]]; then bootstrap="$(openssl rand -hex 32)"; fi
signing_key="$(read_env_value O3K_TOKEN_SIGNING_KEY)"
if [[ -z "$signing_key" ]]; then signing_key="$(openssl rand -hex 48)"; fi
# Canonical P15.6 bootstrap secret (contracts/installer-v1.yaml): o3kd rejects
# /bootstrap/init without it, so the installed control plane can never reach
# canonical readiness when it is missing. Generated once, preserved verbatim
# on every regeneration, never printed.
bootstrap_secret="$(read_env_value O3K_BOOTSTRAP_SECRET)"
if [[ -z "$bootstrap_secret" ]]; then bootstrap_secret="$(openssl rand -hex 32)"; fi

[[ "$bootstrap" != *$'\n'* && "$bootstrap" != *$'\r'* ]] || die "bootstrap password contains a newline"
[[ "$signing_key" =~ ^[[:xdigit:]]{64,}$ ]] || die "token signing key must be at least 32 bytes of hex"
[[ "$bootstrap_secret" =~ ^[[:xdigit:]]{64}$ ]] || die "bootstrap secret must be 32 bytes of hex"

tmp="${OUTPUT_FILE}.tmp.$$"
trap 'rm -f -- "$tmp"' EXIT
{
  # Preserve the original line order and every unrelated line byte-for-byte:
  # the two generated keys are replaced in place, so regeneration is
  # idempotent and the installer's configuration ledger (which hashes the
  # file after installation) keeps matching across reset+reinstall. Reordering
  # the keys here made every reinstall look like an operator modification and
  # fail closed.
  bootstrap_written=0
  signing_written=0
  bootstrap_secret_written=0
  if [[ -f "$OUTPUT_FILE" ]]; then
    while IFS= read -r line; do
      case "$line" in
        O3K_BOOTSTRAP_PASSWORD=*)
          printf 'O3K_BOOTSTRAP_PASSWORD=%q\n' "$bootstrap"
          bootstrap_written=1
          ;;
        O3K_TOKEN_SIGNING_KEY=*)
          printf 'O3K_TOKEN_SIGNING_KEY=%q\n' "$signing_key"
          signing_written=1
          ;;
        O3K_BOOTSTRAP_SECRET=*)
          printf 'O3K_BOOTSTRAP_SECRET=%q\n' "$bootstrap_secret"
          bootstrap_secret_written=1
          ;;
        *)
          printf '%s\n' "$line"
          ;;
      esac
    done <"$OUTPUT_FILE"
  fi
  [[ $bootstrap_written -eq 1 ]] || printf 'O3K_BOOTSTRAP_PASSWORD=%q\n' "$bootstrap"
  [[ $signing_written -eq 1 ]] || printf 'O3K_TOKEN_SIGNING_KEY=%q\n' "$signing_key"
  [[ $bootstrap_secret_written -eq 1 ]] || printf 'O3K_BOOTSTRAP_SECRET=%q\n' "$bootstrap_secret"
} >"$tmp"
chmod 0600 "$tmp"
mv -f -- "$tmp" "$OUTPUT_FILE"
trap - EXIT
printf 'generated O3K credentials at %s\n' "$OUTPUT_FILE"
