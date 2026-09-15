#!/usr/bin/env bash
set -Eeuo pipefail
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/var/tmp}/o3k-p15-7-pg-clean.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT
bin="$work/bin"; mkdir -p "$bin"
cat >"$bin/sudo" <<'SH'
#!/usr/bin/env bash
[[ "$1" == -n ]] && shift
exec "$@"
SH
cat >"$bin/docker" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == inspect ]] || { [[ "$1" == rm ]] && exit 0; exit 1; }
if [[ "${O3K_FAKE_FOREIGN:-false}" == true ]]; then
  case "$*" in *"{{.Id}}"*) echo foreign-id;; *) echo foreign;; esac
else
  case "$*" in *"{{.Id}}"*) echo owned-id;; *"o3k.owner"*) echo o3k;; *"o3k.run_id"*) echo run-1;; *"o3k.phase"*) echo p15-7;; *"o3k.source_sha"*) echo 0123456789abcdef0123456789abcdef01234567;; *) echo ok;; esac
fi
SH
chmod +x "$bin/sudo" "$bin/docker"
artifact="$work/ownership.json"
printf '{"container_id":"owned-id","phase":"p15-7","run_id":"run-1","source_sha":"0123456789abcdef0123456789abcdef01234567","owner":"o3k"}\n' >"$artifact"
PATH="$bin:$PATH" TARGET_SHA=0123456789abcdef0123456789abcdef01234567 \
  bash "$root_dir/scripts/cleanup-owned-postgres.sh" p15-7 run-1 "$artifact"
if PATH="$bin:$PATH" O3K_FAKE_FOREIGN=true TARGET_SHA=0123456789abcdef0123456789abcdef01234567 \
  bash "$root_dir/scripts/cleanup-owned-postgres.sh" p15-7 run-1 "$artifact" >/dev/null 2>&1; then
  echo "foreign PostgreSQL container was removed" >&2; exit 1
fi
echo "P15.7 PostgreSQL cleanup tests passed"
