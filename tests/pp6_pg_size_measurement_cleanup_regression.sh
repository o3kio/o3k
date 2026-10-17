#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
bin=$(mktemp -d /tmp/pp6-fake-bin.XXXXXX); log=$(mktemp /tmp/pp6-fake-log.XXXXXX)
cat >"$bin/psql" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${PP6_FAKE_LOG:?}"
case "$*" in
  *show\ server_version*) printf '16.4\n';;
  *CREATE\ DATABASE*) exit 7;;
esac
exit 0
EOF
for tool in pg_dump pg_restore; do
  cat >"$bin/$tool" <<'EOF'
#!/usr/bin/env bash
printf '%s (PostgreSQL) 16.4\n' "$(basename "$0")"
EOF
  chmod 700 "$bin/$tool"
done
chmod 700 "$bin/psql"
set +e
PATH="$bin:$PATH" PP6_FAKE_LOG="$log" O3K_ADMIN_URL='postgres://fake/postgres' \
  "$root/tests/pp6_pg_size_measurement.sh" "$(mktemp -d /tmp/pp6-fake-out.XXXXXX)/result" >/dev/null 2>&1
rc=$?
set -e
test "$rc" -eq 7
! grep -q 'DROP DATABASE' "$log"
printf 'PASS: failed CREATE exits without DROP DATABASE cleanup\n'
