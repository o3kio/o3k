#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
fixture=$(mktemp -d /tmp/pp6-measure-fixture.XXXXXX)
bin=$(mktemp -d /tmp/pp6-fake-bin.XXXXXX)
log=$(mktemp /tmp/pp6-fake-log.XXXXXX)
trap 'rm -rf "$fixture" "$bin" "$log"' EXIT

mkdir -p "$fixture/tests" "$fixture/crates/o3k-store/migrations_postgres" "$fixture/crates/o3k-store/migrations"
cp "$root/tests/pp6_pg_size_measurement.sh" "$fixture/tests/pp6_pg_size_measurement.sh"
chmod 700 "$fixture/tests/pp6_pg_size_measurement.sh"
printf '%s\n' '-- placeholder' >"$fixture/crates/o3k-store/migrations_postgres/001.sql"
printf '%s\n' '-- placeholder' >"$fixture/crates/o3k-store/migrations/001.sql"
git -C "$fixture" init -q
git -C "$fixture" config user.email pp6-test@example.invalid
git -C "$fixture" config user.name pp6-test
git -C "$fixture" add .
git -C "$fixture" commit -qm fixture

cat >"$bin/psql" <<'EOF'
#!/usr/bin/env bash
printf 'psql %s\n' "$*" >>"${PP6_FAKE_LOG:?}"
case "$*" in
  *"show server_version"*) printf '16.4\n' ;;
  *"CREATE DATABASE"*) [[ "${PP6_FAKE_MODE:-}" == wrong_database ]] || exit 7 ;;
  *"pg_get_userbyid"*) [[ "${PP6_FAKE_MODE:-}" == wrong_database ]] && printf 'fakeadmin\n' ;;
  *"current_user"*) [[ "${PP6_FAKE_MODE:-}" == wrong_database ]] && printf 'fakeadmin\n' ;;
  *"current_database()"*) [[ "${PP6_FAKE_MODE:-}" == wrong_database ]] && printf 'foreign\n' ;;
  *"DROP DATABASE"*) : ;;
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

run_measurement() {
  local url=$1 out=$2 mode=${3:-}
  PATH="$bin:$PATH" PP6_FAKE_LOG="$log" PP6_FAKE_MODE="$mode" O3K_ADMIN_URL="$url" \
    "$fixture/tests/pp6_pg_size_measurement.sh" "$out" >/dev/null 2>&1
}

: >"$log"
set +e
run_measurement 'postgres://fake/postgres' "$fixture/out-create-fails"
rc=$?
set -e
test "$rc" -eq 7
! grep -q 'DROP DATABASE' "$log"
printf 'PASS: failed CREATE exits without DROP DATABASE cleanup\n'

: >"$log"
printf '%s\n' '-- untracked' >"$fixture/crates/o3k-store/migrations_postgres/002.sql"
set +e
run_measurement 'postgres://fake/postgres' "$fixture/out-untracked"
rc=$?
set -e
test "$rc" -ne 0
test ! -s "$log"
rm "$fixture/crates/o3k-store/migrations_postgres/002.sql"
printf 'PASS: untracked migration is rejected before SQL\n'

printf '%s\n' 'migrations_postgres/002.sql' >"$fixture/.git/info/exclude"
printf '%s\n' '-- ignored' >"$fixture/crates/o3k-store/migrations_postgres/002.sql"
: >"$log"
set +e
run_measurement 'postgres://fake/postgres' "$fixture/out-ignored"
rc=$?
set -e
test "$rc" -ne 0
test ! -s "$log"
rm "$fixture/crates/o3k-store/migrations_postgres/002.sql"
printf 'PASS: ignored untracked migration is rejected before SQL\n'

ln -s 001.sql "$fixture/crates/o3k-store/migrations_postgres/002.sql"
git -C "$fixture" add -f crates/o3k-store/migrations_postgres/002.sql
git -C "$fixture" commit -qm symlink
: >"$log"
set +e
run_measurement 'postgres://fake/postgres' "$fixture/out-symlink"
rc=$?
set -e
test "$rc" -ne 0
test ! -s "$log"
printf 'PASS: tracked migration symlink is rejected before SQL\n'

git -C "$fixture" rm -q crates/o3k-store/migrations_postgres/002.sql
git -C "$fixture" commit -qm clean
: >"$log"
set +e
run_measurement 'postgres://user:password@fake/postgres' "$fixture/out-password"
rc=$?
set -e
test "$rc" -ne 0
test ! -s "$log"
printf 'PASS: embedded-password URI is rejected before SQL\n'

git -C "$fixture" config --unset user.email
git -C "$fixture" config --unset user.name
: >"$log"
set +e
run_measurement 'postgres://fake/postgres' "$fixture/out-wrong-database" wrong_database
rc=$?
set -e
test "$rc" -ne 0
test "$(grep -c 'DROP DATABASE' "$log")" -eq 1
! grep -q ' -f ' "$log"
test ! -e "$fixture/out-wrong-database/result.json"
printf 'PASS: foreign current_database fails closed before migration\n'
