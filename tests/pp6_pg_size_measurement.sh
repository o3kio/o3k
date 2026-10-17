#!/usr/bin/env bash
set -euo pipefail
umask 077
: "${O3K_ADMIN_URL:?set O3K_ADMIN_URL to a disposable PostgreSQL admin URL}"
repo_root=$(cd "$(dirname "$0")/.." && pwd)
out_dir=${1:-"$repo_root/docs/pp/evidence/pp6-pg-size-$(date +%Y%m%dT%H%M%S)"}
if [[ -e "$out_dir" ]]; then printf 'output directory already exists: %s\n' "$out_dir" >&2; exit 2; fi
mkdir "$out_dir"; chmod 700 "$out_dir"
db="o3k_pp6_measure_$(date +%s)_$RANDOM"
db_url=$(python3 - "$O3K_ADMIN_URL" "$db" <<'PY'
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
import sys
u = urlsplit(sys.argv[1]); q = [(k,v) for k,v in parse_qsl(u.query, keep_blank_values=True) if k.lower() != "dbname"]
print(urlunsplit((u.scheme, u.netloc, "/" + sys.argv[2], urlencode(q), u.fragment)))
PY
)
created=false
cleanup() {
  if [[ "$created" == true ]]; then
    psql "$O3K_ADMIN_URL" -v ON_ERROR_STOP=1 -q -c "DROP DATABASE \"$db\"" >/dev/null || {
      printf 'cleanup_failed database=%s\n' "$db" >&2
      return 1
    }
  fi
}
trap cleanup EXIT
psql "$O3K_ADMIN_URL" -v ON_ERROR_STOP=1 -q -c "CREATE DATABASE \"$db\""
created=true
owner=$(psql "$O3K_ADMIN_URL" -Atqc "select pg_get_userbyid(datdba) from pg_database where datname='$db'")
admin_user=$(psql "$O3K_ADMIN_URL" -Atqc 'select current_user')
[[ "$owner" == "$admin_user" ]]
[[ "$(psql "$db_url" -Atqc 'select current_database()')" == "$db" ]]
for f in "$repo_root"/crates/o3k-store/migrations_postgres/*.sql; do psql "$db_url" -v ON_ERROR_STOP=1 -q -f "$f" >>"$out_dir/migrations.log" 2>&1; done
pg_database_bytes=$(psql "$db_url" -Atqc 'select pg_database_size(current_database())')
dump="$out_dir/control-plane.dump"
{ /usr/bin/time -f 'elapsed_seconds=%e peak_kib=%M' pg_dump --format=custom --no-owner --no-acl --file="$dump" "$db_url"; } 2>"$out_dir/pg_dump.time"
sqlite="$out_dir/o3k.sqlite"
for f in "$repo_root"/crates/o3k-store/migrations/*.sql; do sqlite3 "$sqlite" <"$f" >>"$out_dir/sqlite.log" 2>&1; done
sqlite_check=$(sqlite3 "$sqlite" 'pragma integrity_check;'); sqlite_source_bytes=$(stat -c %s "$sqlite")
sqlite_snapshot="$out_dir/snapshot.sqlite"; sqlite3 "$sqlite" 'pragma wal_checkpoint(truncate)' >>"$out_dir/sqlite.log"
python3 - "$sqlite" "$sqlite_snapshot" <<'PY'
import sqlite3, sys
db, snapshot = sys.argv[1:]
with sqlite3.connect(db) as c: c.execute("VACUUM INTO ?", (snapshot,))
PY
source_head=$(git -C "$repo_root" rev-parse HEAD); source_tree=$(git -C "$repo_root" rev-parse HEAD^{tree})
printf '{\n  "schema":"o3k.pp6.pg-size-measurement.v1",\n  "source_head":"%s",\n  "source_tree":"%s",\n  "postgres_server":"%s",\n  "pg_dump":"%s",\n  "pg_restore":"%s",\n  "postgres_migration_files":%s,\n  "postgres_database_bytes":%s,\n  "pg_dump_bytes":%s,\n  "pg_dump_sha256":"%s",\n  "pg_restore_list_sha256":"%s",\n  "sqlite_migration_files":%s,\n  "sqlite_source_bytes":%s,\n  "sqlite_snapshot_bytes":%s,\n  "sqlite_integrity_check":"%s",\n  "staging_available_bytes":%s,\n  "encrypted_outer_artifact":"PENDING",\n  "production_backup_restore":"ACCEPTANCE_PENDING"\n}\n' \
  "$source_head" "$source_tree" "$(psql "$db_url" -Atqc 'show server_version')" "$(pg_dump --version)" "$(pg_restore --version)" \
  "$(printf '%s\n' "$repo_root"/crates/o3k-store/migrations_postgres/*.sql | wc -l)" "$pg_database_bytes" "$(stat -c %s "$dump")" \
  "$(sha256sum "$dump" | awk '{print $1}')" "$(pg_restore --list "$dump" | sha256sum | awk '{print $1}')" \
  "$(printf '%s\n' "$repo_root"/crates/o3k-store/migrations/*.sql | wc -l)" "$sqlite_source_bytes" "$(stat -c %s "$sqlite_snapshot")" "$sqlite_check" \
  "$(df -B1 --output=avail "$out_dir" | tail -1 | tr -d ' ')" >"$out_dir/result.json.tmp"
python3 - "$out_dir/result.json.tmp" "$out_dir/result.json" <<'PY'
import json, os, sys
src, dst = sys.argv[1:]
with open(src, encoding="utf-8") as f: value = json.load(f)
tmp = dst + ".new"
with open(tmp, "w", encoding="utf-8") as f: json.dump(value, f, indent=2, sort_keys=True); f.write("\n"); os.fchmod(f.fileno(), 0o600)
os.replace(tmp, dst)
os.unlink(src)
PY
