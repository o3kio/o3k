#!/usr/bin/env bash
set -euo pipefail
umask 077
export PGCONNECT_TIMEOUT=5
psql() { command psql -X --no-password "$@" 2>/dev/null; }
: "${O3K_ADMIN_URL:?set O3K_ADMIN_URL to a disposable PostgreSQL admin URL}"
repo_root=$(cd "$(dirname "$0")/.." && pwd)
out_dir=${1:?provide a new private output directory}
git -C "$repo_root" diff --quiet HEAD -- || { printf 'tracked source is dirty\n' >&2; exit 2; }
migration_dirs=(crates/o3k-store/migrations crates/o3k-store/migrations_postgres)
[[ -z "$(git -C "$repo_root" status --porcelain --untracked-files=all -- "${migration_dirs[@]}")" && -z "$(git -C "$repo_root" ls-files --others -- "${migration_dirs[@]}")" ]] || {
  printf 'migration inputs differ from committed source\n' >&2; exit 2;
}
for f in "$repo_root"/crates/o3k-store/migrations{,_postgres}/*.sql; do
  [[ -f "$f" && ! -L "$f" ]] || { printf 'migration must be a regular committed file\n' >&2; exit 2; }
done
if [[ -e "$out_dir" ]]; then printf 'output directory already exists: %s\n' "$out_dir" >&2; exit 2; fi
mkdir "$out_dir"; chmod 700 "$out_dir"
db="o3k_pp6_measure_$(date +%s)_$RANDOM"
printf '%s\n' "$db" >"$out_dir/database.name"
stage=connection_preflight
trap 'printf "measurement_failed stage=%s\n" "$stage" >&2' ERR
trap 'exit 130' INT
trap 'exit 143' TERM
db_url=$(python3 - "$db" <<'PY'
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
import os, sys
u = urlsplit(os.environ["O3K_ADMIN_URL"])
pairs = parse_qsl(u.query, keep_blank_values=True)
if u.scheme not in {"postgres", "postgresql"} or u.fragment or u.password is not None or any(k.lower() in {"password", "sslpassword"} for k, _ in pairs):
    sys.exit("use a password-free PostgreSQL URI with PGPASSFILE or PGPASSWORD")
q = [(k,v) for k,v in pairs if k.lower() != "dbname"]
if u.netloc:
    print(urlunsplit((u.scheme, u.netloc, "/" + sys.argv[1], urlencode(q), "")))
else:
    # urllib's generic URI serializer collapses the empty PostgreSQL authority.
    print(u.scheme + ":///" + sys.argv[1] + ("?" + urlencode(q) if q else ""))
PY
)
server_version=$(psql "$O3K_ADMIN_URL" -Atqc 'show server_version')
[[ "$server_version" == 16.* ]] || { printf 'PostgreSQL 16 required\n' >&2; exit 2; }
dump_version=$(pg_dump --version)
restore_version=$(pg_restore --version)
[[ "$dump_version" == 'pg_dump (PostgreSQL) 16.'* && "$restore_version" == 'pg_restore (PostgreSQL) 16.'* ]] || exit 2
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
stage=create_database
psql "$O3K_ADMIN_URL" -v ON_ERROR_STOP=1 -q -c "CREATE DATABASE \"$db\""
created=true
owner=$(psql "$O3K_ADMIN_URL" -Atqc "select pg_get_userbyid(datdba) from pg_database where datname='$db'")
admin_user=$(psql "$O3K_ADMIN_URL" -Atqc 'select current_user')
[[ "$owner" == "$admin_user" ]]
[[ "$(psql "$db_url" -Atqc 'select current_database()')" == "$db" ]]
stage=postgres_migrations
for f in "$repo_root"/crates/o3k-store/migrations_postgres/*.sql; do psql "$db_url" -v ON_ERROR_STOP=1 -q -f "$f" >>"$out_dir/migrations.log" 2>&1; done
pg_database_bytes=$(psql "$db_url" -Atqc 'select pg_database_size(current_database())')
stage=postgres_dump
dump="$out_dir/control-plane.dump"
/usr/bin/time -f 'elapsed_seconds=%e peak_kib=%M' -o "$out_dir/pg_dump.time" pg_dump --no-password --format=custom --no-owner --no-acl --file="$dump" "$db_url" 2>/dev/null
stage=sqlite_fixture
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
dump_bytes=$(stat -c %s "$dump")
dump_sha=$(sha256sum "$dump" | awk '{print $1}')
toc_sha=$(pg_restore --list "$dump" 2>/dev/null | sha256sum | awk '{print $1}')
pg_count=$(printf '%s\n' "$repo_root"/crates/o3k-store/migrations_postgres/*.sql | wc -l)
sqlite_count=$(printf '%s\n' "$repo_root"/crates/o3k-store/migrations/*.sql | wc -l)
snapshot_bytes=$(stat -c %s "$sqlite_snapshot")
available=$(df -B1 --output=avail "$out_dir" | tail -1 | tr -d ' ')
[[ "$sqlite_check" == ok ]]
stage=cleanup
# Successful cleanup is part of the result, never a later best-effort promise.
cleanup
created=false
stage=publish_result
python3 - "$out_dir/result.json" "$source_head" "$source_tree" "$server_version" "$dump_version" "$restore_version" "$pg_count" "$pg_database_bytes" "$dump_bytes" "$dump_sha" "$toc_sha" "$sqlite_count" "$sqlite_source_bytes" "$snapshot_bytes" "$sqlite_check" "$available" <<'PYRESULT'
import json, os, sys
path = sys.argv[1]
keys = ["source_head", "source_tree", "postgres_server", "pg_dump", "pg_restore",
        "postgres_migration_files", "postgres_database_bytes", "pg_dump_bytes",
        "pg_dump_sha256", "pg_restore_list_sha256", "sqlite_migration_files",
        "sqlite_source_bytes", "sqlite_snapshot_bytes", "sqlite_integrity_check",
        "staging_available_bytes"]
value = dict(zip(keys, sys.argv[2:], strict=True))
for key in ["postgres_migration_files", "postgres_database_bytes", "pg_dump_bytes",
            "sqlite_migration_files", "sqlite_source_bytes", "sqlite_snapshot_bytes",
            "staging_available_bytes"]:
    value[key] = int(value[key])
value.update(schema="o3k.pp6.pg-size-measurement.v1", cleanup="passed",
             encrypted_outer_artifact="PENDING", production_backup_restore="ACCEPTANCE_PENDING",
             migration_ledger="NOT_RUN: direct SQL fixture excludes SQLx ledger")
with open(path + ".tmp", "x", encoding="utf-8") as stream:
    json.dump(value, stream, indent=2, sort_keys=True)
    stream.write("\n")
    stream.flush()
    os.fsync(stream.fileno())
os.replace(path + ".tmp", path)
PYRESULT
