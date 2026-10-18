#!/usr/bin/env bash
# Real PostgreSQL 16 catalog/grant prototype. Runs only in a disposable
# pg_virtualenv cluster; no shared PostgreSQL service is modified.
set -euo pipefail

if [[ "${PP6_PG16_CATALOG_INNER:-0}" != 1 ]]; then
    exec env PP6_PG16_CATALOG_INNER=1 pg_virtualenv "$0"
fi

if [[ "${PGVERSION:-}" != 16 ]]; then
    printf 'expected PostgreSQL 16, got %s\n' "${PGVERSION:-unset}" >&2
    exit 1
fi

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
db="o3k_pp6_catalog_$$"
createdb "$db"
cleanup() { dropdb --if-exists "$db" >/dev/null; }
trap cleanup EXIT INT TERM

for migration in "$repo_root"/crates/o3k-store/migrations_postgres/*.sql; do
    psql -X -q -v ON_ERROR_STOP=1 -d "$db" -f "$migration" >/dev/null
done

psql -X -q -v ON_ERROR_STOP=1 -d "$db" <<'SQL'
CREATE ROLE o3k_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE o3k_backup_dump NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE o3k_restore_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;
DO $$ BEGIN
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO o3k_runtime', current_database());
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO o3k_backup_dump', current_database());
END $$;
GRANT USAGE ON SCHEMA public TO o3k_runtime, o3k_backup_dump;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO o3k_runtime;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO o3k_backup_dump;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO o3k_runtime;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO o3k_backup_dump;
SQL

counts="$(psql -X -qAt -F '|' -d "$db" -c "SELECT
  (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p')),
  (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='v'),
  (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='S'),
  (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.prokind IN ('f','p')),
  (SELECT count(*) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND NOT t.tgisinternal),
  (SELECT count(*) FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace WHERE n.nspname='public')")"
[[ "$counts" == '77|0|0|2|2|0' ]] || { printf 'unexpected PostgreSQL 16 object counts: %s\n' "$counts" >&2; exit 1; }

function_names="$(psql -X -qAt -d "$db" -c "SELECT string_agg(p.proname, ',' ORDER BY p.proname) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.prokind='f'")"
[[ "$function_names" == 'o3k_delete_generic_resource_operations,o3k_validate_operation_resource_reference' ]] || { printf 'unexpected functions: %s\n' "$function_names" >&2; exit 1; }

trigger_names="$(psql -X -qAt -d "$db" -c "SELECT string_agg(t.tgname, ',' ORDER BY t.tgname) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND NOT t.tgisinternal")"
[[ "$trigger_names" == 'operations_validate_resource_reference,resources_delete_generic_operations' ]] || { printf 'unexpected triggers: %s\n' "$trigger_names" >&2; exit 1; }

role_policy="$(psql -X -qAt -F '|' -d "$db" -c "SELECT bool_and(NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls AND NOT rolinherit) FROM pg_roles WHERE rolname IN ('o3k_runtime','o3k_backup_dump','o3k_restore_owner')")"
[[ "$role_policy" == 't' ]] || { printf 'role attributes violate PP6 policy\n' >&2; exit 1; }

role_modes="$(psql -X -qAt -F '|' -d "$db" -c "SELECT
  (SELECT rolcanlogin FROM pg_roles WHERE rolname='o3k_runtime'),
  (SELECT NOT rolcanlogin FROM pg_roles WHERE rolname='o3k_backup_dump'),
  (SELECT NOT rolcanlogin FROM pg_roles WHERE rolname='o3k_restore_owner'),
  NOT EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member WHERE r.rolname IN ('o3k_runtime','o3k_backup_dump','o3k_restore_owner'))")"
[[ "$role_modes" == 't|t|t|t' ]] || { printf 'role login or membership policy violation: %s\n' "$role_modes" >&2; exit 1; }

function_policy="$(psql -X -qAt -F '|' -d "$db" -c "SELECT bool_and(NOT p.prosecdef AND p.prokind='f') FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public'")"
[[ "$function_policy" == 't' ]] || { printf 'callable object policy violation\n' >&2; exit 1; }

privileges="$(psql -X -qAt -F '|' -d "$db" -c "SELECT
  has_table_privilege('o3k_runtime','public.resources','SELECT,INSERT,UPDATE,DELETE'),
  has_table_privilege('o3k_backup_dump','public.resources','SELECT'),
  has_table_privilege('o3k_backup_dump','public.resources','INSERT'),
  has_schema_privilege('o3k_runtime','public','CREATE'),
  has_function_privilege('o3k_runtime','public.o3k_validate_operation_resource_reference()','EXECUTE'),
  has_function_privilege('o3k_backup_dump','public.o3k_validate_operation_resource_reference()','EXECUTE'),
  (SELECT bool_and(has_table_privilege('o3k_runtime',format('%I.%I',n.nspname,c.relname),'SELECT,INSERT,UPDATE,DELETE')) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p')),
  (SELECT bool_and(has_table_privilege('o3k_backup_dump',format('%I.%I',n.nspname,c.relname),'SELECT') AND NOT has_table_privilege('o3k_backup_dump',format('%I.%I',n.nspname,c.relname),'INSERT,UPDATE,DELETE')) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p'))")"
[[ "$privileges" == 't|t|f|f|f|f|t|t' ]] || { printf 'grant matrix violation: %s\n' "$privileges" >&2; exit 1; }

printf 'PostgreSQL 16 migration catalog/grant prototype PASS: tables=77 views=0 sequences=0 functions=2 triggers=2 extensions=0\n'
printf 'Migration-created functions: %s\n' "$function_names"
printf 'Migration-created triggers: %s\n' "$trigger_names"
printf 'Role flags/login/membership, callable-object security, and per-table grant matrix verified.\n'
