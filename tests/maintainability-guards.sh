#!/usr/bin/env bash
# Permanent regression test for the final architecture guard.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GUARD="$REPO_ROOT/scripts/check-maintainability-guards.py"
PASS=0
FAIL=0
ERRORS=""
CLEANUP_FILES=()

cleanup() {
    for file in "${CLEANUP_FILES[@]}"; do
        rm -f -- "$file"
    done
    rmdir "$REPO_ROOT/tests/z_guard_fixtures" 2>/dev/null || true
}
trap cleanup EXIT

check_fixture() {
    local name="$1" expected_exit="$2" expected_pattern="$3"
    local fixture="$4" fixture_dir="$5" fixture_name="${6:-z_guard_test_fixture.rs}"
    local fixture_path="$REPO_ROOT/$fixture_dir/$fixture_name"

    printf '%s\n' "$fixture" > "$fixture_path"
    CLEANUP_FILES+=("$fixture_path")
    local rc=0 output
    output=$(python3 "$GUARD" 2>&1) || rc=$?

    if [ "$expected_exit" -eq 0 ] && [ "$rc" -eq 0 ]; then
        echo "  PASS: $name"
        PASS=$((PASS + 1))
    elif [ "$expected_exit" -ne 0 ] && [ "$rc" -ne 0 ] && \
         echo "$output" | grep -qF "$expected_pattern"; then
        echo "  PASS: $name"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $name (expected exit $expected_exit, got $rc)"
        echo "    guard output: $(echo "$output" | tail -10)"
        FAIL=$((FAIL + 1))
        ERRORS+="  - $name: expected exit $expected_exit, got $rc\n"
    fi
    rm -f -- "$fixture_path"
}

echo "=== Maintainability Guard Regression Suite ==="
echo
echo "Test 0: maintainability inventory cfg(test) scope regression -> PASS"
python3 "$REPO_ROOT/tests/maintainability-inventory.py"
PASS=$((PASS + 1))

echo "Test 1: clean repository and approved boundaries -> PASS"
rc=0
output=$(python3 "$GUARD" 2>&1) || rc=$?
if [ "$rc" -eq 0 ]; then
    echo "  PASS: clean repository"
    PASS=$((PASS + 1))
else
    echo "  FAIL: clean repository (got $rc)"
    echo "    guard output: $(echo "$output" | tail -10)"
    FAIL=$((FAIL + 1))
    ERRORS+="  - clean repository: expected exit 0, got $rc\n"
fi

echo "Test 2: SQL in store/domain -> FAIL"
check_fixture "SQL in store/domain" 1 "SQL ARCHITECTURE VIOLATION" \
    'pub fn z_query() { sqlx::query("SELECT 1"); }' "crates/o3k-store/src/domain"
echo "Test 3: SQL in store/port -> FAIL"
check_fixture "SQL in store/port" 1 "SQL ARCHITECTURE VIOLATION" \
    'pub fn z_query() { sqlx::query("SELECT 1"); }' "crates/o3k-store/src/port"
echo "Test 4: SQL in store/unified -> FAIL"
check_fixture "SQL in store/unified" 1 "SQL ARCHITECTURE VIOLATION" \
    'pub fn z_query() { sqlx::query("SELECT 1"); }' "crates/o3k-store/src/unified"
echo "Test 5: SQL in o3kd composition -> FAIL"
check_fixture "SQL in o3kd composition" 1 "SQL ARCHITECTURE VIOLATION" \
    'pub fn z_query() { sqlx::query("SELECT 1"); }' "bins/o3kd/src/composition"
echo "Test 6: SQL in Network application -> FAIL"
check_fixture "SQL in Network application" 1 "SQL ARCHITECTURE VIOLATION" \
    'pub fn z_query() { sqlx::query("SELECT 1"); }' "crates/o3k-network/src"
echo "Test 7: SQL in Compute runtime -> FAIL"
check_fixture "SQL in Compute runtime" 1 "SQL ARCHITECTURE VIOLATION" \
    'pub fn z_query() { sqlx::query("SELECT 1"); }' "bins/o3k-compute/src"

echo "Test 8: imported SQL query -> FAIL"
check_fixture "imported SQL query" 1 "SQL ARCHITECTURE VIOLATION" \
    $'use sqlx::query;\nfn z_query() { query("SELECT 1"); }' "crates/o3k-kernel/src"
echo "Test 9: aliased SQL query -> FAIL"
check_fixture "aliased SQL query" 1 "SQL ARCHITECTURE VIOLATION" \
    $'use sqlx::query as q;\nfn z_query() { q("SELECT 1"); }' "crates/o3k-kernel/src"
echo "Test 10: grouped SQL imports -> FAIL"
check_fixture "grouped SQL imports" 1 "SQL ARCHITECTURE VIOLATION" \
    $'use sqlx::{query, query_as, query_scalar};\nfn z_query() { query("SELECT 1"); }' "crates/o3k-kernel/src"
echo "Test 11: grouped aliased SQL imports -> FAIL"
check_fixture "grouped aliased SQL imports" 1 "SQL ARCHITECTURE VIOLATION" \
    $'use sqlx::{query as q, query_as as qa};\nfn z_query() { q("SELECT 1"); }' "crates/o3k-kernel/src"

echo "Test 12: multiline grouped SQL imports -> FAIL"
check_fixture "multiline grouped SQL imports" 1 "SQL ARCHITECTURE VIOLATION" \
    $'use sqlx::{\n    query,\n    query_as,\n};\nfn z_query() { query("SELECT 1"); }' "crates/o3k-kernel/src"

echo "Test 12a: extended SQLx query APIs -> FAIL"
check_fixture "extended SQLx query APIs" 1 "SQL ARCHITECTURE VIOLATION" \
    $'fn z_query() {\n    sqlx::query_with("SELECT 1", ());\n    sqlx::query_as_with("SELECT 1", ());\n    sqlx::query_scalar_with("SELECT 1", ());\n    sqlx::raw_sql("DELETE FROM t");\n    let _builder = sqlx::QueryBuilder::new("SELECT 1");\n}' "crates/o3k-kernel/src"
echo "Test 12b: SQLx file and unchecked macros -> FAIL"
check_fixture "SQLx file and unchecked macros" 1 "SQL ARCHITECTURE VIOLATION" \
    $'fn z_query() {\n    sqlx::query_unchecked!("SELECT 1");\n    sqlx::query_file!("query.sql");\n    sqlx::query_file_unchecked!("query.sql");\n    sqlx::query_file_as!("query.sql");\n    sqlx::query_file_scalar_unchecked!("query.sql");\n}' "crates/o3k-kernel/src"
echo "Test 12c: extended grouped SQLx imports -> FAIL"
check_fixture "extended grouped SQLx imports" 1 "SQL ARCHITECTURE VIOLATION" \
    $'use sqlx::{query_with, query_as_with, query_scalar_with, raw_sql, QueryBuilder};\nfn z_query() { query_with("SELECT 1", ()); }' "crates/o3k-kernel/src"
echo "Test 12d: extended aliased SQLx imports -> FAIL"
check_fixture "extended aliased SQLx imports" 1 "SQL ARCHITECTURE VIOLATION" \
    $'use sqlx::raw_sql as execute_raw;\nuse sqlx::QueryBuilder as Builder;\nfn z_query() { execute_raw("DELETE FROM t"); let _ = Builder::new("SELECT 1"); }' "crates/o3k-kernel/src"
echo "Test 12e: SQLx Executor import and alias -> FAIL"
check_fixture "SQLx Executor import and alias" 1 "SQL ARCHITECTURE VIOLATION" \
    $'use sqlx::Executor as DbExecutor;\nasync fn z_query(pool: &sqlx::PgPool) { pool.execute("DELETE FROM t").await.unwrap(); }' "crates/o3k-kernel/src"
echo "Test 12f: SQLx prelude Executor imports -> FAIL"
check_fixture "SQLx prelude Executor imports" 1 "SQL ARCHITECTURE VIOLATION" \
    $'use sqlx::prelude::Executor;\nuse sqlx::prelude::Executor as DbExecutor;\nfn z_query() { let _ = std::marker::PhantomData::<DbExecutor>; }' "crates/o3k-kernel/src"
echo "Test 12g: grouped SQLx Executor imports -> FAIL"
check_fixture "grouped SQLx Executor imports" 1 "SQL ARCHITECTURE VIOLATION" \
    $'use sqlx::{Executor, Execute, AnyExecutor, Row};\nfn z_query() { sqlx::Executor::execute; }' "crates/o3k-kernel/src"
echo "Test 12h: SQLx prelude wildcard -> FAIL"
check_fixture "SQLx prelude wildcard" 1 "SQL ARCHITECTURE VIOLATION" \
    'use sqlx::prelude::*;' "crates/o3k-kernel/src"
echo "Test 12i: SQLx wildcard -> FAIL"
check_fixture "SQLx wildcard" 1 "SQL ARCHITECTURE VIOLATION" \
    'use sqlx::*;' "crates/o3k-kernel/src"
echo "Test 12j: nested QueryBuilder path and alias -> FAIL"
check_fixture "nested QueryBuilder path and alias" 1 "SQL ARCHITECTURE VIOLATION" \
    $'use sqlx::query_builder::QueryBuilder as Builder;\nfn z_query() { let _ = sqlx::query_builder::QueryBuilder::new("DELETE FROM t"); let _ = Builder::new("SELECT 1"); }' "crates/o3k-kernel/src"

echo "Test 13: SQL path-prefix collision -> FAIL"
check_fixture "SQL path-prefix collision" 1 "SQL ARCHITECTURE VIOLATION" \
    'pub fn z_query() { sqlx::query("SELECT 1"); }' "crates/o3k-store/src" "postgres-extra.rs"

echo "Test 14: forbidden architecture paths are not approved -> PASS"
python3 - "$GUARD" <<'PY'
import runpy
import sys

policy = runpy.run_path(sys.argv[1])
path_is_or_below = policy["_path_is_or_below"]
sql_paths = policy["APPROVED_SQL_PATHS"]
host_paths = policy["APPROVED_HOST_EXECUTION_PATHS"]

for path in (
    "bins/o3kd/src/main.rs",
    "bins/o3kd/src/composition/mod.rs",
    "bins/o3kd/src/composition/compute.rs",
    "crates/o3k-store/src/domain/records.rs",
    "crates/o3k-store/src/port/durable.rs",
    "crates/o3k-store/src/unified/mod.rs",
):
    assert not any(path_is_or_below(path, allowed) for allowed in sql_paths), path

for path in (
    "bins/o3kd/src/main.rs",
    "bins/o3kd/src/composition/mod.rs",
    "bins/o3kd/src/composition/compute.rs",
    "bins/o3k-compute/src/main.rs",
    "bins/o3k-compute/src/runtime.rs",
    "crates/o3k-network/src/gateway.rs",
    "crates/o3k-network/src/public.rs",
    "crates/o3k-network/src/canonical_policy.rs",
):
    assert not any(path_is_or_below(path, allowed) for allowed in host_paths), path

assert not any(path_is_or_below("crates/o3k-image/src/lib.rs", allowed) for allowed in host_paths)
assert any(path_is_or_below("crates/o3k-image/src/execution.rs", allowed) for allowed in host_paths)
print("  PASS: forbidden architecture paths remain unapproved")
PY

echo "Test 15: multiline std grouped Command import -> FAIL"
check_fixture "multiline std grouped Command import" 1 "HOST EXECUTION ARCHITECTURE VIOLATION" \
    $'use std::process::{\n    Command as HostCommand,\n    Stdio,\n};\npub fn z_run() { let _x = HostCommand::new("ls"); }' "crates/o3k-kernel/src"
echo "Test 16: multiline tokio grouped Command import -> FAIL"
check_fixture "multiline tokio grouped Command import" 1 "HOST EXECUTION ARCHITECTURE VIOLATION" \
    $'use tokio::process::{\n    Command as HostCommand,\n    Stdio,\n};\npub fn z_run() { let _x = HostCommand::new("ls"); }' "crates/o3k-kernel/src"
echo "Test 17: imported bare Command::new -> FAIL"
check_fixture "bare Command::new" 1 "HOST EXECUTION ARCHITECTURE VIOLATION" \
    $'use std::process::Command;\npub fn z_run() { let _x = Command::new("ls"); }' "crates/o3k-kernel/src"
echo "Test 18: std Command alias import -> FAIL"
check_fixture "std Command alias import" 1 "HOST EXECUTION ARCHITECTURE VIOLATION" \
    $'use std::process::Command as HostCommand;\npub fn z_run() { let _x = HostCommand::new("ls"); }' "crates/o3k-kernel/src"
echo "Test 19: std grouped Command alias import -> FAIL"
check_fixture "std grouped Command alias import" 1 "HOST EXECUTION ARCHITECTURE VIOLATION" \
    $'use std::process::{Command as HostCommand, Stdio};\npub fn z_run() { let _x = HostCommand::new("ls"); }' "crates/o3k-kernel/src"
echo "Test 20: std Command type alias -> FAIL"
check_fixture "std Command type alias" 1 "HOST EXECUTION ARCHITECTURE VIOLATION" \
    'type HostCommand = std::process::Command; pub fn z_run() { let _x = HostCommand::new("ls"); }' "crates/o3k-kernel/src"
echo "Test 21: tokio Command alias import -> FAIL"
check_fixture "tokio Command alias import" 1 "HOST EXECUTION ARCHITECTURE VIOLATION" \
    $'use tokio::process::Command as HostCommand;\npub fn z_run() { let _x = HostCommand::new("ls"); }' "crates/o3k-kernel/src"
echo "Test 22: tokio grouped Command alias import -> FAIL"
check_fixture "tokio grouped Command alias import" 1 "HOST EXECUTION ARCHITECTURE VIOLATION" \
    $'use tokio::process::{Command as HostCommand, Stdio};\npub fn z_run() { let _x = HostCommand::new("ls"); }' "crates/o3k-kernel/src"
echo "Test 23: fully qualified Command::new -> FAIL"
check_fixture "fully qualified Command::new" 1 "HOST EXECUTION ARCHITECTURE VIOLATION" \
    'pub fn z_run() { let _x = std::process::Command::new("ls"); }' "crates/o3k-kernel/src"
echo "Test 24: tokio qualified Command::new -> FAIL"
check_fixture "tokio qualified Command::new" 1 "HOST EXECUTION ARCHITECTURE VIOLATION" \
    'pub fn z_run() { let _x = tokio::process::Command::new("ls"); }' "crates/o3k-kernel/src"
echo "Test 25: Command::new after #[cfg(test)] -> FAIL"
check_fixture "Command after cfg(test)" 1 "HOST EXECUTION ARCHITECTURE VIOLATION" \
    $'#[cfg(test)] mod tests {}\nfn production_after_tests() { let _ = Command::new("ls"); }' "crates/o3k-kernel/src"
echo "Test 26: SQL after #[cfg(test)] -> FAIL"
check_fixture "SQL after cfg(test)" 1 "SQL ARCHITECTURE VIOLATION" \
    $'#[cfg(test)] mod tests {}\nfn production_after_tests() { sqlx::query("SELECT 1"); }' "crates/o3k-kernel/src"

echo "Test 26a: SQL inside cfg(test) module -> ACCEPT"
check_fixture "SQL inside cfg(test) module" 0 "" \
    $'#[cfg(test)]\nmod tests {\n    fn test_query() { sqlx::query("SELECT 1"); }\n}' "crates/o3k-kernel/src"
echo "Test 26b: Command inside cfg(test) module -> ACCEPT"
check_fixture "Command inside cfg(test) module" 0 "" \
    $'#[cfg(test)]\nmod tests {\n    use std::process::Command;\n    fn test_command() { let _ = Command::new("sleep"); }\n}' "crates/o3k-kernel/src"

echo "Test 27: raw Linux wrapper in canonical Network -> FAIL"
check_fixture "raw Linux wrapper in canonical Network" 1 "HOST EXECUTION ARCHITECTURE VIOLATION" \
    'pub fn z_run() { run("ip", &["link"]); }' "crates/o3k-network/src"
echo "Test 28: host command in o3kd composition -> FAIL"
check_fixture "host command in o3kd composition" 1 "HOST EXECUTION ARCHITECTURE VIOLATION" \
    'pub fn z_run() { let _ = Command::new("ip"); }' "bins/o3kd/src/composition"
echo "Test 29: host command in Compute binary source -> FAIL"
check_fixture "host command in Compute binary source" 1 "HOST EXECUTION ARCHITECTURE VIOLATION" \
    'pub fn z_run() { let _ = Command::new("ip"); }' "bins/o3k-compute/src"
echo "Test 30: shell execution -> FAIL"
check_fixture "shell execution" 1 "HOST EXECUTION ARCHITECTURE VIOLATION" \
    'pub fn z_run() { let _ = Command::new("sh").arg("-c").arg("true"); }' "crates/o3k-kernel/src"

echo "Test 31: approved SQLite persistence -> ACCEPT"
check_fixture "approved SQLite persistence" 0 "" \
    'pub fn z_query() { sqlx::query("SELECT 1"); }' "crates/o3k-store/src/sqlite"
echo "Test 32: approved PostgreSQL persistence -> ACCEPT"
check_fixture "approved PostgreSQL persistence" 0 "" \
    'pub fn z_query() { sqlx::query("SELECT 1"); }' "crates/o3k-store/src/postgres"
echo "Test 32a: approved PostgreSQL execution capabilities -> ACCEPT"
check_fixture "approved PostgreSQL execution capabilities" 0 "" \
    $'use sqlx::Executor;\nfn z_query() { let _ = sqlx::query_builder::QueryBuilder::new("SELECT 1"); }' "crates/o3k-store/src/postgres"
echo "Test 33: approved Linux Network execution -> ACCEPT"
check_fixture "approved Linux Network execution" 0 "" \
    'pub fn z_run() { let _ = std::process::Command::new("ip"); }' "crates/o3k-network/src/linux_fabric"
echo "Test 33a: shell alias remains forbidden in approved execution -> FAIL"
check_fixture "shell alias in approved execution" 1 "HOST EXECUTION ARCHITECTURE VIOLATION" \
    $'use std::process::Command as HostCommand;\npub fn z_run() { let _ = HostCommand::new("sh").arg("-c"); }' "crates/o3k-network/src/linux_fabric"

echo "Test 34: test-only file -> ACCEPT"
TEST_FIXTURE_DIR="$REPO_ROOT/tests/z_guard_fixtures"
mkdir -p "$TEST_FIXTURE_DIR"
TEST_FIXTURE="$TEST_FIXTURE_DIR/test_guard_ok.rs"
CLEANUP_FILES+=("$TEST_FIXTURE")
printf '%s\n' 'pub fn z_query() { sqlx::query("SELECT 1"); }' > "$TEST_FIXTURE"
rc=0
output=$(python3 "$GUARD" 2>&1) || rc=$?
if [ "$rc" -eq 0 ]; then
    echo "  PASS: test-only file ignored"
    PASS=$((PASS + 1))
else
    echo "  FAIL: test-only file caused violation"
    echo "    guard output: $(echo "$output" | tail -5)"
    FAIL=$((FAIL + 1))
    ERRORS+="  - test-only file: unexpected violation\n"
fi
rm -f -- "$TEST_FIXTURE"
rmdir "$TEST_FIXTURE_DIR" 2>/dev/null || true

echo "Test 35: dependency cycle -> SKIP (requires isolated Cargo.toml fixture)"
echo "Test 36: weakened safety policy -> SKIP (requires isolated Cargo.toml fixture)"
echo
echo "=== Results ==="
echo "  PASS: $PASS"
echo "  FAIL: $FAIL"
if [ -n "$ERRORS" ]; then
    echo "  Errors:"
    echo -e "$ERRORS"
    exit 1
fi
echo "  All regression tests passed."
