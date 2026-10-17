#!/usr/bin/env bash
set -euo pipefail

# These checks deliberately inspect source instead of executing PP.5.  The
# process tests are real daemon/campaign probes and must not enter ordinary
# Cargo workspace discovery.
root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
evidence_test="$root_dir/bins/o3kd/tests/pp5_1035_evidence_process.rs"
delete_test="$root_dir/bins/o3kd/tests/pp5_interrupted_delete_process.rs"
focused_runner="$root_dir/scripts/run_pp5_1035_focus.sh"

# The other process tests in this directory are local temporary-SQLite and
# process-helper probes.  They do not provision external TestLab, guests, or
# providers; the three tests below are the explicit PP.5 process lanes.

grep -Fq '#[ignore = "explicit PP.5 #1035 invocation required"]' "$evidence_test"
test "$(grep -Fc '#[ignore = "explicit PP.5 #1035 invocation required"]' "$evidence_test")" -eq 2
grep -Fq '#[ignore = "explicit PP.5 interrupted-delete invocation required"]' "$delete_test"
expected_runner='cargo test -p o3kd --test pp5_1035_evidence_process --all-features pp5_1035_restart_writes_fail_closed_evidence -- --ignored --nocapture'
grep -Fq "$expected_runner" "$focused_runner"
grep -Fq 'O3K_PP5_1035_EXPLICIT_AUTH=RUN_OWNED_SQLITE_LOCALHOST_1035' "$focused_runner"
grep -Fq 'env -u O3K_DATABASE_URL -u O3K_DATABASE_BACKEND -u O3K_TEST_DATABASE_PURPOSE' "$focused_runner"
grep -Fq 'O3K_PP5_1035_RUNNER_MARKER=RUN_OWNED_SQLITE_LOCALHOST_1035' "$focused_runner"
grep -Fq 'cargo >/dev/null 2>&1' "$focused_runner"
grep -Fq 'python3 >/dev/null 2>&1' "$focused_runner"
grep -Fq 'uname -s' "$focused_runner"
grep -Fq 'command -v ss' "$focused_runner"
grep -Fq 'source SHA must equal HEAD' "$focused_runner"
grep -Fq 'worktree must be clean' "$focused_runner"
grep -Fq 'run-owned SQLite/localhost' "$focused_runner"
grep -Fq 'PP.5 #1035 runner marker is required' "$evidence_test"
grep -Fq 'PP.5 runner marker is required' "$delete_test"
test "$(grep -Fc 'O3K_PP5_1035_RUNNER_MARKER' "$evidence_test")" -eq 2
test "$(grep -Fc 'O3K_PP5_1035_RUNNER_MARKER' "$delete_test")" -eq 1

# Every ignored body must check the runner marker before its first setup call.
evidence_body=$(grep -n 'async fn pp5_1035_restart_writes_fail_closed_evidence' "$evidence_test" | cut -d: -f1)
evidence_setup=$(grep -n 'let run_id' "$evidence_test" | tail -1 | cut -d: -f1)
test "$evidence_body" -lt "$evidence_setup"
delete_body=$(grep -n 'async fn fault_pause_interrupted_delete_orphan_is_repaired_and_reuse_is_restored' "$delete_test" | cut -d: -f1)
delete_setup=$(grep -n 'let root = std::env::temp_dir' "$delete_test" | cut -d: -f1)
test "$delete_body" -lt "$delete_setup"

# Direct ignored execution is fail-closed at each test body's first line when
# the runner-issued marker is absent. Keep these exact and marker-free: they
# must not reach any campaign fixture or external resource setup.
run_unmarked_guard() {
    local test_name=$1
    local expected=$2
    local test_target=$3
    local output
    if output=$(env -u O3K_PP5_1035_RUNNER_MARKER \
        cargo test -p o3kd --test "$test_target" --all-features "$test_name" -- --ignored --exact 2>&1); then
        echo "unmarked PP.5 test unexpectedly succeeded: $test_name" >&2
        exit 1
    fi
    grep -Fq "$expected" <<<"$output"
}
run_unmarked_guard \
    pp5_1035_restart_writes_fail_closed_evidence \
    'PP.5 #1035 runner marker is required' \
    pp5_1035_evidence_process
run_unmarked_guard \
    pp5_1035_postgres_restart_takes_over_lease_and_reconstructs_endpoint \
    'PP.5 #1035 runner marker is required' \
    pp5_1035_evidence_process
run_unmarked_guard \
    fault_pause_interrupted_delete_orphan_is_repaired_and_reuse_is_restored \
    'PP.5 runner marker is required' \
    pp5_interrupted_delete_process

if grep -Fq -- '--all-features -- --ignored' "$focused_runner"; then
    echo "focused PP.5 runner must select an exact test before --ignored" >&2
    exit 1
fi

# A missing authorization must fail before Cargo or artifact setup.  A fake
# cargo in PATH proves the negative invocation never reaches the tool.
sentinel_dir=$(mktemp -d "${TMPDIR:-/tmp}/o3k-pp5-isolation.XXXXXX")
trap 'rm -rf "$sentinel_dir"' EXIT
cat >"$sentinel_dir/cargo" <<'EOF'
#!/usr/bin/env bash
echo "cargo was reached without explicit authorization" >&2
exit 99
EOF
chmod +x "$sentinel_dir/cargo"
if PATH="$sentinel_dir:$PATH" O3K_PP5_1035_EXPLICIT_AUTH= bash "$focused_runner" >/dev/null 2>"$sentinel_dir/error"; then
    echo "unauthorized PP.5 runner unexpectedly succeeded" >&2
    exit 1
fi
grep -Fq 'set O3K_PP5_1035_EXPLICIT_AUTH=RUN_OWNED_SQLITE_LOCALHOST_1035' "$sentinel_dir/error"
if grep -Fq 'cargo was reached' "$sentinel_dir/error"; then
    echo "unauthorized PP.5 runner reached Cargo" >&2
    exit 1
fi

# A mismatched source revision fails before artifact setup or Cargo.
if PATH="$sentinel_dir:$PATH" \
    O3K_PP5_1035_EXPLICIT_AUTH=RUN_OWNED_SQLITE_LOCALHOST_1035 \
    bash "$focused_runner" 0000000000000000000000000000000000000000 \
    >/dev/null 2>"$sentinel_dir/mismatch-error"; then
    echo "mismatched-source PP.5 runner unexpectedly succeeded" >&2
    exit 1
fi
grep -Fq 'source SHA must equal HEAD' "$sentinel_dir/mismatch-error"
if grep -Fq 'cargo was reached' "$sentinel_dir/mismatch-error"; then
    echo "mismatched-source PP.5 runner reached Cargo" >&2
    exit 1
fi

# Cargo's listing mode performs test selection without running test bodies.
selection=$(cargo test -p o3kd --test pp5_1035_evidence_process --all-features \
    pp5_1035_restart_writes_fail_closed_evidence -- --ignored --list)
grep -Fq 'pp5_1035_restart_writes_fail_closed_evidence: test' <<<"$selection"
if grep -Fq 'pp5_1035_postgres_restart_takes_over_lease_and_reconstructs_endpoint' <<<"$selection"; then
    echo "focused selection unexpectedly includes PostgreSQL PP.5 test" >&2
    exit 1
fi

# Ordinary Cargo execution must discover the exact test as ignored and execute
# zero test bodies. The explicit --ignored listing above proves authorized
# selection remains available.
default_run=$(cargo test -p o3kd --test pp5_1035_evidence_process --all-features \
    pp5_1035_restart_writes_fail_closed_evidence -- --exact)
grep -Fq 'pp5_1035_restart_writes_fail_closed_evidence ... ignored' <<<"$default_run"
grep -Fq '0 passed; 0 failed; 1 ignored' <<<"$default_run"

# The focused runner must opt in to the ignored process tests; ordinary Cargo
# discovery has no such opt-in.
if grep -Fq -- '--ignored' "$evidence_test" "$delete_test"; then
    echo "PP.5 test sources must not opt themselves back into ignored execution" >&2
    exit 1
fi

echo "PP.5 ordinary-test isolation guards passed"
