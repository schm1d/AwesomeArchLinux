#!/usr/bin/env bash
# Master pure-Bash test runner: syntax-checks every .sh script in the repo
# and runs all regression test suites under tests/.

set -euo pipefail

TESTS_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$TESTS_DIR/.." && pwd)"

printf '=== 1. Bash Syntax Check (all repository .sh scripts) ===\n'
script_count=0
while IFS= read -r -d '' script; do
    bash -n "$script"
    (( ++script_count ))
done < <(find "$REPO_ROOT" -not -path '*/.*' -name '*.sh' -type f -print0 | sort -z)
printf '  [PASS] All %d .sh scripts passed bash -n\n\n' "$script_count"

printf '=== 2. Pure-Bash Requirement Check ===\n'
py_files="$(find "$REPO_ROOT" -not -path '*/.*' -name '*.py' -type f || true)"
if [[ -n "$py_files" ]]; then
    printf '  [FAIL] Non-Bash Python files remain:\n%s\n' "$py_files" >&2
    exit 1
fi
printf '  [PASS] Zero .py files in repository\n\n'

printf '=== 3. Regression Test Suites ===\n'
failed_suites=0
for suite in \
    "$TESTS_DIR/test_board_health.sh" \
    "$TESTS_DIR/test_nvme_stability.sh" \
    "$TESTS_DIR/test_gpu_unlock.sh" \
    "$TESTS_DIR/test_brave_and_regressions.sh" \
    "$TESTS_DIR/test_hardening_regressions.sh" \
    "$TESTS_DIR/test_chroot_security.sh" \
    "$TESTS_DIR/test_high_severity.sh" \
    "$TESTS_DIR/test_medium_severity.sh"; do
    printf '\n--- Running %s ---\n' "${suite##*/}"
    if ! bash "$suite"; then
        (( ++failed_suites ))
    fi
done

printf '\n=========================================\n'
if (( failed_suites > 0 )); then
    printf 'FAILED: %d test suite(s) reported failures.\n' "$failed_suites" >&2
    exit 1
fi
printf 'SUCCESS: All Bash syntax checks and regression suites passed!\n'
