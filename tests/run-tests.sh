#!/usr/bin/env bash
# Master pure-Bash test runner: syntax-checks every .sh script in the repo
# and runs all regression test suites under tests/.

set -euo pipefail

TESTS_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$TESTS_DIR/.." && pwd)"

# List repository files matching a name pattern, NUL-separated. Hidden entries
# inside the repository (.git, editor and tool state) are pruned by name; the
# path of the checkout itself is not part of the match, so a clone below a
# dot-directory (~/.local/src/..., .worktrees/x) is still scanned.
repo_files() {
    find "$REPO_ROOT" -mindepth 1 -name '.*' -prune -o -name "$1" -type f -print0 | sort -z
}

printf '=== 1. Bash Syntax Check (all repository .sh scripts) ===\n'
script_count=0
while IFS= read -r -d '' script; do
    bash -n "$script"
    (( ++script_count ))
done < <(repo_files '*.sh')
if (( script_count == 0 )); then
    printf '  [FAIL] No .sh scripts found under %s: nothing was checked\n' "$REPO_ROOT" >&2
    exit 1
fi
printf '  [PASS] All %d .sh scripts passed bash -n\n\n' "$script_count"

printf '=== 2. Pure-Bash Requirement Check ===\n'
py_files="$(repo_files '*.py' | tr '\0' '\n')"
if [[ -n "$py_files" ]]; then
    printf '  [FAIL] Non-Bash Python files remain:\n%s\n' "$py_files" >&2
    exit 1
fi
printf '  [PASS] Zero .py files in repository\n\n'

printf '=== 3. Regression Test Suites ===\n'
# Every tests/test_*.sh is a suite: a new file runs without being listed here.
suites=("$TESTS_DIR"/test_*.sh)
if [[ ! -f "${suites[0]}" ]]; then
    printf '  [FAIL] No test suites (test_*.sh) found in %s\n' "$TESTS_DIR" >&2
    exit 1
fi

failed_suites=0
for suite in "${suites[@]}"; do
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
printf 'SUCCESS: All Bash syntax checks and %d regression suites passed!\n' "${#suites[@]}"
