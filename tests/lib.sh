#!/usr/bin/env bash
# Shared assertion and fixture helpers for the pure-Bash test suite.

set -euo pipefail

TESTS_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$TESTS_DIR/.." && pwd)"
export TESTS_DIR REPO_ROOT

TEST_PASS=0
TEST_FAIL=0
TEST_SKIP=0

fail() {
    printf '  [FAIL] %s\n' "$*" >&2
    return 1
}

assert_eq() {
    local actual="$1"
    local expected="$2"
    local msg="${3:-expected equality}"
    if [[ "$actual" != "$expected" ]]; then
        printf '  [FAIL] %s\n    expected: %q\n    actual:   %q\n' "$msg" "$expected" "$actual" >&2
        return 1
    fi
}

assert_ne() {
    local actual="$1"
    local unexpected="$2"
    local msg="${3:-expected values to differ}"
    if [[ "$actual" == "$unexpected" ]]; then
        printf '  [FAIL] %s (got %q)\n' "$msg" "$actual" >&2
        return 1
    fi
}

assert_contains() {
    local haystack="$1"
    local needle="$2"
    local msg="${3:-expected substring '$needle'}"
    if [[ "$haystack" != *"$needle"* ]]; then
        printf '  [FAIL] %s\n    missing: %q\n    in:      %q\n' "$msg" "$needle" "${haystack:0:400}" >&2
        return 1
    fi
}

assert_not_contains() {
    local haystack="$1"
    local needle="$2"
    local msg="${3:-unexpected substring '$needle'}"
    if [[ "$haystack" == *"$needle"* ]]; then
        printf '  [FAIL] %s\n    found: %q\n    in:    %q\n' "$msg" "$needle" "${haystack:0:400}" >&2
        return 1
    fi
}

assert_file_mode() {
    local path="$1"
    local expected="$2"
    local actual
    actual="$(stat -c '%a' -- "$path")"
    assert_eq "$actual" "$expected" "mode of $path"
}

# Print a script without its comment-only lines, for assertions about what the
# script does: a string that only survives in a comment must not satisfy
# assert_contains, and a missing, renamed or emptied script must not satisfy
# assert_not_contains. Assign the result first (code="$(script_code FILE)"):
# errexit ignores a failing command substitution inside an argument list.
script_code() {
    local path="$1" code
    [[ -f "$path" ]] || { printf 'Script not found: %s\n' "$path" >&2; return 1; }
    code="$(grep -v '^[[:space:]]*#' -- "$path" || true)"
    [[ -n "${code//[[:space:]]/}" ]] || { printf 'Script has no code: %s\n' "$path" >&2; return 1; }
    printf '%s\n' "$code"
}

# Extract a top-level `name() { ... }` function definition from a repository script.
extract_shell_function() {
    local rel_path="$1"
    local fn_name="$2"
    local full_path="$REPO_ROOT/$rel_path"
    local extracted
    extracted="$(awk -v fn="$fn_name" '
        $0 == fn "() {" { in_fn = 1 }
        in_fn { print }
        in_fn && $0 == "}" { in_fn = 0; found = 1; exit }
        END { if (!found) exit 1 }
    ' "$full_path")" || {
        printf 'Function %s missing from %s\n' "$fn_name" "$rel_path" >&2
        return 1
    }
    printf '%s\n' "$extracted"
}

# A test that exits 77 is skipped (a tool it needs is missing). That is a
# convenience on a developer machine; in CI (CI=true, or TESTS_NO_SKIP=1) a
# skip would quietly stop checking something, so it counts as a failure there.
skips_are_failures() {
    [[ "${CI:-}" == "true" || "${TESTS_NO_SKIP:-0}" == "1" ]]
}

run_test() {
    local name="$1"
    local fn="$2"
    local out="" rc=0 tdir
    tdir="$(mktemp -d)"
    set +e
    out="$(export TMPDIR="$tdir"; set -euo pipefail; "$fn" 2>&1)"
    rc=$?
    set -e
    rm -rf -- "$tdir"
    if (( rc == 0 )); then
        (( ++TEST_PASS ))
        printf '  [PASS] %s\n' "$name"
    elif (( rc == 77 )) && ! skips_are_failures; then
        (( ++TEST_SKIP ))
        printf '  [SKIP] %s (%s)\n' "$name" "$out"
    elif (( rc == 77 )); then
        (( ++TEST_FAIL ))
        printf '  [FAIL] %s (skipped: %s; skips count as failures in CI)\n' "$name" "$out" >&2
    else
        (( ++TEST_FAIL ))
        printf '  [FAIL] %s (rc=%d)\n' "$name" "$rc" >&2
        # An if, not "[[ ... ]] && ...": as the last command of this function
        # a false test would return 1 and errexit would end the suite here,
        # before the remaining tests and the summary.
        if [[ -n "$out" ]]; then
            printf '%s\n' "$out" | sed 's/^/         /' >&2
        fi
    fi
}

finish_test_file() {
    local suite="$1"
    printf 'Suite %s: %d passed, %d skipped, %d failed\n' "$suite" "$TEST_PASS" "$TEST_SKIP" "$TEST_FAIL"
    if (( TEST_PASS + TEST_SKIP + TEST_FAIL == 0 )); then
        printf '  [FAIL] %s ran no tests\n' "$suite" >&2
        return 1
    fi
    (( TEST_FAIL == 0 ))
}
