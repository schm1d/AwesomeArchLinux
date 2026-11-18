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
    elif (( rc == 77 )); then
        (( ++TEST_SKIP ))
        printf '  [SKIP] %s (%s)\n' "$name" "$out"
    else
        (( ++TEST_FAIL ))
        printf '  [FAIL] %s (rc=%d)\n' "$name" "$rc" >&2
        [[ -n "$out" ]] && printf '%s\n' "$out" | sed 's/^/         /' >&2
    fi
}

finish_test_file() {
    local suite="$1"
    printf 'Suite %s: %d passed, %d skipped, %d failed\n' "$suite" "$TEST_PASS" "$TEST_SKIP" "$TEST_FAIL"
    (( TEST_FAIL == 0 ))
}
