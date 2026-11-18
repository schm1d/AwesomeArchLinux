#!/usr/bin/env bash
# Regression tests for Brave permission/ACL/hook fixes, dangling SingletonLock
# handling, and audit-check.sh edge cases.

set -euo pipefail

# shellcheck disable=SC1090,SC1091
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

test_brave_hook_strips_acls_restores_modes_without_null_warnings() {
    local tmp
    tmp="$(mktemp -d)"
    trap 'trap - RETURN EXIT; [[ -n "${tmp:-}" ]] && rm -rf -- "$tmp"' RETURN EXIT

    local b_dir="$tmp/opt/brave-bin"
    mkdir -p "$b_dir/cron" "$b_dir/locales" "$b_dir/apparmor.d"

    # Simulate broken 0700/0600 extraction under inherited home default ACLs
    printf '\x7fELF\x02\x01\x01\x00binary' > "$b_dir/brave"
    printf '#!/usr/bin/env bash\n' > "$b_dir/brave-browser"
    printf '\x7fELF\x02\x01\x01\x00crashpad' > "$b_dir/chrome_crashpad_handler"
    printf '\x7fELF\x02\x01\x01\x00mgmt' > "$b_dir/chrome-management-service"
    printf '\x7fELF\x02\x01\x01\x00sandbox' > "$b_dir/chrome-sandbox"
    printf '#!/bin/sh\n' > "$b_dir/cron/brave-browser"
    printf '\x7fELF\x02\x01\x01\x00shim' > "$b_dir/libqt5_shim.so"
    printf '\x7fELF\x02\x01\x01\x00vk' > "$b_dir/libvulkan.so.1"
    printf 'PAKDATA\x00\x01\x02' > "$b_dir/resources.pak"
    printf 'LOCALE\x00' > "$b_dir/locales/en-US.pak"

    chmod 0700 "$b_dir" "$b_dir/cron" "$b_dir/locales" "$b_dir/apparmor.d"
    chmod 0700 "$b_dir/brave" "$b_dir/brave-browser" "$b_dir/cron/brave-browser" "$b_dir/chrome-sandbox"
    # Even if .so was previously forced 0755, hook must restore 0644 to match pacman mtree
    chmod 0755 "$b_dir/libqt5_shim.so" "$b_dir/libvulkan.so.1"
    chmod 0600 "$b_dir/resources.pak" "$b_dir/locales/en-US.pak" "$b_dir/chrome_crashpad_handler" "$b_dir/chrome-management-service"

    if command -v setfacl >/dev/null 2>&1; then
        setfacl -d -m u::rwx,g::---,o::--- "$b_dir" 2>/dev/null || true
    fi

    # Extract embedded helper script from utils/brave.sh and run it against $b_dir
    local helper_src="$tmp/brave-fix-permissions.sh"
    awk '
        /^    helper_content="\$\(cat <<'\''EOF'\''$/ { capture = 1; next }
        capture && /^EOF$/ { capture = 0; exit }
        capture { print }
    ' "$REPO_ROOT/utils/brave.sh" > "$helper_src"

    # Patch chown root:root to no-op for unprivileged test run and target $b_dir
    sed -i \
        -e 's|chown -hR root:root|true|g' \
        -e 's|chown root:root|true|g' \
        -e "s|for candidate in .*|for candidate in \"$b_dir\"; do|" \
        -e 's|for launcher in .*|for launcher in ; do|' \
        -e 's|for desktop in .*|for desktop in ; do|' \
        "$helper_src"

    local stderr_out
    stderr_out="$(bash "$helper_src" 2>&1 >/dev/null)"
    assert_eq "$stderr_out" "" "zero stderr / zero null-byte warnings"

    assert_file_mode "$b_dir" "755"
    assert_file_mode "$b_dir/cron" "755"
    assert_file_mode "$b_dir/locales" "755"
    assert_file_mode "$b_dir/brave" "755"
    assert_file_mode "$b_dir/brave-browser" "755"
    assert_file_mode "$b_dir/chrome_crashpad_handler" "755"
    assert_file_mode "$b_dir/chrome-management-service" "755"
    assert_file_mode "$b_dir/cron/brave-browser" "755"
    assert_file_mode "$b_dir/libqt5_shim.so" "644"
    assert_file_mode "$b_dir/libvulkan.so.1" "644"
    assert_file_mode "$b_dir/resources.pak" "644"
    assert_file_mode "$b_dir/locales/en-US.pak" "644"
    assert_file_mode "$b_dir/chrome-sandbox" "4755"

    if command -v getfacl >/dev/null 2>&1; then
        assert_not_contains "$(getfacl -p "$b_dir" 2>/dev/null)" "default:" "default ACL stripped"
    fi
}

test_brave_user_profile_handles_singleton_lock_and_preserves_exec() {
    local tmp
    tmp="$(mktemp -d)"
    trap 'trap - RETURN EXIT; [[ -n "${tmp:-}" ]] && rm -rf -- "$tmp"' RETURN EXIT

    local u_conf="$tmp/BraveSoftware/Brave-Browser"
    mkdir -p -m 0755 "$u_conf/tor"
    printf '{"state":1}\n' > "$u_conf/Local State"
    chmod 0644 "$u_conf/Local State"
    printf '#!/usr/bin/env bash\n' > "$u_conf/tor/tor-daemon"
    chmod 0755 "$u_conf/tor/tor-daemon"

    # Dangling SingletonLock symlink created by Chromium/Brave while running
    ln -s "myhost-99999" "$u_conf/SingletonLock"
    # Outside target file pointed to by a symlink inside profile — must NOT be chowned/chmodded!
    printf 'outside\n' > "$tmp/outside.txt"
    chmod 0644 "$tmp/outside.txt"
    ln -s "$tmp/outside.txt" "$u_conf/escape-link"

    local fn_def
    fn_def="$(extract_shell_function "utils/brave.sh" "secure_user_dir")"

    bash -c '
        set -euo pipefail
        REAL_USER="$(id -un)"
        REAL_GROUP="$(id -gn)"
        info() { :; }
        sudo_run() { "$@"; }
        as_user() { "$@"; }
        '"$fn_def"'
        secure_user_dir "$1" "config"
    ' _ "$tmp/BraveSoftware"

    assert_file_mode "$tmp/BraveSoftware" "700"
    assert_file_mode "$u_conf" "700"
    assert_file_mode "$u_conf/Local State" "600"
    assert_file_mode "$u_conf/tor/tor-daemon" "700"
    assert_file_mode "$tmp/outside.txt" "644"
    [[ -L "$u_conf/SingletonLock" ]] || fail "SingletonLock symlink should remain intact"
}

test_audit_check_ssh_and_json_helpers() {
    local tmp
    tmp="$(mktemp -d)"
    trap 'trap - RETURN EXIT; [[ -n "${tmp:-}" ]] && rm -rf -- "$tmp"' RETURN EXIT

    cat > "$tmp/sshd_config" <<'EOF'
Port 22
PermitRootLogin no
PasswordAuthentication no
MaxAuthTries 3
DisableForwarding yes
X11Forwarding no
EOF

    local fn_ssh fn_json
    fn_ssh="$(extract_shell_function "utils/audit-check.sh" "check_ssh_hardening")"
    fn_json="$(extract_shell_function "utils/audit-check.sh" "json_escape")"

    local out
    out="$(bash -c '
        set -euo pipefail
        JSON_OUTPUT=false; VERBOSE=true
        PASS_COUNT=0; FAIL_COUNT=0; WARN_COUNT=0; TOTAL_COUNT=0
        CURRENT_CATEGORY=""
        JSON_RESULTS=()
        C_BLUE=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_NC=""
        '"$fn_json"'
        category_header() { CURRENT_CATEGORY="$1"; }
        result_pass() { (( ++PASS_COUNT )); (( ++TOTAL_COUNT )); echo "PASS: $1"; }
        result_fail() { (( ++FAIL_COUNT )); (( ++TOTAL_COUNT )); echo "FAIL: $1 ($2)"; }
        result_warn() { (( ++WARN_COUNT )); (( ++TOTAL_COUNT )); echo "WARN: $1"; }
        # Test config parser path directly without host sshd -T
        command() {
            if [[ "$1" == "-v" && "$2" == "sshd" ]]; then return 1; fi
            builtin command "$@"
        }
        fn_body=$(cat <<'\''END_FN'\''
'"$fn_ssh"'
END_FN
)
        fn_body="${fn_body//\/etc\/ssh\/sshd_config/$1}"
        eval "$fn_body"
        check_ssh_hardening
        echo "FAIL_COUNT=$FAIL_COUNT PASS_COUNT=$PASS_COUNT"
    ' _ "$tmp/sshd_config")"

    assert_contains "$out" "FAIL_COUNT=0 PASS_COUNT=7"
}

run_test "Brave hook strips ACLs, sets 755/644/4755, emits zero null-byte warnings" test_brave_hook_strips_acls_restores_modes_without_null_warnings
run_test "Brave user profile secures files without failing on SingletonLock or stripping +x" test_brave_user_profile_handles_singleton_lock_and_preserves_exec
run_test "audit-check.sh recognizes DisableForwarding=yes without pipefail crash" test_audit_check_ssh_and_json_helpers

finish_test_file "test_brave_and_regressions.sh"
