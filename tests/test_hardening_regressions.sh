#!/usr/bin/env bash
# Pure-Bash regression tests for critical security and runtime edge cases
# across hardening/ modules.

set -euo pipefail

# shellcheck disable=SC1090,SC1091
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

test_php_set_ini_ampersand_and_duplicate_comments() {
    local tmp
    tmp="$(mktemp -d)"
    trap 'trap - RETURN EXIT; [[ -n "${tmp:-}" ]] && rm -rf -- "$tmp"' RETURN EXIT

    cat > "$tmp/php.ini" <<'EOF'
[PHP]
; error_reporting
;   Default Value: E_ALL
error_reporting = E_ALL & ~E_DEPRECATED & ~E_STRICT
;session.save_path = "N;/path"
;session.save_path = "N;MODE;/path"
;session.save_path = "/tmp"
open_basedir =
EOF

    local fn_set_ini
    fn_set_ini="$(extract_shell_function "hardening/php/php.sh" "set_ini")"

    bash -c '
        set -euo pipefail
        '"$fn_set_ini"'
        set_ini "error_reporting" "E_ALL & ~E_DEPRECATED" "$1"
        set_ini "error_reporting" "E_ALL & ~E_DEPRECATED" "$1"
        set_ini "session.save_path" "\"/var/lib/php/sessions\"" "$1"
        set_ini "open_basedir" "/var/www:/srv/http:/var/lib/php/sessions:/var/log/php:/tmp:/usr/share/php" "$1"
    ' _ "$tmp/php.ini"

    local err_line save_count
    err_line="$(grep -E '^error_reporting[[:space:]]*=' "$tmp/php.ini")"
    assert_eq "$err_line" "error_reporting = E_ALL & ~E_DEPRECATED" "set_ini preserves literal & across re-runs"

    save_count="$(grep -Ec '^session\.save_path[[:space:]]*=' "$tmp/php.ini")"
    assert_eq "$save_count" "1" "set_ini uncomments only one session.save_path line"
    assert_contains "$(cat "$tmp/php.ini")" "/var/lib/php/sessions"
}

test_nginx_regex_location_precedence_in_wordpress_and_react() {
    local wp_sh="$REPO_ROOT/hardening/wordpress/wordpress.sh"
    local react_sh="$REPO_ROOT/hardening/react/react.sh"
    local nginx_sh="$REPO_ROOT/hardening/nginx/nginx.sh"

    # In wordpress.sh, uploads PHP deny MUST appear before generic `location ~ \.php$`
    local uploads_line php_line
    uploads_line="$(grep -n 'wp-content/uploads/.*\\\.php' "$wp_sh" | head -n1 | cut -d: -f1)"
    php_line="$(grep -n 'location ~ \\\.php\$' "$wp_sh" | head -n1 | cut -d: -f1)"
    [[ -n "$uploads_line" && -n "$php_line" && "$uploads_line" -lt "$php_line" ]] || \
        fail "wordpress.sh: uploads PHP block (line ${uploads_line:-none}) must precede generic .php location (line ${php_line:-none})"

    assert_not_contains "$(cat "$wp_sh")" '/wp-content/.*/index\.php' \
        "wordpress.sh must not allow PHP execution in writable wp-content subdirs"

    # In react.sh, dotfile block MUST appear before static extension regex
    local dot_line asset_line
    dot_line="$(grep -n 'location ~ /\\\.(?!well-known)' "$react_sh" | head -n1 | cut -d: -f1)"
    asset_line="$(grep -n 'location ~\* \\\.(js|css|' "$react_sh" | head -n1 | cut -d: -f1)"
    [[ -n "$dot_line" && -n "$asset_line" && "$dot_line" -lt "$asset_line" ]] || \
        fail "react.sh: dotfile block (line ${dot_line:-none}) must precede static extension regex (line ${asset_line:-none})"

    # In nginx.sh, composer.json regex must match leading slash URIs
    local nginx_code
    nginx_code="$(script_code "$nginx_sh")"
    assert_contains "$nginx_code" 'composer\.(json|lock)' "nginx.sh blocks composer metadata"
    assert_not_contains "$nginx_code" '|^(Entries' "nginx.sh does not anchor URI filename without leading slash"
}

test_systemd_capabilities_and_chrony_runtime_dir() {
    local chrony_sh="$REPO_ROOT/hardening/chrony/chrony.sh"
    local chroot_sh="$REPO_ROOT/base/chroot.sh"
    local nginx_sh="$REPO_ROOT/hardening/nginx/nginx.sh"
    local php_sh="$REPO_ROOT/hardening/php/php.sh"
    local postfix_sh="$REPO_ROOT/hardening/postfix/postfix.sh"

    # Comment lines are excluded: the setting has to be in a generated unit,
    # not merely mentioned in an explanation next to it.
    local chrony_code chroot_code script code
    chrony_code="$(script_code "$chrony_sh")"
    chroot_code="$(script_code "$chroot_sh")"
    assert_not_contains "$chrony_code" "RuntimeDirectory=chrony" "chrony.sh avoids root-owned /run/chrony crash"
    assert_not_contains "$chroot_code" "RuntimeDirectory=chrony" "chroot.sh avoids root-owned /run/chrony crash"
    grep -Eq '^[[:space:]]*RestrictAddressFamilies=.*AF_NETLINK' <<<"$chrony_code" || \
        fail "chrony.sh allows AF_NETLINK for DNS/NTS (RestrictAddressFamilies= line)"

    for script in "$nginx_sh" "$php_sh" "$postfix_sh"; do
        code="$(script_code "$script")"
        grep -Eq '^[[:space:]]*CapabilityBoundingSet=.*CAP_KILL' <<<"$code" || \
            fail "${script#"$REPO_ROOT"/}: no CapabilityBoundingSet= line retains CAP_KILL for worker reload/management"
    done
}

# Source-level guards for three fixes that have no runnable fixture here. Each
# one looks at generated configuration lines only (comment lines are dropped).
test_ssh_totp_include_postfix_sasl_and_fail2ban_filter() {
    # sshd keeps the first value it reads for a keyword, so the TOTP drop-in has
    # to be included above the public-key-only AuthenticationMethods line of
    # the generated sshd_config; below it the second factor would be ignored.
    local sshd_conf include_line auth_line
    sshd_conf="$(sed -n '/<<[[:space:]]*SSHD_EOF$/,/^SSHD_EOF$/p' "$REPO_ROOT/hardening/ssh/ssh.sh" | grep -v '^[[:space:]]*#' || true)"
    include_line="$(grep -Fxn -m1 'Include ${TOTP_DROPIN}' <<<"$sshd_conf" | cut -d: -f1 || true)"
    auth_line="$(grep -n -m1 '^AuthenticationMethods ' <<<"$sshd_conf" | cut -d: -f1 || true)"
    [[ -n "$auth_line" ]] || fail "ssh.sh: generated sshd_config has no AuthenticationMethods line"
    [[ -n "$include_line" ]] || fail "ssh.sh: generated sshd_config does not include the TOTP drop-in"
    (( include_line < auth_line )) || \
        fail "ssh.sh: Include \${TOTP_DROPIN} (line $include_line) must come before AuthenticationMethods (line $auth_line)"

    # AUTH is off for smtpd in general (port 25) and switched on only for the
    # submission services in master.cf.
    local postfix_code
    postfix_code="$(script_code "$REPO_ROOT/hardening/postfix/postfix.sh")"
    grep -qx 'smtpd_sasl_auth_enable = no' <<<"$postfix_code" || \
        fail "postfix.sh: main.cf does not turn SASL AUTH off by default"
    if grep -Eq '^smtpd_sasl_auth_enable[[:space:]]*=[[:space:]]*yes' <<<"$postfix_code"; then
        fail "postfix.sh: main.cf offers SASL AUTH on every smtpd, including the MX port"
    fi
    grep -Eq '^[[:space:]]+-o smtpd_sasl_auth_enable=yes' <<<"$postfix_code" || \
        fail "postfix.sh: master.cf no longer enables SASL AUTH for the submission services"

    local fail2ban_code
    fail2ban_code="$(script_code "$REPO_ROOT/hardening/fail2ban/fail2ban.sh")"
    grep -q '^failregex = ' <<<"$fail2ban_code" || fail "fail2ban.sh no longer writes a failregex for its sshd filter"
    assert_not_contains "$fail2ban_code" "Bad protocol version" "fail2ban.sh sshd filter has no 'Bad protocol version' pattern"
}

test_openclaw_privilege_and_v8_inspector_safety() {
    local oc_sh="$REPO_ROOT/hardening/openclaw/openclaw.sh"

    local oc_code
    oc_code="$(script_code "$oc_sh")"
    assert_not_contains "$oc_code" "killall -USR1" "openclaw logrotate never sends SIGUSR1 (V8 debugger)"
    assert_not_contains "$oc_code" 'owner $OC_HOME/**' "openclaw AppArmor never exposes entire user home"
}

test_apparmor_dry_run_and_parser_validation() {
    local tmp
    tmp="$(mktemp -d)"
    trap 'trap - RETURN EXIT; [[ -n "${tmp:-}" ]] && rm -rf -- "$tmp"' RETURN EXIT

    local out
    out="$(bash -c '
        set -euo pipefail
        id() { echo 0; }
        source "$1" --dry-run
    ' _ "$REPO_ROOT/hardening/apparmor/apparmor.sh" 2>&1)"

    local preview_dir
    preview_dir="$(printf '%s\n' "$out" | sed -n 's/.*Preview files remain in: \(.*\)/\1/p' | tail -n1 | tr -d '\r')"
    [[ -n "$preview_dir" && -d "$preview_dir" ]] || fail "apparmor.sh --dry-run did not produce preview dir"

    assert_contains "$(cat "$preview_dir/usr.bin.sshd")" "/systemd/notify" "sshd profile allows sd_notify"
    assert_contains "$(cat "$preview_dir/usr.bin.chronyd")" "/systemd/notify" "chronyd profile allows sd_notify"
    assert_contains "$(cat "$preview_dir/usr.bin.chronyd")" "ssl_certs" "chronyd profile allows TLS CA bundle"

    if command -v apparmor_parser >/dev/null 2>&1 && [[ -d /etc/apparmor.d/abstractions ]]; then
        local prof
        for prof in "$preview_dir"/usr.bin.*; do
            [[ -f "$prof" ]] || continue
            apparmor_parser -Q --skip-cache -I /etc/apparmor.d "$prof" || \
                fail "apparmor_parser rejected $(basename "$prof")"
        done
    fi
    rm -rf -- "$preview_dir"
}

test_fscrypt_refuses_root_and_self_session_termination() {
    local tmp
    tmp="$(mktemp -d)"
    trap 'trap - RETURN EXIT; [[ -n "${tmp:-}" ]] && rm -rf -- "$tmp"' RETURN EXIT

    local rc=0 out=""
    out="$(SUDO_USER="alice" bash -c '
        set -euo pipefail
        id() {
            if [[ "${1:-}" == "-u" && "${2:-}" == "alice" ]]; then echo 1000; return 0; fi
            if [[ "${1:-}" == "-u" ]]; then echo 0; return 0; fi
            builtin command id "$@"
        }
        getent() { echo "alice:x:1000:1000::/home/alice:/bin/zsh"; }
        loginctl() { echo "TERMINATED_SELF" >&2; exit 99; }
        source "$1" --encrypt-user alice
    ' _ "$REPO_ROOT/hardening/fscrypt/fscrypt.sh" 2>&1)" || rc=$?

    assert_ne "$rc" "0" "fscrypt refuses encrypting caller own active sudo session"
    assert_not_contains "$out" "TERMINATED_SELF" "fscrypt never calls loginctl terminate-user on self"
}

run_test "php.sh set_ini preserves literal & and avoids duplicate uncommenting" test_php_set_ini_ampersand_and_duplicate_comments
run_test "wordpress.sh, react.sh, and nginx.sh location regex security precedence" test_nginx_regex_location_precedence_in_wordpress_and_react
run_test "systemd drop-ins preserve CAP_KILL and avoid chrony RuntimeDirectory crash" test_systemd_capabilities_and_chrony_runtime_dir
run_test "ssh.sh TOTP include order, postfix.sh SASL default, fail2ban.sh sshd filter" test_ssh_totp_include_postfix_sasl_and_fail2ban_filter
run_test "openclaw.sh prevents V8 SIGUSR1 debugger and home AppArmor leak" test_openclaw_privilege_and_v8_inspector_safety
run_test "apparmor.sh --dry-run profiles pass apparmor_parser and allow sd_notify" test_apparmor_dry_run_and_parser_validation
run_test "fscrypt.sh refuses self-session termination and root encryption" test_fscrypt_refuses_root_and_self_session_termination

finish_test_file "test_hardening_regressions.sh"
