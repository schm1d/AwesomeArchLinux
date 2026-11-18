#!/usr/bin/env bash
# Offline chroot-security tests in pure Bash: PAM policy, journal sealing,
# arch-audit vulnerability checks, and auditd rule rendering/loading.

set -euo pipefail

# shellcheck disable=SC1090,SC1091
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

LIBRARY="$REPO_ROOT/base/lib/chroot-security.sh"

readonly PAM_STACK='#%PAM-1.0
auth required pam_faillock.so preauth
-auth [success=2 default=ignore] pam_systemd_home.so
auth [success=1 default=bad] pam_unix.so try_first_pass nullok
auth [default=die] pam_faillock.so authfail
auth required pam_faillock.so authsucc
account required pam_unix.so
-password [success=1 default=ignore] pam_systemd_home.so
password required pam_unix.so try_first_pass shadow # local password
password optional pam_permit.so
session required pam_unix.so'

call_helper() {
    bash -c 'set -euo pipefail; source "$1"; shift; "$@"' _ "$LIBRARY" "$@"
}

test_password_policy_repair_and_idempotence() {
    local tmp
    tmp="$(mktemp -d)"
    trap 'trap - RETURN EXIT; [[ -n "${tmp:-}" ]] && rm -rf -- "$tmp"' RETURN EXIT

    mkdir -p "$tmp/etc/pam.d" "$tmp/etc/security"
    local old="${PAM_STACK/preauth/preauth deny=5 unlock_time=900}"
    old="${old/password optional/password required pam_pwquality.so retry=3$'\n'password optional}"
    printf '%s\n' "$old" > "$tmp/etc/pam.d/system-auth"
    printf 'minlen = 8\n' > "$tmp/etc/security/pwquality.conf"
    printf '# existing\ndeny = 3\naudit\n' > "$tmp/etc/security/faillock.conf"

    call_helper configure_password_policy "$tmp"

    local pam first_pw
    pam="$(cat "$tmp/etc/pam.d/system-auth")"
    first_pw="$(awk '$1 ~ /^-?password$/ { print; exit }' "$tmp/etc/pam.d/system-auth")"
    assert_eq "$first_pw" "password requisite pam_pwquality.so retry=3 enforce_for_root" "pam_pwquality first"
    assert_eq "$(grep -c 'pam_pwquality.so' "$tmp/etc/pam.d/system-auth")" "1" "single pam_pwquality line"
    assert_contains "$pam" "shadow use_authtok # local password"
    assert_contains "$pam" "-password [success=1 default=ignore] pam_systemd_home.so"

    call_helper configure_password_policy "$tmp"
    assert_eq "$(cat "$tmp/etc/pam.d/system-auth")" "$pam" "idempotent rerun"
    assert_eq "$(cat "$tmp/etc/pam.d/system-auth.before-awesome")" "$old" "original backup preserved"
    assert_eq "$(cat "$tmp/etc/security/faillock.conf")" $'# existing\naudit\ndeny = 5\nunlock_time = 900'

    # Unsupported PAM stack is refused atomically
    local tmp2 rc=0
    tmp2="$(mktemp -d)"
    mkdir -p "$tmp2/etc/pam.d" "$tmp2/etc/security"
    local bad="${PAM_STACK/password required pam_unix.so/password required pam_ldap.so}"
    printf '%s\n' "$bad" > "$tmp2/etc/pam.d/system-auth"
    printf 'minlen = 8\n' > "$tmp2/etc/security/pwquality.conf"
    printf 'audit\n'       > "$tmp2/etc/security/faillock.conf"
    call_helper configure_password_policy "$tmp2" >/dev/null 2>&1 || rc=$?
    assert_ne "$rc" "0" "unsupported PAM stack rejected"
    assert_eq "$(cat "$tmp2/etc/pam.d/system-auth")" "$bad" "untouched on failure"
    rm -rf -- "$tmp2"

    # Both installers configure policy before passwd calls
    local name policy_line user_line root_line
    for name in chroot.sh vps-chroot.sh; do
        policy_line="$(grep -n '^configure_password_policy$' "$REPO_ROOT/base/$name" | head -1 | cut -d: -f1)"
        user_line="$(grep -n 'passwd "\$USERNAME"' "$REPO_ROOT/base/$name" | head -1 | cut -d: -f1)"
        root_line="$(grep -n 'passwd root' "$REPO_ROOT/base/$name" | head -1 | cut -d: -f1)"
        (( policy_line < user_line && policy_line < root_line )) || fail "$name must call configure_password_policy before passwd"
    done
}

test_journal_sealing() {
    local mid="0123456789abcdef0123456789abcdef"
    local fake_key="012345-6789ab-cdef01-234567/abcd-35a4e900"
    local tmp
    tmp="$(mktemp -d)"
    trap 'trap - RETURN EXIT; [[ -n "${tmp:-}" ]] && rm -rf -- "$tmp"' RETURN EXIT

    mkdir -p "$tmp/etc"
    printf '%s\n' "$mid" > "$tmp/etc/machine-id"

    local out
    out="$(MOCK_ROOT="$tmp" MOCK_MODE="success" MOCK_KEY="$fake_key" MOCK_ID="$mid" bash -c '
        set -euo pipefail
        source "$1"
        journalctl() {
            printf "%s\n" "$*" >> "$MOCK_ROOT/calls"
            [[ "$*" == "--quiet --setup-keys" ]] || return 99
            echo "private setup diagnostic" >&2
            [[ "$MOCK_MODE" != fail ]] || return 43
            printf "%s\n" "$MOCK_KEY"
            if [[ "$MOCK_MODE" == success ]]; then
                printf "sealing state" > "$MOCK_ROOT/var/log/journal/$MOCK_ID/fss"
            fi
        }
        initialize_journal_sealing "$2" 2>&1
    ' _ "$LIBRARY" "$tmp")"

    local state="$tmp/var/log/journal/$mid/fss"
    local ver="$tmp/root/journal-sealing/verification-$mid.txt"
    assert_eq "$(cat "$ver")" "$fake_key" "verification key saved"
    assert_file_mode "$state" "600"
    assert_file_mode "$ver" "600"
    assert_file_mode "$(dirname "$ver")" "700"
    assert_not_contains "$out" "$fake_key" "key never printed to stdout/stderr"
    assert_not_contains "$out" "private setup diagnostic"
    assert_contains "$out" "ACTION REQUIRED"

    # Subsequent boot preserves keys even after verification file is exported off-machine
    rm -f "$ver"
    MOCK_ROOT="$tmp" MOCK_MODE="success" MOCK_KEY="different" MOCK_ID="$mid" bash -c '
        set -euo pipefail
        source "$1"
        journalctl() { echo "UNEXPECTED" >> "$MOCK_ROOT/calls"; return 99; }
        initialize_journal_sealing "$2" >/dev/null
    ' _ "$LIBRARY" "$tmp"
    assert_eq "$(wc -l < "$tmp/calls" | tr -d ' ')" "1" "setup-keys called only once"

    # Invalid machine-id refused
    local bad rc
    for bad in "" "uninitialized" "00000000000000000000000000000000" "../../wrong"; do
        local bad_root
        bad_root="$(mktemp -d)"
        mkdir -p "$bad_root/etc"
        printf '%s' "$bad" > "$bad_root/etc/machine-id"
        rc=0
        call_helper initialize_journal_sealing "$bad_root" >/dev/null 2>&1 || rc=$?
        assert_ne "$rc" "0" "rejected bad machine-id: $bad"
        rm -rf -- "$bad_root"
    done

    # Offline SplitMode=login repair
    local off_root
    off_root="$(mktemp -d)"
    mkdir -p "$off_root/etc/systemd"
    printf '[Journal]\nSplitMode=login\nRateLimitBurst=2000\n' > "$off_root/etc/systemd/journald.conf"
    call_helper configure_journal_sealing "$off_root"
    assert_eq "$(cat "$off_root/etc/systemd/journald.conf")" $'[Journal]\nSplitMode=uid\nRateLimitBurst=2000'
    rm -rf -- "$off_root"
}

test_vulnerability_check() {
    local tmp
    tmp="$(mktemp -d)"
    trap 'trap - RETURN EXIT; [[ -n "${tmp:-}" ]] && rm -rf -- "$tmp"' RETURN EXIT
    mkdir -p "$tmp/var/log"
    local report="$tmp/var/log/arch-audit.log"
    local findings="example | severity: High | CVEs: CVE-2099-0001 | fixed: None"

    local rc=0
    MOCK_FINDINGS="${findings}"$'\n' MOCK_STATUS=0 bash -c '
        set -euo pipefail
        source "$1"
        arch-audit() { printf "%s" "$MOCK_FINDINGS"; return "$MOCK_STATUS"; }
        run_vulnerability_check "$2"
    ' _ "$LIBRARY" "$tmp" >/dev/null 2>&1 || rc=$?
    assert_eq "$rc" "1" "findings return exit code 1"
    assert_eq "$(cat "$report")" "$findings"
    assert_file_mode "$report" "600"

    # Fetch failure preserves previous completed report
    rc=0
    MOCK_FINDINGS="incomplete" MOCK_STATUS=42 bash -c '
        set -euo pipefail
        source "$1"
        arch-audit() { printf "%s" "$MOCK_FINDINGS"; return "$MOCK_STATUS"; }
        run_vulnerability_check "$2"
    ' _ "$LIBRARY" "$tmp" >/dev/null 2>&1 || rc=$?
    assert_eq "$rc" "42" "preserves arch-audit exit status"
    assert_eq "$(cat "$report")" "$findings" "previous report preserved"

    # Clean scan clears report and exits 0
    MOCK_FINDINGS="" MOCK_STATUS=0 bash -c '
        set -euo pipefail
        source "$1"
        arch-audit() { return 0; }
        run_vulnerability_check "$2"
    ' _ "$LIBRARY" "$tmp" >/dev/null
    assert_eq "$(cat "$report")" "" "clean report empty"
}

test_audit_rules_render_load_and_syscalls() {
    local tmp
    tmp="$(mktemp -d)"
    trap 'trap - RETURN EXIT; [[ -n "${tmp:-}" ]] && rm -rf -- "$tmp"' RETURN EXIT

    mkdir -p "$tmp/etc/audit/rules.d" "$tmp/etc/pam.d" "$tmp/usr/bin" "$tmp/usr/local/share/awesomearchlinux"
    touch "$tmp/etc/pam.d/system-auth" "$tmp/etc/passwd" "$tmp/etc/shadow" \
          "$tmp/etc/group" "$tmp/etc/gshadow" "$tmp/etc/sudoers" \
          "$tmp/usr/bin/sudo" "$tmp/usr/bin/pacman" "$tmp/etc/pacman.conf"
    ln -s "bin" "$tmp/usr/sbin"

    local template="$tmp/usr/local/share/awesomearchlinux/auditd-attack.rules"
    cp "$REPO_ROOT/utils/auditd-attack.rules" "$template"
    printf -- '-w /usr/bin/pacman -p x -k alias_test\n-w /usr/sbin/pacman -p x -k alias_test\n' >> "$template"

    local rendered stderr_file="$tmp/stderr"
    rendered="$(call_helper render_audit_rules "$template" "$tmp" 2>"$stderr_file")"
    assert_contains "$(cat "$stderr_file")" "/usr/bin/yay"
    assert_not_contains "$rendered" "-w /usr/bin/yay "
    assert_contains "$rendered" "-w /etc/pam.d/system-auth "
    assert_eq "$(grep -c -- '-k alias_test' <<<"$rendered")" "1" "deduplicated usrmerge alias"

    # Load failure never locks partial policy with -e 2
    local rc=0
    MOCK_ROOT="$tmp" MOCK_CALLS="$tmp/calls" bash -c '
        set -euo pipefail
        source "$1"
        auditctl() {
            printf "%s\n" "$*" >> "$MOCK_CALLS"
            case "$1" in
                -s) echo "enabled 1" ;;
                -R) return 1 ;;
                -e) return 0 ;;
            esac
        }
        augenrules() { cp "$MOCK_ROOT/etc/audit/rules.d/auditd-attack.rules" "$MOCK_ROOT/etc/audit/audit.rules"; }
        load_audit_rules "$2"
    ' _ "$LIBRARY" "$tmp" >/dev/null 2>&1 || rc=$?
    assert_ne "$rc" "0" "failed load returns non-zero"
    assert_not_contains "$(cat "$tmp/calls")" "-e 2" "never locks immutable on load failure"

    # Validate bundled syscalls via ausyscall if installed
    if command -v ausyscall >/dev/null 2>&1; then
        local line arch idx
        local -a words=()
        while IFS= read -r line; do
            [[ "$line" == "-a "* && "$line" == *" -S "* ]] || continue
            read -r -a words <<<"$line"
            arch="x86_64"
            [[ " $line " == *" arch=b32 "* ]] && arch="i386"
            for idx in "${!words[@]}"; do
                if [[ "${words[idx]}" == "-S" ]]; then
                    ausyscall "$arch" "${words[idx + 1]}" --exact >/dev/null || fail "invalid syscall ${words[idx + 1]} ($arch): $line"
                fi
            done
        done < "$REPO_ROOT/utils/auditd-attack.rules"
    fi
}

run_test "PAM password policy repair, idempotence, and passwd ordering" test_password_policy_repair_and_idempotence
run_test "journal sealing key capture, preservation, and SplitMode=uid" test_journal_sealing
run_test "arch-audit findings status and fetch-failure preservation" test_vulnerability_check
run_test "auditd rules rendering, alias dedup, atomic lock, and syscalls" test_audit_rules_render_load_and_syscalls

finish_test_file "test_chroot_security.sh"
