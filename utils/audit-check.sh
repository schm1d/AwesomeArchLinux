#!/usr/bin/env bash

# =============================================================================
# Script:      audit-check.sh
# Description: Hardening compliance checker for Arch Linux.
#              Validates that AwesomeArchLinux security hardening has been
#              correctly applied by checking sysctl parameters, filesystem
#              permissions, authentication config, SSH hardening, network
#              security, service status, boot security, and disabled modules.
#              Outputs a pass/fail/warn report with a final score.
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
#
# Usage:       sudo ./audit-check.sh [--verbose] [--json] [-h]
#
# Options:
#   --verbose   Show actual values for failed/warned checks
#   --json      Output results as a JSON object
#   -h, --help  Show this help message
#
# Exit codes:
#   0 — All checks passed
#   1 — One or more checks failed
# =============================================================================

set -euo pipefail

# --- Colors ---
readonly C_BLUE='\033[1;34m'
readonly C_RED='\033[1;31m'
readonly C_GREEN='\033[1;32m'
readonly C_YELLOW='\033[1;33m'
readonly C_NC='\033[0m'

# --- Globals ---
VERBOSE=false
JSON_OUTPUT=false
PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0
TOTAL_COUNT=0

# JSON accumulator — array of result objects
declare -a JSON_RESULTS=()
CURRENT_CATEGORY=""

# --- Logging helpers ---
msg()  { printf "%b[+]%b %s\n" "$C_GREEN"  "$C_NC" "$1"; }
info() { printf "%b[*]%b %s\n" "$C_BLUE"   "$C_NC" "$1"; }
warn() { printf "%b[!]%b %s\n" "$C_YELLOW" "$C_NC" "$1"; }
err()  { printf "%b[!]%b %s\n" "$C_RED"    "$C_NC" "$1" >&2; exit 1; }

# --- Result helpers ---
result_pass() {
    local description="$1"
    ((TOTAL_COUNT++)) || true
    ((PASS_COUNT++))  || true
    if [[ "$JSON_OUTPUT" == false ]]; then
        printf "  %b[PASS]%b %s\n" "$C_GREEN" "$C_NC" "$description"
    fi
    JSON_RESULTS+=("{\"category\":\"${CURRENT_CATEGORY}\",\"status\":\"PASS\",\"description\":$(json_escape "$description")}")
}

result_fail() {
    local description="$1"
    local actual="${2:-}"
    ((TOTAL_COUNT++)) || true
    ((FAIL_COUNT++))  || true
    if [[ "$JSON_OUTPUT" == false ]]; then
        printf "  %b[FAIL]%b %s\n" "$C_RED" "$C_NC" "$description"
        if [[ "$VERBOSE" == true && -n "$actual" ]]; then
            printf "         %b=> actual: %s%b\n" "$C_YELLOW" "$actual" "$C_NC"
        fi
    fi
    JSON_RESULTS+=("{\"category\":\"${CURRENT_CATEGORY}\",\"status\":\"FAIL\",\"description\":$(json_escape "$description"),\"actual\":$(json_escape "$actual")}")
}

result_warn() {
    local description="$1"
    local actual="${2:-}"
    ((TOTAL_COUNT++)) || true
    ((WARN_COUNT++))  || true
    if [[ "$JSON_OUTPUT" == false ]]; then
        printf "  %b[WARN]%b %s\n" "$C_YELLOW" "$C_NC" "$description"
        if [[ "$VERBOSE" == true && -n "$actual" ]]; then
            printf "         %b=> actual: %s%b\n" "$C_YELLOW" "$actual" "$C_NC"
        fi
    fi
    JSON_RESULTS+=("{\"category\":\"${CURRENT_CATEGORY}\",\"status\":\"WARN\",\"description\":$(json_escape "$description"),\"actual\":$(json_escape "$actual")}")
}

json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\t'/\\t}"
    printf '"%s"' "$s"
}

category_header() {
    CURRENT_CATEGORY="$1"
    if [[ "$JSON_OUTPUT" == false ]]; then
        echo ""
        printf "%b=== %s ===%b\n" "$C_BLUE" "$1" "$C_NC"
    fi
}

# --- Sysctl helper ---
check_sysctl() {
    local key="$1"
    local expected="$2"
    local description="$3"
    local mode="${4:-exact}"  # exact or min

    local actual
    if actual=$(sysctl -n "$key" 2>/dev/null); then
        if [[ "$mode" == "min" ]]; then
            if [[ "$actual" -ge "$expected" ]]; then
                result_pass "$description ($key = $actual)"
            else
                result_fail "$description ($key should be >= $expected)" "$actual"
            fi
        else
            if [[ "$actual" == "$expected" ]]; then
                result_pass "$description ($key = $expected)"
            else
                result_fail "$description ($key should be $expected)" "$actual"
            fi
        fi
    else
        result_fail "$description ($key not available)" "sysctl key not found"
    fi
}

# --- Usage ---
usage() {
    cat <<EOF
Usage: sudo $0 [--verbose] [--json] [-h]

Hardening compliance checker for Arch Linux.
Validates that AwesomeArchLinux security hardening has been correctly applied.

Options:
  --verbose   Show actual values for failed/warned checks
  --json      Output results as a JSON object (implies no color output)
  -h, --help  Show this help message

Exit codes:
  0 — All checks passed
  1 — One or more checks failed

Examples:
  sudo $0
  sudo $0 --verbose
  sudo $0 --json
  sudo $0 --verbose --json
EOF
    exit 0
}

# --- Parse Arguments ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --verbose)    VERBOSE=true; shift ;;
        --json)       JSON_OUTPUT=true; shift ;;
        -h|--help)    usage ;;
        *)            err "Unknown option: $1. See -h for help." ;;
    esac
done

# --- Root Check ---
[[ $(id -u) -eq 0 ]] || err "Must be run as root (use sudo)"

# =============================================================================
# 1. KERNEL HARDENING (sysctl)
# =============================================================================
check_kernel_hardening() {
    category_header "Kernel Hardening (sysctl)"

    check_sysctl "kernel.kptr_restrict" "2" \
        "Kernel pointer restriction"

    check_sysctl "kernel.dmesg_restrict" "1" \
        "Dmesg access restricted to root"

    check_sysctl "kernel.yama.ptrace_scope" "2" \
        "Ptrace scope restricted" "min"

    check_sysctl "kernel.kexec_load_disabled" "1" \
        "Kexec loading disabled"

    check_sysctl "kernel.unprivileged_bpf_disabled" "1" \
        "Unprivileged BPF disabled"

    check_sysctl "net.ipv4.tcp_syncookies" "1" \
        "TCP SYN cookies enabled"

    check_sysctl "net.ipv4.conf.all.rp_filter" "1" \
        "Reverse path filtering enabled"

    check_sysctl "net.ipv4.conf.all.accept_redirects" "0" \
        "ICMP redirects disabled (accept)"

    check_sysctl "net.ipv4.conf.all.send_redirects" "0" \
        "ICMP redirects disabled (send)"

    # ip_forward: warn if enabled (may be intentional for VPN/Docker)
    local ip_fwd
    ip_fwd=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "unknown")
    if [[ "$ip_fwd" == "0" ]]; then
        result_pass "IP forwarding disabled (net.ipv4.ip_forward = 0)"
    elif [[ "$ip_fwd" == "1" ]]; then
        result_warn "IP forwarding is enabled — may be intentional for VPN/Docker" "$ip_fwd"
    else
        result_fail "Could not read net.ipv4.ip_forward" "$ip_fwd"
    fi

    check_sysctl "net.ipv6.conf.all.disable_ipv6" "1" \
        "IPv6 disabled"

    check_sysctl "kernel.randomize_va_space" "2" \
        "Full ASLR enabled"
}

# =============================================================================
# 2. FILESYSTEM SECURITY
# =============================================================================
check_filesystem_security() {
    category_header "Filesystem Security"

    # Helper: check mount options for a given mountpoint
    check_mount_opts() {
        local mpoint="$1"
        local required_opts="$2"  # comma-separated
        local description="$3"

        local mount_line
        mount_line=$(findmnt -n -o OPTIONS "$mpoint" 2>/dev/null || echo "")

        if [[ -z "$mount_line" ]]; then
            result_fail "$description — $mpoint not found as a separate mount" "not mounted"
            return
        fi

        local all_present=true
        local missing=""
        IFS=',' read -ra OPTS <<< "$required_opts"
        for opt in "${OPTS[@]}"; do
            if ! echo ",$mount_line," | grep -q ",$opt,"; then
                all_present=false
                missing="${missing:+$missing, }$opt"
            fi
        done

        if [[ "$all_present" == true ]]; then
            result_pass "$description ($mpoint has $required_opts)"
        else
            result_fail "$description — missing: $missing" "$mount_line"
        fi
    }

    check_mount_opts "/tmp" "nosuid,nodev,noexec" "/tmp mount hardened"
    check_mount_opts "/dev/shm" "nosuid,nodev,noexec" "/dev/shm mount hardened"

    # Check /proc hidepid
    local proc_opts
    proc_opts=$(findmnt -n -o OPTIONS /proc 2>/dev/null || echo "")
    if echo "$proc_opts" | grep -q "hidepid=2"; then
        result_pass "/proc mounted with hidepid=2"
    elif echo "$proc_opts" | grep -q "hidepid=invisible"; then
        result_pass "/proc mounted with hidepid=invisible"
    else
        result_fail "/proc should have hidepid=2" "$proc_opts"
    fi

    # Check /etc/shadow permissions
    if [[ -f /etc/shadow ]]; then
        local shadow_perms
        shadow_perms=$(stat -c '%a' /etc/shadow 2>/dev/null || echo "unknown")
        if [[ "$shadow_perms" == "600" || "$shadow_perms" == "0" ]]; then
            result_pass "/etc/shadow permissions = $shadow_perms"
        else
            result_fail "/etc/shadow permissions should be 600" "$shadow_perms"
        fi
    else
        result_fail "/etc/shadow does not exist" "missing"
    fi

    # Check /etc/gshadow permissions
    if [[ -f /etc/gshadow ]]; then
        local gshadow_perms
        gshadow_perms=$(stat -c '%a' /etc/gshadow 2>/dev/null || echo "unknown")
        if [[ "$gshadow_perms" == "600" || "$gshadow_perms" == "0" ]]; then
            result_pass "/etc/gshadow permissions = $gshadow_perms"
        else
            result_fail "/etc/gshadow permissions should be 600" "$gshadow_perms"
        fi
    else
        result_fail "/etc/gshadow does not exist" "missing"
    fi

    # Check /boot permissions
    if [[ -d /boot ]]; then
        local boot_perms
        boot_perms=$(stat -c '%a' /boot 2>/dev/null || echo "unknown")
        if [[ "$boot_perms" == "700" ]]; then
            result_pass "/boot permissions = 700"
        else
            result_fail "/boot permissions should be 700" "$boot_perms"
        fi
    else
        result_warn "/boot directory not found" "missing"
    fi

    # Check UMASK in /etc/login.defs
    if [[ -f /etc/login.defs ]]; then
        local umask_val
        umask_val=$(grep -E '^\s*UMASK\s+' /etc/login.defs 2>/dev/null | awk '{print $2}' | tail -1)
        if [[ "$umask_val" == "027" || "$umask_val" == "0027" ]]; then
            result_pass "UMASK set to $umask_val in /etc/login.defs"
        elif [[ -n "$umask_val" ]]; then
            result_fail "UMASK should be 027 in /etc/login.defs" "$umask_val"
        else
            result_fail "UMASK not found in /etc/login.defs" "not set"
        fi
    else
        result_fail "/etc/login.defs not found" "missing"
    fi
}

# =============================================================================
# 3. AUTHENTICATION
# =============================================================================
check_authentication() {
    category_header "Authentication"

    # Check PAM faillock configuration
    local faillock_found=false
    if grep -rq "pam_faillock" /etc/pam.d/ 2>/dev/null; then
        faillock_found=true
    fi
    if [[ -f /etc/security/faillock.conf ]]; then
        faillock_found=true
    fi
    if [[ "$faillock_found" == true ]]; then
        result_pass "PAM faillock is configured"
    else
        result_fail "PAM faillock is not configured" "not found in /etc/pam.d/ or /etc/security/faillock.conf"
    fi

    # Check PAM pwquality (minlen >= 12)
    local pwquality_configured=false
    local minlen_val=""
    if grep -rq "pam_pwquality" /etc/pam.d/ 2>/dev/null; then
        pwquality_configured=true
    fi
    if [[ -f /etc/security/pwquality.conf ]]; then
        minlen_val=$(grep -E '^\s*minlen\s*=' /etc/security/pwquality.conf 2>/dev/null \
            | sed 's/.*=\s*//' | tr -d ' ' | tail -1)
    fi

    if [[ "$pwquality_configured" == true && -n "$minlen_val" && "$minlen_val" -ge 12 ]] 2>/dev/null; then
        result_pass "PAM pwquality configured with minlen = $minlen_val (>= 12)"
    elif [[ "$pwquality_configured" == true && -n "$minlen_val" ]]; then
        result_fail "PAM pwquality minlen should be >= 12" "minlen = $minlen_val"
    elif [[ "$pwquality_configured" == true ]]; then
        result_warn "PAM pwquality module loaded but minlen not set in pwquality.conf" ""
    else
        result_fail "PAM pwquality is not configured" "not found"
    fi

    # Check password hashing algorithm = YESCRYPT
    if [[ -f /etc/login.defs ]]; then
        local hash_algo
        hash_algo=$(grep -E '^\s*ENCRYPT_METHOD\s+' /etc/login.defs 2>/dev/null \
            | awk '{print $2}' | tail -1)
        if [[ "${hash_algo^^}" == "YESCRYPT" ]]; then
            result_pass "Password hashing algorithm is YESCRYPT"
        elif [[ -n "$hash_algo" ]]; then
            result_fail "Password hashing should be YESCRYPT" "$hash_algo"
        else
            result_warn "ENCRYPT_METHOD not found in /etc/login.defs" "not set"
        fi
    else
        result_fail "Cannot check password hashing — /etc/login.defs missing" "missing"
    fi

    # Check /etc/securetty
    if [[ -f /etc/securetty ]]; then
        local tty_count
        tty_count=$(grep -cve '^\s*$' -e '^\s*#' /etc/securetty 2>/dev/null || echo "0")
        if [[ "$tty_count" -eq 0 ]]; then
            result_pass "/etc/securetty exists and is empty (no direct root login)"
        elif [[ "$tty_count" -le 2 ]]; then
            result_pass "/etc/securetty is restrictive ($tty_count entries)"
        else
            result_warn "/etc/securetty has $tty_count entries — consider restricting" "$tty_count entries"
        fi
    else
        result_warn "/etc/securetty does not exist — root login may be unrestricted on TTYs" "file missing"
    fi
}

# =============================================================================
# 4. SSH HARDENING
# =============================================================================
check_ssh_hardening() {
    category_header "SSH Hardening"

    local sshd_config="/etc/ssh/sshd_config"
    local sshd_config_d="/etc/ssh/sshd_config.d"

    # Helper: get effective SSH config value (checks config.d overrides too)
    get_ssh_setting() {
        local key="$1"
        local value=""

        # Check sshd_config.d/ drop-in files first (they typically override)
        if [[ -d "$sshd_config_d" ]]; then
            value=$(grep -rhi "^\s*${key}\s\+" "$sshd_config_d" 2>/dev/null \
                | tail -1 | awk '{print $2}')
        fi

        # Fall back to main config
        if [[ -z "$value" && -f "$sshd_config" ]]; then
            value=$(grep -hi "^\s*${key}\s\+" "$sshd_config" 2>/dev/null \
                | tail -1 | awk '{print $2}')
        fi

        echo "$value"
    }

    if [[ ! -f "$sshd_config" ]]; then
        result_warn "sshd_config not found — SSH may not be installed" "file missing"
        return
    fi

    # PermitRootLogin
    local val
    val=$(get_ssh_setting "PermitRootLogin")
    if [[ "${val,,}" == "no" ]]; then
        result_pass "PermitRootLogin = no"
    elif [[ -n "$val" ]]; then
        result_fail "PermitRootLogin should be no" "$val"
    else
        result_fail "PermitRootLogin not explicitly set (default may allow root)" "not set"
    fi

    # PasswordAuthentication
    val=$(get_ssh_setting "PasswordAuthentication")
    if [[ "${val,,}" == "no" ]]; then
        result_pass "PasswordAuthentication = no"
    elif [[ -n "$val" ]]; then
        result_fail "PasswordAuthentication should be no" "$val"
    else
        result_warn "PasswordAuthentication not explicitly set (default: yes)" "not set"
    fi

    # X11Forwarding
    val=$(get_ssh_setting "X11Forwarding")
    if [[ "${val,,}" == "no" ]]; then
        result_pass "X11Forwarding = no"
    elif [[ -n "$val" ]]; then
        result_fail "X11Forwarding should be no" "$val"
    else
        result_pass "X11Forwarding not set (default: no)"
    fi

    # Protocol (2 is default in modern OpenSSH; setting is deprecated)
    val=$(get_ssh_setting "Protocol")
    if [[ -z "$val" || "$val" == "2" ]]; then
        result_pass "SSH Protocol = 2 (${val:-default})"
    else
        result_fail "SSH Protocol should be 2" "$val"
    fi

    # MaxAuthTries
    val=$(get_ssh_setting "MaxAuthTries")
    if [[ -n "$val" && "$val" -le 3 ]] 2>/dev/null; then
        result_pass "MaxAuthTries = $val (<= 3)"
    elif [[ -n "$val" ]]; then
        result_fail "MaxAuthTries should be <= 3" "$val"
    else
        result_fail "MaxAuthTries not set (default: 6)" "not set"
    fi

    # AllowTcpForwarding
    val=$(get_ssh_setting "AllowTcpForwarding")
    if [[ "${val,,}" == "no" ]]; then
        result_pass "AllowTcpForwarding = no"
    elif [[ -n "$val" ]]; then
        result_fail "AllowTcpForwarding should be no" "$val"
    else
        result_fail "AllowTcpForwarding not set (default: yes)" "not set"
    fi

    # AllowAgentForwarding
    val=$(get_ssh_setting "AllowAgentForwarding")
    if [[ "${val,,}" == "no" ]]; then
        result_pass "AllowAgentForwarding = no"
    elif [[ -n "$val" ]]; then
        result_fail "AllowAgentForwarding should be no" "$val"
    else
        result_fail "AllowAgentForwarding not set (default: yes)" "not set"
    fi
}

# =============================================================================
# 5. NETWORK SECURITY
# =============================================================================
check_network_security() {
    category_header "Network Security"

    # nftables
    if systemctl is-active --quiet nftables 2>/dev/null; then
        result_pass "nftables is active"
    else
        result_fail "nftables is not active" "$(systemctl is-active nftables 2>/dev/null || echo 'not found')"
    fi

    # fail2ban
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        result_pass "fail2ban is active"
    else
        result_fail "fail2ban is not active" "$(systemctl is-active fail2ban 2>/dev/null || echo 'not found')"
    fi

    # DNS-over-TLS (stubby)
    if systemctl is-active --quiet stubby 2>/dev/null; then
        result_pass "DNS-over-TLS (stubby) is active"
    else
        result_fail "DNS-over-TLS (stubby) is not active" "$(systemctl is-active stubby 2>/dev/null || echo 'not found')"
    fi

    # Listening services on 0.0.0.0
    local expected_listeners="sshd\|stubby\|systemd-resolve\|dnsmasq\|fail2ban"
    local unexpected
    unexpected=$(ss -tlnp 2>/dev/null | grep '0\.0\.0\.0' | grep -v "$expected_listeners" || true)

    if [[ -z "$unexpected" ]]; then
        result_pass "No unexpected services listening on 0.0.0.0"
    else
        local count
        count=$(echo "$unexpected" | wc -l)
        result_warn "$count unexpected service(s) listening on 0.0.0.0" "$unexpected"
    fi
}

# =============================================================================
# 6. SERVICE SECURITY
# =============================================================================
check_service_security() {
    category_header "Service Security"

    # AppArmor
    if systemctl is-enabled --quiet apparmor 2>/dev/null; then
        result_pass "AppArmor is enabled"
    else
        result_fail "AppArmor is not enabled" "$(systemctl is-enabled apparmor 2>/dev/null || echo 'not found')"
    fi

    # auditd
    if systemctl is-enabled --quiet auditd 2>/dev/null; then
        result_pass "auditd is enabled"
    else
        result_fail "auditd is not enabled" "$(systemctl is-enabled auditd 2>/dev/null || echo 'not found')"
    fi

    # ClamAV freshclam
    if systemctl is-enabled --quiet clamav-freshclam 2>/dev/null; then
        result_pass "ClamAV freshclam is enabled"
    else
        result_fail "ClamAV freshclam is not enabled" "$(systemctl is-enabled clamav-freshclam 2>/dev/null || echo 'not found')"
    fi

    # Automatic updates timer (various common names)
    local auto_update=false
    for timer in pacman-auto-update.timer arch-audit.timer unattended-upgrades.timer auto-update.timer; do
        if systemctl is-active --quiet "$timer" 2>/dev/null; then
            auto_update=true
            result_pass "Automatic updates timer is active ($timer)"
            break
        fi
    done
    if [[ "$auto_update" == false ]]; then
        result_fail "No automatic updates timer found" "checked: pacman-auto-update, arch-audit, unattended-upgrades, auto-update"
    fi

    # rkhunter timer
    if systemctl is-active --quiet rkhunter.timer 2>/dev/null; then
        result_pass "rkhunter timer is active"
    elif systemctl is-enabled --quiet rkhunter.timer 2>/dev/null; then
        result_warn "rkhunter timer is enabled but not active" "enabled"
    else
        result_fail "rkhunter timer is not active" "$(systemctl is-enabled rkhunter.timer 2>/dev/null || echo 'not found')"
    fi
}

# =============================================================================
# 7. BOOT SECURITY
# =============================================================================
check_boot_security() {
    category_header "Boot Security"

    # GRUB password
    local grub_password_set=false
    for f in /etc/grub.d/40_custom /boot/grub/grub.cfg; do
        if [[ -f "$f" ]] && grep -q "password_pbkdf2" "$f" 2>/dev/null; then
            grub_password_set=true
            break
        fi
    done
    if [[ "$grub_password_set" == true ]]; then
        result_pass "GRUB password is set (password_pbkdf2 found)"
    else
        result_fail "GRUB password not set — bootloader is unprotected" "password_pbkdf2 not found"
    fi

    # Kernel boot parameters
    local cmdline
    cmdline=$(cat /proc/cmdline 2>/dev/null || echo "")

    local params=("slab_nomerge" "init_on_alloc=1" "pti=on")
    for param in "${params[@]}"; do
        if echo "$cmdline" | grep -q "$param"; then
            result_pass "Kernel boot param: $param present"
        else
            result_fail "Kernel boot param: $param missing from /proc/cmdline" "$cmdline"
        fi
    done
}

# =============================================================================
# 8. DISABLED MODULES
# =============================================================================
check_disabled_modules() {
    category_header "Disabled Modules"

    local modules=("dccp" "sctp" "rds" "tipc")
    for mod in "${modules[@]}"; do
        local blacklisted=false
        if grep -rq "^\s*blacklist\s\+${mod}\b" /etc/modprobe.d/ 2>/dev/null; then
            blacklisted=true
        fi
        if grep -rq "^\s*install\s\+${mod}\s\+/bin/true\b\|^\s*install\s\+${mod}\s\+/bin/false\b" /etc/modprobe.d/ 2>/dev/null; then
            blacklisted=true
        fi

        if [[ "$blacklisted" == true ]]; then
            result_pass "Module $mod is blacklisted"
        else
            result_fail "Module $mod is not blacklisted in /etc/modprobe.d/" "not found"
        fi
    done
}

# =============================================================================
# OUTPUT: JSON
# =============================================================================
print_json() {
    local results_json=""
    local first=true
    for entry in "${JSON_RESULTS[@]}"; do
        if [[ "$first" == true ]]; then
            results_json="$entry"
            first=false
        else
            results_json="${results_json},${entry}"
        fi
    done

    local pct=0
    if [[ "$TOTAL_COUNT" -gt 0 ]]; then
        pct=$(( (PASS_COUNT * 100) / TOTAL_COUNT ))
    fi

    cat <<EOF
{
  "summary": {
    "total": ${TOTAL_COUNT},
    "pass": ${PASS_COUNT},
    "fail": ${FAIL_COUNT},
    "warn": ${WARN_COUNT},
    "score_percent": ${pct}
  },
  "results": [
    $(echo "$results_json" | sed 's/},{/},\n    {/g')
  ]
}
EOF
}

# =============================================================================
# OUTPUT: TEXT SUMMARY
# =============================================================================
print_summary() {
    local pct=0
    if [[ "$TOTAL_COUNT" -gt 0 ]]; then
        pct=$(( (PASS_COUNT * 100) / TOTAL_COUNT ))
    fi

    echo ""
    printf "%b=======================================%b\n" "$C_BLUE" "$C_NC"
    printf "%b         AUDIT SUMMARY                %b\n" "$C_BLUE" "$C_NC"
    printf "%b=======================================%b\n" "$C_BLUE" "$C_NC"
    echo ""
    printf "  Total checks:  %d\n" "$TOTAL_COUNT"
    printf "  %bPassed:        %d%b\n" "$C_GREEN"  "$PASS_COUNT" "$C_NC"
    printf "  %bFailed:        %d%b\n" "$C_RED"    "$FAIL_COUNT" "$C_NC"
    printf "  %bWarnings:      %d%b\n" "$C_YELLOW" "$WARN_COUNT" "$C_NC"
    echo ""
    printf "  Score: %b%d/%d (%d%%)%b\n" \
        "$(if [[ $pct -ge 90 ]]; then echo "$C_GREEN"; elif [[ $pct -ge 70 ]]; then echo "$C_YELLOW"; else echo "$C_RED"; fi)" \
        "$PASS_COUNT" "$TOTAL_COUNT" "$pct" "$C_NC"
    echo ""

    if [[ "$FAIL_COUNT" -eq 0 && "$WARN_COUNT" -eq 0 ]]; then
        printf "  %bAll checks passed. System is fully hardened.%b\n" "$C_GREEN" "$C_NC"
    elif [[ "$FAIL_COUNT" -eq 0 ]]; then
        printf "  %bNo failures, but %d warning(s) to review.%b\n" "$C_YELLOW" "$WARN_COUNT" "$C_NC"
    else
        printf "  %b%d check(s) failed. Review and remediate.%b\n" "$C_RED" "$FAIL_COUNT" "$C_NC"
        if [[ "$VERBOSE" == false ]]; then
            printf "  Tip: re-run with --verbose for details.\n"
        fi
    fi
    echo ""
}

# =============================================================================
# MAIN
# =============================================================================
main() {
    if [[ "$JSON_OUTPUT" == false ]]; then
        echo ""
        printf "%b=======================================%b\n" "$C_BLUE" "$C_NC"
        printf "%b  AwesomeArchLinux Hardening Audit     %b\n" "$C_BLUE" "$C_NC"
        printf "%b=======================================%b\n" "$C_BLUE" "$C_NC"
        printf "  Date: %s\n" "$(date '+%Y-%m-%d %H:%M:%S')"
        printf "  Host: %s\n" "$(hostname)"
        printf "  Kernel: %s\n" "$(uname -r)"
    fi

    check_kernel_hardening
    check_filesystem_security
    check_authentication
    check_ssh_hardening
    check_network_security
    check_service_security
    check_boot_security
    check_disabled_modules

    if [[ "$JSON_OUTPUT" == true ]]; then
        print_json
    else
        print_summary
    fi

    # Exit code: 0 if all pass, 1 if any fail
    if [[ "$FAIL_COUNT" -gt 0 ]]; then
        exit 1
    fi
    exit 0
}

main
