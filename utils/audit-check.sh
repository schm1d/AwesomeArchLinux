#!/usr/bin/env bash

# =============================================================================
# Script:      audit-check.sh
# Description: Hardening compliance checker for Arch Linux.
#              Validates that AwesomeArchLinux security hardening has been
#              correctly applied across sysctl, filesystem, authentication,
#              SSH, network, services, boot chain, disabled modules, and
#              optional workstation hardening.
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
#
# Usage:       sudo ./audit-check.sh [--verbose] [--json] [-h]
# =============================================================================

set -euo pipefail

readonly C_BLUE='\033[1;34m'
readonly C_RED='\033[1;31m'
readonly C_GREEN='\033[1;32m'
readonly C_YELLOW='\033[1;33m'
readonly C_NC='\033[0m'

VERBOSE=false
JSON_OUTPUT=false
PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0
TOTAL_COUNT=0

declare -a JSON_RESULTS=()
CURRENT_CATEGORY=""

msg()  { printf "%b[+]%b %s\n" "$C_GREEN"  "$C_NC" "$1"; }
info() { printf "%b[*]%b %s\n" "$C_BLUE"   "$C_NC" "$1"; }
warn() { printf "%b[!]%b %s\n" "$C_YELLOW" "$C_NC" "$1"; }
err()  { printf "%b[!]%b %s\n" "$C_RED"    "$C_NC" "$1" >&2; exit 1; }

resolve_hostname() {
    if [[ -n "${HOSTNAME:-}" ]]; then
        printf '%s' "$HOSTNAME"
    elif [[ -r /etc/hostname ]]; then
        tr -d '[:space:]' < /etc/hostname
    else
        uname -n
    fi
}

is_vps_profile() {
    if [[ -r /root/.install-env ]] && grep -qE 'INSTALL_TYPE=.*vps' /root/.install-env 2>/dev/null; then
        return 0
    fi
    if command -v systemd-detect-virt >/dev/null 2>&1 && systemd-detect-virt --quiet 2>/dev/null; then
        return 0
    fi
    return 1
}

json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\t'/\\t}"
    printf '"%s"' "$s"
}

result_pass() {
    local description="$1"
    (( ++TOTAL_COUNT ))
    (( ++PASS_COUNT ))
    if [[ "$JSON_OUTPUT" == false ]]; then
        printf "  %b[PASS]%b %s\n" "$C_GREEN" "$C_NC" "$description"
    fi
    JSON_RESULTS+=("{\"category\":$(json_escape "$CURRENT_CATEGORY"),\"status\":\"PASS\",\"description\":$(json_escape "$description")}")
}

result_fail() {
    local description="$1"
    local actual="${2:-}"
    (( ++TOTAL_COUNT ))
    (( ++FAIL_COUNT ))
    if [[ "$JSON_OUTPUT" == false ]]; then
        printf "  %b[FAIL]%b %s\n" "$C_RED" "$C_NC" "$description"
        if [[ "$VERBOSE" == true && -n "$actual" ]]; then
            printf "         %b=> actual: %s%b\n" "$C_YELLOW" "$actual" "$C_NC"
        fi
    fi
    JSON_RESULTS+=("{\"category\":$(json_escape "$CURRENT_CATEGORY"),\"status\":\"FAIL\",\"description\":$(json_escape "$description"),\"actual\":$(json_escape "$actual")}")
}

result_warn() {
    local description="$1"
    local actual="${2:-}"
    (( ++TOTAL_COUNT ))
    (( ++WARN_COUNT ))
    if [[ "$JSON_OUTPUT" == false ]]; then
        printf "  %b[WARN]%b %s\n" "$C_YELLOW" "$C_NC" "$description"
        if [[ "$VERBOSE" == true && -n "$actual" ]]; then
            printf "         %b=> actual: %s%b\n" "$C_YELLOW" "$actual" "$C_NC"
        fi
    fi
    JSON_RESULTS+=("{\"category\":$(json_escape "$CURRENT_CATEGORY"),\"status\":\"WARN\",\"description\":$(json_escape "$description"),\"actual\":$(json_escape "$actual")}")
}

category_header() {
    CURRENT_CATEGORY="$1"
    if [[ "$JSON_OUTPUT" == false ]]; then
        echo ""
        printf "%b=== %s ===%b\n" "$C_BLUE" "$1" "$C_NC"
    fi
}

check_sysctl() {
    local key="$1"
    local expected="$2"
    local description="$3"
    local mode="${4:-exact}"

    local actual
    if actual=$(sysctl -n "$key" 2>/dev/null); then
        if [[ "$mode" == "min" ]]; then
            if [[ "$actual" =~ ^-?[0-9]+$ ]] && (( actual >= expected )); then
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

check_sysctl_one_of() {
    local key="$1"
    local expected_values="$2"
    local description="$3"
    local actual

    if actual=$(sysctl -n "$key" 2>/dev/null); then
        case ",${expected_values}," in
            *",${actual},"*)
                result_pass "$description ($key = $actual)"
                ;;
            *)
                result_fail "$description ($key should be one of: $expected_values)" "$actual"
                ;;
        esac
    else
        result_fail "$description ($key not available)" "sysctl key not found"
    fi
}

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
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --verbose)    VERBOSE=true; shift ;;
        --json)       JSON_OUTPUT=true; shift ;;
        -h|--help)    usage ;;
        *)            err "Unknown option: $1. See -h for help." ;;
    esac
done

[[ $(id -u) -eq 0 ]] || err "Must be run as root (use sudo)"

# =============================================================================
# 1. KERNEL HARDENING (sysctl)
# =============================================================================
check_kernel_hardening() {
    category_header "Kernel Hardening (sysctl)"

    check_sysctl "kernel.dmesg_restrict" "1" "Dmesg access restricted to root"
    check_sysctl "fs.protected_hardlinks" "1" "Protected hardlinks enabled"
    check_sysctl "fs.protected_symlinks" "1" "Protected symlinks enabled"
    check_sysctl "fs.protected_fifos" "2" "Protected FIFOs enabled"
    check_sysctl "fs.protected_regular" "2" "Protected regular files in sticky dirs enabled"
    check_sysctl "fs.suid_dumpable" "0" "SUID core dumps disabled"

    if [[ -f /etc/sysctl.d/90-awesome-strict.conf ]]; then
        check_sysctl "kernel.kptr_restrict" "2" "Strict kernel pointer restriction"
        check_sysctl "kernel.yama.ptrace_scope" "2" "Strict ptrace restriction" "min"
        check_sysctl "kernel.kexec_load_disabled" "1" "Strict kexec loading disabled"
        check_sysctl "kernel.unprivileged_bpf_disabled" "1" "Strict unprivileged BPF policy"
        check_sysctl "net.ipv4.conf.all.rp_filter" "1" "Strict reverse path filtering"
    else
        check_sysctl "kernel.kptr_restrict" "1" "Kernel pointer restriction" "min"
        check_sysctl "kernel.yama.ptrace_scope" "1" "Compatible ptrace restriction" "min"
        check_sysctl_one_of "kernel.unprivileged_bpf_disabled" "1,2" "Unprivileged BPF restricted"
        check_sysctl "net.ipv4.conf.all.rp_filter" "2" "VPN-compatible reverse path filtering"
    fi

    check_sysctl "net.ipv4.tcp_syncookies" "1" "TCP SYN cookies enabled"
    check_sysctl "net.ipv4.conf.all.accept_redirects" "0" "ICMP redirects disabled (accept)"
    check_sysctl "net.ipv4.conf.all.send_redirects" "0" "ICMP redirects disabled (send)"

    local ip_fwd
    ip_fwd=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "unknown")
    if [[ "$ip_fwd" == "0" ]]; then
        result_pass "IP forwarding disabled (net.ipv4.ip_forward = 0)"
    elif [[ "$ip_fwd" == "1" ]]; then
        result_warn "IP forwarding is enabled — may be intentional for VPN/Docker" "$ip_fwd"
    else
        result_fail "Could not read net.ipv4.ip_forward" "$ip_fwd"
    fi

    if [[ -f /etc/sysctl.d/90-awesome-ipv6-disabled.conf ]]; then
        check_sysctl "net.ipv6.conf.all.disable_ipv6" "1" "Selected IPv6-disable policy enforced"
    else
        check_sysctl "net.ipv6.conf.all.disable_ipv6" "0" "IPv6 enabled by selected policy"
        check_sysctl "net.ipv6.conf.all.accept_redirects" "0" "IPv6 redirects disabled"
        check_sysctl "net.ipv6.conf.all.accept_source_route" "-1" "All IPv6 source-routing headers rejected"
    fi

    check_sysctl "kernel.randomize_va_space" "2" "Full ASLR enabled"
}

# =============================================================================
# 2. FILESYSTEM SECURITY
# =============================================================================
check_filesystem_security() {
    category_header "Filesystem Security"

    check_mount_opts() {
        local mpoint="$1"
        local required_opts="$2"
        local description="$3"
        local warn_on_noexec="${4:-false}"

        local mount_line
        mount_line=$(findmnt -n -o OPTIONS "$mpoint" 2>/dev/null || echo "")

        if [[ -z "$mount_line" ]]; then
            result_fail "$description — $mpoint not found as a separate mount" "not mounted"
            return
        fi

        local all_present=true
        local missing=""
        local -a OPTS=()
        IFS=',' read -ra OPTS <<< "$required_opts"
        for opt in "${OPTS[@]}"; do
            if [[ ",$mount_line," != *",$opt,"* ]]; then
                all_present=false
                missing="${missing:+$missing, }$opt"
            fi
        done

        if [[ "$all_present" == true ]]; then
            result_pass "$description ($mpoint has $required_opts)"
        elif [[ "$warn_on_noexec" == true && "$missing" == "noexec" ]]; then
            result_warn "$description — $mpoint omits noexec on VPS profile" "$mount_line"
        else
            result_fail "$description — missing: $missing" "$mount_line"
        fi
    }

    if is_vps_profile; then
        check_mount_opts "/tmp" "nosuid,nodev,noexec" "/tmp mount hardened" "true"
    else
        check_mount_opts "/tmp" "nosuid,nodev,noexec" "/tmp mount hardened" "false"
    fi

    local tmp_source="" tmp_fstype="" tmp_size_bytes=""
    read -r tmp_source tmp_fstype < <(findmnt -n -o SOURCE,FSTYPE /tmp 2>/dev/null || true) || true
    if [[ "$tmp_fstype" == "tmpfs" ]]; then
        tmp_size_bytes=$(findmnt -n -b -o SIZE /tmp 2>/dev/null || true)
    elif [[ "$tmp_source" == /dev/* ]]; then
        tmp_size_bytes=$(lsblk -b -n -o SIZE "$tmp_source" 2>/dev/null | head -1 || true)
    fi
    if [[ ! "$tmp_size_bytes" =~ ^[0-9]+$ ]]; then
        tmp_size_bytes=$(findmnt -n -b -o SIZE /tmp 2>/dev/null || true)
    fi

    if [[ "$tmp_size_bytes" =~ ^[0-9]+$ ]] && (( tmp_size_bytes >= 10 * 1073741824 )); then
        result_pass "/tmp capacity is at least 10 GiB ($((tmp_size_bytes / 1073741824)) GiB)"
    else
        result_fail "/tmp capacity should be at least 10 GiB" "${tmp_size_bytes:-unknown} bytes"
    fi

    check_mount_opts "/dev/shm" "nosuid,nodev,noexec" "/dev/shm mount hardened"

    local proc_opts
    proc_opts=$(findmnt -n -o OPTIONS /proc 2>/dev/null || echo "")
    if [[ "$proc_opts" == *hidepid=2* || "$proc_opts" == *hidepid=invisible* ]]; then
        result_pass "/proc mounted with hidepid (${proc_opts})"
    else
        result_fail "/proc should have hidepid=2" "$proc_opts"
    fi

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

    if [[ -f /etc/login.defs ]]; then
        local umask_val
        umask_val=$(awk '/^[[:space:]]*UMASK[[:space:]]+/ { val = $2 } END { print val }' /etc/login.defs 2>/dev/null)
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

    local faillock_found=false
    if grep -rq "pam_faillock" /etc/pam.d/ 2>/dev/null || [[ -f /etc/security/faillock.conf ]]; then
        faillock_found=true
    fi
    if [[ "$faillock_found" == true ]]; then
        result_pass "PAM faillock is configured"
    else
        result_fail "PAM faillock is not configured" "not found in /etc/pam.d/ or /etc/security/faillock.conf"
    fi

    local pwquality_configured=false
    local minlen_val=""
    if grep -rq "pam_pwquality" /etc/pam.d/ 2>/dev/null; then
        pwquality_configured=true
    fi
    if [[ -f /etc/security/pwquality.conf ]]; then
        minlen_val=$(awk -F= '/^[[:space:]]*minlen[[:space:]]*=/ { gsub(/[[:space:]]/, "", $2); val = $2 } END { print val }' /etc/security/pwquality.conf 2>/dev/null)
    fi

    if [[ "$pwquality_configured" == true && "$minlen_val" =~ ^[0-9]+$ ]] && (( minlen_val >= 12 )); then
        result_pass "PAM pwquality configured with minlen = $minlen_val (>= 12)"
    elif [[ "$pwquality_configured" == true && -n "$minlen_val" ]]; then
        result_fail "PAM pwquality minlen should be >= 12" "minlen = $minlen_val"
    elif [[ "$pwquality_configured" == true ]]; then
        result_warn "PAM pwquality module loaded but minlen not set in pwquality.conf" ""
    else
        result_fail "PAM pwquality is not configured" "not found"
    fi

    if [[ -f /etc/login.defs ]]; then
        local hash_algo
        hash_algo=$(awk '/^[[:space:]]*ENCRYPT_METHOD[[:space:]]+/ { val = $2 } END { print val }' /etc/login.defs 2>/dev/null)
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

    if [[ -f /etc/securetty ]] || grep -rq "pam_securetty" /etc/pam.d/ 2>/dev/null; then
        if [[ -f /etc/securetty ]]; then
            local tty_count
            tty_count=$(grep -cve '^[[:space:]]*$' -e '^[[:space:]]*#' /etc/securetty 2>/dev/null || true)
            tty_count="${tty_count:-0}"
            if (( tty_count == 0 )); then
                result_pass "/etc/securetty exists and is empty (no direct root TTY login)"
            elif (( tty_count <= 2 )); then
                result_pass "/etc/securetty is restrictive ($tty_count entries)"
            else
                result_warn "/etc/securetty has $tty_count entries — consider restricting" "$tty_count entries"
            fi
        else
            result_warn "pam_securetty referenced in /etc/pam.d/ without /etc/securetty" "file missing"
        fi
    fi
}

# =============================================================================
# 4. SSH HARDENING
# =============================================================================
check_ssh_hardening() {
    category_header "SSH Hardening"

    local sshd_config="/etc/ssh/sshd_config"
    local sshd_config_d="/etc/ssh/sshd_config.d"

    if [[ ! -f "$sshd_config" ]]; then
        result_warn "sshd_config not found — SSH may not be installed" "file missing"
        return
    fi

    local sshd_effective=""
    if command -v sshd >/dev/null 2>&1; then
        sshd_effective="$(sshd -T 2>/dev/null || true)"
    fi

    # OpenSSH uses first-match-wins across included *.conf files then sshd_config.
    get_ssh_setting() {
        local key="$1"
        if [[ -n "$sshd_effective" ]]; then
            local eff
            eff=$(awk -v k="${key,,}" '$1 == k { print $2; exit }' <<<"$sshd_effective")
            if [[ -n "$eff" ]]; then
                printf '%s' "$eff"
                return
            fi
        fi

        local -a files=()
        if [[ -d "$sshd_config_d" ]]; then
            shopt -s nullglob
            files=("$sshd_config_d"/*.conf)
            shopt -u nullglob
        fi
        files+=("$sshd_config")

        awk -v k="${key,,}" '
            /^[[:space:]]*#/ || NF < 2 { next }
            tolower($1) == k { print $2; exit }
        ' "${files[@]}" 2>/dev/null || true
    }

    local val disable_fwd
    disable_fwd="$(get_ssh_setting "DisableForwarding")"

    val="$(get_ssh_setting "PermitRootLogin")"
    if [[ "${val,,}" == "no" ]]; then
        result_pass "PermitRootLogin = no"
    elif [[ -n "$val" ]]; then
        result_fail "PermitRootLogin should be no" "$val"
    else
        result_fail "PermitRootLogin not explicitly set" "not set"
    fi

    val="$(get_ssh_setting "PasswordAuthentication")"
    if [[ "${val,,}" == "no" ]]; then
        result_pass "PasswordAuthentication = no"
    elif [[ -n "$val" ]]; then
        result_fail "PasswordAuthentication should be no" "$val"
    else
        result_warn "PasswordAuthentication not explicitly set (default: yes)" "not set"
    fi

    val="$(get_ssh_setting "X11Forwarding")"
    if [[ "${val,,}" == "no" || "${disable_fwd,,}" == "yes" ]]; then
        result_pass "X11Forwarding disabled (${val:-DisableForwarding=yes})"
    elif [[ -n "$val" ]]; then
        result_fail "X11Forwarding should be no" "$val"
    else
        result_pass "X11Forwarding not set (default: no)"
    fi

    val="$(get_ssh_setting "Protocol")"
    if [[ -z "$val" || "$val" == "2" ]]; then
        result_pass "SSH Protocol = 2 (${val:-default})"
    else
        result_fail "SSH Protocol should be 2" "$val"
    fi

    val="$(get_ssh_setting "MaxAuthTries")"
    if [[ "$val" =~ ^[0-9]+$ ]] && (( val <= 3 )); then
        result_pass "MaxAuthTries = $val (<= 3)"
    elif [[ -n "$val" ]]; then
        result_fail "MaxAuthTries should be <= 3" "$val"
    else
        result_fail "MaxAuthTries not set (default: 6)" "not set"
    fi

    val="$(get_ssh_setting "AllowTcpForwarding")"
    if [[ "${val,,}" == "no" || "${disable_fwd,,}" == "yes" ]]; then
        result_pass "TCP forwarding disabled (${val:+AllowTcpForwarding=$val}${val:-DisableForwarding=yes})"
    elif [[ -n "$val" ]]; then
        result_fail "AllowTcpForwarding should be no (or DisableForwarding yes)" "$val"
    else
        result_fail "TCP forwarding not disabled" "not set"
    fi

    val="$(get_ssh_setting "AllowAgentForwarding")"
    if [[ "${val,,}" == "no" || "${disable_fwd,,}" == "yes" ]]; then
        result_pass "Agent forwarding disabled (${val:+AllowAgentForwarding=$val}${val:-DisableForwarding=yes})"
    elif [[ -n "$val" ]]; then
        result_fail "AllowAgentForwarding should be no (or DisableForwarding yes)" "$val"
    else
        result_fail "Agent forwarding not disabled" "not set"
    fi
}

# =============================================================================
# 5. NETWORK SECURITY
# =============================================================================
check_network_security() {
    category_header "Network Security"

    if systemctl is-active --quiet nftables 2>/dev/null; then
        result_pass "Firewall is active (nftables)"
    elif systemctl is-active --quiet firehol 2>/dev/null; then
        result_pass "Firewall is active (FireHOL)"
    elif systemctl is-active --quiet iptables 2>/dev/null; then
        result_pass "Firewall is active (iptables fallback)"
    else
        result_fail "No host firewall service is active" \
            "nftables=$(systemctl is-active nftables 2>/dev/null || echo 'inactive'), firehol=$(systemctl is-active firehol 2>/dev/null || echo 'inactive'), iptables=$(systemctl is-active iptables 2>/dev/null || echo 'inactive')"
    fi

    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        result_pass "fail2ban is active"
    elif systemctl is-active --quiet crowdsec 2>/dev/null; then
        result_pass "CrowdSec IDS is active"
    else
        result_fail "fail2ban is not active" "$(systemctl is-active fail2ban 2>/dev/null || echo 'not found')"
    fi

    local dot_setting
    dot_setting=$(grep -hE '^[[:space:]]*DNSOverTLS[[:space:]]*=[[:space:]]*(yes|opportunistic)' \
        /etc/systemd/resolved.conf.d/*.conf /etc/systemd/resolved.conf 2>/dev/null | tail -n1 || true)
    if systemctl is-active --quiet systemd-resolved 2>/dev/null && [[ -n "$dot_setting" ]]; then
        result_pass "DNS-over-TLS via systemd-resolved is active"
    elif systemctl is-active --quiet stubby 2>/dev/null; then
        result_pass "DNS-over-TLS via stubby (opt-in) is active"
    else
        result_fail "DNS-over-TLS is not active" \
            "resolved=$(systemctl is-active systemd-resolved 2>/dev/null || echo 'not found'), stubby=$(systemctl is-active stubby 2>/dev/null || echo 'not found'), DoT=${dot_setting:-missing}"
    fi

    local unexpected
    unexpected=$(ss -tlnpH 2>/dev/null \
        | awk '$4 ~ /^(0\.0\.0\.0:|\[::\]:|\*:)/ && $0 !~ /users:\(\("(sshd|stubby|systemd-resolve)"/ { print }' || true)

    if [[ -z "$unexpected" ]]; then
        result_pass "No unexpected TCP services listening on wildcard addresses (0.0.0.0 / [::])"
    else
        local count
        count=$(awk 'END { print NR }' <<<"$unexpected")
        result_warn "$count unexpected service(s) listening on wildcard addresses" "$unexpected"
    fi
}

# =============================================================================
# 6. SERVICE SECURITY
# =============================================================================
check_service_security() {
    category_header "Service Security"

    local failed_units verify_output unit
    local -a hardened_units=(
        sshd.service
        NetworkManager.service
        auditd.service
        clamav-daemon.service
        fail2ban.service
        chronyd.service
        usbguard.service
        bluetooth.service
        awesome-board-health.service
    )

    failed_units=$(systemctl --failed --no-legend --plain 2>/dev/null || true)
    if [[ -z "$failed_units" ]]; then
        result_pass "No failed systemd units"
    else
        result_fail "One or more systemd units are failed" "$failed_units"
    fi

    for unit in "${hardened_units[@]}"; do
        if ! systemctl cat "$unit" >/dev/null 2>&1; then
            continue
        fi
        if verify_output=$(systemd-analyze verify "$unit" 2>&1); then
            result_pass "Merged systemd unit is valid ($unit)"
        else
            result_fail "Merged systemd unit is invalid ($unit)" "$verify_output"
        fi
    done

    probe_active_service() {
        local service="$1"
        local description="$2"
        shift 2
        local probe_output

        if ! systemctl cat "$service" >/dev/null 2>&1; then
            return
        fi
        if ! systemctl is-active --quiet "$service" 2>/dev/null; then
            result_warn "$description was not tested because $service is inactive" \
                "$(systemctl is-active "$service" 2>/dev/null || echo unknown)"
            return
        fi
        if ! command -v "$1" >/dev/null 2>&1; then
            result_fail "$description could not be tested" "missing command: $1"
            return
        fi
        if probe_output=$("$@" 2>&1); then
            result_pass "$description"
        else
            result_fail "$description failed" "${probe_output:0:500}"
        fi
    }

    probe_active_service sshd.service "sshd accepts its installed configuration" sshd -t
    probe_active_service NetworkManager.service "NetworkManager responds over its control interface" nmcli general status
    probe_active_service clamav-daemon.service "ClamAV daemon answers a ping" clamdscan --ping 5
    probe_active_service fail2ban.service "fail2ban daemon answers a ping" fail2ban-client ping
    probe_active_service chronyd.service "chronyd answers a tracking query" chronyc tracking
    probe_active_service usbguard.service "USBGuard IPC policy permits root device listing" usbguard list-devices

    # Verify auditd is both enabled and actively enforcing kernel audit rules
    if systemctl is-enabled --quiet auditd 2>/dev/null; then
        result_pass "auditd is enabled"
    else
        result_fail "auditd is not enabled" "$(systemctl is-enabled auditd 2>/dev/null || echo 'not found')"
    fi
    if command -v auditctl >/dev/null 2>&1 && systemctl is-active --quiet auditd 2>/dev/null; then
        local audit_status
        audit_status="$(auditctl -s 2>/dev/null || true)"
        if grep -qE '^enabled [12]\b' <<<"$audit_status"; then
            result_pass "Kernel audit subsystem is active ($(awk '/^enabled / { print $1"="$2 }' <<<"$audit_status"))"
        else
            result_fail "auditd is running but kernel auditing is disabled (enabled 0)" "$audit_status"
        fi
    fi

    # Journal sealing check
    if [[ -r /etc/machine-id ]]; then
        local mid
        mid="$(tr -d '[:space:]' < /etc/machine-id)"
        if [[ -n "$mid" && -f "/var/log/journal/${mid}/fss" ]]; then
            result_pass "Systemd journal Forward Secure Sealing (FSS) state is initialized"
            if compgen -G "/root/journal-sealing/verification-*.txt" >/dev/null; then
                result_warn "Journal sealing verification key is still stored locally in /root/journal-sealing/" \
                    "export off-machine and remove local copy"
            fi
        else
            result_warn "Journal FSS sealing file not found under /var/log/journal/${mid:-unknown}" "fss missing"
        fi
    fi

    # AppArmor: verify kernel LSM parameter as well as unit state
    local aa_kernel="N"
    if [[ -r /sys/module/apparmor/parameters/enabled ]]; then
        aa_kernel="$(tr -d '[:space:]' < /sys/module/apparmor/parameters/enabled)"
    fi
    if [[ "$aa_kernel" == "Y" ]] && systemctl is-active --quiet apparmor 2>/dev/null; then
        result_pass "AppArmor LSM is active in kernel and apparmor.service is active"
    elif systemctl is-enabled --quiet apparmor 2>/dev/null; then
        result_warn "apparmor.service is enabled, but AppArmor kernel LSM is not active yet" \
            "run hardening/apparmor/apparmor.sh and reboot"
    else
        result_warn "AppArmor MAC is not enabled (opt-in via hardening/apparmor/apparmor.sh)" \
            "kernel=${aa_kernel}"
    fi

    if systemctl is-enabled --quiet clamav-freshclam 2>/dev/null || systemctl is-enabled --quiet clamav-freshclam-once.timer 2>/dev/null; then
        result_pass "ClamAV signature updater is enabled"
    else
        result_fail "ClamAV freshclam is not enabled" "$(systemctl is-enabled clamav-freshclam 2>/dev/null || echo 'not found')"
    fi

    local auto_update=false
    for timer in pacman-autoupdate.timer pacman-auto-update.timer arch-audit.timer unattended-upgrades.timer auto-update.timer; do
        if systemctl is-active --quiet "$timer" 2>/dev/null; then
            auto_update=true
            result_pass "Package update/security audit timer is active ($timer)"
            break
        fi
    done
    if [[ "$auto_update" == false ]]; then
        result_fail "No package update/security audit timer found" "checked: pacman-autoupdate, arch-audit"
    fi

    local rkhunter_timer=""
    for timer in rkhunter-check.timer rkhunter.timer; do
        if systemctl is-active --quiet "$timer" 2>/dev/null; then
            rkhunter_timer="$timer"
            result_pass "rkhunter timer is active ($timer)"
            break
        fi
        if [[ -z "$rkhunter_timer" ]] && systemctl is-enabled --quiet "$timer" 2>/dev/null; then
            rkhunter_timer="$timer"
        fi
    done
    if [[ -n "$rkhunter_timer" ]] && ! systemctl is-active --quiet "$rkhunter_timer" 2>/dev/null; then
        result_warn "rkhunter timer is enabled but not active" "$rkhunter_timer"
    elif [[ -z "$rkhunter_timer" ]]; then
        result_fail "rkhunter timer is not active" "checked: rkhunter-check.timer, rkhunter.timer"
    fi
}

# =============================================================================
# 7. BOOT SECURITY
# =============================================================================
check_boot_security() {
    category_header "Boot Security"

    local boot_protected=false boot_evidence="" is_uki=false
    if [[ -f /efi/EFI/Linux/arch-linux.efi ]]; then
        is_uki=true
    fi

    for f in /etc/grub.d/40_custom /boot/grub/grub.cfg; do
        if [[ -f "$f" ]] && grep -q "password_pbkdf2" "$f" 2>/dev/null; then
            boot_protected=true
            boot_evidence="GRUB password set (password_pbkdf2 in $f)"
            break
        fi
    done

    if [[ "$boot_protected" == false ]]; then
        for f in /efi/loader/loader.conf /boot/loader/loader.conf; do
            if [[ -f "$f" ]] && grep -qE '^[[:space:]]*editor[[:space:]]+(no|0|false)([[:space:]]|$)' "$f" 2>/dev/null; then
                boot_protected=true
                boot_evidence="systemd-boot editor disabled (editor no in $f)"
                break
            fi
        done
    fi

    if [[ "$boot_protected" == true ]]; then
        result_pass "Bootloader console access is restricted — $boot_evidence"
    elif is_vps_profile; then
        result_warn "Bootloader console password not set (expected on headless VPS profile)" "VPS profile"
    else
        result_fail "Bootloader console access is unrestricted" \
            "neither password_pbkdf2 (GRUB) nor 'editor no' (systemd-boot) found"
    fi

    if [[ "$is_uki" == true ]] && command -v sbctl >/dev/null 2>&1; then
        local sb_status
        sb_status="$(sbctl status 2>/dev/null || true)"
        if grep -qE 'Secure Boot:[[:space:]]*.*[Ee]nabled' <<<"$sb_status" && \
           grep -qE 'Setup Mode:[[:space:]]*.*[Dd]isabled' <<<"$sb_status"; then
            result_pass "UEFI Secure Boot is enabled and enforcing (Setup Mode disabled)"
        else
            result_warn "UKI profile detected, but Secure Boot is not yet enforcing" \
                "run 'awesome-secureboot status' / 'enroll-keys'"
        fi
    fi

    local cmdline
    cmdline=$(cat /proc/cmdline 2>/dev/null || echo "")

    local params=(
        "slab_nomerge"
        "init_on_alloc=1"
        "init_on_free=1"
        "page_alloc.shuffle=1"
        "pti=on"
        "randomize_kstack_offset=on"
        "vsyscall=none"
    )
    for param in "${params[@]}"; do
        if [[ " $cmdline " == *" $param "* ]]; then
            result_pass "Kernel boot param: $param present"
        elif [[ -r /root/.install-env ]] && grep -q 'INSTALL_TYPE=.*vps-harden' /root/.install-env 2>/dev/null; then
            result_warn "Kernel boot param: $param missing (live VPS hardening preserves provider bootloader)" "$cmdline"
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
        if grep -rq "^[[:space:]]*blacklist[[:space:]]\+${mod}\b" /etc/modprobe.d/ 2>/dev/null ||
           grep -rq "^[[:space:]]*install[[:space:]]\+${mod}[[:space:]]\+/bin/\(true\|false\)\b" /etc/modprobe.d/ 2>/dev/null; then
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
# 9. OPTIONAL WORKSTATION / DESKTOP HARDENING
# =============================================================================
check_optional_hardening() {
    category_header "Optional Workstation Hardening"

    if grep -Rlq 'pam_u2f' /etc/pam.d 2>/dev/null; then
        result_pass "pam_u2f is wired into at least one PAM stack"
    else
        result_warn "No pam_u2f mapping — hardware keys are not required for local login" \
            "run hardening/u2f/u2f.sh --enroll"
    fi

    if grep -Eq 'pam_google_authenticator' /etc/pam.d/sshd 2>/dev/null; then
        result_pass "SSH TOTP (pam_google_authenticator) is configured"
    else
        result_warn "SSH TOTP is not configured" "run hardening/totp/totp.sh"
    fi

    local scan_rand=""
    scan_rand=$(grep -hR '^[[:space:]]*wifi.scan-rand-mac-address=' /etc/NetworkManager/conf.d/ 2>/dev/null | tail -1 || true)
    if [[ "$scan_rand" == *=yes* ]]; then
        result_pass "NetworkManager randomizes Wi-Fi scan MAC addresses"
    elif [[ ! -d /etc/NetworkManager ]]; then
        result_warn "NetworkManager is not installed — skipping Wi-Fi privacy checks" "no NM"
    else
        result_warn "wifi.scan-rand-mac-address is not explicit" "${scan_rand:-unset}"
    fi

    if [[ -f /etc/firefox/policies/policies.json ]]; then
        result_pass "Firefox enterprise policies are present"
    elif command -v firefox >/dev/null 2>&1; then
        result_warn "Firefox installed without enterprise policies" "run hardening/browser/browser.sh --firefox"
    fi

    if compgen -G '/etc/chromium/policies/managed/*.json' >/dev/null ||
       compgen -G '/etc/brave/policies/managed/*.json' >/dev/null; then
        result_pass "Chromium/Brave managed enterprise policies are present"
    elif command -v chromium >/dev/null 2>&1 || command -v brave >/dev/null 2>&1; then
        result_warn "Chromium/Brave installed without managed policies" "run hardening/browser/browser.sh or utils/brave.sh --policy"
    fi

    if grep -qw sme /proc/cpuinfo 2>/dev/null && grep -qw 'mem_encrypt=on' /proc/cmdline 2>/dev/null; then
        result_pass "AMD SME is advertised and mem_encrypt=on is on the cmdline"
    elif grep -qw tme /proc/cpuinfo 2>/dev/null || grep -qw tme_en /proc/cpuinfo 2>/dev/null; then
        result_warn "Intel TME flag present — confirm it is enabled in firmware" "firmware-controlled"
    else
        result_warn "No SME/TME memory encryption active (opt-in via hardening/memcrypt/)" "not configured"
    fi

    if [[ -f /etc/systemd/zram-generator.conf ]] || swapon --show=NAME 2>/dev/null | grep -q zram; then
        result_pass "zram is configured"
    else
        result_warn "zram-generator is not configured" "run utils/zram.sh"
    fi

    if [[ -f /etc/udev/rules.d/60-awesome-ioschedulers.rules ]]; then
        result_pass "I/O scheduler udev rule is installed"
    else
        result_warn "No I/O scheduler udev rule" "run utils/iosched.sh"
    fi

    if [[ -f /etc/environment.d/20-vaapi.conf ]]; then
        result_pass "VA-API environment drop-in is present"
    elif ! is_vps_profile; then
        local gpu_lines gpu_vendors=0
        gpu_lines=$(lspci 2>/dev/null | grep -Ei 'VGA|3D|Display' || true)
        grep -qi intel <<<"$gpu_lines" && (( ++gpu_vendors ))
        grep -qiE 'amd|radeon' <<<"$gpu_lines" && (( ++gpu_vendors ))
        grep -qi nvidia <<<"$gpu_lines" && (( ++gpu_vendors ))
        if (( gpu_vendors == 1 )); then
            result_warn "No VA-API environment drop-in" "run utils/vaapi.sh"
        fi
    fi

    local userns
    userns=$(sysctl -n kernel.unprivileged_userns_clone 2>/dev/null || echo "")
    if [[ "$userns" == "0" ]]; then
        result_warn "unprivileged user namespaces disabled — Chromium/Brave/Podman userns sandboxes degrade" \
            "kernel.unprivileged_userns_clone=0"
    elif [[ "$userns" == "1" ]]; then
        result_pass "unprivileged user namespaces enabled (browser/Podman sandboxes supported)"
    fi
}

# =============================================================================
# OUTPUT
# =============================================================================
print_json() {
    local pct=0
    if (( TOTAL_COUNT > 0 )); then
        pct=$(( (PASS_COUNT * 100) / TOTAL_COUNT ))
    fi

    printf '{\n'
    printf '  "summary": {\n'
    printf '    "total": %d,\n' "$TOTAL_COUNT"
    printf '    "pass": %d,\n' "$PASS_COUNT"
    printf '    "fail": %d,\n' "$FAIL_COUNT"
    printf '    "warn": %d,\n' "$WARN_COUNT"
    printf '    "score_percent": %d\n' "$pct"
    printf '  },\n'
    printf '  "results": [\n'
    local idx last=$(( ${#JSON_RESULTS[@]} - 1 ))
    for idx in "${!JSON_RESULTS[@]}"; do
        if (( idx < last )); then
            printf '    %s,\n' "${JSON_RESULTS[idx]}"
        else
            printf '    %s\n' "${JSON_RESULTS[idx]}"
        fi
    done
    printf '  ]\n'
    printf '}\n'
}

print_summary() {
    local pct=0
    if (( TOTAL_COUNT > 0 )); then
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
    local score_color="$C_RED"
    if (( pct >= 90 )); then
        score_color="$C_GREEN"
    elif (( pct >= 70 )); then
        score_color="$C_YELLOW"
    fi
    printf "  Score: %b%d/%d (%d%%)%b\n" "$score_color" "$PASS_COUNT" "$TOTAL_COUNT" "$pct" "$C_NC"
    echo ""

    if (( FAIL_COUNT == 0 && WARN_COUNT == 0 )); then
        printf "  %bAll checks passed. System is fully hardened.%b\n" "$C_GREEN" "$C_NC"
    elif (( FAIL_COUNT == 0 )); then
        printf "  %bNo failures, but %d warning(s) to review.%b\n" "$C_YELLOW" "$WARN_COUNT" "$C_NC"
    else
        printf "  %b%d check(s) failed. Review and remediate.%b\n" "$C_RED" "$FAIL_COUNT" "$C_NC"
        if [[ "$VERBOSE" == false ]]; then
            printf "  Tip: re-run with --verbose for details.\n"
        fi
    fi
    echo ""
}

main() {
    if [[ "$JSON_OUTPUT" == false ]]; then
        echo ""
        printf "%b=======================================%b\n" "$C_BLUE" "$C_NC"
        printf "%b  AwesomeArchLinux Hardening Audit     %b\n" "$C_BLUE" "$C_NC"
        printf "%b=======================================%b\n" "$C_BLUE" "$C_NC"
        printf "  Date:   %s\n" "$(date '+%Y-%m-%d %H:%M:%S')"
        printf "  Host:   %s\n" "$(resolve_hostname)"
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
    check_optional_hardening

    if [[ "$JSON_OUTPUT" == true ]]; then
        print_json
    else
        print_summary
    fi

    if (( FAIL_COUNT > 0 )); then
        exit 1
    fi
    exit 0
}

main
