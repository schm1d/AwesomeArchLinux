#!/usr/bin/env bash

# =============================================================================
# Script:      memcrypt.sh
# Description: Detects AMD SME / Intel TME capability and, only with --enable,
#              injects mem_encrypt=on into GRUB or systemd-boot. Never runs as
#              part of the unattended installer.
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
# =============================================================================

set -euo pipefail

readonly C_BLUE='\033[1;34m'
readonly C_RED='\033[1;31m'
readonly C_GREEN='\033[1;32m'
readonly C_YELLOW='\033[1;33m'
readonly C_NC='\033[0m'

msg()  { printf "%b[+]%b %s\n" "$C_GREEN" "$C_NC" "$1"; }
info() { printf "%b[*]%b %s\n" "$C_BLUE"  "$C_NC" "$1"; }
warn() { printf "%b[!]%b %s\n" "$C_YELLOW" "$C_NC" "$1"; }
err()  { printf "%b[!]%b %s\n" "$C_RED"   "$C_NC" "$1" >&2; exit 1; }

DO_STATUS=false
DO_ENABLE=false
DO_DISABLE=false

usage() {
    cat <<EOF
Usage: sudo $0 [--status] [--enable] [--disable] [-h]

--enable is automated for AMD SME only. Intel TME is firmware-controlled.
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --status)   DO_STATUS=true; shift ;;
        --enable)   DO_ENABLE=true; shift ;;
        --disable)  DO_DISABLE=true; shift ;;
        -h|--help)  usage ;;
        *)          err "Unknown option: $1" ;;
    esac
done

[[ $(id -u) -eq 0 ]] || err "Must be run as root"

if [[ "$DO_ENABLE" == false && "$DO_DISABLE" == false ]]; then
    DO_STATUS=true
fi

has_flag() { grep -qw "$1" /proc/cpuinfo; }

vendor() {
    if grep -qi 'AuthenticAMD' /proc/cpuinfo; then
        printf 'amd'
    elif grep -qi 'GenuineIntel' /proc/cpuinfo; then
        printf 'intel'
    else
        printf 'other'
    fi
}

sme_active() {
    if dmesg 2>/dev/null | grep -qiE 'AMD Memory Encryption Features active: SME'; then
        return 0
    fi
    grep -qw sme /proc/cpuinfo && grep -q 'mem_encrypt=on' /proc/cmdline
}

probe() {
    local v
    v=$(vendor)
    info "CPU vendor: $v"
    for f in sme sev sev_es sev_snp tme tme_en; do
        if has_flag "$f"; then
            msg "  $f is present"
        else
            info "  $f is absent"
        fi
    done
    echo
    if [[ "$v" == "amd" ]]; then
        if has_flag sme; then
            msg "AMD SME capability bit is set"
            warn "SME still has to be enabled in firmware. Cost: RAM latency, VFIO breakage, possible non-boot."
        else
            warn "This AMD CPU does not advertise SME. --enable will refuse."
        fi
        if sme_active; then
            msg "SME appears active on the running kernel"
        else
            info "SME does not appear active on the running kernel"
        fi
    elif [[ "$v" == "intel" ]]; then
        if has_flag tme || has_flag tme_en; then
            msg "Intel TME capability bit is set (firmware-controlled; no portable cmdline)"
        else
            warn "This Intel CPU does not advertise TME."
        fi
    fi
    echo
    info "Current /proc/cmdline:"
    echo "  $(cat /proc/cmdline)"
}

add_param_to_line() {
    local line="$1" param="$2"
    if echo "$line" | grep -qE "(^|[[:space:]])${param}([[:space:]]|$)"; then
        printf '%s' "$line"
        return 0
    fi
    printf '%s %s' "$line" "$param"
}

remove_param_from_line() {
    local line="$1" param="$2"
    echo "$line" | sed -E "s/(^|[[:space:]])${param}([[:space:]]|$)/ /g" | awk '{$1=$1;print}'
}

update_grub() {
    local action="$1"
    local grub="/etc/default/grub"
    [[ -f "$grub" ]] || return 1
    cp "$grub" "${grub}.bak.$(date +%Y%m%d-%H%M%S)"
    local current
    current=$(grep '^GRUB_CMDLINE_LINUX_DEFAULT=' "$grub" | sed 's/^GRUB_CMDLINE_LINUX_DEFAULT="//;s/"$//')
    if [[ "$action" == "add" ]]; then
        current=$(add_param_to_line "$current" "mem_encrypt=on")
    else
        current=$(remove_param_from_line "$current" "mem_encrypt=on")
    fi
    sed -i "s|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT=\"${current}\"|" "$grub"
    command -v grub-mkconfig >/dev/null && grub-mkconfig -o /boot/grub/grub.cfg
    msg "Updated GRUB cmdline"
    return 0
}

update_systemd_boot() {
    local action="$1" dir entry found=false
    for dir in /efi/loader/entries /boot/loader/entries /boot/efi/loader/entries; do
        [[ -d "$dir" ]] || continue
        shopt -s nullglob
        for entry in "$dir"/*.conf; do
            found=true
            cp "$entry" "${entry}.bak.$(date +%Y%m%d-%H%M%S)"
            local opts
            opts=$(awk '/^options /{sub(/^options /,""); print}' "$entry")
            if [[ "$action" == "add" ]]; then
                opts=$(add_param_to_line "$opts" "mem_encrypt=on")
            else
                opts=$(remove_param_from_line "$opts" "mem_encrypt=on")
            fi
            awk -v opts="$opts" '
                /^options / { print "options " opts; next }
                { print }
            ' "$entry" >"${entry}.new"
            mv "${entry}.new" "$entry"
            msg "Updated $entry"
        done
        shopt -u nullglob
    done
    [[ "$found" == true ]]
}

enable_sme() {
    [[ "$(vendor)" == "amd" ]] || err "--enable is only automated for AMD SME"
    has_flag sme || err "CPU does not advertise the sme flag. Refusing."
    warn "Confirm Memory Encryption / SME is enabled in firmware before rebooting."
    if update_grub add || update_systemd_boot add; then
        msg "mem_encrypt=on staged. Reboot to activate."
    else
        err "No GRUB or systemd-boot entry found to edit"
    fi
}

disable_sme() {
    if update_grub remove || update_systemd_boot remove; then
        msg "mem_encrypt=on removed. Reboot to drop SME."
    else
        err "No GRUB or systemd-boot entry found to edit"
    fi
}

probe
echo
if [[ "$DO_ENABLE" == true ]]; then
    enable_sme
fi
if [[ "$DO_DISABLE" == true ]]; then
    disable_sme
fi
