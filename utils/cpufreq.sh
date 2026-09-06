#!/usr/bin/env bash

# =============================================================================
# Script:      cpufreq.sh
# Description: Installs linux-cpupower and pins a sensible default governor.
#              Refuses to fight power-profiles-daemon, TLP, auto-cpufreq, or tuned.
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

GOVERNOR="schedutil"
DO_STATUS=false

usage() {
    cat <<EOF
Usage: sudo $0 [--governor NAME] [--performance] [--status] [-h]
On intel_pstate / amd_pstate the available governors may only be
powersave and performance. The script falls back instead of failing.
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --governor)     GOVERNOR="${2:-}"; [[ -n "$GOVERNOR" ]] || err "--governor needs a name"; shift 2 ;;
        --performance)  GOVERNOR="performance"; shift ;;
        --status)       DO_STATUS=true; shift ;;
        -h|--help)      usage ;;
        *)              err "Unknown option: $1" ;;
    esac
done

[[ $(id -u) -eq 0 ]] || err "Must be run as root"

competing_daemon() {
    local unit
    for unit in power-profiles-daemon.service tlp.service auto-cpufreq.service tuned.service; do
        if systemctl is-active --quiet "$unit" 2>/dev/null; then
            printf '%s' "$unit"
            return 0
        fi
    done
    return 1
}

show_status() {
    echo
    if command -v cpupower >/dev/null; then
        cpupower frequency-info || true
    elif [[ -r /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor ]]; then
        info "cpu0 governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)"
        info "available:     $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_available_governors)"
    else
        warn "No cpufreq sysfs — common on some VPS hypervisors."
    fi
    echo
    local rival
    if rival=$(competing_daemon); then
        warn "Competing scaling service is active: $rival"
    else
        info "No competing scaling daemon is active"
    fi
}

if [[ "$DO_STATUS" == true ]]; then
    show_status
    exit 0
fi

if [[ ! -d /sys/devices/system/cpu/cpu0/cpufreq ]]; then
    warn "This machine has no CPU frequency scaling interface. Exiting without changes."
    exit 0
fi

if rival=$(competing_daemon); then
    err "Refusing to configure cpupower while $rival is active."
fi

pacman -Syu --noconfirm --needed linux-cpupower

available=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_available_governors 2>/dev/null || true)
if [[ -n "$available" ]] && ! echo " $available " | grep -q " $GOVERNOR "; then
    warn "Governor '$GOVERNOR' is not available ($available)"
    if echo " $available " | grep -q " schedutil "; then
        GOVERNOR="schedutil"
    elif echo " $available " | grep -q " powersave "; then
        GOVERNOR="powersave"
    else
        GOVERNOR=$(awk '{print $1}' <<<"$available")
    fi
    warn "Falling back to '$GOVERNOR'"
fi

cat > /etc/default/cpupower <<EOF
# Written by utils/cpufreq.sh
governor='${GOVERNOR}'
EOF

systemctl enable --now cpupower.service 2>/dev/null || warn "cpupower.service could not be enabled; applying governor live"
command -v cpupower >/dev/null && cpupower frequency-set -g "$GOVERNOR" || warn "cpupower frequency-set failed"
msg "Governor set to $GOVERNOR"
show_status
