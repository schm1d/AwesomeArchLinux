#!/usr/bin/env bash

# =============================================================================
# Script:      zram.sh
# Description: Configures systemd-zram-generator as high-priority compressed
#              RAM swap and leaves disk swap as overflow. Does not enable
#              zswap — zswap plus zram double-compresses pages.
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

SIZE_EXPR="ram / 2"
DO_DISABLE=false
DO_STATUS=false
CONF="/etc/systemd/zram-generator.conf"

usage() {
    cat <<EOF
Usage: sudo $0 [--size EXPR] [--disable] [--status] [-h]
Default size expression: "ram / 2". Disk-backed swap is kept.
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --size)     SIZE_EXPR="${2:-}"; [[ -n "$SIZE_EXPR" ]] || err "--size needs an expression"; shift 2 ;;
        --disable)  DO_DISABLE=true; shift ;;
        --status)   DO_STATUS=true; shift ;;
        -h|--help)  usage ;;
        *)          err "Unknown option: $1" ;;
    esac
done

[[ $(id -u) -eq 0 ]] || err "Must be run as root"

show_status() {
    echo
    info "Swap devices (higher priority is used first):"
    swapon --show || info "  no swap active"
    echo
    info "zswap:"
    if [[ -r /sys/module/zswap/parameters/enabled ]]; then
        echo "  enabled=$(cat /sys/module/zswap/parameters/enabled)"
    else
        echo "  module not loaded (good — we do not want zswap + zram)"
    fi
    echo
    if [[ -f "$CONF" ]]; then
        info "$CONF:"
        sed 's/^/  /' "$CONF"
    else
        info "No $CONF"
    fi
}

if [[ "$DO_STATUS" == true ]]; then
    show_status
    exit 0
fi

if [[ "$DO_DISABLE" == true ]]; then
    rm -f "$CONF"
    [[ -b /dev/zram0 ]] && swapoff /dev/zram0 2>/dev/null || true
    systemctl daemon-reload
    msg "Removed $CONF"
    show_status
    exit 0
fi

if [[ -r /sys/module/zswap/parameters/enabled ]] && [[ "$(cat /sys/module/zswap/parameters/enabled)" == "Y" ]]; then
    warn "zswap is enabled. Disabling it so pages are not compressed twice."
    mkdir -p /etc/modprobe.d
    echo "options zswap enabled=0" > /etc/modprobe.d/99-disable-zswap.conf
    echo 0 > /sys/module/zswap/parameters/enabled 2>/dev/null || true
fi

pacman -Syu --noconfirm --needed zram-generator
cat > "$CONF" <<EOF
[zram0]
zram-size = ${SIZE_EXPR}
compression-algorithm = zstd
swap-priority = 100
fs-type = swap
EOF
chmod 644 "$CONF"
msg "Wrote $CONF"
systemctl daemon-reload
if systemctl start systemd-zram-setup@zram0.service 2>/dev/null; then
    msg "Started systemd-zram-setup@zram0.service"
else
    warn "Could not start the zram unit live. It will appear after reboot."
fi
show_status
msg "Done."
