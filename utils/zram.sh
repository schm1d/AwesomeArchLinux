#!/usr/bin/env bash

# =============================================================================
# Script:      zram.sh
# Description: Configures systemd-zram-generator as high-priority compressed
#              RAM swap and leaves disk swap as overflow. Disables built-in
#              zswap across boots via tmpfiles.d so pages are not compressed twice.
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
# =============================================================================

set -euo pipefail

umask 022

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
ZSWAP_MODPROBE="/etc/modprobe.d/99-disable-zswap.conf"
ZSWAP_TMPFILES="/etc/tmpfiles.d/99-disable-zswap.conf"

usage() {
    cat <<EOF
Usage: sudo $0 [--size EXPR] [--disable] [--status] [-h]
Default size expression: "ram / 2". Disk-backed swap is kept.
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --size)
            [[ $# -ge 2 && -n "${2:-}" ]] || err "--size needs an expression"
            [[ "$2" != *$'\n'* && "$2" != *$'\r'* && "$2" =~ ^[a-zA-Z0-9_.+/*()\ -]+$ ]] || err "Invalid --size expression: $2"
            SIZE_EXPR="$2"
            shift 2
            ;;
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
    systemctl stop systemd-zram-setup@zram0.service 2>/dev/null || true
    [[ -b /dev/zram0 ]] && swapoff /dev/zram0 2>/dev/null || true
    rm -f "$CONF" "$ZSWAP_MODPROBE" "$ZSWAP_TMPFILES"
    systemctl daemon-reload
    msg "Disabled zram and removed $CONF"
    show_status
    exit 0
fi

# Arch compiles CONFIG_ZSWAP=y built-in, so modprobe.d alone does not disable it
# across reboots; persist via tmpfiles.d as well as modprobe.d + live sysfs.
if [[ -e /sys/module/zswap/parameters/enabled ]]; then
    if [[ "$(cat /sys/module/zswap/parameters/enabled 2>/dev/null || echo N)" == "Y" ]]; then
        warn "zswap is enabled. Disabling it so pages are not compressed twice."
    fi
    install -d -m 0755 /etc/modprobe.d /etc/tmpfiles.d
    printf '%s\n' 'options zswap enabled=0' > "$ZSWAP_MODPROBE"
    chmod 0644 "$ZSWAP_MODPROBE"
    printf '%s\n' 'w /sys/module/zswap/parameters/enabled - - - - 0' > "$ZSWAP_TMPFILES"
    chmod 0644 "$ZSWAP_TMPFILES"
    systemd-tmpfiles --create "$ZSWAP_TMPFILES" 2>/dev/null || echo 0 > /sys/module/zswap/parameters/enabled 2>/dev/null || true
fi

pacman -Syu --noconfirm --needed zram-generator
install -d -m 0755 /etc/systemd
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
