#!/usr/bin/env bash

# =============================================================================
# Script:      vaapi.sh
# Description: Detects GPU vendor, installs the matching VA-API / VDPAU stack,
#              and pins LIBVA_DRIVER_NAME only when the choice is unambiguous.
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
FORCE_DRIVER=""
ENV_FILE="/etc/environment.d/20-vaapi.conf"

usage() { echo "Usage: sudo $0 [--status] [--force-driver NAME] [-h]"; exit 0; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --status)        DO_STATUS=true; shift ;;
        --force-driver)  FORCE_DRIVER="${2:-}"; [[ -n "$FORCE_DRIVER" ]] || err "--force-driver needs a name"; shift 2 ;;
        -h|--help)       usage ;;
        *)               err "Unknown option: $1" ;;
    esac
done

[[ $(id -u) -eq 0 ]] || err "Must be run as root"

vga_intel=false
vga_amd=false
vga_nvidia=false

detect() {
    local lines
    lines=$(lspci 2>/dev/null | grep -Ei 'VGA|3D|Display' || true)
    echo "$lines" | grep -qi intel && vga_intel=true
    echo "$lines" | grep -qiE 'amd|radeon' && vga_amd=true
    echo "$lines" | grep -qi nvidia && vga_nvidia=true
    info "PCI display adapters:"
    echo "$lines" | sed 's/^/  /'
}

count_vendors() {
    local n=0
    [[ "$vga_intel" == true ]] && n=$((n + 1))
    [[ "$vga_amd" == true ]] && n=$((n + 1))
    [[ "$vga_nvidia" == true ]] && n=$((n + 1))
    printf '%s' "$n"
}

intel_driver_name() {
    local model
    model=$(lspci | grep -iE 'VGA|3D|Display' | grep -i intel || true)
    if echo "$model" | grep -qiE 'Haswell|Ivy Bridge|Sandy Bridge|Ironlake|Bay Trail'; then
        printf 'i965'
    else
        printf 'iHD'
    fi
}

write_env() {
    local name="$1"
    mkdir -p /etc/environment.d
    cat > "$ENV_FILE" <<EOF
# Written by utils/vaapi.sh
LIBVA_DRIVER_NAME=${name}
EOF
    chmod 644 "$ENV_FILE"
    msg "Wrote $ENV_FILE (LIBVA_DRIVER_NAME=${name})"
    info "Log out or reboot for the environment drop-in to reach user sessions."
}

show_status() {
    echo
    if [[ -f "$ENV_FILE" ]]; then
        info "$ENV_FILE:"; sed 's/^/  /' "$ENV_FILE"
    else
        info "No $ENV_FILE"
    fi
    echo
    if command -v vainfo >/dev/null; then
        info "vainfo:"; vainfo 2>&1 | sed 's/^/  /' || true
    else
        warn "vainfo not installed"
    fi
}

if [[ "$DO_STATUS" == true ]]; then
    detect
    show_status
    exit 0
fi

detect
echo

packages=(libva libva-utils libvdpau)
driver=""

if [[ "$vga_intel" == true ]]; then
    packages+=(intel-media-driver libva-intel-driver vulkan-intel intel-gpu-tools)
    driver=$(intel_driver_name)
    msg "Intel GPU: installing iHD + i965 user-mode drivers"
fi
if [[ "$vga_amd" == true ]]; then
    packages+=(libva-mesa-driver mesa-vdpau vulkan-radeon)
    driver="radeonsi"
    msg "AMD GPU: installing mesa VA-API/VDPAU"
fi
if [[ "$vga_nvidia" == true ]]; then
    packages+=(libva-nvidia-driver libvdpau)
    if [[ "$(count_vendors)" -eq 1 ]]; then
        driver="nvidia"
    fi
    msg "NVIDIA GPU: installing libva-nvidia-driver"
    warn "Firefox VA-API on proprietary NVIDIA is still flaky."
fi

pacman -Syu --noconfirm --needed "${packages[@]}"

if [[ -n "$FORCE_DRIVER" ]]; then
    write_env "$FORCE_DRIVER"
elif [[ "$(count_vendors)" -eq 1 && -n "$driver" ]]; then
    write_env "$driver"
elif [[ "$(count_vendors)" -gt 1 ]]; then
    warn "Hybrid GPU system detected. Not writing LIBVA_DRIVER_NAME."
    warn "Re-run with --force-driver iHD|radeonsi|nvidia if you want a pin."
    rm -f "$ENV_FILE"
else
    info "No unambiguous driver name to pin."
fi

show_status
msg "Done."
