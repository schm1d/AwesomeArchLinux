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

DO_STATUS=false
FORCE_DRIVER=""
ENV_FILE="/etc/environment.d/20-vaapi.conf"

usage() { echo "Usage: sudo $0 [--status] [--force-driver NAME] [-h]"; exit 0; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --status)  DO_STATUS=true; shift ;;
        --force-driver)
            [[ $# -ge 2 && -n "${2:-}" ]] || err "--force-driver needs a name"
            [[ "$2" =~ ^[a-zA-Z0-9_-]+$ ]] || err "Invalid driver name: $2"
            FORCE_DRIVER="$2"
            shift 2
            ;;
        -h|--help) usage ;;
        *)         err "Unknown option: $1" ;;
    esac
done

[[ $(id -u) -eq 0 ]] || err "Must be run as root"

vga_intel=false
vga_amd=false
vga_nvidia=false

detect() {
    local lines
    lines=$(lspci 2>/dev/null | grep -Ei 'VGA|3D|Display' || true)
    if grep -qi intel <<<"$lines"; then vga_intel=true; fi
    if grep -qiE 'amd|radeon' <<<"$lines"; then vga_amd=true; fi
    if grep -qi nvidia <<<"$lines"; then vga_nvidia=true; fi
    info "PCI display adapters:"
    if [[ -n "$lines" ]]; then
        sed 's/^/  /' <<<"$lines"
    else
        echo "  (none detected)"
    fi
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
    model=$(lspci 2>/dev/null | grep -iE 'VGA|3D|Display' | grep -i intel || true)
    if grep -qiE 'Haswell|Ivy Bridge|Sandy Bridge|Ironlake|Bay Trail' <<<"$model"; then
        printf 'i965'
    else
        printf 'iHD'
    fi
}

write_env() {
    local name="$1"
    install -d -m 0755 /etc/environment.d
    {
        echo "# Written by utils/vaapi.sh"
        echo "LIBVA_DRIVER_NAME=${name}"
        if [[ "$name" == "nvidia" ]]; then
            echo "NVD_BACKEND=direct"
        fi
    } > "$ENV_FILE"
    chmod 644 "$ENV_FILE"
    msg "Wrote $ENV_FILE (LIBVA_DRIVER_NAME=${name})"
    info "Log out or reboot for the environment drop-in to reach user sessions."
}

show_status() {
    echo
    local pinned=""
    if [[ -f "$ENV_FILE" ]]; then
        info "$ENV_FILE:"; sed 's/^/  /' "$ENV_FILE"
        pinned=$(awk -F= '/^LIBVA_DRIVER_NAME=/ { print $2; exit }' "$ENV_FILE" || true)
    else
        info "No $ENV_FILE"
    fi
    echo
    if command -v vainfo >/dev/null; then
        info "vainfo:"
        if [[ -n "$pinned" ]]; then
            LIBVA_DRIVER_NAME="$pinned" vainfo --display drm 2>&1 | sed 's/^/  /' || true
        else
            vainfo --display drm 2>&1 | sed 's/^/  /' || true
        fi
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
    # Modern Arch mesa ships Radeon VA-API (radeonsi) directly; mesa-vdpau was removed.
    packages+=(mesa vulkan-radeon)
    driver="radeonsi"
    msg "AMD GPU: installing mesa VA-API + vulkan-radeon"
fi
if [[ "$vga_nvidia" == true ]]; then
    packages+=(libva-nvidia-driver)
    if [[ "$(count_vendors)" -eq 1 ]]; then
        driver="nvidia"
    fi
    msg "NVIDIA GPU: installing libva-nvidia-driver"
    warn "Firefox VA-API on proprietary NVIDIA may require media.ffmpeg.vaapi.enabled."
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
