#!/usr/bin/env bash

# =============================================================================
# Script:      yay.sh
# Description: Installs the yay AUR helper on Arch Linux safely on systems with
#              /tmp mounted noexec and restrictive home default POSIX ACLs.
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
#
# Usage:       ./yay.sh
# =============================================================================

set -euo pipefail

BBlue='\033[1;34m'
BRed='\033[1;31m'
BGreen='\033[1;32m'
BYellow='\033[1;33m'
NC='\033[0m'

# yay must NOT be built as root
if [ "$(id -u)" -eq 0 ]; then
    echo -e "${BRed}Do not run this script as root. Run as your normal user.${NC}" >&2
    exit 1
fi

# Check dependencies
for cmd in git makepkg pacman; do
    if ! command -v "$cmd" &>/dev/null; then
        echo -e "${BRed}Required command '$cmd' not found.${NC}" >&2
        exit 1
    fi
done

if getent group compilers >/dev/null 2>&1 && ! id -nG | tr ' ' '\n' | grep -qx 'compilers'; then
    echo -e "${BYellow}Warning: Current session is not in the 'compilers' group.${NC}" >&2
    echo -e "${BYellow}If compiler binaries are 0750 root:compilers, log out and back in (or run: sudo usermod -aG compilers $(id -un)).${NC}" >&2
fi

# Prepare an ACL-clean ~/.cache/yay directory so future AUR builds (`cp -a`
# PKGBUILDs like brave-bin) do not inherit /home/$USER's restrictive default
# POSIX ACLs into $pkgdir, while ~/.cache itself stays 0700 private.
mkdir -p -m 0700 "$HOME/.cache" "$HOME/.cache/yay"
if command -v setfacl &>/dev/null; then
    setfacl -b -k "$HOME/.cache/yay" 2>/dev/null || true
fi

# Skip if yay is already installed
if command -v yay &>/dev/null; then
    echo -e "${BGreen}yay is already installed ($(yay --version)).${NC}"
    exit 0
fi

echo -e "${BBlue}Installing base-devel and go (required for building yay)...${NC}"
sudo pacman -S --needed --noconfirm base-devel go

# Build inside ~/.cache rather than /tmp (mounted noexec on hardened installs)
BUILDDIR="$(mktemp -d "$HOME/.cache/yay-bootstrap.XXXXXX")"
if command -v setfacl &>/dev/null; then
    setfacl -b -k "$BUILDDIR" 2>/dev/null || true
fi
mkdir -p -m 0700 "$BUILDDIR/tmp"
trap 'rm -rf -- "$BUILDDIR"' EXIT

echo -e "${BBlue}Cloning yay from AUR...${NC}"
git clone https://aur.archlinux.org/yay.git "$BUILDDIR/yay"

echo -e "${BBlue}Building and installing yay...${NC}"
(
    cd "$BUILDDIR/yay"
    TMPDIR="$BUILDDIR/tmp" GOTMPDIR="$BUILDDIR/tmp" makepkg -si --noconfirm
)

echo -e "${BGreen}yay installed successfully ($(yay --version)).${NC}"
