#!/usr/bin/env bash

# =============================================================================
# Script:      yay.sh
# Description: Installs the yay AUR helper on Arch Linux safely on systems with
#              /tmp mounted noexec and restrictive home default POSIX ACLs.
#              yay itself is an AUR recipe: it is built through the reviewed
#              builder (hardening/lib/aur-review.sh), which shows the recipe
#              and needs a typed confirmation on the terminal.
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
for cmd in pacman sudo; do
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

# AUR recipes are mutable, user-submitted build instructions, so yay is not
# built with a bare `makepkg -si --noconfirm`. The reviewed builder shows the
# exact recipe commit, waits for a typed confirmation, installs the build
# dependencies (go) from the signed repositories and builds as a disposable
# unprivileged user under /var/cache.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
AUR_LIB=""
for candidate in "$SCRIPT_DIR/../hardening/lib/aur-review.sh" "$SCRIPT_DIR/aur-review.sh"; do
    if [ -r "$candidate" ]; then
        AUR_LIB="$candidate"
        break
    fi
done
if [ -z "$AUR_LIB" ]; then
    echo -e "${BRed}hardening/lib/aur-review.sh not found. Run this script from a full checkout of the repository.${NC}" >&2
    exit 1
fi

echo -e "${BBlue}Installing base-devel and git (required for building yay)...${NC}"
sudo pacman -S --needed --noconfirm base-devel git

echo -e "${BBlue}Building yay from the AUR (the recipe is shown for review first)...${NC}"
# shellcheck disable=SC2016
if ! sudo bash -c 'set -euo pipefail; source "$1"; aal_aur_install_reviewed "$2"' _ "$AUR_LIB" yay; then
    echo -e "${BRed}yay was not installed (review declined, no terminal, or the build failed).${NC}" >&2
    exit 1
fi

echo -e "${BGreen}yay installed successfully ($(yay --version)).${NC}"
