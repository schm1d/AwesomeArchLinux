#!/usr/bin/env bash

# =============================================================================
# Script:      yay.sh
# Description: Installs the yay AUR helper on Arch Linux.
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

# Skip if yay is already installed
if command -v yay &>/dev/null; then
    echo -e "${BGreen}yay is already installed ($(yay --version)).${NC}"
    exit 0
fi

echo -e "${BBlue}Installing base-devel group (required for makepkg)...${NC}"
sudo pacman -S --needed --noconfirm base-devel

BUILDDIR="$(mktemp -d)"
trap 'rm -rf "$BUILDDIR"' EXIT

echo -e "${BBlue}Cloning yay from AUR...${NC}"
git clone https://aur.archlinux.org/yay.git "$BUILDDIR/yay"

echo -e "${BBlue}Building and installing yay...${NC}"
(cd "$BUILDDIR/yay" && makepkg -si --noconfirm)

echo -e "${BGreen}yay installed successfully ($(yay --version)).${NC}"
