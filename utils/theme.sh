#!/usr/bin/env bash

# =============================================================================
# Script:      theme.sh
# Description: Installs the WhiteSur GTK theme and grub2-themes for a polished
#              dark desktop appearance on Arch Linux (GNOME).
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
#
# Usage:       ./theme.sh
# =============================================================================

set -euo pipefail

BBlue='\033[1;34m'
BRed='\033[1;31m'
BGreen='\033[1;32m'
NC='\033[0m'

# Check dependencies
if ! command -v git &>/dev/null; then
    echo -e "${BRed}Required command 'git' not found. Install it first.${NC}" >&2
    exit 1
fi

BUILDDIR="$(mktemp -d)"
trap 'rm -rf "$BUILDDIR"' EXIT

# --- WhiteSur GTK Theme ---
echo -e "${BBlue}Installing WhiteSur GTK theme...${NC}"
git clone https://github.com/vinceliuice/WhiteSur-gtk-theme.git --depth=1 "$BUILDDIR/WhiteSur-gtk-theme"
"$BUILDDIR/WhiteSur-gtk-theme/install.sh" --color dark --theme blue --gnomeshell -icon arch --roundedmaxwindow
echo -e "${BGreen}WhiteSur GTK theme installed.${NC}"

# --- GRUB Theme ---
echo -e "${BBlue}Installing grub2-themes...${NC}"
git clone https://github.com/vinceliuice/grub2-themes.git --depth=1 "$BUILDDIR/grub2-themes"

if [ -d /boot/grub ]; then
    sudo "$BUILDDIR/grub2-themes/install.sh" -t vimix -s ultrawide -i whitesur -b /boot/grub
    echo -e "${BGreen}GRUB theme installed.${NC}"
else
    echo -e "${BRed}/boot/grub not found. Skipping GRUB theme installation.${NC}" >&2
    echo "If your GRUB directory is elsewhere, run manually:" >&2
    echo "  sudo ./install.sh -t vimix -s ultrawide -i whitesur -b /path/to/grub" >&2
fi

echo -e "${BGreen}Theming complete.${NC}"
