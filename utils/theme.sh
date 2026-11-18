#!/usr/bin/env bash

# =============================================================================
# Script:      theme.sh
# Description: Installs the WhiteSur GTK theme and (when GRUB is used)
#              grub2-themes for a polished dark desktop appearance on Arch Linux.
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
BYellow='\033[1;33m'
NC='\033[0m'

if [ "$(id -u)" -eq 0 ]; then
    echo -e "${BRed}Do not run this script as root. Run as your normal user (it invokes sudo only if GRUB theming applies).${NC}" >&2
    exit 1
fi

for cmd in git sudo; do
    if ! command -v "$cmd" &>/dev/null; then
        echo -e "${BRed}Required command '$cmd' not found. Install it first.${NC}" >&2
        exit 1
    fi
done

sudo pacman -S --needed --noconfirm sassc glib2 gtk-update-icon-cache

# Build under ~/.cache instead of /tmp (/tmp is mounted noexec on hardened installs)
mkdir -p -m 0700 "$HOME/.cache"
BUILDDIR="$(mktemp -d "$HOME/.cache/theme-build.XXXXXX")"
if command -v setfacl &>/dev/null; then
    setfacl -b -k "$BUILDDIR" 2>/dev/null || true
fi
mkdir -p -m 0700 "$BUILDDIR/tmp"
export TMPDIR="$BUILDDIR/tmp"
trap 'rm -rf -- "$BUILDDIR"' EXIT

# --- WhiteSur GTK Theme ---
echo -e "${BBlue}Installing WhiteSur GTK theme...${NC}"
git clone https://github.com/vinceliuice/WhiteSur-gtk-theme.git --depth=1 "$BUILDDIR/WhiteSur-gtk-theme"
bash "$BUILDDIR/WhiteSur-gtk-theme/install.sh" --color dark --theme blue --gnomeshell -icon arch --roundedmaxwindow
echo -e "${BGreen}WhiteSur GTK theme installed.${NC}"

# --- GRUB Theme (only when /boot/grub exists; /boot is 0700 root:root) ---
if sudo test -d /boot/grub; then
    echo -e "${BBlue}Installing grub2-themes...${NC}"
    git clone https://github.com/vinceliuice/grub2-themes.git --depth=1 "$BUILDDIR/grub2-themes"
    sudo bash -c 'umask 022 && exec bash "$1" -t vimix -s ultrawide -i whitesur -b /boot/grub' _ "$BUILDDIR/grub2-themes/install.sh"
    if command -v setfacl &>/dev/null; then
        sudo setfacl -bR /boot/grub/themes /usr/share/grub/themes 2>/dev/null || true
    fi
    echo -e "${BGreen}GRUB theme installed.${NC}"
else
    echo -e "${BYellow}/boot/grub not present (systemd-boot/UKI or custom layout) — skipping GRUB theme.${NC}"
fi

echo -e "${BGreen}Theming complete.${NC}"
