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

# Both installers are third-party code that runs on this machine. Use the
# release tags below instead of whatever the default branch holds today, and
# check the commit as well because a tag can be moved upstream. The options
# passed further down were checked against these releases; re-check them (and
# read upstream's changes) before moving a pin.
WHITESUR_TAG="2026-09-10"
WHITESUR_COMMIT="99247ecd219bdc1c7409baff062b4aafcf1102a7"
GRUB_THEMES_TAG="2025-07-23"
GRUB_THEMES_COMMIT="6c26f99622cb1c705b3fe2dbe1eb88521096b25a"

clone_pinned() {
    local url="$1" tag="$2" commit="$3" dest="$4" head
    git -c advice.detachedHead=false clone --depth=1 --branch "$tag" -- "$url" "$dest"
    head="$(git -C "$dest" rev-parse HEAD)"
    if [[ "$head" != "$commit" ]]; then
        echo -e "${BRed}${url}: tag ${tag} is at ${head}, expected ${commit}. Refusing to run it.${NC}" >&2
        exit 1
    fi
}

# --- WhiteSur GTK Theme ---
echo -e "${BBlue}Installing WhiteSur GTK theme...${NC}"
clone_pinned https://github.com/vinceliuice/WhiteSur-gtk-theme.git "$WHITESUR_TAG" "$WHITESUR_COMMIT" "$BUILDDIR/WhiteSur-gtk-theme"
# '--shell -i arch' sets the GNOME Shell activities icon. The older spellings
# (--gnomeshell, -icon) are rejected by this release and abort the installer.
bash "$BUILDDIR/WhiteSur-gtk-theme/install.sh" --color dark --theme blue --shell -i arch --roundedmaxwindow
echo -e "${BGreen}WhiteSur GTK theme installed.${NC}"

# --- GRUB Theme (only when /boot/grub exists; /boot is 0700 root:root) ---
if sudo test -d /boot/grub; then
    echo -e "${BBlue}Installing grub2-themes...${NC}"
    clone_pinned https://github.com/vinceliuice/grub2-themes.git "$GRUB_THEMES_TAG" "$GRUB_THEMES_COMMIT" "$BUILDDIR/grub2-themes"

    # The upstream installer needs root only to copy the finished theme into
    # /boot and to point GRUB at it. Let it generate the theme as this user
    # (-g DIR) and do those few root steps here, so no third-party script runs
    # as root.
    GRUB_THEME_NAME="vimix"
    bash "$BUILDDIR/grub2-themes/install.sh" -t "$GRUB_THEME_NAME" -s ultrawide -i whitesur -g "$BUILDDIR/grub-theme"
    if [[ ! -f "$BUILDDIR/grub-theme/$GRUB_THEME_NAME/theme.txt" ]]; then
        echo -e "${BRed}grub2-themes did not generate ${GRUB_THEME_NAME}/theme.txt.${NC}" >&2
        exit 1
    fi

    sudo bash -s -- "$BUILDDIR/grub-theme/$GRUB_THEME_NAME" "$GRUB_THEME_NAME" <<'ROOT_EOF'
set -euo pipefail
umask 022
src="$1"
[[ -n "$2" && "$2" != */* && -f "$src/theme.txt" ]] || { echo "Unexpected GRUB theme source: $src" >&2; exit 1; }
dest="/boot/grub/themes/$2"
grub_default="/etc/default/grub"

[[ -f "$grub_default" ]] || { echo "$grub_default not found; GRUB theme not installed." >&2; exit 1; }

# Replace the active assignment of KEY in /etc/default/grub, or append one.
set_grub_var() {
    local key="$1" value="$2"
    if grep -qE "^[[:space:]]*${key}=" "$grub_default"; then
        sed -i -E "s|^[[:space:]]*${key}=.*|${key}=${value}|" "$grub_default"
    else
        printf '%s=%s\n' "$key" "$value" >> "$grub_default"
    fi
}

# Root-owned copy with default modes, whatever the build directory looked like.
install -d -m 0755 /boot/grub/themes
rm -rf -- "$dest"
cp -r --no-preserve=mode,ownership -- "$src" "$dest"
if command -v setfacl >/dev/null 2>&1; then
    setfacl -bR /boot/grub/themes 2>/dev/null || true
fi

cp -p -- "$grub_default" "${grub_default}.bak.$(date +%Y%m%d%H%M%S)"
set_grub_var GRUB_THEME "\"${dest}/theme.txt\""
set_grub_var GRUB_GFXMODE "2560x1080,auto"
# A graphical theme is not drawn on the plain text console.
sed -i -E "s/^[[:space:]]*(GRUB_TERMINAL(_OUTPUT)?=[\"']?console[\"']?[[:space:]]*)\$/#\\1/" "$grub_default"

grub-mkconfig -o /boot/grub/grub.cfg
chmod og-rwx /boot/grub/grub.cfg 2>/dev/null || true
ROOT_EOF
    echo -e "${BGreen}GRUB theme installed.${NC}"
else
    echo -e "${BYellow}/boot/grub not present (systemd-boot/UKI or custom layout) — skipping GRUB theme.${NC}"
fi

echo -e "${BGreen}Theming complete.${NC}"
