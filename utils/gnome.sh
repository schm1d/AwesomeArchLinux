#!/usr/bin/env bash

# =============================================================================
# Script:      gnome.sh
# Description: Installs and configures a minimal GNOME Desktop on Arch Linux.
#              Avoids games and bloatware, applies GNOME settings, and hardens
#              the setup.
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
#
# Usage:       sudo ./gnome.sh
# =============================================================================

set -euo pipefail

BBlue='\033[1;34m'
BRed='\033[1;31m'
BGreen='\033[1;32m'
NC='\033[0m'

# Must run as root
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${BRed}This script must be run as root (e.g., with sudo).${NC}" >&2
    exit 1
fi

# Resolve target user from SUDO_USER
TARGET_USER="${SUDO_USER:-}"
if [ -z "$TARGET_USER" ] || [ "$TARGET_USER" = "root" ]; then
    echo -e "${BRed}Run this script via sudo as a non-root user.${NC}" >&2
    echo "Example: sudo ./gnome.sh" >&2
    exit 1
fi

HOME_DIR="/home/$TARGET_USER"
if [ ! -d "$HOME_DIR" ]; then
    echo -e "${BRed}Home directory '$HOME_DIR' does not exist.${NC}" >&2
    exit 1
fi

prompt_yes_no() {
    while true; do
        read -p "$1 (y/n): " yn
        case $yn in
            [Yy]*) return 0 ;;
            [Nn]*) return 1 ;;
            *) echo "Please answer y or n." ;;
        esac
    done
}

# 1) Update system and install core GNOME packages
echo -e "${BBlue}Installing core GNOME packages...${NC}"
pacman -S --noconfirm \
  gdm gnome gnome-backgrounds gnome-connections gnome-logs evince glib2 \
  gnome-calculator gnome-console gnome-disk-utility gnome-epub-thumbnailer gnome-firmware eog \
  gnome-keyring networkmanager-openvpn nautilus seahorse gnome-control-center chromium \
  baobab deja-dup sushi xdg-desktop-portal-gnome gnome-font-viewer gnome-nettool gnome-session \
  gnome-screenshot gnome-shell gnome-software gnome-tweaks onionshare ublock-origin \
  gsettings-desktop-schemas gsettings-system-schemas gedit gedit-plugins \
  xdg-user-dirs-gtk xorg-server xdg-utils xorg-xinit xorg-xinput libinput torbrowser-launcher \
  networkmanager-openconnect networkmanager-strongswan
# Note: seahorse-nautilus was merged into seahorse. gtk-engine-murrine and
# gtk-engines (GTK2 theme engines) were dropped from Arch repos — only in
# AUR now, and not needed for modern GTK3/GTK4 themes.

# 2) Optional packages prompt
echo -e "${BBlue}Optional packages...${NC}"
if prompt_yes_no "Install GNOME Shell extensions (arc-menu, caffeine, dash-to-panel, vitals)?"; then
    pacman -S --noconfirm \
      gnome-shell-extension-arc-menu gnome-shell-extension-caffeine \
      gnome-shell-extension-dash-to-panel gnome-shell-extension-desktop-icons-ng \
      gnome-shell-extension-vitals
fi
if prompt_yes_no "Install additional tools (imagemagick, parted)?"; then
    pacman -S --noconfirm imagemagick parted
fi

# 3) Bluetooth detection and installation
if lsusb | grep -iq "bluetooth" || lspci | grep -iq "bluetooth"; then
    echo -e "${BBlue}Bluetooth hardware detected. Installing Bluetooth packages...${NC}"
    pacman -S --noconfirm bluez bluez-utils gnome-bluetooth-3.0 blueman
    systemctl enable bluetooth.service
else
    echo -e "${BBlue}No Bluetooth hardware detected. Skipping.${NC}"
fi

# 4) Configure X11 keyboard from vconsole keymap
echo -e "${BBlue}Configuring X11 keyboard layout...${NC}"
if [[ ! -f /etc/X11/xorg.conf.d/00-keyboard.conf ]]; then
    VCONSOLE_KEYMAP=""
    if [[ -f /etc/vconsole.conf ]]; then
        VCONSOLE_KEYMAP=$(sed -n 's/^KEYMAP=//p' /etc/vconsole.conf)
    fi
    if [[ -n "$VCONSOLE_KEYMAP" ]]; then
        # localectl handles translation and writes 00-keyboard.conf
        localectl set-keymap "$VCONSOLE_KEYMAP" 2>/dev/null || true
        echo -e "${BGreen}X11 keyboard layout set from vconsole keymap '$VCONSOLE_KEYMAP'.${NC}"
    fi
else
    echo -e "${BBlue}X11 keyboard config already exists (from chroot), skipping.${NC}"
fi

# 5) Enable GDM service
echo -e "${BBlue}Enabling GDM...${NC}"
systemctl enable gdm.service

# GDM ships /usr/lib/udev/rules.d/61-gdm.rules which disables Wayland
# whenever the NVIDIA proprietary driver is loaded. That rule is stale
# for modern NVIDIA (470+) where Wayland works fine, and when it kicks
# in GDM falls back to an Xorg session that can also fail, leaving
# "gnome-shell: Failed to init X11 display: Unknown error" in the
# journal and no usable desktop. Symlinking the rule to /dev/null
# overrides it without touching the system file, so GDM can start
# Wayland on NVIDIA. Safe no-op on AMD/Intel (the rule only matches
# NVIDIA proprietary).
if lspci 2>/dev/null | grep -qi 'vga.*nvidia\|3d.*nvidia'; then
    echo -e "${BBlue}NVIDIA GPU detected — overriding GDM's NVIDIA-blocks-Wayland rule...${NC}"
    ln -sf /dev/null /etc/udev/rules.d/61-gdm.rules
fi

echo -e "${BBlue}Ensuring DNS-over-TLS works with NetworkManager...${NC}"

# On an already-running system the NM -> resolved handoff only works if
# resolved is active, /etc/resolv.conf points at its stub, and NM is
# configured with the systemd-resolved DNS backend. chroot.sh only
# writes that drop-in if /etc/NetworkManager/conf.d exists at install
# time; when NM is installed later by this script, we must write it
# ourselves.
systemctl enable --now systemd-resolved
rm -f /etc/resolv.conf
ln -s /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
install -d /etc/NetworkManager/conf.d
cat > /etc/NetworkManager/conf.d/dns.conf <<'EOF'
[main]
dns=systemd-resolved
EOF
# try-restart is a no-op if NM isn't active yet, which avoids a spurious
# error on first boot after this script runs.
if systemctl is-active --quiet NetworkManager; then
    systemctl try-restart NetworkManager || true
fi

# 6) Enable PipeWire for the target user (runs as a user service on login)
echo -e "${BBlue}PipeWire will start automatically on user login via systemd user units.${NC}"

# 7) Apply GNOME settings for the target user
echo -e "${BBlue}Applying GNOME settings for user $TARGET_USER...${NC}"
sudo -u "$TARGET_USER" dbus-launch gsettings set org.gnome.desktop.interface color-scheme 'prefer-dark' 2>/dev/null || true

# 8) Harden GNOME configuration
echo -e "${BBlue}Hardening GNOME configuration...${NC}"
systemctl disable --now geoclue.service 2>/dev/null || true
chmod 700 "$HOME_DIR/.config" 2>/dev/null || true

# 9) Clean up package cache
echo -e "${BBlue}Cleaning up package cache...${NC}"
pacman -Sc --noconfirm

echo -e "${BGreen}GNOME Desktop configuration complete. Reboot to start GNOME.${NC}"
