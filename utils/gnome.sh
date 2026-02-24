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
  gnome-keyring networkmanager-openvpn nautilus seahorse-nautilus gnome-control-center chromium \
  baobab deja-dup sushi xdg-desktop-portal-gnome gnome-font-viewer gnome-nettool gnome-session \
  gnome-screenshot gnome-shell gnome-software gnome-tweaks onionshare ublock-origin \
  gsettings-desktop-schemas gsettings-system-schemas gedit gedit-plugins \
  xdg-user-dirs-gtk xorg-server xdg-utils xorg-xinit torbrowser-launcher \
  networkmanager-openconnect networkmanager-strongswan gtk-engine-murrine gtk-engines

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

# 4) Enable GDM service
echo -e "${BBlue}Enabling GDM...${NC}"
systemctl enable gdm.service

# 5) Enable PipeWire for the target user (runs as user service on login)
echo -e "${BBlue}PipeWire will start automatically on user login via systemd user units.${NC}"

# 6) Apply GNOME settings for the target user
echo -e "${BBlue}Applying GNOME settings for user $TARGET_USER...${NC}"
sudo -u "$TARGET_USER" dbus-launch gsettings set org.gnome.desktop.interface color-scheme 'prefer-dark' 2>/dev/null || true

# 7) Harden GNOME configuration
echo -e "${BBlue}Hardening GNOME configuration...${NC}"
systemctl disable --now geoclue.service 2>/dev/null || true
chmod 700 "$HOME_DIR/.config" 2>/dev/null || true

# 8) Clean up package cache
echo -e "${BBlue}Cleaning up package cache...${NC}"
pacman -Sc --noconfirm

echo -e "${BGreen}GNOME Desktop configuration complete. Reboot to start GNOME.${NC}"
