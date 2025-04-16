#!/bin/bash

# Description: This script installs and configures a minimal GNOME Desktop on Arch Linux.
#              It avoids games and bloatware, applies GNOME settings, and hardens the setup.
# Author: Bruno Schmid @brulliant
# LinkedIn: https://www.linkedin.com/in/schmidbruno/

set -euo pipefail

BBlue='\033[1;34m'
NC='\033[0m'

# Target user configuration
TARGET_USER="${SUDO_USER:-$USER}"
HOME_DIR="/home/$TARGET_USER"

# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root (e.g., with sudo or as root)." >&2
  exit 1
fi

# Function to handle errors
handle_error() {
    echo "Error: $1" >&2
    exit 1
}

# Function to prompt user for yes/no input
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
echo -e "${BBlue}Updating system and installing core GNOME packages...${NC}"
pacman -Syu --noconfirm || handle_error "Failed to update system."
pacman -S --noconfirm \
  gdm gnome gnome-backgrounds gnome-connections gnome-logs evince glib2 \
  gnome-calculator gnome-console gnome-disk-utility gnome-epub-thumbnailer gnome-firmware eog \
  gnome-keyring networkmanager-openvpn nautilus seahorse-nautilus gnome-control-center chromium \
  baobab deja-dup sushi xdg-desktop-portal-gnome gnome-font-viewer gnome-nettool gnome-session \
  gnome-screenshot gnome-shell gnome-software gnome-tweaks onionshare ublock-origin \
  gsettings-desktop-schemas gsettings-system-schemas gedit gedit-plugins \
  xdg-user-dirs-gtk xorg-server xdg-utils xdg-desktop-portal-gnome xorg-xinit torbrowser-launcher \
  networkmanager-openconnect networkmanager-strongswan gtk-engine-murrine gtk-engines \
  || handle_error "Failed to install core GNOME packages."

# 2) Optional packages prompt
echo -e "${BBlue}Optional packages installation...${NC}"
if prompt_yes_no "Install GNOME Shell extensions (e.g., arc-menu, caffeine)?"; then
    pacman -S --noconfirm \
      gnome-shell-extension-arc-menu gnome-shell-extension-caffeine \
      gnome-shell-extension-dash-to-panel gnome-shell-extension-desktop-icons-ng \
      gnome-shell-extension-vitals || handle_error "Failed to install extensions."
fi
if prompt_yes_no "Install additional tools (e.g., imagemagick, parted)?"; then
    pacman -S --noconfirm imagemagick parted || handle_error "Failed to install additional tools."
fi

# 3) Bluetooth detection and installation
if lsusb | grep -iq "bluetooth" || lspci | grep -iq "bluetooth"; then
    echo -e "${BBlue}Bluetooth hardware detected. Installing Bluetooth packages...${NC}"
    pacman -S --noconfirm bluez bluez-utils gnome-bluetooth-3.0 blueman || handle_error "Failed to install Bluetooth packages."
    systemctl enable bluetooth.service || handle_error "Failed to enable Bluetooth service."
else
    echo -e "${BBlue}No Bluetooth hardware detected. Skipping Bluetooth installation.${NC}"
fi

# 4) Enable GDM service
echo -e "${BBlue}Enabling GDM (GNOME Display Manager)...${NC}"
systemctl enable gdm.service || handle_error "Failed to enable GDM service."

echo -e "${BBlue}Enabling pipewire for Wayland...${NC}"
systemctl --user enable --now pipewire pipewire-pulse

# 5) Apply GNOME settings for the target user
echo -e "${BBlue}Applying GNOME settings for user $TARGET_USER...${NC}"
sudo -u "$TARGET_USER" dbus-launch gsettings set org.gnome.desktop.interface color-scheme 'prefer-dark' || handle_error "Failed to set GNOME settings."

# 6) Harden GNOME configuration
echo -e "${BBlue}Hardening GNOME configuration...${NC}"
systemctl disable --now geoclue.service || handle_error "Failed to disable geoclue service."
chmod 700 "$HOME_DIR/.config" || handle_error "Failed to set permissions on .config directory."

# 7) Clean up package cache
echo -e "${BBlue}Cleaning up package cache...${NC}"
pacman -Sc --noconfirm || handle_error "Failed to clean package cache."

echo -e "${BBlue}GNOME Desktop configuration completed.\nReboot to start GNOME.${NC}"
