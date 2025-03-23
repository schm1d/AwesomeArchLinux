#!/bin/bash

# Description: This script installs and configures GNOME Desktop on Arch Linux.
#              It applies specific GNOME/dconf settings for one user and hardens the setup.
# Author: Bruno Schmid @brulliant
# LinkedIn: https://www.linkedin.com/in/schmidbruno/

set -euo pipefail

BBlue='\033[1;34m'
NC='\033[0m'

# -- EDIT THIS to your actual desktop user --
TARGET_USER="${SUDO_USER:-$USER}"
HOME_DIR="/home/$TARGET_USER"

if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root (e.g., with sudo or as root)." >&2
  exit 1
fi

# Function to handle errors
handle_error() {
    echo "Error: $1" >&2
    exit 1
}

# 1) Install GNOME Desktop packages
echo -e "${BBlue}Installing GNOME Desktop packages...${NC}"
pacman -Syu --noconfirm || handle_error "Failed to update system."
pacman -S --noconfirm \
  gdm gitg gnome gnome-appfolders-manager gnome-backgrounds gnome-connections gnome-logs evince vinagre \
  gnome-calculator gnome-console gnome-disk-utility gnome-epub-thumbnailer gnome-firmware gnome-keybindings eog libforensic1394 \
  gnome-keyring networkmanager-openvpn nautilus parted regexxer seahorse-nautilus jomon gnome-control-center firefox baobab deja-dup \
  sushi xdg-desktop-portal-gnome ghex gnome-font-viewer gnome-multi-writer gnome-nettool gnome-session gnome-screenshot loupe \
  gnome-shell gnome-shell-extension-arc-menu gnome-shell-extension-caffeine gnome-shell-extension-dash-to-panel veracrypt \
  gnome-shell-extension-desktop-icons-ng gnome-shell-extension-vitals gnome-software gnome-terminal gnome-tweaks onionshare \
  gsettings-desktop-schemas gsettings-system-schemas gthumb gtranslator komikku mutter gedit gedit-plugins chromium mvt gnome-dictionary \
  xdg-user-dirs-gtk xorg-server xdg-utils xorg-xinit torbrowser-launcher networkmanager-openconnect networkmanager-strongswan gtk-engine-murrine gtk-engines \
  || handle_error "Failed to install GNOME packages."

# 2) Bluetooth Detection and Installation
if lsusb | grep -iq "bluetooth" || lspci | grep -iq "bluetooth"; then
    echo -e "${BBlue}Bluetooth hardware detected. Installing Bluetooth packages...${NC}"
    pacman -S --noconfirm bluez bluez-utils gnome-bluetooth-3.0 blueman || handle_error "Failed to install Bluetooth packages."
    systemctl enable bluetooth.service || handle_error "Failed to enable Bluetooth service."
else
    echo -e "${BBlue}No Bluetooth hardware detected. Skipping Bluetooth installation.${NC}"
fi

# 3) Enable GDM service
echo -e "${BBlue}Enabling GDM (GNOME Display Manager)...${NC}"
systemctl enable gdm.service || handle_error "Failed to enable GDM service."

# 4) Apply GNOME settings for the target user
echo -e "${BBlue}Applying GNOME settings for user $TARGET_USER...${NC}"
sudo -u "$TARGET_USER" dbus-launch gsettings set org.gnome.desktop.interface color-scheme 'prefer-dark' || handle_error "Failed to set GNOME settings."

# 5) Harden GNOME configuration
echo -e "${BBlue}Hardening GNOME configuration...${NC}"
systemctl disable --now geoclue.service || handle_error "Failed to disable geoclue service."
chmod 700 "$HOME_DIR/.config" || handle_error "Failed to set permissions on .config directory."

sleep 2
echo -e "${BBlue}GNOME Desktop configuration completed.\nYou can reboot to start GDM (GNOME) now.${NC}"
