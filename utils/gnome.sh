#!/bin/bash

# Description: This script installs and configures GNOME Desktop on Arch Linux.
#              It also applies specific GNOME/dconf settings for one user.
# Author: Bruno Schmid @brulliant
# LinkedIn: https://www.linkedin.com/in/schmidbruno/

set -euo pipefail

BBlue='\033[1;34m'
NC='\033[0m'

# -- EDIT THIS to your actual desktop user --
TARGET_USER="$USER"
HOME_DIR="/home/$TARGET_USER"

if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root (e.g., with sudo or as root)." >&2
  exit 1
fi

# 1) Install GNOME Desktop packages
echo -e "${BBlue}Installing GNOME Desktop packages...${NC}"
pacman -S --noconfirm \
  gdm gitg gnome gnome-appfolders-manager gnome-backgrounds gnome-connections gnome-logs evince vinagre\
  gnome-calculator gnome-console gnome-disk-utility gnome-epub-thumbnailer gnome-firmware gnome-keybindings eog libforensic1394\
  gnome-keyring networkmanager-openvpn nautilus parted regexxer seahorse-nautilus jomon gnome-control-center firefox baobab deja-dup\
  sushi xdg-desktop-portal-gnome ghex gnome-font-viewer gnome-multi-writer gnome-nettool gnome-session gnome-screenshot loupe\
  gnome-shell gnome-shell-extension-arc-menu gnome-shell-extension-caffeine gnome-shell-extension-dash-to-panel veracrypt \
  gnome-shell-extension-desktop-icons-ng gnome-shell-extension-vitals gnome-software gnome-terminal gnome-tweaks onionshare \
  gsettings-desktop-schemas gsettings-system-schemas gthumb gtranslator komikku mutter gedit gedit-plugins chromium mvt gnome-dictionary\
  xdg-user-dirs-gtk xorg-server xdg-utils xorg-xinit torbrowser-launcher networkmanager-openconnect networkmanager-strongswan gtk-engine-murrine gtk-engines

if lsusb | grep -iq "bluetooth" || lspci | grep -iq "bluetooth"; then  # Improved detection
    echo -e "${BBlue}Bluetooth hardware detected.${NC}"
    pacman -S --noconfirm gnome-bluetooth-3.0 blueman

    if ! pacman -Qi bluez bluez-utils &>/dev/null; then # Check if already installed
      pacman -S --noconfirm bluez bluez-utils gnome-bluetooth-3.0 blueman
    fi
fi

# 2) Enable GDM service
echo -e "${BBlue}Enabling GDM (GNOME Display Manager)...${NC}"
systemctl enable gdm.service

sleep 2
echo -e "${BBlue}GNOME Desktop configuration completed.\nYou can reboot to start GDM (GNOME) now.${NC}"
