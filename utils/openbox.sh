#!/usr/bin/env bash

# =============================================================================
# Script:      openbox.sh
# Description: Installs and configures Openbox with Tint2 panel, LightDM,
#              and applies basic hardening on Arch Linux.
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
#
# Usage:       sudo ./openbox.sh
# =============================================================================

set -euo pipefail

BBlue='\033[1;34m'
BRed='\033[1;31m'
BGreen='\033[1;32m'
NC='\033[0m'

# Must run as root (installs packages, enables services)
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${BRed}This script must be run as root (e.g., with sudo).${NC}" >&2
    exit 1
fi

# Resolve target user from SUDO_USER or prompt
TARGET_USER="${SUDO_USER:-}"
if [ -z "$TARGET_USER" ] || [ "$TARGET_USER" = "root" ]; then
    echo -e "${BRed}Run this script via sudo as a non-root user.${NC}" >&2
    echo "Example: sudo ./openbox.sh" >&2
    exit 1
fi

HOME_DIR="/home/$TARGET_USER"
if [ ! -d "$HOME_DIR" ]; then
    echo -e "${BRed}Home directory '$HOME_DIR' does not exist.${NC}" >&2
    exit 1
fi

# 1) Install Openbox and related packages
echo -e "${BBlue}Installing Openbox and essential desktop packages...${NC}"
pacman -S --noconfirm \
  xorg-server xorg-xinit openbox obconf-qt xdg-user-dirs \
  lightdm lightdm-gtk-greeter terminator lxpolkit \
  tint2 pcmanfm xterm networkmanager network-manager-applet \
  thunar-archive-plugin xarchiver feh lxappearance neofetch \
  xdg-user-dirs-gtk xdg-utils networkmanager-openvpn \
  networkmanager-openconnect networkmanager-strongswan \
  gtk-engine-murrine gtk-engines chromium

# 2) Bluetooth detection and installation
if lsusb | grep -iq "bluetooth" || lspci | grep -iq "bluetooth"; then
    echo -e "${BBlue}Bluetooth hardware detected. Installing Bluetooth packages...${NC}"
    pacman -S --noconfirm bluez bluez-utils blueman
    systemctl enable bluetooth.service
else
    echo -e "${BBlue}No Bluetooth hardware detected. Skipping.${NC}"
fi

# 3) Enable LightDM display manager
echo -e "${BBlue}Enabling LightDM...${NC}"

# Disable GDM if enabled
if systemctl is-enabled gdm.service &>/dev/null; then
    systemctl disable gdm.service --now 2>/dev/null || true
fi

# Remove stale display-manager symlink
if [ -L /etc/systemd/system/display-manager.service ]; then
    rm -f /etc/systemd/system/display-manager.service
fi

systemctl enable lightdm.service

# 4) Apply Openbox settings for the target user
echo -e "${BBlue}Applying Openbox settings for user $TARGET_USER...${NC}"
sudo -u "$TARGET_USER" mkdir -p "$HOME_DIR/.config/openbox"

# Copy default Openbox config if available
if [ -d "/etc/xdg/openbox" ]; then
    sudo -u "$TARGET_USER" cp /etc/xdg/openbox/* "$HOME_DIR/.config/openbox/"
fi

# Create Tint2 configuration (panel at top)
sudo -u "$TARGET_USER" mkdir -p "$HOME_DIR/.config/tint2"
cat > "$HOME_DIR/.config/tint2/tint2rc" << 'EOF'
#---------------------------------------------
# Tint2 Panel Configuration for Top Position
#---------------------------------------------
panel_items = TSC
panel_monitor = all
panel_position = top center horizontal
panel_size = 100% 30
panel_margin = 0 0
panel_padding = 5 5 5
taskbar_mode = multi_desktop
taskbar_padding = 2 2 2
taskbar_background_id = 0
task_icon_size = 0
font = Sans 10
#---------------------------------------------
EOF
chown -R "$TARGET_USER:$TARGET_USER" "$HOME_DIR/.config/tint2"

# Create autostart script for Openbox
cat > "$HOME_DIR/.config/openbox/autostart" << 'EOF'
#!/bin/bash
# Start a top-panel with Tint2
tint2 &
# Set a wallpaper
feh --bg-scale /usr/share/backgrounds/archbtw.jpg
# Start NetworkManager applet
nm-applet &
EOF
chown "$TARGET_USER:$TARGET_USER" "$HOME_DIR/.config/openbox/autostart"
chmod +x "$HOME_DIR/.config/openbox/autostart"

# Install themes into user directory (safe clone into tmpdir, then move)
echo -e "${BBlue}Installing Openbox themes...${NC}"
THEMES_DIR="$HOME_DIR/.themes"
if [ ! -d "$THEMES_DIR" ]; then
    sudo -u "$TARGET_USER" git clone --depth=1 \
        https://github.com/addy-dclxvi/openbox-theme-collections "$THEMES_DIR"
else
    echo "Themes directory already exists, skipping clone."
fi

# 5) Hardening — restrict access to user config directories
echo -e "${BBlue}Applying basic hardening...${NC}"
chmod 700 "$HOME_DIR/.config"
chmod 700 "$THEMES_DIR" 2>/dev/null || true

echo -e "${BGreen}Openbox installation complete. Reboot to start LightDM.${NC}"
