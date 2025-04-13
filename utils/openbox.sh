#!/bin/bash

# Description: This script installs and configures Openbox on Arch Linux.
#              It includes a Tint2 panel configured at the top of the screen
#              and applies optional hardening steps.
# Author: Bruno Schmid @brulliant
# LinkedIn: https://www.linkedin.com/in/schmidbruno/

set -euo pipefail

BBlue='\033[1;34m'
NC='\033[0m'

# -- EDIT THIS to your actual desktop user --
TARGET_USER="$USER"
HOME_DIR="/home/$TARGET_USER"

# Function to handle errors
handle_error() {
    echo "Error: $1" >&2
    exit 1
}

# 1) Install Openbox and related packages
echo -e "${BBlue}Installing Openbox and essential desktop packages...${NC}"
sudo pacman -Syu --noconfirm || handle_error "Failed to update system."
sudo pacman -S --noconfirm \
  xorg-server xorg-xinit openbox obconf-qt \
  lightdm lightdm-gtk-greeter terminator \
  tint2 pcmanfm xterm networkmanager network-manager-applet \
  thunar-archive-plugin xarchiver feh lxappearance neofetch\
  || handle_error "Failed to install Openbox packages."

# 2) Bluetooth detection and installation
if lsusb | grep -iq "bluetooth" || lspci | grep -iq "bluetooth"; then
    echo -e "${BBlue}Bluetooth hardware detected. Installing Bluetooth packages...${NC}"
    sudo pacman -S --noconfirm bluez bluez-utils blueman || handle_error "Failed to install Bluetooth packages."
    sudo systemctl enable bluetooth.service || handle_error "Failed to enable Bluetooth service."
else
    echo -e "${BBlue}No Bluetooth hardware detected. Skipping Bluetooth installation.${NC}"
fi

# 3) Enable LightDM display manager
echo -e "${BBlue}Enabling LightDM (Display Manager)...${NC}"

# 1) Disable GDM (if it exists and is running)
if systemctl is-enabled gdm.service &>/dev/null; then
    sudo systemctl disable gdm.service --now || handle_error "Failed to disable GDM."
fi

# 2) Remove the existing display-manager.service symlink if it's pointing to gdm
if [ -L /etc/systemd/system/display-manager.service ]; then
    sudo rm -f /etc/systemd/system/display-manager.service || handle_error "Failed to remove existing display-manager.service symlink."
fi

# 3) Now enable LightDM
sudo systemctl enable lightdm.service || handle_error "Failed to enable LightDM service."

# 4) Apply Openbox settings for the target user
echo -e "${BBlue}Applying Openbox settings for user $TARGET_USER...${NC}"
sudo -u "$TARGET_USER" mkdir -p "$HOME_DIR/.config/openbox" || handle_error "Failed to create Openbox config directory."

# Copy default Openbox config if available
if [ -d "/etc/xdg/openbox" ]; then
  sudo -u "$TARGET_USER" cp /etc/xdg/openbox/* "$HOME_DIR/.config/openbox" || handle_error "Failed to copy default Openbox configs."
fi

# Create a tint2 configuration folder and file to place the panel at the top
sudo -u "$TARGET_USER" mkdir -p "$HOME_DIR/.config/tint2" || handle_error "Failed to create Tint2 config directory."
cat << 'EOF' > "$HOME_DIR/.config/tint2/tint2rc"
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

chown -R "$TARGET_USER":"$TARGET_USER" "$HOME_DIR/.config/tint2"

# Create a basic autostart script for Openbox
cat << 'EOF' > "$HOME_DIR/.config/openbox/autostart"
#!/bin/bash
# Start a top-panel with Tint2
tint2 &
# Set a wallpaper
feh --bg-scale /usr/share/backgrounds/archbtw.jpg
# Start NetworkManager applet
nm-applet &
EOF
sudo chown "$TARGET_USER":"$TARGET_USER" "$HOME_DIR/.config/openbox/autostart"
sudo chmod +x "$HOME_DIR/.config/openbox/autostart"

echo -e "${BBlue}Adding themes...${NC}"
git clone https://github.com/addy-dclxvi/openbox-theme-collections ~/.themes

# 5) Hardening (general example: limit permissions on ~/.config)
echo -e "${BBlue}Applying basic hardening steps...${NC}"
sudo chmod 700 "$HOME_DIR/.config" || handle_error "Failed to set permissions on .config directory."
sudo chmod 700 "$HOME_DIR/.themes" || handle_error "Failed to set permissions on .themes directory."

sleep 2
echo -e "${BBlue}Openbox installation and configuration completed.\nYou can reboot to start LightDM (and Openbox) now.${NC}"
