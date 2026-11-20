#!/usr/bin/env bash

# =============================================================================
# Script:      gnome.sh
# Description: Installs and configures a GNOME Desktop on Arch Linux.
#              Avoids games, applies Wayland/NVIDIA fixes and GNOME settings,
#              and hardens the setup.
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
#
# Usage:       sudo ./gnome.sh
# =============================================================================

set -euo pipefail

umask 022

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

if ! id "$TARGET_USER" &>/dev/null; then
    echo -e "${BRed}User '$TARGET_USER' does not exist.${NC}" >&2
    exit 1
fi

HOME_DIR="$(getent passwd "$TARGET_USER" | cut -d: -f6)"
if [ -z "$HOME_DIR" ] || [ ! -d "$HOME_DIR" ]; then
    echo -e "${BRed}Home directory '$HOME_DIR' does not exist.${NC}" >&2
    exit 1
fi

prompt_yes_no() {
    local yn
    while true; do
        read -r -p "$1 (y/n): " yn || return 1
        case $yn in
            [Yy]*) return 0 ;;
            [Nn]*) return 1 ;;
            *) echo "Please answer y or n." ;;
        esac
    done
}

# 1) Update package databases and install core GNOME packages
# Note: gedit-plugins was dropped from official Arch repos; gnome-text-editor
# and gedit come from extra.
echo -e "${BBlue}Installing core GNOME packages...${NC}"
pacman -Syu --needed --noconfirm \
  gdm gnome-backgrounds gnome-connections gnome-logs evince glib2 \
  gnome-calculator gnome-console gnome-disk-utility gnome-epub-thumbnailer gnome-firmware eog \
  gnome-keyring networkmanager-openvpn nautilus seahorse gnome-control-center chromium \
  baobab deja-dup sushi xdg-desktop-portal-gnome gnome-font-viewer gnome-nettool gnome-session \
  gnome-screenshot gnome-shell gnome-software gnome-tweaks onionshare ublock-origin secrets \
  gsettings-desktop-schemas gsettings-system-schemas gedit gnome-text-editor \
  xdg-user-dirs-gtk xorg-server xorg-xwayland xdg-utils xorg-xinit xorg-xinput libinput torbrowser-launcher \
  networkmanager-openconnect networkmanager-strongswan \
  qt5-wayland qt6-wayland \
  obsidian obsidian-icon-theme \
  veracrypt

# 2) Optional packages prompt
echo -e "${BBlue}Optional packages...${NC}"
if prompt_yes_no "Install GNOME Shell extensions (arc-menu, caffeine, dash-to-panel, vitals)?"; then
    pacman -S --needed --noconfirm \
      gnome-shell-extension-arc-menu gnome-shell-extension-caffeine \
      gnome-shell-extension-dash-to-panel gnome-shell-extension-desktop-icons-ng \
      gnome-shell-extension-vitals
fi
if prompt_yes_no "Install additional tools (imagemagick, parted)?"; then
    pacman -S --needed --noconfirm imagemagick parted
fi

# 3) Bluetooth detection and installation
if lsusb 2>/dev/null | grep -iq "bluetooth" || lspci 2>/dev/null | grep -iq "bluetooth"; then
    echo -e "${BBlue}Bluetooth hardware detected. Installing Bluetooth packages...${NC}"
    pacman -S --needed --noconfirm bluez bluez-utils gnome-bluetooth-3.0 blueman
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
        localectl set-keymap "$VCONSOLE_KEYMAP" 2>/dev/null || true
        echo -e "${BGreen}X11 keyboard layout set from vconsole keymap '$VCONSOLE_KEYMAP'.${NC}"
    fi
else
    echo -e "${BBlue}X11 keyboard config already exists (from chroot), skipping.${NC}"
fi

# 5) Enable GDM service
echo -e "${BBlue}Enabling GDM...${NC}"
systemctl enable gdm.service

# Ensure both gdm and the desktop user belong to `proc` when /proc uses hidepid=2,gid=proc
if getent group proc >/dev/null 2>&1; then
    if id -u gdm >/dev/null 2>&1; then
        gpasswd -a gdm proc >/dev/null 2>&1 || true
    fi
    gpasswd -a "$TARGET_USER" proc >/dev/null 2>&1 || true
fi

echo -e "${BBlue}Ensuring WaylandEnable=true in GDM config...${NC}"
install -d -m 0755 /etc/gdm
if [[ ! -f /etc/gdm/custom.conf ]]; then
    cat > /etc/gdm/custom.conf <<'EOF'
[daemon]
WaylandEnable=true

[security]

[xdmcp]

[chooser]

[debug]
EOF
    chmod 0644 /etc/gdm/custom.conf
elif ! grep -qE '^\s*WaylandEnable' /etc/gdm/custom.conf; then
    if grep -qE '^\s*\[daemon\]' /etc/gdm/custom.conf; then
        sed -i '/^\s*\[daemon\]/a WaylandEnable=true' /etc/gdm/custom.conf
    else
        printf '\n[daemon]\nWaylandEnable=true\n' >> /etc/gdm/custom.conf
    fi
else
    sed -i 's/^\s*#\?\s*WaylandEnable\s*=.*/WaylandEnable=true/' /etc/gdm/custom.conf
fi

if lspci 2>/dev/null | grep -qi 'vga.*nvidia\|3d.*nvidia'; then
    echo -e "${BBlue}NVIDIA GPU detected — overriding GDM's NVIDIA-blocks-Wayland rule...${NC}"
    install -d -m 0755 /etc/udev/rules.d
    ln -sf /dev/null /etc/udev/rules.d/61-gdm.rules

    echo -e "${BBlue}Applying GSK renderer workaround for NVIDIA GTK segfaults...${NC}"
    install -d -m 0755 /etc/environment.d
    cat > /etc/environment.d/00-nvidia-gsk.conf <<'EOF'
# Force GTK4 GSK to use the "ngl" renderer instead of the default
# GL/Vulkan path, which segfaults in libgtk-3.so on NVIDIA proprietary.
# Switch to "cairo" if ngl also crashes (cairo is pure software — stable
# everywhere but slower). Revert by deleting this file.
GSK_RENDERER=ngl
EOF
    chmod 0644 /etc/environment.d/00-nvidia-gsk.conf
fi

echo -e "${BBlue}Ensuring DNS-over-TLS works with NetworkManager...${NC}"
systemctl enable --now systemd-resolved
chattr -i /etc/resolv.conf 2>/dev/null || true
rm -f /etc/resolv.conf
ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
install -d -m 0755 /etc/NetworkManager/conf.d
cat > /etc/NetworkManager/conf.d/dns.conf <<'EOF'
[main]
dns=systemd-resolved
EOF
chmod 0644 /etc/NetworkManager/conf.d/dns.conf
if systemctl is-active --quiet NetworkManager; then
    systemctl try-restart NetworkManager || true
fi

# 6) PipeWire note
echo -e "${BBlue}PipeWire will start automatically on user login via systemd user units.${NC}"

# 7) Apply GNOME settings for the target user using dbus-run-session (ships in core dbus)
echo -e "${BBlue}Applying GNOME settings for user $TARGET_USER...${NC}"
if command -v dbus-run-session >/dev/null 2>&1; then
    runuser -u "$TARGET_USER" -- env HOME="$HOME_DIR" dbus-run-session -- \
        gsettings set org.gnome.desktop.interface color-scheme 'prefer-dark' 2>/dev/null || true
    runuser -u "$TARGET_USER" -- env HOME="$HOME_DIR" dbus-run-session -- \
        gsettings set org.gnome.mutter experimental-features "['kms-modifiers']" 2>/dev/null || true
fi

# 8) Harden GNOME configuration
echo -e "${BBlue}Hardening GNOME configuration...${NC}"
# geoclue.service is D-Bus activated, so "disable" alone does not keep it from
# starting again; mask it (undo with: systemctl unmask geoclue.service).
systemctl mask --now geoclue.service 2>/dev/null || true
chmod 700 "$HOME_DIR/.config" 2>/dev/null || true

# 9) Clean up package cache
echo -e "${BBlue}Cleaning up package cache...${NC}"
pacman -Sc --noconfirm

echo -e "${BGreen}GNOME Desktop configuration complete. Reboot to start GNOME.${NC}"
