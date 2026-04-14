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
  xdg-user-dirs-gtk xorg-server xorg-xwayland xdg-utils xorg-xinit xorg-xinput libinput torbrowser-launcher \
  networkmanager-openconnect networkmanager-strongswan \
  qt5-wayland qt6-wayland \
  veracrypt
# Note: seahorse-nautilus was merged into seahorse. gtk-engine-murrine and
# gtk-engines (GTK2 theme engines) were dropped from Arch repos — only in
# AUR now, and not needed for modern GTK3/GTK4 themes.
# xorg-xwayland is required for X11 apps to work under a Wayland session;
# without it gnome-shell logs "Failed to init X11 display: Unknown error"
# and X11-only apps (some older tools, screen sharing helpers) won't run.
# qt5-wayland / qt6-wayland provide the Wayland platform plugins so Qt
# apps render natively under Wayland instead of falling back to XWayland
# (which on NVIDIA tends to be slower and blurrier).

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

# The base installer mounts /proc with hidepid=2,gid=proc. Without
# membership in the `proc` group, gdm cannot walk /proc/<pid>/cgroup
# under the hood of PAM/logind session setup, which leaves Wayland
# sessions unable to register ("GdmDisplay: Session never registered").
# Regular desktop users get added to `proc` in chroot.sh's useradd;
# the system `gdm` user needs it too.
# (Same root cause as nixpkgs issue #112867 for GNOME 45 Wayland.)
if id -u gdm >/dev/null 2>&1; then
    gpasswd -a gdm proc 2>/dev/null || true
fi

# GDM ships /usr/lib/udev/rules.d/61-gdm.rules which disables Wayland
# whenever the NVIDIA proprietary driver is loaded. That rule is stale
# for modern NVIDIA (470+) where Wayland works fine, and when it kicks
# in GDM falls back to an Xorg session that can also fail, leaving
# "gnome-shell: Failed to init X11 display: Unknown error" in the
# journal and no usable desktop. Symlinking the rule to /dev/null
# overrides it without touching the system file, so GDM can start
# Wayland on NVIDIA. Safe no-op on AMD/Intel (the rule only matches
# NVIDIA proprietary).
# Explicitly enable Wayland in GDM. The default is already WaylandEnable=true,
# but writing it makes the intent obvious and survives future default flips.
echo -e "${BBlue}Ensuring WaylandEnable=true in GDM config...${NC}"
install -d /etc/gdm
if [[ ! -f /etc/gdm/custom.conf ]]; then
    cat > /etc/gdm/custom.conf <<'EOF'
[daemon]
WaylandEnable=true

[security]

[xdmcp]

[chooser]

[debug]
EOF
elif ! grep -qE '^\s*WaylandEnable' /etc/gdm/custom.conf; then
    # Insert WaylandEnable under the [daemon] section if present, else append a block.
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
    ln -sf /dev/null /etc/udev/rules.d/61-gdm.rules

    # GTK4 GSK defaults to the GL/Vulkan renderer, which crashes GTK apps
    # on NVIDIA proprietary driver with segfaults in libgtk-3.so (Nautilus
    # is the most common victim). Force the "ngl" renderer system-wide —
    # faster than cairo software fallback while still avoiding the crash.
    # If "ngl" also crashes on this hardware, change to "cairo" by hand.
    echo -e "${BBlue}Applying GSK renderer workaround for NVIDIA GTK segfaults...${NC}"
    install -d /etc/environment.d
    cat > /etc/environment.d/00-nvidia-gsk.conf <<'EOF'
# Force GTK4 GSK to use the "ngl" renderer instead of the default
# GL/Vulkan path, which segfaults in libgtk-3.so on NVIDIA proprietary.
# Switch to "cairo" if ngl also crashes (cairo is pure software — stable
# everywhere but slower). Revert by deleting this file.
GSK_RENDERER=ngl
EOF
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

# Enable KMS modifiers in Mutter — lets XWayland apps (including GTK3
# apps rendered via XWayland) use hardware-accelerated dma-buf paths
# on NVIDIA. Mentioned as the key UX fix in edu4rdshl.dev's Wayland
# migration post and the Arch Wiki GDM Wayland+NVIDIA section.
sudo -u "$TARGET_USER" dbus-launch gsettings set org.gnome.mutter experimental-features "['kms-modifiers']" 2>/dev/null || true

# 8) Harden GNOME configuration
echo -e "${BBlue}Hardening GNOME configuration...${NC}"
systemctl disable --now geoclue.service 2>/dev/null || true
chmod 700 "$HOME_DIR/.config" 2>/dev/null || true

# 9) Clean up package cache
echo -e "${BBlue}Cleaning up package cache...${NC}"
pacman -Sc --noconfirm

echo -e "${BGreen}GNOME Desktop configuration complete. Reboot to start GNOME.${NC}"
