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
  gdm gitg gnome gnome-appfolders-manager gnome-backgrounds gnome-bluetooth-3.0 gnome-connections gnome-logs evince vinagre\
  gnome-calculator gnome-console gnome-disk-utility gnome-epub-thumbnailer gnome-firmware gnome-keybindings eog libforensic1394\
  gnome-keyring networkmanager-openvpn nautilus parted regexxer seahorse-nautilus jomon gnome-control-center firefox baobab deja-dup\
  sushi xdg-desktop-portal-gnome ghex gnome-font-viewer gnome-multi-writer gnome-nettool gnome-session gnome-screenshot loupe\
  gnome-shell gnome-shell-extension-arc-menu gnome-shell-extension-caffeine gnome-shell-extension-dash-to-panel veracrypt \
  gnome-shell-extension-desktop-icons-ng gnome-shell-extension-vitals gnome-software gnome-terminal gnome-tweaks onionshare \
  gsettings-desktop-schemas gsettings-system-schemas gthumb gtranslator komikku mutter gedit gedit-plugins chromium mvt gnome-dictionary\
  xdg-user-dirs-gtk xorg-server xdg-utils xorg-xinit torbrowser-launcher networkmanager-openconnect networkmanager-strongswan

# 2) Enable GDM service
echo -e "${BBlue}Enabling GDM (GNOME Display Manager)...${NC}"
systemctl enable gdm.service

# 3) Apply GNOME settings for the specified user
echo -e "${BBlue}Applying GNOME/dconf configuration for user '${TARGET_USER}'...${NC}"

# Explicitly run each gsettings command as the target user
sudo -u "$TARGET_USER" gsettings set apps.update-manager first-run false || true
sudo -u "$TARGET_USER" gsettings set apps.update-manager launch-count 1 || true
sudo -u "$TARGET_USER" gsettings set apps.update-manager launch-time 1736281180 || true

sudo -u "$TARGET_USER" gsettings set org.gnome.control-center last-panel 'privacy'
sudo -u "$TARGET_USER" gsettings set org.gnome.control-center window-state '(980, 640, false)'

sudo -u "$TARGET_USER" gsettings set org.gnome.desktop.app-folders.folder:/org/gnome/desktop/app-folders/folders/Pardus/ categories "['X-Pardus-Apps']"
sudo -u "$TARGET_USER" gsettings set org.gnome.desktop.app-folders.folder:/org/gnome/desktop/app-folders/folders/Pardus/ name 'X-Pardus-Apps.directory'
sudo -u "$TARGET_USER" gsettings set org.gnome.desktop.app-folders.folder:/org/gnome/desktop/app-folders/folders/Pardus/ translate true

sudo -u "$TARGET_USER" gsettings set org.gnome.desktop.app-folders.folder:/org/gnome/desktop/app-folders/folders/Utilities/ apps "['gnome-abrt.desktop', 'gnome-system-log.desktop', 'nm-connection-editor.desktop', 'org.gnome.baobab.desktop', 'org.gnome.Connections.desktop', 'org.gnome.DejaDup.desktop', 'org.gnome.Dictionary.desktop', 'org.gnome.DiskUtility.desktop', 'org.gnome.Evince.desktop', 'org.gnome.FileRoller.desktop', 'org.gnome.fonts.desktop', 'org.gnome.Loupe.desktop', 'org.gnome.seahorse.Application.desktop', 'org.gnome.tweaks.desktop', 'org.gnome.Usage.desktop', 'vinagre.desktop']"
sudo -u "$TARGET_USER" gsettings set org.gnome.desktop.app-folders.folder:/org/gnome/desktop/app-folders/folders/Utilities/ categories "['X-GNOME-Utilities']"
sudo -u "$TARGET_USER" gsettings set org.gnome.desktop.app-folders.folder:/org/gnome/desktop/app-folders/folders/Utilities/ name 'X-GNOME-Utilities.directory'
sudo -u "$TARGET_USER" gsettings set org.gnome.desktop.app-folders.folder:/org/gnome/desktop/app-folders/folders/Utilities/ translate true

sudo -u "$TARGET_USER" gsettings set org.gnome.desktop.input-sources sources "[('xkb', 'ch+de_nodeadkeys')]"

sudo -u "$TARGET_USER" gsettings set org.gnome.desktop.interface color-scheme 'prefer-dark'

sudo -u "$TARGET_USER" gsettings set org.gnome.desktop.notifications application-children "['org-gnome-nautilus']"

sudo -u "$TARGET_USER" gsettings set org.gnome.desktop.notifications.application:/org/gnome/desktop/notifications/application/org-gnome-nautilus/ application-id 'org.gnome.Nautilus.desktop'

sudo -u "$TARGET_USER" gsettings set org.gnome.desktop.screensaver lock-enabled false

sudo -u "$TARGET_USER" gsettings set org.gnome.desktop.session idle-delay 0

sudo -u "$TARGET_USER" gsettings set org.gnome.evolution-data-server migrated true

sudo -u "$TARGET_USER" gsettings set org.gnome.mutter edge-tiling false

sudo -u "$TARGET_USER" gsettings set org.gnome.mutter.keybindings toggle-tiled-left "[]"
sudo -u "$TARGET_USER" gsettings set org.gnome.mutter.keybindings toggle-tiled-right "[]"

sudo -u "$TARGET_USER" gsettings set org.gnome.nautilus.preferences default-folder-viewer 'icon-view'
sudo -u "$TARGET_USER" gsettings set org.gnome.nautilus.preferences migrated-gtk-settings true
sudo -u "$TARGET_USER" gsettings set org.gnome.nautilus.preferences search-filter-time-type 'last_modified'

sudo -u "$TARGET_USER" gsettings set org.gnome.nautilus.window-state initial-size '(889, 562)'

sudo -u "$TARGET_USER" gsettings set org.gnome.settings-daemon.plugins.color night-light-schedule-automatic false

sudo -u "$TARGET_USER" gsettings set org.gnome.shell favorite-apps "['firefox_firefox.desktop', 'org.gnome.Nautilus.desktop', 'snap-store_snap-store.desktop', 'yelp.desktop', 'org.gnome.Terminal.desktop']"
sudo -u "$TARGET_USER" gsettings set org.gnome.shell welcome-dialog-last-shown-version '47.0'

sudo -u "$TARGET_USER" gsettings set org.gnome.shell.extensions.ding check-x11wayland true

sudo -u "$TARGET_USER" gsettings set org.gnome.shell.extensions.tiling-assistant active-window-hint-color 'rgb(211,70,21)'
sudo -u "$TARGET_USER" gsettings set org.gnome.shell.extensions.tiling-assistant last-version-installed 48
sudo -u "$TARGET_USER" gsettings set org.gnome.shell.extensions.tiling-assistant overridden-settings "{'org.gnome.mutter.edge-tiling': <@mb nothing>, 'org.gnome.mutter.keybindings.toggle-tiled-left': <@mb nothing>, 'org.gnome.mutter.keybindings.toggle-tiled-right': <@mb nothing>}"

sudo -u "$TARGET_USER" gsettings set org.gnome.shell.world-clocks locations "[]"

sudo -u "$TARGET_USER" gsettings set org.gtk.gtk4.settings.file-chooser show-hidden false
sudo -u "$TARGET_USER" gsettings set org.gtk.gtk4.settings.file-chooser sort-directories-first true

echo -e "${BBlue}GNOME Desktop configuration completed.\nYou can reboot to start GDM (GNOME) now.${NC}"
