#!/bin/bash

# Description: This script installs and configures GNOME Desktop on Arch Linux.
#              It also applies specific GNOME/dconf settings for one user.
# Author: Bruno Schmid @brulliant
# LinkedIn: https://www.linkedin.com/in/schmidbruno/

set -euo pipefail

BBlue='\033[1;34m'
NC='\033[0m'

# -- EDIT THIS to your actual desktop user --
TARGET_USER="myusername"
HOME_DIR="/home/$TARGET_USER"

if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root (e.g., with sudo or as root)." >&2
  exit 1
fi

# 1) Install GNOME Desktop packages
echo -e "${BBlue}Installing GNOME Desktop packages...${NC}"
pacman -S --noconfirm \
  gdm gitg gnome gnome-appfolders-manager gnome-backgrounds gnome-bluetooth-3.0 gnome-connections gnome-logs \
  gnome-calculator gnome-console gnome-disk-utility gnome-epub-thumbnailer gnome-firmware gnome-keybindings eog \
  gnome-keyring network-manager-gnome network-manager-openvpn-gnome nautilus parted regexxer seahorse-nautilus \
  sushi xdg-desktop-portal-gnome ghex gnome-font-viewer gnome-multi-writer gnome-nettool gnome-session gnome-screenshot \
  gnome-shell gnome-shell-extension-arc-menu gnome-shell-extension-caffeine gnome-shell-extension-dash-to-panel veracrypt \
  gnome-shell-extension-desktop-icons-ng gnome-shell-extension-vitals gnome-software gnome-terminal gnome-tweaks \
  gsettings-desktop-schemas gsettings-system-schemas gthumb gtranslator komikku mutter gedit gedit-plugins chromium \
  xdg-user-dirs-gtk xorg-server xdg-utils xinit x11-session-utils x11-xserver-utils gnome-control-center

# 2) Enable GDM service
echo -e "${BBlue}Enabling GDM (GNOME Display Manager)...${NC}"
systemctl enable gdm.service

# 3) Apply GNOME settings for the specified user
echo -e "${BBlue}Applying GNOME/dconf configuration for user '${TARGET_USER}'...${NC}"

# Make sure the user’s D-Bus session is available (common in a live system). If not, we can still
# write to dconf by forcing environment variables or using a dconf-user override. 
# Easiest approach: use 'sudo -u' with gsettings if the user is already logged in or can log in.

# We’ll do everything in a heredoc to keep it simple
sudo -u "$TARGET_USER" bash <<EOF

################################################################################
# Some of these schemas may NOT exist on a stock Arch GNOME system (e.g. apps.update-manager).
# If you want to avoid errors on missing schemas, append "|| true" to each gsettings line.
################################################################################

# [apps/update-manager]
gsettings set apps.update-manager first-run false || true
gsettings set apps.update-manager launch-count 1 || true
gsettings set apps.update-manager launch-time 1736281180 || true

# [com/ubuntu/update-notifier]
gsettings set com.ubuntu.update-notifier release-check-time 1736280597 || true

# [org/gnome/control-center]
gsettings set org.gnome.control-center last-panel 'privacy'
gsettings set org.gnome.control-center window-state '(980, 640, false)'

# [org/gnome/desktop/app-folders]
gsettings set org.gnome.desktop.app-folders folder-children "['Utilities', 'YaST', 'Pardus']"

# [org/gnome/desktop/app-folders/folders/Pardus]
gsettings set org.gnome.desktop.app-folders.folder:/org/gnome/desktop/app-folders/folders/Pardus/ categories "['X-Pardus-Apps']"
gsettings set org.gnome.desktop.app-folders.folder:/org/gnome/desktop/app-folders/folders/Pardus/ name 'X-Pardus-Apps.directory'
gsettings set org.gnome.desktop.app-folders.folder:/org/gnome/desktop/app-folders/folders/Pardus/ translate true

# [org/gnome/desktop/app-folders/folders/Utilities]
gsettings set org.gnome.desktop.app-folders.folder:/org/gnome/desktop/app-folders/folders/Utilities/ apps "['gnome-abrt.desktop', 'gnome-system-log.desktop', 'nm-connection-editor.desktop', 'org.gnome.baobab.desktop', 'org.gnome.Connections.desktop', 'org.gnome.DejaDup.desktop', 'org.gnome.Dictionary.desktop', 'org.gnome.DiskUtility.desktop', 'org.gnome.Evince.desktop', 'org.gnome.FileRoller.desktop', 'org.gnome.fonts.desktop', 'org.gnome.Loupe.desktop', 'org.gnome.seahorse.Application.desktop', 'org.gnome.tweaks.desktop', 'org.gnome.Usage.desktop', 'vinagre.desktop']"
gsettings set org.gnome.desktop.app-folders.folder:/org/gnome/desktop/app-folders/folders/Utilities/ categories "['X-GNOME-Utilities']"
gsettings set org.gnome.desktop.app-folders.folder:/org/gnome/desktop/app-folders/folders/Utilities/ name 'X-GNOME-Utilities.directory'
gsettings set org.gnome.desktop.app-folders.folder:/org/gnome/desktop/app-folders/folders/Utilities/ translate true

# [org/gnome/desktop/app-folders/folders/YaST]
gsettings set org.gnome.desktop.app-folders.folder:/org/gnome/desktop/app-folders/folders/YaST/ categories "['X-SuSE-YaST']"
gsettings set org.gnome.desktop.app-folders.folder:/org/gnome/desktop/app-folders/folders/YaST/ name 'suse-yast.directory'
gsettings set org.gnome.desktop.app-folders.folder:/org/gnome/desktop/app-folders/folders/YaST/ translate true

# [org/gnome/desktop/input-sources]
gsettings set org.gnome.desktop.input-sources sources "[('xkb', 'ch+de_nodeadkeys')]"

# [org/gnome/desktop/interface]
gsettings set org.gnome.desktop.interface color-scheme 'prefer-dark'
gsettings set org.gnome.desktop.interface gtk-theme 'Yaru-dark'
gsettings set org.gnome.desktop.interface icon-theme 'Yaru-dark'

# [org/gnome/desktop/notifications]
gsettings set org.gnome.desktop.notifications application-children "['org-gnome-nautilus']"

# [org/gnome/desktop/notifications/application/org-gnome-nautilus]
gsettings set org.gnome.desktop.notifications.application:/org/gnome/desktop/notifications/application/org-gnome-nautilus/ application-id 'org.gnome.Nautilus.desktop'

# [org/gnome/desktop/screensaver]
gsettings set org.gnome.desktop.screensaver lock-enabled false

# [org/gnome/desktop/session]
gsettings set org.gnome.desktop.session idle-delay 0

# [org/gnome/evolution-data-server]
gsettings set org.gnome.evolution-data-server migrated true

# [org/gnome/mutter]
gsettings set org.gnome.mutter edge-tiling false

# [org/gnome/mutter/keybindings]
gsettings set org.gnome.mutter.keybindings toggle-tiled-left "[]"
gsettings set org.gnome.mutter.keybindings toggle-tiled-right "[]"

# [org/gnome/nautilus/preferences]
gsettings set org.gnome.nautilus.preferences default-folder-viewer 'icon-view'
gsettings set org.gnome.nautilus.preferences migrated-gtk-settings true
gsettings set org.gnome.nautilus.preferences search-filter-time-type 'last_modified'

# [org/gnome/nautilus/window-state]
gsettings set org.gnome.nautilus.window-state initial-size '(889, 562)'

# [org/gnome/settings-daemon/plugins/color]
gsettings set org.gnome.settings-daemon.plugins.color night-light-schedule-automatic false

# [org/gnome/shell]
gsettings set org.gnome.shell favorite-apps "['firefox_firefox.desktop', 'org.gnome.Nautilus.desktop', 'snap-store_snap-store.desktop', 'yelp.desktop', 'org.gnome.Terminal.desktop']"
gsettings set org.gnome.shell welcome-dialog-last-shown-version '47.0'

# [org/gnome/shell/extensions/ding]
gsettings set org.gnome.shell.extensions.ding check-x11wayland true

# [org/gnome/shell/extensions/tiling-assistant]
gsettings set org.gnome.shell.extensions.tiling-assistant active-window-hint-color 'rgb(211,70,21)'
gsettings set org.gnome.shell.extensions.tiling-assistant last-version-installed 48
gsettings set org.gnome.shell.extensions.tiling-assistant overridden-settings "{'org.gnome.mutter.edge-tiling': <@mb nothing>, 'org.gnome.mutter.keybindings.toggle-tiled-left': <@mb nothing>, 'org.gnome.mutter.keybindings.toggle-tiled-right': <@mb nothing>}"

# [org/gnome/shell/world-clocks]
gsettings set org.gnome.shell.world-clocks locations "[]"

# [org/gtk/gtk4/settings/file-chooser]
gsettings set org.gtk.gtk4.settings.file-chooser show-hidden false
gsettings set org.gtk.gtk4.settings.file-chooser sort-directories-first true

EOF

echo -e "${BBlue}GNOME Desktop configuration completed.\nYou can reboot to start GDM (GNOME) now.${NC}"
