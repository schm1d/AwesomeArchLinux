#!/usr/bin/env bash

# =============================================================================
# Script:      openbox.sh
# Description: Installs an Archcraft-inspired lightweight Openbox desktop:
#              top Tint2 panel, Picom transparency, Terminator, Rofi, Dunst,
#              dark GTK/Openbox theme, wallpaper, and Neofetch/Fastfetch.
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
#
# Usage:       sudo ./openbox.sh [--user USER] [--no-lightdm]
# =============================================================================

set -euo pipefail

BBlue='\033[1;34m'
BRed='\033[1;31m'
BGreen='\033[1;32m'
BYellow='\033[1;33m'
NC='\033[0m'

TARGET_USER="${SUDO_USER:-}"
ENABLE_LIGHTDM=1

usage() {
    cat <<'EOF'
Usage: sudo ./openbox.sh [options]

Options:
  -u, --user USER     Configure the Openbox session for USER.
                      Defaults to SUDO_USER.
      --no-lightdm    Install and configure the desktop, but do not enable LightDM.
  -h, --help          Show this help.

This script should be run as root, normally via sudo from the target user:
  sudo ./utils/openbox.sh
EOF
}

info() {
    echo -e "${BBlue}$*${NC}"
}

ok() {
    echo -e "${BGreen}$*${NC}"
}

warn() {
    echo -e "${BYellow}Warning: $*${NC}" >&2
}

err() {
    echo -e "${BRed}Error: $*${NC}" >&2
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -u|--user)
            if [[ $# -lt 2 ]]; then
                err "$1 requires a username"
                exit 1
            fi
            TARGET_USER="$2"
            shift 2
            ;;
        --no-lightdm)
            ENABLE_LIGHTDM=0
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            err "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

if [[ "$(id -u)" -ne 0 ]]; then
    err "This script must be run as root, for example: sudo ./utils/openbox.sh"
    exit 1
fi

if [[ -z "$TARGET_USER" || "$TARGET_USER" == "root" ]]; then
    err "Run via sudo as a non-root user, or pass --user USER."
    exit 1
fi

if ! id "$TARGET_USER" >/dev/null 2>&1; then
    err "User '$TARGET_USER' does not exist."
    exit 1
fi

TARGET_HOME="$(getent passwd "$TARGET_USER" | awk -F: '{print $6}')"
TARGET_GROUP="$(id -gn "$TARGET_USER")"

if [[ -z "$TARGET_HOME" || ! -d "$TARGET_HOME" ]]; then
    err "Home directory for '$TARGET_USER' does not exist."
    exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"

PACMAN_PACKAGES=(
    xorg-server
    xorg-xinit
    xorg-xrandr
    xorg-xsetroot
    xorg-xprop
    xorg-xwininfo
    xorg-xinput
    xorg-fonts-misc
    ttf-dejavu
    xf86-input-libinput
    libinput
    openbox
    obconf-qt
    lightdm
    lightdm-gtk-greeter
    terminator
    tint2
    picom
    rofi
    dunst
    feh
    lxappearance
    xsettingsd
    thunar
    thunar-archive-plugin
    xarchiver
    gvfs
    tumbler
    networkmanager
    network-manager-applet
    polkit-gnome
    pipewire
    pipewire-pulse
    wireplumber
    pavucontrol
    pamixer
    playerctl
    brightnessctl
    materia-gtk-theme
    papirus-icon-theme
    ttf-jetbrains-mono-nerd
    otf-font-awesome
    noto-fonts
    noto-fonts-emoji
    maim
    xclip
    libnotify
    xdg-user-dirs
    xdg-user-dirs-gtk
    xdg-utils
    numlockx
    volumeicon
    cbatticon
    fastfetch
)

install_packages() {
    info "Installing lightweight Openbox desktop packages..."
    pacman -S --needed --noconfirm "${PACMAN_PACKAGES[@]}"
}

install_neofetch_if_available() {
    if pacman -Si neofetch >/dev/null 2>&1; then
        info "Installing neofetch from the official repositories..."
        pacman -S --needed --noconfirm neofetch
        return
    fi

    if command -v yay >/dev/null 2>&1; then
        info "Installing neofetch from AUR with yay..."
        if sudo -u "$TARGET_USER" yay -S --needed --noconfirm neofetch; then
            return
        fi
        warn "AUR neofetch install failed. Keeping fastfetch as a compatible fallback."
        return
    fi

    if command -v paru >/dev/null 2>&1; then
        info "Installing neofetch from AUR with paru..."
        if sudo -u "$TARGET_USER" paru -S --needed --noconfirm neofetch; then
            return
        fi
        warn "AUR neofetch install failed. Keeping fastfetch as a compatible fallback."
        return
    fi

    warn "neofetch is not in the current official Arch repos. fastfetch was installed; install yay and re-run if you specifically want AUR neofetch."
}

has_bluetooth_hardware() {
    local usb_devices=""
    local pci_devices=""

    usb_devices="$(lsusb 2>/dev/null || true)"
    pci_devices="$(lspci 2>/dev/null || true)"

    [[ "$usb_devices$pci_devices" =~ [Bb]luetooth ]]
}

install_bluetooth_if_present() {
    if has_bluetooth_hardware; then
        info "Bluetooth hardware detected. Installing Bluetooth support..."
        pacman -S --needed --noconfirm bluez bluez-utils blueman
        systemctl enable bluetooth.service
    else
        info "No Bluetooth hardware detected. Skipping Bluetooth packages."
    fi
}

enable_services() {
    info "Enabling desktop services..."
    systemctl enable NetworkManager.service

    info "Ensuring DNS-over-TLS works with NetworkManager..."
    # On an already-running system (the usual case for this script) the
    # NM -> resolved handoff only works if resolved is active,
    # /etc/resolv.conf points at its stub, and NM is configured with the
    # systemd-resolved dns backend. chroot.sh only writes that drop-in if
    # /etc/NetworkManager/conf.d exists at install time; when NM is
    # installed later by this script, we must write it ourselves.
    systemctl enable --now systemd-resolved
    ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
    install -d /etc/NetworkManager/conf.d
    cat > /etc/NetworkManager/conf.d/dns.conf <<'EOF'
[main]
dns=systemd-resolved
EOF
    # try-restart is a no-op if NM isn't active yet (e.g. first boot after
    # this script runs), which keeps set -euo pipefail happy without the
    # blanket `|| true` mask.
    if systemctl is-active --quiet NetworkManager; then
        systemctl try-restart NetworkManager || true
    fi

    if [[ "$ENABLE_LIGHTDM" -eq 1 ]]; then
        for dm in gdm sddm lxdm ly; do
            systemctl disable --now "$dm.service" >/dev/null 2>&1 || true
        done

        if [[ -L /etc/systemd/system/display-manager.service ]]; then
            rm -f /etc/systemd/system/display-manager.service
        fi

        systemctl enable lightdm.service
    else
        warn "LightDM was installed but not enabled because --no-lightdm was passed."
    fi
}

configure_x11_keyboard() {
    # If the chroot already wrote 00-keyboard.conf, skip — it's configured.
    if [[ -f /etc/X11/xorg.conf.d/00-keyboard.conf ]]; then
        info "X11 keyboard config already exists (from chroot), skipping."
        return
    fi

    # Read the current keymap from vconsole.conf
    local vconsole_keymap=""
    if [[ -f /etc/vconsole.conf ]]; then
        vconsole_keymap=$(sed -n 's/^KEYMAP=//p' /etc/vconsole.conf)
    fi

    if [[ -z "$vconsole_keymap" ]]; then
        info "No KEYMAP found in vconsole.conf, skipping X11 keyboard setup."
        return
    fi

    # localectl set-keymap translates the vconsole keymap to X11 via
    # /usr/share/systemd/kbd-model-map and writes 00-keyboard.conf for us.
    info "Setting X11 keyboard layout from vconsole keymap '$vconsole_keymap'..."
    localectl set-keymap "$vconsole_keymap" 2>/dev/null || true
    info "X11 keyboard layout applied from vconsole keymap '$vconsole_keymap'."
}

write_xorg_input_config() {
    info "Writing libinput Xorg catchalls to /etc/X11/xorg.conf.d/50-libinput.conf..."

    install -d /etc/X11/xorg.conf.d
    cat > /etc/X11/xorg.conf.d/50-libinput.conf <<'EOF'
Section "InputClass"
    Identifier "libinput pointer catchall"
    MatchIsPointer "on"
    MatchDevicePath "/dev/input/event*"
    Driver "libinput"
    Option "AccelProfile" "flat"
EndSection

Section "InputClass"
    Identifier "libinput keyboard catchall"
    MatchIsKeyboard "on"
    MatchDevicePath "/dev/input/event*"
    Driver "libinput"
EndSection

Section "InputClass"
    Identifier "libinput touchpad catchall"
    MatchIsTouchpad "on"
    MatchDevicePath "/dev/input/event*"
    Driver "libinput"
    Option "Tapping" "on"
    Option "NaturalScrolling" "true"
EndSection
EOF
}

# Detect a Corsair gaming keyboard via sysfs (no extra package dep needed).
# Corsair K-series gaming keyboards enumerate under /sys/class/input/inputN
# with id/vendor == "1b1c" and a name containing "Keyboard". We scan those
# nodes and return 0 on first match, 1 otherwise.
has_corsair_gaming_keyboard() {
    local input vendor name
    shopt -s nullglob
    for input in /sys/class/input/input*; do
        [[ -d "$input" ]] || continue

        vendor=""
        if [[ -r "$input/id/vendor" ]]; then
            vendor="$(tr -d '[:space:]' < "$input/id/vendor" 2>/dev/null || true)"
        fi

        # Compare against Corsair USB vendor id 1b1c (case-insensitive).
        if [[ "${vendor,,}" != "1b1c" ]]; then
            continue
        fi

        name=""
        if [[ -r "$input/name" ]]; then
            name="$(tr -d '\n' < "$input/name" 2>/dev/null || true)"
        fi

        # Any Corsair input device whose kernel name contains "Keyboard" is
        # good enough: gaming keyboards always advertise that string, while
        # a standalone Corsair mouse does not.
        if [[ "$name" == *[Kk]eyboard* ]]; then
            shopt -u nullglob
            return 0
        fi
    done
    shopt -u nullglob
    return 1
}

install_corsair_keyboard_workaround() {
    local rules_file="/etc/udev/rules.d/99-corsair-gaming-kbd-fake-mouse.rules"

    if ! has_corsair_gaming_keyboard; then
        info "No Corsair gaming keyboard detected, skipping fake-mouse udev workaround."
        return
    fi

    warn "Corsair gaming keyboard detected. Installing fake-mouse udev workaround at $rules_file"
    warn "If you later attach a real Corsair-branded mouse, delete this file: rm $rules_file"

    install -d /etc/udev/rules.d
    cat > "$rules_file" <<'EOF'
# Disable Corsair gaming-keyboard fake mouse interface on device enumeration.
#
# Corsair K-series gaming keyboards (e.g. K95 RGB Platinum) expose two USB HID
# interfaces: a real keyboard and a fake "mouse" used for macros and G-keys.
# On minimal Xorg/libinput setups the fake mouse device confuses libinput and
# the real USB mouse cursor ends up non-functional after startx / LightDM.
#
# This rule unsets ID_INPUT_MOUSE on any input device whose USB vendor id is
# Corsair (1b1c) and which was flagged as a mouse by the kernel. That kills
# the fake-mouse interface without touching the keyboard interface.
#
# Generated by utils/openbox.sh because a Corsair keyboard was detected at
# install time. SIDE-EFFECT: if you later plug in a real Corsair-branded
# mouse it will be ignored by libinput until you remove this file:
#
#   rm /etc/udev/rules.d/99-corsair-gaming-kbd-fake-mouse.rules
#   sudo udevadm control --reload-rules && sudo udevadm trigger
#
SUBSYSTEM=="input", ATTRS{idVendor}=="1b1c", ENV{ID_INPUT_MOUSE}=="1", ENV{ID_INPUT}="0", ENV{ID_INPUT_MOUSE}="0"
EOF

    info "Reloading udev rules so the Corsair workaround takes effect..."
    udevadm control --reload-rules
    udevadm trigger
}

install_wallpaper() {
    info "Installing wallpaper assets..."
    install -d -m 755 /usr/share/backgrounds
    install -d -m 755 -o "$TARGET_USER" -g "$TARGET_GROUP" "$TARGET_HOME/.local/share/backgrounds"

    if [[ -f "$REPO_ROOT/archLinux.png" ]]; then
        install -m 644 "$REPO_ROOT/archLinux.png" /usr/share/backgrounds/awesome-arch-openbox.png
        install -m 644 -o "$TARGET_USER" -g "$TARGET_GROUP" \
            "$REPO_ROOT/archLinux.png" \
            "$TARGET_HOME/.local/share/backgrounds/awesome-arch-openbox.png"
    else
        warn "archLinux.png was not found. The session will fall back to a solid dark background."
    fi
}

write_openbox_config() {
    info "Writing Openbox session configuration for $TARGET_USER..."

    install -d -m 700 -o "$TARGET_USER" -g "$TARGET_GROUP" "$TARGET_HOME/.config"
    install -d -m 700 -o "$TARGET_USER" -g "$TARGET_GROUP" "$TARGET_HOME/.config/openbox"
    install -d -m 700 -o "$TARGET_USER" -g "$TARGET_GROUP" "$TARGET_HOME/.local/bin"

    cat > "$TARGET_HOME/.config/openbox/autostart" <<'EOF'
#!/usr/bin/env bash

run_bg() {
    command -v "$1" >/dev/null 2>&1 || return 0
    "$@" &
}

command -v xsetroot >/dev/null 2>&1 && xsetroot -cursor_name left_ptr
command -v xset >/dev/null 2>&1 && xset s off -dpms
run_bg numlockx on

if [[ -x /usr/lib/polkit-gnome/polkit-gnome-authentication-agent-1 ]]; then
    /usr/lib/polkit-gnome/polkit-gnome-authentication-agent-1 &
fi

run_bg xsettingsd -c "$HOME/.config/xsettingsd/xsettingsd.conf"
run_bg dunst
run_bg nm-applet --indicator
run_bg volumeicon
run_bg cbatticon -u 5
run_bg picom --config "$HOME/.config/picom/picom.conf"

if [[ -f "$HOME/.local/share/backgrounds/awesome-arch-openbox.png" ]]; then
    feh --no-fehbg --bg-fill "$HOME/.local/share/backgrounds/awesome-arch-openbox.png" &
else
    xsetroot -solid "#0b0e14" &
fi

run_bg tint2 -c "$HOME/.config/tint2/tint2rc"
EOF

    cat > "$TARGET_HOME/.config/openbox/environment" <<'EOF'
export PATH="$HOME/.local/bin:$PATH"
export GTK_THEME=Materia-dark
export QT_QPA_PLATFORMTHEME=gtk2
export TERMINAL=terminator
EOF

    cat > "$TARGET_HOME/.config/openbox/menu.xml" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<openbox_menu xmlns="http://openbox.org/3.4/menu">
  <menu id="root-menu" label="Openbox">
    <item label="Launcher">
      <action name="Execute">
        <command>awesome-arch-rofi drun</command>
      </action>
    </item>
    <item label="Run Command">
      <action name="Execute">
        <command>awesome-arch-rofi run</command>
      </action>
    </item>
    <separator/>
    <item label="Terminal">
      <action name="Execute">
        <command>terminator</command>
      </action>
    </item>
    <item label="System Fetch">
      <action name="Execute">
        <command>awesome-arch-fetch-terminal</command>
      </action>
    </item>
    <item label="Files">
      <action name="Execute">
        <command>thunar</command>
      </action>
    </item>
    <separator/>
    <menu id="client-list-menu"/>
    <separator/>
    <item label="Appearance">
      <action name="Execute">
        <command>lxappearance</command>
      </action>
    </item>
    <item label="Openbox Settings">
      <action name="Execute">
        <command>obconf-qt</command>
      </action>
    </item>
    <item label="Reconfigure Openbox">
      <action name="Reconfigure"/>
    </item>
    <item label="Power">
      <action name="Execute">
        <command>awesome-arch-powermenu</command>
      </action>
    </item>
  </menu>
</openbox_menu>
EOF

    cat > "$TARGET_HOME/.config/openbox/rc.xml" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<openbox_config xmlns="http://openbox.org/3.4/rc"
                xmlns:xi="http://www.w3.org/2001/XInclude">
  <resistance>
    <strength>10</strength>
    <screen_edge_strength>20</screen_edge_strength>
  </resistance>
  <focus>
    <focusNew>yes</focusNew>
    <followMouse>no</followMouse>
    <focusLast>yes</focusLast>
    <underMouse>no</underMouse>
    <focusDelay>200</focusDelay>
    <raiseOnFocus>no</raiseOnFocus>
  </focus>
  <placement>
    <policy>Smart</policy>
    <center>yes</center>
    <monitor>Primary</monitor>
  </placement>
  <theme>
    <name>AwesomeArch-Openbox</name>
    <titleLayout>NLIMC</titleLayout>
    <keepBorder>yes</keepBorder>
    <animateIconify>yes</animateIconify>
    <font place="ActiveWindow">
      <name>Noto Sans</name>
      <size>10</size>
      <weight>Bold</weight>
    </font>
    <font place="InactiveWindow">
      <name>Noto Sans</name>
      <size>10</size>
      <weight>Normal</weight>
    </font>
    <font place="MenuHeader">
      <name>Noto Sans</name>
      <size>10</size>
      <weight>Bold</weight>
    </font>
    <font place="MenuItem">
      <name>Noto Sans</name>
      <size>10</size>
      <weight>Normal</weight>
    </font>
  </theme>
  <desktops>
    <number>4</number>
    <firstdesk>1</firstdesk>
    <names>
      <name>main</name>
      <name>web</name>
      <name>term</name>
      <name>work</name>
    </names>
    <popupTime>700</popupTime>
  </desktops>
  <resize>
    <drawContents>yes</drawContents>
    <popupShow>Nonpixel</popupShow>
    <popupPosition>Center</popupPosition>
  </resize>
  <margins>
    <top>36</top>
    <bottom>0</bottom>
    <left>0</left>
    <right>0</right>
  </margins>
  <keyboard>
    <chainQuitKey>C-g</chainQuitKey>
    <keybind key="W-space">
      <action name="Execute"><command>awesome-arch-rofi drun</command></action>
    </keybind>
    <keybind key="W-r">
      <action name="Execute"><command>awesome-arch-rofi run</command></action>
    </keybind>
    <keybind key="W-Return">
      <action name="Execute"><command>terminator</command></action>
    </keybind>
    <keybind key="W-n">
      <action name="Execute"><command>awesome-arch-fetch-terminal</command></action>
    </keybind>
    <keybind key="W-f">
      <action name="Execute"><command>thunar</command></action>
    </keybind>
    <keybind key="W-x">
      <action name="Execute"><command>awesome-arch-powermenu</command></action>
    </keybind>
    <keybind key="W-q">
      <action name="Close"/>
    </keybind>
    <keybind key="A-F4">
      <action name="Close"/>
    </keybind>
    <keybind key="A-Tab">
      <action name="NextWindow"/>
    </keybind>
    <keybind key="W-Left">
      <action name="UnmaximizeFull"/>
      <action name="MoveResizeTo"><x>0</x><y>36</y><width>50%</width><height>100%</height></action>
    </keybind>
    <keybind key="W-Right">
      <action name="UnmaximizeFull"/>
      <action name="MoveResizeTo"><x>-0</x><y>36</y><width>50%</width><height>100%</height></action>
    </keybind>
    <keybind key="W-Up">
      <action name="MaximizeFull"/>
    </keybind>
    <keybind key="W-Down">
      <action name="UnmaximizeFull"/>
    </keybind>
    <keybind key="W-1"><action name="Desktop"><desktop>1</desktop></action></keybind>
    <keybind key="W-2"><action name="Desktop"><desktop>2</desktop></action></keybind>
    <keybind key="W-3"><action name="Desktop"><desktop>3</desktop></action></keybind>
    <keybind key="W-4"><action name="Desktop"><desktop>4</desktop></action></keybind>
    <keybind key="W-S-1"><action name="SendToDesktop"><desktop>1</desktop></action></keybind>
    <keybind key="W-S-2"><action name="SendToDesktop"><desktop>2</desktop></action></keybind>
    <keybind key="W-S-3"><action name="SendToDesktop"><desktop>3</desktop></action></keybind>
    <keybind key="W-S-4"><action name="SendToDesktop"><desktop>4</desktop></action></keybind>
    <keybind key="Print">
      <action name="Execute"><command>awesome-arch-screenshot</command></action>
    </keybind>
    <keybind key="W-Print">
      <action name="Execute"><command>awesome-arch-screenshot --select</command></action>
    </keybind>
    <keybind key="XF86AudioRaiseVolume">
      <action name="Execute"><command>pamixer --increase 5</command></action>
    </keybind>
    <keybind key="XF86AudioLowerVolume">
      <action name="Execute"><command>pamixer --decrease 5</command></action>
    </keybind>
    <keybind key="XF86AudioMute">
      <action name="Execute"><command>pamixer --toggle-mute</command></action>
    </keybind>
    <keybind key="XF86MonBrightnessUp">
      <action name="Execute"><command>brightnessctl set +5%</command></action>
    </keybind>
    <keybind key="XF86MonBrightnessDown">
      <action name="Execute"><command>brightnessctl set 5%-</command></action>
    </keybind>
    <keybind key="C-S-r">
      <action name="Reconfigure"/>
    </keybind>
  </keyboard>
  <mouse>
    <dragThreshold>8</dragThreshold>
    <doubleClickTime>200</doubleClickTime>
    <screenEdgeWarpTime>400</screenEdgeWarpTime>
    <context name="Frame">
      <mousebind button="A-Left" action="Drag"><action name="Move"/></mousebind>
      <mousebind button="A-Right" action="Drag"><action name="Resize"/></mousebind>
      <mousebind button="A-Middle" action="Press"><action name="Lower"/></mousebind>
    </context>
    <context name="Titlebar">
      <mousebind button="Left" action="DoubleClick"><action name="ToggleMaximizeFull"/></mousebind>
    </context>
    <context name="Root">
      <mousebind button="Right" action="Press"><action name="ShowMenu"><menu>root-menu</menu></action></mousebind>
      <mousebind button="Middle" action="Press"><action name="ShowMenu"><menu>client-list-combined-menu</menu></action></mousebind>
    </context>
  </mouse>
  <menu>
    <file>menu.xml</file>
    <hideDelay>200</hideDelay>
    <middle>no</middle>
    <submenuShowDelay>100</submenuShowDelay>
    <applicationIcons>yes</applicationIcons>
    <manageDesktops>yes</manageDesktops>
  </menu>
  <applications/>
</openbox_config>
EOF

    cat > "$TARGET_HOME/.xinitrc" <<'EOF'
#!/usr/bin/env sh
exec openbox-session
EOF

    chown -R "$TARGET_USER:$TARGET_GROUP" \
        "$TARGET_HOME/.config/openbox" \
        "$TARGET_HOME/.local/bin" \
        "$TARGET_HOME/.xinitrc"
    chmod 700 "$TARGET_HOME/.config/openbox"
    chmod 755 "$TARGET_HOME/.xinitrc"
    chmod 755 "$TARGET_HOME/.config/openbox/autostart"
}

write_helper_scripts() {
    info "Writing launcher, fetch, screenshot, and power helper scripts..."

    cat > "$TARGET_HOME/.local/bin/awesome-arch-rofi" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

mode="${1:-drun}"
case "$mode" in
    drun|run|window) ;;
    *) mode="drun" ;;
esac

exec rofi -show "$mode" -theme "$HOME/.config/rofi/awesome-arch.rasi"
EOF

    cat > "$TARGET_HOME/.local/bin/awesome-arch-fetch" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if command -v neofetch >/dev/null 2>&1; then
    exec neofetch "$@"
fi

if command -v fastfetch >/dev/null 2>&1; then
    exec fastfetch "$@"
fi

echo "Install neofetch or fastfetch to show system information."
EOF

    cat > "$TARGET_HOME/.local/bin/awesome-arch-fetch-shell" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

"$HOME/.local/bin/awesome-arch-fetch" || true
exec "${SHELL:-/bin/bash}" -l
EOF

    cat > "$TARGET_HOME/.local/bin/awesome-arch-fetch-terminal" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if command -v terminator >/dev/null 2>&1; then
    exec terminator -e "$HOME/.local/bin/awesome-arch-fetch-shell"
fi

if command -v xterm >/dev/null 2>&1; then
    exec xterm -e "$HOME/.local/bin/awesome-arch-fetch-shell"
fi

"$HOME/.local/bin/awesome-arch-fetch"
EOF

    cat > "$TARGET_HOME/.local/bin/awesome-arch-powermenu" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

choice="$(printf 'Logout\nReboot\nShutdown\nCancel\n' | rofi -dmenu -p power -theme "$HOME/.config/rofi/awesome-arch.rasi")"

case "$choice" in
    Logout) openbox --exit ;;
    Reboot) systemctl reboot ;;
    Shutdown) systemctl poweroff ;;
    *) exit 0 ;;
esac
EOF

    cat > "$TARGET_HOME/.local/bin/awesome-arch-screenshot" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

screenshots_dir="$HOME/Pictures/Screenshots"
mkdir -p "$screenshots_dir"

file="$screenshots_dir/screenshot-$(date +%Y%m%d-%H%M%S).png"

if [[ "${1:-}" == "--select" ]]; then
    maim -s "$file"
else
    maim "$file"
fi

if command -v xclip >/dev/null 2>&1; then
    xclip -selection clipboard -t image/png -i "$file" || true
fi

if command -v notify-send >/dev/null 2>&1; then
    notify-send "Screenshot saved" "$file" || true
fi
EOF

    chown -R "$TARGET_USER:$TARGET_GROUP" "$TARGET_HOME/.local/bin"
    chmod 755 "$TARGET_HOME/.local/bin"/awesome-arch-*
}

write_tint2_config() {
    info "Writing top Tint2 panel configuration..."

    install -d -m 700 -o "$TARGET_USER" -g "$TARGET_GROUP" "$TARGET_HOME/.config/tint2"

    cat > "$TARGET_HOME/.config/tint2/tint2rc" <<'EOF'
# AwesomeArch Openbox top panel
rounded = 8
border_width = 1
background_color = #10131c 82
border_color = #6f8cff 35
background_color_hover = #1c2233 92
border_color_hover = #8aadf4 50
background_color_pressed = #27314a 95
border_color_pressed = #8aadf4 65

rounded = 8
border_width = 0
background_color = #242b3d 88
border_color = #8aadf4 0

rounded = 8
border_width = 1
background_color = #6f8cff 92
border_color = #cad3f5 45

panel_items = LTSC
panel_monitor = all
panel_position = top center horizontal
panel_size = 100% 34
panel_margin = 0 0
panel_padding = 8 4 8
panel_background_id = 1
panel_layer = top
panel_dock = 0
panel_pivot_struts = 0
panel_shrink = 0
wm_menu = 1

launcher_padding = 6 4 6
launcher_background_id = 0
launcher_icon_background_id = 0
launcher_icon_size = 22
launcher_item_app = terminator.desktop
launcher_item_app = thunar.desktop
launcher_item_app = rofi.desktop

taskbar_mode = multi_desktop
taskbar_padding = 2 2 4
taskbar_background_id = 0
taskbar_active_background_id = 0
taskbar_name = 1
taskbar_name_padding = 6 2
taskbar_name_background_id = 0
taskbar_name_active_background_id = 2
taskbar_name_font = Noto Sans 9
taskbar_name_font_color = #cad3f5 60
taskbar_name_active_font_color = #ffffff 100

task_icon = 1
task_text = 1
task_centered = 1
task_maximum_size = 180 28
task_padding = 8 2 8
task_font = Noto Sans 9
task_tooltip = 1
task_font_color = #cad3f5 88
task_active_font_color = #ffffff 100
task_background_id = 0
task_active_background_id = 2
task_urgent_background_id = 3
task_iconified_font_color = #8087a2 70

systray_padding = 6 4 6
systray_background_id = 0
systray_sort = ascending
systray_icon_size = 18
systray_icon_asb = 100 0 0

clock = 1
time1_format = %a %d %b  %H:%M
time1_font = JetBrainsMono Nerd Font 10
clock_font_color = #ffffff 100
clock_padding = 10 4
clock_background_id = 0
clock_tooltip = %Y-%m-%d

tooltip = 1
tooltip_padding = 8 6
tooltip_show_timeout = 0.5
tooltip_hide_timeout = 0.1
tooltip_background_id = 1
tooltip_font = Noto Sans 9
tooltip_font_color = #ffffff 95

mouse_left = toggle_iconify
mouse_middle = close
mouse_right = toggle
mouse_scroll_up = prev_task
mouse_scroll_down = next_task
EOF

    chown -R "$TARGET_USER:$TARGET_GROUP" "$TARGET_HOME/.config/tint2"
}

write_terminal_config() {
    info "Writing transparent Terminator profile..."

    install -d -m 700 -o "$TARGET_USER" -g "$TARGET_GROUP" "$TARGET_HOME/.config/terminator"

    cat > "$TARGET_HOME/.config/terminator/config" <<'EOF'
[global_config]
  borderless = True
  title_font = Noto Sans 9
  title_hide_sizetext = True
  title_inactive_bg_color = "#10131c"
  title_transmit_bg_color = "#6f8cff"
[keybindings]
[profiles]
  [[default]]
    allow_bold = True
    background_color = "#0b0e14"
    background_darkness = 0.84
    background_type = transparent
    cursor_color = "#cad3f5"
    font = JetBrainsMono Nerd Font 10
    foreground_color = "#cad3f5"
    palette = "#1b1d2b:#ed8796:#a6da95:#eed49f:#8aadf4:#c6a0f6:#8bd5ca:#cad3f5:#5b6078:#ed8796:#a6da95:#eed49f:#8aadf4:#c6a0f6:#8bd5ca:#ffffff"
    scrollback_infinite = True
    show_titlebar = False
    use_system_font = False
[layouts]
  [[default]]
    [[[child1]]]
      parent = window0
      profile = default
      type = Terminal
    [[[window0]]]
      parent = ""
      type = Window
[plugins]
EOF

    chown -R "$TARGET_USER:$TARGET_GROUP" "$TARGET_HOME/.config/terminator"
}

write_picom_config() {
    info "Writing Picom compositor configuration..."

    install -d -m 700 -o "$TARGET_USER" -g "$TARGET_GROUP" "$TARGET_HOME/.config/picom"

    cat > "$TARGET_HOME/.config/picom/picom.conf" <<'EOF'
backend = "glx";
vsync = true;

shadow = true;
shadow-radius = 18;
shadow-offset-x = -10;
shadow-offset-y = -10;
shadow-opacity = 0.28;
shadow-exclude = [
  "name = 'Notification'",
  "class_g = 'Conky'",
  "class_g = 'Tint2'",
  "window_type = 'dock'",
  "window_type = 'desktop'"
];

fading = true;
fade-in-step = 0.035;
fade-out-step = 0.035;
fade-delta = 8;

inactive-opacity = 0.96;
active-opacity = 1.0;
frame-opacity = 0.92;
inactive-opacity-override = false;

corner-radius = 8;
rounded-corners-exclude = [
  "window_type = 'dock'",
  "window_type = 'desktop'"
];

opacity-rule = [
  "92:class_g = 'Terminator' && focused",
  "82:class_g = 'Terminator' && !focused",
  "96:class_g = 'Rofi'",
  "90:class_g = 'Dunst'"
];

wintypes:
{
  tooltip = { fade = true; shadow = true; opacity = 0.95; focus = true; full-shadow = false; };
  dock = { shadow = false; };
  dnd = { shadow = false; };
  popup_menu = { opacity = 0.95; };
  dropdown_menu = { opacity = 0.95; };
};
EOF

    chown -R "$TARGET_USER:$TARGET_GROUP" "$TARGET_HOME/.config/picom"
}

write_rofi_config() {
    info "Writing Rofi launcher theme..."

    install -d -m 700 -o "$TARGET_USER" -g "$TARGET_GROUP" "$TARGET_HOME/.config/rofi"

    cat > "$TARGET_HOME/.config/rofi/config.rasi" <<'EOF'
configuration {
  modi: "drun,run,window";
  show-icons: true;
  terminal: "terminator";
  drun-display-format: "{icon} {name}";
  font: "Noto Sans 11";
}

@theme "~/.config/rofi/awesome-arch.rasi"
EOF

    cat > "$TARGET_HOME/.config/rofi/awesome-arch.rasi" <<'EOF'
* {
  bg: #10131cee;
  bg-alt: #1b2233ee;
  fg: #cad3f5;
  muted: #8b93ad;
  accent: #6f8cff;
  urgent: #ed8796;
}

window {
  transparency: "real";
  location: north;
  anchor: north;
  y-offset: 44px;
  width: 42%;
  border: 1px;
  border-radius: 8px;
  border-color: @accent;
  background-color: @bg;
}

mainbox {
  padding: 14px;
  spacing: 10px;
  background-color: transparent;
}

inputbar {
  padding: 10px 12px;
  border-radius: 8px;
  background-color: @bg-alt;
  text-color: @fg;
  children: [ prompt, entry ];
}

prompt {
  padding: 0 10px 0 0;
  text-color: @accent;
}

entry {
  placeholder: "Search";
  placeholder-color: @muted;
  text-color: @fg;
}

listview {
  lines: 8;
  columns: 1;
  fixed-height: false;
  spacing: 6px;
  background-color: transparent;
}

element {
  padding: 8px 10px;
  border-radius: 8px;
  text-color: @fg;
  background-color: transparent;
}

element selected {
  text-color: #ffffff;
  background-color: @accent;
}

element urgent {
  text-color: @urgent;
}

element-icon {
  size: 24px;
  margin: 0 10px 0 0;
}

element-text {
  text-color: inherit;
}
EOF

    chown -R "$TARGET_USER:$TARGET_GROUP" "$TARGET_HOME/.config/rofi"
}

write_dunst_config() {
    info "Writing Dunst notification theme..."

    install -d -m 700 -o "$TARGET_USER" -g "$TARGET_GROUP" "$TARGET_HOME/.config/dunst"

    cat > "$TARGET_HOME/.config/dunst/dunstrc" <<'EOF'
[global]
    monitor = 0
    follow = keyboard
    width = 360
    height = 120
    origin = top-right
    offset = 16x48
    scale = 0
    notification_limit = 5
    progress_bar = true
    progress_bar_height = 8
    progress_bar_frame_width = 0
    indicate_hidden = yes
    transparency = 10
    separator_height = 2
    padding = 12
    horizontal_padding = 12
    text_icon_padding = 10
    frame_width = 1
    frame_color = "#6f8cff"
    separator_color = frame
    sort = yes
    idle_threshold = 120
    font = Noto Sans 10
    line_height = 0
    markup = full
    format = "<b>%s</b>\n%b"
    alignment = left
    vertical_alignment = center
    show_age_threshold = 60
    ellipsize = middle
    ignore_newline = no
    stack_duplicates = true
    hide_duplicate_count = false
    show_indicators = yes
    icon_position = left
    min_icon_size = 32
    max_icon_size = 48
    sticky_history = yes
    history_length = 20
    browser = xdg-open
    always_run_script = true
    corner_radius = 8

[urgency_low]
    background = "#10131c"
    foreground = "#cad3f5"
    timeout = 4

[urgency_normal]
    background = "#10131c"
    foreground = "#cad3f5"
    timeout = 7

[urgency_critical]
    background = "#2b1720"
    foreground = "#ffffff"
    frame_color = "#ed8796"
    timeout = 0
EOF

    chown -R "$TARGET_USER:$TARGET_GROUP" "$TARGET_HOME/.config/dunst"
}

write_theme_config() {
    info "Writing GTK, XSettings, Openbox, and Neofetch theme files..."

    install -d -m 700 -o "$TARGET_USER" -g "$TARGET_GROUP" "$TARGET_HOME/.config/gtk-3.0"
    install -d -m 700 -o "$TARGET_USER" -g "$TARGET_GROUP" "$TARGET_HOME/.config/xsettingsd"
    install -d -m 700 -o "$TARGET_USER" -g "$TARGET_GROUP" "$TARGET_HOME/.config/neofetch"
    install -d -m 700 -o "$TARGET_USER" -g "$TARGET_GROUP" "$TARGET_HOME/.themes/AwesomeArch-Openbox/openbox-3"

    cat > "$TARGET_HOME/.config/gtk-3.0/settings.ini" <<'EOF'
[Settings]
gtk-theme-name=Materia-dark
gtk-icon-theme-name=Papirus-Dark
gtk-font-name=Noto Sans 10
gtk-cursor-theme-name=Adwaita
gtk-application-prefer-dark-theme=1
gtk-toolbar-style=GTK_TOOLBAR_ICONS
gtk-button-images=0
gtk-menu-images=0
EOF

    cat > "$TARGET_HOME/.gtkrc-2.0" <<'EOF'
gtk-theme-name="Materia-dark"
gtk-icon-theme-name="Papirus-Dark"
gtk-font-name="Noto Sans 10"
gtk-cursor-theme-name="Adwaita"
gtk-application-prefer-dark-theme=1
EOF

    cat > "$TARGET_HOME/.config/xsettingsd/xsettingsd.conf" <<'EOF'
Net/ThemeName "Materia-dark"
Net/IconThemeName "Papirus-Dark"
Gtk/FontName "Noto Sans 10"
Gtk/CursorThemeName "Adwaita"
Net/EnableEventSounds 0
Gtk/ButtonImages 0
Gtk/MenuImages 0
EOF

    cat > "$TARGET_HOME/.themes/AwesomeArch-Openbox/openbox-3/themerc" <<'EOF'
border.width: 1
padding.width: 8
window.client.padding.width: 0
window.handle.width: 3
window.active.border.color: #6f8cff
window.inactive.border.color: #1b1d2b
window.active.title.bg: flat solid
window.active.title.bg.color: #10131c
window.inactive.title.bg: flat solid
window.inactive.title.bg.color: #0b0e14
window.active.label.text.color: #ffffff
window.inactive.label.text.color: #8087a2
window.active.button.unpressed.bg: flat solid
window.active.button.unpressed.bg.color: #10131c
window.active.button.unpressed.image.color: #cad3f5
window.active.button.hover.bg: flat solid
window.active.button.hover.bg.color: #27314a
window.active.button.hover.image.color: #ffffff
window.inactive.button.unpressed.bg: flat solid
window.inactive.button.unpressed.bg.color: #0b0e14
window.inactive.button.unpressed.image.color: #6e738d
menu.border.width: 1
menu.border.color: #6f8cff
menu.items.bg: flat solid
menu.items.bg.color: #10131c
menu.items.text.color: #cad3f5
menu.items.active.bg: flat solid
menu.items.active.bg.color: #6f8cff
menu.items.active.text.color: #ffffff
menu.title.bg: flat solid
menu.title.bg.color: #10131c
menu.title.text.color: #ffffff
osd.border.width: 1
osd.border.color: #6f8cff
osd.bg: flat solid
osd.bg.color: #10131c
osd.label.text.color: #ffffff
EOF

    cat > "$TARGET_HOME/.config/neofetch/config.conf" <<'EOF'
print_info() {
    info title
    info underline
    info "OS" distro
    info "Host" model
    info "Kernel" kernel
    info "Uptime" uptime
    info "Packages" packages
    info "Shell" shell
    info "WM" wm
    info "Theme" theme
    info "Icons" icons
    info "Terminal" term
    info "CPU" cpu
    info "GPU" gpu
    info "Memory" memory
    info cols
}

ascii_distro="arch_small"
colors=(4 4 6 6 7 7)
bold="on"
underline_enabled="on"
separator="  "
EOF

    chown -R "$TARGET_USER:$TARGET_GROUP" \
        "$TARGET_HOME/.config/gtk-3.0" \
        "$TARGET_HOME/.config/xsettingsd" \
        "$TARGET_HOME/.config/neofetch" \
        "$TARGET_HOME/.themes/AwesomeArch-Openbox" \
        "$TARGET_HOME/.gtkrc-2.0"
}

write_lightdm_config() {
    if [[ "$ENABLE_LIGHTDM" -ne 1 ]]; then
        return
    fi

    info "Writing LightDM GTK greeter theme..."

    install -d -m 755 /etc/lightdm/lightdm-gtk-greeter.conf.d

    local background="/usr/share/backgrounds/awesome-arch-openbox.png"
    if [[ ! -f "$background" ]]; then
        background="#0b0e14"
    fi

    cat > /etc/lightdm/lightdm-gtk-greeter.conf.d/50-awesome-arch-openbox.conf <<EOF
[greeter]
theme-name=Materia-dark
icon-theme-name=Papirus-Dark
font-name=Noto Sans 10
background=$background
user-background=false
clock-format=%a %d %b, %H:%M
indicators=~host;~spacer;~clock;~spacer;~session;~language;~a11y;~power
EOF
}

update_user_dirs() {
    info "Creating user desktop directories..."
    sudo -u "$TARGET_USER" xdg-user-dirs-update || true
    install -d -m 755 -o "$TARGET_USER" -g "$TARGET_GROUP" "$TARGET_HOME/Pictures/Screenshots"
}

main() {
    install_packages
    install_neofetch_if_available
    install_bluetooth_if_present
    configure_x11_keyboard
    write_xorg_input_config
    install_corsair_keyboard_workaround
    install_wallpaper
    write_openbox_config
    write_helper_scripts
    write_tint2_config
    write_terminal_config
    write_picom_config
    write_rofi_config
    write_dunst_config
    write_theme_config
    write_lightdm_config
    update_user_dirs
    enable_services

    chmod 700 "$TARGET_HOME/.config" 2>/dev/null || true

    ok "Openbox desktop install complete."
    echo "Reboot, choose the Openbox session in LightDM, and use:"
    echo "  Super+Space  launcher"
    echo "  Super+Enter  transparent Terminator"
    echo "  Super+N      Neofetch/Fastfetch terminal"
    echo "  Super+X      power menu"
}

main
