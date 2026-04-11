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
    autorandr
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
    rtkit
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
    imagemagick
)

# obmenu-generator and its Perl deps live in AUR. We try to install them via
# yay after pacman finishes; if yay is not present we fall back to a static
# Applications menu.
AUR_PACKAGES=(
    obmenu-generator
    perl-linux-desktopfiles
    perl-data-dump
)

install_packages() {
    info "Installing lightweight Openbox desktop packages..."
    pacman -S --needed --noconfirm "${PACMAN_PACKAGES[@]}"
}

# Set by install_obmenu_generator(). Consumed by write_openbox_config() to
# pick between a dynamic pipe menu and a static Applications submenu.
HAS_OBMENU=0

install_obmenu_generator() {
    info "Installing obmenu-generator (AUR) for dynamic Openbox application menu..."
    if command -v yay >/dev/null 2>&1; then
        if sudo -u "$TARGET_USER" yay -S --needed --noconfirm "${AUR_PACKAGES[@]}"; then
            HAS_OBMENU=1
            return
        fi
        warn "yay failed to install obmenu-generator. Falling back to a static application menu."
        return
    fi
    warn "yay not found; skipping obmenu-generator install. Run utils/yay.sh then re-run openbox.sh for dynamic menus."
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
    rm -f /etc/resolv.conf
    ln -s /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
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

# NOTE: install_corsair_keyboard_workaround is intentionally NOT called by
# main(). The udev rule it writes unsets ID_INPUT_MOUSE on every device with
# USB vendor 1b1c, which is too aggressive for a default install: a real
# Corsair-branded mouse attached to the same system stops working, and the
# rule can also interfere with adjacent libinput state on non-gaming Corsair
# hardware. Reported as a regression on a fresh install.
#
# When to use it manually: only if you have a Corsair K-series gaming
# keyboard whose fake-mouse HID interface is confusing libinput (symptom:
# cursor jumps or stops responding after startx / LightDM) AND you have
# already confirmed the xf86-input-libinput driver is correctly installed.
#
# How to invoke it manually:
#     source utils/openbox.sh && install_corsair_keyboard_workaround
# (or copy the function body into a root shell).
#
# How to undo it:
#     rm /etc/udev/rules.d/99-corsair-gaming-kbd-fake-mouse.rules
#     udevadm control --reload-rules && udevadm trigger
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

install_openbox_theme() {
    info "Installing Fleon-ArchBlue Openbox theme to /usr/share/themes..."

    local theme_dir="/usr/share/themes/Fleon-ArchBlue/openbox-3"
    install -d -m 755 "$theme_dir"

    # Recolored themerc from dotfiles-ng .themes/Fleon/openbox-3/themerc.
    # Pink/magenta accents mapped to the Arch-blue palette per spec:
    #   #fa74b2 -> #1793D1   (close button, menu title)
    #   #f48ee8 -> #1595E3   (menu active item text)
    #   #d8a6f4 -> #1595E3   (maximize button, toggle images)
    # Grays, existing blues (#89ccf7, #63c5ea), and #f9f9f9 unchanged.
    cat > "$theme_dir/themerc" <<'EOF'
# Fleon-ArchBlue (derived from Fleon (C) 2020-2022 owl4ce)

# Window Appearance
padding.width: 9
padding.height: 7

## Titlebar
window.active.title.bg: flat
window.active.title.bg.color: #373e4d
window.inactive.title.bg: flat
window.inactive.title.bg.color: #373e4d

## Titlebar Text
window.label.text.justify: center
window.active.label.bg: parentrelative
window.active.label.text.color: #f9f9f9
window.inactive.label.bg: parentrelative
window.inactive.label.text.color: #8b93ad

## Borders
border.width: 0
window.active.border.color: #373e4d
window.inactive.border.color: #373e4d

## Handle
window.handle.width: 4
window.active.handle.bg: flat
window.active.handle.bg.color: #3c4454
window.inactive.handle.bg: flat
window.inactive.handle.bg.color: #3a4252

## Client
window.client.padding.width: 0
window.client.padding.height: 0
window.active.client.color:  #373e4d
window.inactive.client.color:  #373e4d

## Grip
window.active.grip.bg: flat
window.active.grip.bg.color: #3a4252
window.inactive.grip.bg: flat
window.inactive.grip.bg.color: #38404f

# Window Buttons
window.*.button.*.bg: parentrelative
window.*.button.*.pressed.bg: flat

## Active Universal
window.active.button.*.hover.bg: flat
window.active.button.*.hover.bg: parentrelative
window.active.button.*.hover.image.color: #5c6780
window.active.button.*.hover.bg.color: #3b4252
window.active.button.*.pressed.image.color: #89ccf7
window.active.button.*.pressed.bg.color: #373e4d
window.active.button.toggled.hover.image.color: #5c6780
window.active.button.toggled.image.color: #1595E3
window.active.button.toggled.pressed.image.color: #1595E3
window.active.button.disabled.image.color: #5c6780

## Inactive Universal
window.inactive.button.*.hover.bg: flat
window.inactive.button.*.hover.bg: parentrelative
window.inactive.button.*.hover.image.color: #5c6780
window.inactive.button.*.hover.bg.color: #3b4252
window.inactive.button.*.pressed.image.color: #89ccf7
window.inactive.button.*.pressed.bg.color: #3b4252
window.inactive.button.toggled.hover.image.color: #5c6780
window.inactive.button.toggled.image.color: #5c6780
window.inactive.button.toggled.pressed.image.color: #1595E3
window.inactive.button.disabled.image.color: #5c6780

## Close Button
window.active.button.close.unpressed.image.color: #1793D1
window.active.button.close.pressed.image.color: #1793D1
window.active.button.close.pressed.bg.color: #373e4d
window.inactive.button.close.unpressed.image.color: #5c6780
window.inactive.button.close.pressed.image.color: #5c6780
window.inactive.button.close.pressed.bg.color: #373e4d

## Maximize Button
window.active.button.max.unpressed.image.color: #1595E3
window.active.button.max.pressed.image.color: #1595E3
window.active.button.max.pressed.bg.color: #373e4d
window.inactive.button.max.unpressed.image.color: #5c6780
window.inactive.button.max.pressed.image.color: #5c6780
window.inactive.button.max.pressed.bg.color: #373e4d

## Iconify Button
window.active.button.iconify.unpressed.image.color: #89ccf7
window.active.button.iconify.pressed.image.color: #89ccf7
window.active.button.iconify.pressed.bg.color: #373e4d
window.inactive.button.iconify.unpressed.image.color: #5c6780
window.inactive.button.iconify.pressed.image.color: #5c6780
window.inactive.button.iconify.pressed.bg.color: #373e4d

## Shade Button
window.active.button.shade.unpressed.image.color: #f9f9f9
window.active.button.shade.pressed.image.color: #f9f9f9
window.active.button.shade.pressed.bg.color: #373e4d
window.inactive.button.shade.unpressed.image.color: #5c6780
window.inactive.button.shade.pressed.image.color: #5c6780
window.inactive.button.shade.pressed.bg.color: #373e4d

## Desk Button
window.active.button.desk.unpressed.image.color: #f9f9f9
window.active.button.desk.pressed.image.color: #f9f9f9
window.active.button.desk.pressed.bg.color: #373e4d
window.inactive.button.desk.unpressed.image.color: #5c6780
window.inactive.button.desk.pressed.image.color: #5c6780
window.inactive.button.desk.pressed.bg.color: #373e4d

# Openbox Menu
menu.overlap.x: -8
menu.separator.padding.height: 2
menu.separator.color: #3b4252
menu.border.width: 5
menu.border.color: #3b4252
menu.title.bg: flat
menu.title.bg.color: #404859
menu.title.text.color: #1793D1
menu.title.text.justify: center
menu.items.bg: flat
menu.items.bg.color: #3b4252
menu.items.text.color: #f9f9f9
menu.items.disabled.text.color: #5c6780
menu.items.active.bg: flat
menu.items.active.bg.color: #3b4252
menu.items.active.text.color: #1595E3

# OSD
osd.bg: flat solid
osd.bg.color: #3b4252
osd.border.width: 5
osd.border.color: #3b4252
osd.label.bg: flat solid
osd.label.bg.color: #3b4252
osd.label.text.color: #f9f9f9
osd.hilight.bg: flat solid
osd.hilight.bg.color: #89ccf7
osd.unhilight.bg: flat solid
osd.unhilight.bg.color: #373e4d
EOF

    # Fleon's button glyphs are 14x14 1-bit XBM masks. Openbox recolors them
    # from themerc's *.image.color properties, so no pixel-level recolor is
    # needed -- we just ship the same shapes. Embedded verbatim from
    # .themes/Fleon/openbox-3/*.xbm.
    _fleon_xbm bullet '0x00, 0x00, 0x00, 0x00, 0x60, 0x00, 0xe0, 0x00, 0xc0, 0x01, 0x80, 0x03, 0x00, 0x07, 0x00, 0x07, 0x80, 0x03, 0xc0, 0x01, 0xe0, 0x00, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00' > "$theme_dir/bullet.xbm"
    local triangle_bits='0x00, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x7c, 0x00, 0xfc, 0x00, 0xfc, 0x01, 0xf8, 0x03, 0xf0, 0x07, 0xe0, 0x0f, 0xc0, 0x0f, 0x80, 0x0f, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00'
    local triangle_mirror='0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x80, 0x0f, 0xc0, 0x0f, 0xe0, 0x0f, 0xf0, 0x07, 0xf8, 0x03, 0xfc, 0x01, 0xfc, 0x00, 0x7c, 0x00, 0x3c, 0x00, 0x00, 0x00, 0x00, 0x00'
    local name
    for name in close desk desk_toggled iconify max max_disabled max_toggled shade; do
        _fleon_xbm "$name" "$triangle_bits" > "$theme_dir/${name}.xbm"
    done
    _fleon_xbm shade_toggled "$triangle_mirror" > "$theme_dir/shade_toggled.xbm"

    chmod 644 "$theme_dir"/*.xbm "$theme_dir/themerc"
}

# Emit a 14x14 XBM file body for a given glyph name and hex-byte sequence.
# Used by install_openbox_theme() to materialize the Fleon button masks.
_fleon_xbm() {
    local name="$1" bits="$2"
    cat <<EOF
#define ${name}_width 14
#define ${name}_height 14
static unsigned char ${name}_bits[] = {
   ${bits} };
EOF
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

# Auto-detect monitor resolution: xrandr --auto applies the preferred
# (native) mode on every connected output. autorandr then overrides
# that with a saved profile if one matches the current EDID set —
# create profiles with "autorandr --save <name>" once configured.
command -v xrandr >/dev/null 2>&1 && xrandr --auto
command -v autorandr >/dev/null 2>&1 && autorandr --change --default default 2>/dev/null || true

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

    # The Applications submenu uses obmenu-generator (AUR) as a dynamic pipe
    # menu: on every open it reads /usr/share/applications/*.desktop and
    # regenerates its XML. No manual menu.xml edits are needed when you
    # install a new IDE, browser, Spotify, etc. -- just install the package
    # and reopen the menu. If obmenu-generator is not installed the Apps
    # submenu is replaced with a small static fallback.
    local apps_entry
    if [[ "$HAS_OBMENU" -eq 1 ]]; then
        apps_entry='    <menu id="apps-menu" label="Applications" execute="obmenu-generator -p -i"/>'
    else
        apps_entry=$'    <menu id="apps-menu" label="Applications">\n      <item label="Terminal"><action name="Execute"><command>terminator</command></action></item>\n      <item label="Files"><action name="Execute"><command>thunar</command></action></item>\n      <item label="Web Browser"><action name="Execute"><command>xdg-open http:</command></action></item>\n      <item label="Text Editor"><action name="Execute"><command>xdg-open about:blank</command></action></item>\n    </menu>'
    fi

    cat > "$TARGET_HOME/.config/openbox/menu.xml" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!--
  The Applications submenu below is dynamic: it is produced by
  obmenu-generator reading /usr/share/applications/*.desktop on every open.
  Installing a new app (IDE, browser, Spotify, ...) will make it appear here
  automatically -- do not hand-edit this file for app entries.
-->
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
${apps_entry}
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
    <name>Fleon-ArchBlue</name>
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
    <top>0</top>
    <bottom>0</bottom>
    <left>48</left>
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
    <!-- Window snapping: arrows = halves, Shift+arrows = thirds, numpad = 9-zone grid -->
    <keybind key="W-Left">
      <action name="UnmaximizeFull"/>
      <action name="MoveResizeTo"><x>0</x><y>0</y><width>50%</width><height>100%</height></action>
    </keybind>
    <keybind key="W-Right">
      <action name="UnmaximizeFull"/>
      <action name="MoveResizeTo"><x>-0</x><y>0</y><width>50%</width><height>100%</height></action>
    </keybind>
    <keybind key="W-Up">
      <action name="UnmaximizeFull"/>
      <action name="MoveResizeTo"><x>0</x><y>0</y><width>100%</width><height>50%</height></action>
    </keybind>
    <keybind key="W-Down">
      <action name="UnmaximizeFull"/>
      <action name="MoveResizeTo"><x>0</x><y>-0</y><width>100%</width><height>50%</height></action>
    </keybind>
    <keybind key="W-S-Left">
      <action name="UnmaximizeFull"/>
      <action name="MoveResizeTo"><x>0</x><y>0</y><width>33%</width><height>100%</height></action>
    </keybind>
    <keybind key="W-S-Right">
      <action name="UnmaximizeFull"/>
      <action name="MoveResizeTo"><x>-0</x><y>0</y><width>33%</width><height>100%</height></action>
    </keybind>
    <keybind key="W-KP_Add">
      <action name="MaximizeFull"/>
    </keybind>
    <keybind key="W-KP_Subtract">
      <action name="UnmaximizeFull"/>
    </keybind>
    <!-- Laptop-friendly maximize toggle (no numpad required) -->
    <keybind key="W-m">
      <action name="ToggleMaximize"/>
    </keybind>
    <keybind key="W-n">
      <action name="Iconify"/>
    </keybind>
    <keybind key="W-KP_1">
      <action name="UnmaximizeFull"/>
      <action name="MoveResizeTo"><x>0</x><y>-0</y><width>50%</width><height>50%</height></action>
    </keybind>
    <keybind key="W-KP_End">
      <action name="UnmaximizeFull"/>
      <action name="MoveResizeTo"><x>0</x><y>-0</y><width>50%</width><height>50%</height></action>
    </keybind>
    <keybind key="W-KP_2">
      <action name="UnmaximizeFull"/>
      <action name="MoveResizeTo"><x>0</x><y>-0</y><width>100%</width><height>50%</height></action>
    </keybind>
    <keybind key="W-KP_Down">
      <action name="UnmaximizeFull"/>
      <action name="MoveResizeTo"><x>0</x><y>-0</y><width>100%</width><height>50%</height></action>
    </keybind>
    <keybind key="W-KP_3">
      <action name="UnmaximizeFull"/>
      <action name="MoveResizeTo"><x>-0</x><y>-0</y><width>50%</width><height>50%</height></action>
    </keybind>
    <keybind key="W-KP_Next">
      <action name="UnmaximizeFull"/>
      <action name="MoveResizeTo"><x>-0</x><y>-0</y><width>50%</width><height>50%</height></action>
    </keybind>
    <keybind key="W-KP_4">
      <action name="UnmaximizeFull"/>
      <action name="MoveResizeTo"><x>0</x><y>0</y><width>50%</width><height>100%</height></action>
    </keybind>
    <keybind key="W-KP_Left">
      <action name="UnmaximizeFull"/>
      <action name="MoveResizeTo"><x>0</x><y>0</y><width>50%</width><height>100%</height></action>
    </keybind>
    <keybind key="W-KP_5">
      <action name="ToggleMaximize"/>
    </keybind>
    <keybind key="W-KP_Begin">
      <action name="ToggleMaximize"/>
    </keybind>
    <keybind key="W-KP_6">
      <action name="UnmaximizeFull"/>
      <action name="MoveResizeTo"><x>-0</x><y>0</y><width>50%</width><height>100%</height></action>
    </keybind>
    <keybind key="W-KP_Right">
      <action name="UnmaximizeFull"/>
      <action name="MoveResizeTo"><x>-0</x><y>0</y><width>50%</width><height>100%</height></action>
    </keybind>
    <keybind key="W-KP_7">
      <action name="UnmaximizeFull"/>
      <action name="MoveResizeTo"><x>0</x><y>0</y><width>50%</width><height>50%</height></action>
    </keybind>
    <keybind key="W-KP_Home">
      <action name="UnmaximizeFull"/>
      <action name="MoveResizeTo"><x>0</x><y>0</y><width>50%</width><height>50%</height></action>
    </keybind>
    <keybind key="W-KP_8">
      <action name="UnmaximizeFull"/>
      <action name="MoveResizeTo"><x>0</x><y>0</y><width>100%</width><height>50%</height></action>
    </keybind>
    <keybind key="W-KP_Up">
      <action name="UnmaximizeFull"/>
      <action name="MoveResizeTo"><x>0</x><y>0</y><width>100%</width><height>50%</height></action>
    </keybind>
    <keybind key="W-KP_9">
      <action name="UnmaximizeFull"/>
      <action name="MoveResizeTo"><x>-0</x><y>0</y><width>50%</width><height>50%</height></action>
    </keybind>
    <keybind key="W-KP_Prior">
      <action name="UnmaximizeFull"/>
      <action name="MoveResizeTo"><x>-0</x><y>0</y><width>50%</width><height>50%</height></action>
    </keybind>
    <keybind key="C-A-Delete">
      <action name="Execute"><command>awesome-arch-powermenu</command></action>
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
      <mousebind button="A-Left" action="Press"><action name="Focus"/><action name="Raise"/></mousebind>
      <mousebind button="A-Left" action="Drag"><action name="Move"/></mousebind>
      <mousebind button="A-Right" action="Press"><action name="Focus"/><action name="Raise"/></mousebind>
      <mousebind button="A-Right" action="Drag"><action name="Resize"/></mousebind>
      <mousebind button="A-Middle" action="Press"><action name="Lower"/></mousebind>
    </context>
    <context name="Titlebar">
      <mousebind button="Left" action="Press"><action name="Focus"/><action name="Raise"/><action name="Unshade"/></mousebind>
      <mousebind button="Left" action="Drag"><action name="Move"/></mousebind>
      <mousebind button="Left" action="DoubleClick"><action name="ToggleMaximizeFull"/></mousebind>
      <mousebind button="Middle" action="Press"><action name="Lower"/><action name="FocusToBottom"/><action name="Unfocus"/></mousebind>
      <mousebind button="Right" action="Press"><action name="Focus"/><action name="Raise"/><action name="ShowMenu"><menu>client-menu</menu></action></mousebind>
      <mousebind button="Up" action="Click"><action name="Shade"/></mousebind>
      <mousebind button="Down" action="Click"><action name="Unshade"/></mousebind>
    </context>
    <context name="Client">
      <mousebind button="Left" action="Press"><action name="Focus"/><action name="Raise"/></mousebind>
      <mousebind button="Middle" action="Press"><action name="Focus"/><action name="Raise"/></mousebind>
      <mousebind button="Right" action="Press"><action name="Focus"/><action name="Raise"/></mousebind>
    </context>
    <context name="Top">
      <mousebind button="Left" action="Drag"><action name="Resize"><edge>top</edge></action></mousebind>
      <mousebind button="Left" action="DoubleClick"><action name="ToggleMaximizeVert"/></mousebind>
    </context>
    <context name="Left">
      <mousebind button="Left" action="Drag"><action name="Resize"><edge>left</edge></action></mousebind>
    </context>
    <context name="Right">
      <mousebind button="Left" action="Drag"><action name="Resize"><edge>right</edge></action></mousebind>
    </context>
    <context name="Bottom">
      <mousebind button="Left" action="Drag"><action name="Resize"><edge>bottom</edge></action></mousebind>
      <mousebind button="Left" action="DoubleClick"><action name="ToggleMaximizeVert"/></mousebind>
    </context>
    <context name="TLCorner">
      <mousebind button="Left" action="Drag"><action name="Resize"/></mousebind>
    </context>
    <context name="TRCorner">
      <mousebind button="Left" action="Drag"><action name="Resize"/></mousebind>
    </context>
    <context name="BLCorner">
      <mousebind button="Left" action="Drag"><action name="Resize"/></mousebind>
    </context>
    <context name="BRCorner">
      <mousebind button="Left" action="Drag"><action name="Resize"/></mousebind>
    </context>
    <context name="Maximize">
      <mousebind button="Left" action="Click"><action name="ToggleMaximizeFull"/></mousebind>
      <mousebind button="Middle" action="Click"><action name="ToggleMaximizeVert"/></mousebind>
      <mousebind button="Right" action="Click"><action name="ToggleMaximizeHorz"/></mousebind>
    </context>
    <context name="Close">
      <mousebind button="Left" action="Click"><action name="Close"/></mousebind>
    </context>
    <context name="Iconify">
      <mousebind button="Left" action="Click"><action name="Iconify"/></mousebind>
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

    # Power menu (obexit-style): Shutdown / Reboot / Suspend / Hibernate / Lock / Logout.
    # Icons are plain UTF-8 glyphs that render with the default Noto/DejaVu stack.
    cat > "$TARGET_HOME/.local/bin/awesome-arch-powermenu" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

options=$'\u23fb  Shutdown\n\u21bb  Reboot\n\u23f8  Suspend\n\u263e  Hibernate\n\U0001f512  Lock\n\u21aa  Logout'

theme="$HOME/.config/rofi/obexit.rasi"
[[ -r "$theme" ]] || theme="$HOME/.config/rofi/awesome-arch.rasi"

choice="$(printf '%s\n' "$options" | rofi -dmenu -i -p "Power" -no-fixed-num-lines -theme "$theme" || true)"

case "${choice##* }" in
    Shutdown)  exec systemctl poweroff ;;
    Reboot)    exec systemctl reboot ;;
    Suspend)   exec systemctl suspend ;;
    Hibernate) exec systemctl hibernate ;;
    Lock)      exec loginctl lock-session ;;
    Logout)    exec openbox --exit ;;
    *)         exit 0 ;;
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
    info "Writing vertical EyeCandy Tint2 panel configuration (Arch blue)..."

    install -d -m 700 -o "$TARGET_USER" -g "$TARGET_GROUP" "$TARGET_HOME/.config/tint2"

    # Ported from dotfiles-ng's eyecandy-vertical.artistic.tint2rc, pink
    # accents swapped for Arch blue (#1793D1 family). Executor/button rows
    # that pointed at dotfiles-only scripts (music-controller, joyful-desktop
    # helpers, ncmpcpp launchers, screenshot-*.sh) have been removed; we
    # keep the launcher/taskbar/systray/clock core and wire button 1/2 to
    # our own rofi launcher and power menu.
    cat > "$TARGET_HOME/.config/tint2/tint2rc" <<'EOF'
# AwesomeArch Openbox vertical left dock (EyeCandy, Arch blue)
#-------------------------------------
# Gradients
gradient = vertical
start_color = #1793D1 100
end_color = #1595E3 100

gradient = vertical
start_color = #1793D1 82
end_color = #1595E3 82

#-------------------------------------
# Backgrounds
# Background 1: Active task
rounded = 8
border_width = 0
background_color = #89ccf7 100
border_color = #89ccf7 100
background_color_hover = #89ccf7 78
border_color_hover = #89ccf7 78
background_color_pressed = #89ccf7 100
border_color_pressed = #89ccf7 100

# Background 2: Default task
rounded = 8
border_width = 0
background_color = #1595E3 100
border_color = #1595E3 100
gradient_id = 0
background_color_hover = #1595E3 82
border_color_hover = #1595E3 82
background_color_pressed = #1595E3 100
border_color_pressed = #1595E3 100

# Background 3: Urgent task
rounded = 8
border_width = 0
background_color = #fa946e 100
border_color = #fa946e 40
gradient_id = 0
background_color_hover = #fa946e 88
border_color_hover = #fa946e 40
background_color_pressed = #fa946e 100
border_color_pressed = #fa946e 78

# Background 4: Panel, taskbar, clock
rounded = 0
border_width = 0
background_color = #f9f9f9 100
border_color = #000000 0

# Background 5: (button glow)
rounded = 6
border_width = 0
background_color = #000000 0
border_color = #a1a8b9 0
gradient_id = 1
background_color_hover = #63c5ea 0
border_color_hover = #a1a8b9 0
gradient_id_hover = 2
background_color_pressed = #63c5ea 0
border_color_pressed = #a1a8b9 0
gradient_id_pressed = 1

# Background 6: Button, Executor
rounded = 6
border_width = 0
background_color = #f7f7f7 100
border_color = #f7f7f7 100
gradient_id = 0
background_color_hover = #f4f4f4 100
border_color_hover = #f4f4f4 100
background_color_pressed = #f7f7f7 100
border_color_pressed = #f7f7f7 100
gradient_id_pressed = 0

# Background 7: Tooltip
rounded = 0
border_width = 0
background_color = #f9f9f9 100
border_color = #000000 0

# Background 8: Systray
rounded = 14
border_width = 0
background_color = #f4f4f4 100
border_color = #a1a8b9 0
background_color_hover = #f4f4f4 100
border_color_hover = #a1a8b9 0
background_color_pressed = #f4f4f4 100
border_color_pressed = #a1a8b9 0

#-------------------------------------
# Panel (vertical left dock)
panel_items = PLTSC
panel_size = 48 100%
panel_margin = 0 0
panel_padding = 6 10 8
panel_background_id = 4
wm_menu = 1
panel_dock = 0
panel_pivot_struts = 0
panel_position = center left vertical
panel_layer = top
panel_monitor = primary
panel_shrink = 0
autohide = 0
strut_policy = follow_size
panel_window_name = eyecandy.vertical.archblue.tint2
disable_transparency = 1
mouse_effects = 1
font_shadow = 0
mouse_hover_icon_asb = 100 0 10
mouse_pressed_icon_asb = 100 0 0

#-------------------------------------
# Taskbar
taskbar_mode = single_desktop
taskbar_hide_if_empty = 0
taskbar_padding = 5 7 8
taskbar_background_id = 4
taskbar_active_background_id = 4
taskbar_name = 0
taskbar_hide_inactive_tasks = 0
taskbar_hide_different_monitor = 0
taskbar_hide_different_desktop = 0
taskbar_always_show_all_desktop_tasks = 0
taskbar_distribute_size = 1
taskbar_sort_order = title
task_align = center

#-------------------------------------
# Task
task_text = 0
task_icon = 1
task_centered = 1
urgent_nb_of_blink = 3
task_maximum_size = 32 32
task_padding = 4 4 4
task_font = Noto Sans 9
task_tooltip = 1
task_thumbnail = 1
task_thumbnail_size = 210
task_font_color = #1595E3 100
task_active_font_color = #89ccf7 100
task_background_id = 2
task_active_background_id = 1
task_urgent_background_id = 3
mouse_left = toggle_iconify
mouse_middle = none
mouse_right = close
mouse_scroll_up = next_task
mouse_scroll_down = prev_task

#-------------------------------------
# System tray
systray_padding = 8 6 10
systray_background_id = 8
systray_sort = ascending
systray_icon_size = 16
systray_icon_asb = 100 0 10
systray_monitor = 1

#-------------------------------------
# Launcher (pinned dock icons)
launcher_padding = 6 4 6
launcher_background_id = 0
launcher_icon_background_id = 0
launcher_icon_size = 28
launcher_icon_asb = 100 0 0
launcher_icon_theme = Papirus-Dark
launcher_icon_theme_override = 1
launcher_item_app = terminator.desktop
launcher_item_app = thunar.desktop
launcher_item_app = rofi.desktop
startup_notifications = 1
launcher_tooltip = 1

#-------------------------------------
# Clock
time1_format = %H
time2_format = %M
time1_font = JetBrainsMono Nerd Font Bold 10
time2_font = JetBrainsMono Nerd Font 9
time1_timezone =
time2_timezone =
clock_font_color = #157FD0 100
clock_padding = 0 3
clock_background_id = 4
clock_tooltip = %A - %B %d, %Y
clock_tooltip_timezone =
clock_lclick_command =
clock_rclick_command =

#-------------------------------------
# Tooltip
tooltip_show_timeout = 0.5
tooltip_hide_timeout = 0.2
tooltip_padding = 8 6
tooltip_background_id = 7
tooltip_font_color = #000000 100
tooltip_font = Cantarell 9
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
    info "Writing Picom compositor configuration (dotfiles-ng base + local tweaks)..."

    install -d -m 700 -o "$TARGET_USER" -g "$TARGET_GROUP" "$TARGET_HOME/.config/picom"

    # Base is dotfiles-ng's .config/picom.conf (soft shadow, no blur, rounded
    # corners, safe detection flags). We extend it with opacity rules for
    # Terminator/Rofi/Dunst that dotfiles-ng didn't ship. No animations or
    # experimental backend options -- the stock Arch picom may not support
    # them.
    cat > "$TARGET_HOME/.config/picom/picom.conf" <<'EOF'
# Shadows
shadow = true;
shadow-radius = 40;
shadow-opacity = 0.1;
shadow-offset-x = -27;
shadow-offset-y = -27;
shadow-exclude = [
    "class_g             = 'Conky'",
    "class_g             = 'GLava'",
    "class_g            ?= 'Notify-osd'",
    "class_g             = 'Tint2'",
    "window_type         = 'dock'",
    "window_type         = 'desktop'",
    "_NET_WM_STATE@:32a *= '_NET_WM_STATE_HIDDEN'",
    "_GTK_FRAME_EXTENTS@:c"
];
xinerama-shadow-crop = true;

# Fading
fading = true;
fade-in-step = 0.025;
fade-out-step = 0.025;
fade-delta = 4;
no-fading-destroyed-argb = true;

# Opacity
inactive-opacity-override = false;
frame-opacity = 0.92;
opacity-rule = [
    "92:class_g = 'Terminator' && focused",
    "82:class_g = 'Terminator' && !focused",
    "96:class_g = 'Rofi'",
    "90:class_g = 'Dunst'"
];

# Corners
corner-radius = 8;
rounded-corners-exclude = [
    "name               *= 'rofi'",
    "name               *= 'screenkey'",
    "name               *= 'tint2'",
    "class_g             = 'Conky'",
    "class_g             = 'GLava'",
    "window_type         = 'dock'",
    "window_type         = 'desktop'",
    "_NET_WM_STATE@:32a *= '_NET_WM_STATE_HIDDEN'",
    "_GTK_FRAME_EXTENTS@:c"
];

# Blur (disabled -- matches dotfiles default)
blur-method = "none";
blur-background-exclude = [
    "! name             ~= ''",
    "  name             *= 'jgmenu'",
    "  name             *= 'tint2'",
    "class_g             = 'Conky'",
    "class_g             = 'GLava'",
    "window_type         = 'dock'",
    "window_type         = 'desktop'",
    "_NET_WM_STATE@:32a *= '_NET_WM_STATE_HIDDEN'",
    "_GTK_FRAME_EXTENTS@:c"
];

# General
backend = "glx";
vsync = true;
mark-wmwin-focused = true;
mark-ovredir-focused = true;
detect-rounded-corners = true;
detect-client-opacity = true;
use-ewmh-active-win = true;
unredir-if-possible = false;
detect-transient = true;
detect-client-leader = true;
glx-no-stencil = true;
glx-no-rebind-pixmap = true;
xrender-sync-fence = true;
log-level = "warn";
log-file = "/dev/null";

wintypes:
{
    tooltip       = { fade = true; shadow = true;  opacity = 0.95; focus = true; full-shadow = false; };
    menu          = { fade = true; shadow = true;  opacity = 1.00; };
    popup_menu    = { fade = true; shadow = true;  opacity = 0.95; };
    dropdown_menu = { fade = true; shadow = true;  opacity = 0.95; };
    utility       = { fade = true; shadow = true;  opacity = 1.00; };
    dialog        = { fade = true; shadow = true;  opacity = 1.00; };
    notify        = { fade = true; shadow = true;  opacity = 1.00; };
    dock          = { fade = true; shadow = false; clip-shadow-above = true; };
    dnd           = { fade = true; shadow = false; };
    unknown       = { fade = true; shadow = true;  opacity = 1.00; };
};
EOF

    chown -R "$TARGET_USER:$TARGET_GROUP" "$TARGET_HOME/.config/picom"
}

write_rofi_config() {
    info "Writing Rofi theme stack (EyeCandy, Arch blue)..."

    install -d -m 700 -o "$TARGET_USER" -g "$TARGET_GROUP" "$TARGET_HOME/.config/rofi"
    install -d -m 700 -o "$TARGET_USER" -g "$TARGET_GROUP" "$TARGET_HOME/.config/rofi/themes"
    install -d -m 700 -o "$TARGET_USER" -g "$TARGET_GROUP" "$TARGET_HOME/.config/rofi/themes/colorschemes"

    # Ported verbatim from dotfiles-ng/.config/rofi/config.rasi, entry point
    # switched to main.rasi (avoids loading the retired awesome-arch.rasi).
    cat > "$TARGET_HOME/.config/rofi/config.rasi" <<'EOF'
// AwesomeArch Rofi configuration, based on dotfiles-ng EyeCandy.
configuration {
  filebrowser {
    directories-first: true;
  }
  cycle:               true;
  disable-history:     true;
  hover-select:        true;
  show-icons:          true;
  steal-focus:         false;
  window-thumbnail:    true;
  monitor:             "-4";
  dpi:                    0;
  modi:                "drun,run,filebrowser,window";
  display-drun:        "";
  display-run:         "";
  display-filebrowser: "";
  display-window:      "";
  me-select-entry:     "";
  me-accept-entry:     "MousePrimary";
  terminal:            "terminator";
}

window {
  border: inherit;
  border-radius: inherit;
}
mainbox { children: [ inputbar, listview, message ]; }
inputbar { margin: 4px 4px 2px 4px; padding: inherit; spacing: 6px; }
listview { scrollbar: false; margin: 0px 2px 2px 2px; padding: inherit; border: inherit; }
element { margin: 2px; }
element.alternate.normal { background-color: black/4%; }
element-text, element-icon { background-color: transparent; }
message { margin: 2px 4px 4px 4px; border: inherit; }
mode-switcher { padding: 0px 1px; }
button { margin: -1px; }

@import "themes/colorschemes/eyecandy.rasi"
@theme "~/.config/rofi/themes/main.rasi"
EOF

    # Colorscheme: pinks swapped for Arch blue, keep greens/orange intact.
    cat > "$TARGET_HOME/.config/rofi/themes/colorschemes/eyecandy.rasi" <<'EOF'
* {
  accent1:          #1793D1;
  accent2:          #1595E3;
  button-gradient:  linear-gradient(90, #1793D1, #1595E3);
  background-alpha: #f9f9f9f7;
  background:       #f9f9f9;
  background-light: #f4f4f4;
  background-focus: #efefef;
  foreground:       #373e4d;
  foreground-list:  #373e4d;
  on:               #2be491;
  off:              #1585CC;
  urgent:           #fa946e;
}
EOF

    cat > "$TARGET_HOME/.config/rofi/themes/shared.rasi" <<'EOF'
* {
  text-font:                        "Comfortaa Bold 12";
  icon-font:                        "Material 14";
  center-align:                     0.5;
  window-padding:                   15.4% 8%;
  button-padding:                   14px;
  entry-padding:                    @button-padding;
  indicator-padding:                @entry-padding;
  message-padding:                  @indicator-padding;
  element-padding:                  @message-padding;
  element-border:                   0px 4px;
  element-icon-margin:              0px 6px 0px 0px;
  border-radius:                    8px;

  exts-textbox-font:                "Comfortaa Bold 48";
  exts-window-padding:              6.5% 4% 4% 4%;
  exts-window-width:                26%;
  exts-window-height:               100%;
  exts-window-location:             east;
  exts-window-x-offset:             0px;
  exts-window-y-offset:             0px;
  exts-window-border-radius:        0px 0px 0px 0px;
  exts-button-custom-margin:        4px;
  exts-button-custom-padding:       7px 9px;
  exts-button-custom-border-radius: 16px;
  exts-message-margin:              4px 4px 2px 4px;
  exts-message-padding:             4.4% 14px 3% 14px;
  exts-message-border-radius:       8px 8px 8px 8px;
  exts-inputbar-margin:             2px 4px 2px 4px;
}

window {
  width: 100%;
  height: 100%;
}
EOF

    cat > "$TARGET_HOME/.config/rofi/themes/main.rasi" <<'EOF'
@import "shared.rasi"
@import "colorschemes/eyecandy.rasi"

* {
  font: @text-font;
  text-color: @foreground-list;
  vertical-align: @center-align;
}
window {
  background-color: @background-alpha;
  padding: @window-padding;
}
inputbar { children: [ mode-switcher, entry, indicator ]; }
mode-switcher, button,
entry,
indicator, num-filtered-rows, textbox-sep, num-rows {
  background-color: @background-light;
  text-color: @accent1;
  horizontal-align: @center-align;
}
button { font: @icon-font; padding: @button-padding; }
button.selected {
  background-image: @button-gradient;
  text-color: @background-light;
}
entry {
  padding: @entry-padding;
  placeholder: "FILTER";
  placeholder-color: @background-focus;
}
indicator {
  children: [ num-filtered-rows, textbox-sep, num-rows ];
  expand: false;
  orientation: horizontal;
  padding: @indicator-padding;
}
num-filtered-rows, textbox-sep, num-rows { str: "/"; }
listview { columns: 3; }
element { padding: @element-padding; border: @element-border; }
element.normal.normal,
element.alternate.normal {
  background-color: @background-light;
  text-color: inherit;
  border-color: @background-light;
}
element.normal.active,
element.normal.urgent,
element.alternate.active,
element.alternate.urgent,
element.selected.normal,
element.selected.active,
element.selected.urgent {
  background-color: @background-focus;
  text-color: inherit;
}
element.selected.normal,
element.selected.active,
element.selected.urgent { border-color: @accent2; }
element.normal.active,
element.alternate.active { border-color: @on; }
element.normal.urgent,
element.alternate.urgent { border-color: @urgent; }
element-icon { margin: @element-icon-margin; }
message {
  background-color: @background-light;
  padding: @message-padding;
}
textbox { background-color: inherit; }
EOF

    cat > "$TARGET_HOME/.config/rofi/themes/exts.rasi" <<'EOF'
@import "shared.rasi"
@import "colorschemes/eyecandy.rasi"

* {
  font: @text-font;
  text-color: @foreground-list;
  vertical-align: @center-align;
}
window {
  background-color: @background-alpha;
  padding: @exts-window-padding;
  width: @exts-window-width;
  height: @exts-window-height;
  location: @exts-window-location;
  x-offset: @exts-window-x-offset;
  y-offset: @exts-window-y-offset;
  border-radius: @exts-window-border-radius;
}
mainbox { children: [ message, inputbar, listview, button-custom ]; }
message {
  background-color: @background-light;
  margin: @exts-message-margin;
  padding: @exts-message-padding;
  border-radius: @exts-message-border-radius;
}
textbox { background-color: inherit; font: @exts-textbox-font; horizontal-align: @center-align; }
inputbar { children: [ mode-switcher ]; margin: @exts-inputbar-margin; orientation: vertical; }
mode-switcher, button, button-custom {
  background-color: @background-light;
  font: @icon-font;
  text-color: @accent1;
}
button { padding: @button-padding; horizontal-align: @center-align; }
button.selected { background-image: @button-gradient; text-color: @background-light; }
listview { columns: 1; }
element { padding: @element-padding; border: @element-border; }
element.normal.normal,
element.alternate.normal {
  background-color: @background-light;
  text-color: inherit;
  border-color: @background-light;
}
element.normal.active,
element.normal.urgent,
element.alternate.active,
element.alternate.urgent,
element.selected.normal,
element.selected.active,
element.selected.urgent {
  background-color: @background-focus;
  text-color: inherit;
}
element.selected.normal,
element.selected.active,
element.selected.urgent { border-color: @accent2; }
element.normal.active,
element.alternate.active { border-color: @on; }
element.normal.urgent,
element.alternate.urgent { border-color: @urgent; }
button-custom {
  expand: false;
  margin: @exts-button-custom-margin;
  padding: @exts-button-custom-padding;
  border-radius: @exts-button-custom-border-radius;
  content: "";
  action: "kb-custom-19";
}
EOF

    # Back-compat shim: helper scripts pass -theme awesome-arch.rasi directly.
    # Make that file a thin alias that re-imports the new main theme stack
    # so we don't have to touch the helper scripts.
    cat > "$TARGET_HOME/.config/rofi/awesome-arch.rasi" <<'EOF'
@import "themes/colorschemes/eyecandy.rasi"
@import "themes/main.rasi"
EOF

    # Power menu theme, recolored to the Arch-blue EyeCandy palette so it
    # does not clash with the rest of the Rofi stack.
    cat > "$TARGET_HOME/.config/rofi/obexit.rasi" <<'EOF'
* {
  bg:      #f9f9f9f7;
  bg-alt:  #f4f4f4;
  fg:      #373e4d;
  muted:   #8b93ad;
  accent:  #1793D1;
  background-color: transparent;
  text-color: @fg;
  font: "Comfortaa Bold 13";
}

window {
  transparency: "real";
  location: center;
  anchor: center;
  width: 260px;
  padding: 16px;
  border: 1px;
  border-radius: 10px;
  border-color: @accent;
  background-color: @bg;
}

mainbox {
  children: [ listview ];
  spacing: 6px;
}

listview {
  lines: 6;
  fixed-height: true;
  spacing: 4px;
  scrollbar: false;
  background-color: transparent;
}

element {
  padding: 9px 12px;
  border-radius: 8px;
  background-color: transparent;
  text-color: @fg;
}

element selected {
  background-color: @accent;
  text-color: #ffffff;
}

element-text {
  text-color: inherit;
  vertical-align: 0.5;
}
EOF

    chown -R "$TARGET_USER:$TARGET_GROUP" "$TARGET_HOME/.config/rofi"
}

write_dunst_config() {
    info "Writing Dunst notification theme..."

    install -d -m 700 -o "$TARGET_USER" -g "$TARGET_GROUP" "$TARGET_HOME/.config/dunst"

    # Ported from dotfiles-ng .config/dunst/eyecandy.artistic.dunstrc
    # (the pair for the vertical artistic tint2). Urgency highlight colors
    # stay on the green/orange/blue scale -- they are not accent1 tokens.
    cat > "$TARGET_HOME/.config/dunst/dunstrc" <<'EOF'
[global]
    follow = mouse
    width = (111, 444)
    height = 222
    origin = top-right
    offset = 25x50

    progress_bar_height = 5
    progress_bar_min_width = 0
    progress_bar_max_width = 444
    progress_bar_frame_width = 0

    transparency = 3
    horizontal_padding = 11
    frame_width = 6
    frame_color = "#f9f9f9"
    gap_size = 8
    separator_color = "#f5f5f5"
    idle_threshold = 120

    font = "JetBrainsMono Nerd Font 10"

    format = "<span size='x-large' font_desc='Cantarell,JetBrainsMono Nerd Font 9' weight='bold' foreground='#63c5ea'>%s</span>\n%b"

    show_age_threshold = 60
    icon_position = left
    min_icon_size = 48
    max_icon_size = 80

    enable_recursive_icon_lookup = true
    icon_theme = "Papirus-Dark"

    sticky_history = false
    dmenu = "rofi -no-show-icons -no-lazy-grab -no-plugins -dmenu -mesg 'Context Menu'"
    browser = xdg-open

    mouse_left_click = close_current
    mouse_middle_click = context_all
    mouse_right_click = close_all

    alignment = center
    markup = full
    always_run_script = true
    corner_radius = 8

[urgency_low]
    timeout = 3
    background = "#f9f9f9"
    foreground = "#373e4d"
    highlight = "#1793D1"

[urgency_normal]
    timeout = 6
    background = "#f9f9f9"
    foreground = "#373e4d"
    highlight = "#1793D1"

[urgency_critical]
    timeout = 0
    background = "#f9f9f9"
    foreground = "#373e4d"
    frame_color = "#fa946e"
    highlight = "#fa946e"
EOF

    chown -R "$TARGET_USER:$TARGET_GROUP" "$TARGET_HOME/.config/dunst"
}

write_theme_config() {
    info "Writing GTK, XSettings, Openbox, and Neofetch theme files..."

    install -d -m 700 -o "$TARGET_USER" -g "$TARGET_GROUP" "$TARGET_HOME/.config/gtk-3.0"
    install -d -m 700 -o "$TARGET_USER" -g "$TARGET_GROUP" "$TARGET_HOME/.config/xsettingsd"
    install -d -m 700 -o "$TARGET_USER" -g "$TARGET_GROUP" "$TARGET_HOME/.config/neofetch"

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
    install_obmenu_generator
    install_neofetch_if_available
    install_bluetooth_if_present
    configure_x11_keyboard
    write_xorg_input_config
    install_openbox_theme
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
