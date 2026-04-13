#!/usr/bin/env bash

# =============================================================================
# Script:      openbox.sh
# Description: Installs an Archcraft-inspired lightweight Openbox desktop
#              using vendored dotfiles-ng + Fleon assets recolored to the
#              AwesomeArch Arch-blue palette. Installs Tint2, Picom, Rofi,
#              Dunst, Terminator, Thunar, the Fleon-ArchBlue Openbox theme,
#              and helper binaries (obexit power menu).
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
#
# Usage:       sudo ./openbox.sh [--user USER] [--no-lightdm]
# =============================================================================

set -euo pipefail

# shellcheck disable=SC2034
BBlue='\033[1;34m'
# shellcheck disable=SC2034
BRed='\033[1;31m'
# shellcheck disable=SC2034
BGreen='\033[1;32m'
# shellcheck disable=SC2034
BYellow='\033[1;33m'
# shellcheck disable=SC2034
NC='\033[0m'

TARGET_USER="${SUDO_USER:-}"
ENABLE_LIGHTDM=1

usage() {
    cat <<'EOF'
Usage: sudo ./openbox.sh [options]

Options:
  -u, --user USER     Configure the Openbox session for USER.
                      Defaults to SUDO_USER.
      --no-lightdm    Install the desktop, but do not enable LightDM.
  -h, --help          Show this help.
EOF
}

info() { echo -e "${BBlue}$*${NC}"; }
ok()   { echo -e "${BGreen}$*${NC}"; }
warn() { echo -e "${BYellow}Warning: $*${NC}" >&2; }
err()  { echo -e "${BRed}Error: $*${NC}" >&2; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        -u|--user)
            if [[ $# -lt 2 ]]; then err "$1 requires a username"; exit 1; fi
            TARGET_USER="$2"; shift 2 ;;
        --no-lightdm) ENABLE_LIGHTDM=0; shift ;;
        -h|--help) usage; exit 0 ;;
        *) err "Unknown option: $1"; usage; exit 1 ;;
    esac
done

if [[ "$(id -u)" -ne 0 ]]; then
    err "This script must be run as root (sudo ./utils/openbox.sh)."
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
ASSETS_DIR="$SCRIPT_DIR/openbox-assets"

if [[ ! -d "$ASSETS_DIR" ]]; then
    err "Vendored assets directory not found: $ASSETS_DIR"
    exit 1
fi

PACMAN_PACKAGES=(
    xorg-server xorg-xwayland xorg-xinit xorg-xrandr autorandr xorg-xsetroot xorg-xprop
    xorg-xwininfo xorg-xinput xorg-fonts-misc ttf-dejavu
    xf86-input-libinput libinput
    openbox obconf-qt
    lightdm lightdm-gtk-greeter
    terminator tint2 picom rofi dunst feh
    lxappearance xsettingsd
    thunar thunar-archive-plugin xarchiver gvfs tumbler
    networkmanager network-manager-applet polkit-gnome
    pipewire pipewire-pulse wireplumber rtkit
    pavucontrol pamixer playerctl brightnessctl
    materia-gtk-theme papirus-icon-theme
    ttf-jetbrains-mono-nerd otf-font-awesome
    noto-fonts noto-fonts-emoji
    ttf-comfortaa cantarell-fonts
    maim xclip libnotify
    xdg-user-dirs xdg-user-dirs-gtk xdg-utils
    numlockx volumeicon cbatticon
    fastfetch imagemagick
)

# AUR packages for dynamic application menu and material icons.
AUR_PACKAGES=(
    obmenu-generator
    perl-linux-desktopfiles
    perl-data-dump
    ttf-material-design-icons-extended
)

# Set by install_obmenu_generator(). Consumed by apply_overlays() to pick
# between a dynamic pipe menu and a static Applications submenu.
HAS_OBMENU=0

install_packages() {
    info "Installing Openbox desktop packages from the official repos..."
    pacman -S --needed --noconfirm "${PACMAN_PACKAGES[@]}"
}

install_aur_packages() {
    info "Installing AUR desktop helpers via yay (non-fatal on failure)..."
    if ! command -v yay >/dev/null 2>&1; then
        warn "yay not found; skipping AUR packages. Run utils/yay.sh then re-run openbox.sh."
        return
    fi
    local pkg
    for pkg in "${AUR_PACKAGES[@]}"; do
        if ! sudo -u "$TARGET_USER" yay -S --needed --noconfirm "$pkg"; then
            warn "yay failed to install $pkg, continuing."
        fi
    done
}

install_obmenu_generator() {
    info "Checking for obmenu-generator to enable the dynamic Applications submenu..."
    if command -v obmenu-generator >/dev/null 2>&1; then
        HAS_OBMENU=1
        return
    fi
    if command -v yay >/dev/null 2>&1; then
        if sudo -u "$TARGET_USER" yay -S --needed --noconfirm obmenu-generator perl-linux-desktopfiles perl-data-dump; then
            HAS_OBMENU=1
            return
        fi
        warn "yay failed to install obmenu-generator. Using a static Applications submenu."
        return
    fi
    warn "yay not found; dynamic Applications menu disabled."
}

enable_lightdm_if_present() {
    if [[ "$ENABLE_LIGHTDM" -ne 1 ]]; then
        warn "LightDM was installed but not enabled (--no-lightdm)."
        return
    fi
    if ! command -v lightdm >/dev/null 2>&1; then
        warn "LightDM not installed, skipping display-manager enablement."
        return
    fi
    info "Enabling LightDM as the display manager..."
    local dm
    for dm in gdm sddm lxdm ly; do
        systemctl disable --now "$dm.service" >/dev/null 2>&1 || true
    done
    if [[ -L /etc/systemd/system/display-manager.service ]]; then
        rm -f /etc/systemd/system/display-manager.service
    fi
    systemctl enable lightdm.service
}

# -----------------------------------------------------------------------------
# X11 keyboard + Corsair workaround (reused verbatim from the previous script).
# -----------------------------------------------------------------------------

silence_autorandr_no_profile() {
    # autorandr ships a udev rule + systemd unit that fire on every card
    # connect/disconnect. Without a saved profile, the unit exits 4
    # ("no profile matched") and dbus-broker logs the failure. Treat
    # exit code 4 as success via a drop-in so the noise stops until
    # the user runs `autorandr --save <name>`.
    info "Silencing autorandr.service noise when no profile is saved..."
    install -d /etc/systemd/system/autorandr.service.d
    cat > /etc/systemd/system/autorandr.service.d/no-profile-ok.conf <<'EOF'
[Service]
SuccessExitStatus=4
EOF
    systemctl daemon-reload 2>/dev/null || true
}

configure_dns_handoff() {
    # On an already-running system the NM -> systemd-resolved handoff only
    # works if resolved is active, /etc/resolv.conf points at its stub, and
    # NM is configured with the systemd-resolved DNS backend. chroot.sh only
    # writes that drop-in if /etc/NetworkManager/conf.d exists at install
    # time; when NM is installed later by this script, we must write it.
    info "Wiring NetworkManager DNS handoff to systemd-resolved..."
    systemctl enable --now systemd-resolved 2>/dev/null || true
    chattr -i /etc/resolv.conf 2>/dev/null || true
    umount /etc/resolv.conf 2>/dev/null || true
    rm -f /etc/resolv.conf
    ln -s /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
    install -d /etc/NetworkManager/conf.d
    cat > /etc/NetworkManager/conf.d/dns.conf <<'EOF'
[main]
dns=systemd-resolved
EOF
    if systemctl is-active --quiet NetworkManager; then
        systemctl try-restart NetworkManager || true
    fi
}

configure_x11_keyboard() {
    if [[ -f /etc/X11/xorg.conf.d/00-keyboard.conf ]]; then
        info "X11 keyboard config already exists (from chroot), skipping."
        return
    fi

    local vconsole_keymap=""
    if [[ -f /etc/vconsole.conf ]]; then
        vconsole_keymap=$(sed -n 's/^KEYMAP=//p' /etc/vconsole.conf)
    fi

    if [[ -z "$vconsole_keymap" ]]; then
        info "No KEYMAP found in vconsole.conf, skipping X11 keyboard setup."
        return
    fi

    info "Setting X11 keyboard layout from vconsole keymap '$vconsole_keymap'..."
    localectl set-keymap "$vconsole_keymap" 2>/dev/null || true
    info "X11 keyboard layout applied from vconsole keymap '$vconsole_keymap'."
}

# Detect a Corsair gaming keyboard via sysfs. Returns 0 on match, 1 otherwise.
has_corsair_gaming_keyboard() {
    local input vendor name
    shopt -s nullglob
    for input in /sys/class/input/input*; do
        [[ -d "$input" ]] || continue

        vendor=""
        if [[ -r "$input/id/vendor" ]]; then
            vendor="$(tr -d '[:space:]' < "$input/id/vendor" 2>/dev/null || true)"
        fi

        if [[ "${vendor,,}" != "1b1c" ]]; then
            continue
        fi

        name=""
        if [[ -r "$input/name" ]]; then
            name="$(tr -d '\n' < "$input/name" 2>/dev/null || true)"
        fi

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
# USB vendor 1b1c, which is too aggressive for a default install. Invoke
# manually if you have a Corsair K-series gaming keyboard whose fake-mouse
# HID interface is confusing libinput.
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
SUBSYSTEM=="input", ATTRS{idVendor}=="1b1c", ENV{ID_INPUT_MOUSE}=="1", ENV{ID_INPUT}="0", ENV{ID_INPUT_MOUSE}="0"
EOF

    info "Reloading udev rules so the Corsair workaround takes effect..."
    udevadm control --reload-rules
    udevadm trigger
}

# -----------------------------------------------------------------------------
# Asset install + recolor
# -----------------------------------------------------------------------------

install_assets() {
    info "Copying vendored desktop assets to $TARGET_HOME/.config..."

    install -d -m 755 "$TARGET_HOME/.config"
    install -d -m 755 "$TARGET_HOME/.config/openbox"
    install -d -m 755 "$TARGET_HOME/.config/tint2"
    install -d -m 755 "$TARGET_HOME/.config/dunst"
    install -d -m 755 "$TARGET_HOME/.config/rofi"
    install -d -m 755 "$TARGET_HOME/.config/rofi/themes"
    install -d -m 755 "$TARGET_HOME/.config/rofi/themes/colorschemes"

    install -D -m 755 "$ASSETS_DIR/config/openbox/autostart.sh"    "$TARGET_HOME/.config/openbox/autostart.sh"
    install -D -m 644 "$ASSETS_DIR/config/openbox/environment"     "$TARGET_HOME/.config/openbox/environment"
    install -D -m 644 "$ASSETS_DIR/config/openbox/menu.xml"        "$TARGET_HOME/.config/openbox/menu.xml"
    install -D -m 644 "$ASSETS_DIR/config/openbox/rc.xml"          "$TARGET_HOME/.config/openbox/rc.xml"
    install -D -m 644 "$ASSETS_DIR/config/tint2/tint2rc"           "$TARGET_HOME/.config/tint2/tint2rc"
    install -D -m 644 "$ASSETS_DIR/config/dunst/dunstrc"           "$TARGET_HOME/.config/dunst/dunstrc"
    install -D -m 644 "$ASSETS_DIR/config/rofi/config.rasi"        "$TARGET_HOME/.config/rofi/config.rasi"
    install -D -m 644 "$ASSETS_DIR/config/rofi/themes/main.rasi"   "$TARGET_HOME/.config/rofi/themes/main.rasi"
    install -D -m 644 "$ASSETS_DIR/config/rofi/themes/shared.rasi" "$TARGET_HOME/.config/rofi/themes/shared.rasi"
    install -D -m 644 "$ASSETS_DIR/config/rofi/themes/exts.rasi"   "$TARGET_HOME/.config/rofi/themes/exts.rasi"
    install -D -m 644 "$ASSETS_DIR/config/rofi/themes/colorschemes/eyecandy.rasi" \
                       "$TARGET_HOME/.config/rofi/themes/colorschemes/eyecandy.rasi"
    install -D -m 644 "$ASSETS_DIR/config/picom.conf"              "$TARGET_HOME/.config/picom.conf"

    chown -R "$TARGET_USER:$TARGET_GROUP" "$TARGET_HOME/.config"
}

# Recolor the upstream pink/magenta dotfiles-ng palette to AwesomeArch blue.
# Applied across all user config files in one pass.
_apply_recolor_in_dir() {
    local root="$1"
    find "$root" -type f -exec sed -i 's|#fa74b2|#1793D1|gI' {} +
    find "$root" -type f -exec sed -i 's|#e88ef4|#1595E3|gI' {} +
    find "$root" -type f -exec sed -i 's|#f48ee8|#1595E3|gI' {} +
    find "$root" -type f -exec sed -i 's|#d8a6f4|#1595E3|gI' {} +
    find "$root" -type f -exec sed -i 's|#cf8ef4|#157FD0|gI' {} +
    find "$root" -type f -exec sed -i 's|#fa5aa4|#1585CC|gI' {} +
}

recolor_assets() {
    info "Recoloring vendored assets to the Arch-blue palette..."
    local target
    for target in \
        "$TARGET_HOME/.config/openbox" \
        "$TARGET_HOME/.config/tint2" \
        "$TARGET_HOME/.config/rofi" \
        "$TARGET_HOME/.config/dunst"
    do
        [[ -d "$target" ]] && _apply_recolor_in_dir "$target"
    done

    if [[ -f "$TARGET_HOME/.config/picom.conf" ]]; then
        sed -i 's|#fa74b2|#1793D1|gI' "$TARGET_HOME/.config/picom.conf"
        sed -i 's|#e88ef4|#1595E3|gI' "$TARGET_HOME/.config/picom.conf"
        sed -i 's|#f48ee8|#1595E3|gI' "$TARGET_HOME/.config/picom.conf"
        sed -i 's|#d8a6f4|#1595E3|gI' "$TARGET_HOME/.config/picom.conf"
        sed -i 's|#cf8ef4|#157FD0|gI' "$TARGET_HOME/.config/picom.conf"
        sed -i 's|#fa5aa4|#1585CC|gI' "$TARGET_HOME/.config/picom.conf"
    fi

    # Dunst ships a placeholder browser command -- point it at xdg-open so
    # clicking a notification URL works out of the box.
    if [[ -f "$TARGET_HOME/.config/dunst/dunstrc" ]]; then
        sed -i 's|your_web_browser|xdg-open|g' "$TARGET_HOME/.config/dunst/dunstrc"
    fi
}

install_openbox_theme() {
    info "Installing Fleon-ArchBlue Openbox theme to /usr/share/themes..."
    local theme_root="/usr/share/themes/Fleon-ArchBlue"

    install -d -m 755 "$theme_root"
    install -d -m 755 "$theme_root/openbox-3"
    cp -r "$ASSETS_DIR/themes/Fleon/openbox-3/." "$theme_root/openbox-3/"

    # Apply the six colour substitutions (no your_web_browser in theme files).
    find "$theme_root" -type f -exec sed -i 's|#fa74b2|#1793D1|gI' {} +
    find "$theme_root" -type f -exec sed -i 's|#e88ef4|#1595E3|gI' {} +
    find "$theme_root" -type f -exec sed -i 's|#f48ee8|#1595E3|gI' {} +
    find "$theme_root" -type f -exec sed -i 's|#d8a6f4|#1595E3|gI' {} +
    find "$theme_root" -type f -exec sed -i 's|#cf8ef4|#157FD0|gI' {} +
    find "$theme_root" -type f -exec sed -i 's|#fa5aa4|#1585CC|gI' {} +

    chown -R root:root "$theme_root"
    find "$theme_root" -type f -exec chmod 644 {} +
    find "$theme_root" -type d -exec chmod 755 {} +
}

# -----------------------------------------------------------------------------
# Overlays: idempotent patches applied on top of the vendored assets.
# -----------------------------------------------------------------------------

apply_overlays() {
    info "Applying AwesomeArch overlay patches..."
    local rcxml="$TARGET_HOME/.config/openbox/rc.xml"
    local menuxml="$TARGET_HOME/.config/openbox/menu.xml"
    local autostart="$TARGET_HOME/.config/openbox/autostart.sh"

    # --- Overlay 1: snap keybinds --------------------------------------------
    if [[ -f "$rcxml" ]] && ! grep -q "AwesomeArch snap keybinds" "$rcxml"; then
        local KEYBINDS
        KEYBINDS=$(cat <<'KEYBINDS_EOF'
    <!-- AwesomeArch snap keybinds -->
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
    <keybind key="W-m"><action name="ToggleMaximize"/></keybind>
    <keybind key="W-n"><action name="Iconify"/></keybind>
    <keybind key="W-KP_Add"><action name="MaximizeFull"/></keybind>
    <keybind key="W-KP_Subtract"><action name="UnmaximizeFull"/></keybind>
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
    <keybind key="W-KP_5"><action name="ToggleMaximize"/></keybind>
    <keybind key="W-KP_Begin"><action name="ToggleMaximize"/></keybind>
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
KEYBINDS_EOF
)
        awk -v block="$KEYBINDS" '/<\/keyboard>/ && !done { print block; done=1 } { print }' \
            "$rcxml" > "$rcxml.tmp" && mv "$rcxml.tmp" "$rcxml"
        chown "$TARGET_USER:$TARGET_GROUP" "$rcxml"
    fi

    # --- Overlay 2: power menu keybind ---------------------------------------
    if [[ -f "$rcxml" ]] && ! grep -q "AwesomeArch power menu" "$rcxml"; then
        local POWERBIND
        POWERBIND=$(cat <<'PB_EOF'
    <!-- AwesomeArch power menu -->
    <keybind key="C-A-Delete"><action name="Execute"><command>obexit</command></action></keybind>
PB_EOF
)
        awk -v block="$POWERBIND" '/<\/keyboard>/ && !done { print block; done=1 } { print }' \
            "$rcxml" > "$rcxml.tmp" && mv "$rcxml.tmp" "$rcxml"
        chown "$TARGET_USER:$TARGET_GROUP" "$rcxml"
    fi

    # --- Overlay 3: theme name patch -----------------------------------------
    if [[ -f "$rcxml" ]] && ! grep -q "<name>Fleon-ArchBlue</name>" "$rcxml"; then
        sed -i 's|<name>Fleon</name>|<name>Fleon-ArchBlue</name>|' "$rcxml"
    fi

    # --- Overlay 4: menu.xml replacement -------------------------------------
    local apps_entry
    if [[ "$HAS_OBMENU" -eq 1 ]]; then
        apps_entry='    <menu id="apps-menu" label="Applications" execute="obmenu-generator -p -i"/>'
    else
        apps_entry=$'    <menu id="apps-menu" label="Applications">\n      <item label="Terminal"><action name="Execute"><command>terminator</command></action></item>\n      <item label="Files"><action name="Execute"><command>thunar</command></action></item>\n      <item label="Web Browser"><action name="Execute"><command>xdg-open http:</command></action></item>\n      <item label="Text Editor"><action name="Execute"><command>xdg-open about:blank</command></action></item>\n    </menu>'
    fi

    cat > "$menuxml" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!--
  The Applications submenu below is dynamic when obmenu-generator is
  installed: it reads /usr/share/applications/*.desktop on every open.
  Do not hand-edit this file for app entries.
-->
<openbox_menu xmlns="http://openbox.org/3.4/menu">
  <menu id="root-menu" label="Openbox">
    <item label="Terminal">
      <action name="Execute"><command>terminator</command></action>
    </item>
    <item label="Files">
      <action name="Execute"><command>thunar</command></action>
    </item>
    <item label="Web Browser">
      <action name="Execute"><command>xdg-open http:</command></action>
    </item>
    <separator/>
${apps_entry}
    <separator/>
    <menu id="client-list-menu"/>
    <separator/>
    <item label="Power">
      <action name="Execute"><command>obexit</command></action>
    </item>
  </menu>
</openbox_menu>
EOF
    chown "$TARGET_USER:$TARGET_GROUP" "$menuxml"

    # --- Overlay 5: obexit binary + rofi theme -------------------------------
    install -m 0755 /dev/stdin /usr/local/bin/obexit <<'OBEXIT_EOF'
#!/usr/bin/env bash
set -euo pipefail

options=$'\u23fb  Shutdown\n\u21bb  Reboot\n\u23f8  Suspend\n\u263e  Hibernate\n\U0001f512  Lock\n\u21aa  Logout'

theme="$HOME/.config/rofi/themes/obexit.rasi"
[[ -r "$theme" ]] || theme="$HOME/.config/rofi/config.rasi"

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
OBEXIT_EOF

    install -D -m 644 /dev/stdin "$TARGET_HOME/.config/rofi/themes/obexit.rasi" <<'RASI_EOF'
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
RASI_EOF
    chown "$TARGET_USER:$TARGET_GROUP" "$TARGET_HOME/.config/rofi/themes/obexit.rasi"

    # --- Overlay 6: autorandr + xrandr --auto in autostart -------------------
    if [[ -f "$autostart" ]] && ! grep -q "AwesomeArch display autoconfigure" "$autostart"; then
        local DISPLAY_BLOCK
        DISPLAY_BLOCK=$(cat <<'DSP_EOF'
# AwesomeArch display autoconfigure
command -v xrandr >/dev/null 2>&1 && xrandr --auto || true
command -v autorandr >/dev/null 2>&1 && autorandr --change --default default 2>/dev/null || true
DSP_EOF
)
        # Anchor: first occurrence of a line starting with "command -v xsetroot".
        awk -v block="$DISPLAY_BLOCK" '
            !inserted && /^command -v xsetroot/ { print block; inserted=1 }
            { print }
        ' "$autostart" > "$autostart.tmp" && mv "$autostart.tmp" "$autostart"
        chmod 755 "$autostart"
        chown "$TARGET_USER:$TARGET_GROUP" "$autostart"
    fi
}

# -----------------------------------------------------------------------------
# Orchestration
# -----------------------------------------------------------------------------

main() {
    install_packages
    install_aur_packages
    install_obmenu_generator
    enable_lightdm_if_present
    configure_dns_handoff
    silence_autorandr_no_profile
    install_assets
    recolor_assets
    install_openbox_theme
    apply_overlays
    configure_x11_keyboard

    ok "Openbox desktop install complete."
    echo "Reboot, pick the Openbox session in LightDM, and use:"
    echo "  Ctrl+Alt+Delete  power menu (obexit)"
    echo "  Super+Arrows     window snap halves"
    echo "  Super+Shift+L/R  window snap thirds"
    echo "  Super+Numpad     9-zone snap grid"
    echo "  Super+M / Super+N  maximize toggle / iconify"
}

main
