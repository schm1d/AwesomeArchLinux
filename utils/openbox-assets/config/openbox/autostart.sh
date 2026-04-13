#!/usr/bin/env bash
#
# AwesomeArch Openbox autostart (derived from dotfiles-ng owl4ce/dotfiles,
# rewritten for standalone use — the upstream version sourced ~/.joyfuld
# and required its joyd_* helpers which we do not ship).
#
# shellcheck shell=bash

run_bg() {
    command -v "$1" >/dev/null 2>&1 || return 0
    "$@" &
}

command -v xsetroot >/dev/null 2>&1 && xsetroot -cursor_name left_ptr
command -v xset >/dev/null 2>&1 && xset s off -dpms

# PolicyKit authentication agent
if [[ -x /usr/lib/polkit-gnome/polkit-gnome-authentication-agent-1 ]]; then
    /usr/lib/polkit-gnome/polkit-gnome-authentication-agent-1 &
fi

run_bg numlockx on

run_bg xsettingsd -c "$HOME/.config/xsettingsd/xsettingsd.conf"
run_bg dunst
run_bg nm-applet --indicator
run_bg volumeicon
run_bg cbatticon -u 5
run_bg picom --config "$HOME/.config/picom/picom.conf"

# Wallpaper: prefer feh with saved background, fall back to solid color.
if command -v feh >/dev/null 2>&1 && [[ -f "$HOME/.local/share/backgrounds/awesome-arch-openbox.png" ]]; then
    feh --no-fehbg --bg-fill "$HOME/.local/share/backgrounds/awesome-arch-openbox.png" &
elif command -v xsetroot >/dev/null 2>&1; then
    xsetroot -solid "#0b0e14" &
fi

run_bg tint2 -c "$HOME/.config/tint2/tint2rc"
