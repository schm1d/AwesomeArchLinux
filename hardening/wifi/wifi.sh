#!/usr/bin/env bash

# =============================================================================
# Script:      wifi.sh
# Description: Wi-Fi privacy and WPA3 helpers for NetworkManager + iwd.
#              Enables scan-time MAC randomization, a sane cloned-MAC policy,
#              and an opt-in WPA3-only template. Does NOT globally force WPA3
#              on every saved connection (that bricks hotel and IoT APs).
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
#
# Usage:       sudo ./wifi.sh [--random-mac] [--wpa3-template]
#                            [--wpa3-connection NAME] [--status] [-h]
# =============================================================================

set -euo pipefail

readonly C_BLUE='\033[1;34m'
readonly C_RED='\033[1;31m'
readonly C_GREEN='\033[1;32m'
readonly C_YELLOW='\033[1;33m'
readonly C_NC='\033[0m'

msg()  { printf "%b[+]%b %s\n" "$C_GREEN" "$C_NC" "$1"; }
info() { printf "%b[*]%b %s\n" "$C_BLUE"  "$C_NC" "$1"; }
warn() { printf "%b[!]%b %s\n" "$C_YELLOW" "$C_NC" "$1"; }
err()  { printf "%b[!]%b %s\n" "$C_RED"   "$C_NC" "$1" >&2; exit 1; }

RANDOM_MAC=false
WPA3_TEMPLATE=false
WPA3_CONNECTION=""
DO_STATUS=false
NM_PRIVACY="/etc/NetworkManager/conf.d/00-privacy.conf"
NM_WIFI="/etc/NetworkManager/conf.d/20-wifi-hardening.conf"
IWD_MAIN="/etc/iwd/main.conf"

usage() {
    cat <<EOF
Usage: sudo $0 [options]

With no flags the script writes the safe baseline:
  - wifi.scan-rand-mac-address=yes
  - cloned MAC stays "stable" per SSID
  - iwd privacy knobs when iwd is the NM backend

Options:
  --random-mac            New random MAC on every Wi-Fi association
  --wpa3-template         Install an SAE-only NetworkManager template
  --wpa3-connection NAME  Flip an existing NM connection to SAE-only
  --status                Show current Wi-Fi privacy / security state
  -h                      Show this help
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --random-mac)         RANDOM_MAC=true; shift ;;
        --wpa3-template)      WPA3_TEMPLATE=true; shift ;;
        --wpa3-connection)    WPA3_CONNECTION="${2:-}"; [[ -n "$WPA3_CONNECTION" ]] || err "--wpa3-connection needs a name"; shift 2 ;;
        --status)             DO_STATUS=true; shift ;;
        -h|--help)            usage ;;
        *)                    err "Unknown option: $1" ;;
    esac
done

[[ $(id -u) -eq 0 ]] || err "Must be run as root"

cloned_policy="stable"
if [[ "$RANDOM_MAC" == true ]]; then
    cloned_policy="random"
fi

write_nm_baseline() {
    mkdir -p /etc/NetworkManager/conf.d
    cat > "$NM_WIFI" <<EOF
[device]
wifi.scan-rand-mac-address=yes

[connection]
wifi.cloned-mac-address=${cloned_policy}
EOF
    msg "Wrote $NM_WIFI (scan randomization on, cloned MAC=${cloned_policy})"
    if [[ -f "$NM_PRIVACY" ]] && grep -q 'wifi.cloned-mac-address=stable' "$NM_PRIVACY" && [[ "$RANDOM_MAC" == true ]]; then
        warn "$NM_PRIVACY still sets cloned-mac-address=stable; $NM_WIFI overrides Wi-Fi to random"
    fi
}

write_iwd_baseline() {
    if [[ ! -d /etc/iwd ]] && ! command -v iwctl >/dev/null; then
        info "iwd not installed — skipping iwd privacy config"
        return 0
    fi
    mkdir -p /etc/iwd
    if [[ -f "$IWD_MAIN" ]]; then
        cp "$IWD_MAIN" "${IWD_MAIN}.bak.$(date +%Y%m%d-%H%M%S)"
    fi

    if [[ ! -f "$IWD_MAIN" ]]; then
        cat > "$IWD_MAIN" <<'EOF'
[General]
AddressRandomization=network
EnableNetworkConfiguration=false

[Scan]
DisablePeriodicScan=false
EOF
        msg "Wrote $IWD_MAIN"
        return 0
    fi

    if grep -q '^\[General\]' "$IWD_MAIN"; then
        if grep -q '^AddressRandomization=' "$IWD_MAIN"; then
            sed -i 's/^AddressRandomization=.*/AddressRandomization=network/' "$IWD_MAIN"
        else
            sed -i '/^\[General\]/a AddressRandomization=network' "$IWD_MAIN"
        fi
    else
        printf '\n[General]\nAddressRandomization=network\n' >> "$IWD_MAIN"
    fi
    msg "Updated AddressRandomization in $IWD_MAIN"
}

install_wpa3_template() {
    mkdir -p /etc/NetworkManager/system-connections
    local file="/etc/NetworkManager/system-connections/wpa3-personal-template.nmconnection"
    cat > "$file" <<'EOF'
[connection]
id=wpa3-personal-template
uuid=00000000-0000-4000-a000-00000000wpa3
type=wifi
autoconnect=false

[wifi]
mode=infrastructure
ssid=CHANGE-ME

[wifi-security]
key-mgmt=sae
psk=CHANGE-ME-PASSPHRASE

[ipv4]
method=auto

[ipv6]
method=auto
addr-gen-mode=stable-privacy
EOF
    chmod 600 "$file"
    msg "Installed $file"
    info "Clone it, set ssid= and psk=, then: nmcli connection load $file"
    warn "Do not leave CHANGE-ME-PASSPHRASE on a real profile."
}

harden_named_connection() {
    command -v nmcli >/dev/null || err "nmcli not found"
    nmcli -g NAME connection show | grep -Fxq "$WPA3_CONNECTION" \
        || err "No NetworkManager connection named '$WPA3_CONNECTION'"

    nmcli connection modify "$WPA3_CONNECTION" \
        wifi-sec.key-mgmt sae \
        802-11-wireless.cloned-mac-address "$cloned_policy"

    msg "Set $WPA3_CONNECTION to SAE (WPA3-Personal) with cloned-mac=$cloned_policy"
    warn "If this AP is WPA2-only the next association will fail. Revert with:"
    info "  nmcli connection modify '$WPA3_CONNECTION' wifi-sec.key-mgmt wpa-psk"
}

show_status() {
    echo
    info "NetworkManager Wi-Fi drop-ins:"
    shopt -s nullglob
    local f
    for f in /etc/NetworkManager/conf.d/*.conf; do
        printf '  %s\n' "$f"
    done
    shopt -u nullglob
    echo
    if [[ -f "$NM_WIFI" ]]; then
        grep -E 'wifi\.|cloned-mac' "$NM_WIFI" | sed 's/^/  /'
    else
        warn "No $NM_WIFI yet"
    fi
    echo
    if [[ -f "$IWD_MAIN" ]]; then
        info "iwd AddressRandomization:"
        grep -E 'AddressRandomization|\[General\]' "$IWD_MAIN" | sed 's/^/  /'
    fi
}

if [[ "$DO_STATUS" == true ]]; then
    show_status
    exit 0
fi

write_nm_baseline
write_iwd_baseline

if [[ "$WPA3_TEMPLATE" == true ]]; then
    install_wpa3_template
fi
if [[ -n "$WPA3_CONNECTION" ]]; then
    harden_named_connection
fi

if systemctl is-active --quiet NetworkManager 2>/dev/null; then
    systemctl reload NetworkManager 2>/dev/null || systemctl restart NetworkManager
    msg "Reloaded NetworkManager"
fi
if systemctl is-active --quiet iwd 2>/dev/null; then
    warn "iwd AddressRandomization changes apply to the next association (or restart iwd)."
fi

show_status
msg "Done."
