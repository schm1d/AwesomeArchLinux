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
umask 022

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
IWD_CHANGED=false
NM_PRIVACY="/etc/NetworkManager/conf.d/00-privacy.conf"
NM_WIFI="/etc/NetworkManager/conf.d/20-wifi-hardening.conf"
IWD_MAIN="/etc/iwd/main.conf"

usage() {
    cat <<EOF
Usage: sudo $0 [options]

With no flags the script writes the safe baseline:
  - wifi.scan-rand-mac-address=yes
  - NetworkManager cloned MAC stays "stable" per SSID
  - iwd privacy knobs: AddressRandomization=network (per-SSID) and
    AddressRandomizationRange=full when iwd is installed

Options:
  --random-mac            Randomize MAC (NM per-association "random";
                          iwd "once" per-boot, as iwd supports network|once)
  --wpa3-template         Install an SAE-only (PMF required) NM template
  --wpa3-connection NAME  Flip an existing NM connection to SAE-only (pmf=3)
  --status                Show current Wi-Fi privacy / security state
  -h                      Show this help
EOF
    exit 0
}

need_arg() { [[ $# -ge 2 && -n "${2:-}" ]] || err "Option $1 requires a value"; }
while [[ $# -gt 0 ]]; do
    case "$1" in
        --random-mac)         RANDOM_MAC=true; shift ;;
        --wpa3-template)      WPA3_TEMPLATE=true; shift ;;
        --wpa3-connection)    need_arg "$@"; WPA3_CONNECTION="$2"; shift 2 ;;
        --status)             DO_STATUS=true; shift ;;
        -h|--help)            usage ;;
        *)                    err "Unknown option: $1" ;;
    esac
done

[[ $(id -u) -eq 0 ]] || err "Must be run as root"

cloned_policy="stable"
iwd_mac_policy="network"
if [[ "$RANDOM_MAC" == true ]]; then
    cloned_policy="random"
    iwd_mac_policy="once"
elif [[ "$WPA3_TEMPLATE" == true || -n "$WPA3_CONNECTION" ]]; then
    # Preserve existing MAC randomization policy when running WPA3 helpers without --random-mac
    if [[ -f "$NM_WIFI" ]]; then
        existing_nm_mac=$(awk -F= '/^[[:space:]]*wifi\.cloned-mac-address[[:space:]]*=/ {
            val = $2
            sub(/#.*/, "", val)
            gsub(/[[:space:]]/, "", val)
            if (val != "") { print val; exit }
        }' "$NM_WIFI")
        [[ -n "$existing_nm_mac" ]] && cloned_policy="$existing_nm_mac"
    fi
    if [[ -f "$IWD_MAIN" ]]; then
        existing_iwd_mac=$(awk -F= '
            /^[[:space:]]*\[General\][[:space:]]*(#.*)?$/ { in_gen = 1; next }
            /^[[:space:]]*\[[^]]+\]/ { in_gen = 0 }
            in_gen && /^[[:space:]]*AddressRandomization[[:space:]]*=/ {
                val = $2
                sub(/#.*/, "", val)
                gsub(/[[:space:]]/, "", val)
                if (val != "") { print val; exit }
            }
        ' "$IWD_MAIN")
        [[ -n "$existing_iwd_mac" ]] && iwd_mac_policy="$existing_iwd_mac"
    fi
fi

write_nm_baseline() {
    install -d -m 0755 /etc/NetworkManager/conf.d
    cat > "$NM_WIFI" <<EOF
[device]
wifi.scan-rand-mac-address=yes

[connection]
wifi.cloned-mac-address=${cloned_policy}
EOF
    chown root:root "$NM_WIFI"
    chmod 0644 "$NM_WIFI"
    msg "Wrote $NM_WIFI (scan randomization on, cloned MAC=${cloned_policy})"
    if [[ -f "$NM_PRIVACY" ]] && grep -Eq '^[[:space:]]*wifi\.cloned-mac-address[[:space:]]*=[[:space:]]*stable' "$NM_PRIVACY" && [[ "$cloned_policy" == "random" ]]; then
        warn "$NM_PRIVACY still sets cloned-mac-address=stable; $NM_WIFI overrides Wi-Fi to random"
    fi
}

write_iwd_baseline() {
    if [[ ! -d /etc/iwd ]] && ! command -v iwctl >/dev/null; then
        info "iwd not installed — skipping iwd privacy config"
        return 0
    fi
    install -d -m 0755 /etc/iwd

    if [[ ! -f "$IWD_MAIN" ]]; then
        cat > "$IWD_MAIN" <<EOF
[General]
AddressRandomization=${iwd_mac_policy}
AddressRandomizationRange=full
EnableNetworkConfiguration=false

[Scan]
DisablePeriodicScan=false
EOF
        chown root:root "$IWD_MAIN"
        chmod 0644 "$IWD_MAIN"
        IWD_CHANGED=true
        msg "Wrote $IWD_MAIN (AddressRandomization=${iwd_mac_policy}, AddressRandomizationRange=full)"
        return 0
    fi

    local tmp
    tmp=$(umask 077; mktemp "${IWD_MAIN}.XXXXXX")
    IWD_RAND="$iwd_mac_policy" awk '
        BEGIN {
            found_general = 0
            in_general = 0
            seen_rand = 0
            seen_range = 0
        }
        /^[[:space:]]*\[General\][[:space:]]*(#.*)?$/ {
            found_general = 1
            in_general = 1
            print
            next
        }
        /^[[:space:]]*\[[^]]+\]/ {
            if (in_general) {
                if (!seen_rand)  print "AddressRandomization=" ENVIRON["IWD_RAND"]
                if (!seen_range) print "AddressRandomizationRange=full"
                in_general = 0
            }
            print
            next
        }
        in_general && /^[[:space:]]*AddressRandomization[[:space:]]*=/ {
            if (!seen_rand) {
                print "AddressRandomization=" ENVIRON["IWD_RAND"]
                seen_rand = 1
            }
            next
        }
        in_general && /^[[:space:]]*AddressRandomizationRange[[:space:]]*=/ {
            if (!seen_range) {
                print "AddressRandomizationRange=full"
                seen_range = 1
            }
            next
        }
        { print }
        END {
            if (found_general) {
                if (in_general) {
                    if (!seen_rand)  print "AddressRandomization=" ENVIRON["IWD_RAND"]
                    if (!seen_range) print "AddressRandomizationRange=full"
                }
            } else {
                print ""
                print "[General]"
                print "AddressRandomization=" ENVIRON["IWD_RAND"]
                print "AddressRandomizationRange=full"
            }
        }
    ' "$IWD_MAIN" > "$tmp"

    if cmp -s "$tmp" "$IWD_MAIN"; then
        rm -f -- "$tmp"
        info "$IWD_MAIN already sets AddressRandomization=${iwd_mac_policy} and AddressRandomizationRange=full"
        return 0
    fi

    cp "$IWD_MAIN" "${IWD_MAIN}.bak.$(date +%Y%m%d-%H%M%S)"
    chmod 0644 "${IWD_MAIN}.bak."* 2>/dev/null || true
    chown root:root "$tmp"
    chmod 0644 "$tmp"
    mv -f -- "$tmp" "$IWD_MAIN"
    IWD_CHANGED=true
    msg "Updated $IWD_MAIN (AddressRandomization=${iwd_mac_policy}, AddressRandomizationRange=full)"
}

install_wpa3_template() {
    install -d -o root -g root -m 0700 /etc/NetworkManager/system-connections
    local file="/etc/NetworkManager/system-connections/wpa3-personal-template.nmconnection"
    local template_uuid=""
    if [[ -f "$file" ]]; then
        template_uuid=$(awk -F= '/^[[:space:]]*uuid[[:space:]]*=/ {
            val = $2
            gsub(/[[:space:]]/, "", val)
            if (val != "") { print val; exit }
        }' "$file")
    fi
    if [[ -z "$template_uuid" ]]; then
        template_uuid=$(</proc/sys/kernel/random/uuid)
    fi
    (
        umask 077
        cat > "$file" <<EOF
[connection]
id=wpa3-personal-template
uuid=${template_uuid}
type=wifi
autoconnect=false

[wifi]
mode=infrastructure
ssid=CHANGE-ME

[wifi-security]
key-mgmt=sae
pmf=3
psk=CHANGE-ME-PASSPHRASE

[ipv4]
method=auto

[ipv6]
method=auto
addr-gen-mode=stable-privacy
EOF
    )
    chown root:root "$file"
    chmod 0600 "$file"
    msg "Installed $file"
    info "Clone it, set ssid= and psk=, then: nmcli connection load $file"
    warn "Do not leave CHANGE-ME-PASSPHRASE on a real profile."
}

harden_named_connection() {
    command -v nmcli >/dev/null || err "nmcli not found"
    nmcli -g NAME connection show | grep -Fxq "$WPA3_CONNECTION" \
        || err "No NetworkManager connection named '$WPA3_CONNECTION'"

    if [[ "$RANDOM_MAC" == true ]]; then
        nmcli connection modify "$WPA3_CONNECTION" \
            wifi-sec.key-mgmt sae \
            wifi-sec.pmf 3 \
            802-11-wireless.cloned-mac-address "$cloned_policy"
        msg "Set $WPA3_CONNECTION to SAE (WPA3-Personal, pmf=3) with cloned-mac=$cloned_policy"
    else
        nmcli connection modify "$WPA3_CONNECTION" \
            wifi-sec.key-mgmt sae \
            wifi-sec.pmf 3
        msg "Set $WPA3_CONNECTION to SAE (WPA3-Personal, pmf=3; preserved existing cloned-mac setting)"
    fi

    warn "If this AP is WPA2-only the next association will fail. Revert with:"
    info "  nmcli connection modify '$WPA3_CONNECTION' wifi-sec.key-mgmt wpa-psk wifi-sec.pmf 2"
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
        { grep -E 'wifi\.|cloned-mac' "$NM_WIFI" || true; } | sed 's/^/  /'
    else
        warn "No $NM_WIFI yet"
    fi
    echo
    if [[ -f "$IWD_MAIN" ]]; then
        info "iwd AddressRandomization:"
        { grep -E '^[[:space:]]*(AddressRandomization(Range)?|\[General\])' "$IWD_MAIN" || true; } | sed 's/^/  /'
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

if systemctl is-active --quiet iwd 2>/dev/null && [[ "$IWD_CHANGED" == true ]]; then
    systemctl restart iwd
    msg "Restarted iwd to apply updated $IWD_MAIN"
fi
if systemctl is-active --quiet NetworkManager 2>/dev/null; then
    systemctl reload NetworkManager 2>/dev/null || systemctl restart NetworkManager
    msg "Reloaded NetworkManager"
fi

show_status
msg "Done."
