#!/usr/bin/env bash

# =============================================================================
# Script:      memcrypt.sh
# Description: Detects AMD SME / Intel TME capability and, only with --enable,
#              injects mem_encrypt=on into UKI (/etc/kernel/cmdline),
#              systemd-boot, or GRUB. Never runs as part of the unattended
#              installer.
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
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

DO_STATUS=false
DO_ENABLE=false
DO_DISABLE=false

usage() {
    cat <<EOF
Usage: sudo $0 [--status] [--enable] [--disable] [-h]

--enable is automated for AMD SME only. Intel TME is firmware-controlled.
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --status)   DO_STATUS=true; shift ;;
        --enable)   DO_ENABLE=true; shift ;;
        --disable)  DO_DISABLE=true; shift ;;
        -h|--help)  usage ;;
        *)          err "Unknown option: $1" ;;
    esac
done

if [[ "$DO_ENABLE" == true && "$DO_DISABLE" == true ]]; then
    err "Options --enable and --disable are mutually exclusive"
fi

[[ $(id -u) -eq 0 ]] || err "Must be run as root"

if [[ "$DO_ENABLE" == false && "$DO_DISABLE" == false ]]; then
    DO_STATUS=true
fi

has_flag() { grep -qw "$1" /proc/cpuinfo; }

vendor() {
    if grep -qi 'AuthenticAMD' /proc/cpuinfo; then
        printf 'amd'
    elif grep -qi 'GenuineIntel' /proc/cpuinfo; then
        printf 'intel'
    else
        printf 'other'
    fi
}

sme_active() {
    if dmesg 2>/dev/null | grep -qiE 'AMD Memory Encryption Features active:.*SME'; then
        return 0
    fi
    journalctl -k -b 0 --no-pager 2>/dev/null | grep -qiE 'AMD Memory Encryption Features active:.*SME'
}

probe() {
    local v
    v=$(vendor)
    info "CPU vendor: $v"
    for f in sme sev sev_es sev_snp tme tme_en; do
        if has_flag "$f"; then
            msg "  $f is present"
        else
            info "  $f is absent"
        fi
    done
    echo
    if [[ "$v" == "amd" ]]; then
        if has_flag sme; then
            msg "AMD SME capability bit is set"
            warn "SME still has to be enabled in firmware. Cost: RAM latency, VFIO breakage, possible non-boot."
        else
            warn "This AMD CPU does not advertise SME. --enable will refuse."
        fi
        if sme_active; then
            msg "SME appears active on the running kernel"
        else
            info "SME does not appear active on the running kernel"
        fi
    elif [[ "$v" == "intel" ]]; then
        if has_flag tme || has_flag tme_en; then
            msg "Intel TME capability bit is set (firmware-controlled; no portable cmdline)"
        else
            warn "This Intel CPU does not advertise TME."
        fi
    fi
    echo
    info "Current /proc/cmdline:"
    echo "  $(cat /proc/cmdline)"
}

add_param_to_line() {
    local line="$1" param="$2"
    PARAM="$param" awk '
        {
            for (i = 1; i <= NF; i++) {
                if ($i == ENVIRON["PARAM"]) {
                    printf "%s", $0
                    exit
                }
            }
            if (NF == 0) {
                printf "%s", ENVIRON["PARAM"]
            } else {
                sub(/[[:space:]]+$/, "", $0)
                printf "%s %s", $0, ENVIRON["PARAM"]
            }
        }
    ' <<< "$line"
}

remove_param_from_line() {
    local line="$1" param="$2"
    PARAM="$param" awk '
        {
            out = ""
            removed = 0
            for (i = 1; i <= NF; i++) {
                if ($i == ENVIRON["PARAM"]) {
                    removed = 1
                } else {
                    out = (out == "" ? $i : out " " $i)
                }
            }
            printf "%s", (removed ? out : $0)
        }
    ' <<< "$line"
}

update_cmdline_params() {
    local line="$1" action="$2" out
    if [[ "$action" == "add" ]]; then
        out=$(remove_param_from_line "$line" "mem_encrypt=off")
        out=$(add_param_to_line "$out" "mem_encrypt=on")
    else
        out=$(remove_param_from_line "$line" "mem_encrypt=on")
    fi
    printf '%s' "$out"
}

has_uki_preset() {
    local preset
    shopt -s nullglob
    for preset in /etc/mkinitcpio.d/*.preset; do
        if grep -Eq '^[[:space:]]*[A-Za-z0-9_]+_uki=' "$preset" 2>/dev/null; then
            shopt -u nullglob
            return 0
        fi
    done
    shopt -u nullglob
    return 1
}

update_uki() {
    local action="$1"
    local cmdline="/etc/kernel/cmdline"
    [[ -f "$cmdline" ]] && has_uki_preset || return 1

    local current updated
    current=$(tr '\n' ' ' < "$cmdline" | awk '{$1=$1; print}')
    updated=$(update_cmdline_params "$current" "$action")

    if [[ "$updated" != "$current" ]]; then
        cp -a "$cmdline" "${cmdline}.bak.$(date +%Y%m%d-%H%M%S)"
        printf '%s\n' "$updated" > "$cmdline"
        chmod 0600 "$cmdline"
        mkinitcpio -P
        if command -v sbctl >/dev/null 2>&1 && [[ \
            -d /var/lib/sbctl/keys || -f /var/lib/sbctl/GUID || \
            -d /usr/share/secureboot/keys || -f /usr/share/secureboot/GUID || \
            -f /etc/awesome-secureboot.conf ]]; then
            sbctl sign-all
            msg "Re-signed Secure Boot UKIs via sbctl"
        fi
        msg "Updated UKI cmdline ($cmdline) and rebuilt UKIs"
    else
        info "UKI cmdline ($cmdline) already in requested state"
    fi
    return 0
}

update_grub() {
    local action="$1"
    local grub="/etc/default/grub"
    [[ -f "$grub" ]] || return 1

    local has_key=false raw_line="" orig_val="" quote_char='"' updated grub_tmp grub_cfg
    if grep -Eq '^[[:space:]]*GRUB_CMDLINE_LINUX_DEFAULT=' "$grub"; then
        has_key=true
        raw_line=$(grep -E '^[[:space:]]*GRUB_CMDLINE_LINUX_DEFAULT=' "$grub" | head -n 1)
        orig_val="${raw_line#*=}"
        orig_val="${orig_val#"${orig_val%%[![:space:]]*}"}"
        orig_val="${orig_val%"${orig_val##*[![:space:]]}"}"
        if [[ ${#orig_val} -ge 2 ]]; then
            if [[ "${orig_val:0:1}" == '"' && "${orig_val: -1}" == '"' ]]; then
                quote_char='"'
                orig_val="${orig_val:1:${#orig_val}-2}"
            elif [[ "${orig_val:0:1}" == "'" && "${orig_val: -1}" == "'" ]]; then
                quote_char="'"
                orig_val="${orig_val:1:${#orig_val}-2}"
            fi
        fi
    fi

    updated=$(update_cmdline_params "$orig_val" "$action")

    if { [[ "$has_key" == true && "$updated" == "$orig_val" ]] || \
         [[ "$has_key" == false && -z "$updated" ]]; }; then
        info "GRUB cmdline ($grub) already in requested state"
        return 0
    fi

    cp -a "$grub" "${grub}.bak.$(date +%Y%m%d-%H%M%S)"
    grub_tmp=$(mktemp "${grub}.new.XXXXXX")
    chmod --reference="$grub" "$grub_tmp" 2>/dev/null || chmod 0644 "$grub_tmp"
    chown --reference="$grub" "$grub_tmp" 2>/dev/null || chown root:root "$grub_tmp"

    AAL_GRUB_VAL="$updated" AAL_GRUB_QUOTE="$quote_char" awk '
        !replaced && /^[[:space:]]*GRUB_CMDLINE_LINUX_DEFAULT=/ {
            q = ENVIRON["AAL_GRUB_QUOTE"]
            print "GRUB_CMDLINE_LINUX_DEFAULT=" q ENVIRON["AAL_GRUB_VAL"] q
            replaced = 1
            next
        }
        { print }
        END {
            if (!replaced) {
                q = ENVIRON["AAL_GRUB_QUOTE"]
                print "GRUB_CMDLINE_LINUX_DEFAULT=" q ENVIRON["AAL_GRUB_VAL"] q
            }
        }
    ' "$grub" > "$grub_tmp"
    mv -f "$grub_tmp" "$grub"

    if command -v grub-mkconfig >/dev/null 2>&1; then
        grub_cfg="/boot/grub/grub.cfg"
        if [[ -d /efi/grub && ! -d /boot/grub ]]; then
            grub_cfg="/efi/grub/grub.cfg"
        fi
        grub-mkconfig -o "$grub_cfg"
        if [[ -f "$grub_cfg" ]]; then
            chown root:root "$grub_cfg"
            chmod 0600 "$grub_cfg"
        fi
    fi
    msg "Updated GRUB cmdline"
    return 0
}

update_systemd_boot() {
    local action="$1" dir entry found=false
    for dir in /efi/loader/entries /boot/loader/entries /boot/efi/loader/entries; do
        [[ -d "$dir" ]] || continue
        shopt -s nullglob
        for entry in "$dir"/*.conf; do
            found=true
            local has_options=false orig_opts="" updated entry_tmp
            if grep -Eq '^options([[:space:]]+|$)' "$entry"; then
                has_options=true
                orig_opts=$(awk '/^options([[:space:]]+|$)/ { sub(/^options[[:space:]]*/, ""); print; exit }' "$entry")
            fi
            updated=$(update_cmdline_params "$orig_opts" "$action")
            if [[ "$updated" == "$orig_opts" ]]; then
                info "Boot entry $entry already in requested state"
                continue
            fi
            cp -a "$entry" "${entry}.bak.$(date +%Y%m%d-%H%M%S)"
            if [[ "$has_options" == true ]]; then
                entry_tmp=$(mktemp "${entry}.new.XXXXXX")
                chmod --reference="$entry" "$entry_tmp" 2>/dev/null || chmod 0600 "$entry_tmp"
                chown --reference="$entry" "$entry_tmp" 2>/dev/null || chown root:root "$entry_tmp"
                AAL_OPTS="$updated" awk '
                    !done && /^options([[:space:]]+|$)/ {
                        if (ENVIRON["AAL_OPTS"] != "") {
                            print "options " ENVIRON["AAL_OPTS"]
                        }
                        done = 1
                        next
                    }
                    { print }
                ' "$entry" > "$entry_tmp"
                mv -f "$entry_tmp" "$entry"
            elif [[ -n "$updated" ]]; then
                printf 'options %s\n' "$updated" >> "$entry"
            fi
            msg "Updated $entry"
        done
        shopt -u nullglob
    done
    [[ "$found" == true ]]
}

enable_sme() {
    [[ "$(vendor)" == "amd" ]] || err "--enable is only automated for AMD SME"
    has_flag sme || err "CPU does not advertise the sme flag. Refusing."
    warn "Confirm Memory Encryption / SME is enabled in firmware before rebooting."
    if update_uki add || update_systemd_boot add || update_grub add; then
        msg "mem_encrypt=on staged. Reboot to activate."
    else
        err "No UKI, systemd-boot, or GRUB configuration found to edit"
    fi
}

disable_sme() {
    if update_uki remove || update_systemd_boot remove || update_grub remove; then
        msg "mem_encrypt=on removed. Reboot to drop SME."
    else
        err "No UKI, systemd-boot, or GRUB configuration found to edit"
    fi
}

if [[ "$DO_STATUS" == true ]]; then
    probe
    echo
fi
if [[ "$DO_ENABLE" == true ]]; then
    probe
    echo
    enable_sme
fi
if [[ "$DO_DISABLE" == true ]]; then
    probe
    echo
    disable_sme
fi
