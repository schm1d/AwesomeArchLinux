#!/usr/bin/env bash

# =============================================================================
# Script:      apparmor.sh
# Description: Installs, configures, and enforces AppArmor profiles on
#              Arch Linux for the following services:
#                - nginx
#                - sshd
#                - fail2ban-server
#                - freshclam (ClamAV)
#                - clamd (ClamAV)
#                - stubby (DNS-over-TLS) — only if /usr/bin/stubby exists
#                - chronyd (NTP)
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
#
# Usage:       sudo ./apparmor.sh [--dry-run] [--complain|--enforce] [-h|--help]
#
# Requirements:
#   - Arch Linux with pacman
#   - Root privileges
#   - UKI (/etc/kernel/cmdline), systemd-boot, or GRUB bootloader
#
# What this script does:
#   1. Installs apparmor
#   2. Enables the AppArmor systemd service
#   3. Configures UKI, systemd-boot, or GRUB to load AppArmor at boot
#      (apparmor=1 plus apparmor in the kernel's lsm= list)
#   4. Writes profiles for 7 services: enforce mode, except that the sshd
#      profile stays in complain mode until it is enforced explicitly
#   5. Loads the profiles when AppArmor is already active in the kernel
#   6. Displays a status summary via aa-status
# =============================================================================

set -euo pipefail
umask 022

# --- Colors ---
readonly C_BLUE='\033[1;34m'
readonly C_RED='\033[1;31m'
readonly C_GREEN='\033[1;32m'
readonly C_YELLOW='\033[1;33m'
readonly C_NC='\033[0m'

msg()  { printf "%b[+]%b %s\n" "$C_GREEN" "$C_NC" "$1"; }
info() { printf "%b[*]%b %s\n" "$C_BLUE"  "$C_NC" "$1"; }
warn() { printf "%b[!]%b %s\n" "$C_YELLOW" "$C_NC" "$1"; }
err()  { printf "%b[!]%b %s\n" "$C_RED"   "$C_NC" "$1" >&2; exit 1; }

# --- Defaults ---
DRY_RUN=false
MODE_REQUEST=""
KERNEL_CMDLINE="/etc/kernel/cmdline"
GRUB_DEFAULT="/etc/default/grub"
APPARMOR_DIR="/etc/apparmor.d"
BOOTLOADER_DESC="unknown"
LOGFILE="/var/log/apparmor-hardening-$(date +%Y%m%d-%H%M%S).log"

# Kernel interfaces that describe the running kernel
LSM_SYSFS="/sys/kernel/security/lsm"
AA_ENABLED_SYSFS="/sys/module/apparmor/parameters/enabled"
AA_PROFILES_SYSFS="/sys/kernel/security/apparmor/profiles"

# LSM list used when neither the command line nor the running kernel gives one
LSM_FALLBACK="landlock,lockdown,yama,integrity,apparmor,bpf"
AA_PARAMS_DESC="apparmor=1 and an lsm= list that contains apparmor"
AA_LSM_TOKEN=""

# --- Usage ---
usage() {
    cat <<EOF
Usage: sudo $0 [options]

Options:
  --dry-run    Write profiles to a unique /tmp/apparmor-preview.XXXXXX/
               directory; do not install packages, enable services, or load profiles
  --complain   Deploy every profile in complain mode (log only, nothing is blocked)
  --enforce    Deploy every profile in enforce mode, including sshd
  -h, --help   Show this help

Without --complain or --enforce every profile is enforced except sshd. The
sshd profile is deployed in complain mode until this system already runs it
enforced, so a gap in it is logged instead of locking out remote logins.
Check the log after the reboot, then re-run with --enforce.

Examples:
  sudo $0
  sudo $0 --dry-run
  sudo $0 --enforce
EOF
    exit 0
}

# --- Parse Arguments ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)   DRY_RUN=true; shift ;;
        --complain|--enforce)
            if [[ -n "$MODE_REQUEST" && "$MODE_REQUEST" != "${1#--}" ]]; then
                err "--complain and --enforce are mutually exclusive"
            fi
            MODE_REQUEST="${1#--}"
            shift
            ;;
        -h|--help)   usage ;;
        *)           err "Unknown option: $1" ;;
    esac
done

# --- Validate ---
[[ $(id -u) -eq 0 ]] || err "Must be run as root"

if [[ "$DRY_RUN" == true ]]; then
    # A unique directory prevents an unprivileged user from pre-planting
    # symlinks that a root dry-run would follow.
    APPARMOR_DIR=$(mktemp -d /tmp/apparmor-preview.XXXXXX)
    chmod 0700 "$APPARMOR_DIR"
    LOGFILE="$APPARMOR_DIR/apparmor-hardening.log"
    install -m 0600 /dev/null "$LOGFILE"
    warn "DRY-RUN mode: profiles will be written to $APPARMOR_DIR (not loaded)"
else
    install -d -o root -g root -m 0755 "$APPARMOR_DIR"
    # Redirect output to a root-only logfile while keeping umask 022 for profiles
    install -o root -g root -m 0600 /dev/null "$LOGFILE"
fi

exec > >(tee -a "$LOGFILE") 2>&1

info "AppArmor hardening script started"
info "Log: $LOGFILE"

# --- Profile mode ---
# A gap in the sshd profile only shows once AppArmor is active, which is
# normally after the reboot this script asks for; enforcing it untested can
# lock out every remote login. Unless --enforce or --complain says otherwise,
# the sshd profile is therefore deployed in complain mode (log only) until
# this system already runs it enforced. All other profiles are enforced.

# True when the AppArmor LSM is enabled in the running kernel.
apparmor_is_active() {
    [[ -r "$AA_ENABLED_SYSFS" ]] || return 1
    [[ "$(tr -d '[:space:]' < "$AA_ENABLED_SYSFS" 2>/dev/null || true)" == Y ]]
}

# True when the running kernel has the sshd profile loaded in enforce mode.
sshd_profile_enforced() {
    apparmor_is_active || return 1
    grep -qxF 'sshd (enforce)' "$AA_PROFILES_SYSFS" 2>/dev/null
}

AA_ACTIVE=false
if apparmor_is_active; then
    AA_ACTIVE=true
fi

OTHER_MODE=enforce
case "$MODE_REQUEST" in
    enforce)
        SSHD_MODE=enforce
        MODE_REASON="--enforce"
        ;;
    complain)
        SSHD_MODE=complain
        OTHER_MODE=complain
        MODE_REASON="--complain"
        ;;
    *)
        if sshd_profile_enforced; then
            SSHD_MODE=enforce
            MODE_REASON="default; sshd is already enforced on this system"
        else
            SSHD_MODE=complain
            MODE_REASON="default; sshd stays log-only until you run --enforce"
        fi
        ;;
esac

info "Profile modes: sshd=$SSHD_MODE, other services=$OTHER_MODE ($MODE_REASON)"
if [[ "$MODE_REQUEST" == enforce ]] && ! sshd_profile_enforced; then
    warn "--enforce: the sshd profile has not been enforced on this system before."
    warn "Keep console (non-SSH) access until a new SSH login has worked under it."
fi

# =============================================================================
# 1. INSTALL PACKAGES
# =============================================================================

msg "Installing AppArmor packages..."

if [[ "$DRY_RUN" == false ]]; then
    pacman -Syu --noconfirm --needed apparmor

    # Runtime utilities (aa-enforce, aa-complain, aa-status, apparmor_parser)
    # ship inside the apparmor package on Arch Linux. Verify they are available.
    for tool in aa-enforce aa-complain aa-status apparmor_parser; do
        if ! command -v "$tool" &>/dev/null; then
            err "$tool not found after installing apparmor. Check your installation."
        fi
    done

    msg "AppArmor packages installed successfully"
else
    info "DRY-RUN: package installation and upgrades skipped"
fi

# =============================================================================
# 2. ENABLE APPARMOR SERVICE
# =============================================================================

msg "Enabling AppArmor systemd service..."

if [[ "$DRY_RUN" == false ]]; then
    systemctl enable apparmor.service
    systemctl start apparmor.service 2>/dev/null || warn "AppArmor service may require a reboot to start (kernel parameters needed)"
else
    info "DRY-RUN: service enable/start skipped"
fi

# =============================================================================
# 3. CONFIGURE BOOTLOADER KERNEL PARAMETERS
# =============================================================================

msg "Configuring bootloader kernel parameters for AppArmor..."

# AppArmor is switched on through the kernel's lsm= list. security=apparmor
# is not used: as soon as a command line carries lsm=, the kernel ignores
# security= entirely and AppArmor would silently stay off.

# Insert apparmor into a comma-separated LSM list: before bpf when bpf is
# listed, otherwise at the end. A list that already names it is unchanged.
lsm_list_with_apparmor() {
    local list="$1" item out="" placed=false
    local -a items=()
    if [[ ",$list," == *,apparmor,* ]]; then
        printf '%s\n' "$list"
        return 0
    fi
    IFS=',' read -r -a items <<< "$list"
    for item in "${items[@]}"; do
        [[ -n "$item" ]] || continue
        if [[ "$item" == bpf && "$placed" == false ]]; then
            out+="${out:+,}apparmor"
            placed=true
        fi
        out+="${out:+,}$item"
    done
    if [[ "$placed" == false ]]; then
        out+="${out:+,}apparmor"
    fi
    printf '%s\n' "$out"
}

# LSM list for a command line that has no lsm= yet: what the running kernel
# has active (minus the always-on "capability") plus apparmor, so that
# introducing lsm= does not switch off an LSM that is active today.
default_lsm_list() {
    local running=""
    if [[ -r "$LSM_SYSFS" ]]; then
        running=$(tr -d '[:space:]' < "$LSM_SYSFS" 2>/dev/null || true)
    fi
    running=",${running},"
    running="${running/,capability,/,}"
    running="${running#,}"
    running="${running%,}"
    if [[ "$running" =~ ^[a-z0-9_]+(,[a-z0-9_]+)*$ ]]; then
        lsm_list_with_apparmor "$running"
    else
        printf '%s\n' "$LSM_FALLBACK"
    fi
}

# The lsm= token the kernel will honour (the last one), or nothing.
cmdline_lsm_token() {
    local token found=""
    local -a tokens=()
    read -r -a tokens <<< "$1"
    for token in "${tokens[@]}"; do
        if [[ "$token" == lsm=* ]]; then
            found="$token"
        fi
    done
    printf '%s\n' "$found"
}

# Return a kernel command line that enables AppArmor: exactly one apparmor=1
# (an apparmor=0 is replaced) and apparmor in every lsm= list. Without an
# lsm= token a full list is added. Other parameters, including an existing
# security=, are left alone. Whitespace is normalised to single spaces.
add_apparmor_params() {
    local token out="" have_enable=false have_lsm=false
    local -a tokens=()
    read -r -a tokens <<< "$1"
    for token in "${tokens[@]}"; do
        case "$token" in
            apparmor=*)
                [[ "$have_enable" == false ]] || continue
                token="apparmor=1"
                have_enable=true
                ;;
            lsm=*)
                token="lsm=$(lsm_list_with_apparmor "${token#lsm=}")"
                have_lsm=true
                ;;
        esac
        out+="${out:+ }$token"
    done
    if [[ "$have_enable" == false ]]; then
        out+="${out:+ }apparmor=1"
    fi
    if [[ "$have_lsm" == false ]]; then
        out+="${out:+ }lsm=$(default_lsm_list)"
    fi
    printf '%s\n' "$out"
}

# The kernel enables only the first exclusive LSM of the list, so SELinux or
# Smack listed ahead of apparmor still leaves AppArmor off. Say so.
warn_if_lsm_blocked() {
    local list item
    local -a items=()
    list=$(cmdline_lsm_token "$1")
    IFS=',' read -r -a items <<< "${list#lsm=}"
    for item in "${items[@]}"; do
        case "$item" in
            apparmor)
                return 0
                ;;
            selinux|smack)
                warn "$2: lsm= lists '$item' ahead of apparmor. Only the first of them is enabled, so AppArmor stays off until '$item' is removed from that list."
                return 0
                ;;
        esac
    done
    return 0
}

# Kernel parameters of a UKI cmdline file as one line. Comment lines are not
# parameters: mkinitcpio drops every line that starts with '#'.
uki_cmdline_params() {
    { grep -v '^[[:space:]]*#' "$1" || true; } | tr '\n' ' ' | awk '{$1=$1; print}'
}

# Text of a UKI cmdline file with its parameters replaced by "$2": comment and
# blank lines stay where they are, all parameter lines collapse into one line
# at the position of the first (or at the end when there was none).
uki_cmdline_with_params() {
    AAL_PARAMS="$2" awk '
        /^[[:space:]]*#/ || /^[[:space:]]*$/ { print; next }
        !done { print ENVIRON["AAL_PARAMS"]; done = 1 }
        END { if (!done) print ENVIRON["AAL_PARAMS"] }
    ' "$1"
}

# The command line mkinitcpio would embed from a cmdline file (same filter as
# its build_uki()), with whitespace normalised.
mkinitcpio_cmdline_view() {
    { grep -ha -- '^[^#]' "$1" || true; } | tr -s '\n' ' ' | awk '{$1=$1; print}'
}

# All "options" lines of a systemd-boot entry as one line, joined with a
# space the way sd-boot joins them when it loads the entry.
sdboot_entry_options() {
    awk '
        /^[[:space:]]*options([[:space:]]|$)/ {
            sub(/^[[:space:]]*options[[:space:]]*/, "")
            sub(/[[:space:]]+$/, "")
            if ($0 ~ /^".*"$/) $0 = substr($0, 2, length($0) - 2)
            out = out " " $0
        }
        END { $0 = out; $1 = $1; print }
    ' "$1"
}

# Text of a systemd-boot entry with all its "options" lines replaced by a
# single one holding "$2" at the position of the first (appended when the
# entry had none), so no parameter of a later options line is lost.
sdboot_entry_with_options() {
    AAL_OPTS="$2" awk '
        /^[[:space:]]*options([[:space:]]|$)/ {
            if (!done) { print "options " ENVIRON["AAL_OPTS"]; done = 1 }
            next
        }
        { print }
        END { if (!done) print "options " ENVIRON["AAL_OPTS"] }
    ' "$1"
}

# Value of the last GRUB_CMDLINE_LINUX_DEFAULT= assignment, the one that wins
# when grub-mkconfig sources the file, without its quotes (empty when there
# is none). Fails on a value that cannot be rewritten safely, such as one
# followed by a comment or built from several quoted parts.
grub_cmdline_default() {
    local line value plain
    line=$(grep -E '^[[:space:]]*GRUB_CMDLINE_LINUX_DEFAULT=' "$1" | tail -n 1 || true)
    value="${line#*=}"
    value="${value%"${value##*[![:space:]]}"}"
    if [[ ${#value} -ge 2 && "$value" == \"*\" ]]; then
        value="${value:1:${#value}-2}"
        plain="${value//\\\"/}"
        [[ "$plain" != *\"* ]] || return 1
    elif [[ ${#value} -ge 2 && "$value" == \'*\' ]]; then
        value="${value:1:${#value}-2}"
        [[ "$value" != *\'* ]] || return 1
    elif [[ "$value" == *[^A-Za-z0-9_=.,:/@%+-]* ]]; then
        return 1
    fi
    printf '%s\n' "$value"
}

# Text of /etc/default/grub with that assignment set to "$2" (its quote style
# is kept), or with a new assignment appended when the file has none.
grub_with_cmdline_default() {
    AAL_CMDLINE="$2" awk '
        NR == FNR {
            if ($0 ~ /^[[:space:]]*GRUB_CMDLINE_LINUX_DEFAULT=/) last = FNR
            next
        }
        FNR == last {
            quote = ($0 ~ /^[[:space:]]*GRUB_CMDLINE_LINUX_DEFAULT=\047/) ? "\047" : "\""
            print "GRUB_CMDLINE_LINUX_DEFAULT=" quote ENVIRON["AAL_CMDLINE"] quote
            next
        }
        { print }
        END { if (!last) print "GRUB_CMDLINE_LINUX_DEFAULT=\"" ENVIRON["AAL_CMDLINE"] "\"" }
    ' "$1" "$1"
}

has_uki_preset() {
    local preset
    shopt -s nullglob
    for preset in /etc/mkinitcpio.d/*.preset; do
        if grep -Eq '^[[:space:]]*default_uki=' "$preset" 2>/dev/null; then
            shopt -u nullglob
            return 0
        fi
    done
    shopt -u nullglob
    return 1
}

declare -a SDBOOT_ENTRIES=()
shopt -s nullglob
for sd_dir in /efi/loader/entries /boot/loader/entries /boot/efi/loader/entries; do
    [[ -d "$sd_dir" ]] || continue
    for sd_entry in "$sd_dir"/*.conf; do
        SDBOOT_ENTRIES+=("$sd_entry")
    done
done
shopt -u nullglob

if [[ -f "$KERNEL_CMDLINE" ]] && has_uki_preset; then
    BOOTLOADER_DESC="UKI ($KERNEL_CMDLINE)"
    if [[ "$DRY_RUN" == true && ! -r "$KERNEL_CMDLINE" ]]; then
        info "DRY-RUN: $KERNEL_CMDLINE is not readable in unprivileged preview; would ensure $AA_PARAMS_DESC"
    else
        CURRENT_CMDLINE=$(uki_cmdline_params "$KERNEL_CMDLINE")
        if [[ -z "$CURRENT_CMDLINE" ]]; then
            if grep -qE '^#.*[[:space:]]apparmor=1([[:space:]]|$)' "$KERNEL_CMDLINE"; then
                # Earlier versions of this script folded comment lines and
                # parameters into one line. When the file began with a
                # comment, that line starts with '#' and mkinitcpio drops it.
                warn "$KERNEL_CMDLINE has no parameter line, but a comment line carries apparmor=1."
                warn "An earlier run of this script joined your comments and parameters into one line that mkinitcpio ignores, so the UKI was built with an empty command line."
                warn "Restore the parameters from ${KERNEL_CMDLINE}.bak.* (or move them to a line of their own), then re-run."
                [[ "$DRY_RUN" == true ]] || err "Refusing to rebuild UKIs from $KERNEL_CMDLINE in this state."
            else
                warn "$KERNEL_CMDLINE holds no kernel parameters (only comment or blank lines); the AppArmor parameters will be the whole embedded command line."
            fi
        fi
        UPDATED_CMDLINE=$(add_apparmor_params "$CURRENT_CMDLINE")
        AA_LSM_TOKEN=$(cmdline_lsm_token "$UPDATED_CMDLINE")
        warn_if_lsm_blocked "$UPDATED_CMDLINE" "$KERNEL_CMDLINE"

        if [[ "$UPDATED_CMDLINE" != "$CURRENT_CMDLINE" ]]; then
            if [[ "$DRY_RUN" == false ]]; then
                cp -a "$KERNEL_CMDLINE" "${KERNEL_CMDLINE}.bak.$(date +%Y%m%d-%H%M%S)"
                TMP_CMDLINE=$(mktemp "${KERNEL_CMDLINE}.XXXXXX")
                uki_cmdline_with_params "$KERNEL_CMDLINE" "$UPDATED_CMDLINE" > "$TMP_CMDLINE"
                # Check the result with mkinitcpio's own filter before it can
                # end up in a signed UKI.
                if [[ "$(mkinitcpio_cmdline_view "$TMP_CMDLINE")" != *"$UPDATED_CMDLINE"* ]]; then
                    rm -f -- "$TMP_CMDLINE"
                    err "Rewritten $KERNEL_CMDLINE would not give mkinitcpio the expected parameters; file left unchanged."
                fi
                chmod 0600 "$TMP_CMDLINE"
                mv -f -- "$TMP_CMDLINE" "$KERNEL_CMDLINE"
                msg "Updated $KERNEL_CMDLINE: $UPDATED_CMDLINE"

                mkinitcpio -P
                msg "Rebuilt UKI images via mkinitcpio -P"

                if command -v sbctl &>/dev/null && [[ -d /var/lib/sbctl/keys || -f /var/lib/sbctl/GUID || -d /usr/share/secureboot/keys || -f /usr/share/secureboot/GUID || -f /etc/awesome-secureboot.conf ]]; then
                    sbctl sign-all
                    msg "Re-signed Secure Boot UKI images via sbctl"
                fi
            else
                info "DRY-RUN: Would set $KERNEL_CMDLINE to: $UPDATED_CMDLINE (and rebuild/sign UKIs)"
            fi
        else
            info "UKI $KERNEL_CMDLINE already contains AppArmor kernel parameters"
        fi
    fi
elif (( ${#SDBOOT_ENTRIES[@]} > 0 )); then
    BOOTLOADER_DESC="systemd-boot (${#SDBOOT_ENTRIES[@]} entry file(s))"
    for sd_entry in "${SDBOOT_ENTRIES[@]}"; do
        if [[ "$DRY_RUN" == true && ! -r "$sd_entry" ]]; then
            info "DRY-RUN: $sd_entry is not readable in unprivileged preview; would ensure $AA_PARAMS_DESC"
            continue
        fi
        # An entry may carry several "options" lines; sd-boot joins them, so
        # they are read as one string and written back as one line.
        CURRENT_OPTS=$(sdboot_entry_options "$sd_entry")
        UPDATED_OPTS=$(add_apparmor_params "$CURRENT_OPTS")
        AA_LSM_TOKEN=$(cmdline_lsm_token "$UPDATED_OPTS")
        warn_if_lsm_blocked "$UPDATED_OPTS" "$sd_entry"

        if [[ "$UPDATED_OPTS" != "$CURRENT_OPTS" ]]; then
            if [[ "$DRY_RUN" == false ]]; then
                cp -a "$sd_entry" "${sd_entry}.bak.$(date +%Y%m%d-%H%M%S)"
                sdboot_entry_with_options "$sd_entry" "$UPDATED_OPTS" > "${sd_entry}.new"
                if [[ "$(sdboot_entry_options "${sd_entry}.new")" != "$UPDATED_OPTS" ]]; then
                    rm -f -- "${sd_entry}.new"
                    err "Rewritten $sd_entry would not carry the expected options; file left unchanged."
                fi
                mv -f "${sd_entry}.new" "$sd_entry"
                msg "Updated systemd-boot entry: $sd_entry"
            else
                info "DRY-RUN: Would update options in $sd_entry to: $UPDATED_OPTS"
            fi
        else
            info "systemd-boot entry already contains AppArmor parameters: $sd_entry"
        fi
    done
elif [[ -f "$GRUB_DEFAULT" ]]; then
    BOOTLOADER_DESC="GRUB ($GRUB_DEFAULT)"
    if [[ "$DRY_RUN" == true && ! -r "$GRUB_DEFAULT" ]]; then
        info "DRY-RUN: $GRUB_DEFAULT is not readable in unprivileged preview; would ensure $AA_PARAMS_DESC"
    else
        if ! CURRENT_CMDLINE=$(grub_cmdline_default "$GRUB_DEFAULT"); then
            err "Cannot rewrite GRUB_CMDLINE_LINUX_DEFAULT in $GRUB_DEFAULT safely (text after the closing quote, or several quoted parts). Make its last assignment one quoted string on a single line, then re-run this script."
        fi
        UPDATED_CMDLINE=$(add_apparmor_params "$CURRENT_CMDLINE")
        AA_LSM_TOKEN=$(cmdline_lsm_token "$UPDATED_CMDLINE")
        warn_if_lsm_blocked "$UPDATED_CMDLINE" "$GRUB_DEFAULT"

        if [[ "$UPDATED_CMDLINE" != "$CURRENT_CMDLINE" ]]; then
            if [[ "$DRY_RUN" == false ]]; then
                cp -a "$GRUB_DEFAULT" "${GRUB_DEFAULT}.bak.$(date +%Y%m%d-%H%M%S)"
                TMP_GRUB=$(mktemp /etc/default/.grub.XXXXXX)
                grub_with_cmdline_default "$GRUB_DEFAULT" "$UPDATED_CMDLINE" > "$TMP_GRUB"
                if [[ "$(grub_cmdline_default "$TMP_GRUB" || true)" != "$UPDATED_CMDLINE" ]]; then
                    rm -f -- "$TMP_GRUB"
                    err "Rewritten $GRUB_DEFAULT would not carry the expected GRUB_CMDLINE_LINUX_DEFAULT; file left unchanged."
                fi
                chmod --reference="$GRUB_DEFAULT" "$TMP_GRUB" 2>/dev/null || chmod 0644 "$TMP_GRUB"
                mv -f -- "$TMP_GRUB" "$GRUB_DEFAULT"
                msg "GRUB updated: GRUB_CMDLINE_LINUX_DEFAULT=\"$UPDATED_CMDLINE\""

                if [[ -d /efi/grub && ! -d /boot/grub ]]; then
                    grub-mkconfig -o /efi/grub/grub.cfg
                    chmod 0600 /efi/grub/grub.cfg
                else
                    grub-mkconfig -o /boot/grub/grub.cfg
                    chmod 0600 /boot/grub/grub.cfg
                fi
                msg "GRUB configuration regenerated (mode 0600)"
            else
                info "DRY-RUN: Would set GRUB_CMDLINE_LINUX_DEFAULT=\"$UPDATED_CMDLINE\""
            fi
        else
            info "GRUB already contains AppArmor kernel parameters"
        fi
    fi
elif [[ "$DRY_RUN" == true ]]; then
    BOOTLOADER_DESC="preview only (no local bootloader detected)"
    info "DRY-RUN: No UKI (/etc/kernel/cmdline), systemd-boot entries, or GRUB (/etc/default/grub) found; skipping bootloader update"
else
    err "No supported bootloader configuration found (/etc/kernel/cmdline UKI, systemd-boot entries, or $GRUB_DEFAULT)."
fi

# =============================================================================
# 4. WRITE APPARMOR PROFILES
# =============================================================================

msg "Writing AppArmor profiles..."

# Write the profile on stdin to $APPARMOR_DIR/<name> in the given mode. The
# profile texts below are written for enforce mode; complain mode only swaps
# the flag on the profile header, which is also what aa-complain does.
write_profile() {
    sed "s/ flags=(enforce) {\$/ flags=($2) {/" > "$APPARMOR_DIR/$1"
    grep -q " flags=($2) {\$" "$APPARMOR_DIR/$1" || err "Profile $1 was not written in $2 mode"
}

# Mode a profile file is deployed in.
profile_mode() {
    if [[ "$1" == usr.bin.sshd ]]; then
        printf '%s\n' "$SSHD_MODE"
    else
        printf '%s\n' "$OTHER_MODE"
    fi
}

# --- 4.1 nginx ---
info "Writing profile: usr.bin.nginx"
write_profile usr.bin.nginx "$OTHER_MODE" <<'PROFILE'
# AppArmor profile for nginx
# Generated by AwesomeArchLinux/hardening/apparmor/apparmor.sh

abi <abi/3.0>,

#include <tunables/global>

profile nginx /usr/bin/nginx flags=(enforce) {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/openssl>
  #include <abstractions/ssl_certs>

  # Capabilities
  capability net_bind_service,
  capability setuid,
  capability setgid,
  capability chown,
  capability dac_override,
  capability dac_read_search,

  # Network
  network inet stream,
  network inet dgram,
  network inet6 stream,
  network inet6 dgram,
  network unix stream,

  # Binary
  /usr/bin/nginx                   mr,

  # Configuration
  /etc/nginx/{,**}                 r,

  # Web content
  /var/www/{,**}                   r,
  /srv/http/{,**}                  r,
  /usr/share/nginx/html/{,**}      r,

  # Logs
  /var/log/nginx/{,**}             rw,
  owner /var/log/nginx/**          w,

  # PID file and FastCGI upstream sockets
  /run/nginx.pid                   rw,
  /run/php-fpm/*.sock              rw,

  # TLS certificates
  /etc/letsencrypt/{,**}           r,
  /etc/ssl/{,**}                   r,

  # Temp and cache
  /var/cache/nginx/{,**}           rw,
  /var/lib/nginx/{,**}             rw,

  # Proc
  /proc/sys/kernel/random/boot_id  r,
  owner /proc/*/fd/                r,

  # Shared libraries
  /usr/lib/**                      mr,

  # Signal children
  signal (send) peer=nginx,
  signal (receive) peer=nginx,
}
PROFILE

# --- 4.2 sshd ---
info "Writing profile: usr.bin.sshd"
write_profile usr.bin.sshd "$SSHD_MODE" <<'PROFILE'
# AppArmor profile for sshd
# Generated by AwesomeArchLinux/hardening/apparmor/apparmor.sh

abi <abi/3.0>,

#include <tunables/global>

profile sshd /usr/bin/sshd flags=(enforce) {
  #include <abstractions/base>
  #include <abstractions/authentication>
  #include <abstractions/libpam-systemd>
  #include <abstractions/nameservice>
  #include <abstractions/openssl>
  #include <abstractions/wutmp>

  # Capabilities
  capability net_bind_service,
  capability setuid,
  capability setgid,
  capability sys_chroot,
  capability sys_resource,
  capability chown,
  capability dac_override,
  capability dac_read_search,
  capability kill,
  capability audit_write,

  # Network
  network inet stream,
  network inet6 stream,
  network netlink raw,
  network unix stream,
  network unix dgram,

  # Binary and OpenSSH 10.x privilege-separated helpers. sshd re-executes
  # itself on SIGHUP (systemctl reload sshd), hence ix on its own binary.
  /usr/bin/sshd                    mrix,
  /usr/lib/ssh/sshd-session        rix,
  /usr/lib/ssh/sshd-auth           rix,
  /usr/lib/ssh/sftp-server         rix,
  /usr/lib/ssh/ssh-sk-helper       rix,
  /usr/lib/ssh/ssh-pkcs11-helper   rix,

  # Configuration and authorized keys
  /etc/ssh/{,**}                   r,
  owner /etc/ssh/ssh_host_*_key    r,
  @{HOME}/.ssh/{,**}               r,

  # TOTP (hardening/totp/totp.sh): pam_google_authenticator runs inside
  # sshd-session with the fsuid of the user logging in. It reads the secret
  # and rewrites it through "<secret>~" plus rename() on every login.
  owner @{HOME}/.google_authenticator{,~} rw,

  # fscrypt (hardening/fscrypt/fscrypt.sh wires pam_fscrypt.so into
  # system-login, which the sshd PAM stack includes). The module reads its
  # config, the mount table and the metadata on / and /home, opens the mount
  # points and home directories for the key ioctls, keeps a per-user session
  # count, and drops caches on the last logout. No "owner" on mountinfo:
  # the module works with the user's euid, and /proc/<pid>/* of a process
  # that changed euid belongs to root. Best effort: derived from the
  # module's documented behaviour, not exercised under an enforcing kernel.
  /etc/fscrypt.conf                r,
  /                                r,
  /.fscrypt/{,**}                  r,
  @{HOMEDIRS}/                     r,
  @{HOMEDIRS}/.fscrypt/{,**}       r,
  @{HOME}/                         r,
  @{run}/fscrypt/{,**}             rwk,
  @{PROC}/@{pid}/mountinfo         r,
  @{PROC}/sys/vm/drop_caches       w,

  # Logs
  /var/log/{,**}                   rw,
  owner /var/log/auth.log          w,
  owner /var/log/btmp              rw,
  owner /var/log/wtmp              rw,
  owner /var/log/lastlog           rw,

  # PID, systemd notify, and PAM faillock state
  /run/sshd.pid                    rw,
  @{run}/systemd/notify            w,
  /run/faillock/{,**}              rwk,

  # Proc
  /proc/sys/kernel/ngroups_max     r,
  owner /proc/*/fd/                r,
  owner /proc/*/loginuid           rw,
  owner /proc/*/oom_score_adj      w,

  # PTY allocation
  /dev/pts/**                      rw,
  /dev/ptmx                        rw,
  /dev/tty                         rw,

  # User session
  /etc/shells                      r,
  /etc/login.defs                  r,
  /etc/security/{,**}              r,
  /etc/pam.d/{,**}                 r,
  /etc/environment                 r,
  /etc/default/locale              r,
  /etc/motd                        r,
  /etc/issue.net                   r,

  # Privilege separation directory
  /run/sshd/                       r,

  # Login shells — allow exec transition
  /bin/bash                        Ux,
  /bin/sh                          Ux,
  /bin/zsh                         Ux,
  /bin/fish                        Ux,
  /bin/git-shell                   Ux,
  /bin/nologin                     rix,
  /usr/bin/bash                    Ux,
  /usr/bin/sh                      Ux,
  /usr/bin/zsh                     Ux,
  /usr/bin/fish                    Ux,
  /usr/bin/git-shell               Ux,
  /usr/bin/nologin                 rix,

  # Shared libraries
  /usr/lib/**                      mr,

  # Signal children
  signal (send) peer=sshd,
  signal (receive) peer=sshd,

  # Site-specific additions; this file is not touched by re-runs
  include if exists <local/usr.bin.sshd>
}
PROFILE

# --- 4.3 fail2ban-server ---
info "Writing profile: usr.bin.fail2ban-server"
write_profile usr.bin.fail2ban-server "$OTHER_MODE" <<'PROFILE'
# AppArmor profile for fail2ban-server
# Generated by AwesomeArchLinux/hardening/apparmor/apparmor.sh

abi <abi/3.0>,

#include <tunables/global>

profile fail2ban-server /usr/bin/fail2ban-server flags=(enforce) {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/python>

  # Capabilities
  capability net_admin,
  capability net_raw,
  capability dac_read_search,

  # Network
  network inet stream,
  network inet dgram,
  network inet6 stream,
  network inet6 dgram,
  network netlink raw,
  network unix stream,
  network unix dgram,

  # Binary
  /usr/bin/fail2ban-server         mr,

  # Python interpreter and action shell/text helpers
  /usr/bin/python3*                mrix,
  /{usr/,}bin/{bash,sh,dash}       rix,
  /usr/bin/{sed,grep,gawk,awk}     rix,

  # Configuration and systemd journal machine identity
  /etc/fail2ban/{,**}              r,
  /etc/machine-id                  r,

  # State
  /var/lib/fail2ban/{,**}          rwk,
  owner /var/lib/fail2ban/**       rwk,

  # Logs — read to detect intrusions, write own log
  /var/log/{,**}                   r,
  /run/log/journal/{,**}           r,
  owner /var/log/fail2ban.log      rw,

  # Runtime
  /run/fail2ban/{,**}              rw,
  owner /run/fail2ban/fail2ban.pid rw,
  owner /run/fail2ban/fail2ban.sock rw,

  # Firewall tools — needed for ban/unban actions
  /usr/bin/nft                     rix,
  /usr/bin/xtables-{nft,legacy}-multi rix,
  /usr/bin/iptables                rix,
  /usr/bin/iptables-save           rix,
  /usr/bin/iptables-restore        rix,
  /usr/bin/ip6tables               rix,
  /usr/bin/ip6tables-save          rix,
  /usr/bin/ip6tables-restore       rix,

  # Shared libraries
  /usr/lib/**                      mr,

  # Proc
  owner /proc/*/fd/                r,
  /proc/sys/kernel/random/boot_id  r,
}
PROFILE

# --- 4.4 freshclam (ClamAV) ---
info "Writing profile: usr.bin.freshclam"
write_profile usr.bin.freshclam "$OTHER_MODE" <<'PROFILE'
# AppArmor profile for freshclam (ClamAV signature updater)
# Generated by AwesomeArchLinux/hardening/apparmor/apparmor.sh

abi <abi/3.0>,

#include <tunables/global>

profile freshclam /usr/bin/freshclam flags=(enforce) {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/openssl>
  #include <abstractions/ssl_certs>

  # Capabilities. chown: started as root with a log file configured (the
  # Arch default), freshclam lchown()s the log before dropping privileges
  # and exits if that fails; the kernel wants CAP_CHOWN even for a no-op.
  capability setuid,
  capability setgid,
  capability chown,

  # Network — download signature updates and notify clamd over local socket
  network inet stream,
  network inet6 stream,
  network unix stream,
  unix (connect, send, receive) type=stream peer=(label=clamd),

  # Binary
  /usr/bin/freshclam               mr,

  # Signature database
  /var/lib/clamav/{,**}            rw,
  owner /var/lib/clamav/**         rwk,

  # Logs
  /var/log/clamav/{,**}            rw,
  owner /var/log/clamav/**         rw,

  # Configuration
  /etc/clamav/{,**}                r,

  # Runtime
  /run/clamav/{,**}                rw,
  owner /run/clamav/freshclam.pid  rw,

  # DNS resolution for mirror lookups
  /etc/resolv.conf                 r,
  /etc/hosts                       r,

  # Shared libraries
  /usr/lib/**                      mr,

  # Proc
  owner /proc/*/fd/                r,
}
PROFILE

# --- 4.5 clamd (ClamAV) ---
info "Writing profile: usr.bin.clamd"
write_profile usr.bin.clamd "$OTHER_MODE" <<'PROFILE'
# AppArmor profile for clamd (ClamAV daemon)
# Generated by AwesomeArchLinux/hardening/apparmor/apparmor.sh

abi <abi/3.0>,

#include <tunables/global>

profile clamd /usr/bin/clamd flags=(enforce) {
  #include <abstractions/base>
  #include <abstractions/nameservice-strict>

  # Capabilities. chown: started as root with LogFile set (the Arch default),
  # clamd lchown()s the log before dropping privileges and exits if that
  # fails; the kernel wants CAP_CHOWN even when the owner does not change.
  capability setuid,
  capability setgid,
  capability chown,
  capability dac_override,

  # Network — unix sockets for local scanning
  network unix stream,

  # Binary
  /usr/bin/clamd                   mr,

  # Signature database
  /var/lib/clamav/{,**}            r,
  owner /var/lib/clamav/**         r,

  # Logs
  /var/log/clamav/{,**}            rw,
  owner /var/log/clamav/**         rw,

  # Configuration
  /etc/clamav/{,**}                r,

  # Runtime
  /run/clamav/{,**}                rw,
  owner /run/clamav/clamd.ctl      rw,
  owner /run/clamav/clamd.pid      rw,

  # Temporary unpack directories and scan targets
  /tmp/                            r,
  /tmp/**                          r,
  owner /tmp/**                    rwk,
  /var/tmp/                        r,
  owner /var/tmp/**                rwk,
  /home/{,**}                      r,
  /var/{,**}                       r,
  /srv/{,**}                       r,
  /opt/{,**}                       r,

  # Shared libraries
  /usr/lib/**                      mr,

  # Proc
  owner /proc/*/fd/                r,
  /proc/sys/kernel/random/boot_id  r,
}
PROFILE

# --- 4.6 stubby (DNS-over-TLS) ---
# Stubby is no longer installed by the default AwesomeArchLinux path
# (systemd-resolved native DoT replaced it). Only write and load the
# profile if the binary is actually present so this script stays safe
# on systems without Stubby.
STUBBY_INSTALLED=false
if [[ -x /usr/bin/stubby ]]; then
    STUBBY_INSTALLED=true
fi

if [[ "$STUBBY_INSTALLED" == true ]]; then
info "Writing profile: usr.bin.stubby"
write_profile usr.bin.stubby "$OTHER_MODE" <<'PROFILE'
# AppArmor profile for stubby (DNS-over-TLS resolver)
# Generated by AwesomeArchLinux/hardening/apparmor/apparmor.sh

abi <abi/3.0>,

#include <tunables/global>

profile stubby /usr/bin/stubby flags=(enforce) {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/openssl>
  #include <abstractions/ssl_certs>

  # Capabilities
  capability net_bind_service,
  capability setuid,
  capability setgid,

  # Network — DNS forwarding over TLS
  network inet stream,
  network inet dgram,
  network inet6 stream,
  network inet6 dgram,

  # Binary
  /usr/bin/stubby                  mr,

  # Configuration
  /etc/stubby/{,**}                r,

  # Cache
  /var/cache/stubby/{,**}          rw,
  owner /var/cache/stubby/**       rw,

  # Runtime
  /run/stubby/{,**}                rw,
  owner /run/stubby/stubby.pid     rw,

  # TLS trust store
  /etc/ssl/certs/{,**}             r,
  /etc/ca-certificates/{,**}       r,
  /usr/share/ca-certificates/{,**} r,

  # Shared libraries
  /usr/lib/**                      mr,

  # Proc
  owner /proc/*/fd/                r,
}
PROFILE
else
    info "Skipping stubby profile (binary not installed)"
    # Reverse idempotency: unload and drop any stale profile from an older run
    # that did have stubby installed.
    if [[ "$DRY_RUN" == false && -f "$APPARMOR_DIR/usr.bin.stubby" ]]; then
        apparmor_parser -R "$APPARMOR_DIR/usr.bin.stubby" 2>/dev/null || true
    fi
    rm -f "$APPARMOR_DIR/usr.bin.stubby"
fi

# --- 4.7 chronyd ---
info "Writing profile: usr.bin.chronyd"
write_profile usr.bin.chronyd "$OTHER_MODE" <<'PROFILE'
# AppArmor profile for chronyd (NTP client/server)
# Generated by AwesomeArchLinux/hardening/apparmor/apparmor.sh

abi <abi/3.0>,

#include <tunables/global>

profile chronyd /usr/bin/chronyd flags=(enforce) {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/openssl>
  #include <abstractions/ssl_certs>
  #include <abstractions/p11-kit>

  # Capabilities
  capability sys_time,
  capability setuid,
  capability setgid,
  capability chown,
  capability dac_override,
  capability net_bind_service,

  # Network — NTP uses UDP (dgram), NTS-KE uses TCP 4460 (stream)
  network inet dgram,
  network inet6 dgram,
  network inet stream,
  network inet6 stream,
  network unix dgram,

  # Binary
  /usr/bin/chronyd                 mr,

  # Configuration and authentication keys
  /etc/chrony.conf                 r,
  /etc/chrony.keys                 r,

  # State
  /var/lib/chrony/{,**}            rw,
  owner /var/lib/chrony/drift      rw,
  owner /var/lib/chrony/rtc        rw,

  # Logs
  /var/log/chrony/{,**}            rw,
  owner /var/log/chrony/**         rw,

  # Runtime and systemd Type=notify socket
  /run/systemd/notify              w,
  /run/chrony/{,**}                rw,
  /var/run/chrony/{,**}            rw,
  owner /run/chrony/chronyd.pid    rw,
  owner /run/chrony/chronyd.sock   rw,

  # Shared libraries
  /usr/lib/**                      mr,

  # Proc — needed for time-related operations
  owner /proc/*/fd/                r,
  /proc/sys/kernel/random/boot_id  r,

  # Device — RTC, PPS (Pulse Per Second), and PTP hardware clock support
  /dev/pps*                        rw,
  /dev/ptp*                        rw,
  /dev/rtc*                        rw,
}
PROFILE

if [[ "$STUBBY_INSTALLED" == true ]]; then
    msg "All 7 AppArmor profiles written to $APPARMOR_DIR"
else
    msg "6 AppArmor profiles written to $APPARMOR_DIR (stubby skipped)"
fi

# =============================================================================
# 5. LOAD PROFILES
# =============================================================================

PROFILES=(
    "$APPARMOR_DIR/usr.bin.nginx"
    "$APPARMOR_DIR/usr.bin.sshd"
    "$APPARMOR_DIR/usr.bin.fail2ban-server"
    "$APPARMOR_DIR/usr.bin.freshclam"
    "$APPARMOR_DIR/usr.bin.clamd"
    "$APPARMOR_DIR/usr.bin.chronyd"
)
if [[ "$STUBBY_INSTALLED" == true ]]; then
    PROFILES+=("$APPARMOR_DIR/usr.bin.stubby")
fi

if [[ "$DRY_RUN" == false ]]; then
    LOAD_ERRORS=0
    if [[ "$AA_ACTIVE" == true ]]; then
        msg "Loading profiles into the running kernel..."
        for profile in "${PROFILES[@]}"; do
            profile_name=$(basename "$profile")
            profile_mode_now=$(profile_mode "$profile_name")
            # The mode is the flags= value in the profile file itself.
            if ! PARSER_OUT=$(apparmor_parser -r -W "$profile" 2>&1); then
                warn "Failed to load: $profile_name. apparmor_parser said:"
                printf '%s\n' "$PARSER_OUT"
                (( ++LOAD_ERRORS ))
                continue
            fi
            if [[ -n "$PARSER_OUT" ]]; then
                printf '%s\n' "$PARSER_OUT"
            fi
            if [[ "$profile_mode_now" == enforce ]]; then
                # aa-enforce also removes a stale disable/ or force-complain/
                # link that would undo the mode at the next boot. It is not
                # run for a profile that is meant to stay in complain mode.
                if ! PARSER_OUT=$(aa-enforce "$profile" 2>&1); then
                    warn "Loaded, but aa-enforce failed for $profile_name:"
                    printf '%s\n' "$PARSER_OUT"
                    (( ++LOAD_ERRORS ))
                    continue
                fi
            fi
            msg "Loaded in $profile_mode_now mode: $profile_name"
        done
    else
        info "AppArmor is not active in the running kernel yet, so the profiles cannot be loaded now."
        info "Checking that they compile; apparmor.service loads them at the next boot."
        for profile in "${PROFILES[@]}"; do
            profile_name=$(basename "$profile")
            if PARSER_OUT=$(apparmor_parser -Q --skip-cache "$profile" 2>&1); then
                msg "Compiles ($(profile_mode "$profile_name") mode at next boot): $profile_name"
            else
                warn "Does not compile: $profile_name. apparmor_parser said:"
                printf '%s\n' "$PARSER_OUT"
                (( ++LOAD_ERRORS ))
            fi
        done
    fi

    if (( LOAD_ERRORS > 0 )); then
        warn "$LOAD_ERRORS profile(s) had errors; the parser output above says why."
        warn "A profile that does not load leaves its service unconfined. A missing service binary is not a cause: profiles load without it."
    fi
else
    info "DRY-RUN: Skipping profile loading. Profiles are in $APPARMOR_DIR"
    info "To review profiles: ls -la $APPARMOR_DIR/usr.bin.*"
fi

# =============================================================================
# 6. STATUS SUMMARY
# =============================================================================

echo
echo -e "${C_GREEN}========================================================================${C_NC}"
if [[ "$DRY_RUN" == false ]]; then
    echo -e "${C_GREEN} AppArmor hardening complete!${C_NC}"
else
    echo -e "${C_GREEN} AppArmor dry-run preview complete!${C_NC}"
fi
echo -e "${C_GREEN}========================================================================${C_NC}"
echo

if [[ "$DRY_RUN" == false ]]; then
    echo -e "${C_BLUE}AppArmor Status:${C_NC}"
    aa-status 2>/dev/null || warn "aa-status failed (AppArmor may require a reboot)"
    echo
fi

echo -e "${C_BLUE}Profiles written:${C_NC}"
echo "  - $APPARMOR_DIR/usr.bin.nginx           (nginx web server, $OTHER_MODE mode)"
echo "  - $APPARMOR_DIR/usr.bin.sshd            (OpenSSH daemon, $SSHD_MODE mode)"
echo "  - $APPARMOR_DIR/usr.bin.fail2ban-server  (fail2ban intrusion prevention, $OTHER_MODE mode)"
echo "  - $APPARMOR_DIR/usr.bin.freshclam        (ClamAV signature updater, $OTHER_MODE mode)"
echo "  - $APPARMOR_DIR/usr.bin.clamd            (ClamAV scanning daemon, $OTHER_MODE mode)"
if [[ "$STUBBY_INSTALLED" == true ]]; then
    echo "  - $APPARMOR_DIR/usr.bin.stubby           (DNS-over-TLS resolver, $OTHER_MODE mode)"
fi
echo "  - $APPARMOR_DIR/usr.bin.chronyd          (NTP daemon, $OTHER_MODE mode)"
echo
if [[ "$DRY_RUN" == false ]]; then
    echo -e "${C_BLUE}Bootloader:${C_NC}        $BOOTLOADER_DESC"
    echo -e "${C_BLUE}Kernel params:${C_NC}     apparmor=1 ${AA_LSM_TOKEN:-lsm=<list that contains apparmor>}"
    echo -e "${C_BLUE}Profile modes:${C_NC}     sshd: $SSHD_MODE, other services: $OTHER_MODE ($MODE_REASON)"
    echo -e "${C_BLUE}Service:${C_NC}           apparmor.service (enabled)"
    echo -e "${C_BLUE}Log:${C_NC}               $LOGFILE"
    echo

    echo -e "${C_YELLOW}IMPORTANT next steps:${C_NC}"
    if [[ "$AA_ACTIVE" == true ]]; then
        echo "  1. AppArmor is already active in this kernel. A profile attaches when its"
        echo "     service starts: restart the services (or reboot) to confine processes"
        echo "     that are already running."
    else
        echo "  1. REBOOT to activate AppArmor. The kernel must boot with:"
        echo "       apparmor=1 ${AA_LSM_TOKEN:-lsm=<list that contains apparmor>}"
    fi
    echo "  2. Verify that the LSM is really on (an enabled apparmor.service is not enough):"
    echo "       cat /sys/kernel/security/lsm     # must list apparmor"
    echo "       sudo aa-status"
    echo "     If apparmor is missing there, the entry you booted does not carry the"
    echo "     parameters above (for UKIs: sudo mkinitcpio -P, then re-sign if you use Secure Boot)."
    if [[ "$SSHD_MODE" == complain ]]; then
        echo "  3. The sshd profile is in COMPLAIN mode: it blocks nothing yet and only logs"
        echo "     what it does not allow. Log in over SSH the way you normally do (key,"
        echo "     password, TOTP, sftp), then list what the profile is missing:"
        echo "       sudo grep 'apparmor=\"ALLOWED\"' /var/log/audit/audit.log | grep 'profile=\"sshd\"'"
        echo "       sudo journalctl -b | grep 'apparmor=\"ALLOWED\"' | grep 'profile=\"sshd\"'"
        echo "     (audit.log when auditd runs, the journal otherwise.) No output means the"
        echo "     profile covers your logins. Otherwise add the missing rules to"
        echo "     /etc/apparmor.d/local/usr.bin.sshd and reload the profile:"
        echo "       sudo apparmor_parser -r /etc/apparmor.d/usr.bin.sshd"
        echo "  4. Then enforce it. Keep one SSH session open and test a new login before"
        echo "     you close it:"
        echo "       sudo $0 --enforce"
        echo "     (or only sshd: sudo aa-enforce /etc/apparmor.d/usr.bin.sshd)"
    elif [[ "$AA_ACTIVE" == true ]]; then
        echo "  3. The sshd profile is in ENFORCE mode. Keep this session (or a console)"
        echo "     open and test a new SSH login once sshd runs under the profile. If it"
        echo "     fails, switch back from the session you kept:"
        echo "       sudo aa-complain /etc/apparmor.d/usr.bin.sshd"
    else
        echo "  3. The sshd profile is in ENFORCE mode and applies from the first login"
        echo "     after the reboot; no SSH session survives a reboot. Make sure you have"
        echo "     console (non-SSH) access before you reboot. If SSH logins fail, run"
        echo "     from the console:"
        echo "       sudo aa-complain /etc/apparmor.d/usr.bin.sshd"
    fi
    echo
    echo "  If another service misbehaves, switch its profile to complain mode, look"
    echo "  for apparmor=\"DENIED\" (enforce) or apparmor=\"ALLOWED\" (complain) lines in"
    echo "  /var/log/audit/audit.log or the journal, then enforce it again:"
    echo "       sudo aa-complain /etc/apparmor.d/usr.bin.<service>"
    echo "       sudo aa-enforce /etc/apparmor.d/usr.bin.<service>"
    echo
else
    echo -e "${C_BLUE}Bootloader:${C_NC}        $BOOTLOADER_DESC (unchanged — dry-run)"
    echo -e "${C_BLUE}Kernel params:${C_NC}     would ensure apparmor=1 ${AA_LSM_TOKEN:-lsm=<list that contains apparmor>}"
    echo -e "${C_BLUE}Profile modes:${C_NC}     sshd: $SSHD_MODE, other services: $OTHER_MODE ($MODE_REASON)"
    echo -e "${C_BLUE}Service:${C_NC}           apparmor.service (unchanged — dry-run)"
    echo "Preview files remain in: $APPARMOR_DIR"
    echo -e "${C_BLUE}Log:${C_NC}               $LOGFILE"
    echo
    echo -e "${C_YELLOW}DRY-RUN notes:${C_NC}"
    echo "  - No packages, services, bootloader entries, or live profiles were modified."
    echo "  - The preview profiles carry the mode a real run would use (see flags= on"
    echo "    each profile line)."
    echo "  - Validate previewed profiles manually with:"
    echo "      apparmor_parser -Q --skip-cache -I /etc/apparmor.d $APPARMOR_DIR/usr.bin.*"
    echo
fi

echo -e "${C_GREEN}Done.${C_NC}"
