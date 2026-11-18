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
# Usage:       sudo ./apparmor.sh [--dry-run] [-h|--help]
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
#   4. Writes enforce-mode profiles for 7 services
#   5. Loads all profiles in enforce mode via aa-enforce
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
KERNEL_CMDLINE="/etc/kernel/cmdline"
GRUB_DEFAULT="/etc/default/grub"
APPARMOR_DIR="/etc/apparmor.d"
BOOTLOADER_DESC="unknown"
LOGFILE="/var/log/apparmor-hardening-$(date +%Y%m%d-%H%M%S).log"

# --- Usage ---
usage() {
    cat <<EOF
Usage: sudo $0 [options]

Options:
  --dry-run    Write profiles to a unique /tmp/apparmor-preview.XXXXXX/
               directory; do not install packages, enable services, or load profiles
  -h, --help   Show this help

Examples:
  sudo $0
  sudo $0 --dry-run
EOF
    exit 0
}

# --- Parse Arguments ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)   DRY_RUN=true; shift ;;
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

add_apparmor_params() {
    local line="$1" param
    for param in apparmor=1 security=apparmor; do
        if ! grep -qE "(^|[[:space:]])${param}([[:space:]]|$)" <<< "$line"; then
            line="${line:+$line }$param"
        fi
    done
    awk '{$1=$1; print}' <<< "$line"
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
        info "DRY-RUN: $KERNEL_CMDLINE is not readable in unprivileged preview; would ensure apparmor=1 security=apparmor"
    else
        CURRENT_CMDLINE=$(tr '\n' ' ' < "$KERNEL_CMDLINE" | awk '{$1=$1; print}')
        UPDATED_CMDLINE=$(add_apparmor_params "$CURRENT_CMDLINE")

        if [[ "$UPDATED_CMDLINE" != "$CURRENT_CMDLINE" ]]; then
            if [[ "$DRY_RUN" == false ]]; then
                cp -a "$KERNEL_CMDLINE" "${KERNEL_CMDLINE}.bak.$(date +%Y%m%d-%H%M%S)"
                printf '%s\n' "$UPDATED_CMDLINE" > "$KERNEL_CMDLINE"
                chmod 0600 "$KERNEL_CMDLINE"
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
            info "DRY-RUN: $sd_entry is not readable in unprivileged preview; would ensure apparmor=1 security=apparmor"
            continue
        fi
        CURRENT_OPTS=$(awk '/^options[[:space:]]+/ { sub(/^options[[:space:]]+/, ""); print; exit }' "$sd_entry")
        UPDATED_OPTS=$(add_apparmor_params "$CURRENT_OPTS")

        if [[ "$UPDATED_OPTS" != "$CURRENT_OPTS" ]]; then
            if [[ "$DRY_RUN" == false ]]; then
                cp -a "$sd_entry" "${sd_entry}.bak.$(date +%Y%m%d-%H%M%S)"
                if grep -Eq '^options[[:space:]]+' "$sd_entry"; then
                    AAL_OPTS="$UPDATED_OPTS" awk '
                        /^options[[:space:]]+/ { print "options " ENVIRON["AAL_OPTS"]; next }
                        { print }
                    ' "$sd_entry" > "${sd_entry}.new"
                    mv -f "${sd_entry}.new" "$sd_entry"
                else
                    printf 'options %s\n' "$UPDATED_OPTS" >> "$sd_entry"
                fi
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
        info "DRY-RUN: $GRUB_DEFAULT is not readable in unprivileged preview; would ensure apparmor=1 security=apparmor"
    else
        GRUB_LINE=$(grep -E '^[[:space:]]*GRUB_CMDLINE_LINUX_DEFAULT=' "$GRUB_DEFAULT" | head -n 1 || true)
        CURRENT_CMDLINE="${GRUB_LINE#*=}"
        if [[ "$CURRENT_CMDLINE" == \"*\" ]]; then
            CURRENT_CMDLINE="${CURRENT_CMDLINE#\"}"
            CURRENT_CMDLINE="${CURRENT_CMDLINE%\"}"
        elif [[ "$CURRENT_CMDLINE" == \'*\' ]]; then
            CURRENT_CMDLINE="${CURRENT_CMDLINE#\'}"
            CURRENT_CMDLINE="${CURRENT_CMDLINE%\'}"
        fi
        UPDATED_CMDLINE=$(add_apparmor_params "$CURRENT_CMDLINE")

        if [[ "$UPDATED_CMDLINE" != "$CURRENT_CMDLINE" ]]; then
            if [[ "$DRY_RUN" == false ]]; then
                cp -a "$GRUB_DEFAULT" "${GRUB_DEFAULT}.bak.$(date +%Y%m%d-%H%M%S)"
                if grep -Eq '^[[:space:]]*GRUB_CMDLINE_LINUX_DEFAULT=' "$GRUB_DEFAULT"; then
                    TMP_GRUB=$(mktemp /etc/default/.grub.XXXXXX)
                    AAL_CMDLINE="$UPDATED_CMDLINE" awk '
                        !updated && /^[[:space:]]*GRUB_CMDLINE_LINUX_DEFAULT=/ {
                            print "GRUB_CMDLINE_LINUX_DEFAULT=\"" ENVIRON["AAL_CMDLINE"] "\""
                            updated = 1
                            next
                        }
                        { print }
                    ' "$GRUB_DEFAULT" > "$TMP_GRUB"
                    chmod --reference="$GRUB_DEFAULT" "$TMP_GRUB" 2>/dev/null || chmod 0644 "$TMP_GRUB"
                    mv -f -- "$TMP_GRUB" "$GRUB_DEFAULT"
                else
                    printf 'GRUB_CMDLINE_LINUX_DEFAULT="%s"\n' "$UPDATED_CMDLINE" >> "$GRUB_DEFAULT"
                fi
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

# --- 4.1 nginx ---
info "Writing profile: usr.bin.nginx"
cat > "$APPARMOR_DIR/usr.bin.nginx" <<'PROFILE'
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
cat > "$APPARMOR_DIR/usr.bin.sshd" <<'PROFILE'
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

  # Binary and OpenSSH 10.x privilege-separated helpers
  /usr/bin/sshd                    mr,
  /usr/lib/ssh/sshd-session        rix,
  /usr/lib/ssh/sshd-auth           rix,
  /usr/lib/ssh/sftp-server         rix,
  /usr/lib/ssh/ssh-sk-helper       rix,
  /usr/lib/ssh/ssh-pkcs11-helper   rix,

  # Configuration and authorized keys
  /etc/ssh/{,**}                   r,
  owner /etc/ssh/ssh_host_*_key    r,
  @{HOME}/.ssh/{,**}               r,

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
}
PROFILE

# --- 4.3 fail2ban-server ---
info "Writing profile: usr.bin.fail2ban-server"
cat > "$APPARMOR_DIR/usr.bin.fail2ban-server" <<'PROFILE'
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
cat > "$APPARMOR_DIR/usr.bin.freshclam" <<'PROFILE'
# AppArmor profile for freshclam (ClamAV signature updater)
# Generated by AwesomeArchLinux/hardening/apparmor/apparmor.sh

abi <abi/3.0>,

#include <tunables/global>

profile freshclam /usr/bin/freshclam flags=(enforce) {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/openssl>
  #include <abstractions/ssl_certs>

  # Capabilities
  capability setuid,
  capability setgid,

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
cat > "$APPARMOR_DIR/usr.bin.clamd" <<'PROFILE'
# AppArmor profile for clamd (ClamAV daemon)
# Generated by AwesomeArchLinux/hardening/apparmor/apparmor.sh

abi <abi/3.0>,

#include <tunables/global>

profile clamd /usr/bin/clamd flags=(enforce) {
  #include <abstractions/base>
  #include <abstractions/nameservice-strict>

  # Capabilities
  capability setuid,
  capability setgid,
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
cat > "$APPARMOR_DIR/usr.bin.stubby" <<'PROFILE'
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
cat > "$APPARMOR_DIR/usr.bin.chronyd" <<'PROFILE'
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
# 5. LOAD PROFILES IN ENFORCE MODE
# =============================================================================

if [[ "$DRY_RUN" == false ]]; then
    msg "Loading profiles in enforce mode..."

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

    LOAD_ERRORS=0
    for profile in "${PROFILES[@]}"; do
        profile_name=$(basename "$profile")
        if apparmor_parser -r -W "$profile" 2>/dev/null; then
            if aa-enforce "$profile" 2>/dev/null; then
                msg "Loaded and enforced: $profile_name"
            else
                warn "Failed to enforce: $profile_name"
                (( ++LOAD_ERRORS ))
            fi
        else
            warn "Failed to parse: $profile_name (service binary or AppArmor kernel LSM may not be active yet)"
            (( ++LOAD_ERRORS ))
        fi
    done

    if [[ "$LOAD_ERRORS" -gt 0 ]]; then
        warn "$LOAD_ERRORS profile(s) failed to load. This is expected if the service is not installed."
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
echo "  - $APPARMOR_DIR/usr.bin.nginx           (nginx web server)"
echo "  - $APPARMOR_DIR/usr.bin.sshd            (OpenSSH daemon)"
echo "  - $APPARMOR_DIR/usr.bin.fail2ban-server  (fail2ban intrusion prevention)"
echo "  - $APPARMOR_DIR/usr.bin.freshclam        (ClamAV signature updater)"
echo "  - $APPARMOR_DIR/usr.bin.clamd            (ClamAV scanning daemon)"
if [[ "$STUBBY_INSTALLED" == true ]]; then
    echo "  - $APPARMOR_DIR/usr.bin.stubby           (DNS-over-TLS resolver)"
fi
echo "  - $APPARMOR_DIR/usr.bin.chronyd          (NTP daemon)"
echo
if [[ "$DRY_RUN" == false ]]; then
    echo -e "${C_BLUE}Bootloader:${C_NC}        $BOOTLOADER_DESC (apparmor=1 security=apparmor)"
    echo -e "${C_BLUE}Service:${C_NC}           apparmor.service (enabled)"
    echo -e "${C_BLUE}Log:${C_NC}               $LOGFILE"
    echo

    echo -e "${C_YELLOW}IMPORTANT next steps:${C_NC}"
    echo "  1. REBOOT to activate AppArmor kernel parameters."
    echo "     The kernel must load with apparmor=1 security=apparmor."
    echo "  2. After reboot, verify AppArmor is active:"
    echo "     sudo aa-status"
    echo "  3. If a service misbehaves, switch its profile to complain mode:"
    echo "     sudo aa-complain /etc/apparmor.d/usr.bin.<service>"
    echo "  4. Review /var/log/audit/audit.log or journalctl for AppArmor denials."
    echo "  5. Once satisfied, re-enforce the profile:"
    echo "     sudo aa-enforce /etc/apparmor.d/usr.bin.<service>"
    echo
else
    echo -e "${C_BLUE}Bootloader:${C_NC}        $BOOTLOADER_DESC (unchanged — dry-run)"
    echo -e "${C_BLUE}Service:${C_NC}           apparmor.service (unchanged — dry-run)"
    echo "Preview files remain in: $APPARMOR_DIR"
    echo -e "${C_BLUE}Log:${C_NC}               $LOGFILE"
    echo
    echo -e "${C_YELLOW}DRY-RUN notes:${C_NC}"
    echo "  - No packages, services, bootloader entries, or live profiles were modified."
    echo "  - Validate previewed profiles manually with:"
    echo "      apparmor_parser -Q --skip-cache -I /etc/apparmor.d $APPARMOR_DIR/usr.bin.*"
    echo
fi

echo -e "${C_GREEN}Done.${C_NC}"
