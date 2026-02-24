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
#                - stubby (DNS-over-TLS)
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
#   - GRUB bootloader (for kernel parameter injection)
#
# What this script does:
#   1. Installs apparmor and apparmor-utils
#   2. Enables the AppArmor systemd service
#   3. Configures GRUB to load AppArmor at boot
#   4. Writes enforce-mode profiles for 7 services
#   5. Loads all profiles in enforce mode via aa-enforce
#   6. Displays a status summary via aa-status
# =============================================================================

set -euo pipefail

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
GRUB_DEFAULT="/etc/default/grub"
APPARMOR_DIR="/etc/apparmor.d"
LOGFILE="/var/log/apparmor-hardening-$(date +%Y%m%d-%H%M%S).log"

# --- Usage ---
usage() {
    cat <<EOF
Usage: sudo $0 [options]

Options:
  --dry-run    Write profiles to /tmp/apparmor-preview/ instead of $APPARMOR_DIR
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
    APPARMOR_DIR="/tmp/apparmor-preview"
    mkdir -p "$APPARMOR_DIR"
    warn "DRY-RUN mode: profiles will be written to $APPARMOR_DIR (not loaded)"
fi

# Redirect output to logfile as well
exec > >(tee -a "$LOGFILE") 2>&1

info "AppArmor hardening script started"
info "Log: $LOGFILE"

# =============================================================================
# 1. INSTALL PACKAGES
# =============================================================================

msg "Installing AppArmor packages..."

pacman -Syu --noconfirm --needed apparmor

# apparmor-utils (aa-enforce, aa-complain, aa-status) is part of the apparmor
# package on Arch Linux. Verify the tools are available.
for tool in aa-enforce aa-complain aa-status apparmor_parser; do
    if ! command -v "$tool" &>/dev/null; then
        err "$tool not found after installing apparmor. Check your installation."
    fi
done

msg "AppArmor packages installed successfully"

# =============================================================================
# 2. ENABLE APPARMOR SERVICE
# =============================================================================

msg "Enabling AppArmor systemd service..."

systemctl enable apparmor.service
if [[ "$DRY_RUN" == false ]]; then
    systemctl start apparmor.service 2>/dev/null || warn "AppArmor service may require a reboot to start (kernel parameters needed)"
fi

# =============================================================================
# 3. CONFIGURE GRUB KERNEL PARAMETERS
# =============================================================================

msg "Configuring GRUB for AppArmor..."

if [[ ! -f "$GRUB_DEFAULT" ]]; then
    err "GRUB configuration not found at $GRUB_DEFAULT. Is GRUB installed?"
fi

# Read the current GRUB_CMDLINE_LINUX_DEFAULT value
CURRENT_CMDLINE=$(grep '^GRUB_CMDLINE_LINUX_DEFAULT=' "$GRUB_DEFAULT" | sed 's/^GRUB_CMDLINE_LINUX_DEFAULT="//;s/"$//')

NEEDS_UPDATE=false

if [[ "$CURRENT_CMDLINE" != *"apparmor=1"* ]]; then
    CURRENT_CMDLINE="$CURRENT_CMDLINE apparmor=1"
    NEEDS_UPDATE=true
fi

if [[ "$CURRENT_CMDLINE" != *"security=apparmor"* ]]; then
    CURRENT_CMDLINE="$CURRENT_CMDLINE security=apparmor"
    NEEDS_UPDATE=true
fi

# Clean up any double spaces
CURRENT_CMDLINE=$(echo "$CURRENT_CMDLINE" | sed 's/  */ /g;s/^ //;s/ $//')

if [[ "$NEEDS_UPDATE" == true ]]; then
    if [[ "$DRY_RUN" == false ]]; then
        # Back up GRUB config
        cp "$GRUB_DEFAULT" "${GRUB_DEFAULT}.bak.$(date +%Y%m%d-%H%M%S)"
        sed -i "s|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT=\"$CURRENT_CMDLINE\"|" "$GRUB_DEFAULT"
        msg "GRUB updated: GRUB_CMDLINE_LINUX_DEFAULT=\"$CURRENT_CMDLINE\""

        # Regenerate GRUB config
        grub-mkconfig -o /boot/grub/grub.cfg
        msg "GRUB configuration regenerated"
    else
        info "DRY-RUN: Would set GRUB_CMDLINE_LINUX_DEFAULT=\"$CURRENT_CMDLINE\""
    fi
else
    info "GRUB already contains AppArmor kernel parameters"
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

  # Capabilities
  capability net_bind_service,
  capability setuid,
  capability setgid,
  capability dac_override,

  # Network
  network inet stream,
  network inet dgram,
  network inet6 stream,
  network inet6 dgram,

  # Binary
  /usr/bin/nginx                   mr,

  # Configuration
  /etc/nginx/**                    r,

  # Web content
  /var/www/**                      r,

  # Logs
  /var/log/nginx/**                rw,
  owner /var/log/nginx/**          w,

  # PID file
  /run/nginx.pid                   rw,

  # TLS certificates
  /etc/letsencrypt/**              r,
  /etc/ssl/**                      r,

  # Temp and cache
  /var/cache/nginx/**              rw,
  /var/lib/nginx/**                rw,

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
  #include <abstractions/nameservice>
  #include <abstractions/openssl>

  # Capabilities
  capability net_bind_service,
  capability setuid,
  capability setgid,
  capability sys_chroot,
  capability chown,
  capability dac_override,
  capability kill,
  capability audit_write,

  # Network
  network inet stream,
  network inet6 stream,

  # Binary
  /usr/bin/sshd                    mr,

  # Configuration
  /etc/ssh/**                      r,
  owner /etc/ssh/ssh_host_*_key    r,

  # Logs
  /var/log/**                      rw,
  owner /var/log/auth.log          w,
  owner /var/log/btmp              rw,
  owner /var/log/wtmp              rw,
  owner /var/log/lastlog           rw,

  # PID file
  /run/sshd.pid                    rw,

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
  /etc/security/**                 r,
  /etc/pam.d/**                    r,
  /etc/environment                 r,
  /etc/default/locale              r,
  /etc/motd                        r,

  # Privilege separation directory
  /run/sshd/                       r,

  # Login shells — allow exec transition
  /bin/bash                        Ux,
  /bin/sh                          Ux,
  /bin/zsh                         Ux,
  /usr/bin/bash                    Ux,
  /usr/bin/sh                      Ux,
  /usr/bin/zsh                     Ux,

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

  # Binary
  /usr/bin/fail2ban-server         mr,

  # Python interpreter
  /usr/bin/python3*                ix,

  # Configuration
  /etc/fail2ban/**                 r,

  # State
  /var/lib/fail2ban/**             rw,
  owner /var/lib/fail2ban/**       rwk,

  # Logs — read to detect intrusions, write own log
  /var/log/**                      r,
  owner /var/log/fail2ban.log      rw,

  # Runtime
  /run/fail2ban/**                 rw,
  owner /run/fail2ban/fail2ban.pid rw,
  owner /run/fail2ban/fail2ban.sock rw,

  # Firewall tools — needed for ban/unban actions
  /usr/bin/nft                     ix,
  /usr/bin/iptables                ix,
  /usr/bin/iptables-save           ix,
  /usr/bin/iptables-restore        ix,
  /usr/bin/ip6tables               ix,
  /usr/bin/ip6tables-save          ix,
  /usr/bin/ip6tables-restore       ix,

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

  # Capabilities
  capability setuid,
  capability setgid,

  # Network — needs to download signature updates
  network inet stream,
  network inet6 stream,

  # Binary
  /usr/bin/freshclam               mr,

  # Signature database
  /var/lib/clamav/**               rw,
  owner /var/lib/clamav/**         rwk,

  # Logs
  /var/log/clamav/**               rw,
  owner /var/log/clamav/**         rw,

  # Configuration
  /etc/clamav/**                   r,

  # Runtime
  /run/clamav/**                   rw,
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
  #include <abstractions/nameservice>

  # Capabilities
  capability setuid,
  capability setgid,
  capability dac_override,

  # Network — unix sockets for local scanning
  network unix stream,

  # Binary
  /usr/bin/clamd                   mr,

  # Signature database
  /var/lib/clamav/**               r,
  owner /var/lib/clamav/**         r,

  # Logs
  /var/log/clamav/**               rw,
  owner /var/log/clamav/**         rw,

  # Configuration
  /etc/clamav/**                   r,

  # Runtime
  /run/clamav/**                   rw,
  owner /run/clamav/clamd.ctl      rw,
  owner /run/clamav/clamd.pid      rw,

  # Scan targets — needs read access to files submitted for scanning
  /tmp/**                          r,

  # Shared libraries
  /usr/lib/**                      mr,

  # Proc
  owner /proc/*/fd/                r,
  /proc/sys/kernel/random/boot_id  r,
}
PROFILE

# --- 4.6 stubby (DNS-over-TLS) ---
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
  /etc/stubby/**                   r,

  # Cache
  /var/cache/stubby/**             rw,
  owner /var/cache/stubby/**       rw,

  # Runtime
  /run/stubby/**                   rw,
  owner /run/stubby/stubby.pid     rw,

  # TLS trust store
  /etc/ssl/certs/**                r,
  /etc/ca-certificates/**          r,
  /usr/share/ca-certificates/**    r,

  # Shared libraries
  /usr/lib/**                      mr,

  # Proc
  owner /proc/*/fd/                r,
}
PROFILE

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

  # Capabilities
  capability sys_time,
  capability setuid,
  capability setgid,
  capability net_bind_service,

  # Network — NTP uses UDP (dgram)
  network inet dgram,
  network inet6 dgram,

  # Binary
  /usr/bin/chronyd                 mr,

  # Configuration
  /etc/chrony.conf                 r,

  # State
  /var/lib/chrony/**               rw,
  owner /var/lib/chrony/drift      rw,
  owner /var/lib/chrony/rtc        rw,

  # Logs
  /var/log/chrony/**               rw,
  owner /var/log/chrony/**         rw,

  # Runtime
  /run/chrony/**                   rw,
  /var/run/chrony/**               rw,
  owner /run/chrony/chronyd.pid    rw,
  owner /run/chrony/chronyd.sock   rw,

  # Shared libraries
  /usr/lib/**                      mr,

  # Proc — needed for time-related operations
  owner /proc/*/fd/                r,
  /proc/sys/kernel/random/boot_id  r,

  # Device — PPS (Pulse Per Second) hardware clock support
  /dev/pps*                        r,
  /dev/rtc*                        r,
}
PROFILE

msg "All 7 AppArmor profiles written to $APPARMOR_DIR"

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
        "$APPARMOR_DIR/usr.bin.stubby"
        "$APPARMOR_DIR/usr.bin.chronyd"
    )

    LOAD_ERRORS=0
    for profile in "${PROFILES[@]}"; do
        profile_name=$(basename "$profile")
        if apparmor_parser -r -W "$profile" 2>/dev/null; then
            aa-enforce "$profile" 2>/dev/null && \
                msg "Loaded and enforced: $profile_name" || \
                { warn "Failed to enforce: $profile_name"; ((LOAD_ERRORS++)); }
        else
            warn "Failed to parse: $profile_name (service binary may not be installed)"
            ((LOAD_ERRORS++))
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
echo -e "${C_GREEN} AppArmor hardening complete!${C_NC}"
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
echo "  - $APPARMOR_DIR/usr.bin.stubby           (DNS-over-TLS resolver)"
echo "  - $APPARMOR_DIR/usr.bin.chronyd          (NTP daemon)"
echo
echo -e "${C_BLUE}GRUB:${C_NC}              apparmor=1 security=apparmor"
echo -e "${C_BLUE}Service:${C_NC}           apparmor.service (enabled)"
echo -e "${C_BLUE}Log:${C_NC}               $LOGFILE"
echo

echo -e "${C_YELLOW}IMPORTANT next steps:${C_NC}"
echo "  1. REBOOT to activate AppArmor kernel parameters in GRUB."
echo "     The kernel must load with apparmor=1 security=apparmor."
echo "  2. After reboot, verify AppArmor is active:"
echo "     sudo aa-status"
echo "  3. If a service misbehaves, switch its profile to complain mode:"
echo "     sudo aa-complain /etc/apparmor.d/usr.bin.<service>"
echo "  4. Review /var/log/audit/audit.log or journalctl for AppArmor denials."
echo "  5. Once satisfied, re-enforce the profile:"
echo "     sudo aa-enforce /etc/apparmor.d/usr.bin.<service>"
echo

echo -e "${C_GREEN}Done.${C_NC}"
