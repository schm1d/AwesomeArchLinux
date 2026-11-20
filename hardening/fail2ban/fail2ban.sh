#!/usr/bin/env bash

# =============================================================================
# Script:      fail2ban.sh
# Description: Installs and configures fail2ban with extended jails on Arch
#              Linux, targeting:
#                - SSH brute-force protection (standard + aggressive)
#                - nginx HTTP abuse protection
#                - Postfix SMTP AUTH and Dovecot login protection (when installed)
#                - Recidive jail for repeat offenders
#                - nftables integration (Arch default firewall)
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
#
# Usage:       sudo ./fail2ban.sh [-p SSH_PORT] [-i ADDRESS]... [-h]
#
# Requirements:
#   - Arch Linux with pacman
#   - Root privileges
#   - nftables installed and running (Arch default)
#
# What this script does:
#   1. Installs fail2ban if not present
#   2. Creates /etc/fail2ban/jail.local with hardened jail configuration
#   3. Creates a custom sshd-aggressive filter for zero-tolerance SSH abuse
#   4. Creates nftables action override for Arch compatibility
#   5. Enables and restarts fail2ban
#   6. Shows jail status summary
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
SSH_PORT=22
IGNORE_IPS=()

# --- Usage ---
usage() {
    cat <<EOF
Usage: sudo $0 [options]

Optional:
  -p PORT       SSH port (default: $SSH_PORT)
  -i ADDRESS    Never ban this IP address or CIDR network (repeatable). Use it
                for the address you administer the host from, so a few typos
                cannot lock you out for up to four weeks.
  -h            Show this help

jail.local is regenerated on every run: pass the same -p and -i options again
when you re-run the script.

Examples:
  sudo $0
  sudo $0 -p 2222
  sudo $0 -p 2222 -i 203.0.113.7 -i 2001:db8:1234::/48
EOF
    exit 0
}

# --- Parse Arguments ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        -p)
            [[ $# -ge 2 && -n "${2:-}" ]] || err "Option -p requires a port number"
            SSH_PORT="$2"
            shift 2
            ;;
        -i)
            [[ $# -ge 2 && -n "${2:-}" ]] || err "Option -i requires an IP address or CIDR network"
            IGNORE_IPS+=("$2")
            shift 2
            ;;
        -h|--help)  usage ;;
        *)          err "Unknown option: $1" ;;
    esac
done

# --- Validate ---
[[ $(id -u) -eq 0 ]] || err "Must be run as root"

# Validate SSH_PORT is a number in valid range. 10# keeps a leading zero from
# being read as octal ("08" is an error, "010" would silently become 8).
if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || (( 10#$SSH_PORT < 1 || 10#$SSH_PORT > 65535 )); then
    err "Invalid SSH port: $SSH_PORT (must be 1-65535)"
fi
SSH_PORT=$((10#$SSH_PORT))

# Succeeds for an IPv4/IPv6 address with an optional prefix length. The value
# is written into jail.local, so anything else (spaces, newlines, option
# syntax) is rejected. Hex digits are listed explicitly because the range a-f
# also matches accented letters in UTF-8 locales.
valid_ignore_entry() {
    local entry="$1" addr prefix="" max octet
    local v4_re='^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$'
    local v6_re='^[0123456789abcdefABCDEF:]{2,39}$'

    addr="${entry%%/*}"
    if [[ "$addr" =~ $v4_re ]]; then
        for octet in "${BASH_REMATCH[@]:1:4}"; do
            (( 10#$octet <= 255 )) || return 1
        done
        max=32
    elif [[ "$addr" == *:* && "$addr" != *:::* && "$addr" =~ $v6_re ]]; then
        max=128
    else
        return 1
    fi
    if [[ "$entry" == */* ]]; then
        prefix="${entry#*/}"
        # No leading zero, and not /0: that would exempt the whole address
        # family from every jail.
        [[ "$prefix" =~ ^[1-9][0-9]{0,2}$ ]] || return 1
        (( prefix <= max )) || return 1
    fi
}

IGNORE_LIST=""
for entry in "${IGNORE_IPS[@]}"; do
    valid_ignore_entry "$entry" ||
        err "Invalid -i value: $entry (expected an IPv4/IPv6 address or CIDR network, prefix length at least 1)"
    IGNORE_LIST+=" $entry"
done

info "SSH port: $SSH_PORT"
if [[ -n "$IGNORE_LIST" ]]; then
    info "Never banned:$IGNORE_LIST"
else
    warn "No -i ADDRESS given: only loopback is exempt from bans, including your own address."
fi

# =============================================================================
# 1. INSTALL FAIL2BAN
# =============================================================================

msg "Installing fail2ban..."

if pacman -Qi fail2ban &>/dev/null; then
    info "fail2ban is already installed"
else
    pacman -Syu --noconfirm --needed fail2ban
    msg "fail2ban installed successfully"
fi

# Ensure nftables is available (Arch ships it by default)
if ! command -v nft &>/dev/null; then
    warn "nftables not found, installing..."
    pacman -Syu --noconfirm --needed nftables
fi

# =============================================================================
# 2. CREATE JAIL CONFIGURATION
# =============================================================================

msg "Writing /etc/fail2ban/jail.local..."

install -d -m 0755 /etc/fail2ban /etc/fail2ban/filter.d /etc/fail2ban/action.d

# Ensure fail2ban's own log file exists so [recidive] (backend = auto) starts cleanly
if [[ ! -f /var/log/fail2ban.log ]]; then
    install -o root -g root -m 0640 /dev/null /var/log/fail2ban.log
    info "Initialized /var/log/fail2ban.log (0640)"
fi

# Enable nginx file-backed jails only when nginx log files exist on disk so
# fail2ban always starts cleanly on hosts without nginx installed yet.
NGINX_JAILS_ENABLED=false
if [[ -f /var/log/nginx/access.log && -f /var/log/nginx/error.log ]]; then
    NGINX_JAILS_ENABLED=true
    info "Detected /var/log/nginx/{access,error}.log — enabling [nginx-*] jails"
else
    info "nginx log files not present — setting [nginx-*] jails to enabled = false"
fi

# Mail jails read the systemd journal (paths-arch.conf), so there is no log
# file to wait for; they are enabled as soon as the service is installed.
POSTFIX_JAIL_ENABLED=false
DOVECOT_JAIL_ENABLED=false
if pacman -Qq postfix &>/dev/null; then
    POSTFIX_JAIL_ENABLED=true
    info "Detected postfix — enabling [postfix-sasl] jail"
fi
if pacman -Qq dovecot &>/dev/null; then
    DOVECOT_JAIL_ENABLED=true
    info "Detected dovecot — enabling [dovecot] jail"
fi
if ! $POSTFIX_JAIL_ENABLED && ! $DOVECOT_JAIL_ENABLED; then
    info "postfix/dovecot not installed — mail jails set to enabled = false (re-run after installing them)"
fi

# Back up existing jail.local if present
if [[ -f /etc/fail2ban/jail.local ]]; then
    BACKUP="/etc/fail2ban/jail.local.bak.$(date +%Y%m%d-%H%M%S)"
    cp /etc/fail2ban/jail.local "$BACKUP"
    info "Existing jail.local backed up to $BACKUP"
fi

cat > /etc/fail2ban/jail.local <<EOF
# =============================================================================
# fail2ban jail configuration
# Generated by AwesomeArchLinux/hardening/fail2ban/fail2ban.sh
#
# This file overrides /etc/fail2ban/jail.conf — do NOT edit jail.conf directly.
# =============================================================================

[DEFAULT]
# --- Ban defaults ---
bantime   = 1h
findtime  = 10m
maxretry  = 5

# --- nftables actions (Arch Linux default firewall) ---
banaction          = nftables-multiport
banaction_allports = nftables-allports

# --- Whitelist loopback and the addresses given with -i ---
ignoreip = 127.0.0.1/8 ::1${IGNORE_LIST}

# --- Use systemd journal (Arch does not use rsyslog by default) ---
backend = systemd

# ============================================================================
# SSH JAILS
# ============================================================================

[sshd]
enabled  = true
port     = ${SSH_PORT}
maxretry = 3
bantime  = 24h
findtime = 1h

# --- Aggressive SSH jail (custom filter) ---
# Harsh 7-day ban for clearly malicious SSH probing:
#   - Invalid user attempts
#   - Pre-auth disconnects/closures involving invalid/authenticating users
#   - Clients that do not send an SSH protocol banner
[sshd-aggressive]
enabled  = true
filter   = sshd-aggressive
port     = ${SSH_PORT}
maxretry = 3
bantime  = 7d
findtime = 24h

# ============================================================================
# NGINX JAILS
# ============================================================================

[nginx-http-auth]
enabled  = ${NGINX_JAILS_ENABLED}
backend  = auto
port     = http,https
logpath  = /var/log/nginx/error.log
maxretry = 3
bantime  = 1h

[nginx-botsearch]
enabled  = ${NGINX_JAILS_ENABLED}
backend  = auto
port     = http,https
logpath  = /var/log/nginx/access.log
maxretry = 2
bantime  = 7d

[nginx-limit-req]
enabled  = ${NGINX_JAILS_ENABLED}
backend  = auto
port     = http,https
logpath  = /var/log/nginx/error.log
maxretry = 5
bantime  = 1h

# ============================================================================
# MAIL JAILS
# ============================================================================

# SMTP AUTH brute force on submission/smtps ("SASL ... authentication failed").
[postfix-sasl]
enabled  = ${POSTFIX_JAIL_ENABLED}
maxretry = 5
bantime  = 24h
findtime = 1h

# IMAP/POP3/ManageSieve logins and the SASL lookups Dovecot does for Postfix.
[dovecot]
enabled  = ${DOVECOT_JAIL_ENABLED}
maxretry = 5
bantime  = 24h
findtime = 1h

# ============================================================================
# RECIDIVE JAIL (repeat offenders)
# ============================================================================

# Monitors fail2ban's own log. If an IP gets banned 3 times across any jail
# within 1 day, it is banned from ALL ports for 4 weeks.
[recidive]
enabled   = true
backend   = auto
banaction = nftables-allports
logpath   = /var/log/fail2ban.log
bantime   = 4w
findtime  = 1d
maxretry  = 3
EOF
chmod 0644 /etc/fail2ban/jail.local

msg "jail.local written successfully"

# =============================================================================
# 3. CREATE OPENSSH 10.X SSHD OVERRIDE AND CUSTOM SSHD-AGGRESSIVE FILTER
# =============================================================================

msg "Writing OpenSSH 10.x filter override /etc/fail2ban/filter.d/sshd.local..."

cat > /etc/fail2ban/filter.d/sshd.local <<'EOF'
# =============================================================================
# OpenSSH 10.x privilege-separation filter override for [sshd]
# Generated by AwesomeArchLinux/hardening/fail2ban/fail2ban.sh
#
# OpenSSH 10.x emits authentication failures from sshd-auth / sshd-session
# child binaries under sshd.service rather than _COMM=sshd.
# =============================================================================

[Definition]
_daemon = sshd(?:-session|-auth)?

[Init]
journalmatch = _SYSTEMD_UNIT=sshd.service
EOF
chmod 0644 /etc/fail2ban/filter.d/sshd.local

msg "sshd.local filter override created"

msg "Writing custom filter /etc/fail2ban/filter.d/sshd-aggressive.conf..."

cat > /etc/fail2ban/filter.d/sshd-aggressive.conf <<'EOF'
# =============================================================================
# fail2ban filter: sshd-aggressive
# Generated by AwesomeArchLinux/hardening/fail2ban/fail2ban.sh
#
# Aggressive filter for malicious SSH probing (invalid users, pre-auth user
# disconnects, and bad protocol banners) while ignoring bare Happy Eyeballs
# or load-balancer TCP probes that close before sending an SSH username.
# =============================================================================

[INCLUDES]
before = common.conf

[Definition]
_daemon = sshd(?:-session|-auth)?

failregex = ^%(__prefix_line)sInvalid user .* from <HOST>
            ^%(__prefix_line)sConnection closed by (?:invalid|authenticating) user .* <HOST> port \d+ \[preauth\]
            ^%(__prefix_line)sDisconnected from (?:invalid|authenticating) user .* <HOST> port \d+ \[preauth\]
            ^%(__prefix_line)sbanner exchange: Connection from <HOST> port \d+: invalid format

ignoreregex =

[Init]
journalmatch = _SYSTEMD_UNIT=sshd.service
EOF
chmod 0644 /etc/fail2ban/filter.d/sshd-aggressive.conf

msg "sshd-aggressive filter created"

# =============================================================================
# 4. CREATE DUAL-STACK NFTABLES ACTION OVERRIDE
# =============================================================================

msg "Writing dual-stack nftables action override /etc/fail2ban/action.d/nftables.local..."

# Remove any legacy broken IPv4-only nftables-common.local override
rm -f /etc/fail2ban/action.d/nftables-common.local

cat > /etc/fail2ban/action.d/nftables.local <<'EOF'
# =============================================================================
# Dual-stack nftables action override for Arch Linux
# Generated by AwesomeArchLinux/hardening/fail2ban/fail2ban.sh
#
# Upstream nftables.conf already handles IPv4 (addr_type = ipv4_addr) and IPv6
# ([Init?family=inet6] addr_type = ipv6_addr) sets inside the inet table.
# Keep dual-stack set definitions intact and drop banned packets early.
# =============================================================================

[Init]
table_family   = inet
table          = f2b-table
chain_hook     = input
chain_priority = -1
blocktype      = drop
EOF
chmod 0644 /etc/fail2ban/action.d/nftables.local

msg "nftables action override created"

# =============================================================================
# 5. ENABLE AND RESTART FAIL2BAN
# =============================================================================

msg "Enabling and starting fail2ban..."

systemctl enable fail2ban
systemctl restart fail2ban

# Wait briefly for jails to initialize
sleep 2

if systemctl is-active --quiet fail2ban; then
    msg "fail2ban is running"
else
    err "fail2ban failed to start. Check: journalctl -u fail2ban -n 50 --no-pager"
fi

# =============================================================================
# 6. JAIL STATUS SUMMARY
# =============================================================================

echo
echo -e "${C_GREEN}========================================================================${C_NC}"
echo -e "${C_GREEN} fail2ban hardening complete!${C_NC}"
echo -e "${C_GREEN}========================================================================${C_NC}"
echo

echo -e "${C_BLUE}Configuration files:${C_NC}"
echo "  Jail config:          /etc/fail2ban/jail.local"
echo "  OpenSSH 10.x filter:  /etc/fail2ban/filter.d/sshd.local"
echo "  Aggressive filter:    /etc/fail2ban/filter.d/sshd-aggressive.conf"
echo "  nftables override:    /etc/fail2ban/action.d/nftables.local"
echo

echo -e "${C_BLUE}Active jails:${C_NC}"
fail2ban-client status || warn "Could not retrieve fail2ban status"
echo

echo -e "${C_BLUE}Jail overview:${C_NC}"
echo "  sshd              - Standard SSH brute-force (3 attempts -> 24h ban)"
echo "  sshd-aggressive   - Aggressive SSH abuse (3 attempts -> 7d ban)"
echo "  nginx-http-auth   - HTTP basic auth failures (3 attempts -> 1h ban)"
echo "  nginx-botsearch   - Vulnerability scanner bots (2 attempts -> 7d ban)"
echo "  nginx-limit-req   - Rate limit violations (5 attempts -> 1h ban)"
echo "  postfix-sasl      - SMTP AUTH failures (5 attempts -> 24h ban, enabled: ${POSTFIX_JAIL_ENABLED})"
echo "  dovecot           - IMAP/POP3/Sieve login failures (5 attempts -> 24h ban, enabled: ${DOVECOT_JAIL_ENABLED})"
echo "  recidive          - Repeat offenders (3 bans -> 4 weeks, all ports)"
echo

echo -e "${C_BLUE}Never banned:${C_NC}"
echo "  127.0.0.1/8 ::1${IGNORE_LIST}"
echo

echo -e "${C_YELLOW}Useful commands:${C_NC}"
echo "  fail2ban-client status                  # List active jails"
echo "  fail2ban-client status sshd             # Show banned IPs for sshd"
echo "  fail2ban-client set sshd unbanip <IP>   # Unban a specific IP"
echo "  fail2ban-client reload                  # Reload configuration"
echo "  journalctl -u fail2ban -f               # Follow fail2ban logs"
echo "  nft list ruleset                        # View active nftables rules"
echo

echo -e "${C_GREEN}Done.${C_NC}"
