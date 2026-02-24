#!/usr/bin/env bash

# =============================================================================
# Script:      postfix.sh
# Description: Installs and configures Postfix as a send-only mail relay for
#              system notifications on Arch Linux, targeting:
#                - Send-only configuration (no inbound mail)
#                - SMTP relay through external provider (Gmail, SendGrid, etc.)
#                - TLS encryption with SASL authentication
#                - Header stripping to hide internal topology
#                - systemd service hardening
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
#
# Usage:       sudo ./postfix.sh -r RELAY_HOST [-P RELAY_PORT] [-u RELAY_USER]
#                                [-p RELAY_PASS] [-f FROM_EMAIL] [-a ALIAS_EMAIL]
#                                [-h]
#
# Requirements:
#   - Arch Linux with pacman
#   - Root privileges
#   - Valid SMTP relay credentials (for authenticated relays)
#
# What this script does:
#   1. Installs postfix and s-nail
#   2. Stops and masks sendmail if present
#   3. Configures /etc/postfix/main.cf as a send-only relay
#   4. Applies hardening directives to main.cf
#   5. Creates SASL password map (if credentials provided)
#   6. Creates header_checks to strip internal routing headers
#   7. Configures root alias forwarding (if alias provided)
#   8. Hardens the postfix systemd service
#   9. Enables and starts postfix
#  10. Sends a test email
# =============================================================================

set -euo pipefail

# --- Colors ---
readonly C_BLUE='\033[1;34m'
readonly C_RED='\033[1;31m'
readonly C_GREEN='\033[1;32m'
readonly C_YELLOW='\033[1;33m'
readonly C_NC='\033[0m'

msg()  { printf "%b[+]%b %s\n" "$C_GREEN"  "$C_NC" "$1"; }
info() { printf "%b[*]%b %s\n" "$C_BLUE"   "$C_NC" "$1"; }
warn() { printf "%b[!]%b %s\n" "$C_YELLOW" "$C_NC" "$1"; }
err()  { printf "%b[!]%b %s\n" "$C_RED"    "$C_NC" "$1" >&2; exit 1; }

# --- Defaults ---
RELAY_HOST=""
RELAY_PORT=587
RELAY_USER=""
RELAY_PASS=""
FROM_EMAIL=""
ALIAS_EMAIL=""

# --- Usage ---
usage() {
    cat <<EOF
Usage: sudo $0 [options]

Required:
  -r HOST       SMTP relay hostname (e.g., smtp.gmail.com)

Optional:
  -P PORT       SMTP relay port (default: $RELAY_PORT)
  -u USER       SMTP relay username
  -p PASS       SMTP relay password
  -f EMAIL      From email address (default: root@\$(hostname -f))
  -a EMAIL      Forward root mail to this address
  -h            Show this help

Examples:
  sudo $0 -r smtp.gmail.com -u user@gmail.com -p 'app-password'
  sudo $0 -r smtp.sendgrid.net -P 587 -u apikey -p 'SG.xxxx' -a admin@example.com
  sudo $0 -r smtp.mailgun.org -u postmaster@mg.example.com -p 'key-xxxx' -f noreply@example.com
EOF
    exit 0
}

# --- Parse Arguments ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        -r)         RELAY_HOST="$2"; shift 2 ;;
        -P)         RELAY_PORT="$2"; shift 2 ;;
        -u)         RELAY_USER="$2"; shift 2 ;;
        -p)         RELAY_PASS="$2"; shift 2 ;;
        -f)         FROM_EMAIL="$2"; shift 2 ;;
        -a)         ALIAS_EMAIL="$2"; shift 2 ;;
        -h|--help)  usage ;;
        *)          err "Unknown option: $1" ;;
    esac
done

# --- Validate ---
[[ $(id -u) -eq 0 ]] || err "Must be run as root"
[[ -n "$RELAY_HOST" ]] || err "Relay host is required (-r). Use -h for help."

if ! [[ "$RELAY_PORT" =~ ^[0-9]+$ ]] || (( RELAY_PORT < 1 || RELAY_PORT > 65535 )); then
    err "Invalid relay port: $RELAY_PORT (must be 1-65535)"
fi

# Set default FROM_EMAIL if not provided
if [[ -z "$FROM_EMAIL" ]]; then
    FROM_EMAIL="root@$(hostname -f)"
fi

info "Relay host:  $RELAY_HOST"
info "Relay port:  $RELAY_PORT"
info "From email:  $FROM_EMAIL"
[[ -n "$RELAY_USER" ]] && info "Relay user:  $RELAY_USER"
[[ -n "$ALIAS_EMAIL" ]] && info "Root alias:  $ALIAS_EMAIL"

# =============================================================================
# 1. INSTALL PACKAGES
# =============================================================================

msg "Installing postfix and s-nail..."

for pkg in postfix s-nail; do
    if pacman -Qi "$pkg" &>/dev/null; then
        info "$pkg is already installed"
    else
        pacman -S --noconfirm --needed "$pkg"
        msg "$pkg installed successfully"
    fi
done

# =============================================================================
# 2. STOP AND MASK SENDMAIL
# =============================================================================

msg "Disabling sendmail (if present)..."

if systemctl is-active sendmail &>/dev/null; then
    systemctl stop sendmail
    info "sendmail stopped"
fi

if systemctl is-enabled sendmail &>/dev/null 2>&1; then
    systemctl mask sendmail
    info "sendmail masked"
else
    info "sendmail is not enabled (nothing to mask)"
fi

# =============================================================================
# 3. CONFIGURE /etc/postfix/main.cf — SEND-ONLY RELAY
# =============================================================================

msg "Writing /etc/postfix/main.cf..."

# Back up existing main.cf if present
if [[ -f /etc/postfix/main.cf ]]; then
    BACKUP="/etc/postfix/main.cf.bak.$(date +%Y%m%d-%H%M%S)"
    cp /etc/postfix/main.cf "$BACKUP"
    info "Existing main.cf backed up to $BACKUP"
fi

MYHOSTNAME="$(hostname -f)"
MYDOMAIN="$(hostname -d 2>/dev/null || echo "localdomain")"

cat > /etc/postfix/main.cf <<EOF
# =============================================================================
# Postfix main.cf — Send-only relay configuration
# Generated by AwesomeArchLinux/hardening/postfix/postfix.sh
#
# This host does NOT accept inbound mail. It only relays outbound system
# notifications through an external SMTP provider.
# =============================================================================

# --- Identity ---
myhostname = ${MYHOSTNAME}
mydomain = ${MYDOMAIN}
myorigin = \$mydomain

# --- Send-only: listen on loopback only, no local delivery ---
inet_interfaces = loopback-only
mydestination =

# --- Relay ---
relayhost = [${RELAY_HOST}]:${RELAY_PORT}
default_transport = smtp
relay_transport = smtp

# --- TLS (encrypt all outbound mail) ---
smtp_use_tls = yes
smtp_tls_security_level = encrypt
smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt
smtp_tls_wrappermode = no
smtp_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1

# --- SASL authentication ---
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous
smtp_sasl_tls_security_options = noanonymous

# --- Header rewriting ---
smtp_header_checks = regexp:/etc/postfix/header_checks

# --- Aliases ---
alias_maps = hash:/etc/postfix/aliases
alias_database = hash:/etc/postfix/aliases

# --- Limits ---
mailbox_size_limit = 0
recipient_delimiter = +

# --- Misc ---
compatibility_level = 3.9
smtpd_banner = \$myhostname ESMTP

# --- Inbound restrictions (reject everything) ---
smtpd_relay_restrictions = permit_mynetworks, reject

# =============================================================================
# 4. HARDENING
# =============================================================================

# Disable VRFY command (user enumeration prevention)
disable_vrfy_command = yes

# Require HELO/EHLO
smtpd_helo_required = yes

# TLS logging (1 = log TLS connection summary)
smtp_tls_loglevel = 1

# Reject all external client connections
smtpd_client_restrictions = permit_mynetworks, reject

# Size limits
header_size_limit = 51200
message_size_limit = 10240000
EOF

msg "main.cf written successfully"

# =============================================================================
# 5. CREATE SASL PASSWORD FILE
# =============================================================================

if [[ -n "$RELAY_USER" && -n "$RELAY_PASS" ]]; then
    msg "Writing SASL credentials to /etc/postfix/sasl_passwd..."

    cat > /etc/postfix/sasl_passwd <<EOF
[${RELAY_HOST}]:${RELAY_PORT} ${RELAY_USER}:${RELAY_PASS}
EOF

    postmap /etc/postfix/sasl_passwd

    chmod 600 /etc/postfix/sasl_passwd
    chmod 600 /etc/postfix/sasl_passwd.db

    msg "SASL credentials configured (permissions locked to 600)"
else
    warn "No SASL credentials provided (-u / -p). Skipping sasl_passwd."
    warn "Relay will attempt unauthenticated delivery (may be rejected)."

    # Create empty sasl_passwd so postfix does not complain
    if [[ ! -f /etc/postfix/sasl_passwd ]]; then
        touch /etc/postfix/sasl_passwd
        postmap /etc/postfix/sasl_passwd
        chmod 600 /etc/postfix/sasl_passwd
        chmod 600 /etc/postfix/sasl_passwd.db
    fi
fi

# =============================================================================
# 6. CREATE HEADER CHECKS (strip internal routing)
# =============================================================================

msg "Writing /etc/postfix/header_checks..."

cat > /etc/postfix/header_checks <<'EOF'
# Strip internal Received headers to hide network topology
/^Received:.*/ IGNORE
EOF

chmod 644 /etc/postfix/header_checks

msg "header_checks created (internal Received headers will be stripped)"

# =============================================================================
# 7. CONFIGURE ALIASES
# =============================================================================

msg "Configuring /etc/postfix/aliases..."

# Back up existing aliases if present
if [[ -f /etc/postfix/aliases ]]; then
    ALIAS_BACKUP="/etc/postfix/aliases.bak.$(date +%Y%m%d-%H%M%S)"
    cp /etc/postfix/aliases "$ALIAS_BACKUP"
    info "Existing aliases backed up to $ALIAS_BACKUP"
fi

if [[ -n "$ALIAS_EMAIL" ]]; then
    cat > /etc/postfix/aliases <<EOF
# System aliases
# Generated by AwesomeArchLinux/hardening/postfix/postfix.sh
postmaster: root
root: ${ALIAS_EMAIL}
EOF
    msg "Root mail will be forwarded to $ALIAS_EMAIL"
else
    cat > /etc/postfix/aliases <<'EOF'
# System aliases
# Generated by AwesomeArchLinux/hardening/postfix/postfix.sh
postmaster: root
EOF
    info "No alias email provided (-a). Root mail stays local."
fi

postalias /etc/postfix/aliases

msg "Aliases configured"

# =============================================================================
# 8. HARDEN POSTFIX SYSTEMD SERVICE
# =============================================================================

msg "Writing systemd hardening override for postfix..."

mkdir -p /etc/systemd/system/postfix.service.d

cat > /etc/systemd/system/postfix.service.d/hardening.conf <<'EOF'
# =============================================================================
# Postfix systemd hardening override
# Generated by AwesomeArchLinux/hardening/postfix/postfix.sh
# =============================================================================

[Service]
# Filesystem protection
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

# Writable paths required by postfix
ReadWritePaths=/var/spool/postfix /var/lib/postfix /var/log/mail

# Privilege restrictions
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
EOF

systemctl daemon-reload

msg "systemd hardening override applied"

# =============================================================================
# 9. ENABLE AND START POSTFIX
# =============================================================================

msg "Enabling and starting postfix..."

systemctl enable postfix
systemctl restart postfix

# Wait briefly for postfix to initialize
sleep 2

if systemctl is-active --quiet postfix; then
    msg "postfix is running"
else
    err "postfix failed to start. Check: journalctl -u postfix -e"
fi

# =============================================================================
# 10. SEND TEST EMAIL
# =============================================================================

msg "Sending test email..."

echo "Test from $(hostname) at $(date)" | mail -s "Postfix relay test from $(hostname)" root

info "Test email queued. Check the mail queue with: mailq"

# =============================================================================
# SUMMARY
# =============================================================================

echo
echo -e "${C_GREEN}========================================================================${C_NC}"
echo -e "${C_GREEN} Postfix send-only relay configuration complete!${C_NC}"
echo -e "${C_GREEN}========================================================================${C_NC}"
echo

echo -e "${C_BLUE}Configuration files:${C_NC}"
echo "  Main config:          /etc/postfix/main.cf"
echo "  SASL credentials:     /etc/postfix/sasl_passwd"
echo "  Header checks:        /etc/postfix/header_checks"
echo "  Aliases:              /etc/postfix/aliases"
echo "  systemd hardening:    /etc/systemd/system/postfix.service.d/hardening.conf"
echo

echo -e "${C_BLUE}Relay configuration:${C_NC}"
echo "  Relay host:           [${RELAY_HOST}]:${RELAY_PORT}"
echo "  From address:         ${FROM_EMAIL}"
echo "  TLS:                  encrypt (STARTTLS on port ${RELAY_PORT})"
[[ -n "$RELAY_USER" ]] && echo "  SASL auth:            enabled ($RELAY_USER)"
[[ -n "$ALIAS_EMAIL" ]] && echo "  Root alias:           ${ALIAS_EMAIL}"
echo

echo -e "${C_BLUE}Security:${C_NC}"
echo "  Listening:            loopback-only (no inbound mail)"
echo "  Inbound policy:       reject all"
echo "  TLS protocols:        TLS 1.2+ only"
echo "  VRFY command:         disabled"
echo "  Internal headers:     stripped"
echo "  systemd hardening:    ProtectSystem=strict, NoNewPrivileges, PrivateTmp"
echo

echo -e "${C_YELLOW}Useful commands:${C_NC}"
echo "  mailq                                   # Show mail queue"
echo "  postqueue -f                            # Flush (retry) queued mail"
echo "  journalctl -u postfix -f                # Follow postfix logs"
echo "  echo 'test' | mail -s 'test' user@x.com  # Send a test email"
echo "  postconf -n                             # Show non-default postfix config"
echo "  postfix check                           # Validate configuration"
echo

echo -e "${C_GREEN}Done.${C_NC}"
