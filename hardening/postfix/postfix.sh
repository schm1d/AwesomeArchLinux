#!/usr/bin/env bash

# =============================================================================
# Script:      postfix.sh
# Description: Installs and configures a hardened mail server
#              on Arch Linux with full inbound/outbound capability:
#                - Postfix MX with postscreen, DANE, SMTP smuggling protection
#                - Dovecot IMAP with LMTP, encryption at rest, Sieve filtering
#                - OpenDKIM signing and verification (RSA 2048)
#                - rspamd for SPF/DKIM/DMARC/ARC, spam, phishing, ClamAV
#                - TLS 1.2+ with ECDHE/AEAD-only ciphers on all services
#                - Submission (587) and SMTPS (465) with header privacy
#                - systemd hardening for all services
#                - DNS record generation (SPF, DKIM, DMARC, DANE, MTA-STS, TLS-RPT)
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
#
# Usage:       sudo ./postfix.sh -d DOMAIN [-H HOSTNAME] [-s DKIM_SELECTOR]
#                                [-r RELAY_HOST] [-R RELAY_PORT] [-u RELAY_USER]
#                                [--relay-password-file FILE]
#                                [--relay-spf-include DOMAIN] [-e ADMIN_EMAIL]
#                                [--dry-run] [-h]
#
# Requirements:
#   - Arch Linux with pacman
#   - Root privileges
#   - TLS certificate at /etc/letsencrypt/live/<hostname>/ (or --dry-run)
#   - DNSSEC-validating resolver for DANE (systemd-resolved or unbound)
#   - Official Arch repositories enabled and current
#
# What this script does:
#   1.  Installs postfix, dovecot, opendkim, rspamd, Valkey, clamav, s-nail
#   2.  Stops and masks competing MTAs (sendmail, exim)
#   3.  Creates vmail user/group and mailbox directories
#   4.  Creates and validates Dovecot's global mail-encryption keypair
#   5.  Configures Postfix main.cf as a full MX with DANE, postscreen, milters
#   6.  Configures Postfix master.cf with submission (587), SMTPS (465), postscreen
#   7.  Creates header privacy rules for submission ports
#   8.  Sets up virtual mailbox mapping
#   9.  Configures optional SMTP relay with SASL credentials
#  10.  Generates DKIM keys and configures OpenDKIM
#  11.  Configures Dovecot (IMAP, LMTP, TLS, encryption at rest, Sieve)
#  12.  Configures rspamd (SPF, DKIM, DMARC, ARC, phishing, rate limiting)
#  13.  Configures ClamAV integration with rspamd
#  14.  Applies systemd hardening overrides for all services
#  15.  Adds nftables firewall rules for ports 25, 465, 587, 993
#  16.  Enables and starts all services in dependency order
#  17.  Generates DNS records (SPF, DKIM, DMARC, DANE/TLSA, MTA-STS, TLS-RPT)
#  18.  Prints summary with verification commands
# =============================================================================

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck disable=SC1091
source "$SCRIPT_DIR/../lib/nftables.sh"

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
DOMAIN=""
MAIL_HOSTNAME=""
DKIM_SELECTOR="default"
RELAY_HOST=""
RELAY_PORT=587
RELAY_USER=""
RELAY_PASS=""
RELAY_PASSWORD_FILE=""
RELAY_SPF_INCLUDE=""
ADMIN_EMAIL=""
DRY_RUN=false

# --- Cipher list (ECDHE + AEAD only) ---
readonly TLS_CIPHERS="ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"

# --- Usage ---
usage() {
    cat <<EOF
Usage: sudo $0 [options]

Required:
  -d DOMAIN       Mail domain (e.g., example.com)

Optional:
  -H HOSTNAME     Mail server hostname (default: mail.\$DOMAIN)
  -s SELECTOR     DKIM selector name (default: default)
  -r HOST         SMTP relay hostname for outbound (hybrid relay setup)
  -R PORT         SMTP relay port (default: 587)
  -u USER         SMTP relay username
  --relay-password-file FILE
                  Read the SMTP relay password from a private file
  --relay-spf-include DOMAIN
                  Provider-published SPF include domain (for example, sendgrid.net)
  -e EMAIL        Admin email address (default: postmaster@\$DOMAIN)
  --dry-run       Write configs but do not start services or require certs
  -h              Show this help

Examples:
  sudo $0 -d example.com
  sudo $0 -d example.com -H mx1.example.com -s dkim2024
  sudo $0 -d example.com -r smtp.sendgrid.net -u apikey \
    --relay-password-file /root/.smtp-relay-password \
    --relay-spf-include sendgrid.net
  sudo $0 -d example.com --dry-run
EOF
    exit 0
}

# --- Parse Arguments ---
need_arg() { [[ $# -ge 2 && -n "${2:-}" ]] || err "Option $1 requires a value"; }
while [[ $# -gt 0 ]]; do
    case "$1" in
        -d)         need_arg "$@"; DOMAIN="$2"; shift 2 ;;
        -H)         need_arg "$@"; MAIL_HOSTNAME="$2"; shift 2 ;;
        -s)         need_arg "$@"; DKIM_SELECTOR="$2"; shift 2 ;;
        -r)         need_arg "$@"; RELAY_HOST="$2"; shift 2 ;;
        -R)         need_arg "$@"; RELAY_PORT="$2"; shift 2 ;;
        -u)         need_arg "$@"; RELAY_USER="$2"; shift 2 ;;
        --relay-password-file)
                    need_arg "$@"; RELAY_PASSWORD_FILE="$2"; shift 2 ;;
        --relay-spf-include)
                    need_arg "$@"; RELAY_SPF_INCLUDE="$2"; shift 2 ;;
        -p)         err "-p is unsafe because it exposes the password in process listings and shell history; use --relay-password-file" ;;
        -e)         need_arg "$@"; ADMIN_EMAIL="$2"; shift 2 ;;
        --dry-run)  DRY_RUN=true; shift ;;
        -h|--help)  usage ;;
        *)          err "Unknown option: $1" ;;
    esac
done

# --- Validate ---
[[ $(id -u) -eq 0 ]] || err "Must be run as root"
[[ -n "$DOMAIN" ]] || err "Domain is required (-d). Use -h for help."

valid_dns_name() {
    local name="$1" label
    local -a labels

    (( ${#name} <= 253 )) || return 1
    [[ "$name" != .* && "$name" != *. && "$name" == *.* ]] || return 1
    IFS='.' read -r -a labels <<< "$name"
    for label in "${labels[@]}"; do
        (( ${#label} >= 1 && ${#label} <= 63 )) || return 1
        [[ "$label" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]] || return 1
    done
}

valid_email() {
    local address="$1" local_part domain_part

    [[ "$address" == *@* && "$address" != *@*@* ]] || return 1
    local_part="${address%@*}"
    domain_part="${address##*@}"
    (( ${#local_part} >= 1 && ${#local_part} <= 64 )) || return 1
    [[ "$local_part" =~ ^[A-Za-z0-9_%+-]+([.][A-Za-z0-9_%+-]+)*$ ]] || return 1
    valid_dns_name "$domain_part"
}

valid_dns_name "$DOMAIN" || err "Invalid mail domain: $DOMAIN"
[[ "$DKIM_SELECTOR" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$ ]] || \
    err "Invalid DKIM selector: $DKIM_SELECTOR"

# Derive defaults
MAIL_HOSTNAME="${MAIL_HOSTNAME:-mail.$DOMAIN}"
ADMIN_EMAIL="${ADMIN_EMAIL:-postmaster@$DOMAIN}"

valid_dns_name "$MAIL_HOSTNAME" || err "Invalid mail hostname: $MAIL_HOSTNAME"
valid_email "$ADMIN_EMAIL" || err "Invalid admin email address: $ADMIN_EMAIL"

if [[ -n "$RELAY_HOST" ]]; then
    valid_dns_name "$RELAY_HOST" || err "Invalid relay hostname: $RELAY_HOST"
    [[ "$RELAY_PORT" =~ ^[0-9]+$ ]] && (( RELAY_PORT >= 1 && RELAY_PORT <= 65535 )) || \
        err "Invalid relay port: $RELAY_PORT (must be 1-65535)"
fi

if [[ -n "$RELAY_SPF_INCLUDE" ]]; then
    [[ -n "$RELAY_HOST" ]] || err "An SPF include domain requires -r HOST"
    valid_dns_name "$RELAY_SPF_INCLUDE" || \
        err "Invalid relay SPF include domain: $RELAY_SPF_INCLUDE"
fi

if [[ -n "$RELAY_USER" ]]; then
    [[ -n "$RELAY_HOST" ]] || err "A relay username requires -r HOST"
    [[ "$RELAY_USER" != *:* && "$RELAY_USER" != *[[:space:]]* ]] || \
        err "Relay username must not contain a colon or whitespace"
fi

if [[ -n "$RELAY_PASSWORD_FILE" ]]; then
    [[ -n "$RELAY_HOST" ]] || err "A relay password file requires -r HOST"
    [[ -f "$RELAY_PASSWORD_FILE" && ! -L "$RELAY_PASSWORD_FILE" && -r "$RELAY_PASSWORD_FILE" ]] || \
        err "Relay password file must be a readable regular file, not a symlink: $RELAY_PASSWORD_FILE"
    PASSWORD_FILE_MODE=$(stat -c '%a' -- "$RELAY_PASSWORD_FILE") || \
        err "Could not read -r relay password file mode"
    (( (8#$PASSWORD_FILE_MODE & 8#077) == 0 )) || \
        err "Relay password file must not be accessible by group or others: $RELAY_PASSWORD_FILE"
    mapfile -t RELAY_PASSWORD_LINES < "$RELAY_PASSWORD_FILE"
    (( ${#RELAY_PASSWORD_LINES[@]} == 1 )) && [[ -n "${RELAY_PASSWORD_LINES[0]}" ]] || \
        err "Relay password file must contain exactly one non-empty line"
    RELAY_PASS="${RELAY_PASSWORD_LINES[0]}"
    [[ "$RELAY_PASS" =~ ^[[:graph:]]+$ ]] || \
        err "Relay password must contain printable non-whitespace characters only"
    unset RELAY_PASSWORD_LINES PASSWORD_FILE_MODE
fi

if [[ -n "$RELAY_USER" || -n "$RELAY_PASS" ]]; then
    [[ -n "$RELAY_USER" && -n "$RELAY_PASS" ]] || \
        err "Authenticated relay mode requires both -u USER and --relay-password-file FILE"
fi

readonly DOMAIN MAIL_HOSTNAME DKIM_SELECTOR ADMIN_EMAIL DRY_RUN
readonly RELAY_HOST RELAY_PORT RELAY_USER RELAY_PASSWORD_FILE RELAY_SPF_INCLUDE
readonly CERT_DIR="/etc/letsencrypt/live/$MAIL_HOSTNAME"
readonly VMAIL_UID=5000
readonly VMAIL_GID=5000
readonly MAIL_DIR="/var/mail/vdomains"

# Check the certificate identity and key before changing mail services. Merely
# checking for path existence can accept a certificate for the wrong host or a
# mismatched private key, leaving submission/IMAP unavailable after restart.
if [[ "$DRY_RUN" == false ]]; then
    if [[ ! -f "$CERT_DIR/fullchain.pem" || ! -f "$CERT_DIR/privkey.pem" ]]; then
        err "TLS certificate not found at $CERT_DIR/. Run certbot first or use --dry-run."
    fi
    command -v openssl &>/dev/null || err "openssl is required to validate the TLS certificate"
    openssl x509 -in "$CERT_DIR/fullchain.pem" -noout -checkhost "$MAIL_HOSTNAME" &>/dev/null || \
        err "TLS certificate does not cover $MAIL_HOSTNAME"
    CERT_PUBLIC_KEY=$(openssl x509 -in "$CERT_DIR/fullchain.pem" -noout -pubkey | \
        openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}') || \
        err "Could not read -r the TLS certificate public key"
    PRIVATE_PUBLIC_KEY=$(openssl pkey -in "$CERT_DIR/privkey.pem" -pubout -outform DER 2>/dev/null | \
        sha256sum | awk '{print $1}') || err "Could not read -r the TLS private key"
    [[ -n "$CERT_PUBLIC_KEY" && "$CERT_PUBLIC_KEY" == "$PRIVATE_PUBLIC_KEY" ]] || \
        err "TLS certificate and private key do not match"
    PRIVATE_KEY_MODE=$(stat -Lc '%a' -- "$CERT_DIR/privkey.pem") || \
        err "Could not inspect TLS private key permissions"
    (( (8#$PRIVATE_KEY_MODE & 8#077) == 0 )) || \
        err "TLS private key must not be accessible by group or others"
    PRIVATE_KEY_OWNER=$(stat -Lc '%u' -- "$CERT_DIR/privkey.pem") || \
        err "Could not inspect TLS private key ownership"
    [[ "$PRIVATE_KEY_OWNER" == 0 ]] || err "TLS private key must be owned by root"
    unset CERT_PUBLIC_KEY PRIVATE_PUBLIC_KEY PRIVATE_KEY_MODE PRIVATE_KEY_OWNER
else
    warn "Dry-run mode: skipping certificate checks and service starts"
fi

info "Domain:        $DOMAIN"
info "Hostname:      $MAIL_HOSTNAME"
info "DKIM selector: $DKIM_SELECTOR"
info "Admin email:   $ADMIN_EMAIL"
[[ -n "$RELAY_HOST" ]] && info "Relay host:    [$RELAY_HOST]:$RELAY_PORT"

# --- Helper: backup a file before overwriting ---
backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        local bak
        bak="${file}.bak.$(date +%Y%m%d-%H%M%S)"
        cp "$file" "$bak"
        info "Backed up $file → $bak"
    fi
}

# =============================================================================
# 1. INSTALL PACKAGES
# =============================================================================

msg "Installing packages..."

# All dependencies are signed packages from the official Arch repositories.
# Do not reintroduce an AUR fallback here: a mail installer must not execute
# third-party PKGBUILDs with a path to host-root package management. Refresh
# and upgrade together because Arch does not support partial upgrades.
pacman -Syu --noconfirm --needed \
    postfix postfix-lmdb dovecot valkey clamav s-nail pigeonhole rspamd opendkim perl

command -v opendkim-genkey &>/dev/null || \
    err "The signed opendkim package did not provide opendkim-genkey"
command -v rspamd &>/dev/null || err "The signed rspamd package did not provide rspamd"
postconf -m | grep -qxF lmdb || err "Postfix LMDB map support is unavailable"
POSTFIX_VERSION=$(postconf -d -h mail_version)
[[ "$POSTFIX_VERSION" =~ ^([0-9]+[.][0-9]+) ]] || \
    err "Could not determine the packaged Postfix version"
POSTFIX_COMPATIBILITY_LEVEL="${BASH_REMATCH[1]}"
readonly POSTFIX_COMPATIBILITY_LEVEL
unset POSTFIX_VERSION

# =============================================================================
# 2. STOP AND MASK COMPETING MTAs
# =============================================================================

msg "Disabling competing MTAs..."

for mta in sendmail exim; do
    if systemctl is-active "$mta" &>/dev/null; then
        systemctl stop "$mta"
        info "$mta stopped"
    fi
    if systemctl is-enabled "$mta" &>/dev/null 2>&1; then
        systemctl mask "$mta"
        info "$mta masked"
    fi
done

# Stop postfix for reconfiguration
systemctl stop postfix &>/dev/null || true

# =============================================================================
# 3. CREATE SYSTEM USERS AND DIRECTORIES
# =============================================================================

msg "Setting up vmail user and mail directories..."

if ! getent group vmail &>/dev/null; then
    groupadd -g "$VMAIL_GID" vmail
    info "Created vmail group (GID $VMAIL_GID)"
fi

if ! getent passwd vmail &>/dev/null; then
    useradd -r -u "$VMAIL_UID" -g vmail -d "$MAIL_DIR" -s /usr/bin/nologin -c "Virtual mail" vmail
    info "Created vmail user (UID $VMAIL_UID)"
fi

mkdir -p "$MAIL_DIR/$DOMAIN"
# Dovecot sieve directory
mkdir -p "$MAIL_DIR/sieve-before"

# Ownership: everything under MAIL_DIR belongs to vmail.
chown -R vmail:vmail "$MAIL_DIR"
# Permissions: set mode on directories only; leave existing mail files
# (Maildir uses 0600) untouched. A blanket `chmod -R 770` would make every
# stored message group-writable and executable.
chmod 0770 "$MAIL_DIR"
find "$MAIL_DIR" -type d -exec chmod 0770 {} +

# OpenDKIM directories
mkdir -p /etc/opendkim/keys/"$DOMAIN"
mkdir -p /run/opendkim
# Keep the milter socket inside Postfix's private queue directory. The
# opendkim service runs with postfix as its primary group, so it can create a
# group-restricted socket without exposing a signing endpoint to other users.
install -d -o postfix -g postfix -m 0770 /var/spool/postfix/private

# Ensure postfix can access opendkim socket
if getent group opendkim &>/dev/null; then
    chown opendkim:postfix /run/opendkim
    chmod 750 /run/opendkim
fi

# tmpfiles.d for opendkim runtime directory (survives reboot)
cat > /etc/tmpfiles.d/opendkim.conf <<'EOF'
d /run/opendkim 0750 opendkim postfix -
EOF

msg "Mail directories created"

# =============================================================================
# 4. DOVECOT MAIL-ENCRYPTION KEYS
# =============================================================================

msg "Configuring Dovecot mail-encryption keys..."

readonly MAIL_CRYPT_PRIVATE_KEY="/etc/dovecot/mail-crypt.key"
readonly MAIL_CRYPT_PUBLIC_KEY="/etc/dovecot/mail-crypt.pub"

if [[ -f "$MAIL_CRYPT_PRIVATE_KEY" ]]; then
    openssl pkey -in "$MAIL_CRYPT_PRIVATE_KEY" -check -noout &>/dev/null || \
        err "Existing Dovecot mail-encryption private key is invalid"
    if [[ -f "$MAIL_CRYPT_PUBLIC_KEY" ]]; then
        MAIL_CRYPT_PRIVATE_HASH=$(openssl pkey -in "$MAIL_CRYPT_PRIVATE_KEY" -pubout -outform DER 2>/dev/null | \
            sha256sum | awk '{print $1}')
        MAIL_CRYPT_PUBLIC_HASH=$(openssl pkey -pubin -in "$MAIL_CRYPT_PUBLIC_KEY" -outform DER 2>/dev/null | \
            sha256sum | awk '{print $1}')
        [[ -n "$MAIL_CRYPT_PRIVATE_HASH" && "$MAIL_CRYPT_PRIVATE_HASH" == "$MAIL_CRYPT_PUBLIC_HASH" ]] || \
            err "Existing Dovecot mail-encryption public and private keys do not match"
        unset MAIL_CRYPT_PRIVATE_HASH MAIL_CRYPT_PUBLIC_HASH
    else
        if ! (
            umask 077 &&
            mail_crypt_public_tmp=$(mktemp /etc/dovecot/.mail-crypt.pub.XXXXXX) &&
            trap 'rm -f -- "$mail_crypt_public_tmp"' EXIT &&
            openssl pkey -in "$MAIL_CRYPT_PRIVATE_KEY" -pubout -out "$mail_crypt_public_tmp" &&
            install -o root -g root -m 0644 "$mail_crypt_public_tmp" "$MAIL_CRYPT_PUBLIC_KEY"
        ); then
            err "Could not derive the Dovecot mail-encryption public key"
        fi
    fi
    chown root:vmail "$MAIL_CRYPT_PRIVATE_KEY"
    chmod 0640 "$MAIL_CRYPT_PRIVATE_KEY"
    chown root:root "$MAIL_CRYPT_PUBLIC_KEY"
    chmod 0644 "$MAIL_CRYPT_PUBLIC_KEY"
elif [[ -e "$MAIL_CRYPT_PUBLIC_KEY" ]]; then
    err "Dovecot mail-encryption public key exists without its private key; restore the private key from backup"
else
    EXISTING_MAIL=$(find "$MAIL_DIR" -type f \( -path '*/cur/*' -o -path '*/new/*' \) -print -quit)
    if [[ -n "$EXISTING_MAIL" ]]; then
        err "Existing mail was found without a managed encryption key; migrate or back it up before enabling global mail encryption"
    fi
    unset EXISTING_MAIL
    if ! (
        umask 077 &&
        mail_crypt_private_tmp=$(mktemp /etc/dovecot/.mail-crypt.key.XXXXXX) &&
        trap 'rm -f -- "$mail_crypt_private_tmp"; if [[ -n "${mail_crypt_public_tmp:-}" ]]; then rm -f -- "$mail_crypt_public_tmp"; fi' EXIT &&
        mail_crypt_public_tmp=$(mktemp /etc/dovecot/.mail-crypt.pub.XXXXXX) &&
        openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 \
            -out "$mail_crypt_private_tmp" &&
        openssl pkey -in "$mail_crypt_private_tmp" -pubout -out "$mail_crypt_public_tmp" &&
        install -o root -g vmail -m 0640 "$mail_crypt_private_tmp" "$MAIL_CRYPT_PRIVATE_KEY" &&
        install -o root -g root -m 0644 "$mail_crypt_public_tmp" "$MAIL_CRYPT_PUBLIC_KEY"
    ); then
        err "Could not generate Dovecot mail-encryption keys"
    fi
    warn "Back up $MAIL_CRYPT_PRIVATE_KEY now; losing it makes encrypted mail unrecoverable."
fi

msg "Dovecot global EC mail encryption is ready"

# =============================================================================
# 5. POSTFIX main.cf
# =============================================================================

msg "Writing /etc/postfix/main.cf..."
backup_file /etc/postfix/main.cf

cat > /etc/postfix/main.cf <<EOF
# =============================================================================
# Postfix main.cf — hardened MX server
# Generated by AwesomeArchLinux/hardening/postfix/postfix.sh
# =============================================================================

# --- Identity ---
myhostname = ${MAIL_HOSTNAME}
mydomain = ${DOMAIN}
myorigin = \$mydomain
mydestination = \$myhostname, localhost.\$mydomain, localhost

# --- Network ---
inet_interfaces = all
inet_protocols = all
# Explicit mynetworks: don't rely on mynetworks_style=subnet, which would
# grant permit_mynetworks to the whole LAN subnet the server sits on.
mynetworks = 127.0.0.0/8 [::1]/128

# --- Virtual mailbox ---
virtual_mailbox_domains = ${DOMAIN}
virtual_mailbox_base = ${MAIL_DIR}
virtual_mailbox_maps = lmdb:/etc/postfix/vmailbox
virtual_minimum_uid = 1000
virtual_uid_maps = static:${VMAIL_UID}
virtual_gid_maps = static:${VMAIL_GID}
virtual_transport = lmtp:unix:private/dovecot-lmtp

# --- TLS inbound (smtpd) ---
smtpd_tls_cert_file = ${CERT_DIR}/fullchain.pem
smtpd_tls_key_file = ${CERT_DIR}/privkey.pem
smtpd_tls_security_level = may
smtpd_tls_auth_only = yes
smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtpd_tls_mandatory_ciphers = high
smtpd_tls_mandatory_exclude_ciphers = aNULL, MD5, DES, 3DES, RC4, eNULL
smtpd_tls_exclude_ciphers = aNULL, MD5, DES, 3DES, RC4, eNULL
tls_high_cipherlist = ${TLS_CIPHERS}
smtpd_tls_loglevel = 1

# --- TLS outbound (smtp) — DANE when usable TLSA records exist ---
smtp_tls_security_level = dane
smtp_dns_support_level = dnssec
smtp_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtp_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtp_tls_mandatory_ciphers = high
smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt
smtp_tls_loglevel = 1

# --- SMTP smuggling protection (CVE-2023-51764) ---
smtpd_forbid_bare_newline = normalize
smtpd_forbid_bare_newline_exclusions = \$mynetworks

# --- Postscreen (connection-level screening) ---
postscreen_access_list = permit_mynetworks
postscreen_dnsbl_sites = zen.spamhaus.org*3, bl.spamcop.net*2, b.barracudacentral.org*2
postscreen_dnsbl_threshold = 3
postscreen_dnsbl_action = enforce
postscreen_greet_action = enforce
postscreen_pipelining_enable = yes
postscreen_non_smtp_command_enable = yes
postscreen_bare_newline_enable = yes

# --- Milter integration (OpenDKIM + rspamd) ---
# Temporary failure keeps mail queued/retriable if a security filter is down;
# accepting would silently bypass DKIM signing and spam/virus inspection.
milter_default_action = tempfail
milter_protocol = 6
smtpd_milters = unix:private/opendkim.sock, inet:127.0.0.1:11332
non_smtpd_milters = unix:private/opendkim.sock, inet:127.0.0.1:11332

# --- SASL authentication (via Dovecot) ---
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = yes

# --- Restrictions (strict, ordered) ---
smtpd_helo_required = yes
smtpd_helo_restrictions = permit_mynetworks, reject_invalid_helo_hostname, reject_non_fqdn_helo_hostname, reject_unknown_helo_hostname
smtpd_sender_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_non_fqdn_sender, reject_unknown_sender_domain
smtpd_recipient_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination, reject_non_fqdn_recipient, reject_unknown_recipient_domain
smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination
smtpd_data_restrictions = reject_unauth_pipelining

# --- Rate limiting ---
smtpd_client_connection_rate_limit = 10
smtpd_client_message_rate_limit = 30
smtpd_client_recipient_rate_limit = 50
anvil_rate_time_unit = 60s

# --- Misc ---
compatibility_level = ${POSTFIX_COMPATIBILITY_LEVEL}
smtpd_banner = \$myhostname ESMTP
disable_vrfy_command = yes
message_size_limit = 26214400
mailbox_size_limit = 0
recipient_delimiter = +
biff = no
append_dot_mydomain = no

# --- Aliases ---
alias_maps = lmdb:/etc/postfix/aliases
alias_database = lmdb:/etc/postfix/aliases
EOF

# Append relay config if specified
if [[ -n "$RELAY_HOST" ]]; then
    cat >> /etc/postfix/main.cf <<EOF

# --- Outbound relay (hybrid setup) ---
relayhost = [${RELAY_HOST}]:${RELAY_PORT}
EOF
    if [[ -n "$RELAY_USER" && -n "$RELAY_PASS" ]]; then
        cat >> /etc/postfix/main.cf <<'EOF'
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = lmdb:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous
smtp_sasl_tls_security_options = noanonymous
EOF
    fi
fi

msg "main.cf written"

# =============================================================================
# 6. POSTFIX master.cf
# =============================================================================

msg "Writing /etc/postfix/master.cf..."
backup_file /etc/postfix/master.cf

cat > /etc/postfix/master.cf <<'EOF'
# =============================================================================
# Postfix master.cf — hardened service definitions
# Generated by AwesomeArchLinux/hardening/postfix/postfix.sh
# =============================================================================

# --- Postscreen on port 25 (MX traffic) ---
smtp      inet  n       -       n       -       1       postscreen
smtpd     pass  -       -       n       -       -       smtpd
dnsblog   unix  -       -       n       -       0       dnsblog
tlsproxy  unix  -       -       n       -       0       tlsproxy

# --- Submission (587) — authenticated users, STARTTLS ---
submission inet n       -       n       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_tls_auth_only=yes
  -o smtpd_reject_unlisted_recipient=no
  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING
  -o smtpd_client_restrictions=
  -o smtpd_helo_restrictions=
  -o smtpd_sender_restrictions=
  -o cleanup_service_name=header_cleanup

# --- SMTPS (465) — authenticated users, implicit TLS (RFC 8314) ---
smtps     inet  n       -       n       -       -       smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_tls_auth_only=yes
  -o smtpd_reject_unlisted_recipient=no
  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING
  -o smtpd_client_restrictions=
  -o smtpd_helo_restrictions=
  -o smtpd_sender_restrictions=
  -o cleanup_service_name=header_cleanup

# --- Header cleanup (strips headers on submission/smtps only) ---
header_cleanup unix n   -       n       -       0       cleanup
  -o header_checks=regexp:/etc/postfix/header_checks_submission

# --- Standard services ---
pickup    unix  n       -       n       60      1       pickup
cleanup   unix  n       -       n       -       0       cleanup
qmgr      unix  n       -       n       300     1       qmgr
rewrite   unix  -       -       n       -       -       trivial-rewrite
bounce    unix  -       -       n       -       0       bounce
defer     unix  -       -       n       -       0       bounce
trace     unix  -       -       n       -       0       bounce
verify    unix  -       -       n       -       1       verify
flush     unix  n       -       n       1000?   0       flush
proxymap  unix  -       -       n       -       -       proxymap
proxywrite unix -       -       n       -       1       proxymap
smtp      unix  -       -       n       -       -       smtp
relay     unix  -       -       n       -       -       smtp
  -o syslog_name=postfix/$service_name
showq     unix  n       -       n       -       -       showq
error     unix  -       -       n       -       -       error
retry     unix  -       -       n       -       -       error
discard   unix  -       -       n       -       -       discard
local     unix  -       n       n       -       -       local
virtual   unix  -       n       n       -       -       virtual
lmtp      unix  -       -       n       -       -       lmtp
anvil     unix  -       -       n       -       1       anvil
scache    unix  -       -       n       -       1       scache
postlog   unix-dgram n  -       n       -       1       postlogd
EOF

msg "master.cf written"

# =============================================================================
# 7. HEADER PRIVACY
# =============================================================================

msg "Writing header check rules..."

# Inbound header checks (minimal)
cat > /etc/postfix/header_checks <<'EOF'
# Minimal inbound header checks — do not strip Received on inbound
# (needed for DKIM verification and spam analysis)
EOF
chmod 644 /etc/postfix/header_checks

# Submission header checks (aggressive privacy — ProtonMail-style)
cat > /etc/postfix/header_checks_submission <<'EOF'
# Strip internal headers from outbound submission/smtps mail
# Matches ProtonMail's header privacy: hide sender IP and client info
/^Received:/            IGNORE
/^X-Mailer:/            IGNORE
/^User-Agent:/          IGNORE
/^X-Originating-IP:/    IGNORE
EOF
chmod 644 /etc/postfix/header_checks_submission

msg "Header checks created (submission traffic gets headers stripped)"

# =============================================================================
# 8. VIRTUAL MAILBOX MAP
# =============================================================================

msg "Writing /etc/postfix/vmailbox..."

# Create initial mailboxes
cat > /etc/postfix/vmailbox <<EOF
postmaster@${DOMAIN}    ${DOMAIN}/postmaster/Maildir/
EOF
ADMIN_EMAIL_DOMAIN="${ADMIN_EMAIL##*@}"
if [[ "$ADMIN_EMAIL_DOMAIN" == "$DOMAIN" && "$ADMIN_EMAIL" != "postmaster@$DOMAIN" ]]; then
    printf '%s    %s/%s/Maildir/\n' \
        "$ADMIN_EMAIL" "$DOMAIN" "${ADMIN_EMAIL%@*}" >> /etc/postfix/vmailbox
fi
unset ADMIN_EMAIL_DOMAIN

postmap lmdb:/etc/postfix/vmailbox
chown root:root /etc/postfix/vmailbox /etc/postfix/vmailbox.lmdb
chmod 0644 /etc/postfix/vmailbox /etc/postfix/vmailbox.lmdb

msg "Virtual mailbox map created"

# =============================================================================
# 9. SASL PASSWORD (optional relay)
# =============================================================================

if [[ -n "$RELAY_HOST" && -n "$RELAY_USER" && -n "$RELAY_PASS" ]]; then
    msg "Writing SASL relay credentials..."

    sasl_password_tmp=$(umask 077; mktemp /etc/postfix/.sasl_passwd.XXXXXX) || \
        err "Could not create a temporary Postfix relay credential file"
    cleanup_sasl_password_tmp() {
        rm -f -- "$sasl_password_tmp" "${sasl_password_tmp}.lmdb"
    }
    trap cleanup_sasl_password_tmp EXIT
    if ! printf '[%s]:%s %s:%s\n' \
        "$RELAY_HOST" "$RELAY_PORT" "$RELAY_USER" "$RELAY_PASS" > "$sasl_password_tmp"; then
        err "Could not write the temporary Postfix relay credential file"
    fi
    postmap "lmdb:$sasl_password_tmp" || err "Could not compile the Postfix relay credential map"
    # Install the runtime database first so a failure never pairs a new
    # plaintext source file with stale compiled credentials.
    install -o root -g root -m 0600 \
        "${sasl_password_tmp}.lmdb" /etc/postfix/sasl_passwd.lmdb || \
        err "Could not install the Postfix relay credential database"
    install -o root -g root -m 0600 \
        "$sasl_password_tmp" /etc/postfix/sasl_passwd || \
        err "Could not install the Postfix relay credential source"
    # Remove the legacy hash map if this host was configured by an older
    # version of the installer; Postfix now reads only the LMDB map.
    rm -f /etc/postfix/sasl_passwd.db
    cleanup_sasl_password_tmp
    trap - EXIT
    unset -f cleanup_sasl_password_tmp
    unset sasl_password_tmp
    unset RELAY_PASS
    msg "SASL relay credentials configured"
else
    # The generated main.cf no longer references a credential map. Do not
    # retain a password from an earlier authenticated-relay configuration.
    rm -f /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.lmdb \
        /etc/postfix/sasl_passwd.db
    if [[ -n "$RELAY_HOST" ]]; then
        warn "Relay host set without credentials; this is valid only for an IP-authorized relay."
    fi
fi

# =============================================================================
# 10. ALIASES
# =============================================================================

msg "Configuring /etc/postfix/aliases..."
backup_file /etc/postfix/aliases

cat > /etc/postfix/aliases <<EOF
# System aliases
# Generated by AwesomeArchLinux/hardening/postfix/postfix.sh
postmaster: root
root: ${ADMIN_EMAIL}
EOF

postalias lmdb:/etc/postfix/aliases
chown root:root /etc/postfix/aliases /etc/postfix/aliases.lmdb
chmod 0644 /etc/postfix/aliases /etc/postfix/aliases.lmdb
msg "Aliases configured (root → $ADMIN_EMAIL)"

# =============================================================================
# 11. OPENDKIM
# =============================================================================

msg "Configuring OpenDKIM..."

if ! command -v opendkim-genkey &>/dev/null; then
    err "The signed opendkim package installed without opendkim-genkey; refusing a mail setup without DKIM"
else
    DKIM_CONFIGURED=true

    DKIM_KEY_DIR="/etc/opendkim/keys/$DOMAIN"

    # Generate RSA 2048 key if not present
    if [[ ! -f "$DKIM_KEY_DIR/$DKIM_SELECTOR.private" ]]; then
        opendkim-genkey -b 2048 -d "$DOMAIN" -D "$DKIM_KEY_DIR" -s "$DKIM_SELECTOR" -v
        chown -R opendkim:opendkim /etc/opendkim
        msg "DKIM key generated ($DKIM_SELECTOR, RSA 2048)"
    else
        info "DKIM key already exists, skipping generation"
    fi

    # opendkim.conf
    backup_file /etc/opendkim/opendkim.conf
    cat > /etc/opendkim/opendkim.conf <<EOF
# =============================================================================
# OpenDKIM configuration
# Generated by AwesomeArchLinux/hardening/postfix/postfix.sh
# =============================================================================

Syslog              yes
SyslogSuccess       yes
LogWhy              yes

# Sign and verify mode
Mode                sv

Canonicalization    relaxed/simple
Domain              ${DOMAIN}

KeyTable            /etc/opendkim/KeyTable
SigningTable        refile:/etc/opendkim/SigningTable
ExternalIgnoreList  /etc/opendkim/TrustedHosts
InternalHosts       /etc/opendkim/TrustedHosts

Socket              local:/var/spool/postfix/private/opendkim.sock
PidFile             /run/opendkim/opendkim.pid
UMask               007
# Match the systemd service's primary group so the 0660 milter socket is
# reachable by Postfix without making it world-accessible.
UserID              opendkim:postfix

# Prevent header injection attacks (ProtonMail oversigns From)
OversignHeaders     From
EOF

    # KeyTable
    cat > /etc/opendkim/KeyTable <<EOF
${DKIM_SELECTOR}._domainkey.${DOMAIN} ${DOMAIN}:${DKIM_SELECTOR}:${DKIM_KEY_DIR}/${DKIM_SELECTOR}.private
EOF

    # SigningTable
    cat > /etc/opendkim/SigningTable <<EOF
*@${DOMAIN} ${DKIM_SELECTOR}._domainkey.${DOMAIN}
EOF

    # TrustedHosts
    cat > /etc/opendkim/TrustedHosts <<'EOF'
127.0.0.1
::1
localhost
EOF
    echo "$MAIL_HOSTNAME" >> /etc/opendkim/TrustedHosts

    chown -R opendkim:opendkim /etc/opendkim
    chmod 600 "$DKIM_KEY_DIR/$DKIM_SELECTOR.private"
    opendkim -n -x /etc/opendkim/opendkim.conf || \
        err "Generated OpenDKIM configuration is invalid"

    msg "OpenDKIM configured"
fi

# =============================================================================
# 12. DOVECOT
# =============================================================================

msg "Configuring Dovecot..."

# Dovecot 2.4 deliberately rejects 2.3-era settings. Keep a single complete
# configuration so package-provided snippets cannot silently re-enable a
# plaintext listener or a different authentication backend.
backup_file /etc/dovecot/dovecot.conf
cat > /etc/dovecot/dovecot.conf <<EOF
# =============================================================================
# Dovecot 2.4 configuration — TLS-only IMAP, LMTP, Sieve, mail encryption
# Generated by AwesomeArchLinux/hardening/postfix/postfix.sh
# =============================================================================

dovecot_config_version = 2.4.0
dovecot_storage_version = 2.4.0

protocols {
  imap = yes
  lmtp = yes
}
listen = *, ::
login_greeting = Dovecot ready.

# PLAIN/LOGIN are permitted only inside TLS.
auth_allow_cleartext = no
auth_mechanisms = plain login

# Maildir storage under a single unprivileged vmail account.
mail_home = ${MAIL_DIR}/%{user | domain}/%{user | username}
mail_driver = maildir
mail_path = ~/Maildir
mail_uid = ${VMAIL_UID}
mail_gid = ${VMAIL_GID}
first_valid_uid = ${VMAIL_UID}
last_valid_uid = ${VMAIL_UID}

namespace inbox {
  inbox = yes
  separator = /
}

# Encrypt every newly written message with the managed global EC keypair.
mail_plugins {
  mail_crypt = yes
}
crypt_global_public_key_file = ${MAIL_CRYPT_PUBLIC_KEY}
crypt_global_private_key main {
  crypt_private_key_file = ${MAIL_CRYPT_PRIVATE_KEY}
}

# TLS-only IMAP. TLS 1.3 suites remain restricted to AEAD algorithms.
ssl = required
ssl_min_protocol = TLSv1.2
ssl_cipher_list = ${TLS_CIPHERS}
ssl_cipher_suites = TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256
ssl_server {
  cert_file = ${CERT_DIR}/fullchain.pem
  key_file = ${CERT_DIR}/privkey.pem
  prefer_ciphers = server
}

# The passwd-file is the source of truth for login and LMTP recipient checks.
passdb passwd-file {
  default_password_scheme = BLF-CRYPT
  passwd_file_path = /etc/dovecot/users
}
userdb static {
  fields {
    uid = ${VMAIL_UID}
    gid = ${VMAIL_GID}
    home = ${MAIL_DIR}/%{user | domain}/%{user | username}
  }
}

# LMTP delivery socket (inside Postfix chroot)
service lmtp {
  unix_listener /var/spool/postfix/private/dovecot-lmtp {
    group = postfix
    mode = 0600
    user = postfix
  }
}

# SASL auth socket for Postfix
service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}

# Disable unencrypted IMAP (143); expose implicit-TLS IMAP only.
service imap-login {
  inet_listener imap {
    port = 0
  }
  inet_listener imaps {
    port = 993
    ssl = yes
  }
}

protocol lmtp {
  mail_plugins {
    sieve = yes
  }
  postmaster_address = postmaster@${DOMAIN}
}
protocol imap {
  mail_max_userip_connections = 20
}

# Personal Sieve scripts and a mandatory administrator script that files spam.
sieve_script personal {
  type = personal
  path = ~/sieve
  active_path = ~/.dovecot.sieve
}
sieve_script spam-before {
  type = before
  path = ${MAIL_DIR}/sieve-before/spam-to-junk.sieve
}
EOF

# Global sieve script: move spam to Junk
cat > "$MAIL_DIR/sieve-before/spam-to-junk.sieve" <<'EOF'
require ["fileinto", "mailbox"];
if header :contains "X-Spam" "Yes" {
  fileinto :create "Junk";
  stop;
}
EOF
chown vmail:vmail "$MAIL_DIR/sieve-before/spam-to-junk.sieve"

# Compile the script against the generated Dovecot configuration. A failure is
# fatal because silently skipping it changes mail-delivery behavior.
sievec "$MAIL_DIR/sieve-before/spam-to-junk.sieve"
chown vmail:vmail "$MAIL_DIR/sieve-before/spam-to-junk.svbin"

# Create empty users file if not present
if [[ ! -f /etc/dovecot/users ]]; then
    touch /etc/dovecot/users
    warn "Dovecot users file created empty. Add users with:"
    warn "  doveadm pw -s BLF-CRYPT | xargs -I{} echo 'user@$DOMAIN:{}' >> /etc/dovecot/users"
fi
chmod 0600 /etc/dovecot/users
chown root:root /etc/dovecot/users

doveconf -n &>/dev/null || err "Generated Dovecot 2.4 configuration is invalid"

msg "Dovecot configured"

# =============================================================================
# 13. RSPAMD
# =============================================================================

msg "Configuring rspamd..."

if ! command -v rspamd &>/dev/null; then
    warn "rspamd not installed — skipping rspamd configuration"
else
    mkdir -p /etc/rspamd/local.d

    # Worker proxy (milter mode for Postfix)
    cat > /etc/rspamd/local.d/worker-proxy.inc <<'EOF'
bind_socket = "127.0.0.1:11332";
milter = yes;
timeout = 120s;
upstream "local" {
  default = yes;
  self_scan = yes;
}
EOF

    # The packaged 8-second task timeout is shorter than ARC plus the other
    # enabled checks; allow checks to finish instead of silently terminating.
    cat > /etc/rspamd/local.d/options.inc <<'EOF'
task_timeout = 30s;
EOF

    # Actions (scoring thresholds)
    cat > /etc/rspamd/local.d/actions.conf <<'EOF'
reject = 15;
add_header = 6;
greylist = 4;
EOF

    # Milter headers
    cat > /etc/rspamd/local.d/milter_headers.conf <<'EOF'
use = ["x-spam-status", "spam-header", "authentication-results"];
routines {
  spam-header {
    header = "X-Spam";
    value = "Yes";
    remove = 0;
  }
}
EOF

    # Valkey backend (Rspamd retains the redis.conf/module name)
    cat > /etc/rspamd/local.d/redis.conf <<'EOF'
servers = "127.0.0.1";
EOF

    # SPF
    cat > /etc/rspamd/local.d/spf.conf <<'EOF'
spf_cache_size = 2k;
spf_cache_expire = 12h;
EOF

    # DMARC
    cat > /etc/rspamd/local.d/dmarc.conf <<EOF
actions = {
  quarantine = "add_header";
  reject = "reject";
}
reporting {
  enabled = true;
  org_name = "${DOMAIN}";
  email = "dmarc-reports@${DOMAIN}";
  domain = "${DOMAIN}";
}
EOF

    # ARC signing — rspamd runs as its dedicated user and cannot read -r the OpenDKIM
    # private key (mode 0600, owned opendkim:opendkim). Stage a copy that
    # the rspamd service account owns so ARC signing succeeds at runtime.
    if [[ "$DKIM_CONFIGURED" == true ]]; then
        RSPAMD_ARC_KEY="/var/lib/rspamd/arc-${DKIM_SELECTOR}.key"
        if getent passwd rspamd &>/dev/null; then
            install -d -o rspamd -g rspamd -m 0750 /var/lib/rspamd
            install -o rspamd -g rspamd -m 0600 \
                "/etc/opendkim/keys/${DOMAIN}/${DKIM_SELECTOR}.private" \
                "$RSPAMD_ARC_KEY"
        else
            err "The signed rspamd package did not create its rspamd service account"
        fi

        cat > /etc/rspamd/local.d/arc.conf <<EOF
allow_envfrom_empty = true;
allow_hdrfrom_mismatch = false;
allow_hdrfrom_multiple = false;
allow_username_mismatch = false;
sign_authenticated = true;
use_domain = "header";
path = "${RSPAMD_ARC_KEY}";
selector = "${DKIM_SELECTOR}";
EOF
        chmod 640 /etc/rspamd/local.d/arc.conf
    fi

    # Antivirus (ClamAV)
    cat > /etc/rspamd/local.d/antivirus.conf <<'EOF'
clamav {
  action = "reject";
  type = "clamav";
  scan_mime_parts = true;
  scan_text_mime = true;
  scan_image_mime = true;
  symbol = "CLAM_VIRUS";
  log_clean = true;
  servers = "/run/clamav/clamd.ctl";
}
EOF

    # Phishing detection
    cat > /etc/rspamd/local.d/phishing.conf <<'EOF'
openphish_enabled = true;
phishtank_enabled = true;
EOF

    # Rate limiting
    cat > /etc/rspamd/local.d/ratelimit.conf <<'EOF'
rates {
  to = {
    symbol = "RATELIMIT_TO";
    bucket = {
      burst = 100;
      rate = "10 / 1m";
    }
  }
  to_ip_from = {
    symbol = "RATELIMIT_TO_IP_FROM";
    bucket = {
      burst = 50;
      rate = "5 / 1m";
    }
  }
}
EOF

    # Bayes classifier with Valkey's Redis-compatible protocol
    cat > /etc/rspamd/local.d/classifier-bayes.conf <<'EOF'
backend = "redis";
autolearn = true;
EOF

    msg "rspamd configured"
fi

# =============================================================================
# 14. CLAMAV
# =============================================================================

msg "Configuring ClamAV..."

if [[ -f /etc/clamav/freshclam.conf ]]; then
    backup_file /etc/clamav/freshclam.conf
fi

# Ensure freshclam.conf has no Example line (which disables it)
if [[ -f /etc/clamav/freshclam.conf ]]; then
    sed -i 's/^Example/#Example/' /etc/clamav/freshclam.conf
else
    cat > /etc/clamav/freshclam.conf <<'EOF'
DatabaseOwner clamav
UpdateLogFile /var/log/clamav/freshclam.log
LogSyslog yes
DatabaseDirectory /var/lib/clamav
DatabaseMirror database.clamav.net
EOF
fi

if [[ -f /etc/clamav/clamd.conf ]]; then
    backup_file /etc/clamav/clamd.conf
fi

# Ensure clamd.conf has the socket and no Example line
if [[ -f /etc/clamav/clamd.conf ]]; then
    sed -i 's/^Example/#Example/' /etc/clamav/clamd.conf
    grep -qxF 'LocalSocket /run/clamav/clamd.ctl' /etc/clamav/clamd.conf || \
        echo 'LocalSocket /run/clamav/clamd.ctl' >> /etc/clamav/clamd.conf
else
    cat > /etc/clamav/clamd.conf <<'EOF'
User clamav
LocalSocket /run/clamav/clamd.ctl
LogSyslog yes
DatabaseDirectory /var/lib/clamav
ScanPE yes
ScanELF yes
ScanOLE2 yes
ScanPDF yes
ScanSWF yes
ScanXMLDOCS yes
ScanHWP3 yes
EOF
fi

mkdir -p /var/log/clamav
chown clamav:clamav /var/log/clamav

clamav_database_ready() {
    [[ -e /var/lib/clamav/main.cvd || -e /var/lib/clamav/main.cld || \
       -e /var/lib/clamav/main.inc ]] &&
        [[ -e /var/lib/clamav/daily.cvd || -e /var/lib/clamav/daily.cld || \
           -e /var/lib/clamav/daily.inc ]]
}

# Download initial virus definitions if either required database is missing.
if ! clamav_database_ready; then
    if [[ "$DRY_RUN" == false ]]; then
        info "Downloading ClamAV virus definitions (this may take a few minutes)..."
        freshclam || err "freshclam failed; refusing to claim antivirus coverage without current definitions"
        clamav_database_ready || \
            err "freshclam completed without installing the required main and daily databases"
    else
        info "Dry-run: skipping freshclam database download"
    fi
fi
unset -f clamav_database_ready

msg "ClamAV configured"

# =============================================================================
# 15. SYSTEMD HARDENING
# =============================================================================

msg "Applying systemd hardening overrides..."

# --- Postfix ---
mkdir -p /etc/systemd/system/postfix.service.d
cat > /etc/systemd/system/postfix.service.d/hardening.conf <<'EOF'
[Service]
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
NoNewPrivileges=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
PrivateDevices=yes
DevicePolicy=closed
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK

ReadWritePaths=/var/spool/postfix /var/lib/postfix /var/mail/vdomains
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_DAC_READ_SEARCH CAP_KILL
EOF

# --- Dovecot ---
mkdir -p /etc/systemd/system/dovecot.service.d
cat > /etc/systemd/system/dovecot.service.d/hardening.conf <<'EOF'
[Service]
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
NoNewPrivileges=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
PrivateDevices=yes
DevicePolicy=closed
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

ReadWritePaths=/var/mail/vdomains /run/dovecot /var/spool/postfix/private
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_DAC_READ_SEARCH CAP_CHOWN CAP_SYS_CHROOT
EOF

# --- OpenDKIM ---
if [[ "$DKIM_CONFIGURED" == true ]]; then
    mkdir -p /etc/systemd/system/opendkim.service.d
    cat > /etc/systemd/system/opendkim.service.d/hardening.conf <<'EOF'
[Service]
# The socket is mode 0660; using Postfix as the primary group lets smtpd reach
# it while the daemon continues to run as the unprivileged opendkim user.
Group=postfix
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
NoNewPrivileges=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
PrivateDevices=yes
DevicePolicy=closed
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

ReadWritePaths=/run/opendkim /var/spool/postfix/private
CapabilityBoundingSet=
EOF
fi

# --- rspamd ---
if command -v rspamd &>/dev/null; then
    mkdir -p /etc/systemd/system/rspamd.service.d
    cat > /etc/systemd/system/rspamd.service.d/hardening.conf <<'EOF'
[Service]
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
NoNewPrivileges=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
PrivateDevices=yes
DevicePolicy=closed
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

ReadWritePaths=/var/lib/rspamd /run/rspamd /var/log/rspamd
CapabilityBoundingSet=
EOF
fi

systemctl daemon-reload
msg "systemd hardening applied to all mail services"

# =============================================================================
# 16. FIREWALL RULES (nftables)
# =============================================================================

msg "Adding firewall rules for mail ports..."

MAIL_PORTS=(25 465 587 993)

if [[ "$DRY_RUN" == true ]]; then
    info "Dry-run: skipping live firewall changes"
elif command -v nft &>/dev/null && nft list chain inet filter input &>/dev/null; then
    {
        for port in "${MAIL_PORTS[@]}"; do
            printf 'insert rule inet filter input ct state new tcp dport %s accept comment "awesome-postfix-%s"\n' \
                "$port" "$port"
        done
    } | aal_nft_persist_block "postfix"

    for port in "${MAIL_PORTS[@]}"; do
        aal_nft_remove_live_rules inet filter input "awesome-postfix-$port"
        nft insert rule inet filter input ct state new tcp dport "$port" accept \
            comment "awesome-postfix-$port"
    done
    msg "nftables rules added for ports ${MAIL_PORTS[*]} without replacing the live ruleset"
elif command -v iptables &>/dev/null && command -v ip6tables &>/dev/null && \
    iptables -L INPUT -n &>/dev/null && ip6tables -L INPUT -n &>/dev/null; then
    for port in "${MAIL_PORTS[@]}"; do
        # Only insert if the rule isn't already present, avoiding duplicates on rerun.
        iptables  -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || \
            iptables  -I INPUT -p tcp --dport "$port" -j ACCEPT
        ip6tables -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || \
            ip6tables -I INPUT -p tcp --dport "$port" -j ACCEPT
    done
    warn "iptables rules added for ports ${MAIL_PORTS[*]} but NOT persisted — install iptables-nft + iptables-save to persist."
else
    warn "No firewall tool found. Manually open ports ${MAIL_PORTS[*]}."
fi

# =============================================================================
# 17. ENABLE AND START SERVICES
# =============================================================================

if [[ "$DRY_RUN" == true ]]; then
    msg "Dry-run: validating configs without starting services..."

    postfix check && msg "Postfix config is valid" || err "Postfix config has errors"
    doveconf -n &>/dev/null && msg "Dovecot config is valid" || err "Dovecot config has errors"
    rspamadm configtest && msg "rspamd config is valid" || err "rspamd config has errors"

    info "Use --dry-run to review, then re-run without it to start services"
else
    msg "Starting services in dependency order..."

    # 1. Valkey (Redis-compatible rspamd backend)
    systemctl enable --now valkey
    systemctl is-active --quiet valkey && msg "valkey is running" || \
        err "valkey failed after startup; rspamd persistence is unavailable"

    # 2. ClamAV
    systemctl enable --now clamav-freshclam
    systemctl is-active --quiet clamav-freshclam || \
        err "clamav-freshclam failed after startup; virus definitions will not stay current"
    systemctl enable --now clamav-daemon
    systemctl is-active --quiet clamav-daemon || \
        err "clamav-daemon failed after startup; refusing to leave antivirus scanning unavailable"

    # 3. OpenDKIM
    if [[ "$DKIM_CONFIGURED" == true ]]; then
        systemctl enable --now opendkim
        systemctl is-active --quiet opendkim && msg "opendkim is running" || \
            err "opendkim failed after startup; refusing to leave outbound mail unsigned"
    fi

    # 4. rspamd
    if command -v rspamd &>/dev/null; then
        systemctl enable --now rspamd
        systemctl is-active --quiet rspamd && msg "rspamd is running" || \
            err "rspamd failed after startup; refusing to leave mail filtering unavailable"
    fi

    # 5. Dovecot
    systemctl enable --now dovecot
    systemctl is-active --quiet dovecot && msg "dovecot is running" || \
        err "dovecot failed after startup; refusing an incomplete mail service"

    # 6. Postfix
    systemctl enable postfix
    systemctl restart postfix
    sleep 2
    systemctl is-active --quiet postfix && msg "postfix is running" || err "postfix failed to start: journalctl -u postfix -e"
fi

# =============================================================================
# 18. DNS RECORD GENERATION
# =============================================================================

msg "Generating DNS records..."

echo
echo -e "${C_BLUE}========================================================================${C_NC}"
echo -e "${C_BLUE} DNS RECORDS — Add these to your DNS provider${C_NC}"
echo -e "${C_BLUE}========================================================================${C_NC}"
echo

# MX record
echo -e "${C_GREEN}--- MX Record ---${C_NC}"
echo "${DOMAIN}.    IN MX   10 ${MAIL_HOSTNAME}."
echo

# SPF record
echo -e "${C_GREEN}--- SPF Record ---${C_NC}"
if [[ -n "$RELAY_SPF_INCLUDE" ]]; then
    echo "${DOMAIN}.    IN TXT   \"v=spf1 mx a:${MAIL_HOSTNAME} include:${RELAY_SPF_INCLUDE} -all\""
else
    echo "${DOMAIN}.    IN TXT   \"v=spf1 mx a:${MAIL_HOSTNAME} -all\""
fi
echo
if [[ -n "$RELAY_HOST" && -z "$RELAY_SPF_INCLUDE" ]]; then
    echo -e "${C_YELLOW}NOTE: No relay SPF include was supplied. Add your provider's documented include before publishing this record.${C_NC}"
    echo
fi

# DKIM record
if [[ "$DKIM_CONFIGURED" == true ]] && [[ -f "/etc/opendkim/keys/$DOMAIN/$DKIM_SELECTOR.txt" ]]; then
    echo -e "${C_GREEN}--- DKIM Record ---${C_NC}"
    cat "/etc/opendkim/keys/$DOMAIN/$DKIM_SELECTOR.txt"
    echo
fi

# DMARC record
echo -e "${C_GREEN}--- DMARC Record ---${C_NC}"
echo "_dmarc.${DOMAIN}.    IN TXT   \"v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@${DOMAIN}; ruf=mailto:dmarc-reports@${DOMAIN}; fo=1; adkim=s; aspf=s; pct=100\""
echo
echo -e "${C_YELLOW}NOTE: Start with p=quarantine, upgrade to p=reject after 2-4 weeks of monitoring${C_NC}"
echo

# DANE/TLSA records
if [[ "$DRY_RUN" == false ]] && [[ -f "$CERT_DIR/cert.pem" ]]; then
    TLSA_HASH=$(openssl x509 -in "$CERT_DIR/cert.pem" -noout -pubkey 2>/dev/null | \
                openssl pkey -pubin -outform DER 2>/dev/null | \
                openssl dgst -sha256 -hex 2>/dev/null | \
                awk '{print $NF}' || echo "ERROR_GENERATING_HASH")
    TLSA_HASH=${TLSA_HASH:-ERROR_GENERATING_HASH}

    if [[ "$TLSA_HASH" != "ERROR_GENERATING_HASH" ]]; then
        echo -e "${C_GREEN}--- DANE/TLSA Records ---${C_NC}"
        for port in 25 465 587; do
            echo "_${port}._tcp.${MAIL_HOSTNAME}.  IN TLSA  3 1 1 ${TLSA_HASH}"
        done
        echo
        echo -e "${C_YELLOW}NOTE: DANE requires DNSSEC on your domain. Verify: dig +dnssec ${DOMAIN} SOA${C_NC}"
        echo
    fi
fi

# MTA-STS
echo -e "${C_GREEN}--- MTA-STS Record ---${C_NC}"
echo "_mta-sts.${DOMAIN}.    IN TXT   \"v=STSv1; id=$(date +%Y%m%d%H%M%S)\""
echo
echo -e "${C_YELLOW}Also create https://mta-sts.${DOMAIN}/.well-known/mta-sts.txt with:${C_NC}"
echo "  version: STSv1"
echo "  mode: enforce"
echo "  mx: ${MAIL_HOSTNAME}"
echo "  max_age: 604800"
echo

# TLS-RPT
echo -e "${C_GREEN}--- TLS Reporting Record ---${C_NC}"
echo "_smtp._tls.${DOMAIN}.  IN TXT   \"v=TLSRPTv1; rua=mailto:tls-reports@${DOMAIN}\""
echo

# Reverse DNS reminder
echo -e "${C_GREEN}--- Reverse DNS (PTR) ---${C_NC}"
echo -e "${C_YELLOW}Set your server's PTR record to: ${MAIL_HOSTNAME}${C_NC}"
echo

# =============================================================================
# 19. SUMMARY
# =============================================================================

echo
echo -e "${C_GREEN}========================================================================${C_NC}"
echo -e "${C_GREEN} Hardened mail server configuration complete!${C_NC}"
echo -e "${C_GREEN}========================================================================${C_NC}"
echo

echo -e "${C_BLUE}Configuration files:${C_NC}"
echo "  Postfix main.cf:        /etc/postfix/main.cf"
echo "  Postfix master.cf:      /etc/postfix/master.cf"
echo "  Header checks:          /etc/postfix/header_checks_submission"
echo "  Virtual mailboxes:      /etc/postfix/vmailbox"
echo "  Aliases:                /etc/postfix/aliases"
echo "  Dovecot:                /etc/dovecot/dovecot.conf"
echo "  Mail encryption key:    $MAIL_CRYPT_PRIVATE_KEY (back this up)"
echo "  Dovecot users:          /etc/dovecot/users"
echo "  OpenDKIM:               /etc/opendkim/opendkim.conf"
echo "  rspamd:                 /etc/rspamd/local.d/"
echo "  ClamAV:                 /etc/clamav/{clamd,freshclam}.conf"
echo "  systemd overrides:      /etc/systemd/system/{postfix,dovecot,opendkim,rspamd}.service.d/"
echo

echo -e "${C_BLUE}Security features:${C_NC}"
echo "  TLS:                    1.2+ only, ECDHE/AEAD ciphers"
echo "  Outbound TLS:           DANE with valid TLSA; opportunistic otherwise"
echo "  SMTP smuggling:         Protected (smtpd_forbid_bare_newline)"
echo "  Postscreen:             DNSBL + deep protocol tests"
echo "  DKIM:                   RSA 2048, OversignHeaders From"
echo "  SPF/DMARC/ARC:          Via rspamd"
echo "  Spam filtering:         rspamd with Bayes + phishing detection"
echo "  Antivirus:              ClamAV via rspamd"
echo "  Rate limiting:          Postfix + rspamd (dual layer)"
echo "  Header privacy:         Internal headers stripped on submission"
echo "  Encryption at rest:     Dovecot mail_crypt (global EC P-384 key)"
echo "  IMAP:                   TLS-only (port 143 disabled)"
echo "  VRFY:                   Disabled"
echo "  systemd:                Core mail daemons hardened"
echo

echo -e "${C_YELLOW}IMPORTANT — Next steps:${C_NC}"
echo "  1. Add the DNS records shown above to your domain"
echo "  2. Create Dovecot users:"
echo "       doveadm pw -s BLF-CRYPT"
echo "       echo 'user@${DOMAIN}:{BLF-CRYPT}hash' >> /etc/dovecot/users"
echo "  3. Add virtual mailboxes:"
echo "       echo 'user@${DOMAIN} ${DOMAIN}/user/Maildir/' >> /etc/postfix/vmailbox"
echo "       postmap lmdb:/etc/postfix/vmailbox"
echo "  4. Set PTR record to ${MAIL_HOSTNAME}"
echo "  5. Upgrade DMARC to p=reject after 2-4 weeks"
echo "  6. Set up MTA-STS policy file at https://mta-sts.${DOMAIN}/.well-known/mta-sts.txt"
echo "  7. ClamAV uses ~1GB RAM — monitor with: systemctl status clamav-daemon"
echo

echo -e "${C_BLUE}Verification commands:${C_NC}"
echo "  postfix check                                            # Validate Postfix config"
echo "  dovecot -n                                               # Show Dovecot config"
echo "  openssl s_client -connect ${MAIL_HOSTNAME}:25 -starttls smtp  # Test STARTTLS"
echo "  openssl s_client -connect ${MAIL_HOSTNAME}:465               # Test SMTPS"
echo "  openssl s_client -connect ${MAIL_HOSTNAME}:993               # Test IMAPS"
echo "  opendkim-testkey -d ${DOMAIN} -s ${DKIM_SELECTOR} -vvv       # Test DKIM"
echo "  rspamc stat                                              # rspamd statistics"
echo "  echo 'test' | mail -s 'test' ${ADMIN_EMAIL}                  # Send test email"
echo

echo -e "${C_BLUE}Testing services:${C_NC}"
echo "  https://www.checktls.com/TestReceiver                    # Inbound TLS test"
echo "  https://mxtoolbox.com/SuperTool.aspx                     # MX/SPF/DKIM/DMARC"
echo "  https://internet.nl/mail/${DOMAIN}/                       # Comprehensive test"
echo "  https://www.mail-tester.com/                             # Deliverability test"
echo

echo -e "${C_GREEN}Done.${C_NC}"
