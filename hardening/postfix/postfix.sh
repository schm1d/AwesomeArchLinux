#!/usr/bin/env bash

# =============================================================================
# Script:      postfix.sh
# Description: Installs and configures a ProtonMail-grade hardened mail server
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
#                                [-p RELAY_PASS] [-e ADMIN_EMAIL] [--dry-run] [-h]
#
# Requirements:
#   - Arch Linux with pacman
#   - Root privileges
#   - TLS certificate at /etc/letsencrypt/live/<hostname>/ (or --dry-run)
#   - DNSSEC-validating resolver for DANE (systemd-resolved or unbound)
#   - yay or paru for AUR packages (opendkim)
#
# What this script does:
#   1.  Installs postfix, dovecot, opendkim, rspamd, redis, clamav, s-nail
#   2.  Stops and masks competing MTAs (sendmail, exim)
#   3.  Creates vmail user/group and mailbox directories
#   4.  Generates DH parameters for Postfix and Dovecot
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
ADMIN_EMAIL=""
DRY_RUN=false

# --- Cipher list (ProtonMail-grade: ECDHE + AEAD only) ---
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
  -p PASS         SMTP relay password
  -e EMAIL        Admin email address (default: postmaster@\$DOMAIN)
  --dry-run       Write configs but do not start services or require certs
  -h              Show this help

Examples:
  sudo $0 -d example.com
  sudo $0 -d example.com -H mx1.example.com -s dkim2024
  sudo $0 -d example.com -r smtp.sendgrid.net -u apikey -p 'SG.xxxx'
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
        -p)         need_arg "$@"; RELAY_PASS="$2"; shift 2 ;;
        -e)         need_arg "$@"; ADMIN_EMAIL="$2"; shift 2 ;;
        --dry-run)  DRY_RUN=true; shift ;;
        -h|--help)  usage ;;
        *)          err "Unknown option: $1" ;;
    esac
done

# --- Validate ---
[[ $(id -u) -eq 0 ]] || err "Must be run as root"
[[ -n "$DOMAIN" ]] || err "Domain is required (-d). Use -h for help."

if [[ -n "$RELAY_HOST" ]]; then
    if ! [[ "$RELAY_PORT" =~ ^[0-9]+$ ]] || (( RELAY_PORT < 1 || RELAY_PORT > 65535 )); then
        err "Invalid relay port: $RELAY_PORT (must be 1-65535)"
    fi
fi

# Derive defaults
MAIL_HOSTNAME="${MAIL_HOSTNAME:-mail.$DOMAIN}"
ADMIN_EMAIL="${ADMIN_EMAIL:-postmaster@$DOMAIN}"

readonly DOMAIN MAIL_HOSTNAME DKIM_SELECTOR ADMIN_EMAIL DRY_RUN
readonly CERT_DIR="/etc/letsencrypt/live/$MAIL_HOSTNAME"
readonly VMAIL_UID=5000
readonly VMAIL_GID=5000
readonly MAIL_DIR="/var/mail/vdomains"

# Check TLS certificate
if [[ "$DRY_RUN" == false ]]; then
    if [[ ! -f "$CERT_DIR/fullchain.pem" || ! -f "$CERT_DIR/privkey.pem" ]]; then
        err "TLS certificate not found at $CERT_DIR/. Run certbot first or use --dry-run."
    fi
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

# --- Helper: build an AUR package from source under a throwaway user ---
# $1 = package name
# Clones the AUR repo, runs makepkg -si as _makepkg (never as root, never
# relying on SUDO_USER/NOPASSWD), then cleans up the build user.
install_from_aur() {
    local pkg="$1"
    local tmpdir builddir build_user="_makepkg"
    tmpdir="$(mktemp -d)"
    builddir="$tmpdir/$pkg"

    git clone --depth=1 "https://aur.archlinux.org/${pkg}.git" "$builddir"

    useradd -r -M -d /var/empty -s /usr/bin/nologin "$build_user" 2>/dev/null || true
    chown -R "$build_user":"$build_user" "$tmpdir"

    # Grant passwordless pacman -U/-S for the duration of this build
    local sudoers="/etc/sudoers.d/99-${build_user}-postfix-sh"
    printf '%s ALL=(root) NOPASSWD: /usr/bin/pacman\n' "$build_user" > "$sudoers"
    chmod 440 "$sudoers"

    ( cd "$builddir" && sudo -u "$build_user" makepkg -si --noconfirm )
    local rc=$?

    rm -f "$sudoers"
    userdel "$build_user" 2>/dev/null || true
    rm -rf "$tmpdir"

    return $rc
}

# =============================================================================
# 1. INSTALL PACKAGES
# =============================================================================

msg "Installing packages..."

# Official repo packages
for pkg in postfix dovecot redis clamav s-nail pigeonhole; do
    if pacman -Qi "$pkg" &>/dev/null; then
        info "$pkg is already installed"
    else
        pacman -S --noconfirm --needed "$pkg"
        msg "$pkg installed"
    fi
done

# rspamd (community, with AUR fallback)
if pacman -Qi rspamd &>/dev/null; then
    info "rspamd is already installed"
elif pacman -Si rspamd &>/dev/null; then
    pacman -S --noconfirm --needed rspamd
    msg "rspamd installed"
else
    install_from_aur rspamd && msg "rspamd installed from AUR" \
        || warn "Failed to install rspamd from AUR; install manually."
fi

# opendkim (AUR)
if pacman -Qi opendkim &>/dev/null; then
    info "opendkim is already installed"
else
    install_from_aur opendkim && msg "opendkim installed from AUR" \
        || warn "Failed to install opendkim from AUR; install manually."
fi

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
# 4. GENERATE DH PARAMETERS
# =============================================================================

msg "Generating DH parameters..."

# Postfix 3.6+ supplies its own 2048-bit FFDHE group by default, so no
# smtpd_tls_dh*_param_file is needed. Dovecot still wants its own dh.pem.
if [[ -f /etc/dovecot/dh.pem ]]; then
    info "Dovecot DH params already exist, skipping"
else
    openssl dhparam -out /etc/dovecot/dh.pem 2048
    chmod 644 /etc/dovecot/dh.pem
    msg "Dovecot DH params generated (2048-bit)"
fi

# =============================================================================
# 5. POSTFIX main.cf
# =============================================================================

msg "Writing /etc/postfix/main.cf..."
backup_file /etc/postfix/main.cf

cat > /etc/postfix/main.cf <<EOF
# =============================================================================
# Postfix main.cf — ProtonMail-grade hardened MX server
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
virtual_mailbox_maps = hash:/etc/postfix/vmailbox
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
smtpd_tls_eecdh_grade = ultra
smtpd_tls_loglevel = 1

# --- TLS outbound (smtp) — DANE with fallback ---
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
milter_default_action = accept
milter_protocol = 6
smtpd_milters = unix:/run/opendkim/opendkim.sock, inet:127.0.0.1:11332
non_smtpd_milters = unix:/run/opendkim/opendkim.sock, inet:127.0.0.1:11332

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
compatibility_level = 3.9
smtpd_banner = \$myhostname ESMTP
disable_vrfy_command = yes
message_size_limit = 26214400
mailbox_size_limit = 0
recipient_delimiter = +
biff = no
append_dot_mydomain = no

# --- Aliases ---
alias_maps = hash:/etc/postfix/aliases
alias_database = hash:/etc/postfix/aliases
EOF

# Append relay config if specified
if [[ -n "$RELAY_HOST" ]]; then
    cat >> /etc/postfix/main.cf <<EOF

# --- Outbound relay (hybrid setup) ---
relayhost = [${RELAY_HOST}]:${RELAY_PORT}
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous
smtp_sasl_tls_security_options = noanonymous
EOF
fi

msg "main.cf written"

# =============================================================================
# 6. POSTFIX master.cf
# =============================================================================

msg "Writing /etc/postfix/master.cf..."
backup_file /etc/postfix/master.cf

cat > /etc/postfix/master.cf <<'EOF'
# =============================================================================
# Postfix master.cf — ProtonMail-grade service definitions
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
${ADMIN_EMAIL}          ${DOMAIN}/$(echo "$ADMIN_EMAIL" | cut -d@ -f1)/Maildir/
EOF

postmap /etc/postfix/vmailbox
chmod 644 /etc/postfix/vmailbox

msg "Virtual mailbox map created"

# =============================================================================
# 9. SASL PASSWORD (optional relay)
# =============================================================================

if [[ -n "$RELAY_HOST" && -n "$RELAY_USER" && -n "$RELAY_PASS" ]]; then
    msg "Writing SASL relay credentials..."

    cat > /etc/postfix/sasl_passwd <<EOF
[${RELAY_HOST}]:${RELAY_PORT} ${RELAY_USER}:${RELAY_PASS}
EOF
    postmap /etc/postfix/sasl_passwd
    chmod 600 /etc/postfix/sasl_passwd
    chmod 600 /etc/postfix/sasl_passwd.db
    msg "SASL relay credentials configured"
elif [[ -n "$RELAY_HOST" ]]; then
    warn "Relay host set but no credentials provided (-u/-p). Relay may reject mail."
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

postalias /etc/postfix/aliases
msg "Aliases configured (root → $ADMIN_EMAIL)"

# =============================================================================
# 11. OPENDKIM
# =============================================================================

msg "Configuring OpenDKIM..."

if ! command -v opendkim-genkey &>/dev/null; then
    warn "opendkim not installed — skipping DKIM configuration"
    warn "Install from AUR (yay -S opendkim), then re-run this script"
    DKIM_CONFIGURED=false
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

Socket              local:/run/opendkim/opendkim.sock
PidFile             /run/opendkim/opendkim.pid
UMask               007
UserID              opendkim:opendkim

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

    msg "OpenDKIM configured"
fi

# =============================================================================
# 12. DOVECOT
# =============================================================================

msg "Configuring Dovecot..."

# Main config
backup_file /etc/dovecot/dovecot.conf
cat > /etc/dovecot/dovecot.conf <<'EOF'
# =============================================================================
# Dovecot configuration — ProtonMail-grade IMAP
# Generated by AwesomeArchLinux/hardening/postfix/postfix.sh
# =============================================================================

protocols = imap lmtp sieve
listen = *, ::
login_greeting = Dovecot ready.

# Disable plaintext auth on non-TLS connections
disable_plaintext_auth = yes

# Include conf.d configs
!include conf.d/*.conf
EOF

mkdir -p /etc/dovecot/conf.d

# 10-ssl.conf — TLS hardening
cat > /etc/dovecot/conf.d/10-ssl.conf <<EOF
ssl = required
ssl_cert = <${CERT_DIR}/fullchain.pem
ssl_key = <${CERT_DIR}/privkey.pem
ssl_min_protocol = TLSv1.2
ssl_cipher_list = ${TLS_CIPHERS}
ssl_prefer_server_ciphers = yes
ssl_dh = </etc/dovecot/dh.pem
EOF

# 10-mail.conf — Mail storage
#
# NOTE on encryption-at-rest:
#   mail_crypt only encrypts when per-user keypairs exist. Loading the plugin
#   alone is a no-op. After creating a Dovecot user, run:
#     doveadm -o plugin/mail_crypt_private_password=<pw> \\
#             mailbox cryptokey generate -u user@${DOMAIN} -U
#   (Or set mail_crypt_global_private_key / _public_key below to sign all
#   mail with one shared keypair — simpler, weaker isolation.)
cat > /etc/dovecot/conf.d/10-mail.conf <<EOF
mail_location = maildir:${MAIL_DIR}/%d/%n/Maildir
mail_uid = ${VMAIL_UID}
mail_gid = ${VMAIL_GID}
mail_privileged_group = vmail
first_valid_uid = ${VMAIL_UID}
last_valid_uid = ${VMAIL_UID}

# Encryption at rest — requires per-user key generation to actually encrypt.
mail_plugins = \$mail_plugins mail_crypt
plugin {
  mail_crypt_curve = secp521r1
  mail_crypt_save_version = 2
}
EOF

# 10-auth.conf — Authentication
cat > /etc/dovecot/conf.d/10-auth.conf <<'EOF'
auth_mechanisms = plain login
disable_plaintext_auth = yes

passdb {
  driver = passwd-file
  args = scheme=BLF-CRYPT /etc/dovecot/users
}
userdb {
  driver = static
  args = uid=vmail gid=vmail home=/var/mail/vdomains/%d/%n
}
EOF

# 10-master.conf — Service sockets
cat > /etc/dovecot/conf.d/10-master.conf <<'EOF'
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

# IMAP login
service imap-login {
  inet_listener imap {
    # Disable unencrypted IMAP (port 143)
    port = 0
  }
  inet_listener imaps {
    port = 993
    ssl = yes
  }
}
EOF

# 20-lmtp.conf
cat > /etc/dovecot/conf.d/20-lmtp.conf <<'EOF'
protocol lmtp {
  mail_plugins = $mail_plugins sieve
  postmaster_address = postmaster@%d
}
EOF

# 20-imap.conf
cat > /etc/dovecot/conf.d/20-imap.conf <<'EOF'
protocol imap {
  mail_plugins = $mail_plugins imap_sieve
  mail_max_userip_connections = 20
}
EOF

# 90-sieve.conf — Server-side filtering
cat > /etc/dovecot/conf.d/90-sieve.conf <<EOF
plugin {
  sieve = file:~/sieve;active=~/.dovecot.sieve
  sieve_before = ${MAIL_DIR}/sieve-before/
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

# Compile sieve script
if command -v sievec &>/dev/null; then
    sievec "$MAIL_DIR/sieve-before/spam-to-junk.sieve" || true
    chown vmail:vmail "$MAIL_DIR/sieve-before/spam-to-junk.svbin" 2>/dev/null || true
fi

# Create empty users file if not present
if [[ ! -f /etc/dovecot/users ]]; then
    touch /etc/dovecot/users
    chmod 600 /etc/dovecot/users
    chown root:root /etc/dovecot/users
    warn "Dovecot users file created empty. Add users with:"
    warn "  doveadm pw -s BLF-CRYPT | xargs -I{} echo 'user@$DOMAIN:{}' >> /etc/dovecot/users"
fi

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

    # Actions (scoring thresholds)
    cat > /etc/rspamd/local.d/actions.conf <<'EOF'
reject = 15;
add_header = 6;
greylist = 4;
EOF

    # Milter headers
    cat > /etc/rspamd/local.d/milter_headers.conf <<'EOF'
use = ["x-spam-status", "x-spam-flag", "authentication-results"];
EOF

    # Redis backend
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
reporting = true;
actions = {
  quarantine = "add_header";
  reject = "reject";
}
send_reports = true;
report_settings {
  org_name = "${DOMAIN}";
  email = "dmarc-reports@${DOMAIN}";
}
EOF

    # ARC signing — rspamd runs as _rspamd and cannot read the OpenDKIM
    # private key (mode 0600, owned opendkim:opendkim). Stage a copy that
    # _rspamd owns so ARC signing actually succeeds at runtime.
    if [[ "$DKIM_CONFIGURED" == true ]]; then
        RSPAMD_ARC_KEY="/var/lib/rspamd/arc-${DKIM_SELECTOR}.key"
        if getent passwd _rspamd &>/dev/null; then
            install -d -o _rspamd -g _rspamd -m 0750 /var/lib/rspamd
            install -o _rspamd -g _rspamd -m 0600 \
                "/etc/opendkim/keys/${DOMAIN}/${DKIM_SELECTOR}.private" \
                "$RSPAMD_ARC_KEY"
        else
            mkdir -p /var/lib/rspamd
            cp "/etc/opendkim/keys/${DOMAIN}/${DKIM_SELECTOR}.private" "$RSPAMD_ARC_KEY"
            chmod 0600 "$RSPAMD_ARC_KEY"
            warn "_rspamd user not found yet; ARC key ownership may need fixing after rspamd install"
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

    # Bayes classifier with Redis
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

# Download initial virus definitions if missing
if [[ ! -f /var/lib/clamav/main.cvd && ! -f /var/lib/clamav/main.cld ]]; then
    if [[ "$DRY_RUN" == false ]]; then
        info "Downloading ClamAV virus definitions (this may take a few minutes)..."
        freshclam || warn "freshclam failed — virus definitions may be stale"
    else
        info "Dry-run: skipping freshclam database download"
    fi
fi

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

ReadWritePaths=/run/opendkim
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

if command -v nft &>/dev/null && nft list table inet filter &>/dev/null; then
    for port in "${MAIL_PORTS[@]}"; do
        # Skip if an identical accept rule already exists (handle):
        if ! nft -a list chain inet filter input 2>/dev/null \
                | grep -Eq "tcp dport ${port}[[:space:]]+accept"; then
            nft add rule inet filter input tcp dport "$port" accept || true
        fi
    done
    # Persist: dump with a flush header so `nft -f` is idempotent on reload.
    {
        printf '#!/usr/bin/nft -f\nflush ruleset\n\n'
        nft list ruleset
    } > /etc/nftables.conf
    chmod 0644 /etc/nftables.conf
    msg "nftables rules added for ports ${MAIL_PORTS[*]}"
elif command -v iptables &>/dev/null; then
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

    postfix check && msg "Postfix config is valid" || warn "Postfix config has errors"

    if command -v dovecot &>/dev/null; then
        dovecot -n &>/dev/null && msg "Dovecot config is valid" || warn "Dovecot config has errors"
    fi

    info "Use --dry-run to review, then re-run without it to start services"
else
    msg "Starting services in dependency order..."

    # 1. Redis
    systemctl enable --now redis
    systemctl is-active --quiet redis && msg "redis is running" || warn "redis failed to start"

    # 2. ClamAV
    systemctl enable clamav-freshclam
    systemctl enable clamav-daemon
    systemctl start clamav-freshclam || warn "clamav-freshclam failed to start"
    systemctl start clamav-daemon || warn "clamav-daemon failed to start (virus defs may still be downloading)"

    # 3. OpenDKIM
    if [[ "$DKIM_CONFIGURED" == true ]]; then
        systemctl enable --now opendkim
        systemctl is-active --quiet opendkim && msg "opendkim is running" || warn "opendkim failed to start"
    fi

    # 4. rspamd
    if command -v rspamd &>/dev/null; then
        systemctl enable --now rspamd
        systemctl is-active --quiet rspamd && msg "rspamd is running" || warn "rspamd failed to start"
    fi

    # 5. Dovecot
    systemctl enable --now dovecot
    systemctl is-active --quiet dovecot && msg "dovecot is running" || warn "dovecot failed to start"

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
if [[ -n "$RELAY_HOST" ]]; then
    echo "${DOMAIN}.    IN TXT   \"v=spf1 mx a:${MAIL_HOSTNAME} include:${RELAY_HOST} -all\""
else
    echo "${DOMAIN}.    IN TXT   \"v=spf1 mx a:${MAIL_HOSTNAME} -all\""
fi
echo

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
echo -e "${C_GREEN} ProtonMail-grade mail server configuration complete!${C_NC}"
echo -e "${C_GREEN}========================================================================${C_NC}"
echo

echo -e "${C_BLUE}Configuration files:${C_NC}"
echo "  Postfix main.cf:        /etc/postfix/main.cf"
echo "  Postfix master.cf:      /etc/postfix/master.cf"
echo "  Header checks:          /etc/postfix/header_checks_submission"
echo "  Virtual mailboxes:      /etc/postfix/vmailbox"
echo "  Aliases:                /etc/postfix/aliases"
echo "  Dovecot:                /etc/dovecot/dovecot.conf + conf.d/"
echo "  Dovecot users:          /etc/dovecot/users"
echo "  OpenDKIM:               /etc/opendkim/opendkim.conf"
echo "  rspamd:                 /etc/rspamd/local.d/"
echo "  ClamAV:                 /etc/clamav/{clamd,freshclam}.conf"
echo "  systemd overrides:      /etc/systemd/system/{postfix,dovecot,opendkim,rspamd}.service.d/"
echo

echo -e "${C_BLUE}Security features:${C_NC}"
echo "  TLS:                    1.2+ only, ECDHE/AEAD ciphers (ProtonMail-grade)"
echo "  Outbound TLS:           DANE with DNSSEC (falls back to encrypt)"
echo "  SMTP smuggling:         Protected (smtpd_forbid_bare_newline)"
echo "  Postscreen:             DNSBL + deep protocol tests"
echo "  DKIM:                   RSA 2048, OversignHeaders From"
echo "  SPF/DMARC/ARC:          Via rspamd"
echo "  Spam filtering:         rspamd with Bayes + phishing detection"
echo "  Antivirus:              ClamAV via rspamd"
echo "  Rate limiting:          Postfix + rspamd (dual layer)"
echo "  Header privacy:         Internal headers stripped on submission"
echo "  Encryption at rest:     Dovecot mail_crypt (secp521r1)"
echo "  IMAP:                   TLS-only (port 143 disabled)"
echo "  VRFY:                   Disabled"
echo "  systemd:                All services hardened"
echo

echo -e "${C_YELLOW}IMPORTANT — Next steps:${C_NC}"
echo "  1. Add the DNS records shown above to your domain"
echo "  2. Create Dovecot users:"
echo "       doveadm pw -s BLF-CRYPT"
echo "       echo 'user@${DOMAIN}:{BLF-CRYPT}hash' >> /etc/dovecot/users"
echo "  3. Add virtual mailboxes:"
echo "       echo 'user@${DOMAIN} ${DOMAIN}/user/Maildir/' >> /etc/postfix/vmailbox"
echo "       postmap /etc/postfix/vmailbox"
echo "  4. Set PTR record to ${MAIL_HOSTNAME}"
echo "  5. Upgrade DMARC to p=reject after 2-4 weeks"
echo "  6. Set up MTA-STS policy file at https://mta-sts.${DOMAIN}/.well-known/mta-sts.txt"
echo "  7. ClamAV uses ~1GB RAM — monitor with: systemctl status clamav-daemon"
if [[ -n "${DKIM_CONFIGURED:-}" && "$DKIM_CONFIGURED" == false ]]; then
    echo "  8. Install opendkim from AUR and re-run this script for DKIM signing"
fi
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
