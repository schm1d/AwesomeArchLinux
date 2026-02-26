#!/usr/bin/env bash

# =============================================================================
# Script:      nginx.sh
# Description: Installs and hardens nginx-mainline on Arch Linux with
#              Let's Encrypt (certbot), targeting:
#                - SSL Labs A+ rating
#                - securityheaders.com A+ (all green headers)
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
#
# Usage:       sudo ./nginx.sh -d example.com [-d sub.example.com] [-p 443]
#                               [-w /var/www/html] [-e admin@example.com]
#                               [--dry-run] [--skip-certbot] [-h]
#
# Requirements:
#   - Arch Linux with pacman
#   - Root privileges
#   - DNS A/AAAA records pointing to this server
#   - Port 80 open (for Let's Encrypt HTTP-01 challenge)
#
# What this script does:
#   1. Installs nginx-mainline + certbot + certbot-nginx
#   2. Generates a 4096-bit DH parameter file
#   3. Obtains Let's Encrypt certificates via certbot
#   4. Writes a hardened nginx configuration
#   5. Sets up automatic certificate renewal via systemd timer
#   6. Hardens the nginx systemd service with security overrides
#   7. Verifies configuration and reloads nginx
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
declare -a DOMAINS=()
WEBROOT="/var/www/html"
EMAIL=""
HTTPS_PORT=443
DRY_RUN=false
SKIP_CERTBOT=false
NGINX_CONF="/etc/nginx/nginx.conf"
SSL_DIR="/etc/nginx/ssl"
DH_PARAM="$SSL_DIR/dhparam.pem"
SECURITY_CONF="/etc/nginx/conf.d/security-headers.conf"
SSL_CONF="/etc/nginx/conf.d/ssl-hardening.conf"
LOGFILE="/var/log/nginx-hardening-$(date +%Y%m%d-%H%M%S).log"

# --- Usage ---
usage() {
    cat <<EOF
Usage: sudo $0 [options]

Required:
  -d DOMAIN       Domain name (repeat for multiple: -d a.com -d b.com)

Optional:
  -e EMAIL        Email for Let's Encrypt notifications (default: webmaster@DOMAIN)
  -w WEBROOT      Web root directory (default: $WEBROOT)
  -p PORT         HTTPS port (default: $HTTPS_PORT)
  --dry-run       Use Let's Encrypt staging server (for testing)
  --skip-certbot  Skip certificate issuance (use existing certs)
  -h              Show this help

Examples:
  sudo $0 -d example.com -d www.example.com -e admin@example.com
  sudo $0 -d example.com --dry-run
  sudo $0 -d example.com --skip-certbot
EOF
    exit 0
}

# --- Parse Arguments ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        -d)          DOMAINS+=("$2"); shift 2 ;;
        -e)          EMAIL="$2"; shift 2 ;;
        -w)          WEBROOT="$2"; shift 2 ;;
        -p)          HTTPS_PORT="$2"; shift 2 ;;
        --dry-run)   DRY_RUN=true; shift ;;
        --skip-certbot) SKIP_CERTBOT=true; shift ;;
        -h|--help)   usage ;;
        *)           err "Unknown option: $1" ;;
    esac
done

# --- Validate ---
[[ $(id -u) -eq 0 ]] || err "Must be run as root"
[[ ${#DOMAINS[@]} -gt 0 ]] || err "At least one domain is required (-d example.com)"

PRIMARY_DOMAIN="${DOMAINS[0]}"
EMAIL="${EMAIL:-webmaster@$PRIMARY_DOMAIN}"

# Redirect output to logfile as well
exec > >(tee -a "$LOGFILE") 2>&1

info "Primary domain: $PRIMARY_DOMAIN"
info "All domains: ${DOMAINS[*]}"
info "Email: $EMAIL"
info "Webroot: $WEBROOT"
info "Log: $LOGFILE"

# =============================================================================
# 1. INSTALL PACKAGES
# =============================================================================

msg "Installing nginx-mainline and certbot..."

# nginx-mainline is in the official Arch repos
pacman -Syu --noconfirm --needed nginx-mainline certbot certbot-nginx openssl

# Verify nginx version supports TLS 1.3
NGINX_VER=$(nginx -v 2>&1 | grep -oP '[\d.]+')
info "nginx version: $NGINX_VER"

# =============================================================================
# 2. GENERATE DH PARAMETERS
# =============================================================================

mkdir -p "$SSL_DIR"
chmod 700 "$SSL_DIR"

if [[ ! -f "$DH_PARAM" ]]; then
    msg "Generating 4096-bit DH parameters (this takes a few minutes)..."
    openssl dhparam -out "$DH_PARAM" 4096
    chmod 600 "$DH_PARAM"
else
    info "DH parameters already exist at $DH_PARAM"
fi

# =============================================================================
# 3. PREPARE DIRECTORIES
# =============================================================================

msg "Preparing web directories..."
mkdir -p "$WEBROOT/.well-known/acme-challenge"
chown -R http:http "$WEBROOT"

mkdir -p /var/log/nginx
mkdir -p /var/cache/nginx/client_temp
mkdir -p /etc/nginx/conf.d
mkdir -p /etc/nginx/sites-enabled

# =============================================================================
# 4. WRITE PRE-CERTIFICATE NGINX CONFIG (for ACME challenge)
# =============================================================================

msg "Writing initial nginx config for ACME challenge..."

cat > "$NGINX_CONF" <<'NGINX_MAIN'
# =============================================================================
# nginx-mainline hardened configuration
# Generated by AwesomeArchLinux/hardening/nginx/nginx.sh
# =============================================================================

# Run as unprivileged user
user http;
worker_processes auto;
worker_rlimit_nofile 8192;
pid /run/nginx.pid;

# Reduce information leakage
error_log /var/log/nginx/error.log warn;

events {
    worker_connections 4096;
    multi_accept on;
    use epoll;
}

http {
    # --- Core ---
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    charset       utf-8;

    # --- Hide version ---
    server_tokens off;

    # --- Logging ---
    log_format main '$remote_addr - $remote_user [$time_local] '
                    '"$request" $status $body_bytes_sent '
                    '"$http_referer" "$http_user_agent"';
    access_log /var/log/nginx/access.log main;

    # --- Performance ---
    sendfile        on;
    tcp_nopush      on;
    tcp_nodelay     on;
    keepalive_timeout 65;
    types_hash_max_size 2048;

    # --- Buffer limits (mitigate buffer overflow attacks) ---
    client_body_buffer_size    16k;
    client_header_buffer_size  1k;
    client_max_body_size       10m;
    large_client_header_buffers 4 8k;

    # --- Timeouts (mitigate slowloris) ---
    client_body_timeout   12;
    client_header_timeout 12;
    send_timeout          10;

    # --- Gzip (disable for SSL to prevent BREACH) ---
    gzip off;

    # --- Include modular configs ---
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*.conf;
}
NGINX_MAIN

# Write a temporary HTTP-only server for ACME challenge
cat > /etc/nginx/sites-enabled/default.conf <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAINS[*]};

    # ACME challenge
    location ^~ /.well-known/acme-challenge/ {
        root $WEBROOT;
        allow all;
        default_type "text/plain";
        try_files \$uri =404;
    }

    # Redirect everything else to HTTPS
    location / {
        return 301 https://\$host\$request_uri;
    }
}
EOF

# Test and start nginx
nginx -t || err "nginx config test failed"
systemctl enable nginx
systemctl restart nginx

# =============================================================================
# 4b. OPEN FIREWALL PORTS (80/443)
# =============================================================================

msg "Opening firewall ports 80 (HTTP) and 443 (HTTPS)..."
if command -v nft &>/dev/null && nft list table inet filter &>/dev/null 2>&1; then
    # Insert (not add) so rules land before the final drop rule
    nft insert rule inet filter input tcp dport 80 accept 2>/dev/null || true
    nft insert rule inet filter input tcp dport 443 accept 2>/dev/null || true
    # Persist to nftables.conf if it exists
    if [[ -f /etc/nftables.conf ]]; then
        nft list ruleset > /etc/nftables.conf
    fi
    msg "nftables: ports 80/443 opened."
elif command -v iptables &>/dev/null && iptables -L -n &>/dev/null 2>&1; then
    iptables -I INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || true
    iptables -I INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || true
    if command -v iptables-save &>/dev/null; then
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/iptables.rules
    fi
    msg "iptables: ports 80/443 opened."
else
    warn "No firewall detected — ensure ports 80/443 are reachable."
fi

# =============================================================================
# 5. OBTAIN CERTIFICATES
# =============================================================================

if [[ "$SKIP_CERTBOT" == false ]]; then
    msg "Obtaining Let's Encrypt certificates..."

    CERTBOT_ARGS=(
        certonly
        --webroot
        -w "$WEBROOT"
        --email "$EMAIL"
        --agree-tos
        --no-eff-email
        --key-type ecdsa
        --elliptic-curve secp384r1
    )

    for d in "${DOMAINS[@]}"; do
        CERTBOT_ARGS+=(-d "$d")
    done

    if [[ "$DRY_RUN" == true ]]; then
        CERTBOT_ARGS+=(--staging)
        warn "Using Let's Encrypt STAGING server (certificates will NOT be trusted)"
    fi

    certbot "${CERTBOT_ARGS[@]}"
else
    info "Skipping certbot (--skip-certbot)"
fi

# Verify certificate exists
CERT_DIR="/etc/letsencrypt/live/$PRIMARY_DOMAIN"
if [[ ! -d "$CERT_DIR" ]]; then
    err "Certificate directory not found: $CERT_DIR. Run without --skip-certbot first."
fi

# =============================================================================
# 6. WRITE SSL HARDENING CONFIG
# =============================================================================

msg "Writing SSL hardening configuration..."

cat > "$SSL_CONF" <<EOF
# =============================================================================
# SSL/TLS Hardening — targets SSL Labs A+
# Generated by AwesomeArchLinux/hardening/nginx/nginx.sh
#
# NOTE: Let's Encrypt ended OCSP support in 2025.
#       ssl_stapling is intentionally disabled.
# =============================================================================

# --- Protocols: TLS 1.2 + 1.3 only ---
ssl_protocols TLSv1.2 TLSv1.3;

# --- Cipher suites ---
# TLS 1.3 ciphers are not configurable via ssl_ciphers (handled by OpenSSL).
# TLS 1.2 ciphers: ECDHE + AEAD only, server preference.
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';
ssl_prefer_server_ciphers on;

# --- ECDH curve ---
ssl_ecdh_curve X25519:secp384r1:secp256r1;

# --- DH parameters (4096-bit) ---
ssl_dhparam $DH_PARAM;

# --- Session settings ---
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:50m;

# Disable session tickets (forward secrecy for TLS 1.2)
# TLS 1.3 handles this with its own ticket mechanism
ssl_session_tickets off;

# --- OCSP Stapling ---
# Let's Encrypt ended OCSP support in 2025. Disable to avoid errors.
# ssl_stapling on;
# ssl_stapling_verify on;
# ssl_trusted_certificate $CERT_DIR/chain.pem;

# --- Certificate ---
ssl_certificate     $CERT_DIR/fullchain.pem;
ssl_certificate_key $CERT_DIR/privkey.pem;

# --- Resolver for any future OCSP or upstream needs ---
resolver 9.9.9.9 1.1.1.1 valid=300s;
resolver_timeout 5s;
EOF

# =============================================================================
# 7. WRITE SECURITY HEADERS CONFIG
# =============================================================================

msg "Writing security headers configuration..."

cat > "$SECURITY_CONF" <<'HEADERS'
# =============================================================================
# Security Headers — targets securityheaders.com A+ (all green)
# Generated by AwesomeArchLinux/hardening/nginx/nginx.sh
#
# Graded headers (securityheaders.com):
#   [1] Strict-Transport-Security (HSTS)
#   [2] Content-Security-Policy (CSP)
#   [3] Permissions-Policy
#   [4] Referrer-Policy
#   [5] X-Content-Type-Options
#   [6] X-Frame-Options
#
# Additional hardening (OWASP recommended):
#   [7] Cross-Origin-Embedder-Policy (COEP)
#   [8] Cross-Origin-Opener-Policy (COOP)
#   [9] Cross-Origin-Resource-Policy (CORP)
#   [10] X-Permitted-Cross-Domain-Policies
#   [11] Remove Server header leakage
# =============================================================================

# --- [1] HSTS: 2 years, include subdomains, preload-ready ---
# Submit to https://hstspreload.org/ after confirming it works.
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

# --- [2] Content-Security-Policy ---
# IMPORTANT: This is a strict baseline. You MUST adjust this for your application.
# - If you use inline scripts/styles, add specific hashes or nonces.
# - If you load resources from CDNs, add their origins.
# - Test thoroughly before deploying to production.
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'; upgrade-insecure-requests;" always;

# --- [3] Permissions-Policy ---
# Deny all powerful browser APIs by default. Enable only what your app needs.
add_header Permissions-Policy "accelerometer=(), autoplay=(), camera=(), cross-origin-isolated=(), display-capture=(), encrypted-media=(), fullscreen=(self), geolocation=(), gyroscope=(), keyboard-map=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=(self), usb=(), xr-spatial-tracking=()" always;

# --- [4] Referrer-Policy ---
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# --- [5] X-Content-Type-Options ---
add_header X-Content-Type-Options "nosniff" always;

# --- [6] X-Frame-Options ---
# Prevents clickjacking. Use DENY unless you need to embed in same-origin iframes.
add_header X-Frame-Options "DENY" always;

# --- [7] Cross-Origin-Embedder-Policy (COEP) ---
# Requires all cross-origin resources to opt in via CORS or CORP.
# Set to "unsafe-none" if your site loads third-party resources without CORS.
add_header Cross-Origin-Embedder-Policy "require-corp" always;

# --- [8] Cross-Origin-Opener-Policy (COOP) ---
# Isolates the browsing context to prevent XS-Leak attacks.
add_header Cross-Origin-Opener-Policy "same-origin" always;

# --- [9] Cross-Origin-Resource-Policy (CORP) ---
add_header Cross-Origin-Resource-Policy "same-origin" always;

# --- [10] X-Permitted-Cross-Domain-Policies ---
# Prevents Adobe Flash/Acrobat from loading cross-domain data.
add_header X-Permitted-Cross-Domain-Policies "none" always;

# --- [11] Remove server identification ---
# server_tokens is set to off in the main config.
# Some builds support: more_clear_headers Server;
# If using headers-more module, uncomment:
# more_clear_headers Server;
HEADERS

# =============================================================================
# 8. WRITE FINAL HTTPS SERVER BLOCK
# =============================================================================

msg "Writing final server block..."

cat > /etc/nginx/sites-enabled/default.conf <<EOF
# --- HTTP: Redirect all to HTTPS ---
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAINS[*]};

    # ACME challenge (certbot renewal)
    location ^~ /.well-known/acme-challenge/ {
        root $WEBROOT;
        allow all;
        default_type "text/plain";
        try_files \$uri =404;
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}

# --- HTTPS: Hardened server ---
server {
    listen $HTTPS_PORT ssl;
    listen [::]:$HTTPS_PORT ssl;
    http2 on;
    server_name ${DOMAINS[*]};

    root $WEBROOT;
    index index.html;

    # --- SSL (from ssl-hardening.conf) ---
    # Certificates and TLS settings are loaded via conf.d/ssl-hardening.conf

    # --- Locations ---
    location / {
        try_files \$uri \$uri/ =404;
    }

    # Block dotfiles (except .well-known)
    location ~ /\.(?!well-known) {
        deny all;
        return 404;
    }

    # Block access to sensitive files
    location ~* \.(engine|inc|info|install|make|module|profile|test|po|sh|sql|theme|tpl(\.php)?|xtmpl)\$|^(Entries.*|Repository|Root|Tag|Template|composer\.(json|lock))\$|^\# {
        deny all;
        return 404;
    }

    # Deny access to backup and source files
    location ~* \.(bak|conf|dist|fla|in[ci]|log|orig|psd|sh|sql|sw[op])\$ {
        deny all;
        return 404;
    }

    # Custom error pages
    error_page 404 /404.html;
    error_page 500 502 503 504 /50x.html;
    location = /50x.html {
        root /usr/share/nginx/html;
    }
}
EOF

# =============================================================================
# 9. CERTBOT AUTO-RENEWAL
# =============================================================================

msg "Setting up automatic certificate renewal..."

# Use systemd timer (preferred over cron on Arch)
cat > /etc/systemd/system/certbot-renew.service <<EOF
[Unit]
Description=Let's Encrypt certificate renewal
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/certbot renew --quiet --deploy-hook "systemctl reload nginx"
PrivateTmp=true
EOF

cat > /etc/systemd/system/certbot-renew.timer <<EOF
[Unit]
Description=Run certbot renewal twice daily

[Timer]
OnCalendar=*-*-* 00,12:00:00
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable certbot-renew.timer
systemctl start certbot-renew.timer

# =============================================================================
# 10. NGINX SYSTEMD HARDENING
# =============================================================================

msg "Hardening nginx systemd service..."

mkdir -p /etc/systemd/system/nginx.service.d/
cat > /etc/systemd/system/nginx.service.d/hardening.conf <<'EOF'
[Service]
# Filesystem protection
ProtectSystem=strict
ReadWritePaths=/var/log/nginx /var/cache/nginx /run
ProtectHome=yes
PrivateTmp=yes

# Kernel protection
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes

# Capabilities — nginx needs to bind to privileged ports
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_DAC_READ_SEARCH CAP_SETUID CAP_SETGID
AmbientCapabilities=CAP_NET_BIND_SERVICE

# System call filtering
SystemCallFilter=@system-service @network-io
SystemCallErrorNumber=EPERM
SystemCallArchitectures=native

# Network
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

# Misc hardening
NoNewPrivileges=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
PrivateDevices=yes
DevicePolicy=closed

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

# Restart policy
Restart=on-failure
RestartSec=5s
EOF

systemctl daemon-reload

# =============================================================================
# 11. ADDITIONAL HARDENING
# =============================================================================

msg "Applying additional hardening..."

# Restrict config file permissions
chmod 640 /etc/nginx/nginx.conf
chown root:http /etc/nginx/nginx.conf
chmod 640 "$SSL_CONF"
chmod 640 "$SECURITY_CONF"
chmod 700 "$SSL_DIR"

# Ensure log directory permissions
chmod 750 /var/log/nginx
chown http:http /var/log/nginx

# Remove default nginx welcome page if it exists
rm -f /etc/nginx/sites-enabled/example* 2>/dev/null || true

# Create a minimal index if none exists
if [[ ! -f "$WEBROOT/index.html" ]]; then
    cat > "$WEBROOT/index.html" <<'HTML'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Server</title>
</head>
<body>
    <p>It works.</p>
</body>
</html>
HTML
    chown http:http "$WEBROOT/index.html"
fi

# =============================================================================
# 12. VALIDATE AND RELOAD
# =============================================================================

msg "Testing nginx configuration..."
if nginx -t; then
    msg "Configuration test passed"
    systemctl reload nginx
    msg "nginx reloaded successfully"
else
    err "nginx configuration test failed! Check $LOGFILE"
fi

# =============================================================================
# 13. SUMMARY
# =============================================================================

echo
echo -e "${C_GREEN}========================================================================${C_NC}"
echo -e "${C_GREEN} nginx-mainline hardening complete!${C_NC}"
echo -e "${C_GREEN}========================================================================${C_NC}"
echo
echo -e "${C_BLUE}Domain(s):${C_NC}     ${DOMAINS[*]}"
echo -e "${C_BLUE}HTTPS Port:${C_NC}    $HTTPS_PORT"
echo -e "${C_BLUE}Web Root:${C_NC}      $WEBROOT"
echo -e "${C_BLUE}SSL Config:${C_NC}    $SSL_CONF"
echo -e "${C_BLUE}Headers:${C_NC}       $SECURITY_CONF"
echo -e "${C_BLUE}DH Params:${C_NC}     $DH_PARAM"
echo -e "${C_BLUE}Certificates:${C_NC}  $CERT_DIR/"
echo -e "${C_BLUE}Log:${C_NC}           $LOGFILE"
echo
echo -e "${C_BLUE}SSL/TLS Features:${C_NC}"
echo "  - TLS 1.2 + 1.3 only (no SSLv3, TLS 1.0, TLS 1.1)"
echo "  - ECDHE + AEAD ciphers only (ChaCha20-Poly1305, AES-GCM)"
echo "  - 4096-bit DH parameters"
echo "  - ECDSA P-384 certificate (Let's Encrypt)"
echo "  - Forward secrecy (session tickets disabled)"
echo "  - HTTP/2 enabled"
echo "  - OCSP stapling disabled (Let's Encrypt ended OCSP in 2025)"
echo
echo -e "${C_BLUE}Security Headers:${C_NC}"
echo "  - Strict-Transport-Security (HSTS, 2yr, preload)"
echo "  - Content-Security-Policy (strict baseline)"
echo "  - Permissions-Policy (all APIs denied by default)"
echo "  - Referrer-Policy (strict-origin-when-cross-origin)"
echo "  - X-Content-Type-Options (nosniff)"
echo "  - X-Frame-Options (DENY)"
echo "  - Cross-Origin-Embedder-Policy (require-corp)"
echo "  - Cross-Origin-Opener-Policy (same-origin)"
echo "  - Cross-Origin-Resource-Policy (same-origin)"
echo "  - X-Permitted-Cross-Domain-Policies (none)"
echo
echo -e "${C_YELLOW}IMPORTANT next steps:${C_NC}"
echo "  1. Review and customize Content-Security-Policy in:"
echo "     $SECURITY_CONF"
echo "  2. If your app loads third-party resources (CDN, APIs),"
echo "     adjust CSP, COEP, and CORP headers accordingly."
echo "  3. Test your site at:"
echo "     https://www.ssllabs.com/ssltest/analyze.html?d=$PRIMARY_DOMAIN"
echo "     https://securityheaders.com/?q=https://$PRIMARY_DOMAIN"
echo "  4. Submit for HSTS preload (after confirming everything works):"
echo "     https://hstspreload.org/?domain=$PRIMARY_DOMAIN"
echo "  5. Certificate auto-renewal is active via systemd timer."
echo "     Check: systemctl list-timers certbot-renew.timer"
echo
echo -e "${C_GREEN}Done.${C_NC}"
