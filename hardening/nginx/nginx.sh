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
#   2. Obtains Let's Encrypt certificates via certbot
#   3. Writes a hardened nginx configuration (the files it replaces are saved
#      under /var/backups/nginx-hardening/<timestamp>/ and restored on failure)
#   4. Sets up automatic certificate renewal via systemd timer
#   5. Hardens the nginx systemd service with security overrides
#   6. Verifies configuration and reloads nginx
# =============================================================================

set -euo pipefail
umask 022

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck disable=SC1090,SC1091
source "$SCRIPT_DIR/../lib/nftables.sh"
# shellcheck disable=SC1090,SC1091
source "$SCRIPT_DIR/../lib/validation.sh"

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
SECURITY_CONF="/etc/nginx/snippets/security-headers.conf"
LEGACY_SECURITY_CONF="/etc/nginx/conf.d/security-headers.conf"
SSL_CONF="/etc/nginx/conf.d/ssl-hardening.conf"
DEFAULT_SITE="/etc/nginx/sites-enabled/default.conf"
NGINX_DROPIN="/etc/systemd/system/nginx.service.d/hardening.conf"
BACKUP_ROOT="/var/backups/nginx-hardening"
BACKUP_DIR="$BACKUP_ROOT/$(date +%Y%m%d-%H%M%S)"
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
need_arg() { [[ $# -ge 2 && -n "${2:-}" ]] || err "Option $1 requires a value"; }
while [[ $# -gt 0 ]]; do
    case "$1" in
        -d)          need_arg "$@"; DOMAINS+=("$2"); shift 2 ;;
        -e)          need_arg "$@"; EMAIL="$2"; shift 2 ;;
        -w)          need_arg "$@"; WEBROOT="$2"; shift 2 ;;
        -p)          need_arg "$@"; HTTPS_PORT="$2"; shift 2 ;;
        --dry-run)   DRY_RUN=true; shift ;;
        --skip-certbot) SKIP_CERTBOT=true; shift ;;
        -h|--help)   usage ;;
        *)           err "Unknown option: $1" ;;
    esac
done

# --- Validate ---
[[ $(id -u) -eq 0 ]] || err "Must be run as root"
[[ ${#DOMAINS[@]} -gt 0 ]] || err "At least one domain is required (-d example.com)"
[[ "$HTTPS_PORT" =~ ^[0-9]+$ ]] && (( HTTPS_PORT >= 1 && HTTPS_PORT <= 65535 )) || \
    err "HTTPS port must be between 1 and 65535"
(( HTTPS_PORT != 80 )) || \
    err "HTTPS port cannot be 80 (conflicts with the port-80 HTTP redirect and ACME challenge server)"

declare -A SEEN_DOMAINS=()
declare -a NORMALIZED_DOMAINS=()
for domain in "${DOMAINS[@]}"; do
    domain="${domain,,}"
    if [[ "$SKIP_CERTBOT" == false ]]; then
        aal_valid_fqdn "$domain" || err "Invalid domain name (FQDN required): $domain"
    else
        aal_valid_hostname "$domain" || err "Invalid domain name: $domain"
    fi
    if [[ -z "${SEEN_DOMAINS[$domain]:-}" ]]; then
        NORMALIZED_DOMAINS+=("$domain")
        SEEN_DOMAINS["$domain"]=1
    fi
done
DOMAINS=("${NORMALIZED_DOMAINS[@]}")
unset SEEN_DOMAINS NORMALIZED_DOMAINS domain

# This path is used as the target of recursive chown/chmod operations. Resolve
# existing symlinks and constrain it to dedicated web-content hierarchies so a
# typo such as '-w /' cannot alter the operating system tree.
WEBROOT=$(realpath -m -- "$WEBROOT") || err "Could not resolve webroot: $WEBROOT"
case "$WEBROOT" in
    /var/www/*|/srv/http/*) ;;
    *) err "Unsafe webroot '$WEBROOT'. Use a dedicated directory below /var/www/ or /srv/http/." ;;
esac
[[ "$WEBROOT" =~ ^/(var/www|srv/http)/[A-Za-z0-9._/-]+$ ]] || \
    err "Webroot contains unsupported characters: $WEBROOT"

PRIMARY_DOMAIN="${DOMAINS[0]}"
EMAIL="${EMAIL:-webmaster@$PRIMARY_DOMAIN}"
aal_valid_email "$EMAIL" || err "Invalid certificate notification email: $EMAIL"

if (( HTTPS_PORT == 443 )); then
    HTTPS_REDIRECT_AUTHORITY='$host'
    HTTPS_URL_PORT=""
else
    HTTPS_REDIRECT_AUTHORITY="\$host:${HTTPS_PORT}"
    HTTPS_URL_PORT=":${HTTPS_PORT}"
fi

# Redirect output to logfile as well
install -o root -g root -m 0600 /dev/null "$LOGFILE"
exec > >(tee -a "$LOGFILE") 2>&1

info "Primary domain: $PRIMARY_DOMAIN"
info "All domains: ${DOMAINS[*]}"
info "Email: $EMAIL"
info "Webroot: $WEBROOT"
info "Log: $LOGFILE"

# =============================================================================
# HELPERS
# =============================================================================

# --- Backup / rollback of everything this script replaces ---
# Every run saves the previous version of each managed file below
# $BACKUP_ROOT/<timestamp>/ (root-only, outside /etc/nginx and any webroot), so
# a re-run never destroys operator changes and a failed run can be rolled back.
MANAGED_FILES=(
    "$NGINX_CONF"
    "$DEFAULT_SITE"
    "$SSL_CONF"
    "$SECURITY_CONF"
    "$LEGACY_SECURITY_CONF"
    "$NGINX_DROPIN"
    /etc/systemd/system/certbot-renew.service
    /etc/systemd/system/certbot-renew.timer
)

backup_managed_files() {
    local f
    install -d -o root -g root -m 0700 "$BACKUP_ROOT" "$BACKUP_DIR"
    for f in "${MANAGED_FILES[@]}"; do
        [[ -f "$f" ]] || continue
        install -d -m 0700 "$BACKUP_DIR${f%/*}"
        cp -p -- "$f" "$BACKUP_DIR$f"
    done
    info "Previous configuration saved to $BACKUP_DIR"
}

restore_managed_files() {
    local f
    [[ -d "$BACKUP_DIR" ]] || return 0
    for f in "${MANAGED_FILES[@]}"; do
        if [[ -f "$BACKUP_DIR$f" ]]; then
            cp -p -- "$BACKUP_DIR$f" "$f"
        else
            rm -f -- "$f"
        fi
    done
    systemctl daemon-reload || true
    warn "Restored the configuration that was in place before this run"
}

# Restore the previous configuration, put nginx back on it, and abort.
rollback_and_die() {
    local reason="$1"
    warn "$reason"
    restore_managed_files
    if nginx -t &>/dev/null; then
        if systemctl is-active --quiet nginx; then
            systemctl reload nginx 2>/dev/null || \
                warn "Could not reload nginx with the restored configuration"
        elif [[ "$NGINX_WAS_ACTIVE" == true ]]; then
            systemctl restart nginx 2>/dev/null || \
                warn "Could not restart nginx with the restored configuration"
        fi
    else
        warn "The restored configuration does not pass 'nginx -t' either; nginx was left as it is"
    fi
    err "$reason (rolled back; previous files are also kept in $BACKUP_DIR)"
}

# Reload a running nginx (no dropped connections), otherwise start it.
apply_nginx_config() {
    if systemctl is-active --quiet nginx; then
        systemctl reload nginx
    else
        systemctl start nginx
    fi
}

# Print the first vhost file other than $DEFAULT_SITE that already declares $1
# as a server_name on port 80 or the HTTPS port. nginx honours only the first
# server block per name and listen socket, so declaring such a name again in
# $DEFAULT_SITE would either shadow that site or be ignored, depending on
# include order. A vhost on another port (an app on :3000) is not a conflict.
vhost_claiming() {
    local domain="$1" f
    for f in /etc/nginx/sites-enabled/*.conf; do
        [[ -f "$f" && "$f" != "$DEFAULT_SITE" ]] || continue
        if DOMAIN_TARGET="$domain" HTTPS_PORT_TARGET="$HTTPS_PORT" awk '
            function end_block() {
                # A server block without a listen directive listens on port 80.
                if (named && (standard || !listens)) {
                    found = 1
                }
                in_server = 0
                named = 0
                standard = 0
                listens = 0
            }
            {
                line = $0
                sub(/#.*/, "", line)
                if (!in_server && line ~ /^[[:space:]]*server[[:space:]]*\{/) {
                    in_server = 1
                    depth = 0
                }
                if (!in_server) {
                    next
                }
                if (line ~ /^[[:space:]]*listen[[:space:]]/) {
                    listens = 1
                    port = line
                    sub(/^[[:space:]]*listen[[:space:]]+/, "", port)
                    sub(/[[:space:];].*/, "", port)
                    if (port !~ /^unix:/) {
                        sub(/^.*:/, "", port)
                        if (port !~ /^[0-9]+$/) {
                            port = "80"
                        }
                        if (port == "80" || port == ENVIRON["HTTPS_PORT_TARGET"]) {
                            standard = 1
                        }
                    }
                } else if (line ~ /^[[:space:]]*server_name[[:space:]]/) {
                    names_line = line
                    sub(/^[[:space:]]*server_name[[:space:]]+/, "", names_line)
                    sub(/;.*/, "", names_line)
                    n = split(names_line, names, /[[:space:]]+/)
                    for (i = 1; i <= n; i++) {
                        if (tolower(names[i]) == ENVIRON["DOMAIN_TARGET"]) {
                            named = 1
                        }
                    }
                }
                opens = gsub(/\{/, "{", line)
                closes = gsub(/\}/, "}", line)
                depth += opens - closes
                if (depth <= 0) {
                    end_block()
                }
            }
            END {
                if (in_server) {
                    end_block()
                }
                exit !found
            }
        ' "$f"; then
            printf '%s\n' "$f"
            return 0
        fi
    done
    return 1
}

# Print the directory a vhost generated by ../wordpress/wordpress.sh or
# ../react/react.sh serves /.well-known/acme-challenge/ from (the
# "# ACME-Webroot:" line in its header).
vhost_acme_root() {
    local root
    root=$(awk '/^# ACME-Webroot:[[:space:]]/ { print $3; exit }' "$1")
    [[ "$root" =~ ^/[A-Za-z0-9._/-]+$ && -d "$root" ]] || return 1
    printf '%s\n' "$root"
}

NGINX_WAS_ACTIVE=false
if systemctl is-active --quiet nginx 2>/dev/null; then
    NGINX_WAS_ACTIVE=true
fi

# A usable certificate from an earlier run means the TLS vhost can stay in place
# for the whole run instead of being swapped for the HTTP-only ACME bootstrap
# vhost until certbot has finished.
CERT_DIR="/etc/letsencrypt/live/$PRIMARY_DOMAIN"
HAVE_CERT=false
if [[ -s "$CERT_DIR/fullchain.pem" && -s "$CERT_DIR/privkey.pem" ]]; then
    HAVE_CERT=true
fi
[[ "$SKIP_CERTBOT" == false || "$HAVE_CERT" == true ]] || \
    err "No certificate found in $CERT_DIR. Run without --skip-certbot first."

# =============================================================================
# 1. INSTALL PACKAGES
# =============================================================================

msg "Installing nginx-mainline and certbot..."

# nginx-mainline is in the official Arch repos
pacman -Syu --noconfirm --needed nginx-mainline certbot certbot-nginx openssl

# Verify nginx version supports TLS 1.3
NGINX_VER=$(nginx -v 2>&1 | grep -oP '[\d.]+' | head -n 1 || true)
info "nginx version: $NGINX_VER"

# =============================================================================
# 2. PREPARE DIRECTORIES
# =============================================================================

msg "Preparing web directories..."
WEBROOT_PREEXISTED=false
if [[ -d "$WEBROOT" ]]; then
    WEBROOT_PREEXISTED=true
fi
mkdir -p "$WEBROOT/.well-known/acme-challenge"
# The selected content hierarchy must be traversable so http and certbot can
# reach the webroot.
if [[ "$WEBROOT" == /var/www/* ]]; then
    chmod 755 /var/www
else
    chmod 755 /srv /srv/http
fi

# Web content is served read-only: the http workers only need to read it, so it
# stays owned by root (or by whoever deploys it) and is never handed to the
# worker user. An existing tree is not re-owned or re-moded recursively either:
# it may hold application-writable directories or files that are deliberately
# not world-readable (a WordPress wp-config.php, for example).
if [[ "$WEBROOT_PREEXISTED" == false ]]; then
    chown -R root:root "$WEBROOT"
    chmod -R u=rwX,go=rX "$WEBROOT"
else
    info "Existing content in $WEBROOT keeps its current ownership and permissions"
    if ! runuser -u http -- test -r "$WEBROOT/.well-known/acme-challenge" 2>/dev/null; then
        # Open only what the ACME challenge needs: search permission on the
        # webroot itself, read + search on the challenge directories.
        chmod o+x "$WEBROOT"
        chmod o+rx "$WEBROOT/.well-known" "$WEBROOT/.well-known/acme-challenge"
    fi
    if ! runuser -u http -- test -r "$WEBROOT/.well-known/acme-challenge" 2>/dev/null; then
        warn "The http user cannot read $WEBROOT/.well-known/acme-challenge — ACME challenges will fail until its permissions are fixed"
    fi
fi

# Log directory: root-owned, as packaged on Arch. The master process runs as
# root, follows symlinks when it (re)opens a log and then chowns the file to the
# worker user, so a directory writable by http would let a compromised worker
# point that open + chown at any file on the system (the CVE-2016-1247 pattern).
# http owns only the log files themselves, which is also what the packaged
# logrotate policy ("create 640 http root") produces.
install -d -o root -g root -m 0755 /var/log/nginx
for nginx_log in access.log error.log; do
    if [[ ! -e "/var/log/nginx/$nginx_log" && ! -L "/var/log/nginx/$nginx_log" ]]; then
        install -o http -g root -m 0640 /dev/null "/var/log/nginx/$nginx_log"
    fi
done
unset nginx_log
while IFS= read -r nginx_log_link; do
    warn "Symlink in the nginx log directory: $nginx_log_link -> $(readlink -- "$nginx_log_link") (nginx follows it as root; remove it unless it is intentional)"
done < <(find /var/log/nginx -maxdepth 1 -type l 2>/dev/null)
unset nginx_log_link

install -d -o root -g root -m 0755 /var/cache/nginx
for cache_subdir in client_temp proxy_temp fastcgi_temp uwsgi_temp scgi_temp; do
    install -d -o http -g root -m 0700 "/var/cache/nginx/$cache_subdir"
done
install -d -o root -g root -m 0755 /etc/nginx /etc/nginx/conf.d /etc/nginx/sites-enabled /etc/nginx/snippets

# Names that another vhost file already serves stay with that vhost: only the
# remaining ones are declared in $DEFAULT_SITE. The certificate still covers
# every requested name; a claimed name is validated through the webroot its own
# vhost announces, falling back to $WEBROOT.
declare -a SITE_DOMAINS=()
declare -a CLAIMING_VHOSTS=()
declare -A ACME_ROOT=()
for d in "${DOMAINS[@]}"; do
    ACME_ROOT["$d"]="$WEBROOT"
    if claiming_vhost=$(vhost_claiming "$d"); then
        if [[ " ${CLAIMING_VHOSTS[*]} " != *" $claiming_vhost "* ]]; then
            CLAIMING_VHOSTS+=("$claiming_vhost")
        fi
        if claimed_acme_root=$(vhost_acme_root "$claiming_vhost"); then
            ACME_ROOT["$d"]="$claimed_acme_root"
            info "$d is already served by $claiming_vhost — not declaring it in $DEFAULT_SITE (ACME webroot: $claimed_acme_root)"
        else
            warn "$d is already served by $claiming_vhost — not declaring it in $DEFAULT_SITE."
            warn "  That vhost must serve /.well-known/acme-challenge/ from $WEBROOT for issuance and renewal to work."
        fi
    else
        SITE_DOMAINS+=("$d")
    fi
done
unset d claiming_vhost claimed_acme_root

# =============================================================================
# 3. WRITE NGINX CONFIG (plus an HTTP-only ACME vhost on first issuance)
# =============================================================================

msg "Writing nginx configuration..."

backup_managed_files

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

    # --- Temp paths ---
    # Request bodies larger than client_body_buffer_size and buffered upstream
    # responses are spooled to disk and fail with a 500 when these directories
    # are not writable. Use the directories nginx.sh creates below
    # /var/cache/nginx, which the hardened unit (ProtectSystem=strict) keeps
    # writable, rather than the compiled-in defaults.
    client_body_temp_path /var/cache/nginx/client_temp;
    proxy_temp_path       /var/cache/nginx/proxy_temp;
    fastcgi_temp_path     /var/cache/nginx/fastcgi_temp;
    uwsgi_temp_path       /var/cache/nginx/uwsgi_temp;
    scgi_temp_path        /var/cache/nginx/scgi_temp;

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

# Write a temporary HTTP-only server for the ACME challenge. Only needed for the
# first issuance: with a certificate already on disk the existing TLS vhost keeps
# serving until the refreshed one is written in Step 7.
if [[ "$HAVE_CERT" == true ]]; then
    info "Existing certificate found in $CERT_DIR — keeping the current TLS vhost online during this run"
elif (( ${#SITE_DOMAINS[@]} > 0 )); then
    cat > "$DEFAULT_SITE" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${SITE_DOMAINS[*]};

    # ACME challenge
    location ^~ /.well-known/acme-challenge/ {
        root $WEBROOT;
        allow all;
        default_type "text/plain";
        try_files \$uri =404;
    }

    # Redirect everything else to HTTPS
    location / {
        return 301 https://${HTTPS_REDIRECT_AUTHORITY}\$request_uri;
    }
}
EOF
else
    printf '%s\n' "# Every requested name is served by its own vhost file in this directory." > "$DEFAULT_SITE"
fi

# Remove any legacy http-level security-headers.conf so plain HTTP never emits HSTS
rm -f -- "$LEGACY_SECURITY_CONF"

# If ssl-hardening.conf remains from a prior run whose referenced cert/key files
# no longer exist on disk, remove it before testing/starting the ACME server so
# Step 3 does not deadlock before Step 4 Certbot runs.
if [[ -f "$SSL_CONF" ]]; then
    SSL_REFS_MISSING=false
    while IFS= read -r ssl_ref_path; do
        [[ -n "$ssl_ref_path" ]] || continue
        if [[ ! -f "$ssl_ref_path" ]]; then
            SSL_REFS_MISSING=true
            break
        fi
    done < <(awk '
        /^[[:space:]]*ssl_(trusted_)?certificate(_key)?[[:space:]]+/ {
            line = $0
            sub(/^[[:space:]]*ssl_(trusted_)?certificate(_key)?[[:space:]]+/, "", line)
            sub(/[[:space:]]*;.*$/, "", line)
            gsub(/^["'\'']|["'\'']$/, "", line)
            print line
        }
    ' "$SSL_CONF")
    if [[ "$SSL_REFS_MISSING" == true ]]; then
        warn "Removing stale $SSL_CONF (referenced certificate/key missing on disk)"
        rm -f -- "$SSL_CONF"
    fi
    unset SSL_REFS_MISSING ssl_ref_path
fi

# Test and start nginx (first issuance only; see Step 7 for the re-run path)
if [[ "$HAVE_CERT" == false ]]; then
    nginx -t || rollback_and_die "nginx config test failed"
    systemctl enable nginx
    apply_nginx_config || rollback_and_die "nginx could not be started with the ACME bootstrap configuration"
fi

# =============================================================================
# 3b. OPEN FIREWALL PORTS (80/443)
# =============================================================================

msg "Opening firewall ports 80 (HTTP) and $HTTPS_PORT (HTTPS)..."
if command -v nft &>/dev/null && nft list chain inet filter input &>/dev/null 2>&1; then
    # Remove the legacy fallback service if this host has moved to the
    # installer-owned nftables ruleset.
    if [[ -x /usr/local/bin/awesome-nginx-iptables ]]; then
        /usr/local/bin/awesome-nginx-iptables stop || \
            err "Could not remove the legacy nginx iptables chain"
    fi
    if [[ -f /etc/systemd/system/awesome-nginx-firewall.service ]]; then
        systemctl disable awesome-nginx-firewall.service
    fi
    aal_nft_persist_block "nginx" <<EOF
insert rule inet filter input ct state new tcp dport 80 accept comment "awesome-nginx-http"
insert rule inet filter input ct state new tcp dport $HTTPS_PORT accept comment "awesome-nginx-https"
EOF
    aal_nft_remove_live_rules inet filter input "awesome-nginx-http"
    aal_nft_remove_live_rules inet filter input "awesome-nginx-https"
    nft insert rule inet filter input ct state new tcp dport 80 accept comment "awesome-nginx-http"
    nft insert rule inet filter input ct state new tcp dport "$HTTPS_PORT" accept comment "awesome-nginx-https"
    # The inserts above landed in front of the drop-only guard blocks (Docker
    # isolation, ...); put those back on top, as in the persisted ruleset.
    # Guarded: an older copy of the library does not have this helper.
    if declare -F aal_nft_raise_guard_rules >/dev/null; then
        aal_nft_raise_guard_rules || \
            warn "Could not re-order the live guard rules; reload nftables to apply the persisted order."
    fi
    msg "nftables: ports 80/$HTTPS_PORT opened without replacing the live ruleset."
elif command -v iptables &>/dev/null && iptables -L -n &>/dev/null 2>&1; then
    install -d -o root -g root -m 0755 /etc/default
    install -d -o root -g root -m 0755 /usr/local/bin
    cat > /etc/default/awesome-nginx-firewall <<EOF
HTTP_PORT=80
HTTPS_PORT=$HTTPS_PORT
EOF
    chmod 0600 /etc/default/awesome-nginx-firewall

    cat > /usr/local/bin/awesome-nginx-iptables <<'NGINX_IPTABLES'
#!/usr/bin/env bash
set -euo pipefail
umask 022

CONFIG=${AAL_NGINX_FIREWALL_CONFIG:-/etc/default/awesome-nginx-firewall}
IPTABLES_BIN=${AAL_IPTABLES_BIN:-iptables}
IP6TABLES_BIN=${AAL_IP6TABLES_BIN:-ip6tables}
CHAIN=AWESOME_NGINX

[[ -r "$CONFIG" ]] || { printf 'Firewall configuration is unreadable: %s\n' "$CONFIG" >&2; exit 1; }
# shellcheck disable=SC1090
source "$CONFIG"
for port in "${HTTP_PORT:-}" "${HTTPS_PORT:-}"; do
    [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 )) || {
        printf 'Invalid nginx firewall port: %s\n' "$port" >&2
        exit 1
    }
done

family_available() {
    command -v "$1" &>/dev/null && "$1" -L INPUT -n &>/dev/null
}

start_family() {
    local command=$1

    if "$command" -L "$CHAIN" -n &>/dev/null; then
        "$command" -F "$CHAIN"
    else
        "$command" -N "$CHAIN"
    fi
    "$command" -A "$CHAIN" -p tcp --dport "$HTTP_PORT" -j ACCEPT
    if [[ "$HTTPS_PORT" != "$HTTP_PORT" ]]; then
        "$command" -A "$CHAIN" -p tcp --dport "$HTTPS_PORT" -j ACCEPT
    fi
    if ! "$command" -C INPUT -j "$CHAIN" &>/dev/null; then
        "$command" -I INPUT 1 -j "$CHAIN"
    fi
}

stop_family() {
    local command=$1

    while "$command" -C INPUT -j "$CHAIN" &>/dev/null; do
        "$command" -D INPUT -j "$CHAIN"
    done
    if "$command" -L "$CHAIN" -n &>/dev/null; then
        "$command" -F "$CHAIN"
        "$command" -X "$CHAIN"
    fi
}

case "${1:-}" in
    start)
        family_available "$IPTABLES_BIN" || {
            printf 'iptables INPUT chain is unavailable\n' >&2
            exit 1
        }
        start_family "$IPTABLES_BIN"
        if family_available "$IP6TABLES_BIN"; then
            start_family "$IP6TABLES_BIN"
        fi
        ;;
    stop)
        if family_available "$IPTABLES_BIN"; then
            stop_family "$IPTABLES_BIN"
        fi
        if family_available "$IP6TABLES_BIN"; then
            stop_family "$IP6TABLES_BIN"
        fi
        ;;
    *)
        printf 'Usage: %s {start|stop}\n' "$0" >&2
        exit 2
        ;;
esac
NGINX_IPTABLES
    chmod 0755 /usr/local/bin/awesome-nginx-iptables

    cat > /etc/systemd/system/awesome-nginx-firewall.service <<'EOF'
[Unit]
Description=AwesomeArchLinux nginx iptables fallback
After=network-pre.target iptables.service ip6tables.service
Before=nginx.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/awesome-nginx-iptables start
ExecReload=/usr/local/bin/awesome-nginx-iptables start
ExecStop=/usr/local/bin/awesome-nginx-iptables stop
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    chmod 0644 /etc/systemd/system/awesome-nginx-firewall.service
    systemctl daemon-reload
    /usr/local/bin/awesome-nginx-iptables start
    systemctl enable awesome-nginx-firewall.service
    msg "iptables: managed IPv4/IPv6 chain opened ports 80/$HTTPS_PORT without snapshotting the live ruleset."
else
    warn "No supported firewall detected — ensure ports 80/$HTTPS_PORT are reachable."
fi

# =============================================================================
# 4. OBTAIN CERTIFICATES
# =============================================================================

run_certbot() {
    local d acme_root prev_root=""

    msg "Obtaining Let's Encrypt certificates..."

    CERTBOT_ARGS=(
        certonly
        --non-interactive
        --webroot
        --cert-name "$PRIMARY_DOMAIN"
        --expand
        --email "$EMAIL"
        --agree-tos
        --no-eff-email
        --key-type ecdsa
        --elliptic-curve secp384r1
    )

    # certbot applies each -w to the -d options that follow it.
    for d in "${DOMAINS[@]}"; do
        acme_root="${ACME_ROOT[$d]}"
        if [[ "$acme_root" != "$prev_root" ]]; then
            CERTBOT_ARGS+=(-w "$acme_root")
            prev_root="$acme_root"
        fi
        CERTBOT_ARGS+=(-d "$d")
    done

    if [[ "$DRY_RUN" == true ]]; then
        CERTBOT_ARGS+=(--staging --keep-until-expiring)
        warn "Using Let's Encrypt STAGING server (certificates will NOT be trusted)"
    elif [[ -f "$CERT_DIR/cert.pem" ]] && \
         openssl x509 -in "$CERT_DIR/cert.pem" -noout -issuer 2>/dev/null | grep -qiE 'Staging|Fake LE'; then
        CERTBOT_ARGS+=(--force-renewal)
        info "Existing staging certificate detected in $CERT_DIR; forcing production renewal"
    else
        CERTBOT_ARGS+=(--keep-until-expiring)
    fi

    certbot "${CERTBOT_ARGS[@]}"
}

if [[ "$SKIP_CERTBOT" == true ]]; then
    info "Skipping certbot (--skip-certbot)"
elif [[ "$HAVE_CERT" == false ]]; then
    run_certbot || rollback_and_die "certbot could not obtain a certificate for ${DOMAINS[*]}"
else
    info "certbot runs after the TLS vhost has been refreshed (Step 7)"
fi

# Verify certificate exists
if [[ ! -d "$CERT_DIR" ]]; then
    err "Certificate directory not found: $CERT_DIR. Run without --skip-certbot first."
fi

# =============================================================================
# 5. WRITE SSL HARDENING CONFIG
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
# 6. WRITE SECURITY HEADERS CONFIG
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
# Practical baseline that works with Google Fonts, analytics, and common CDNs.
# Review and tighten for your specific application.
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' https://www.googletagmanager.com https://www.google-analytics.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data: https://*.google-analytics.com https://*.googletagmanager.com; font-src 'self' https://fonts.gstatic.com; connect-src 'self' https://www.google-analytics.com https://*.google-analytics.com https://*.analytics.google.com https://*.googletagmanager.com; frame-ancestors 'none'; form-action 'self'; base-uri 'self'; upgrade-insecure-requests" always;

# --- [3] Permissions-Policy ---
# Deny all powerful browser APIs by default. Enable only what your app needs.
add_header Permissions-Policy "accelerometer=(), autoplay=(), camera=(), display-capture=(), encrypted-media=(), fullscreen=(self), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), usb=(), xr-spatial-tracking=()" always;

# --- [4] Referrer-Policy ---
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# --- [5] X-Content-Type-Options ---
add_header X-Content-Type-Options "nosniff" always;

# --- [6] X-Frame-Options ---
# Prevents clickjacking. SAMEORIGIN allows same-origin iframes (OAuth popups, payment gateways).
add_header X-Frame-Options "SAMEORIGIN" always;

# --- [7] Cross-Origin-Embedder-Policy (COEP) ---
# Set to "unsafe-none" because we load cross-origin resources (Google Fonts,
# Analytics) that don't set CORP/CORS headers. Use "require-corp" only for
# sites that serve all resources from same-origin or CORS-enabled CDNs.
add_header Cross-Origin-Embedder-Policy "unsafe-none" always;

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
# 7. WRITE FINAL HTTPS SERVER BLOCK
# =============================================================================

msg "Writing final server block..."

if (( ${#SITE_DOMAINS[@]} == 0 )); then
    printf '%s\n' "# Every requested name is served by its own vhost file in this directory." > "$DEFAULT_SITE"
    info "No server block written to $DEFAULT_SITE: every requested name already has its own vhost"
else
cat > "$DEFAULT_SITE" <<EOF
# --- HTTP: Redirect all to HTTPS ---
server {
    listen 80;
    listen [::]:80;
    server_name ${SITE_DOMAINS[*]};

    # ACME challenge (certbot renewal)
    location ^~ /.well-known/acme-challenge/ {
        root $WEBROOT;
        allow all;
        default_type "text/plain";
        try_files \$uri =404;
    }

    location / {
        return 301 https://${HTTPS_REDIRECT_AUTHORITY}\$request_uri;
    }
}

# --- HTTPS: Hardened server ---
server {
    listen $HTTPS_PORT ssl;
    listen [::]:$HTTPS_PORT ssl;
    http2 on;
    server_name ${SITE_DOMAINS[*]};

    root $WEBROOT;
    index index.html;

    # --- SSL (from ssl-hardening.conf) ---
    # Certificates and TLS settings are loaded via conf.d/ssl-hardening.conf

    # --- Security headers (HTTPS only — avoids emitting HSTS over plain HTTP) ---
    include /etc/nginx/snippets/security-headers.conf;

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
    location ~* \.(engine|inc|info|install|make|module|profile|test|po|sh|sql|theme|tpl(\.php)?|xtmpl)\$|(?:^|/)(Entries.*|Repository|Root|Tag|Template|composer\.(json|lock))\$|(?:^|/)\# {
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
fi

# Re-run path: the TLS vhost never left service. Validate and load the refreshed
# configuration first, then let certbot renew or extend the certificate through
# the port-80 ACME location that is now live.
if [[ "$HAVE_CERT" == true ]]; then
    nginx -t || rollback_and_die "nginx configuration test failed"
    systemctl enable nginx
    apply_nginx_config || rollback_and_die "nginx could not load the refreshed configuration"
    if [[ "$SKIP_CERTBOT" == false ]]; then
        run_certbot || \
            err "certbot failed. nginx keeps serving the existing certificate in $CERT_DIR; fix the problem reported above and re-run."
    fi
fi

# =============================================================================
# 8. CERTBOT AUTO-RENEWAL
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

chmod 0644 /etc/systemd/system/certbot-renew.service /etc/systemd/system/certbot-renew.timer
systemctl daemon-reload
systemctl enable certbot-renew.timer
systemctl start certbot-renew.timer

# =============================================================================
# 9. NGINX SYSTEMD HARDENING
# =============================================================================

msg "Hardening nginx systemd service..."

install -d -o root -g root -m 0755 /etc/systemd/system/nginx.service.d
cat > "$NGINX_DROPIN" <<'EOF'
[Service]
# Filesystem protection
ProtectSystem=strict
# The only path below /run the master writes is its PID file, so /run as a whole
# stays read-only (a writable /run would let a compromised master drop files
# into /run/systemd, /run/udev, ...). The file is created outside the sandbox
# ("+") before every start so it can be bound read-write on its own.
# Side effects, both harmless: until the master has written its PID systemd may
# log one informational "Failed to create reference to PID" line per start, and
# nginx cannot unlink a bind-mounted file, so every stop logs one
# 'unlink() "/run/nginx.pid" failed' alert (systemd removes the file itself).
ExecStartPre=+/usr/bin/install -o root -g root -m 0644 /dev/null /run/nginx.pid
ReadWritePaths=/var/log/nginx /var/cache/nginx -/var/lib/nginx -/run/nginx.pid
ProtectHome=yes
PrivateTmp=yes
# New log files are created 0640, never world-readable
UMask=0027

# Kernel protection
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes

# Capabilities — master binds privileged ports, manages temp/log files, signals http workers, and drops to http
CapabilityBoundingSet=
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_CHOWN CAP_SETUID CAP_SETGID CAP_KILL

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
chmod 0644 "$NGINX_DROPIN"

systemctl daemon-reload

# =============================================================================
# 10. ADDITIONAL HARDENING
# =============================================================================

msg "Applying additional hardening..."

# Restrict config file permissions while keeping snippets readable by http
chown root:http "$NGINX_CONF" "$SSL_CONF" "$SECURITY_CONF" "$DEFAULT_SITE"
chmod 0640 "$NGINX_CONF" "$SSL_CONF" "$SECURITY_CONF" "$DEFAULT_SITE"

# Ensure log directory permissions (root-owned, never writable by http; see Step 2)
chown root:root /var/log/nginx
chmod 0755 /var/log/nginx

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
    chown root:root "$WEBROOT/index.html"
    chmod 0644 "$WEBROOT/index.html"
fi

# =============================================================================
# 11. VALIDATE AND RESTART
# =============================================================================

msg "Testing nginx configuration..."
if nginx -t; then
    msg "Configuration test passed"
    # A restart (not a reload) is required for the systemd sandbox to apply.
    if systemctl restart nginx && systemctl is-active --quiet nginx; then
        msg "nginx restarted and running cleanly under hardened systemd unit"
    else
        journalctl -u nginx -n 20 --no-pager 2>/dev/null || true
        rollback_and_die "nginx failed to stay active after the restart (see the journal excerpt above)"
    fi
else
    rollback_and_die "nginx configuration test failed! Check $LOGFILE"
fi

# =============================================================================
# 12. SUMMARY
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
echo -e "${C_BLUE}Certificates:${C_NC}  $CERT_DIR/"
echo -e "${C_BLUE}Backup:${C_NC}        $BACKUP_DIR/ (configuration replaced by this run)"
echo -e "${C_BLUE}Log:${C_NC}           $LOGFILE"
echo
echo -e "${C_BLUE}SSL/TLS Features:${C_NC}"
echo "  - TLS 1.2 + 1.3 only (no SSLv3, TLS 1.0, TLS 1.1)"
echo "  - ECDHE + AEAD ciphers only (ChaCha20-Poly1305, AES-GCM)"
echo "  - ECDSA P-384 certificate (Let's Encrypt)"
echo "  - Forward secrecy (session tickets disabled)"
echo "  - HTTP/2 enabled"
echo "  - OCSP stapling disabled (Let's Encrypt ended OCSP in 2025)"
echo
echo -e "${C_BLUE}Security Headers:${C_NC}"
echo "  - Strict-Transport-Security (HSTS, 2yr, preload)"
echo "  - Content-Security-Policy (practical baseline)"
echo "  - Permissions-Policy (all APIs denied by default)"
echo "  - Referrer-Policy (strict-origin-when-cross-origin)"
echo "  - X-Content-Type-Options (nosniff)"
echo "  - X-Frame-Options (SAMEORIGIN)"
echo "  - Cross-Origin-Embedder-Policy (unsafe-none)"
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
echo "     https://securityheaders.com/?q=https://${PRIMARY_DOMAIN}${HTTPS_URL_PORT}"
echo "  4. Submit for HSTS preload (after confirming everything works):"
echo "     https://hstspreload.org/?domain=$PRIMARY_DOMAIN"
echo "  5. Certificate auto-renewal is active via systemd timer."
echo "     Check: systemctl list-timers certbot-renew.timer"
if (( ${#CLAIMING_VHOSTS[@]} > 0 )); then
    echo "  6. Some requested names are served by their own vhost file, which this script"
    echo "     does not rewrite. Re-run the script that generated it (e.g. ../wordpress/wordpress.sh"
    echo "     or ../react/react.sh) so the vhost picks up the certificate:"
    printf '       %s\n' "${CLAIMING_VHOSTS[@]}"
fi
echo
echo -e "${C_GREEN}Done.${C_NC}"
