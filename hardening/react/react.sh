#!/usr/bin/env bash

# =============================================================================
# Script:      react.sh
# Description: Hardens the serving infrastructure for a React (or any SPA)
#              production deployment on Arch Linux via nginx, targeting:
#                - Secure nginx server block with SPA routing
#                - Content-Security-Policy tuned for React
#                - Aggressive static asset caching with immutable headers
#                - Source map and dotfile protection
#                - Rate limiting for API proxy endpoints
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
#
# Usage:       sudo ./react.sh -a APP_PATH [-p PORT] [-d DOMAIN] [-h]
#
# Requirements:
#   - Arch Linux with pacman
#   - Root privileges
#   - nginx-mainline installed (see ../nginx/nginx.sh)
#   - A pre-built React app (this script does NOT install Node.js or build)
#
# What this script does:
#   1. Detects the SPA build directory (dist/, build/, out/, or root)
#   2. Writes a hardened nginx server block with SPA routing
#   3. Configures Content-Security-Policy tuned for React production
#   4. Sets security headers (X-Content-Type-Options, COOP, CORP, etc.)
#   5. Configures aggressive caching for hashed assets, no-cache for index
#   6. Blocks source maps and dotfiles in production
#   7. Sets up rate limiting template for API proxy
#   8. Locks down file permissions on the build directory
#   9. Creates a .env.production.example template
# =============================================================================

set -euo pipefail
umask 022

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
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
APP_PATH=""
PORT=3000
DOMAIN="localhost"
BACKUP_ROOT="/var/backups/react-hardening"

# --- Usage ---
usage() {
    cat <<EOF
Usage: sudo $0 [options]

Required:
  -a APP_PATH   Path to the React app (project root or build directory)

Optional:
  -p PORT       Listening port (default: $PORT). With certificates for DOMAIN,
                80 or 443 serves HTTPS on 443 and redirects port 80
  -d DOMAIN     Server name / domain (default: $DOMAIN)
  -h            Show this help

Examples:
  sudo $0 -a /var/www/myapp
  sudo $0 -a /var/www/myapp -p 8080 -d app.example.com
  sudo $0 -a /var/www/myapp/dist -d app.example.com
EOF
    exit 0
}

# --- Parse Arguments ---
need_arg() { [[ $# -ge 2 && -n "${2:-}" ]] || err "Option $1 requires a value"; }
while [[ $# -gt 0 ]]; do
    case "$1" in
        -a)         need_arg "$@"; APP_PATH="$2"; shift 2 ;;
        -p)         need_arg "$@"; PORT="$2"; shift 2 ;;
        -d)         need_arg "$@"; DOMAIN="$2"; shift 2 ;;
        -h|--help)  usage ;;
        *)          err "Unknown option: $1" ;;
    esac
done

# --- Validate ---
[[ $(id -u) -eq 0 ]] || err "Must be run as root"
[[ -n "$APP_PATH" ]] || err "App path is required (-a /path/to/app)"
[[ -d "$APP_PATH" ]] || err "App path does not exist: $APP_PATH"
DOMAIN="${DOMAIN,,}"
aal_valid_hostname "$DOMAIN" || err "Invalid domain name: $DOMAIN"

APP_PATH=$(realpath -- "$APP_PATH") || err "Could not resolve application path"
case "$APP_PATH" in
    /var/www/*|/srv/http/*) ;;
    *) err "Unsafe application path '$APP_PATH'. Use a dedicated directory below /var/www/ or /srv/http/." ;;
esac
[[ "$APP_PATH" =~ ^/(var/www|srv/http)/[A-Za-z0-9._/-]+$ ]] || \
    err "Application path contains unsupported characters: $APP_PATH"

# Validate PORT is a number in valid range
if ! [[ "$PORT" =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then
    err "Invalid port: $PORT (must be 1-65535)"
fi

# =============================================================================
# 1. DETECT BUILD DIRECTORY
# =============================================================================

msg "Detecting build directory..."

BUILD_DIR=""

# Look for build output first. A Vite project keeps its *source* index.html in
# the project root, so preferring APP_PATH/index.html would publish the project
# root (sources, package.json, node_modules) instead of the bundle in dist/.
for candidate in dist build out; do
    if [[ -f "$APP_PATH/$candidate/index.html" ]]; then
        BUILD_DIR="$APP_PATH/$candidate"
        info "Found build directory: $BUILD_DIR (detected $candidate/)"
        break
    fi
done

# Otherwise APP_PATH itself is the build directory (contains index.html)
if [[ -z "$BUILD_DIR" && -f "$APP_PATH/index.html" ]]; then
    BUILD_DIR="$APP_PATH"
    info "Build directory is APP_PATH itself: $BUILD_DIR"
    if [[ -f "$APP_PATH/package.json" ]]; then
        warn "$APP_PATH contains package.json and index.html but no dist/, build/ or out/ output."
        warn "It looks like an unbuilt project root: the whole directory (sources, package.json) will be served."
        warn "Run your build (e.g. npm run build) and re-run this script, or pass the build directory with -a."
    fi
fi

if [[ -z "$BUILD_DIR" ]]; then
    err "No index.html found in $APP_PATH or its dist/, build/, out/ subdirectories.
     Build your app first (e.g., npm run build) before running this script."
fi

# Resolve to absolute path
BUILD_DIR="$(cd "$BUILD_DIR" && pwd)"
info "Build directory: $BUILD_DIR"
info "Domain: $DOMAIN"
info "Port: $PORT"

# =============================================================================
# 2. ENSURE NGINX IS INSTALLED
# =============================================================================

msg "Verifying nginx is installed..."

if ! command -v nginx &>/dev/null; then
    err "nginx is not installed. Run ../nginx/nginx.sh first or: pacman -S nginx-mainline"
fi

info "nginx found: $(nginx -v 2>&1)"

# Ensure directories exist and sites-enabled is included by nginx.conf
install -d -m 0755 /etc/nginx/sites-enabled /etc/nginx/conf.d

if [[ -f /etc/nginx/nginx.conf ]] && ! grep -Eq '^[[:space:]]*include[[:space:]]+/etc/nginx/sites-enabled/' /etc/nginx/nginx.conf; then
    cp /etc/nginx/nginx.conf "/etc/nginx/nginx.conf.bak.$(date +%Y%m%d-%H%M%S)"
    NGINX_TMP=$(mktemp /etc/nginx/.nginx.conf.XXXXXX)
    awk '
        !inserted && /^[[:space:]]*http[[:space:]]*\{/ { in_http = 1 }
        in_http {
            line = $0
            gsub(/#.*/, "", line)
            opens = gsub(/\{/, "{", line)
            closes = gsub(/\}/, "}", line)
            depth += opens - closes
            if (depth == 0) {
                print "    include /etc/nginx/sites-enabled/*.conf;"
                in_http = 0
                inserted = 1
            }
        }
        { print }
    ' /etc/nginx/nginx.conf > "$NGINX_TMP"
    install -o root -g root -m 0644 "$NGINX_TMP" /etc/nginx/nginx.conf
    rm -f -- "$NGINX_TMP"
    info "Added sites-enabled include to /etc/nginx/nginx.conf"
fi

# =============================================================================
# 3. DETECT SSL CERTIFICATES
# =============================================================================

USE_SSL=false
CERT_DIR="/etc/letsencrypt/live/$DOMAIN"

if [[ -f "$CERT_DIR/fullchain.pem" && -f "$CERT_DIR/privkey.pem" ]]; then
    USE_SSL=true
    msg "SSL certificates found for $DOMAIN"
else
    warn "No SSL certificates found at $CERT_DIR"
    warn "Configuring HTTP-only. Run ../nginx/nginx.sh for HTTPS setup."
fi

# TLS belongs on 443: "-p 80" with certificates present would put an "ssl"
# listener on the plain-HTTP port. Serve HTTPS on 443 instead and keep port 80
# for the redirect and the ACME challenge.
if [[ "$USE_SSL" == true && "$PORT" == "80" ]]; then
    warn "Certificates found: serving HTTPS on port 443 and redirecting port 80 to it"
    PORT=443
fi

# On the standard web ports (HTTP on 80, or HTTPS on 443 with the port-80
# redirect) this vhost owns the name: it answers the ACME challenge on port 80
# and replaces whatever default.conf declared for it.
STANDARD_PORT=false
if [[ ( "$USE_SSL" == true && "$PORT" == "443" ) || ( "$USE_SSL" == false && "$PORT" == "80" ) ]]; then
    STANDARD_PORT=true
elif [[ "$PORT" == "443" ]]; then
    warn "No certificate in $CERT_DIR: this vhost will listen on port 443 without TLS settings of its own."
    warn "Use -p 80 until a certificate exists for $DOMAIN (../nginx/nginx.sh), then re-run with -p 443."
fi

# =============================================================================
# 4. WRITE NGINX SERVER BLOCK
# =============================================================================

CONF_FILE="/etc/nginx/sites-enabled/${DOMAIN}.conf"
CONF_BACKUP=""
CONF_PREEXISTED=false
DEFAULT_SITE="/etc/nginx/sites-enabled/default.conf"
DEFAULT_SITE_BACKUP=""

restore_nginx_conf() {
    if [[ "$CONF_PREEXISTED" == true ]]; then
        cp -- "$CONF_BACKUP" "$CONF_FILE"
        warn "Restored the previous nginx server block"
    else
        rm -f -- "$CONF_FILE"
        warn "Removed the new nginx server block"
    fi
    if [[ -n "$DEFAULT_SITE_BACKUP" && -f "$DEFAULT_SITE_BACKUP" ]]; then
        cp -p -- "$DEFAULT_SITE_BACKUP" "$DEFAULT_SITE"
        warn "Restored $DEFAULT_SITE"
    fi
}

# nginx honours only the first server block per name and listen socket, in
# include (alphabetical) order, so a default.conf from ../nginx/nginx.sh that
# declares the same name on ports 80/443 either hides this vhost or is hidden
# by it. Take the name over instead of leaving the outcome to file naming:
#   - default.conf serves nothing else  -> it is superseded and removed
#   - it serves other names as well     -> only our names are dropped from it
# The original is saved to $1 first and restored if nginx rejects the new vhost.
# Call it once the new vhost is written, immediately before "nginx -t".
# Usage: resolve_default_site_overlap BACKUP_PATH NAME...
resolve_default_site_overlap() {
    local backup_path="$1" state
    shift
    [[ -f "$DEFAULT_SITE" && "$CONF_FILE" != "$DEFAULT_SITE" ]] || return 0

    state=$(OUR_NAMES=" $* " awk '
        function ours(name) { return index(tolower(ENVIRON["OUR_NAMES"]), " " tolower(name) " ") > 0 }
        {
            line = $0
            sub(/#.*/, "", line)
            if (line ~ /^[[:space:]]*server_name[[:space:]]/) {
                sub(/^[[:space:]]*server_name[[:space:]]+/, "", line)
                sub(/;.*/, "", line)
                n = split(line, names, /[[:space:]]+/)
                mine = 0
                others = 0
                for (i = 1; i <= n; i++) {
                    if (names[i] == "") {
                        continue
                    }
                    if (ours(names[i])) {
                        mine++
                    } else {
                        others++
                    }
                }
                if (mine && others)  { partial = 1 }
                if (mine && !others) { whole = 1 }
                if (!mine && others) { foreign = 1 }
            } else if (line ~ /^[[:space:]]*listen[[:space:]]/) {
                sub(/^[[:space:]]*listen[[:space:]]+/, "", line)
                sub(/[[:space:]]*;.*/, "", line)
                if (line !~ /^(\[::\]:)?(80|443 ssl)$/) {
                    odd_listen = 1
                }
            }
        }
        END {
            if (!partial && !whole) {
                print "none"
            } else if (whole && !partial && !foreign && !odd_listen) {
                print "only"
            } else if (partial && !whole) {
                print "shared"
            } else {
                print "mixed"
            }
        }
    ' "$DEFAULT_SITE")

    case "$state" in
        only)
            cp -p -- "$DEFAULT_SITE" "$backup_path"
            DEFAULT_SITE_BACKUP="$backup_path"
            rm -f -- "$DEFAULT_SITE"
            warn "$DEFAULT_SITE served only $* and is superseded by $CONF_FILE; it was moved to $backup_path"
            ;;
        shared)
            cp -p -- "$DEFAULT_SITE" "$backup_path"
            DEFAULT_SITE_BACKUP="$backup_path"
            OUR_NAMES=" $* " awk '
                function ours(name) { return index(tolower(ENVIRON["OUR_NAMES"]), " " tolower(name) " ") > 0 }
                {
                    line = $0
                    sub(/#.*/, "", line)
                    if (line ~ /^[[:space:]]*server_name[[:space:]]+[^;]*;[[:space:]]*$/) {
                        match($0, /^[[:space:]]*/)
                        indent = substr($0, 1, RLENGTH)
                        sub(/^[[:space:]]*server_name[[:space:]]+/, "", line)
                        sub(/;.*/, "", line)
                        n = split(line, names, /[[:space:]]+/)
                        kept = ""
                        dropped = 0
                        for (i = 1; i <= n; i++) {
                            if (names[i] == "") {
                                continue
                            }
                            if (ours(names[i])) {
                                dropped = 1
                                continue
                            }
                            kept = kept " " names[i]
                        }
                        if (dropped && kept != "") {
                            print indent "server_name" kept ";"
                            next
                        }
                    }
                    print
                }
            ' "$backup_path" > "$DEFAULT_SITE"
            warn "Removed $* from the server_name lines of $DEFAULT_SITE (now served by $CONF_FILE); original saved to $backup_path"
            ;;
        mixed)
            if ( LC_ALL=C; [[ "${CONF_FILE##*/}" < "${DEFAULT_SITE##*/}" ]] ); then
                warn "$DEFAULT_SITE also declares $*. nginx will use $CONF_FILE (read first) and log 'conflicting server name' warnings; remove the name(s) from $DEFAULT_SITE to silence them."
            else
                restore_nginx_conf
                err "$DEFAULT_SITE also declares $* and is read before $CONF_FILE, so nginx would ignore this vhost. Remove the name(s) from $DEFAULT_SITE, then re-run this script."
            fi
            ;;
    esac
}

# Print the webroot certbot recorded for DOMAIN ($1) when its certificate was
# issued (../nginx/nginx.sh passes its own -w directory), or FALLBACK ($2).
# Renewals are validated through that directory, so the vhost has to serve
# /.well-known/acme-challenge/ from it rather than assume its own root.
acme_webroot_for() {
    local domain="$1" fallback="$2" renewal_dir="/etc/letsencrypt/renewal" renewal_conf recorded=""
    # The certificate may be named after another domain (nginx.sh names it after
    # its first -d), so look for this name in the webroot map of every lineage,
    # starting with the one named after the domain itself.
    for renewal_conf in "$renewal_dir/$domain.conf" "$renewal_dir"/*.conf; do
        [[ -f "$renewal_conf" ]] || continue
        recorded=$(DOMAIN_TARGET="$domain" awk '
            /^\[\[webroot_map\]\]/ { in_map = 1; next }
            /^\[/                  { in_map = 0 }
            in_map && $1 == ENVIRON["DOMAIN_TARGET"] && $2 == "=" { print $3; exit }
        ' "$renewal_conf")
        [[ -z "$recorded" ]] || break
    done
    if [[ -z "$recorded" && -f "$renewal_dir/$domain.conf" ]]; then
        recorded=$(awk '
            /^webroot_path[[:space:]]*=/ {
                val = $0
                sub(/^[^=]*=[[:space:]]*/, "", val)
                sub(/[[:space:]]*,.*$/, "", val)
                print val
                exit
            }
        ' "$renewal_dir/$domain.conf")
    fi
    if [[ "$recorded" =~ ^/[A-Za-z0-9._/-]+$ && -d "$recorded" ]]; then
        printf '%s\n' "$recorded"
    else
        printf '%s\n' "$fallback"
    fi
}

msg "Writing nginx server block: $CONF_FILE"

# Back up existing config if present
if [[ -f "$CONF_FILE" ]]; then
    CONF_PREEXISTED=true
    BACKUP="${CONF_FILE}.bak.$(date +%Y%m%d-%H%M%S)"
    cp "$CONF_FILE" "$BACKUP"
    CONF_BACKUP="$BACKUP"
    info "Existing config backed up to $BACKUP"
fi

ACME_ROOT=""
ACME_LOCATION=""
if [[ "$STANDARD_PORT" == true ]]; then
    ACME_ROOT=$(acme_webroot_for "$DOMAIN" "$BUILD_DIR")
    ACME_LOCATION="    # ACME challenge (certbot issuance and renewal)
    location ^~ /.well-known/acme-challenge/ {
        root $ACME_ROOT;
        default_type \"text/plain\";
        try_files \$uri =404;
    }"
elif [[ -f "$DEFAULT_SITE" ]]; then
    info "This vhost only answers on port $PORT; other ports for $DOMAIN stay with the other vhosts (e.g. $DEFAULT_SITE)"
fi

# Build the listen, SSL, HSTS, and CSP directives
if [[ "$USE_SSL" == true ]]; then
    LISTEN_DIRECTIVE="listen $PORT ssl;
    listen [::]:$PORT ssl;
    http2 on;"
    SSL_PROTOCOLS_LINE=""
    if [[ ! -f /etc/nginx/conf.d/ssl-hardening.conf ]]; then
        SSL_PROTOCOLS_LINE=$'\n'"    ssl_protocols       TLSv1.2 TLSv1.3;"
    fi
    SSL_BLOCK="
    # --- SSL certificates ---
    ssl_certificate     $CERT_DIR/fullchain.pem;
    ssl_certificate_key $CERT_DIR/privkey.pem;${SSL_PROTOCOLS_LINE}"
    CSP_UPGRADE=" upgrade-insecure-requests;"
    HSTS_SERVER_LINE=$'    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;\n'
    HSTS_LOC_LINE=$'        add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;\n'
    MAIN_ACME_LOCATION=""
else
    LISTEN_DIRECTIVE="listen $PORT;
    listen [::]:$PORT;"
    SSL_BLOCK=""
    # HTTP-only on port 80: this server block also answers the ACME challenge.
    MAIN_ACME_LOCATION=""
    if [[ "$PORT" == "80" ]]; then
        MAIN_ACME_LOCATION=$'\n'"$ACME_LOCATION"$'\n'
    fi
    CSP_UPGRADE=""
    HSTS_SERVER_LINE=""
    HSTS_LOC_LINE=""
fi

CSP_POLICY="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https://fonts.gstatic.com; connect-src 'self' https: wss:; frame-ancestors 'none'; form-action 'self'; base-uri 'self';${CSP_UPGRADE}"

cat > "$CONF_FILE" <<EOF
# =============================================================================
# nginx server block — React SPA production serving
# Generated by AwesomeArchLinux/hardening/react/react.sh
#
# Domain: $DOMAIN
# Port:   $PORT
# Root:   $BUILD_DIR
# SSL:    $USE_SSL
# =============================================================================
${ACME_ROOT:+# ACME-Webroot: $ACME_ROOT}

# --- Rate limit zone for API proxy ---
# Adjust rate as needed. 10r/s = 10 requests per second per IP.
limit_req_zone \$binary_remote_addr zone=api_${DOMAIN//./_}:10m rate=10r/s;

EOF

# HTTP to HTTPS redirect block (only when this vhost serves HTTPS on port 443)
if [[ "$USE_SSL" == true && "$PORT" == "443" ]]; then
    cat >> "$CONF_FILE" <<EOF
# --- HTTP: Redirect all to HTTPS ---
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;

$ACME_LOCATION

    location / {
        return 301 https://\$host\$request_uri;
    }
}

EOF
fi

cat >> "$CONF_FILE" <<EOF
server {
    $LISTEN_DIRECTIVE
    server_name $DOMAIN;
$SSL_BLOCK

    root $BUILD_DIR;
    index index.html;
$MAIN_ACME_LOCATION
    # --- Gzip compression for static assets ---
    # Safe to enable for static SPA files (no secrets, no session cookies).
    gzip on;
    gzip_types text/css application/javascript application/json image/svg+xml text/plain text/xml application/xml;
    gzip_min_length 1000;
    gzip_comp_level 5;
    gzip_vary on;

    # =========================================================================
    # SECURITY HEADERS
    # =========================================================================

    # --- Content-Security-Policy (tuned for React production) ---
    # React does NOT need unsafe-inline or unsafe-eval for scripts in production.
    # CSS-in-JS libraries (styled-components, emotion) may need 'unsafe-inline' for styles.
    # Adjust connect-src for your API endpoints and WebSocket connections.
    add_header Content-Security-Policy "${CSP_POLICY}" always;

    # --- Standard security headers ---
${HSTS_SERVER_LINE}    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-XSS-Protection "0" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;
    add_header Cross-Origin-Opener-Policy "same-origin" always;
    add_header Cross-Origin-Resource-Policy "same-origin" always;

    # =========================================================================
    # SPA ROUTING
    # =========================================================================

    # --- Default: serve static files, fall back to index.html for client routes ---
    location / {
        try_files \$uri \$uri/ /index.html;
    }

    # =========================================================================
    # SOURCE MAP & DOTFILE PROTECTION (evaluated BEFORE static asset regex!)
    # =========================================================================

    # --- Block source maps in production ---
    location ~* \.map$ {
        deny all;
        return 404;
    }

    # --- Block hidden files (except .well-known for ACME) ---
    location ~ /\.(?!well-known) {
        deny all;
        return 404;
    }

    # =========================================================================
    # CACHE CONTROL
    # =========================================================================

    # --- index.html: NEVER cache (contains hashed asset references) ---
    location = /index.html {
        add_header Cache-Control "no-cache, no-store, must-revalidate" always;
        add_header Pragma "no-cache" always;
        expires 0;

        # Re-add security headers (nginx clears server-level add_header in nested locations)
${HSTS_LOC_LINE}        add_header Content-Security-Policy "${CSP_POLICY}" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-Frame-Options "DENY" always;
        add_header X-XSS-Protection "0" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;
        add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;
        add_header Cross-Origin-Opener-Policy "same-origin" always;
        add_header Cross-Origin-Resource-Policy "same-origin" always;
    }

    # --- Service worker: NEVER cache (must always be fresh) ---
    location = /sw.js {
        add_header Cache-Control "no-cache, no-store, must-revalidate" always;
        add_header Pragma "no-cache" always;
        expires 0;

        # Re-add security headers
${HSTS_LOC_LINE}        add_header Content-Security-Policy "${CSP_POLICY}" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-Frame-Options "DENY" always;
        add_header X-XSS-Protection "0" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;
        add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;
        add_header Cross-Origin-Opener-Policy "same-origin" always;
        add_header Cross-Origin-Resource-Policy "same-origin" always;
    }

    # --- Hashed static assets: cache aggressively (1 year, immutable) ---
    # Vite/CRA/Next.js all use content-hashed filenames for JS, CSS, and media.
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
        expires 1y;
        add_header Cache-Control "public, immutable" always;

        # Re-add security headers
${HSTS_LOC_LINE}        add_header X-Content-Type-Options "nosniff" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;
        add_header Cross-Origin-Resource-Policy "same-origin" always;
    }

    # =========================================================================
    # API PROXY (template — uncomment and adjust)
    # =========================================================================

    # Uncomment this block if your SPA proxies API calls through nginx.
    # Adjust the proxy_pass target to your backend service.
    #
    # location /api/ {
    #     limit_req zone=api_${DOMAIN//./_} burst=20 nodelay;
    #     limit_req_status 429;
    #
    #     proxy_pass http://127.0.0.1:4000;
    #     proxy_set_header Host \$host;
    #     proxy_set_header X-Real-IP \$remote_addr;
    #     proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    #     proxy_set_header X-Forwarded-Proto \$scheme;
    #
    #     # WebSocket support (uncomment if needed)
    #     # proxy_http_version 1.1;
    #     # proxy_set_header Upgrade \$http_upgrade;
    #     # proxy_set_header Connection "upgrade";
    # }
}
EOF

chmod 0644 "$CONF_FILE"
msg "nginx server block written: $CONF_FILE"

# =============================================================================
# 5. FILE PERMISSIONS
# =============================================================================

msg "Setting file permissions on application and build directories..."

# Ensure parent APP_PATH (and any intermediate dir under /var/www or /srv/http)
# is traversable by nginx (0750 root:http) so BUILD_DIR can be reached.
for base_root in /var/www /srv/http; do
    if [[ "$APP_PATH" == "$base_root"/* ]]; then
        chmod 0755 "$base_root"
        parent_walk="$APP_PATH"
        while [[ "$parent_walk" != "$base_root" && "$parent_walk" != "/" ]]; do
            chown root:http "$parent_walk"
            chmod 0750 "$parent_walk"
            parent_walk=$(dirname -- "$parent_walk")
        done
    fi
done

# Build directory owned by root:http
# Directories: 750 (rwxr-x---) — root can write, http can read+traverse
# Files: 640 (rw-r-----) — root can write, http can read, no one else
chown -R root:http "$BUILD_DIR"
find "$BUILD_DIR" -type d -exec chmod 0750 {} +
find "$BUILD_DIR" -type f -exec chmod 0640 {} +

msg "Permissions set: dirs=750, files=640, owner=root:http"

# =============================================================================
# 6. CREATE .env.production.example
# =============================================================================

ENV_EXAMPLE="$APP_PATH/.env.production.example"

if [[ ! -f "$ENV_EXAMPLE" ]]; then
    msg "Creating $ENV_EXAMPLE..."
    cat > "$ENV_EXAMPLE" <<'ENVFILE'
# =============================================================================
# .env.production.example
# Generated by AwesomeArchLinux/hardening/react/react.sh
#
# IMPORTANT: Environment variables in React/Vite are embedded at BUILD TIME
# into the JavaScript bundle. They are NOT secret — anyone can read them
# by inspecting the built JS files.
#
# NEVER put secrets (API keys, database passwords, JWT secrets) in these
# variables. Use a backend proxy for any authenticated API calls.
# =============================================================================

# --- API endpoint (public, embedded in bundle) ---
VITE_API_URL=https://api.example.com

# --- Public feature flags ---
VITE_ENABLE_ANALYTICS=true
VITE_ENABLE_SENTRY=true

# --- Public third-party identifiers (NOT secrets) ---
# VITE_SENTRY_DSN=https://public@sentry.example.com/1
# VITE_GA_TRACKING_ID=G-XXXXXXXXXX

# --- WebSocket endpoint ---
# VITE_WS_URL=wss://api.example.com/ws

# --- DO NOT ADD THESE HERE ---
# SECRET_API_KEY=xxx      <-- NEVER! Use backend proxy instead.
# DATABASE_URL=xxx        <-- NEVER! Backend only.
# JWT_SECRET=xxx          <-- NEVER! Backend only.
ENVFILE
    chmod 644 "$ENV_EXAMPLE"
    msg ".env.production.example created"
else
    info ".env.production.example already exists, skipping"
fi

# =============================================================================
# 7. VALIDATE AND RELOAD NGINX
# =============================================================================

if [[ "$STANDARD_PORT" == true ]]; then
    install -d -o root -g root -m 0700 "$BACKUP_ROOT"
    resolve_default_site_overlap "$BACKUP_ROOT/nginx-default.conf.$DOMAIN.$(date +%Y%m%d-%H%M%S)" "$DOMAIN"
fi

msg "Testing nginx configuration..."

if nginx -t 2>&1; then
    msg "Configuration test passed"
    NGINX_APPLIED=false
    if systemctl is-active --quiet nginx; then
        systemctl reload nginx && NGINX_APPLIED=true
    else
        systemctl enable --now nginx && NGINX_APPLIED=true
    fi
    if [[ "$NGINX_APPLIED" == true ]]; then
        msg "nginx is active and serving the updated configuration"
    else
        restore_nginx_conf
        if systemctl is-active --quiet nginx; then
            systemctl reload nginx 2>/dev/null || \
                warn "Could not reload nginx after restoring its previous configuration"
        fi
        err "nginx start/reload failed; the server block was rolled back"
    fi
else
    restore_nginx_conf
    err "nginx configuration test failed; no invalid server block was left enabled"
fi

# =============================================================================
# 8. SUMMARY
# =============================================================================

# Determine the serving URL
if [[ "$USE_SSL" == true ]]; then
    PROTOCOL="https"
else
    PROTOCOL="http"
fi

if [[ "$PORT" == "80" || "$PORT" == "443" ]]; then
    SERVE_URL="${PROTOCOL}://${DOMAIN}"
else
    SERVE_URL="${PROTOCOL}://${DOMAIN}:${PORT}"
fi

echo
echo -e "${C_GREEN}========================================================================${C_NC}"
echo -e "${C_GREEN} React SPA production hardening complete!${C_NC}"
echo -e "${C_GREEN}========================================================================${C_NC}"
echo
echo -e "${C_BLUE}Configuration:${C_NC}"
echo "  App path:        $APP_PATH"
echo "  Build directory:  $BUILD_DIR"
echo "  nginx config:     $CONF_FILE"
echo "  Serving URL:      $SERVE_URL"
echo "  SSL enabled:      $USE_SSL"
echo
echo -e "${C_BLUE}Security features:${C_NC}"
echo "  - Content-Security-Policy (React-tuned, no unsafe-eval)"
echo "  - X-Content-Type-Options: nosniff"
echo "  - X-Frame-Options: DENY"
echo "  - Referrer-Policy: strict-origin-when-cross-origin"
echo "  - Permissions-Policy: camera, mic, geo, payment denied"
echo "  - Cross-Origin-Opener-Policy: same-origin"
echo "  - Cross-Origin-Resource-Policy: same-origin"
echo "  - Source maps blocked (.map files return 404)"
echo "  - Hidden files blocked (dotfiles return 404)"
echo "  - Build dir owned by root:http (750/640)"
echo
echo -e "${C_BLUE}Caching strategy:${C_NC}"
echo "  - index.html:       no-cache (always fresh)"
echo "  - sw.js:            no-cache (always fresh)"
echo "  - JS/CSS/fonts/img: 1 year, immutable (content-hashed)"
echo "  - Gzip:             enabled for text assets"
echo
echo -e "${C_YELLOW}IMPORTANT — Customize the Content-Security-Policy:${C_NC}"
echo "  The default CSP is a secure baseline. You may need to adjust it for"
echo "  your specific app. Edit the CSP in:"
echo "    $CONF_FILE"
echo
echo "  Common adjustments:"
echo "    - External API:   connect-src 'self' https://api.yoursite.com"
echo "    - Google Fonts:   font-src 'self' https://fonts.gstatic.com"
echo "                      style-src 'self' 'unsafe-inline' https://fonts.googleapis.com"
echo "    - CDN scripts:    script-src 'self' https://cdn.example.com"
echo "    - Inline styles:  style-src already includes 'unsafe-inline' for CSS-in-JS"
echo "    - Images from S3: img-src 'self' data: https://s3.amazonaws.com"
echo
if [[ "$PORT" != "80" && "$PORT" != "443" ]]; then
    echo -e "${C_YELLOW}Firewall:${C_NC}"
    echo "  Port $PORT is not opened by this script (../nginx/nginx.sh only opens 80 and its"
    echo "  HTTPS port). Allow it in your firewall, or serve the app on the standard ports"
    echo "  with -p 443 (certificates present) or -p 80."
    echo
fi
if [[ "$STANDARD_PORT" == true ]]; then
    echo -e "${C_BLUE}ACME webroot:${C_NC}"
    echo "  /.well-known/acme-challenge/ is served from $ACME_ROOT"
    echo
fi
if [[ "$USE_SSL" == false ]]; then
    echo -e "${C_YELLOW}SSL setup:${C_NC}"
    echo "  HTTPS is not configured. For production, run:"
    echo "    cd ../nginx && sudo ./nginx.sh -d $DOMAIN"
    echo "  Then re-run this script to auto-detect the certificates."
    echo
fi
echo -e "${C_BLUE}Verification:${C_NC}"
echo "  curl -I $SERVE_URL"
echo "  https://securityheaders.com/?q=$SERVE_URL"
if [[ "$USE_SSL" == true ]]; then
    echo "  https://www.ssllabs.com/ssltest/analyze.html?d=$DOMAIN"
fi
echo
echo -e "${C_GREEN}Done.${C_NC}"
