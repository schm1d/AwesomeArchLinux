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

# --- Usage ---
usage() {
    cat <<EOF
Usage: sudo $0 [options]

Required:
  -a APP_PATH   Path to the React app (project root or build directory)

Optional:
  -p PORT       Listening port (default: $PORT)
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

# Check if APP_PATH itself is the build directory (contains index.html)
if [[ -f "$APP_PATH/index.html" ]]; then
    BUILD_DIR="$APP_PATH"
    info "Build directory is APP_PATH itself: $BUILD_DIR"
else
    # Check common build output directories
    for candidate in dist build out; do
        if [[ -f "$APP_PATH/$candidate/index.html" ]]; then
            BUILD_DIR="$APP_PATH/$candidate"
            info "Found build directory: $BUILD_DIR (detected $candidate/)"
            break
        fi
    done
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

# =============================================================================
# 4. WRITE NGINX SERVER BLOCK
# =============================================================================

CONF_FILE="/etc/nginx/sites-enabled/${DOMAIN}.conf"
CONF_BACKUP=""
CONF_PREEXISTED=false

restore_nginx_conf() {
    if [[ "$CONF_PREEXISTED" == true ]]; then
        cp -- "$CONF_BACKUP" "$CONF_FILE"
        warn "Restored the previous nginx server block"
    else
        rm -f -- "$CONF_FILE"
        warn "Removed the new nginx server block"
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

# Warn if /etc/nginx/sites-enabled/default.conf also claims $DOMAIN on port 80/443
DEFAULT_SITE="/etc/nginx/sites-enabled/default.conf"
if [[ -f "$DEFAULT_SITE" && "$CONF_FILE" != "$DEFAULT_SITE" ]]; then
    if DOMAIN_TARGET="$DOMAIN" awk '
        {
            line = $0
            sub(/#.*/, "", line)
            if (line ~ /^[[:space:]]*server_name[[:space:]]/) {
                sub(/^[[:space:]]*server_name[[:space:]]+/, "", line)
                sub(/;.*/, "", line)
                n = split(line, names, /[[:space:]]+/)
                for (i = 1; i <= n; i++) {
                    if (tolower(names[i]) == ENVIRON["DOMAIN_TARGET"]) {
                        found = 1
                        exit
                    }
                }
            }
        }
        END { exit !found }
    ' "$DEFAULT_SITE"; then
        warn "$DEFAULT_SITE also declares server_name '$DOMAIN' (on port 80/443)."
        if [[ "$PORT" == "80" || "$PORT" == "443" ]]; then
            warn "Remove or update $DEFAULT_SITE so it does not shadow $CONF_FILE on port $PORT."
        else
            warn "Requests to $DOMAIN on port 80/443 will still hit $DEFAULT_SITE unless updated."
        fi
    fi
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
else
    LISTEN_DIRECTIVE="listen $PORT;
    listen [::]:$PORT;"
    SSL_BLOCK=""
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

# --- Rate limit zone for API proxy ---
# Adjust rate as needed. 10r/s = 10 requests per second per IP.
limit_req_zone \$binary_remote_addr zone=api_${DOMAIN//./_}:10m rate=10r/s;

server {
    $LISTEN_DIRECTIVE
    server_name $DOMAIN;
$SSL_BLOCK

    root $BUILD_DIR;
    index index.html;

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
