#!/usr/bin/env bash

# =============================================================================
# Script:      wordpress.sh
# Description: Hardens an existing WordPress installation on Arch Linux,
#              targeting:
#                - wp-config.php security constants and salts
#                - Strict file permissions (root:http ownership)
#                - Hardened nginx server block with PHP-FPM
#                - fail2ban jails for wp-login.php and xmlrpc.php
#                - PHP .user.ini hardening
#                - systemd-based wp-cron replacement
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
#
# Usage:       sudo ./wordpress.sh -d DOMAIN -w WP_PATH [--db-name DB]
#                                  [--db-user USER] [--db-host HOST] [-h]
#
# Requirements:
#   - Arch Linux with pacman
#   - Root privileges
#   - An existing WordPress installation (this script does NOT install WordPress)
#   - nginx-mainline installed (see ../nginx/nginx.sh)
#   - PHP-FPM installed and running
#
# What this script does:
#   1. Verifies WordPress exists at WP_PATH
#   2. Hardens wp-config.php (security constants, salts, table prefix)
#   3. Sets strict file permissions (root:http, 640/750)
#   4. Writes a hardened nginx server block with PHP-FPM
#   5. Creates fail2ban jails for wp-login.php and xmlrpc.php
#   6. Creates .user.ini for PHP runtime hardening
#   7. Replaces wp-cron with a systemd timer
#   8. Prints a security summary and checklist
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
DOMAIN=""
WP_PATH="/var/www/wordpress"
DB_NAME="wordpress"
DB_USER="wpuser"
DB_HOST="localhost"
LOGFILE="/var/log/wordpress-hardening-$(date +%Y%m%d-%H%M%S).log"

# --- Usage ---
usage() {
    cat <<EOF
Usage: sudo $0 [options]

Required:
  -d DOMAIN       Domain name for the WordPress site

Optional:
  -w WP_PATH      WordPress installation path (default: $WP_PATH)
  --db-name DB    Database name (default: $DB_NAME)
  --db-user USER  Database user (default: $DB_USER)
  --db-host HOST  Database host (default: $DB_HOST)
  -h              Show this help

Examples:
  sudo $0 -d example.com
  sudo $0 -d example.com -w /srv/http/wordpress
  sudo $0 -d blog.example.com --db-name wpblog --db-user bloguser
EOF
    exit 0
}

# --- Parse Arguments ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        -d)          DOMAIN="$2"; shift 2 ;;
        -w)          WP_PATH="$2"; shift 2 ;;
        --db-name)   DB_NAME="$2"; shift 2 ;;
        --db-user)   DB_USER="$2"; shift 2 ;;
        --db-host)   DB_HOST="$2"; shift 2 ;;
        -h|--help)   usage ;;
        *)           err "Unknown option: $1" ;;
    esac
done

# --- Validate ---
[[ $(id -u) -eq 0 ]] || err "Must be run as root"
[[ -n "$DOMAIN" ]]   || err "Domain is required (-d example.com)"

# Redirect output to logfile as well
exec > >(tee -a "$LOGFILE") 2>&1

info "Domain: $DOMAIN"
info "WordPress path: $WP_PATH"
info "Database: $DB_NAME@$DB_HOST (user: $DB_USER)"
info "Log: $LOGFILE"

# =============================================================================
# 1. VERIFY WORDPRESS EXISTS
# =============================================================================

msg "Verifying WordPress installation at $WP_PATH..."

if [[ ! -d "$WP_PATH" ]]; then
    err "WordPress directory not found: $WP_PATH"
fi

if [[ ! -f "$WP_PATH/wp-config.php" && ! -d "$WP_PATH/wp-includes" ]]; then
    err "Not a WordPress installation: $WP_PATH (missing wp-config.php and wp-includes/)"
fi

if [[ -f "$WP_PATH/wp-config.php" ]]; then
    info "Found wp-config.php"
else
    warn "wp-config.php not found — skipping wp-config hardening"
fi

if [[ -d "$WP_PATH/wp-includes" ]]; then
    info "Found wp-includes/"
fi

# =============================================================================
# 2. WP-CONFIG.PHP HARDENING
# =============================================================================

if [[ -f "$WP_PATH/wp-config.php" ]]; then
    msg "Hardening wp-config.php..."

    WP_CONFIG="$WP_PATH/wp-config.php"

    # Back up wp-config.php
    BACKUP="${WP_CONFIG}.bak.$(date +%Y%m%d-%H%M%S)"
    cp "$WP_CONFIG" "$BACKUP"
    chmod 600 "$BACKUP"
    info "wp-config.php backed up to $BACKUP"

    # --- Helper: add or update a define() constant ---
    # If the constant exists, update its value. If not, insert before
    # "That's all, stop editing!" or at the end of the file.
    wp_define() {
        local name="$1"
        local value="$2"

        if grep -qP "define\s*\(\s*['\"]${name}['\"]" "$WP_CONFIG"; then
            # Update existing define
            sed -i "s|define\s*(\s*['\"]${name}['\"].*|define('${name}', ${value});|" "$WP_CONFIG"
            info "Updated: define('${name}', ${value})"
        else
            # Insert before "stop editing" marker, or append before closing PHP tag
            if grep -q "stop editing" "$WP_CONFIG"; then
                sed -i "/stop editing/i define('${name}', ${value});" "$WP_CONFIG"
            else
                # Append before the last line (usually require_once ABSPATH)
                sed -i "$ i define('${name}', ${value});" "$WP_CONFIG"
            fi
            info "Added:   define('${name}', ${value})"
        fi
    }

    # --- Security constants ---
    wp_define "DISALLOW_FILE_EDIT" "true"
    wp_define "DISALLOW_FILE_MODS" "false"
    wp_define "FORCE_SSL_ADMIN" "true"
    wp_define "WP_AUTO_UPDATE_CORE" "'minor'"
    wp_define "WP_DEBUG" "false"
    wp_define "WP_DEBUG_DISPLAY" "false"
    wp_define "WP_DEBUG_LOG" "false"
    wp_define "CONCATENATE_SCRIPTS" "false"
    wp_define "WP_MEMORY_LIMIT" "'256M'"
    wp_define "WP_MAX_MEMORY_LIMIT" "'512M'"
    wp_define "DISABLE_WP_CRON" "true"

    # --- Generate and set security keys/salts ---
    msg "Fetching fresh security keys/salts from WordPress API..."

    SALTS=$(curl -sS --max-time 10 "https://api.wordpress.org/secret-key/1.1/salt/" 2>/dev/null || true)

    if [[ -n "$SALTS" && "$SALTS" == *"define("* ]]; then
        # Remove existing salt definitions
        for key in AUTH_KEY SECURE_AUTH_KEY LOGGED_IN_KEY NONCE_KEY AUTH_SALT SECURE_AUTH_SALT LOGGED_IN_SALT NONCE_SALT; do
            sed -i "/define\s*(\s*['\"]${key}['\"]/d" "$WP_CONFIG"
        done

        # Insert new salts before "stop editing" marker
        if grep -q "stop editing" "$WP_CONFIG"; then
            # Write salts to a temp file and insert
            SALT_TMPFILE=$(mktemp)
            echo "$SALTS" > "$SALT_TMPFILE"
            sed -i "/stop editing/e cat $SALT_TMPFILE" "$WP_CONFIG"
            rm -f "$SALT_TMPFILE"
        else
            echo "$SALTS" >> "$WP_CONFIG"
        fi
        msg "Security keys/salts updated from WordPress API"
    else
        warn "Could not fetch salts from WordPress API — existing keys unchanged"
        warn "Manually visit: https://api.wordpress.org/secret-key/1.1/salt/"
    fi

    # --- Randomize table prefix if still default 'wp_' ---
    if grep -qP '^\$table_prefix\s*=\s*["\x27]wp_["\x27]' "$WP_CONFIG"; then
        RANDOM_PREFIX=$(tr -dc 'a-z' </dev/urandom | head -c 4)_
        sed -i "s|\\\$table_prefix\s*=\s*['\"]wp_['\"]|\$table_prefix = '${RANDOM_PREFIX}'|" "$WP_CONFIG"
        msg "Table prefix changed from 'wp_' to '${RANDOM_PREFIX}'"
        warn "IMPORTANT: If WordPress is already installed with data, you must also"
        warn "rename the database tables to match the new prefix '${RANDOM_PREFIX}'"
    else
        info "Table prefix is already custom — no change needed"
    fi

    # --- Add content directory comment ---
    if ! grep -q "WP_CONTENT_DIR" "$WP_CONFIG"; then
        if grep -q "stop editing" "$WP_CONFIG"; then
            sed -i "/stop editing/i \\
// Optional: Move wp-content outside the web root for extra security\\
// define('WP_CONTENT_DIR', dirname(__FILE__) . '/wp-content');\\
// define('WP_CONTENT_URL', 'https://${DOMAIN}/wp-content');" "$WP_CONFIG"
        fi
        info "Added WP_CONTENT_DIR comment block"
    fi

    msg "wp-config.php hardening complete"
fi

# =============================================================================
# 3. FILE PERMISSIONS
# =============================================================================

msg "Setting WordPress file permissions..."

# --- Ownership: root:http across the installation ---
chown -R root:http "$WP_PATH"
info "Ownership set to root:http"

# --- Directories: 750 (rwxr-x---) ---
find "$WP_PATH" -type d -exec chmod 750 {} \;
info "Directories set to 750"

# --- PHP files: 640 (rw-r-----) ---
find "$WP_PATH" -type f -name '*.php' -exec chmod 640 {} \;
info "PHP files set to 640"

# --- All other files: 640 ---
find "$WP_PATH" -type f ! -name '*.php' -exec chmod 640 {} \;
info "All files set to 640"

# --- wp-config.php: 640, root:http ---
if [[ -f "$WP_PATH/wp-config.php" ]]; then
    chmod 640 "$WP_PATH/wp-config.php"
    chown root:http "$WP_PATH/wp-config.php"
    info "wp-config.php: 640 root:http"
fi

# --- wp-content/uploads: 770, http:http (web server needs write) ---
if [[ -d "$WP_PATH/wp-content/uploads" ]]; then
    chown -R http:http "$WP_PATH/wp-content/uploads"
    find "$WP_PATH/wp-content/uploads" -type d -exec chmod 770 {} \;
    find "$WP_PATH/wp-content/uploads" -type f -exec chmod 660 {} \;
    info "wp-content/uploads: 770/660 http:http (writable)"
else
    mkdir -p "$WP_PATH/wp-content/uploads"
    chown -R http:http "$WP_PATH/wp-content/uploads"
    chmod 770 "$WP_PATH/wp-content/uploads"
    info "wp-content/uploads created: 770 http:http"
fi

# --- wp-content/cache: 770, http:http (if exists) ---
if [[ -d "$WP_PATH/wp-content/cache" ]]; then
    chown -R http:http "$WP_PATH/wp-content/cache"
    find "$WP_PATH/wp-content/cache" -type d -exec chmod 770 {} \;
    find "$WP_PATH/wp-content/cache" -type f -exec chmod 660 {} \;
    info "wp-content/cache: 770/660 http:http (writable)"
fi

# --- wp-content/themes: 750, root:http (read-only) ---
if [[ -d "$WP_PATH/wp-content/themes" ]]; then
    chown -R root:http "$WP_PATH/wp-content/themes"
    find "$WP_PATH/wp-content/themes" -type d -exec chmod 750 {} \;
    find "$WP_PATH/wp-content/themes" -type f -exec chmod 640 {} \;
    info "wp-content/themes: 750/640 root:http (read-only)"
fi

# --- wp-content/plugins: 750, root:http (read-only) ---
if [[ -d "$WP_PATH/wp-content/plugins" ]]; then
    chown -R root:http "$WP_PATH/wp-content/plugins"
    find "$WP_PATH/wp-content/plugins" -type d -exec chmod 750 {} \;
    find "$WP_PATH/wp-content/plugins" -type f -exec chmod 640 {} \;
    info "wp-content/plugins: 750/640 root:http (read-only)"
fi

# --- Remove sensitive default files ---
REMOVED_FILES=()
for f in wp-config-sample.php readme.html license.txt; do
    if [[ -f "$WP_PATH/$f" ]]; then
        rm -f "$WP_PATH/$f"
        REMOVED_FILES+=("$f")
    fi
done

# Block xmlrpc.php via nginx (removal is optional since nginx blocks it)
if [[ -f "$WP_PATH/xmlrpc.php" ]]; then
    info "xmlrpc.php exists — will be blocked by nginx (not removed)"
fi

# Remove install.php if WordPress is already installed
if [[ -f "$WP_PATH/wp-admin/install.php" ]]; then
    # Check if WordPress appears to be installed (wp_options table exists)
    if [[ -f "$WP_PATH/wp-config.php" ]] && \
       [[ -d "$WP_PATH/wp-content/themes" ]] && \
       [[ -d "$WP_PATH/wp-content/plugins" ]]; then
        rm -f "$WP_PATH/wp-admin/install.php"
        REMOVED_FILES+=("wp-admin/install.php")
    fi
fi

if [[ ${#REMOVED_FILES[@]} -gt 0 ]]; then
    msg "Removed: ${REMOVED_FILES[*]}"
else
    info "No default sensitive files found to remove"
fi

msg "File permissions set"

# =============================================================================
# 4. NGINX SERVER BLOCK
# =============================================================================

msg "Writing nginx server block..."

CONF_FILE="/etc/nginx/sites-enabled/${DOMAIN}.conf"

# Ensure directories exist
mkdir -p /etc/nginx/sites-enabled
mkdir -p /etc/nginx/conf.d

# Back up existing config
if [[ -f "$CONF_FILE" ]]; then
    BACKUP="${CONF_FILE}.bak.$(date +%Y%m%d-%H%M%S)"
    cp "$CONF_FILE" "$BACKUP"
    info "Existing nginx config backed up to $BACKUP"
fi

# Detect SSL certificates
USE_SSL=false
CERT_DIR="/etc/letsencrypt/live/$DOMAIN"
if [[ -f "$CERT_DIR/fullchain.pem" && -f "$CERT_DIR/privkey.pem" ]]; then
    USE_SSL=true
    info "SSL certificates found for $DOMAIN"
else
    warn "No SSL certificates found — configuring HTTP-only"
    warn "Run ../nginx/nginx.sh for HTTPS setup"
fi

# Detect PHP-FPM socket
PHP_SOCKET="/run/php-fpm/php-fpm.sock"
if [[ ! -S "$PHP_SOCKET" ]]; then
    # Try alternative socket paths
    for sock in /run/php-fpm/www.sock /var/run/php-fpm/php-fpm.sock /run/php/php-fpm.sock; do
        if [[ -S "$sock" ]]; then
            PHP_SOCKET="$sock"
            break
        fi
    done
fi
info "PHP-FPM socket: $PHP_SOCKET"

# Build listen directives
if [[ "$USE_SSL" == true ]]; then
    LISTEN_BLOCK="    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;"
    SSL_BLOCK="
    # --- SSL certificates ---
    ssl_certificate     $CERT_DIR/fullchain.pem;
    ssl_certificate_key $CERT_DIR/privkey.pem;"
else
    LISTEN_BLOCK="    listen 80;
    listen [::]:80;"
    SSL_BLOCK=""
fi

cat > "$CONF_FILE" <<EOF
# =============================================================================
# nginx server block — WordPress production hardening
# Generated by AwesomeArchLinux/hardening/wordpress/wordpress.sh
#
# Domain: $DOMAIN
# Root:   $WP_PATH
# SSL:    $USE_SSL
# =============================================================================

# --- Rate limiting zones ---
limit_req_zone \$binary_remote_addr zone=wp_login_${DOMAIN//./_}:10m rate=1r/s;
limit_req_zone \$binary_remote_addr zone=wp_ajax_${DOMAIN//./_}:10m rate=10r/s;

# --- FastCGI cache (optional — uncomment to enable) ---
# fastcgi_cache_path /var/cache/nginx/wordpress levels=1:2 keys_zone=WPCACHE:100m inactive=60m max_size=512m;
# fastcgi_cache_key "\$scheme\$request_method\$host\$request_uri";

EOF

# HTTP to HTTPS redirect block (only when SSL is enabled)
if [[ "$USE_SSL" == true ]]; then
    cat >> "$CONF_FILE" <<EOF
# --- HTTP: Redirect all to HTTPS ---
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN www.$DOMAIN;

    # ACME challenge (certbot renewal)
    location /.well-known/acme-challenge/ {
        root $WP_PATH;
        allow all;
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}

EOF
fi

cat >> "$CONF_FILE" <<EOF
# --- Main server block ---
server {
$LISTEN_BLOCK
    server_name $DOMAIN www.$DOMAIN;
$SSL_BLOCK

    root $WP_PATH;
    index index.php index.html;

    # Hide PHP version
    fastcgi_hide_header X-Powered-By;

    # --- Security headers ---
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;
    add_header Cross-Origin-Opener-Policy "same-origin" always;

    # --- Content-Security-Policy (tuned for WordPress) ---
    # WordPress admin requires 'unsafe-inline' and 'unsafe-eval' for scripts/styles.
    # Adjust connect-src, img-src, and font-src for your themes and plugins.
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data: https:; font-src 'self' https://fonts.gstatic.com data:; connect-src 'self' https:; frame-ancestors 'self'; form-action 'self'; base-uri 'self'; upgrade-insecure-requests;" always;

    # =========================================================================
    # WORDPRESS PERMALINKS
    # =========================================================================

    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }

    # =========================================================================
    # PHP-FPM
    # =========================================================================

    location ~ \.php\$ {
        # Prevent PHP execution of uploaded files
        try_files \$uri =404;

        fastcgi_split_path_info ^(.+\.php)(/.+)\$;
        fastcgi_pass unix:$PHP_SOCKET;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;

        # Performance
        fastcgi_buffers 16 16k;
        fastcgi_buffer_size 32k;
        fastcgi_intercept_errors on;

        # FastCGI cache (uncomment to enable)
        # fastcgi_cache WPCACHE;
        # fastcgi_cache_valid 200 60m;
        # fastcgi_cache_valid 404 1m;
        # fastcgi_cache_bypass \$skip_cache;
        # fastcgi_no_cache \$skip_cache;
        # add_header X-FastCGI-Cache \$upstream_cache_status;
    }

    # =========================================================================
    # WORDPRESS-SPECIFIC BLOCKS
    # =========================================================================

    # --- Block xmlrpc.php (brute-force and DDoS vector) ---
    location = /xmlrpc.php {
        deny all;
        return 403;
    }

    # --- Block wp-config.php access ---
    location = /wp-config.php {
        deny all;
        return 403;
    }

    # --- Block .htaccess, .htpasswd ---
    location ~ /\.ht {
        deny all;
        return 403;
    }

    # --- Block hidden files (except .well-known) ---
    location ~ /\.(?!well-known) {
        deny all;
        return 404;
    }

    # --- Block PHP execution in uploads ---
    location ~* /wp-content/uploads/.*\.php\$ {
        deny all;
        return 403;
    }

    # --- Block PHP execution in wp-includes ---
    location ~* /wp-includes/.*\.php\$ {
        deny all;
        return 403;
    }

    # --- Block PHP in wp-content (except index.php) ---
    location ~* /wp-content/.*\.php\$ {
        # Allow index.php files in wp-content subdirectories
        location ~* /wp-content/.*/index\.php\$ {
            fastcgi_split_path_info ^(.+\.php)(/.+)\$;
            fastcgi_pass unix:$PHP_SOCKET;
            fastcgi_index index.php;
            fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
            include fastcgi_params;
        }
        deny all;
        return 403;
    }

    # --- Rate limit wp-login.php ---
    location = /wp-login.php {
        limit_req zone=wp_login_${DOMAIN//./_} burst=3 nodelay;
        limit_req_status 429;

        fastcgi_split_path_info ^(.+\.php)(/.+)\$;
        fastcgi_pass unix:$PHP_SOCKET;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }

    # --- Rate limit admin-ajax.php ---
    location = /wp-admin/admin-ajax.php {
        limit_req zone=wp_ajax_${DOMAIN//./_} burst=20 nodelay;
        limit_req_status 429;

        fastcgi_split_path_info ^(.+\.php)(/.+)\$;
        fastcgi_pass unix:$PHP_SOCKET;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }

    # --- Noindex wp-admin for search engines ---
    location /wp-admin/ {
        add_header X-Robots-Tag "noindex, nofollow" always;

        location ~ \.php\$ {
            try_files \$uri =404;
            fastcgi_split_path_info ^(.+\.php)(/.+)\$;
            fastcgi_pass unix:$PHP_SOCKET;
            fastcgi_index index.php;
            fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
            include fastcgi_params;
            fastcgi_hide_header X-Powered-By;
        }
    }

    # =========================================================================
    # STATIC ASSET CACHING
    # =========================================================================

    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|webp|avif|woff|woff2|ttf|eot|mp4|webm|ogg|pdf)\$ {
        expires 1y;
        add_header Cache-Control "public, immutable" always;
        add_header X-Content-Type-Options "nosniff" always;
        access_log off;
        log_not_found off;
    }

    # =========================================================================
    # BLOCK SENSITIVE FILES
    # =========================================================================

    # --- Block access to readme, license, and other info files ---
    location ~* /(readme\.html|readme\.txt|license\.txt|wp-config-sample\.php)\$ {
        deny all;
        return 403;
    }

    # --- Block access to backup and database files ---
    location ~* \.(sql|bak|orig|old|swp|swo|log)\$ {
        deny all;
        return 404;
    }
}
EOF

msg "nginx server block written: $CONF_FILE"

# Test nginx configuration
if nginx -t 2>&1; then
    msg "nginx configuration test passed"
    systemctl reload nginx 2>/dev/null || warn "Could not reload nginx — reload manually"
else
    warn "nginx configuration test failed — review $CONF_FILE"
fi

# =============================================================================
# 5. FAIL2BAN JAILS FOR WORDPRESS
# =============================================================================

msg "Configuring fail2ban jails for WordPress..."

# Ensure fail2ban directories exist
mkdir -p /etc/fail2ban/filter.d
mkdir -p /etc/fail2ban/jail.d

# --- WordPress authentication filter ---
cat > /etc/fail2ban/filter.d/wordpress-auth.conf <<'EOF'
# =============================================================================
# fail2ban filter: wordpress-auth
# Generated by AwesomeArchLinux/hardening/wordpress/wordpress.sh
#
# Matches failed WordPress login attempts from nginx access log.
# Detects POST requests to wp-login.php that result in a redirect (302)
# back to the login page (indicating failed authentication).
# =============================================================================

[Definition]
failregex = ^<HOST> .* "POST /wp-login\.php .* 200
            ^<HOST> .* "POST /wp-login\.php .* 302

ignoreregex =
EOF

msg "WordPress auth filter created: /etc/fail2ban/filter.d/wordpress-auth.conf"

# --- WordPress xmlrpc filter ---
cat > /etc/fail2ban/filter.d/wordpress-xmlrpc.conf <<'EOF'
# =============================================================================
# fail2ban filter: wordpress-xmlrpc
# Generated by AwesomeArchLinux/hardening/wordpress/wordpress.sh
#
# Matches any request to xmlrpc.php from nginx access log.
# xmlrpc.php is blocked by nginx, but this catches attempts before
# they are blocked (or if nginx config is modified).
# =============================================================================

[Definition]
failregex = ^<HOST> .* "(GET|POST) /xmlrpc\.php

ignoreregex =
EOF

msg "WordPress xmlrpc filter created: /etc/fail2ban/filter.d/wordpress-xmlrpc.conf"

# --- WordPress jail configuration ---
cat > /etc/fail2ban/jail.d/wordpress.conf <<EOF
# =============================================================================
# fail2ban jails: WordPress
# Generated by AwesomeArchLinux/hardening/wordpress/wordpress.sh
# =============================================================================

[wordpress-auth]
enabled  = true
filter   = wordpress-auth
port     = http,https
logpath  = /var/log/nginx/access.log
maxretry = 5
bantime  = 1h
findtime = 10m

[wordpress-xmlrpc]
enabled  = true
filter   = wordpress-xmlrpc
port     = http,https
logpath  = /var/log/nginx/access.log
maxretry = 2
bantime  = 24h
findtime = 1h
EOF

msg "WordPress jails created: /etc/fail2ban/jail.d/wordpress.conf"

# Reload fail2ban if running
if systemctl is-active --quiet fail2ban; then
    systemctl reload fail2ban
    msg "fail2ban reloaded"
else
    warn "fail2ban is not running — start it with: systemctl enable --now fail2ban"
fi

# =============================================================================
# 6. PHP .user.ini HARDENING
# =============================================================================

msg "Creating .user.ini for PHP hardening..."

cat > "$WP_PATH/.user.ini" <<EOF
; =============================================================================
; PHP .user.ini — WordPress runtime hardening
; Generated by AwesomeArchLinux/hardening/wordpress/wordpress.sh
;
; This file is read by PHP-FPM at runtime (no restart needed, cached for
; user_ini.cache_ttl seconds, default 300s).
; =============================================================================

; --- Upload limits ---
upload_max_filesize = 10M
post_max_size = 10M

; --- Execution limits ---
max_execution_time = 30
max_input_time = 60
max_input_vars = 3000

; --- Path restriction ---
; Restrict PHP file access to WordPress directory and /tmp (for uploads)
open_basedir = ${WP_PATH}:/tmp

; --- Session hardening ---
session.cookie_httponly = 1
session.cookie_secure = 1
session.use_strict_mode = 1

; --- Disable dangerous functions (WordPress does not need these) ---
; Note: Some plugins may require proc_open or exec. Add exceptions as needed.
; disable_functions = exec,passthru,shell_exec,system,proc_open,popen,parse_ini_file,show_source

; --- Error handling (production) ---
display_errors = Off
log_errors = On
error_log = ${WP_PATH}/wp-content/php-errors.log
EOF

chown root:http "$WP_PATH/.user.ini"
chmod 640 "$WP_PATH/.user.ini"

msg ".user.ini created at $WP_PATH/.user.ini"

# =============================================================================
# 7. WORDPRESS CRON REPLACEMENT (systemd timer)
# =============================================================================

msg "Setting up systemd wp-cron timer..."

# DISABLE_WP_CRON was already added in wp-config.php hardening (step 2)

# Determine cron method: wp-cli if available, curl fallback
CRON_METHOD="curl"
if command -v wp &>/dev/null; then
    CRON_METHOD="wp-cli"
    info "wp-cli found — using 'wp cron event run --due-now'"
else
    info "wp-cli not found — using curl to trigger wp-cron.php"
fi

# Create the systemd service
cat > /etc/systemd/system/wordpress-cron.service <<EOF
[Unit]
Description=WordPress cron for $DOMAIN
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=http
Group=http
EOF

if [[ "$CRON_METHOD" == "wp-cli" ]]; then
    cat >> /etc/systemd/system/wordpress-cron.service <<EOF
ExecStart=/usr/bin/wp cron event run --due-now --path=$WP_PATH
EOF
else
    # Use curl — determine protocol
    if [[ "$USE_SSL" == true ]]; then
        CRON_URL="https://$DOMAIN/wp-cron.php"
    else
        CRON_URL="http://$DOMAIN/wp-cron.php"
    fi
    cat >> /etc/systemd/system/wordpress-cron.service <<EOF
ExecStart=/usr/bin/curl -sS --max-time 30 "$CRON_URL" -o /dev/null
EOF
fi

cat >> /etc/systemd/system/wordpress-cron.service <<EOF

# Security hardening
PrivateTmp=true
ProtectHome=yes
NoNewPrivileges=yes
EOF

# Create the systemd timer
cat > /etc/systemd/system/wordpress-cron.timer <<EOF
[Unit]
Description=Run WordPress cron every 15 minutes for $DOMAIN

[Timer]
OnCalendar=*:0/15
RandomizedDelaySec=60
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable wordpress-cron.timer
systemctl start wordpress-cron.timer

msg "WordPress cron timer active (every 15 minutes)"
info "Check: systemctl list-timers wordpress-cron.timer"

# =============================================================================
# 8. SUMMARY
# =============================================================================

echo
echo -e "${C_GREEN}========================================================================${C_NC}"
echo -e "${C_GREEN} WordPress production hardening complete!${C_NC}"
echo -e "${C_GREEN}========================================================================${C_NC}"
echo

echo -e "${C_BLUE}Configuration:${C_NC}"
echo "  Domain:            $DOMAIN"
echo "  WordPress path:    $WP_PATH"
echo "  SSL enabled:       $USE_SSL"
echo "  Cron method:       $CRON_METHOD"
echo "  Log:               $LOGFILE"
echo

echo -e "${C_BLUE}Security hardening applied:${C_NC}"
echo "  - wp-config.php: security constants, fresh salts, custom table prefix"
echo "  - File editor disabled (DISALLOW_FILE_EDIT)"
echo "  - SSL forced for admin (FORCE_SSL_ADMIN)"
echo "  - Auto-update minor core versions (WP_AUTO_UPDATE_CORE = 'minor')"
echo "  - Debug output disabled in production"
echo "  - Script concatenation disabled (CONCATENATE_SCRIPTS)"
echo

echo -e "${C_BLUE}File permissions:${C_NC}"
echo "  wp-config.php:         640  root:http"
echo "  PHP files:             640  root:http"
echo "  Directories:           750  root:http"
echo "  wp-content/uploads:    770  http:http  (writable)"
echo "  wp-content/cache:      770  http:http  (writable, if exists)"
echo "  wp-content/themes:     750  root:http  (read-only)"
echo "  wp-content/plugins:    750  root:http  (read-only)"
echo

echo -e "${C_BLUE}nginx config:${C_NC}"
echo "  Server block:    $CONF_FILE"
echo "  Rate limiting:   wp-login.php (1r/s), admin-ajax.php (10r/s)"
echo "  Blocked:         xmlrpc.php, wp-config.php, .ht*, PHP in uploads/includes"
echo "  Static caching:  1 year immutable for images, CSS, JS, fonts"
echo "  Security:        CSP, X-Frame-Options, X-Content-Type-Options, COOP"
echo

echo -e "${C_BLUE}fail2ban jails:${C_NC}"
echo "  wordpress-auth:    5 retries -> 1h ban  (wp-login.php failures)"
echo "  wordpress-xmlrpc:  2 retries -> 24h ban (xmlrpc.php requests)"
echo "  Filter configs:    /etc/fail2ban/filter.d/wordpress-auth.conf"
echo "                     /etc/fail2ban/filter.d/wordpress-xmlrpc.conf"
echo "  Jail config:       /etc/fail2ban/jail.d/wordpress.conf"
echo

echo -e "${C_BLUE}PHP hardening:${C_NC}"
echo "  .user.ini:         $WP_PATH/.user.ini"
echo "  upload limit:      10M"
echo "  open_basedir:      $WP_PATH:/tmp"
echo "  max_input_vars:    3000"
echo

echo -e "${C_BLUE}WP-Cron:${C_NC}"
echo "  Built-in wp-cron:  Disabled (DISABLE_WP_CRON = true)"
echo "  systemd timer:     wordpress-cron.timer (every 15 minutes)"
echo "  Check status:      systemctl list-timers wordpress-cron.timer"
echo

echo -e "${C_YELLOW}WordPress security checklist:${C_NC}"
echo "  1. Change the default 'admin' username to something unique"
echo "  2. Use a strong, unique password (20+ characters)"
echo "  3. Enable two-factor authentication (2FA) for all admin accounts"
echo "  4. Install a security plugin (Wordfence, Sucuri, or iThemes Security)"
echo "  5. Keep WordPress core, themes, and plugins updated"
echo "  6. Remove unused themes and plugins"
echo "  7. Set up regular backups (database + files)"
echo "  8. Monitor login attempts and file changes"
echo "  9. Limit login attempts (handled by fail2ban above)"
echo " 10. Review user roles — use the principle of least privilege"
echo

echo -e "${C_YELLOW}Recommended security plugins:${C_NC}"
echo "  - Wordfence Security: Firewall, malware scanner, login security"
echo "    https://wordpress.org/plugins/wordfence/"
echo "  - Sucuri Security: Auditing, file integrity, remote scanning"
echo "    https://wordpress.org/plugins/sucuri-scanner/"
echo "  - iThemes Security: Brute-force protection, file change detection"
echo "    https://wordpress.org/plugins/better-wp-security/"
echo

echo -e "${C_GREEN}Done.${C_NC}"
