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
#                                  [--db-user USER] [--db-host HOST]
#                                  [--fresh-install] [-h]
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
DOMAIN=""
WP_PATH="/var/www/wordpress"
DB_NAME="wordpress"
DB_USER="wpuser"
DB_HOST="localhost"
DB_NAME_SET=false
DB_USER_SET=false
DB_HOST_SET=false
FRESH_INSTALL=false
LOGFILE="/var/log/wordpress-hardening-$(date +%Y%m%d-%H%M%S).log"

# --- Usage ---
usage() {
    cat <<EOF
Usage: sudo $0 [options]

Required:
  -d DOMAIN         Domain name for the WordPress site

Optional:
  -w WP_PATH        WordPress installation path (default: $WP_PATH)
  --db-name DB      Database name (default: $DB_NAME)
  --db-user USER    Database user (default: $DB_USER)
  --db-host HOST    Database host (default: $DB_HOST)
  --fresh-install   Randomize \$table_prefix even if DB credentials are already set
  -h                Show this help

Examples:
  sudo $0 -d example.com
  sudo $0 -d example.com -w /srv/http/wordpress
  sudo $0 -d blog.example.com --db-name wpblog --db-user bloguser
EOF
    exit 0
}

# --- Parse Arguments ---
need_arg() { [[ $# -ge 2 && -n "${2:-}" ]] || err "Option $1 requires a value"; }
while [[ $# -gt 0 ]]; do
    case "$1" in
        -d)              need_arg "$@"; DOMAIN="$2"; shift 2 ;;
        -w)              need_arg "$@"; WP_PATH="$2"; shift 2 ;;
        --db-name)       need_arg "$@"; DB_NAME="$2"; DB_NAME_SET=true; shift 2 ;;
        --db-user)       need_arg "$@"; DB_USER="$2"; DB_USER_SET=true; shift 2 ;;
        --db-host)       need_arg "$@"; DB_HOST="$2"; DB_HOST_SET=true; shift 2 ;;
        --fresh-install) FRESH_INSTALL=true; shift ;;
        -h|--help)       usage ;;
        *)               err "Unknown option: $1" ;;
    esac
done

# --- Validate ---
[[ $(id -u) -eq 0 ]] || err "Must be run as root"
[[ -n "$DOMAIN" ]]   || err "Domain is required (-d example.com)"
DOMAIN="${DOMAIN,,}"
aal_valid_hostname "$DOMAIN" || err "Invalid domain name: $DOMAIN"
[[ "$DB_NAME" =~ ^[A-Za-z0-9_$-]{1,64}$ ]] || err "Invalid database name: $DB_NAME"
[[ "$DB_USER" =~ ^[A-Za-z0-9_.-]{1,64}$ ]] || err "Invalid database user: $DB_USER"
[[ "$DB_HOST" =~ ^[\[\]A-Za-z0-9_.:/-]{1,253}$ ]] || err "Invalid database host: $DB_HOST"
command -v nginx &>/dev/null || err "nginx is not installed. Run ../nginx/nginx.sh first or: pacman -S nginx-mainline"

[[ -d "$WP_PATH" ]] || err "WordPress directory does not exist: $WP_PATH"
WP_PATH=$(realpath -- "$WP_PATH") || err "Could not resolve WordPress path"
case "$WP_PATH" in
    /var/www/*|/srv/http/*) ;;
    *) err "Unsafe WordPress path '$WP_PATH'. Use a dedicated directory below /var/www/ or /srv/http/." ;;
esac
[[ "$WP_PATH" =~ ^/(var/www|srv/http)/[A-Za-z0-9._/-]+$ ]] || \
    err "WordPress path contains unsupported characters: $WP_PATH"

# Redirect output to logfile as well
install -d -m 0755 /var/log
( umask 077 && : > "$LOGFILE" )
chmod 0600 "$LOGFILE"
exec > >(tee -a "$LOGFILE") 2>&1

info "Domain: $DOMAIN"
info "WordPress path: $WP_PATH"
info "Database: $DB_NAME@$DB_HOST (user: $DB_USER)"
info "Log: $LOGFILE"

# =============================================================================
# 1. VERIFY WORDPRESS EXISTS
# =============================================================================

msg "Verifying WordPress installation at $WP_PATH..."

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

# Detect SSL certificates BEFORE Step 2 so wp-config.php, nginx, .user.ini, and
# wp-cron all agree on HTTPS vs HTTP-only mode (preventing admin lockout).
USE_SSL=false
CERT_DIR="/etc/letsencrypt/live/$DOMAIN"
if [[ -f "$CERT_DIR/fullchain.pem" && -f "$CERT_DIR/privkey.pem" ]]; then
    USE_SSL=true
    info "SSL certificates found for $DOMAIN"
else
    warn "No SSL certificates found at $CERT_DIR — configuring HTTP-only"
    warn "Run ../nginx/nginx.sh for HTTPS setup, then re-run this script"
fi

wp_get_define_val() {
    local name="$1"
    [[ -f "$WP_PATH/wp-config.php" ]] || return 0
    WP_DEF_NAME="$name" awk -F"['\"]" '
        BEGIN {
            re = "^[[:space:]]*define[[:space:]]*\\([[:space:]]*[\x27\"]" ENVIRON["WP_DEF_NAME"] "[\x27\"]"
        }
        $0 ~ re { print $4; exit }
    ' "$WP_PATH/wp-config.php"
}

wp_db_has_placeholders() {
    [[ -f "$WP_PATH/wp-config.php" ]] || return 0
    local db_name_val db_user_val db_pass_val
    db_name_val=$(wp_get_define_val "DB_NAME")
    db_user_val=$(wp_get_define_val "DB_USER")
    db_pass_val=$(wp_get_define_val "DB_PASSWORD")
    [[ -z "$db_name_val" || "$db_name_val" == "database_name_here" || \
       -z "$db_user_val" || "$db_user_val" == "username_here" || \
       "$db_pass_val" == "password_here" ]]
}

INITIAL_DB_PLACEHOLDER=false
if wp_db_has_placeholders; then
    INITIAL_DB_PLACEHOLDER=true
fi

# =============================================================================
# 2. WP-CONFIG.PHP HARDENING
# =============================================================================

if [[ -f "$WP_PATH/wp-config.php" ]]; then
    msg "Hardening wp-config.php..."

    WP_CONFIG="$WP_PATH/wp-config.php"

    # Back up wp-config.php
    BACKUP="${WP_CONFIG}.bak.$(date +%Y%m%d-%H%M%S)"
    ( umask 077 && cp "$WP_CONFIG" "$BACKUP" )
    chmod 600 "$BACKUP"
    info "wp-config.php backed up to $BACKUP"

    # --- Helper: add or update an active define() constant ---
    # Matches only active non-comment lines using POSIX ERE. If absent, inserts
    # before "stop editing" or before require_once ... wp-settings.php.
    wp_define() {
        local name="$1"
        local value="$2"
        local active_re="^[[:space:]]*define[[:space:]]*\\([[:space:]]*['\"]${name}['\"]"
        local tmp_cfg
        tmp_cfg=$(umask 077; mktemp "$WP_PATH/.wp-config.def.XXXXXX")

        if grep -Eq "$active_re" "$WP_CONFIG"; then
            WP_DEF_NAME="$name" WP_DEF_VAL="$value" awk '
                BEGIN {
                    re = "^[[:space:]]*define[[:space:]]*\\([[:space:]]*[\x27\"]" ENVIRON["WP_DEF_NAME"] "[\x27\"]"
                }
                !updated && $0 ~ re {
                    printf "define(\x27%s\x27, %s);\n", ENVIRON["WP_DEF_NAME"], ENVIRON["WP_DEF_VAL"]
                    updated = 1
                    next
                }
                { print }
            ' "$WP_CONFIG" > "$tmp_cfg"
            chown root:http "$tmp_cfg" 2>/dev/null || true
            chmod 0640 "$tmp_cfg"
            mv -f -- "$tmp_cfg" "$WP_CONFIG"
            info "Updated: define('${name}', ${value})"
        else
            WP_DEF_NAME="$name" WP_DEF_VAL="$value" awk '
                !inserted && (/stop editing/ || /^[[:space:]]*require(_once)?[[:space:]\(].*wp-settings\.php/) {
                    printf "define(\x27%s\x27, %s);\n", ENVIRON["WP_DEF_NAME"], ENVIRON["WP_DEF_VAL"]
                    inserted = 1
                }
                { print }
                END {
                    if (!inserted) {
                        printf "define(\x27%s\x27, %s);\n", ENVIRON["WP_DEF_NAME"], ENVIRON["WP_DEF_VAL"]
                    }
                }
            ' "$WP_CONFIG" > "$tmp_cfg"
            chown root:http "$tmp_cfg" 2>/dev/null || true
            chmod 0640 "$tmp_cfg"
            mv -f -- "$tmp_cfg" "$WP_CONFIG"
            info "Added:   define('${name}', ${value})"
        fi
    }

    # --- Apply --db-name / --db-user / --db-host when explicitly passed or still placeholder ---
    CUR_DB_NAME=$(wp_get_define_val "DB_NAME")
    CUR_DB_USER=$(wp_get_define_val "DB_USER")
    CUR_DB_HOST=$(wp_get_define_val "DB_HOST")
    if [[ "$DB_NAME_SET" == true || "$CUR_DB_NAME" == "database_name_here" ]]; then
        wp_define "DB_NAME" "'${DB_NAME}'"
    fi
    if [[ "$DB_USER_SET" == true || "$CUR_DB_USER" == "username_here" ]]; then
        wp_define "DB_USER" "'${DB_USER}'"
    fi
    if [[ "$DB_HOST_SET" == true || -z "$CUR_DB_HOST" ]]; then
        wp_define "DB_HOST" "'${DB_HOST}'"
    fi

    # --- Security constants ---
    wp_define "DISALLOW_FILE_EDIT" "true"
    wp_define "DISALLOW_FILE_MODS" "false"
    if [[ "$USE_SSL" == true ]]; then
        wp_define "FORCE_SSL_ADMIN" "true"
    else
        wp_define "FORCE_SSL_ADMIN" "false"
    fi
    wp_define "WP_AUTO_UPDATE_CORE" "'minor'"
    wp_define "WP_DEBUG" "false"
    wp_define "WP_DEBUG_DISPLAY" "false"
    wp_define "WP_DEBUG_LOG" "false"
    wp_define "CONCATENATE_SCRIPTS" "false"
    wp_define "WP_MEMORY_LIMIT" "'256M'"
    wp_define "WP_MAX_MEMORY_LIMIT" "'512M'"
    wp_define "DISABLE_WP_CRON" "true"

    # --- Generate and set security keys/salts (pure awk splice, no sed /e shell execution) ---
    msg "Fetching fresh security keys/salts from WordPress API..."

    SALTS=$(curl -fsS --max-time 10 "https://api.wordpress.org/secret-key/1.1/salt/" 2>/dev/null || true)
    SALTS_VALID=false
    if [[ -n "$SALTS" ]]; then
        SALT_LINE_COUNT=$(awk '
            /^[[:space:]]*$/ { next }
            /^define\(['\''"](AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY|AUTH_SALT|SECURE_AUTH_SALT|LOGGED_IN_SALT|NONCE_SALT)['\''"],[[:space:]]*['\''"].+['\''"]\);$/ {
                valid++
                next
            }
            { invalid = 1 }
            END { print (invalid ? 0 : valid + 0) }
        ' <<< "$SALTS")
        (( SALT_LINE_COUNT == 8 )) && SALTS_VALID=true
    fi

    if [[ "$SALTS_VALID" == true ]]; then
        WP_DIR=$(dirname -- "$WP_CONFIG")
        SALT_TMPFILE=$(umask 077; mktemp "$WP_DIR/.wp-salts.XXXXXX")
        WP_CONFIG_TMP=$(umask 077; mktemp "$WP_DIR/.wp-config.XXXXXX")
        printf '%s\n' "$SALTS" > "$SALT_TMPFILE"

        awk -v salt_file="$SALT_TMPFILE" '
            /^[[:space:]]*define[[:space:]]*\([[:space:]]*['\''"](AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY|AUTH_SALT|SECURE_AUTH_SALT|LOGGED_IN_SALT|NONCE_SALT)['\''"]/ { next }
            !inserted && (/stop editing/ || /^[[:space:]]*require(_once)?[[:space:]\(].*wp-settings\.php/) {
                while ((getline salt_line < salt_file) > 0) {
                    print salt_line
                }
                close(salt_file)
                inserted = 1
            }
            { print }
            END {
                if (!inserted) {
                    while ((getline salt_line < salt_file) > 0) {
                        print salt_line
                    }
                    close(salt_file)
                }
            }
        ' "$WP_CONFIG" > "$WP_CONFIG_TMP"
        chown root:http "$WP_CONFIG_TMP"
        chmod 0640 "$WP_CONFIG_TMP"
        mv -f -- "$WP_CONFIG_TMP" "$WP_CONFIG"
        rm -f -- "$SALT_TMPFILE"
        msg "Security keys/salts updated from WordPress API"
    else
        warn "Could not fetch valid salts from WordPress API — existing keys unchanged"
        warn "Manually visit: https://api.wordpress.org/secret-key/1.1/salt/"
    fi

    # --- Randomize table prefix only on unconfigured/fresh installs ---
    if grep -qE '^[[:space:]]*\$table_prefix[[:space:]]*=[[:space:]]*["\x27]wp_["\x27]' "$WP_CONFIG"; then
        if [[ "$FRESH_INSTALL" == true || "$INITIAL_DB_PLACEHOLDER" == true ]] || wp_db_has_placeholders; then
            RANDOM_PREFIX=""
            while (( ${#RANDOM_PREFIX} < 4 )); do
                RANDOM_PREFIX+=$(dd if=/dev/urandom bs=64 count=1 2>/dev/null | LC_ALL=C tr -dc 'a-z')
            done
            RANDOM_PREFIX="${RANDOM_PREFIX:0:4}_"
            sed -i "s|^[[:space:]]*\\\$table_prefix[[:space:]]*=[[:space:]]*['\"]wp_['\"]|\$table_prefix = '${RANDOM_PREFIX}'|" "$WP_CONFIG"
            msg "Table prefix changed from 'wp_' to '${RANDOM_PREFIX}'"
            if [[ "$FRESH_INSTALL" == true && "$INITIAL_DB_PLACEHOLDER" == false ]]; then
                warn "IMPORTANT: Ensure database table names match '${RANDOM_PREFIX}' if tables already exist."
            fi
        else
            info "Keeping existing \$table_prefix = 'wp_' (DB credentials are already configured; pass --fresh-install before installation to randomize)"
        fi
    else
        info "Table prefix is already custom — no change needed"
    fi

    # --- Add content directory comment ---
    if ! grep -q "WP_CONTENT_DIR" "$WP_CONFIG"; then
        WP_SCHEME="http"
        [[ "$USE_SSL" == true ]] && WP_SCHEME="https"
        WP_CONFIG_TMP=$(umask 077; mktemp "$WP_PATH/.wp-config.cnt.XXXXXX")
        WP_URL="${WP_SCHEME}://${DOMAIN}/wp-content" awk '
            !inserted && (/stop editing/ || /^[[:space:]]*require(_once)?[[:space:]\(].*wp-settings\.php/) {
                print "// Optional: Move wp-content outside the web root for extra security"
                print "// define(\x27WP_CONTENT_DIR\x27, dirname(__FILE__) . \x27/wp-content\x27);"
                print "// define(\x27WP_CONTENT_URL\x27, \x27" ENVIRON["WP_URL"] "\x27);"
                inserted = 1
            }
            { print }
        ' "$WP_CONFIG" > "$WP_CONFIG_TMP"
        chown root:http "$WP_CONFIG_TMP" 2>/dev/null || true
        chmod 0640 "$WP_CONFIG_TMP"
        mv -f -- "$WP_CONFIG_TMP" "$WP_CONFIG"
        info "Added WP_CONTENT_DIR comment block"
    fi

    msg "wp-config.php hardening complete"
fi

# =============================================================================
# 3. FILE PERMISSIONS
# =============================================================================

msg "Setting WordPress file permissions..."

# --- Ensure parent webroot hierarchy is traversable by nginx (http) ---
for base_root in /var/www /srv/http; do
    if [[ "$WP_PATH" == "$base_root"/* ]]; then
        chmod 0755 "$base_root"
        parent_walk=$(dirname -- "$WP_PATH")
        while [[ "$parent_walk" != "$base_root" && "$parent_walk" != "/" ]]; do
            chown root:http "$parent_walk"
            chmod 0750 "$parent_walk"
            parent_walk=$(dirname -- "$parent_walk")
        done
    fi
done

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

# Remove install.php ONLY when WordPress is already configured (never on --fresh-install
# or when DB credentials are still placeholders)
if [[ -f "$WP_PATH/wp-admin/install.php" ]]; then
    if [[ "$FRESH_INSTALL" == true || "$INITIAL_DB_PLACEHOLDER" == true ]] || wp_db_has_placeholders; then
        info "Preserving wp-admin/install.php (fresh install or placeholder DB credentials)"
    else
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

# Back up existing config
if [[ -f "$CONF_FILE" ]]; then
    CONF_PREEXISTED=true
    BACKUP="${CONF_FILE}.bak.$(date +%Y%m%d-%H%M%S)"
    cp "$CONF_FILE" "$BACKUP"
    CONF_BACKUP="$BACKUP"
    info "Existing nginx config backed up to $BACKUP"
fi

# Avoid www.www.example.com when $DOMAIN already starts with www. or is single-label
if [[ "$DOMAIN" == www.* || "$DOMAIN" != *.* ]]; then
    SERVER_NAMES="$DOMAIN"
else
    SERVER_NAMES="$DOMAIN www.$DOMAIN"
fi

# Warn if /etc/nginx/sites-enabled/default.conf shadows $DOMAIN
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
                    cand = tolower(names[i])
                    if (cand == ENVIRON["DOMAIN_TARGET"] || cand == "www." ENVIRON["DOMAIN_TARGET"]) {
                        found = 1
                        exit
                    }
                }
            }
        }
        END { exit !found }
    ' "$DEFAULT_SITE"; then
        warn "$DEFAULT_SITE also declares server_name for '$DOMAIN' and may shadow $CONF_FILE."
        warn "Remove or update $DEFAULT_SITE after verifying $CONF_FILE."
    fi
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

# Build listen, SSL, HSTS, and CSP directives
if [[ "$USE_SSL" == true ]]; then
    LISTEN_BLOCK="    listen 443 ssl;
    listen [::]:443 ssl;
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
    LISTEN_BLOCK="    listen 80;
    listen [::]:80;"
    SSL_BLOCK=""
    CSP_UPGRADE=""
    HSTS_SERVER_LINE=""
    HSTS_LOC_LINE=""
fi

WP_CSP="default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data: https:; font-src 'self' https://fonts.gstatic.com data:; connect-src 'self' https:; frame-ancestors 'self'; form-action 'self'; base-uri 'self';${CSP_UPGRADE}"

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
    server_name $SERVER_NAMES;

    # ACME challenge (certbot renewal)
    location ^~ /.well-known/acme-challenge/ {
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
    server_name $SERVER_NAMES;
$SSL_BLOCK

    root $WP_PATH;
    index index.php index.html;

    # Hide PHP version
    fastcgi_hide_header X-Powered-By;

    # --- Security headers ---
${HSTS_SERVER_LINE}    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;
    add_header Cross-Origin-Opener-Policy "same-origin" always;

    # --- Content-Security-Policy (tuned for WordPress) ---
    # WordPress admin requires 'unsafe-inline' and 'unsafe-eval' for scripts/styles.
    # Adjust connect-src, img-src, and font-src for your themes and plugins.
    add_header Content-Security-Policy "${WP_CSP}" always;

    # =========================================================================
    # WORDPRESS PERMALINKS
    # =========================================================================

    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }

    # =========================================================================
    # EXACT & REGEX DENY RULES (evaluated before FastCGI PHP handler)
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
    location ~* /wp-content/uploads/.*\.php$ {
        deny all;
        return 403;
    }

    # --- Block direct PHP execution in wp-includes ---
    location ~* /wp-includes/.*\.php$ {
        deny all;
        return 403;
    }

    # --- Block all direct PHP execution in wp-content (no index.php exception!) ---
    location ~* /wp-content/.*\.php$ {
        deny all;
        return 403;
    }

    # --- Block access to readme, license, and sample config files ---
    location ~* /(readme\.html|readme\.txt|license\.txt|wp-config-sample\.php)$ {
        deny all;
        return 403;
    }

    # --- Block access to backup, SQL, editor swap, and log files ---
    location ~* \.(sql|bak|orig|old|swp|swo|log)$ {
        deny all;
        return 404;
    }

    # =========================================================================
    # RATE-LIMITED & ADMIN ENDPOINTS
    # =========================================================================

    # --- Rate limit wp-login.php ---
    location = /wp-login.php {
        try_files \$uri =404;
        limit_req zone=wp_login_${DOMAIN//./_} burst=3 nodelay;
        limit_req_status 429;

        fastcgi_split_path_info ^(.+\.php)(/.+)\$;
        fastcgi_pass unix:$PHP_SOCKET;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
        fastcgi_hide_header X-Powered-By;
    }

    # --- Rate limit admin-ajax.php ---
    location = /wp-admin/admin-ajax.php {
        try_files \$uri =404;
        limit_req zone=wp_ajax_${DOMAIN//./_} burst=20 nodelay;
        limit_req_status 429;

        fastcgi_split_path_info ^(.+\.php)(/.+)\$;
        fastcgi_pass unix:$PHP_SOCKET;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
        fastcgi_hide_header X-Powered-By;
    }

    # --- Noindex wp-admin for search engines (re-add server security headers) ---
    location /wp-admin/ {
        add_header X-Robots-Tag "noindex, nofollow" always;
${HSTS_LOC_LINE}        add_header X-Content-Type-Options "nosniff" always;
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;
        add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;
        add_header Cross-Origin-Opener-Policy "same-origin" always;
        add_header Content-Security-Policy "${WP_CSP}" always;

        location ~ /\.(?!well-known) {
            deny all;
            return 404;
        }

        location ~* \.(sql|bak|orig|old|swp|swo|log)$ {
            deny all;
            return 404;
        }

        location ~ \.php$ {
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

    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|webp|avif|woff|woff2|ttf|eot|mp4|webm|ogg|pdf)$ {
        expires 1y;
        add_header Cache-Control "public, immutable" always;
${HSTS_LOC_LINE}        add_header X-Content-Type-Options "nosniff" always;
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;
        access_log off;
        log_not_found off;
    }

    # =========================================================================
    # PHP-FPM (evaluated AFTER all deny regexes above!)
    # =========================================================================

    location ~ \.php$ {
        try_files \$uri =404;

        fastcgi_split_path_info ^(.+\.php)(/.+)\$;
        fastcgi_pass unix:$PHP_SOCKET;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
        fastcgi_hide_header X-Powered-By;

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
}
EOF

chmod 0644 "$CONF_FILE"
msg "nginx server block written: $CONF_FILE"

# Test and start/reload nginx configuration
if nginx -t 2>&1; then
    msg "nginx configuration test passed"
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
# 5. FAIL2BAN JAILS FOR WORDPRESS
# =============================================================================

msg "Configuring fail2ban jails for WordPress..."

# Ensure fail2ban and nginx log directories exist
install -d -m 0755 /etc/fail2ban/filter.d /etc/fail2ban/jail.d /var/log/nginx
[[ -f /var/log/nginx/access.log ]] || install -m 0640 -o http -g log /dev/null /var/log/nginx/access.log 2>/dev/null || touch /var/log/nginx/access.log

# --- WordPress authentication filter ---
cat > /etc/fail2ban/filter.d/wordpress-auth.conf <<'EOF'
# =============================================================================
# fail2ban filter: wordpress-auth
# Generated by AwesomeArchLinux/hardening/wordpress/wordpress.sh
#
# Matches failed WordPress login attempts from nginx access log.
# Failed logins re-render wp-login.php with HTTP 200; successful logins return
# HTTP 302 to /wp-admin/ and must NOT be matched here.
# =============================================================================

[Definition]
failregex = ^<HOST> .* "POST /wp-login\.php[^"]*" 200\b

ignoreregex =
EOF
chmod 0644 /etc/fail2ban/filter.d/wordpress-auth.conf

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
chmod 0644 /etc/fail2ban/filter.d/wordpress-xmlrpc.conf

msg "WordPress xmlrpc filter created: /etc/fail2ban/filter.d/wordpress-xmlrpc.conf"

# --- WordPress jail configuration (backend = auto for file logpath on Arch) ---
cat > /etc/fail2ban/jail.d/wordpress.conf <<EOF
# =============================================================================
# fail2ban jails: WordPress
# Generated by AwesomeArchLinux/hardening/wordpress/wordpress.sh
# =============================================================================

[wordpress-auth]
enabled  = true
backend  = auto
filter   = wordpress-auth
port     = http,https
logpath  = /var/log/nginx/access.log
maxretry = 5
bantime  = 1h
findtime = 10m

[wordpress-xmlrpc]
enabled  = true
backend  = auto
filter   = wordpress-xmlrpc
port     = http,https
logpath  = /var/log/nginx/access.log
maxretry = 2
bantime  = 24h
findtime = 1h
EOF
chmod 0644 /etc/fail2ban/jail.d/wordpress.conf

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

install -d -o http -g http -m 0750 /var/log/php
[[ -f /var/log/php/wordpress-errors.log ]] || install -o http -g http -m 0640 /dev/null /var/log/php/wordpress-errors.log

COOKIE_SECURE=0
[[ "$USE_SSL" == true ]] && COOKIE_SECURE=1

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
; Restrict PHP file access to WordPress directory, /tmp, and dedicated PHP log dir
open_basedir = ${WP_PATH}:/tmp:/var/log/php:/usr/share/php

; --- Session hardening ---
session.cookie_httponly = 1
session.cookie_secure = ${COOKIE_SECURE}
session.use_strict_mode = 1

; --- Disable dangerous functions (WordPress does not need these) ---
; Note: Some plugins may require proc_open or exec. Add exceptions as needed.
; disable_functions = exec,passthru,shell_exec,system,proc_open,popen,parse_ini_file,show_source

; --- Error handling (production, logged outside public webroot) ---
display_errors = Off
log_errors = On
error_log = /var/log/php/wordpress-errors.log
EOF

chown root:http "$WP_PATH/.user.ini"
chmod 640 "$WP_PATH/.user.ini"

msg ".user.ini created at $WP_PATH/.user.ini"

# Check php.ini / php-fpm pool overrides (e.g. from ../php/php.sh) for conflicts
PHP_INI_FILE="/etc/php/php.ini"
shopt -s nullglob
FPM_POOL_FILES=(/etc/php/php-fpm.d/*.conf)
shopt -u nullglob

CURL_EXEC_DISABLED=false
URL_FOPEN_OFF=false
if [[ -f "$PHP_INI_FILE" ]]; then
    if grep -Eq '^[[:space:]]*disable_functions[[:space:]]*=.*(^|[,[:space:]])curl_exec([,[:space:]]|$)' "$PHP_INI_FILE"; then
        CURL_EXEC_DISABLED=true
    fi
    if grep -Eqi '^[[:space:]]*allow_url_fopen[[:space:]]*=[[:space:]]*(off|0|false|no)([[:space:];]|$)' "$PHP_INI_FILE"; then
        URL_FOPEN_OFF=true
    fi
fi
for pool_conf in "${FPM_POOL_FILES[@]}"; do
    if grep -Eq '^[[:space:]]*php_admin_value\[disable_functions\][[:space:]]*=.*(^|[,[:space:]])curl_exec([,[:space:]]|$)' "$pool_conf"; then
        CURL_EXEC_DISABLED=true
    fi
    if grep -Eqi '^[[:space:]]*php_admin_(flag|value)\[allow_url_fopen\][[:space:]]*=[[:space:]]*(off|0|false|no)([[:space:];]|$)' "$pool_conf"; then
        URL_FOPEN_OFF=true
    fi
    while IFS= read -r basedir_val; do
        [[ -n "$basedir_val" ]] || continue
        wp_covered=false
        log_covered=false
        IFS=':' read -r -a basedir_paths <<< "$basedir_val"
        for bd_path in "${basedir_paths[@]}"; do
            bd_clean="${bd_path%/}"
            [[ -n "$bd_clean" ]] || continue
            if [[ "$WP_PATH" == "$bd_clean" || "$WP_PATH" == "$bd_clean"/* ]]; then
                wp_covered=true
            fi
            if [[ "/var/log/php" == "$bd_clean" || "/var/log/php" == "$bd_clean"/* ]]; then
                log_covered=true
            fi
        done
        if [[ "$wp_covered" == false || "$log_covered" == false ]]; then
            warn "$pool_conf sets php_admin_value[open_basedir]='$basedir_val', which overrides .user.ini and excludes $( [[ "$wp_covered" == false ]] && printf '%s ' "$WP_PATH" )$( [[ "$log_covered" == false ]] && printf '/var/log/php' )."
            warn "Add $WP_PATH and /var/log/php to php_admin_value[open_basedir] in $pool_conf, then reload php-fpm."
        fi
    done < <(
        awk '/^[[:space:]]*php_admin_value\[open_basedir\][[:space:]]*=/ {
            val = substr($0, index($0, "=") + 1)
            sub(/;.*/, "", val)
            gsub(/^[[:space:]"'\'']+|[[:space:]"'\'']+$/, "", val)
            print val
        }' "$pool_conf"
    )
done
if [[ "$CURL_EXEC_DISABLED" == true && "$URL_FOPEN_OFF" == true ]]; then
    warn "PHP has both curl_exec disabled and allow_url_fopen=Off (e.g. from ../php/php.sh)."
    warn "WordPress updates, loopback cron, and remote API calls require outbound HTTP — re-enable curl_exec in /etc/php/php.ini and reload php-fpm."
fi

# =============================================================================
# 7. WORDPRESS CRON REPLACEMENT (per-domain systemd timer)
# =============================================================================

msg "Setting up systemd wp-cron timer..."

# DISABLE_WP_CRON was already added in wp-config.php hardening (step 2)
CRON_UNIT_BASE="wordpress-cron-${DOMAIN//./-}"

# Clean up legacy single-site unit if it belonged to this exact domain
if [[ -f /etc/systemd/system/wordpress-cron.service ]] && \
   grep -Fqx "Description=WordPress cron for $DOMAIN" /etc/systemd/system/wordpress-cron.service; then
    systemctl disable --now wordpress-cron.timer 2>/dev/null || true
    rm -f /etc/systemd/system/wordpress-cron.service /etc/systemd/system/wordpress-cron.timer
fi

# Determine cron method: wp-cli if available, curl fallback
CRON_METHOD="curl"
if command -v wp &>/dev/null; then
    CRON_METHOD="wp-cli"
    info "wp-cli found — using 'wp cron event run --due-now'"
else
    info "wp-cli not found — using curl to trigger wp-cron.php"
fi

install -d -m 0755 /etc/systemd/system
# Create the per-domain systemd service
cat > "/etc/systemd/system/${CRON_UNIT_BASE}.service" <<EOF
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
    cat >> "/etc/systemd/system/${CRON_UNIT_BASE}.service" <<EOF
ExecStart=/usr/bin/wp cron event run --due-now --path=$WP_PATH
EOF
else
    if [[ "$USE_SSL" == true ]]; then
        CRON_PORT=443
        CRON_URL="https://${DOMAIN}/wp-cron.php?doing_wp_cron"
    else
        CRON_PORT=80
        CRON_URL="http://${DOMAIN}/wp-cron.php?doing_wp_cron"
    fi
    cat >> "/etc/systemd/system/${CRON_UNIT_BASE}.service" <<EOF
ExecStart=/usr/bin/curl -fsS --max-time 30 --resolve "${DOMAIN}:${CRON_PORT}:127.0.0.1" "${CRON_URL}" -o /dev/null
EOF
fi

cat >> "/etc/systemd/system/${CRON_UNIT_BASE}.service" <<EOF

# Security hardening
ProtectSystem=strict
ReadWritePaths=-${WP_PATH}/wp-content/uploads -${WP_PATH}/wp-content/cache -/var/log/php
PrivateTmp=true
ProtectHome=yes
NoNewPrivileges=yes
EOF

# Create the per-domain systemd timer
cat > "/etc/systemd/system/${CRON_UNIT_BASE}.timer" <<EOF
[Unit]
Description=Run WordPress cron every 15 minutes for $DOMAIN

[Timer]
OnCalendar=*:0/15
RandomizedDelaySec=60
Persistent=true

[Install]
WantedBy=timers.target
EOF
chmod 0644 "/etc/systemd/system/${CRON_UNIT_BASE}.service" "/etc/systemd/system/${CRON_UNIT_BASE}.timer"

systemctl daemon-reload
systemctl enable --now "${CRON_UNIT_BASE}.timer"

msg "WordPress cron timer active: ${CRON_UNIT_BASE}.timer (every 15 minutes)"
info "Check: systemctl list-timers ${CRON_UNIT_BASE}.timer"

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
echo "  - Admin SSL policy: FORCE_SSL_ADMIN = $USE_SSL"
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
echo "  open_basedir:      $WP_PATH:/tmp:/var/log/php:/usr/share/php"
echo "  error_log:         /var/log/php/wordpress-errors.log"
echo "  max_input_vars:    3000"
echo

echo -e "${C_BLUE}WP-Cron:${C_NC}"
echo "  Built-in wp-cron:  Disabled (DISABLE_WP_CRON = true)"
echo "  systemd timer:     ${CRON_UNIT_BASE}.timer (every 15 minutes)"
echo "  Check status:      systemctl list-timers ${CRON_UNIT_BASE}.timer"
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
