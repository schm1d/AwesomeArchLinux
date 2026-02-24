#!/usr/bin/env bash

# =============================================================================
# Script:      php.sh
# Description: Installs and hardens PHP for production on Arch Linux,
#              including:
#                - Hardened php.ini (error handling, security, sessions, limits)
#                - Hardened PHP-FPM pool (Unix socket, process management)
#                - systemd service sandboxing
#                - Optional nginx FastCGI integration
#                - Log rotation and secure directory structure
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
#
# Usage:       sudo ./php.sh [--with-fpm] [--with-nginx] [--pool-user POOL_USER]
#                             [-v VERSION] [-h]
#
# Requirements:
#   - Arch Linux with pacman
#   - Root privileges
#
# What this script does:
#   1.  Installs PHP and security-related extensions
#   2.  Hardens php.ini (error handling, security, sessions, resource limits)
#   3.  Hardens PHP-FPM pool configuration (Unix socket, process management)
#   4.  Creates log and session directories with proper permissions
#   5.  Optionally creates an nginx FastCGI configuration snippet
#   6.  Hardens the PHP-FPM systemd service with security overrides
#   7.  Creates logrotate configuration for PHP logs
#   8.  Enables and starts PHP-FPM
#   9.  Prints a security summary
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
WITH_FPM=true
WITH_NGINX=false
POOL_USER="http"
VERSION=""
PHP_INI="/etc/php/php.ini"
FPM_POOL="/etc/php/php-fpm.d/www.conf"
LOGFILE="/var/log/php-hardening-$(date +%Y%m%d-%H%M%S).log"

# --- Usage ---
usage() {
    cat <<EOF
Usage: sudo $0 [options]

Options:
  --with-fpm          Enable PHP-FPM hardening (default: enabled)
  --no-fpm            Disable PHP-FPM hardening
  --with-nginx        Create nginx FastCGI configuration snippet
  --pool-user USER    PHP-FPM pool user (default: $POOL_USER)
  -v VERSION          PHP version hint (informational only; pacman installs current)
  -h, --help          Show this help

Examples:
  sudo $0                                    # Default: harden PHP + FPM
  sudo $0 --with-nginx                       # Also create nginx snippet
  sudo $0 --with-nginx --pool-user www-data  # Custom pool user
  sudo $0 --no-fpm                           # Harden php.ini only, skip FPM
EOF
    exit 0
}

# --- Parse Arguments ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --with-fpm)     WITH_FPM=true; shift ;;
        --no-fpm)       WITH_FPM=false; shift ;;
        --with-nginx)   WITH_NGINX=true; shift ;;
        --pool-user)    POOL_USER="$2"; shift 2 ;;
        -v)             VERSION="$2"; shift 2 ;;
        -h|--help)      usage ;;
        *)              err "Unknown option: $1" ;;
    esac
done

# --- Validate ---
[[ $(id -u) -eq 0 ]] || err "Must be run as root"

# Redirect output to logfile as well
exec > >(tee -a "$LOGFILE") 2>&1

info "PHP-FPM:    $WITH_FPM"
info "nginx:      $WITH_NGINX"
info "Pool user:  $POOL_USER"
info "Log:        $LOGFILE"
if [[ -n "$VERSION" ]]; then
    info "Version hint: $VERSION (pacman installs the current version)"
fi

# =============================================================================
# 1. INSTALL PHP AND SECURITY-RELATED EXTENSIONS
# =============================================================================

msg "Installing PHP and security-related extensions..."

# Core packages to install
PACKAGES=(php php-fpm php-gd php-intl php-sodium)

# Install only what's available, skip gracefully if a package isn't found
INSTALL_PACKAGES=()
for pkg in "${PACKAGES[@]}"; do
    if pacman -Si "$pkg" &>/dev/null; then
        INSTALL_PACKAGES+=("$pkg")
    else
        warn "Package '$pkg' not found in repositories, skipping"
    fi
done

if [[ ${#INSTALL_PACKAGES[@]} -gt 0 ]]; then
    pacman -Syu --noconfirm --needed "${INSTALL_PACKAGES[@]}"
else
    err "No PHP packages could be found. Check your pacman configuration."
fi

PHP_VER=$(php -v 2>/dev/null | head -1 || echo "unknown")
info "Installed: $PHP_VER"

# =============================================================================
# 2. HARDEN php.ini
# =============================================================================

msg "Hardening php.ini..."

if [[ ! -f "$PHP_INI" ]]; then
    err "php.ini not found at $PHP_INI"
fi

# Back up the original
BACKUP="${PHP_INI}.bak.$(date +%Y%m%d-%H%M%S)"
cp "$PHP_INI" "$BACKUP"
info "Backup created: $BACKUP"

# Helper: set a php.ini directive using sed
# Handles both commented and uncommented directives
set_ini() {
    local key="$1"
    local value="$2"
    local file="$3"

    # If the directive exists (commented or not), replace it
    if grep -qE "^\s*;?\s*${key}\s*=" "$file"; then
        sed -i "s|^\s*;*\s*${key}\s*=.*|${key} = ${value}|" "$file"
    else
        # Append if not found at all
        echo "${key} = ${value}" >> "$file"
    fi
}

# --- Error handling (production) ---
info "Setting error handling directives..."
set_ini "expose_php"            "Off"                                    "$PHP_INI"
set_ini "display_errors"        "Off"                                    "$PHP_INI"
set_ini "display_startup_errors" "Off"                                   "$PHP_INI"
set_ini "log_errors"            "On"                                     "$PHP_INI"
set_ini "error_log"             "/var/log/php/error.log"                 "$PHP_INI"
set_ini "error_reporting"       "E_ALL & ~E_DEPRECATED & ~E_STRICT"     "$PHP_INI"

# --- Security ---
info "Setting security directives..."

DISABLE_FUNCTIONS="exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source,highlight_file,phpinfo"
set_ini "disable_functions"     "$DISABLE_FUNCTIONS"                     "$PHP_INI"

set_ini "allow_url_fopen"       "Off"                                    "$PHP_INI"
set_ini "allow_url_include"     "Off"                                    "$PHP_INI"
set_ini "open_basedir"          "/var/www:/tmp:/usr/share/php"           "$PHP_INI"
set_ini "cgi.fix_pathinfo"      "0"                                      "$PHP_INI"

# --- Session security ---
info "Setting session security directives..."
set_ini "session.cookie_httponly"       "1"                              "$PHP_INI"
set_ini "session.cookie_secure"        "1"                              "$PHP_INI"
set_ini "session.use_strict_mode"      "1"                              "$PHP_INI"
set_ini "session.cookie_samesite"      "Strict"                         "$PHP_INI"
set_ini "session.use_only_cookies"     "1"                              "$PHP_INI"
set_ini "session.name"                 "__Secure-PHPSESSID"             "$PHP_INI"
set_ini "session.sid_length"           "48"                             "$PHP_INI"
set_ini "session.sid_bits_per_character" "6"                            "$PHP_INI"

# --- Resource limits ---
info "Setting resource limit directives..."
set_ini "max_execution_time"    "30"                                     "$PHP_INI"
set_ini "max_input_time"        "30"                                     "$PHP_INI"
set_ini "memory_limit"          "256M"                                   "$PHP_INI"
set_ini "post_max_size"         "10M"                                    "$PHP_INI"
set_ini "upload_max_filesize"   "10M"                                    "$PHP_INI"
set_ini "max_file_uploads"      "5"                                      "$PHP_INI"
set_ini "max_input_vars"        "1000"                                   "$PHP_INI"
set_ini "max_input_nesting_level" "64"                                   "$PHP_INI"

# --- Session storage ---
info "Setting session storage directives..."
set_ini "session.save_handler"     "files"                              "$PHP_INI"
set_ini "session.save_path"        "/var/lib/php/sessions"              "$PHP_INI"
set_ini "session.gc_maxlifetime"   "1440"                               "$PHP_INI"

msg "php.ini hardened successfully"

# =============================================================================
# 3. HARDEN PHP-FPM POOL
# =============================================================================

if [[ "$WITH_FPM" == true ]]; then
    msg "Hardening PHP-FPM pool configuration..."

    if [[ ! -f "$FPM_POOL" ]]; then
        # Create the pool directory and file if it doesn't exist
        mkdir -p "$(dirname "$FPM_POOL")"
        warn "Pool config not found at $FPM_POOL, creating from scratch"
        touch "$FPM_POOL"
    else
        # Back up the original
        FPM_BACKUP="${FPM_POOL}.bak.$(date +%Y%m%d-%H%M%S)"
        cp "$FPM_POOL" "$FPM_BACKUP"
        info "Backup created: $FPM_BACKUP"
    fi

    cat > "$FPM_POOL" <<EOF
; =============================================================================
; PHP-FPM pool configuration — hardened for production
; Generated by AwesomeArchLinux/hardening/php/php.sh
; =============================================================================

[www]

; --- User and Group ---
user = $POOL_USER
group = $POOL_USER

; --- Listen (Unix socket, not TCP — avoids network exposure) ---
listen = /run/php-fpm/php-fpm.sock
listen.owner = http
listen.group = http
listen.mode = 0660

; --- Process Management ---
pm = dynamic
pm.max_children = 25
pm.start_servers = 5
pm.min_spare_servers = 2
pm.max_spare_servers = 10
pm.max_requests = 500

; --- Monitoring ---
pm.status_path = /fpm-status
ping.path = /fpm-ping

; --- Timeouts ---
request_terminate_timeout = 60

; --- Resource Limits ---
rlimit_files = 1024
rlimit_core = 0

; --- Security: PHP admin overrides (cannot be changed by application code) ---
php_admin_value[open_basedir] = /var/www:/tmp
php_admin_flag[allow_url_fopen] = off

; --- Logging ---
access.log = /var/log/php/fpm-access.log
slowlog = /var/log/php/fpm-slow.log
request_slowlog_timeout = 5

; --- File Extension Security ---
security.limit_extensions = .php

; --- Environment ---
clear_env = yes
EOF

    msg "PHP-FPM pool hardened: $FPM_POOL"
fi

# =============================================================================
# 4. CREATE LOG AND SESSION DIRECTORIES
# =============================================================================

msg "Creating log and session directories..."

# PHP error and FPM log directory
mkdir -p /var/log/php
chown http:http /var/log/php
chmod 750 /var/log/php

# PHP session directory
mkdir -p /var/lib/php/sessions
chown http:http /var/lib/php/sessions
chmod 750 /var/lib/php/sessions

# PHP-FPM socket directory
mkdir -p /run/php-fpm
chown http:http /run/php-fpm
chmod 750 /run/php-fpm

msg "Directories created with secure permissions"

# =============================================================================
# 5. NGINX FASTCGI CONFIGURATION (optional)
# =============================================================================

if [[ "$WITH_NGINX" == true ]]; then
    msg "Creating nginx FastCGI configuration..."

    NGINX_PHP_CONF="/etc/nginx/conf.d/php-fpm.conf"
    mkdir -p /etc/nginx/conf.d

    cat > "$NGINX_PHP_CONF" <<'EOF'
# =============================================================================
# nginx FastCGI configuration for PHP-FPM
# Generated by AwesomeArchLinux/hardening/php/php.sh
#
# Include this in your server block:
#   location ~ \.php$ {
#       include conf.d/php-fpm.conf;
#   }
#
# Or use the full configuration below as a reference.
# =============================================================================

# --- FastCGI pass to PHP-FPM Unix socket ---
fastcgi_pass unix:/run/php-fpm/php-fpm.sock;
fastcgi_index index.php;

# --- Required parameters ---
fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
include fastcgi_params;

# --- Security: hide PHP version header ---
fastcgi_hide_header X-Powered-By;

# --- Security: restrict open_basedir per vhost ---
fastcgi_param PHP_VALUE "open_basedir=/var/www:/tmp";

# --- FastCGI performance ---
fastcgi_buffering on;
fastcgi_buffer_size 16k;
fastcgi_buffers 16 16k;
fastcgi_busy_buffers_size 32k;
fastcgi_read_timeout 60;
fastcgi_send_timeout 60;
fastcgi_connect_timeout 30;
EOF

    msg "nginx FastCGI config created: $NGINX_PHP_CONF"

    # Create a sample server block with PHP and upload security
    NGINX_PHP_SAMPLE="/etc/nginx/conf.d/php-security.conf.sample"

    cat > "$NGINX_PHP_SAMPLE" <<'EOF'
# =============================================================================
# Sample nginx server block with PHP security rules
# Generated by AwesomeArchLinux/hardening/php/php.sh
#
# Rename this to .conf and customize for your application.
# =============================================================================

# --- Deny PHP execution in uploads directories ---
# Prevents uploaded malicious PHP files from being executed.
# Adjust paths to match your application's upload directories.
location ~* /(?:uploads|files|media|images|content)/.*\.php$ {
    deny all;
    return 403;
}

# --- Deny access to hidden files (except .well-known) ---
location ~ /\.(?!well-known) {
    deny all;
    return 404;
}

# --- Deny access to sensitive PHP files ---
location ~* (?:xmlrpc|wp-config|config|install|setup)\.php$ {
    deny all;
    return 404;
}

# --- PHP handler ---
# location ~ \.php$ {
#     # Prevent execution of non-existent PHP files
#     try_files $uri =404;
#
#     include conf.d/php-fpm.conf;
# }
EOF

    msg "nginx PHP security sample created: $NGINX_PHP_SAMPLE"
    info "Rename $NGINX_PHP_SAMPLE to .conf and customize for your application"

    # Verify nginx can parse the config (non-fatal)
    if command -v nginx &>/dev/null; then
        if nginx -t 2>/dev/null; then
            msg "nginx configuration test passed"
        else
            warn "nginx configuration test failed (the sample .conf.sample is not loaded by default)"
        fi
    else
        info "nginx is not installed; FastCGI config written for later use"
    fi
fi

# =============================================================================
# 6. HARDEN PHP-FPM SYSTEMD SERVICE
# =============================================================================

if [[ "$WITH_FPM" == true ]]; then
    msg "Hardening PHP-FPM systemd service..."

    mkdir -p /etc/systemd/system/php-fpm.service.d/

    cat > /etc/systemd/system/php-fpm.service.d/hardening.conf <<'EOF'
# =============================================================================
# PHP-FPM systemd hardening override
# Generated by AwesomeArchLinux/hardening/php/php.sh
# =============================================================================

[Service]
# --- Filesystem protection ---
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ReadWritePaths=/var/log/php /var/lib/php /run/php-fpm /var/www

# --- Privilege restrictions ---
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_NET_BIND_SERVICE

# --- Kernel protection ---
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes

# --- System call filtering ---
SystemCallFilter=@system-service @network-io
SystemCallArchitectures=native

# --- Network restrictions ---
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

# --- Memory ---
# PHP OPcache requires write+execute memory for JIT compilation;
# MemoryDenyWriteExecute must be set to no.
MemoryDenyWriteExecute=no

# --- Namespace and personality restrictions ---
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes

# --- Resource limits ---
LimitNOFILE=65536
LimitNPROC=4096
EOF

    systemctl daemon-reload
    msg "systemd hardening override created"
fi

# =============================================================================
# 7. LOGROTATE CONFIGURATION
# =============================================================================

msg "Creating logrotate configuration..."

cat > /etc/logrotate.d/php <<'EOF'
# Log rotation for PHP and PHP-FPM
# Generated by AwesomeArchLinux/hardening/php/php.sh

/var/log/php/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 640 http http
    sharedscripts
    postrotate
        /usr/bin/systemctl reload php-fpm 2>/dev/null || true
    endscript
}
EOF

msg "Logrotate config created: /etc/logrotate.d/php"

# =============================================================================
# 8. ENABLE AND START PHP-FPM
# =============================================================================

if [[ "$WITH_FPM" == true ]]; then
    msg "Enabling and starting PHP-FPM..."

    systemctl enable php-fpm.service
    systemctl restart php-fpm.service

    sleep 2
    if systemctl is-active --quiet php-fpm.service; then
        msg "PHP-FPM is running"
    else
        warn "PHP-FPM failed to start. Check: journalctl -u php-fpm"
    fi
fi

# =============================================================================
# 9. SUMMARY
# =============================================================================

echo
echo -e "${C_GREEN}========================================================================${C_NC}"
echo -e "${C_GREEN} PHP production hardening complete!${C_NC}"
echo -e "${C_GREEN}========================================================================${C_NC}"
echo

echo -e "${C_BLUE}PHP Version:${C_NC}   $PHP_VER"
echo -e "${C_BLUE}Pool User:${C_NC}     $POOL_USER"
echo -e "${C_BLUE}Log:${C_NC}           $LOGFILE"
echo

echo -e "${C_BLUE}Generated Files:${C_NC}"
echo "  php.ini backup:       $BACKUP"
echo "  php.ini:              $PHP_INI"
if [[ "$WITH_FPM" == true ]]; then
    echo "  FPM pool:             $FPM_POOL"
    echo "  systemd override:     /etc/systemd/system/php-fpm.service.d/hardening.conf"
fi
if [[ "$WITH_NGINX" == true ]]; then
    echo "  nginx FastCGI:        /etc/nginx/conf.d/php-fpm.conf"
    echo "  nginx PHP security:   /etc/nginx/conf.d/php-security.conf.sample"
fi
echo "  Logrotate:            /etc/logrotate.d/php"
echo "  Log directory:        /var/log/php/"
echo "  Session directory:    /var/lib/php/sessions/"
echo

echo -e "${C_BLUE}php.ini Hardening Applied:${C_NC}"
echo "  - expose_php = Off (hide version from HTTP headers)"
echo "  - display_errors = Off, log_errors = On"
echo "  - error_log = /var/log/php/error.log"
echo "  - allow_url_fopen = Off, allow_url_include = Off"
echo "  - open_basedir = /var/www:/tmp:/usr/share/php"
echo "  - cgi.fix_pathinfo = 0 (prevent path traversal)"
echo "  - Session: httponly, secure, strict mode, SameSite=Strict"
echo "  - Session name: __Secure-PHPSESSID (48-char, 6 bits/char)"
echo "  - Resource limits: 256M memory, 10M upload, 30s execution"
echo

echo -e "${C_BLUE}Disabled Functions:${C_NC}"
echo "  $DISABLE_FUNCTIONS"
echo

if [[ "$WITH_FPM" == true ]]; then
    echo -e "${C_BLUE}PHP-FPM Pool Settings:${C_NC}"
    echo "  - Unix socket: /run/php-fpm/php-fpm.sock (mode 0660)"
    echo "  - Process manager: dynamic (5 start, 2-10 spare, 25 max)"
    echo "  - Max requests per child: 500 (prevent memory leaks)"
    echo "  - Request timeout: 60s"
    echo "  - Slow log threshold: 5s"
    echo "  - security.limit_extensions = .php"
    echo "  - clear_env = yes"
    echo "  - Core dumps disabled (rlimit_core = 0)"
    echo

    echo -e "${C_BLUE}systemd Hardening Applied:${C_NC}"
    echo "  - ProtectSystem=strict, ProtectHome=yes"
    echo "  - PrivateTmp=yes, PrivateDevices=yes"
    echo "  - NoNewPrivileges=yes, LockPersonality=yes"
    echo "  - Kernel tunable/module/log/cgroup protection"
    echo "  - RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6"
    echo "  - RestrictNamespaces=yes, RestrictRealtime=yes"
    echo "  - SystemCallFilter=@system-service @network-io"
    echo "  - MemoryDenyWriteExecute=no (required for OPcache JIT)"
    echo "  - CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_NET_BIND_SERVICE"
    echo
fi

echo -e "${C_YELLOW}IMPORTANT next steps:${C_NC}"
echo "  1. Review and customize disable_functions for your framework:"
echo "     - Laravel needs: proc_open (for artisan)"
echo "     - WordPress needs: exec (for some plugins)"
echo "     Edit: $PHP_INI"
echo "  2. Adjust open_basedir for your application document root:"
echo "     open_basedir = /var/www/myapp:/tmp:/usr/share/php"
echo "  3. Configure OPcache for production performance:"
echo "     opcache.enable=1, opcache.memory_consumption=128,"
echo "     opcache.validate_timestamps=0 (restart FPM to pick up changes)"
echo "  4. If using --with-nginx, customize the FastCGI config:"
echo "     /etc/nginx/conf.d/php-fpm.conf"
echo "  5. Verify PHP-FPM is running:"
echo "     systemctl status php-fpm"
echo "     journalctl -u php-fpm -f"
echo "  6. Monitor FPM status page (from localhost only):"
echo "     curl http://localhost/fpm-status"
echo "  7. Check the slow log for performance issues:"
echo "     tail -f /var/log/php/fpm-slow.log"
echo

echo -e "${C_GREEN}Done.${C_NC}"
