#!/usr/bin/env bash

# =============================================================================
# Script:      nodejs.sh
# Description: Installs and hardens a Node.js/Express application for
#              production on Arch Linux, including:
#                - Dedicated service user with minimal privileges
#                - Hardened systemd service with comprehensive sandboxing
#                - nginx reverse proxy with rate limiting and security headers
#                - AppArmor confinement profile
#                - Automated npm security audits via systemd timer
#                - Log rotation and strict file permissions
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
#
# Usage:       sudo ./nodejs.sh -a APP_PATH [-u APP_USER] [-p PORT]
#                               [-n APP_NAME] [-h]
#
# Requirements:
#   - Arch Linux with pacman
#   - Root privileges
#   - Application code already present at APP_PATH
#
# What this script does:
#   1.  Creates a dedicated system user with no login shell
#   2.  Installs Node.js and npm securely via pacman
#   3.  Creates a hardened systemd service unit
#   4.  Configures nginx as a reverse proxy with rate limiting
#   5.  Adds security response headers to nginx
#   6.  Sets up Node.js security environment variables
#   7.  Configures log rotation
#   8.  Writes an AppArmor profile for the Node.js process
#   9.  Creates an automated npm audit script and systemd timer
#   10. Locks down file permissions on the application directory
#   11. Enables and starts the service
#   12. Prints a security summary and checklist
# =============================================================================

set -euo pipefail
umask 022

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
APP_USER="nodeapp"
PORT=3000
APP_NAME="nodeapp"
LOGFILE="/var/log/nodejs-hardening-$(date +%Y%m%d-%H%M%S).log"

# --- Usage ---
usage() {
    cat <<EOF
Usage: sudo $0 [options]

Required:
  -a APP_PATH       Absolute path to the Node.js application directory

Optional:
  -u APP_USER       System user to run the app (default: $APP_USER)
  -p PORT           Application port (default: $PORT)
  -n APP_NAME       Application/service name (default: $APP_NAME)
  -h                Show this help

Examples:
  sudo $0 -a /opt/myapp
  sudo $0 -a /opt/myapp -u webapp -p 8080 -n myapp
  sudo $0 -a /srv/api -n api-server -p 443
EOF
    exit 0
}

# --- Parse Arguments ---
need_arg() { [[ $# -ge 2 && -n "${2:-}" ]] || err "Option $1 requires a value"; }
while [[ $# -gt 0 ]]; do
    case "$1" in
        -a)          need_arg "$@"; APP_PATH="$2"; shift 2 ;;
        -u)          need_arg "$@"; APP_USER="$2"; shift 2 ;;
        -p)          need_arg "$@"; PORT="$2"; shift 2 ;;
        -n)          need_arg "$@"; APP_NAME="$2"; shift 2 ;;
        -h|--help)   usage ;;
        *)           err "Unknown option: $1" ;;
    esac
done

# --- Validate ---
[[ $(id -u) -eq 0 ]] || err "Must be run as root"
[[ -n "$APP_PATH" ]] || err "Application path is required (-a /path/to/app)"
[[ -d "$APP_PATH" ]] || err "Application directory does not exist: $APP_PATH"
[[ "$PORT" =~ ^[0-9]+$ ]] && (( PORT >= 1 && PORT <= 65535 )) || \
    err "Application port must be between 1 and 65535"
[[ "$APP_USER" =~ ^[a-z_][a-z0-9_-]*$ ]] || \
    err "Invalid service user '$APP_USER'"
[[ "$APP_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9_-]*$ ]] || \
    err "Invalid application name '$APP_NAME' (use letters, digits, hyphens, and underscores only)"

# This path is passed to recursive ownership changes. Resolve symlinks and
# constrain it to application-content hierarchies so '-a /' and similar input
# cannot transfer ownership of operating-system files.
APP_PATH=$(realpath -- "$APP_PATH") || err "Could not resolve application path"
case "$APP_PATH" in
    /opt/*|/srv/*|/var/www/*) ;;
    *) err "Unsafe application path '$APP_PATH'. Use a dedicated directory below /opt/, /srv/, or /var/www/." ;;
esac
# The path is written verbatim into a systemd unit (whitespace separates list
# items and '%' starts a specifier), an AppArmor profile (whitespace and glob
# characters change the rule) and an nginx vhost, so only plain path characters
# are accepted.
[[ "$APP_PATH" =~ ^/[A-Za-z0-9._/-]+$ ]] || \
    err "Application path contains unsupported characters (allowed: letters, digits, '.', '_', '-', '/'): $APP_PATH"

# APP_NAME becomes /etc/<name>/, /var/log/<name>/, <name>.service, a logrotate
# file, an AppArmor profile and an nginx vhost. Reusing the name of something
# that already exists (nginx, sshd, default, ...) would re-own its directories,
# shadow its unit or replace its profile, so every such path must be absent or
# carry this script's marker from an earlier run.
GENERATED_MARKER="Generated by AwesomeArchLinux/hardening/nodejs/nodejs.sh"
generated_here() { [[ -f "$1" && ! -L "$1" ]] && grep -qF -- "$GENERATED_MARKER" "$1"; }

for vendor_unit in "$APP_NAME.service" "$APP_NAME-audit.service" "$APP_NAME-audit.timer"; do
    [[ ! -e "/usr/lib/systemd/system/$vendor_unit" ]] || \
        err "Application name '$APP_NAME' collides with the packaged unit /usr/lib/systemd/system/$vendor_unit. Choose another name (-n)."
done
for generated_file in \
    "/etc/systemd/system/$APP_NAME.service" \
    "/etc/nginx/sites-enabled/$APP_NAME.conf" \
    "/etc/logrotate.d/$APP_NAME" \
    "/etc/apparmor.d/usr.bin.$APP_NAME" \
    "/usr/local/bin/$APP_NAME-audit.sh"; do
    if [[ -e "$generated_file" || -L "$generated_file" ]] && ! generated_here "$generated_file"; then
        err "$generated_file already exists and was not generated by this script. Choose another application name (-n)."
    fi
done
if ! generated_here "/etc/systemd/system/$APP_NAME.service" && ! generated_here "/etc/$APP_NAME/env"; then
    for app_dir in "/etc/$APP_NAME" "/var/log/$APP_NAME"; do
        [[ ! -e "$app_dir" && ! -L "$app_dir" ]] || \
            err "$app_dir already exists and does not belong to an application set up by this script. Choose another application name (-n), or remove the directory if it is a left-over from an interrupted run."
    done
    if [[ -r /sys/kernel/security/apparmor/profiles ]] && \
       grep -qE "^${APP_NAME} \\(" /sys/kernel/security/apparmor/profiles; then
        err "An AppArmor profile named '$APP_NAME' is already loaded. Choose another application name (-n)."
    fi
fi
unset vendor_unit generated_file app_dir

# Redirect output to logfile as well
install -d -m 0755 /var/log
( umask 077 && : > "$LOGFILE" )
chmod 0600 "$LOGFILE"
exec > >(tee -a "$LOGFILE") 2>&1

info "Application path: $APP_PATH"
info "Application name: $APP_NAME"
info "Service user:     $APP_USER"
info "Port:             $PORT"
info "Log:              $LOGFILE"

# =============================================================================
# 1. CREATE DEDICATED SERVICE USER
# =============================================================================

msg "Creating dedicated service user..."

if id "$APP_USER" &>/dev/null; then
    info "User '$APP_USER' already exists"
else
    useradd \
        --system \
        --shell /usr/bin/nologin \
        --home-dir "$APP_PATH" \
        --no-create-home \
        --comment "Node.js application service account for $APP_NAME" \
        "$APP_USER"
    msg "Created system user: $APP_USER"
fi

# Ensure the home directory exists and is owned correctly
chown -R "$APP_USER:$APP_USER" "$APP_PATH"
msg "Set ownership of $APP_PATH to $APP_USER:$APP_USER"

# =============================================================================
# 2. INSTALL NODE.JS SECURELY
# =============================================================================

msg "Installing Node.js and npm..."

pacman -Syu --noconfirm --needed nodejs npm

NODE_VER=$(node --version 2>/dev/null || echo "unknown")
NPM_VER=$(npm --version 2>/dev/null || echo "unknown")
info "Node.js version: $NODE_VER"
info "npm version:     $NPM_VER"

# Configure npm globally (writes /etc/npmrc without altering global install prefix)
msg "Hardening npm configuration..."

npm config set --location=global fund false update-notifier false audit-level high

# Disable scripts from running during install by default (opt-in per project)
info "npm audit-level set to high"
info "npm telemetry/fund notifications disabled"

# =============================================================================
# 3. CREATE NODE.JS SECURITY ENVIRONMENT FILE
# =============================================================================

msg "Configuring security environment file..."

ENV_DIR="/etc/$APP_NAME"
ENV_FILE="$ENV_DIR/env"

install -d -o root -g "$APP_USER" -m 0750 "$ENV_DIR"

if [[ -f "$ENV_FILE" ]]; then
    if grep -qE '^PORT=' "$ENV_FILE"; then
        sed -i "s/^PORT=.*/PORT=$PORT/" "$ENV_FILE"
    else
        printf '\nPORT=%s\n' "$PORT" >> "$ENV_FILE"
    fi
    chown "root:$APP_USER" "$ENV_FILE"
    chmod 0640 "$ENV_FILE"
    info "Preserved existing environment file (secrets intact): $ENV_FILE"
else
    (
        umask 027
        cat > "$ENV_FILE" <<EOF
# =============================================================================
# Node.js production environment for $APP_NAME
# Generated by AwesomeArchLinux/hardening/nodejs/nodejs.sh
#
# WARNING: Add application secrets here (DB passwords, API keys, etc.)
#          This file is chmod 640 and owned by root:$APP_USER
# =============================================================================

# --- Runtime mode ---
NODE_ENV=production

# --- Memory and security limits ---
# --max-old-space-size: Limit V8 heap to prevent OOM on the host (adjust to your needs)
# --max-http-header-size: Limit HTTP header size to 8KB (mitigate header-based attacks)
NODE_OPTIONS=--max-old-space-size=512 --max-http-header-size=8192

# --- libuv thread pool ---
# Controls the number of threads for async I/O (DNS, fs). Default is 4.
UV_THREADPOOL_SIZE=4

# --- Application port ---
PORT=$PORT
EOF
    )
    chown "root:$APP_USER" "$ENV_FILE"
    chmod 0640 "$ENV_FILE"
    msg "Environment file created: $ENV_FILE (mode 640)"
fi

# =============================================================================
# 4. CREATE LOG AND DATA DIRECTORIES
# =============================================================================

msg "Creating log and data directories..."

install -d -o "$APP_USER" -g "$APP_USER" -m 0750 "/var/log/$APP_NAME"
install -d -o "$APP_USER" -g "$APP_USER" -m 0750 "$APP_PATH/data" "$APP_PATH/logs"

# =============================================================================
# 5. CREATE HARDENED SYSTEMD SERVICE
# =============================================================================

msg "Creating hardened systemd service..."

# Detect entry point: check for package.json "start" script without executing JS,
# falling back to index.js.
ENTRY_POINT="$APP_PATH/index.js"
if [[ -f "$APP_PATH/package.json" ]]; then
    START_SCRIPT=""
    if command -v jq &>/dev/null; then
        START_SCRIPT=$(jq -r '.scripts.start // empty' -- "$APP_PATH/package.json" 2>/dev/null || true)
    else
        START_SCRIPT=$(awk '
            /"scripts"[[:space:]]*:[[:space:]]*\{/ {
                in_scripts = 1
                sub(/.*"scripts"[[:space:]]*:[[:space:]]*\{/, "")
            }
            in_scripts {
                if (match($0, /"start"[[:space:]]*:[[:space:]]*"([^"\\]|\\.)*"/)) {
                    val = substr($0, RSTART, RLENGTH)
                    sub(/^"start"[[:space:]]*:[[:space:]]*"/, "", val)
                    sub(/"$/, "", val)
                    gsub(/\\"/, "\"", val)
                    print val
                    exit
                }
                if ($0 ~ /\}/) { in_scripts = 0 }
            }
        ' "$APP_PATH/package.json" 2>/dev/null || true)
    fi

    if [[ -n "$START_SCRIPT" ]]; then
        info "Detected package.json start script: $START_SCRIPT"
        # Accept only a safe single-file "node <file>" invocation inside APP_PATH
        if [[ "$START_SCRIPT" =~ ^node[[:space:]]+([A-Za-z0-9_./-]+)$ ]]; then
            SCRIPT_FILE="${BASH_REMATCH[1]}"
            if [[ "$SCRIPT_FILE" != /* ]]; then
                CANDIDATE_ENTRY=$(realpath -m -- "$APP_PATH/$SCRIPT_FILE")
            else
                CANDIDATE_ENTRY=$(realpath -m -- "$SCRIPT_FILE")
            fi
            if [[ "$CANDIDATE_ENTRY" == "$APP_PATH"/* ]]; then
                ENTRY_POINT="$CANDIDATE_ENTRY"
            else
                warn "Ignoring start script target outside $APP_PATH: $SCRIPT_FILE"
            fi
        fi
    fi
fi

info "Entry point: $ENTRY_POINT"

# Determine capability settings based on port
CAP_SETTINGS=""
APPARMOR_CAP_RULES=""
if [[ "$PORT" -lt 1024 ]]; then
    warn "Port $PORT < 1024: granting CAP_NET_BIND_SERVICE capability"
    CAP_SETTINGS="CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE"
    # AppArmor denies every capability the profile does not list, including
    # ones systemd grants, so the profile has to allow the bind as well.
    APPARMOR_CAP_RULES=$'\n  # Bind the privileged application port\n  capability net_bind_service,\n'
else
    CAP_SETTINGS="CapabilityBoundingSet="
fi

# Build ReadWritePaths dynamically
RW_PATHS=""
for dir in "$APP_PATH/data" "$APP_PATH/logs" "/var/log/$APP_NAME"; do
    if [[ -d "$dir" ]]; then
        RW_PATHS="$RW_PATHS $dir"
    fi
done
RW_PATHS=$(echo "$RW_PATHS" | sed 's/^ //')

install -d -m 0755 /etc/systemd/system
cat > "/etc/systemd/system/$APP_NAME.service" <<EOF
# =============================================================================
# Hardened systemd service for $APP_NAME (Node.js)
# Generated by AwesomeArchLinux/hardening/nodejs/nodejs.sh
# =============================================================================

[Unit]
Description=$APP_NAME Node.js Application
Documentation=https://nodejs.org/
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$APP_USER
Group=$APP_USER
WorkingDirectory=$APP_PATH
ExecStart=/usr/bin/node $ENTRY_POINT
EnvironmentFile=$ENV_FILE
Environment=NODE_ENV=production
Environment=PORT=$PORT
AppArmorProfile=-$APP_NAME

# --- Restart policy ---
Restart=always
RestartSec=10

# --- Filesystem sandboxing ---
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ReadOnlyPaths=$APP_PATH
ReadWritePaths=$RW_PATHS
UMask=077

# --- Kernel protection ---
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes

# --- Privilege restrictions ---
NoNewPrivileges=yes
LockPersonality=yes
RestrictSUIDSGID=yes
$CAP_SETTINGS

# --- Memory ---
# Node.js V8 JIT requires write+execute memory; cannot use MemoryDenyWriteExecute
MemoryDenyWriteExecute=no

# --- Network restrictions ---
# AF_NETLINK: os.networkInterfaces() enumerates interfaces over a netlink
# socket and throws EAFNOSUPPORT without it (frameworks call it at startup to
# print their listen addresses).
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK

# --- Namespace and realtime restrictions ---
RestrictNamespaces=yes
RestrictRealtime=yes

# --- System call filtering ---
SystemCallFilter=@system-service @network-io
SystemCallErrorNumber=EPERM
SystemCallArchitectures=native

# --- Resource limits ---
LimitNOFILE=65535
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "/etc/systemd/system/$APP_NAME.service"

msg "Systemd service created: /etc/systemd/system/$APP_NAME.service"

# =============================================================================
# 6. NGINX REVERSE PROXY
# =============================================================================

msg "Configuring nginx reverse proxy..."

# Install nginx if not present
pacman -S --noconfirm --needed nginx-mainline || pacman -S --noconfirm --needed nginx

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

NGINX_SITE="/etc/nginx/sites-enabled/$APP_NAME.conf"
NGINX_SITE_BACKUP=""
if [[ -f "$NGINX_SITE" ]]; then
    NGINX_SITE_BACKUP="$NGINX_SITE.bak.$(date +%Y%m%d-%H%M%S)"
    cp -p -- "$NGINX_SITE" "$NGINX_SITE_BACKUP"
    info "Existing nginx config backed up to $NGINX_SITE_BACKUP"
fi

restore_nginx_site() {
    if [[ -n "$NGINX_SITE_BACKUP" ]]; then
        cp -p -- "$NGINX_SITE_BACKUP" "$NGINX_SITE"
        warn "Restored the previous nginx server block"
    else
        rm -f -- "$NGINX_SITE"
        warn "Removed the new nginx server block"
    fi
}

# "server_name _" matches no real host name, so this proxy is only reached when
# it is the default server for port 80. Claim that role explicitly unless some
# other configuration already has it (nginx rejects two default servers).
LISTEN_DEFAULT=" default_server"
OTHER_DEFAULT_SERVER=$(awk -v self="$NGINX_SITE" '
    FILENAME == self { next }
    {
        line = $0
        sub(/#.*/, "", line)
        if (line ~ /^[[:space:]]*listen[[:space:]].*[[:space:]]default_server([[:space:];]|$)/) {
            port = line
            sub(/^[[:space:]]*listen[[:space:]]+/, "", port)
            sub(/[[:space:];].*/, "", port)
            if (port ~ /^unix:/) {
                next
            }
            sub(/^.*:/, "", port)
            if (port !~ /^[0-9]+$/) {
                port = "80"
            }
            if (port == "80") {
                print FILENAME
                exit
            }
        }
    }
' /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/*.conf 2>/dev/null || true)
if [[ -n "$OTHER_DEFAULT_SERVER" ]]; then
    LISTEN_DEFAULT=""
    warn "$OTHER_DEFAULT_SERVER already declares the default server for port 80."
    warn "Set a real server_name in $NGINX_SITE to reach $APP_NAME through nginx."
fi

# Variable names may not contain hyphens
CSP_VAR="csp_${APP_NAME//-/_}"

cat > "$NGINX_SITE" <<EOF
# =============================================================================
# nginx reverse proxy for $APP_NAME (Node.js)
# Generated by AwesomeArchLinux/hardening/nodejs/nodejs.sh
# =============================================================================

# --- Rate limiting zone ---
# 10 requests/second per IP, burst of 20, 10MB shared memory zone
limit_req_zone \$binary_remote_addr zone=${APP_NAME}_ratelimit:10m rate=10r/s;

# --- Content-Security-Policy fallback ---
# Sent only when the application does not set its own policy. Two CSP headers
# are intersected by browsers, so adding this one unconditionally would override
# any policy the app (e.g. helmet) sends. The fallback suits a JSON API; an app
# that serves HTML must send its own Content-Security-Policy.
map \$upstream_http_content_security_policy \$$CSP_VAR {
    ""      "default-src 'none'; frame-ancestors 'none'";
    default "";
}

# --- Upstream ---
upstream ${APP_NAME}_backend {
    server 127.0.0.1:$PORT;
    keepalive 64;
}

# --- HTTP Reverse Proxy (valid out-of-the-box; convert to 301 redirect once TLS certs exist) ---
server {
    listen 80$LISTEN_DEFAULT;
    listen [::]:80$LISTEN_DEFAULT;
    server_name _;

    # --- Security headers ---
    # No Strict-Transport-Security here: browsers ignore it over plain HTTP. It
    # belongs to the HTTPS server block below.
    add_header Content-Security-Policy \$$CSP_VAR always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "no-referrer" always;

    # --- Hide upstream technology ---
    proxy_hide_header X-Powered-By;

    # --- Proxy to Node.js ---
    location / {
        limit_req zone=${APP_NAME}_ratelimit burst=20 nodelay;

        proxy_pass http://${APP_NAME}_backend;

        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";

        # Timeouts
        proxy_read_timeout 90s;
        proxy_connect_timeout 30s;
        proxy_send_timeout 30s;

        # Buffering
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 8k;
        proxy_busy_buffers_size 16k;
    }

    # Block dotfiles
    location ~ /\\.(?!well-known) {
        deny all;
        return 404;
    }
}

# --- HTTPS Reverse Proxy Template (uncomment after provisioning TLS certificates) ---
# server {
#     listen 443 ssl;
#     listen [::]:443 ssl;
#     http2 on;
#     server_name YOUR_DOMAIN;
#
#     ssl_certificate     /etc/letsencrypt/live/YOUR_DOMAIN/fullchain.pem;
#     ssl_certificate_key /etc/letsencrypt/live/YOUR_DOMAIN/privkey.pem;
#
#     add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
#     add_header Content-Security-Policy \$$CSP_VAR always;
#     add_header X-Content-Type-Options "nosniff" always;
#     add_header X-Frame-Options "DENY" always;
#     add_header Referrer-Policy "no-referrer" always;
#
#     proxy_hide_header X-Powered-By;
#
#     location / {
#         limit_req zone=${APP_NAME}_ratelimit burst=20 nodelay;
#         proxy_pass http://${APP_NAME}_backend;
#         proxy_set_header Host \$host;
#         proxy_set_header X-Real-IP \$remote_addr;
#         proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
#         proxy_set_header X-Forwarded-Proto \$scheme;
#         proxy_http_version 1.1;
#         proxy_set_header Upgrade \$http_upgrade;
#         proxy_set_header Connection "upgrade";
#     }
#
#     location ~ /\\.(?!well-known) {
#         deny all;
#         return 404;
#     }
# }
EOF
chmod 0644 "$NGINX_SITE"

msg "nginx config created: $NGINX_SITE"

# Never leave a server block enabled that nginx rejects: it would also break the
# next reload of every other site. Start nginx when it is not running yet (the
# proxy is useless otherwise). A proxy problem is reported but does not stop the
# hardening of the application service itself.
NGINX_PROXY_OK=false
if nginx -t 2>&1; then
    msg "nginx configuration test passed"
    if systemctl is-active --quiet nginx; then
        systemctl reload nginx && NGINX_PROXY_OK=true
    else
        systemctl enable --now nginx && NGINX_PROXY_OK=true
    fi
    if [[ "$NGINX_PROXY_OK" == true ]]; then
        msg "nginx is active and serving the updated configuration"
    else
        restore_nginx_site
        if systemctl is-active --quiet nginx; then
            systemctl reload nginx 2>/dev/null || \
                warn "Could not reload nginx after restoring its previous configuration"
        fi
        warn "nginx start/reload failed; the server block was rolled back"
    fi
else
    restore_nginx_site
    warn "nginx configuration test failed; the server block was rolled back so no invalid configuration stays enabled"
fi

# =============================================================================
# 7. LOG ROTATION
# =============================================================================

msg "Configuring log rotation..."

install -d -m 0755 /etc/logrotate.d
cat > "/etc/logrotate.d/$APP_NAME" <<EOF
# Log rotation for $APP_NAME (Node.js)
# Generated by AwesomeArchLinux/hardening/nodejs/nodejs.sh

/var/log/$APP_NAME/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    copytruncate
    su $APP_USER $APP_USER
}
EOF
chmod 0644 "/etc/logrotate.d/$APP_NAME"

msg "Logrotate config created: /etc/logrotate.d/$APP_NAME"

# =============================================================================
# 8. APPARMOR PROFILE
# =============================================================================

msg "Creating AppArmor profile..."

APPARMOR_DIR="/etc/apparmor.d"
APPARMOR_PROFILE="$APPARMOR_DIR/usr.bin.$APP_NAME"

if [[ -d "$APPARMOR_DIR" ]]; then
    cat > "$APPARMOR_PROFILE" <<EOF
# AppArmor profile for $APP_NAME (Node.js application)
# Generated by AwesomeArchLinux/hardening/nodejs/nodejs.sh
# Unattached profile: applied only to $APP_NAME.service via AppArmorProfile=-$APP_NAME

abi <abi/3.0>,

#include <tunables/global>

profile $APP_NAME flags=(enforce) {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/openssl>

  # Network — allow TCP/UDP for inet and inet6, plus unix sockets
  network inet stream,
  network inet dgram,
  network inet6 stream,
  network inet6 dgram,
  network unix stream,
$APPARMOR_CAP_RULES
  # Node.js binary
  /usr/bin/node                    mr,

  # Application directory — read-only
  $APP_PATH/                       r,
  $APP_PATH/**                     r,
  $APP_PATH/node_modules/**        mr,

  # Data and logs — read/write
  $APP_PATH/data/                  rw,
  $APP_PATH/data/**                rw,
  $APP_PATH/logs/                  rw,
  $APP_PATH/logs/**                rw,
  /var/log/$APP_NAME/              rw,
  /var/log/$APP_NAME/**            rw,
  owner /var/log/$APP_NAME/**      w,

  # Temporary files (isolated by systemd PrivateTmp=yes)
  owner /tmp/**                    rw,
  owner /var/tmp/**                rw,

  # Environment config
  /etc/$APP_NAME/**                r,

  # TLS trust store
  /etc/ssl/certs/**                r,
  /etc/ca-certificates/**          r,
  /usr/share/ca-certificates/**    r,

  # Shared libraries (Node.js native addons)
  /usr/lib/**                      mr,

  # Proc and cgroup (V8 heap/CPU detection)
  /sys/fs/cgroup/**                r,
  owner /proc/*/fd/                r,
  /proc/sys/kernel/random/boot_id  r,
  owner /proc/*/status             r,
  owner /proc/*/stat               r,
  owner /proc/*/cgroup             r,

  # Deny everything else implicitly
}
EOF
    chmod 0644 "$APPARMOR_PROFILE"

    msg "AppArmor profile created: $APPARMOR_PROFILE"

    # Load the unattached profile if AppArmor is active (flags=(enforce) sets enforce mode)
    if command -v apparmor_parser &>/dev/null; then
        if apparmor_parser -r -W "$APPARMOR_PROFILE" 2>/dev/null; then
            msg "AppArmor profile '$APP_NAME' loaded in enforce mode"
        else
            warn "Failed to parse AppArmor profile (AppArmor may require a reboot)"
        fi
    else
        info "apparmor_parser not found; profile written but not loaded"
        info "Install apparmor and reboot to activate the profile"
    fi
else
    warn "AppArmor directory $APPARMOR_DIR does not exist; skipping profile creation"
    warn "Run the apparmor hardening script first to install AppArmor"
fi

# =============================================================================
# 9. AUTOMATED SECURITY AUDIT
# =============================================================================

msg "Setting up automated npm security audit..."

# Each timer needs its own script: a shared script would retain only the
# most recently configured application's path.
AUDIT_USER="${APP_USER:-$APP_NAME}"
AUDIT_SCRIPT="/usr/local/bin/$APP_NAME-audit.sh"

install -d -m 0750 "/var/log/$APP_NAME"
if [[ $(id -u) -eq 0 ]] && id "$AUDIT_USER" &>/dev/null; then
    chown "$AUDIT_USER:$AUDIT_USER" "/var/log/$APP_NAME"
fi

cat > "$AUDIT_SCRIPT" <<EOF
#!/usr/bin/env bash
# =============================================================================
# Automated npm security audit for $APP_NAME
# Generated by AwesomeArchLinux/hardening/nodejs/nodejs.sh
#
# Runs npm audit on the production dependencies and logs results.
# Called by systemd timer: $APP_NAME-audit.timer
# =============================================================================

set -euo pipefail

APP_PATH=$(printf '%q' "$APP_PATH")
APP_NAME=$(printf '%q' "$APP_NAME")
LOG_DIR="/var/log/\$APP_NAME"
AUDIT_LOG="\$LOG_DIR/npm-audit-\$(date +%Y%m%d-%H%M%S).log"

mkdir -p "\$LOG_DIR"

echo "=== npm security audit: \$(date) ===" >> "\$AUDIT_LOG"
echo "Application: \$APP_NAME (\$APP_PATH)" >> "\$AUDIT_LOG"
echo "" >> "\$AUDIT_LOG"

# Run npm audit on production dependencies only
cd "\$APP_PATH"
if npm audit --omit=dev --cache /tmp/npm-cache >> "\$AUDIT_LOG" 2>&1; then
    echo "" >> "\$AUDIT_LOG"
    echo "RESULT: No vulnerabilities found." >> "\$AUDIT_LOG"
else
    AUDIT_EXIT=\$?
    echo "" >> "\$AUDIT_LOG"
    echo "RESULT: Vulnerabilities detected (exit code \$AUDIT_EXIT)." >> "\$AUDIT_LOG"
    echo "Review: \$AUDIT_LOG" >> "\$AUDIT_LOG"

    # Optional: send notification via mail (uncomment if postfix/msmtp is configured)
    # echo "npm audit found vulnerabilities in \$APP_NAME. See \$AUDIT_LOG" | \\
    #     mail -s "[\$APP_NAME] npm security audit warning" admin@example.com

    # Optional: send notification via webhook (uncomment and set URL)
    # curl -s -X POST -H 'Content-Type: application/json' \\
    #     -d "{\"text\": \"npm audit found vulnerabilities in \$APP_NAME. See \$AUDIT_LOG\"}" \\
    #     https://hooks.example.com/webhook
fi

echo "=== audit complete ===" >> "\$AUDIT_LOG"

# Clean up old audit logs (keep last 30)
ls -1t "\$LOG_DIR"/npm-audit-*.log 2>/dev/null | tail -n +31 | xargs -r rm -f || true
EOF

chmod 0755 "$AUDIT_SCRIPT"
msg "Audit script created: $AUDIT_SCRIPT"

# Create systemd service for the audit (runs as unprivileged APP_USER, never root)
cat > "/etc/systemd/system/$APP_NAME-audit.service" <<EOF
[Unit]
Description=npm security audit for $APP_NAME
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=$AUDIT_USER
Group=$AUDIT_USER
ExecStart=$AUDIT_SCRIPT
NoNewPrivileges=yes
PrivateTmp=true
UMask=0077
EOF
chmod 0644 "/etc/systemd/system/$APP_NAME-audit.service"

# Create systemd timer for weekly audit
cat > "/etc/systemd/system/$APP_NAME-audit.timer" <<EOF
[Unit]
Description=Weekly npm security audit for $APP_NAME

[Timer]
OnCalendar=weekly
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
EOF
chmod 0644 "/etc/systemd/system/$APP_NAME-audit.timer"

systemctl daemon-reload
systemctl enable "$APP_NAME-audit.timer"
systemctl start "$APP_NAME-audit.timer"
msg "Weekly npm audit timer enabled: $APP_NAME-audit.timer"

# =============================================================================
# 10. FILE PERMISSIONS
# =============================================================================

msg "Locking down file permissions..."

# Application directory owned by service user
chown -R "$APP_USER:$APP_USER" "$APP_PATH"

# Source files (excluding node_modules so CLI targets in node_modules/.bin/* retain +x):
# 640 (owner rw, group r, other none)
find "$APP_PATH" -path "$APP_PATH/node_modules" -prune -o \
    -type f \( -name "*.js" -o -name "*.ts" -o -name "*.json" -o -name "*.mjs" -o -name "*.cjs" \) \
    -exec chmod 640 {} +

# Directories (including node_modules directories): 750 (owner rwx, group rx, other none)
find "$APP_PATH" -type d -exec chmod 750 {} +

# .env files (excluding node_modules): 600 (owner rw only) — should not exist in production, but secure them if present
find "$APP_PATH" -path "$APP_PATH/node_modules" -prune -o \
    -type f -name ".env*" -exec chmod 600 {} +

# Data and log directories
chmod 750 "$APP_PATH/data" "$APP_PATH/logs"
chmod 750 "/var/log/$APP_NAME"

msg "File permissions locked down"

# =============================================================================
# 11. ENABLE AND START SERVICE
# =============================================================================

msg "Enabling and starting $APP_NAME service..."

systemctl daemon-reload
systemctl enable "$APP_NAME.service"

if [[ -f "$ENTRY_POINT" ]]; then
    # restart, not start: a re-run must pick up the regenerated unit, environment
    # and AppArmor profile even when the service is already running.
    systemctl restart "$APP_NAME.service" || true
    sleep 2
    if systemctl is-active --quiet "$APP_NAME.service"; then
        msg "$APP_NAME service is running"
    else
        warn "$APP_NAME service failed to start. Check: journalctl -u $APP_NAME"
    fi
else
    warn "Entry point not found: $ENTRY_POINT"
    warn "Service enabled but not started. Deploy your application and run:"
    warn "  systemctl start $APP_NAME"
fi

# =============================================================================
# 12. SUMMARY
# =============================================================================

echo
echo -e "${C_GREEN}========================================================================${C_NC}"
echo -e "${C_GREEN} Node.js production hardening complete!${C_NC}"
echo -e "${C_GREEN}========================================================================${C_NC}"
echo

echo -e "${C_BLUE}Application:${C_NC}"
echo "  Name:            $APP_NAME"
echo "  Path:            $APP_PATH"
echo "  Entry point:     $ENTRY_POINT"
echo "  User:            $APP_USER"
echo "  Port:            $PORT"
echo

echo -e "${C_BLUE}Service Status:${C_NC}"
systemctl status "$APP_NAME.service" --no-pager --lines=3 2>/dev/null || echo "  (not running)"
echo

if [[ "$NGINX_PROXY_OK" == false ]]; then
    echo -e "${C_YELLOW}nginx reverse proxy:${C_NC}"
    echo "  NOT active: nginx rejected the configuration or could not be (re)started, and"
    echo "  the server block was rolled back. Fix the nginx error shown above and re-run."
    echo
fi

echo -e "${C_BLUE}Generated Files:${C_NC}"
echo "  systemd service:   /etc/systemd/system/$APP_NAME.service"
echo "  Environment file:  $ENV_FILE"
echo "  nginx config:      $NGINX_SITE"
echo "  Logrotate:         /etc/logrotate.d/$APP_NAME"
echo "  AppArmor profile:  $APPARMOR_PROFILE"
echo "  Audit script:      $AUDIT_SCRIPT"
echo "  Audit timer:       /etc/systemd/system/$APP_NAME-audit.timer"
echo "  Log directory:     /var/log/$APP_NAME/"
echo

echo -e "${C_BLUE}systemd Hardening Applied:${C_NC}"
echo "  - ProtectSystem=strict, ProtectHome=yes"
echo "  - PrivateTmp=yes, PrivateDevices=yes"
echo "  - NoNewPrivileges=yes, LockPersonality=yes"
echo "  - Kernel tunable/module/log/cgroup protection"
echo "  - RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK"
echo "  - RestrictNamespaces=yes, RestrictRealtime=yes"
echo "  - SystemCallFilter=@system-service @network-io (EPERM)"
echo "  - SystemCallArchitectures=native"
echo "  - MemoryDenyWriteExecute=no (required for V8 JIT)"
if [[ "$PORT" -lt 1024 ]]; then
    echo "  - CapabilityBoundingSet=CAP_NET_BIND_SERVICE (port < 1024)"
else
    echo "  - CapabilityBoundingSet= (empty, no capabilities needed)"
fi
echo "  - LimitNOFILE=65535, LimitNPROC=4096"
echo "  - UMask=077"
echo

echo -e "${C_BLUE}Security Checklist:${C_NC}"
echo "  - ReadOnlyPaths on application source"
echo "  - ReadWritePaths limited to data/logs only"
echo "  - nginx rate limiting (10 req/s per IP)"
echo "  - Security headers (CSP fallback, X-Frame-Options, etc.; HSTS in the HTTPS template)"
echo "  - X-Powered-By header stripped"
echo "  - WebSocket upgrade support enabled"
echo "  - AppArmor confinement profile"
echo "  - Weekly npm audit via systemd timer"
echo "  - Source files chmod 640, directories chmod 750"
echo "  - .env files chmod 600"
echo

echo -e "${C_YELLOW}IMPORTANT next steps:${C_NC}"
if [[ -n "$LISTEN_DEFAULT" ]]; then
    echo "  1. The nginx proxy is the default server on port 80: it answers every host name"
    echo "     that no other vhost declares. To serve a specific domain (and HTTPS), set"
    echo "     server_name and uncomment the HTTPS template in:"
else
    echo "  1. Another vhost is already the default server on port 80, so the proxy is not"
    echo "     reachable until you set a real server_name (and, for HTTPS, uncomment the"
    echo "     template) in:"
fi
echo "     $NGINX_SITE"
echo "     (Certificates: run the nginx hardening script with certbot)"
echo "  2. Add application secrets to $ENV_FILE"
echo "     (database URLs, API keys, JWT secrets, etc.)"
echo "  3. Install production dependencies in $APP_PATH:"
echo "     cd $APP_PATH && npm ci --omit=dev"
echo "  4. Verify the service is running:"
echo "     systemctl status $APP_NAME"
echo "     journalctl -u $APP_NAME -f"
echo "  5. Check npm audit timer:"
echo "     systemctl list-timers $APP_NAME-audit.timer"
echo "  6. Test nginx config after SSL setup:"
echo "     nginx -t && systemctl reload nginx"
echo "  7. Review AppArmor profile if the app uses additional filesystem paths."
echo "  8. Use 'helmet' middleware in your Express app for defense-in-depth headers."
echo

echo -e "${C_GREEN}Done.${C_NC}"
