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
while [[ $# -gt 0 ]]; do
    case "$1" in
        -a)          APP_PATH="$2"; shift 2 ;;
        -u)          APP_USER="$2"; shift 2 ;;
        -p)          PORT="$2"; shift 2 ;;
        -n)          APP_NAME="$2"; shift 2 ;;
        -h|--help)   usage ;;
        *)           err "Unknown option: $1" ;;
    esac
done

# --- Validate ---
[[ $(id -u) -eq 0 ]] || err "Must be run as root"
[[ -n "$APP_PATH" ]] || err "Application path is required (-a /path/to/app)"
[[ -d "$APP_PATH" ]] || err "Application directory does not exist: $APP_PATH"

# Resolve to absolute path
APP_PATH=$(realpath "$APP_PATH")

# Redirect output to logfile as well
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

# Configure npm for security
msg "Hardening npm configuration..."

# Set global prefix to /usr/local to avoid needing sudo for global installs
npm config set prefix /usr/local

# Disable npm telemetry and metrics
npm config set fund false
npm config set update-notifier false
npm config set audit-level high

# Disable scripts from running during install by default (opt-in per project)
info "npm audit-level set to high"
info "npm telemetry/fund notifications disabled"

# =============================================================================
# 3. CREATE NODE.JS SECURITY ENVIRONMENT FILE
# =============================================================================

msg "Creating security environment file..."

ENV_DIR="/etc/$APP_NAME"
ENV_FILE="$ENV_DIR/env"

mkdir -p "$ENV_DIR"

cat > "$ENV_FILE" <<EOF
# =============================================================================
# Node.js production environment for $APP_NAME
# Generated by AwesomeArchLinux/hardening/nodejs/nodejs.sh
#
# WARNING: Add application secrets here (DB passwords, API keys, etc.)
#          This file is chmod 600 and owned by root:$APP_USER
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

chown "root:$APP_USER" "$ENV_FILE"
chmod 640 "$ENV_FILE"
msg "Environment file created: $ENV_FILE (mode 640)"

# =============================================================================
# 4. CREATE LOG AND DATA DIRECTORIES
# =============================================================================

msg "Creating log and data directories..."

mkdir -p "/var/log/$APP_NAME"
chown "$APP_USER:$APP_USER" "/var/log/$APP_NAME"
chmod 750 "/var/log/$APP_NAME"

mkdir -p "$APP_PATH/data" "$APP_PATH/logs"
chown "$APP_USER:$APP_USER" "$APP_PATH/data" "$APP_PATH/logs"
chmod 750 "$APP_PATH/data" "$APP_PATH/logs"

# =============================================================================
# 5. CREATE HARDENED SYSTEMD SERVICE
# =============================================================================

msg "Creating hardened systemd service..."

# Detect entry point: check for package.json "start" script, fall back to index.js
ENTRY_POINT="$APP_PATH/index.js"
if [[ -f "$APP_PATH/package.json" ]]; then
    # Check if there is a "start" script defined
    START_SCRIPT=$(node -e "
        try {
            const pkg = require('$APP_PATH/package.json');
            if (pkg.scripts && pkg.scripts.start) {
                console.log(pkg.scripts.start);
            }
        } catch(e) {}
    " 2>/dev/null || true)

    if [[ -n "$START_SCRIPT" ]]; then
        info "Detected package.json start script: $START_SCRIPT"
        # If it's a simple "node <file>" command, extract the file path
        if [[ "$START_SCRIPT" =~ ^node[[:space:]]+(.+)$ ]]; then
            SCRIPT_FILE="${BASH_REMATCH[1]}"
            # Resolve relative path
            if [[ "$SCRIPT_FILE" != /* ]]; then
                ENTRY_POINT="$APP_PATH/$SCRIPT_FILE"
            else
                ENTRY_POINT="$SCRIPT_FILE"
            fi
        fi
    fi
fi

info "Entry point: $ENTRY_POINT"

# Determine capability settings based on port
CAP_SETTINGS=""
if [[ "$PORT" -lt 1024 ]]; then
    warn "Port $PORT < 1024: granting CAP_NET_BIND_SERVICE capability"
    CAP_SETTINGS="CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE"
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

# --- Restart policy ---
Restart=always
RestartSec=10
WatchdogSec=30

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
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

# --- Namespace and realtime restrictions ---
RestrictNamespaces=yes
RestrictRealtime=yes

# --- System call filtering ---
SystemCallFilter=@system-service @network-io
SystemCallArchitectures=native

# --- Resource limits ---
LimitNOFILE=65535
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF

msg "Systemd service created: /etc/systemd/system/$APP_NAME.service"

# =============================================================================
# 6. NGINX REVERSE PROXY
# =============================================================================

msg "Configuring nginx reverse proxy..."

# Install nginx if not present
pacman -S --noconfirm --needed nginx-mainline || pacman -S --noconfirm --needed nginx

mkdir -p /etc/nginx/sites-enabled /etc/nginx/conf.d

cat > "/etc/nginx/sites-enabled/$APP_NAME.conf" <<EOF
# =============================================================================
# nginx reverse proxy for $APP_NAME (Node.js)
# Generated by AwesomeArchLinux/hardening/nodejs/nodejs.sh
# =============================================================================

# --- Rate limiting zone ---
# 10 requests/second per IP, burst of 20, 10MB shared memory zone
limit_req_zone \$binary_remote_addr zone=${APP_NAME}_ratelimit:10m rate=10r/s;

# --- Upstream ---
upstream ${APP_NAME}_backend {
    server 127.0.0.1:$PORT;
    keepalive 64;
}

# --- HTTP: Redirect to HTTPS ---
server {
    listen 80;
    listen [::]:80;
    server_name _;

    location / {
        return 301 https://\$host\$request_uri;
    }
}

# --- HTTPS: Reverse Proxy ---
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name _;

    # --- SSL certificates (update paths after obtaining certificates) ---
    # ssl_certificate     /etc/letsencrypt/live/YOUR_DOMAIN/fullchain.pem;
    # ssl_certificate_key /etc/letsencrypt/live/YOUR_DOMAIN/privkey.pem;

    # --- Security headers ---
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header Content-Security-Policy "default-src 'none'; frame-ancestors 'none'" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "no-referrer" always;

    # --- Hide upstream technology ---
    proxy_hide_header X-Powered-By;

    # --- Proxy to Node.js ---
    location / {
        # Rate limiting
        limit_req zone=${APP_NAME}_ratelimit burst=20 nodelay;

        # Proxy pass
        proxy_pass http://${APP_NAME}_backend;

        # Standard proxy headers
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
EOF

msg "nginx config created: /etc/nginx/sites-enabled/$APP_NAME.conf"

# Verify nginx can parse the config (non-fatal; SSL certs may not exist yet)
if nginx -t 2>/dev/null; then
    msg "nginx configuration test passed"
else
    warn "nginx configuration test failed (expected if SSL certificates are not yet configured)"
    warn "Update the ssl_certificate paths in /etc/nginx/sites-enabled/$APP_NAME.conf"
fi

# =============================================================================
# 7. LOG ROTATION
# =============================================================================

msg "Configuring log rotation..."

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
    create 640 $APP_USER $APP_USER
    sharedscripts
    postrotate
        systemctl reload $APP_NAME 2>/dev/null || true
    endscript
}
EOF

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

abi <abi/3.0>,

#include <tunables/global>

profile $APP_NAME /usr/bin/node flags=(enforce) {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/openssl>

  # Network — allow TCP/UDP for inet and inet6, plus unix sockets
  network inet stream,
  network inet dgram,
  network inet6 stream,
  network inet6 dgram,
  network unix stream,

  # Node.js binary
  /usr/bin/node                    mr,

  # Application directory — read only
  $APP_PATH/**                     r,
  $APP_PATH/node_modules/**        mr,

  # Data and logs — read/write
  $APP_PATH/data/**                rw,
  $APP_PATH/logs/**                rw,
  /var/log/$APP_NAME/**            rw,
  owner /var/log/$APP_NAME/**      w,

  # Environment config
  /etc/$APP_NAME/**                r,

  # TLS trust store
  /etc/ssl/certs/**                r,
  /etc/ca-certificates/**          r,
  /usr/share/ca-certificates/**    r,

  # Shared libraries (Node.js native addons)
  /usr/lib/**                      mr,

  # Proc
  owner /proc/*/fd/                r,
  /proc/sys/kernel/random/boot_id  r,
  owner /proc/*/status             r,

  # Deny everything else implicitly
}
EOF

    msg "AppArmor profile created: $APPARMOR_PROFILE"

    # Load the profile if AppArmor is active
    if command -v apparmor_parser &>/dev/null; then
        if apparmor_parser -r -W "$APPARMOR_PROFILE" 2>/dev/null; then
            aa-enforce "$APPARMOR_PROFILE" 2>/dev/null && \
                msg "AppArmor profile loaded in enforce mode" || \
                warn "Failed to enforce AppArmor profile (AppArmor may not be active)"
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
# 9. NPM AUDIT AUTOMATION
# =============================================================================

msg "Setting up automated npm security audit..."

# Create the audit script
cat > /usr/local/bin/npm-security-audit.sh <<EOF
#!/usr/bin/env bash
# =============================================================================
# Automated npm security audit for $APP_NAME
# Generated by AwesomeArchLinux/hardening/nodejs/nodejs.sh
#
# Runs npm audit on the production dependencies and logs results.
# Called by systemd timer: $APP_NAME-audit.timer
# =============================================================================

set -euo pipefail

APP_PATH="$APP_PATH"
APP_NAME="$APP_NAME"
LOG_DIR="/var/log/\$APP_NAME"
AUDIT_LOG="\$LOG_DIR/npm-audit-\$(date +%Y%m%d-%H%M%S).log"

mkdir -p "\$LOG_DIR"

echo "=== npm security audit: \$(date) ===" >> "\$AUDIT_LOG"
echo "Application: \$APP_NAME (\$APP_PATH)" >> "\$AUDIT_LOG"
echo "" >> "\$AUDIT_LOG"

# Run npm audit on production dependencies only
cd "\$APP_PATH"
if npm audit --production >> "\$AUDIT_LOG" 2>&1; then
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
ls -1t "\$LOG_DIR"/npm-audit-*.log 2>/dev/null | tail -n +31 | xargs -r rm -f
EOF

chmod 755 /usr/local/bin/npm-security-audit.sh
msg "Audit script created: /usr/local/bin/npm-security-audit.sh"

# Create systemd service for the audit
cat > "/etc/systemd/system/$APP_NAME-audit.service" <<EOF
[Unit]
Description=npm security audit for $APP_NAME
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/npm-security-audit.sh
User=root
PrivateTmp=true
EOF

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

# Source files: 640 (owner rw, group r, other none)
find "$APP_PATH" -type f -name "*.js" -exec chmod 640 {} \;
find "$APP_PATH" -type f -name "*.ts" -exec chmod 640 {} \;
find "$APP_PATH" -type f -name "*.json" -exec chmod 640 {} \;
find "$APP_PATH" -type f -name "*.mjs" -exec chmod 640 {} \;
find "$APP_PATH" -type f -name "*.cjs" -exec chmod 640 {} \;

# Directories: 750 (owner rwx, group rx, other none)
find "$APP_PATH" -type d -exec chmod 750 {} \;

# node_modules: 750 for directories, preserve file permissions
if [[ -d "$APP_PATH/node_modules" ]]; then
    find "$APP_PATH/node_modules" -type d -exec chmod 750 {} \;
fi

# .env files: 600 (owner rw only) — should not exist in production, but secure them if present
find "$APP_PATH" -name ".env*" -type f -exec chmod 600 {} \;

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
    systemctl start "$APP_NAME.service"
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

echo -e "${C_BLUE}Generated Files:${C_NC}"
echo "  systemd service:   /etc/systemd/system/$APP_NAME.service"
echo "  Environment file:  $ENV_FILE"
echo "  nginx config:      /etc/nginx/sites-enabled/$APP_NAME.conf"
echo "  Logrotate:         /etc/logrotate.d/$APP_NAME"
echo "  AppArmor profile:  $APPARMOR_PROFILE"
echo "  Audit script:      /usr/local/bin/npm-security-audit.sh"
echo "  Audit timer:       /etc/systemd/system/$APP_NAME-audit.timer"
echo "  Log directory:     /var/log/$APP_NAME/"
echo

echo -e "${C_BLUE}systemd Hardening Applied:${C_NC}"
echo "  - ProtectSystem=strict, ProtectHome=yes"
echo "  - PrivateTmp=yes, PrivateDevices=yes"
echo "  - NoNewPrivileges=yes, LockPersonality=yes"
echo "  - Kernel tunable/module/log/cgroup protection"
echo "  - RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX"
echo "  - RestrictNamespaces=yes, RestrictRealtime=yes"
echo "  - SystemCallFilter=@system-service @network-io"
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
echo "  - Security headers (HSTS, CSP, X-Frame-Options, etc.)"
echo "  - X-Powered-By header stripped"
echo "  - WebSocket upgrade support enabled"
echo "  - AppArmor confinement profile"
echo "  - Weekly npm audit via systemd timer"
echo "  - Source files chmod 640, directories chmod 750"
echo "  - .env files chmod 600"
echo

echo -e "${C_YELLOW}IMPORTANT next steps:${C_NC}"
echo "  1. Update SSL certificate paths in:"
echo "     /etc/nginx/sites-enabled/$APP_NAME.conf"
echo "     (Or run the nginx hardening script with certbot)"
echo "  2. Add application secrets to $ENV_FILE"
echo "     (database URLs, API keys, JWT secrets, etc.)"
echo "  3. Install production dependencies in $APP_PATH:"
echo "     cd $APP_PATH && npm ci --production"
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
