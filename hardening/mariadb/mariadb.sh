#!/usr/bin/env bash

# =============================================================================
# Script:      mariadb.sh
# Description: Installs and hardens MariaDB on Arch Linux for production use,
#              targeting:
#                - Secure default configuration (no anonymous users, no test DB)
#                - Network hardening (local-only by default)
#                - Strict SQL mode and file access restrictions
#                - Optional TLS encryption
#                - systemd service hardening
#                - Slow query logging and log rotation
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
#
# Usage:       sudo ./mariadb.sh [-p PORT] [--ssl] [--local-only] [-h]
#
# Requirements:
#   - Arch Linux with pacman
#   - Root privileges
#
# What this script does:
#   1. Installs mariadb
#   2. Initializes the database (if not already initialized)
#   3. Runs security hardening (mysql_secure_installation equivalent)
#   4. Writes a hardened configuration file
#   5. Creates log and security directories
#   6. Generates self-signed SSL certificates (if --ssl)
#   7. Hardens file permissions
#   8. Applies systemd service hardening
#   9. Configures logrotate
#  10. Restarts and verifies MariaDB
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
PORT=3306
ENABLE_SSL=false
LOCAL_ONLY=true
HARDENING_CONF="/etc/my.cnf.d/hardening.cnf"
ROOT_PASS_FILE="/root/.mariadb-root-pass"
LOGFILE="/var/log/mariadb-hardening-$(date +%Y%m%d-%H%M%S).log"

# --- Usage ---
usage() {
    cat <<EOF
Usage: sudo $0 [options]

Options:
  -p PORT       MariaDB listen port (default: $PORT)
  --ssl         Enable TLS with self-signed certificates
  --local-only  Bind to 127.0.0.1 only (default: enabled)
  --no-local    Bind to 0.0.0.0 (accept remote connections)
  -h, --help    Show this help

Examples:
  sudo $0                           # Defaults: port 3306, local-only
  sudo $0 -p 3307 --ssl             # Custom port with TLS
  sudo $0 --ssl --no-local          # TLS + accept remote connections
EOF
    exit 0
}

# --- Parse Arguments ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        -p)          PORT="$2"; shift 2 ;;
        --ssl)       ENABLE_SSL=true; shift ;;
        --local-only) LOCAL_ONLY=true; shift ;;
        --no-local)  LOCAL_ONLY=false; shift ;;
        -h|--help)   usage ;;
        *)           err "Unknown option: $1" ;;
    esac
done

# --- Validate ---
[[ $(id -u) -eq 0 ]] || err "Must be run as root"

if ! [[ "$PORT" =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then
    err "Invalid port: $PORT (must be 1-65535)"
fi

# Redirect output to logfile as well
exec > >(tee -a "$LOGFILE") 2>&1

BIND_ADDRESS="127.0.0.1"
if [[ "$LOCAL_ONLY" == false ]]; then
    BIND_ADDRESS="0.0.0.0"
fi

info "Port:        $PORT"
info "Bind:        $BIND_ADDRESS"
info "SSL:         $ENABLE_SSL"
info "Local only:  $LOCAL_ONLY"
info "Log:         $LOGFILE"

# =============================================================================
# 1. INSTALL MARIADB
# =============================================================================

msg "Installing MariaDB..."

if pacman -Qi mariadb &>/dev/null; then
    info "mariadb is already installed"
else
    pacman -S --noconfirm --needed mariadb
    msg "mariadb installed successfully"
fi

# =============================================================================
# 2. INITIALIZE DATABASE
# =============================================================================

if [[ -d /var/lib/mysql/mysql ]]; then
    info "Database already initialized (skipping mariadb-install-db)"
else
    msg "Initializing MariaDB data directory..."
    mariadb-install-db --user=mysql --basedir=/usr --datadir=/var/lib/mysql
    msg "Database initialized"
fi

# =============================================================================
# 3. START MARIADB TEMPORARILY
# =============================================================================

msg "Starting MariaDB temporarily for security hardening..."

# Start with skip-grant-tables so we can set root password
# Use skip-networking to prevent any external access during setup
mysqld_safe --skip-grant-tables --skip-networking &
MYSQLD_PID=$!

# Wait for MariaDB to be ready
RETRIES=30
until mariadb -u root -e "SELECT 1" &>/dev/null; do
    RETRIES=$((RETRIES - 1))
    if (( RETRIES <= 0 )); then
        err "MariaDB failed to start within 30 seconds"
    fi
    sleep 1
done

info "MariaDB is ready"

# =============================================================================
# 4. SECURITY HARDENING (mysql_secure_installation equivalent)
# =============================================================================

msg "Running security hardening..."

# Generate a strong random root password
ROOT_PASS="$(openssl rand -base64 32 | tr -d '/+=' | head -c 32)"

mariadb -u root <<EOSQL
-- Flush privileges first to enable grant tables
FLUSH PRIVILEGES;

-- Set root password
ALTER USER 'root'@'localhost' IDENTIFIED BY '${ROOT_PASS}';

-- Remove anonymous users
DELETE FROM mysql.global_priv WHERE User='';

-- Disallow remote root login
DELETE FROM mysql.global_priv WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');

-- Remove test database
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';

-- Apply changes
FLUSH PRIVILEGES;
EOSQL

msg "Security hardening applied"

# Save root password securely
cat > "$ROOT_PASS_FILE" <<EOF
# MariaDB root password
# Generated by AwesomeArchLinux/hardening/mariadb/mariadb.sh on $(date)
# Keep this file secure. Delete after storing in a password manager.
root_password=${ROOT_PASS}
EOF

chmod 600 "$ROOT_PASS_FILE"
chown root:root "$ROOT_PASS_FILE"

msg "Root password saved to $ROOT_PASS_FILE (mode 600)"

# Stop the temporary MariaDB instance
kill "$MYSQLD_PID" 2>/dev/null || true
wait "$MYSQLD_PID" 2>/dev/null || true

# Wait for shutdown
RETRIES=15
while pgrep -x mysqld &>/dev/null; do
    RETRIES=$((RETRIES - 1))
    if (( RETRIES <= 0 )); then
        warn "MariaDB did not stop cleanly, sending SIGKILL"
        pkill -9 -x mysqld || true
        sleep 2
        break
    fi
    sleep 1
done

info "Temporary MariaDB instance stopped"

# =============================================================================
# 5. CREATE LOG AND SECURITY DIRECTORIES
# =============================================================================

msg "Creating directories..."

# Log directory
mkdir -p /var/log/mysql
chown mysql:mysql /var/log/mysql
chmod 750 /var/log/mysql

# Secure file directory (for LOAD DATA / SELECT INTO)
mkdir -p /var/lib/mysql-files
chown mysql:mysql /var/lib/mysql-files
chmod 750 /var/lib/mysql-files

# Runtime directory
mkdir -p /run/mysqld
chown mysql:mysql /run/mysqld
chmod 755 /run/mysqld

msg "Directories created"

# =============================================================================
# 6. SSL CERTIFICATES (if --ssl)
# =============================================================================

if [[ "$ENABLE_SSL" == true ]]; then
    msg "Generating self-signed SSL certificates..."

    SSL_DIR="/etc/mysql/ssl"
    mkdir -p "$SSL_DIR"

    # Generate CA key and certificate
    openssl genrsa 4096 > "$SSL_DIR/ca-key.pem"
    openssl req -new -x509 -nodes -days 3650 \
        -key "$SSL_DIR/ca-key.pem" \
        -out "$SSL_DIR/ca-cert.pem" \
        -subj "/CN=MariaDB-CA/O=AwesomeArchLinux"

    # Generate server key and certificate
    openssl genrsa 4096 > "$SSL_DIR/server-key.pem"
    openssl req -new -nodes \
        -key "$SSL_DIR/server-key.pem" \
        -out "$SSL_DIR/server-req.pem" \
        -subj "/CN=$(hostname -f)/O=AwesomeArchLinux"
    openssl x509 -req -days 3650 \
        -in "$SSL_DIR/server-req.pem" \
        -CA "$SSL_DIR/ca-cert.pem" \
        -CAkey "$SSL_DIR/ca-key.pem" \
        -CAcreateserial \
        -out "$SSL_DIR/server-cert.pem"

    # Generate client key and certificate (for client authentication)
    openssl genrsa 4096 > "$SSL_DIR/client-key.pem"
    openssl req -new -nodes \
        -key "$SSL_DIR/client-key.pem" \
        -out "$SSL_DIR/client-req.pem" \
        -subj "/CN=MariaDB-Client/O=AwesomeArchLinux"
    openssl x509 -req -days 3650 \
        -in "$SSL_DIR/client-req.pem" \
        -CA "$SSL_DIR/ca-cert.pem" \
        -CAkey "$SSL_DIR/ca-key.pem" \
        -CAcreateserial \
        -out "$SSL_DIR/client-cert.pem"

    # Clean up CSR files
    rm -f "$SSL_DIR/server-req.pem" "$SSL_DIR/client-req.pem"

    # Set permissions
    chown -R mysql:mysql "$SSL_DIR"
    chmod 700 "$SSL_DIR"
    chmod 600 "$SSL_DIR"/*.pem

    msg "SSL certificates generated in $SSL_DIR"
fi

# =============================================================================
# 7. WRITE HARDENED CONFIGURATION
# =============================================================================

msg "Writing hardened configuration to $HARDENING_CONF..."

# Back up existing config if present
if [[ -f "$HARDENING_CONF" ]]; then
    BACKUP="${HARDENING_CONF}.bak.$(date +%Y%m%d-%H%M%S)"
    cp "$HARDENING_CONF" "$BACKUP"
    info "Existing config backed up to $BACKUP"
fi

cat > "$HARDENING_CONF" <<EOF
# =============================================================================
# MariaDB Production Hardening Configuration
# Generated by AwesomeArchLinux/hardening/mariadb/mariadb.sh on $(date)
#
# This file is loaded after server.cnf. Settings here override defaults.
# =============================================================================

[mysqld]

# --- Network ---
bind-address            = ${BIND_ADDRESS}
port                    = ${PORT}
skip-name-resolve
max_connections         = 100
max_connect_errors      = 10
wait_timeout            = 600
interactive_timeout     = 600

# --- Security ---
local-infile            = 0
skip-symbolic-links
secure-file-priv        = /var/lib/mysql-files
sql-mode                = STRICT_TRANS_TABLES,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION
log-raw                 = OFF

EOF

# Append SSL settings if enabled
if [[ "$ENABLE_SSL" == true ]]; then
    cat >> "$HARDENING_CONF" <<EOF
# --- SSL/TLS ---
ssl-ca                  = /etc/mysql/ssl/ca-cert.pem
ssl-cert                = /etc/mysql/ssl/server-cert.pem
ssl-key                 = /etc/mysql/ssl/server-key.pem
tls-version             = TLSv1.2,TLSv1.3
require-secure-transport = ON

EOF
fi

cat >> "$HARDENING_CONF" <<'EOF'
# --- Logging ---
log-error               = /var/log/mysql/error.log
general-log             = 0
general-log-file        = /var/log/mysql/general.log
slow-query-log          = 1
slow-query-log-file     = /var/log/mysql/slow.log
long-query-time         = 2
log-queries-not-using-indexes = 1
log-warnings            = 2

# --- Performance (reasonable defaults) ---
innodb-buffer-pool-size = 256M
innodb-log-file-size    = 64M
innodb-flush-log-at-trx-commit = 1
innodb-file-per-table   = 1
key-buffer-size         = 32M
max-allowed-packet      = 16M
tmp-table-size          = 32M
max-heap-table-size     = 32M
table-open-cache        = 400
sort-buffer-size        = 2M
read-buffer-size        = 2M

[client]
default-character-set   = utf8mb4
EOF

chmod 640 "$HARDENING_CONF"
chown root:mysql "$HARDENING_CONF"

msg "Hardened configuration written"

# =============================================================================
# 8. HARDEN FILE PERMISSIONS
# =============================================================================

msg "Hardening file permissions..."

# Data directory
chown -R mysql:mysql /var/lib/mysql
chmod 750 /var/lib/mysql

# Configuration files
for f in /etc/my.cnf.d/*.cnf; do
    if [[ -f "$f" ]]; then
        chmod 640 "$f"
        chown root:mysql "$f"
    fi
done

if [[ -f /etc/my.cnf ]]; then
    chmod 640 /etc/my.cnf
    chown root:mysql /etc/my.cnf
fi

msg "File permissions hardened"

# =============================================================================
# 9. HARDEN SYSTEMD SERVICE
# =============================================================================

msg "Writing systemd hardening override for MariaDB..."

mkdir -p /etc/systemd/system/mariadb.service.d

# Determine capabilities
CAPABILITY_SETTING="CapabilityBoundingSet="
if (( PORT < 1024 )); then
    CAPABILITY_SETTING="CapabilityBoundingSet=CAP_NET_BIND_SERVICE"
    info "Port $PORT < 1024: adding CAP_NET_BIND_SERVICE"
fi

cat > /etc/systemd/system/mariadb.service.d/hardening.conf <<EOF
# =============================================================================
# MariaDB systemd hardening override
# Generated by AwesomeArchLinux/hardening/mariadb/mariadb.sh
# =============================================================================

[Service]
# Filesystem protection
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes

# Writable paths required by MariaDB
ReadWritePaths=/var/lib/mysql /var/log/mysql /run/mysqld /var/lib/mysql-files

# Privilege restrictions
NoNewPrivileges=yes
${CAPABILITY_SETTING}

# Kernel protection
ProtectKernelTunables=yes
ProtectKernelModules=yes

# Network
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

# MariaDB uses memory-mapped files; do not deny write-execute
MemoryDenyWriteExecute=no
EOF

systemctl daemon-reload

msg "systemd hardening override applied"

# =============================================================================
# 10. CONFIGURE LOGROTATE
# =============================================================================

msg "Configuring logrotate for MariaDB logs..."

cat > /etc/logrotate.d/mariadb <<'EOF'
/var/log/mysql/*.log {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 640 mysql mysql
    sharedscripts
    postrotate
        # Signal MariaDB to reopen log files
        if [ -f /run/mysqld/mysqld.pid ]; then
            kill -USR1 $(cat /run/mysqld/mysqld.pid) 2>/dev/null || true
        fi
    endscript
}
EOF

chmod 644 /etc/logrotate.d/mariadb

msg "Logrotate configured"

# =============================================================================
# 11. RESTART AND VERIFY
# =============================================================================

msg "Enabling and starting MariaDB..."

systemctl enable mariadb
systemctl restart mariadb

# Wait for MariaDB to be ready
sleep 3

if systemctl is-active --quiet mariadb; then
    msg "MariaDB is running"
else
    err "MariaDB failed to start. Check: journalctl -u mariadb -e"
fi

# Verify we can connect with the root password
if mariadb -u root -p"${ROOT_PASS}" -e "SELECT 1" &>/dev/null; then
    msg "Root authentication verified"
else
    warn "Could not verify root authentication. Check $ROOT_PASS_FILE for the password."
fi

# =============================================================================
# 12. SUMMARY
# =============================================================================

echo
echo -e "${C_GREEN}========================================================================${C_NC}"
echo -e "${C_GREEN} MariaDB production hardening complete!${C_NC}"
echo -e "${C_GREEN}========================================================================${C_NC}"
echo

echo -e "${C_BLUE}Configuration:${C_NC}"
echo "  Hardening config:     $HARDENING_CONF"
echo "  Root password:        $ROOT_PASS_FILE"
echo "  Data directory:       /var/lib/mysql"
echo "  Secure file dir:      /var/lib/mysql-files"
echo "  systemd hardening:    /etc/systemd/system/mariadb.service.d/hardening.conf"
echo "  Logrotate:            /etc/logrotate.d/mariadb"
echo "  Log:                  $LOGFILE"
echo

echo -e "${C_BLUE}Network:${C_NC}"
echo "  Bind address:         $BIND_ADDRESS"
echo "  Port:                 $PORT"
echo "  DNS lookups:          disabled (skip-name-resolve)"
echo "  Max connections:      100"
echo

echo -e "${C_BLUE}Security:${C_NC}"
echo "  Anonymous users:      removed"
echo "  Remote root login:    disabled"
echo "  Test database:        removed"
echo "  LOAD DATA LOCAL:      disabled"
echo "  Symbolic links:       disabled"
echo "  Strict SQL mode:      enabled"
echo "  Plaintext log:        OFF (log-raw = OFF)"

if [[ "$ENABLE_SSL" == true ]]; then
    echo
    echo -e "${C_BLUE}SSL/TLS:${C_NC}"
    echo "  CA certificate:       /etc/mysql/ssl/ca-cert.pem"
    echo "  Server certificate:   /etc/mysql/ssl/server-cert.pem"
    echo "  Server key:           /etc/mysql/ssl/server-key.pem"
    echo "  Client certificate:   /etc/mysql/ssl/client-cert.pem"
    echo "  Client key:           /etc/mysql/ssl/client-key.pem"
    echo "  TLS versions:         TLSv1.2, TLSv1.3"
    echo "  Require secure:       ON"
fi

echo
echo -e "${C_BLUE}Logging:${C_NC}"
echo "  Error log:            /var/log/mysql/error.log"
echo "  Slow query log:       /var/log/mysql/slow.log (threshold: 2s)"
echo "  General log:          OFF (enable for debugging only)"
echo "  Logrotate:            weekly, 12 rotations, compressed"
echo

echo -e "${C_BLUE}systemd Hardening:${C_NC}"
echo "  ProtectSystem:        strict"
echo "  ProtectHome:          yes"
echo "  PrivateTmp:           yes"
echo "  PrivateDevices:       yes"
echo "  NoNewPrivileges:      yes"
echo "  ProtectKernelTunables: yes"
echo "  ProtectKernelModules: yes"
echo

echo -e "${C_YELLOW}IMPORTANT next steps:${C_NC}"
echo "  1. Save the root password from $ROOT_PASS_FILE to a password manager,"
echo "     then delete the file: shred -u $ROOT_PASS_FILE"
echo "  2. Create application-specific users (never use root for applications):"
echo
echo "     mariadb -u root -p"
echo "     CREATE DATABASE myapp CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
echo "     CREATE USER 'myapp'@'localhost' IDENTIFIED BY 'strong-password-here';"
echo "     GRANT SELECT, INSERT, UPDATE, DELETE ON myapp.* TO 'myapp'@'localhost';"
echo "     FLUSH PRIVILEGES;"
echo

if [[ "$ENABLE_SSL" == true ]]; then
    echo "  3. Replace self-signed certificates with real ones for production."
    echo "     Copy your CA, cert, and key to /etc/mysql/ssl/ and restart MariaDB."
    echo
    echo "  4. Connect with SSL:"
    echo "     mariadb -u root -p --ssl-ca=/etc/mysql/ssl/ca-cert.pem"
    echo
fi

echo -e "${C_YELLOW}Useful commands:${C_NC}"
echo "  systemctl status mariadb                  # Check service status"
echo "  journalctl -u mariadb -f                  # Follow MariaDB logs"
echo "  mariadb -u root -p                        # Connect as root"
echo "  mariadb -u root -p -e 'SHOW VARIABLES'    # Show all server variables"
echo "  mariadb -u root -p -e 'SHOW STATUS'       # Show server status"
echo "  mysqladmin -u root -p processlist          # Show active connections"
echo

echo -e "${C_GREEN}Done.${C_NC}"
