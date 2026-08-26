#!/usr/bin/env bash

# =============================================================================
# Script:      postgresql.sh
# Description: Installs and hardens PostgreSQL on Arch Linux for production,
#              targeting:
#                - scram-sha-256 authentication (no md5, no trust)
#                - Strict pg_hba.conf with peer and scram-sha-256 only
#                - Hardened systemd service with sandboxing
#                - Comprehensive logging for audit trails
#                - Resource limits to prevent runaway queries
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
#
# Usage:       sudo ./postgresql.sh [-p PORT] [--ssl --ssl-cert PATH
#                    --ssl-key PATH] [--local-only | --no-local
#                    --allow-cidr CIDR] [-h]
#
# Requirements:
#   - Arch Linux with pacman
#   - Root privileges
#
# What this script does:
#   1. Installs PostgreSQL
#   2. Initializes the database with data checksums and scram-sha-256
#   3. Hardens postgresql.conf (connections, auth, logging, resources)
#   4. Hardens pg_hba.conf (no trust, scram-sha-256 everywhere)
#   5. Prints restricted application user template
#   6. Hardens file permissions (700/600)
#   7. Hardens the systemd service with security overrides
#   8. Creates nftables snippet for remote access (if applicable)
#   9. Enables and starts PostgreSQL
#  10. Prints summary with security checklist and next steps
# =============================================================================

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck disable=SC1091
source "$SCRIPT_DIR/../lib/nftables.sh"

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
PORT=5432
ENABLE_SSL=false
LOCAL_ONLY=true
REMOTE_CIDR=""
SSL_CERT_SOURCE=""
SSL_KEY_SOURCE=""
PG_DATA="/var/lib/postgres/data"
PG_CONF="$PG_DATA/postgresql.conf"
PG_HBA="$PG_DATA/pg_hba.conf"
PG_TLS_DIR="/var/lib/postgres/tls"
PG_SSL_CERT="$PG_TLS_DIR/server.crt"
PG_SSL_KEY="$PG_TLS_DIR/server.key"
NFT_CONFIG="${AAL_NFT_CONFIG:-/etc/nftables.conf}"
LOGFILE="/var/log/postgresql-hardening-$(date +%Y%m%d-%H%M%S).log"

# --- Usage ---
usage() {
    cat <<EOF
Usage: sudo $0 [options]

Options:
  -p PORT          PostgreSQL listen port (default: $PORT)
  --ssl            Enable SSL/TLS connections
  --ssl-cert PATH  PEM server certificate to install (required with --ssl)
  --ssl-key PATH   PEM private key to install (required with --ssl)
  --local-only     Listen only on localhost (default: enabled)
  --no-local       Listen on all interfaces; requires --ssl and --allow-cidr
  --allow-cidr CIDR
                   IPv4 client network allowed in remote mode (for example,
                   10.20.30.0/24)
  -h, --help       Show this help

Examples:
  sudo $0                           # Localhost only, port 5432
  sudo $0 -p 5433 --ssl --ssl-cert /root/server.crt --ssl-key /root/server.key
  sudo $0 --no-local --allow-cidr 10.20.30.0/24 --ssl \
      --ssl-cert /root/server.crt --ssl-key /root/server.key
EOF
    exit 0
}

# --- Parse Arguments ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        -p)
            [[ $# -ge 2 && -n "$2" && "$2" != -* ]] || err "-p requires a port"
            PORT="$2"; shift 2
            ;;
        --ssl)       ENABLE_SSL=true; shift ;;
        --ssl-cert)
            [[ $# -ge 2 && -n "$2" && "$2" != -* ]] || err "--ssl-cert requires a path"
            SSL_CERT_SOURCE="$2"; shift 2
            ;;
        --ssl-key)
            [[ $# -ge 2 && -n "$2" && "$2" != -* ]] || err "--ssl-key requires a path"
            SSL_KEY_SOURCE="$2"; shift 2
            ;;
        --local-only) LOCAL_ONLY=true; shift ;;
        --no-local)  LOCAL_ONLY=false; shift ;;
        --allow-cidr)
            [[ $# -ge 2 && -n "$2" && "$2" != -* ]] || \
                err "--allow-cidr requires an IPv4 CIDR"
            REMOTE_CIDR="$2"; shift 2
            ;;
        -h|--help)   usage ;;
        *)           err "Unknown option: $1" ;;
    esac
done

# --- Validate ---
[[ $(id -u) -eq 0 ]] || err "Must be run as root"

# Validate port range
if [[ ! "$PORT" =~ ^[0-9]+$ ]] || (( 10#$PORT < 1 || 10#$PORT > 65535 )); then
    err "Port must be between 1 and 65535"
fi

validate_ipv4_cidr() {
    local cidr="$1" address prefix octet
    local -a octets

    [[ "$cidr" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([1-9]|[12][0-9]|3[0-2])$ ]] || return 1
    address=${cidr%/*}
    prefix=${cidr#*/}
    IFS=. read -r -a octets <<< "$address"
    (( ${#octets[@]} == 4 )) || return 1
    for octet in "${octets[@]}"; do
        (( 10#$octet <= 255 )) || return 1
    done
    [[ "$prefix" =~ ^[0-9]+$ ]]
}

if [[ "$ENABLE_SSL" == true ]]; then
    [[ -n "$SSL_CERT_SOURCE" && -n "$SSL_KEY_SOURCE" ]] || \
        err "--ssl requires both --ssl-cert and --ssl-key"
    [[ -f "$SSL_CERT_SOURCE" ]] || err "SSL certificate not found: $SSL_CERT_SOURCE"
    [[ -f "$SSL_KEY_SOURCE" ]] || err "SSL private key not found: $SSL_KEY_SOURCE"
    command -v openssl &>/dev/null || err "--ssl requires openssl"
    openssl x509 -in "$SSL_CERT_SOURCE" -noout &>/dev/null || \
        err "Invalid PEM certificate: $SSL_CERT_SOURCE"
    openssl pkey -in "$SSL_KEY_SOURCE" -passin pass: -noout &>/dev/null || \
        err "Invalid or encrypted PEM private key: $SSL_KEY_SOURCE"
    CERT_PUBLIC_KEY=$(openssl x509 -in "$SSL_CERT_SOURCE" -pubkey -noout 2>/dev/null |
        openssl pkey -pubin -outform DER 2>/dev/null | sha256sum)
    PRIVATE_PUBLIC_KEY=$(openssl pkey -in "$SSL_KEY_SOURCE" -passin pass: -pubout -outform DER 2>/dev/null |
        sha256sum)
    [[ "$CERT_PUBLIC_KEY" == "$PRIVATE_PUBLIC_KEY" ]] || \
        err "SSL certificate and private key do not match"
elif [[ -n "$SSL_CERT_SOURCE" || -n "$SSL_KEY_SOURCE" ]]; then
    err "--ssl-cert and --ssl-key require --ssl"
fi

if [[ "$LOCAL_ONLY" == false ]]; then
    [[ "$ENABLE_SSL" == true ]] || err "--no-local requires --ssl"
    [[ -n "$REMOTE_CIDR" ]] || err "--no-local requires --allow-cidr"
    validate_ipv4_cidr "$REMOTE_CIDR" || err "Invalid IPv4 CIDR: $REMOTE_CIDR"
    command -v nft &>/dev/null || err "Remote mode requires nftables"
    [[ -f "$NFT_CONFIG" ]] || err "Remote mode requires the installer-owned $NFT_CONFIG"
    nft list chain inet filter input &>/dev/null || \
        err "Remote mode requires the installer-owned inet filter input chain"
    if grep -Fq '/etc/nftables.d/postgresql.conf' "$NFT_CONFIG"; then
        err "Remove the legacy PostgreSQL snippet include from $NFT_CONFIG and reload nftables before using remote mode"
    fi
elif [[ -n "$REMOTE_CIDR" ]]; then
    err "--allow-cidr is only valid with --no-local"
fi

# Redirect output to logfile as well
exec > >(tee -a "$LOGFILE") 2>&1

info "Port: $PORT"
info "SSL: $ENABLE_SSL"
info "Local only: $LOCAL_ONLY"
if [[ "$LOCAL_ONLY" == false ]]; then
    info "Allowed client network: $REMOTE_CIDR"
fi
info "Log: $LOGFILE"

# =============================================================================
# 1. INSTALL POSTGRESQL
# =============================================================================

msg "Installing PostgreSQL..."

pacman -Syu --noconfirm --needed postgresql

# Verify installation
PG_VER=$(postgres --version 2>&1 | grep -oP '[\d.]+')
info "PostgreSQL version: $PG_VER"

# =============================================================================
# 2. INITIALIZE DATABASE
# =============================================================================

if [[ -f "$PG_DATA/PG_VERSION" ]]; then
    info "Database cluster already initialized at $PG_DATA"
else
    msg "Initializing database cluster..."

    # Ensure the postgres user home directory exists
    mkdir -p /var/lib/postgres
    chown postgres:postgres /var/lib/postgres

    su - postgres -c "initdb \
        --locale=en_US.UTF-8 \
        -D '$PG_DATA' \
        --data-checksums \
        --auth-local=peer \
        --auth-host=scram-sha-256"

    msg "Database cluster initialized with data checksums and scram-sha-256"
fi

# Install operator-supplied TLS material under PostgreSQL's writable state
# directory. PostgreSQL refuses permissive private-key modes, so keep both
# files postgres-owned and private.
if [[ "$ENABLE_SSL" == true ]]; then
    msg "Installing PostgreSQL TLS certificate and private key..."
    install -d -o postgres -g postgres -m 0700 "$PG_TLS_DIR"
    if [[ ! "$SSL_CERT_SOURCE" -ef "$PG_SSL_CERT" ]]; then
        install -o postgres -g postgres -m 0600 "$SSL_CERT_SOURCE" "$PG_SSL_CERT"
    else
        chown postgres:postgres "$PG_SSL_CERT"
        chmod 0600 "$PG_SSL_CERT"
    fi
    if [[ ! "$SSL_KEY_SOURCE" -ef "$PG_SSL_KEY" ]]; then
        install -o postgres -g postgres -m 0600 "$SSL_KEY_SOURCE" "$PG_SSL_KEY"
    else
        chown postgres:postgres "$PG_SSL_KEY"
        chmod 0600 "$PG_SSL_KEY"
    fi
fi

# =============================================================================
# 3. HARDEN postgresql.conf
# =============================================================================

msg "Hardening postgresql.conf..."

# Back up original
if [[ -f "$PG_CONF" && ! -f "${PG_CONF}.orig" ]]; then
    cp "$PG_CONF" "${PG_CONF}.orig"
    info "Backed up original to ${PG_CONF}.orig"
fi

# Determine listen address
if [[ "$LOCAL_ONLY" == true ]]; then
    LISTEN_ADDR="localhost"
else
    LISTEN_ADDR="*"
fi

cat > "$PG_CONF" <<EOF
# =============================================================================
# PostgreSQL Hardened Configuration
# Generated by AwesomeArchLinux/hardening/postgresql/postgresql.sh
# =============================================================================

# -----------------------------------------------------------------------------
# CONNECTION
# -----------------------------------------------------------------------------
listen_addresses = '$LISTEN_ADDR'
port = $PORT
max_connections = 100
superuser_reserved_connections = 3

# -----------------------------------------------------------------------------
# AUTHENTICATION
# -----------------------------------------------------------------------------
password_encryption = scram-sha-256
authentication_timeout = 30s

# -----------------------------------------------------------------------------
# SSL / TLS
# -----------------------------------------------------------------------------
EOF

if [[ "$ENABLE_SSL" == true ]]; then
    cat >> "$PG_CONF" <<EOF
ssl = on
ssl_cert_file = '$PG_SSL_CERT'
ssl_key_file = '$PG_SSL_KEY'
ssl_min_protocol_version = 'TLSv1.2'
ssl_ciphers = 'HIGH:!aNULL:!MD5:!3DES:!RC4'
ssl_prefer_server_ciphers = on
EOF
else
    cat >> "$PG_CONF" <<'EOF'
ssl = off
# To enable SSL, re-run with --ssl or set these manually:
# ssl = on
# ssl_cert_file = '/path/to/server.crt'
# ssl_key_file = '/path/to/server.key'
# ssl_min_protocol_version = 'TLSv1.2'
# ssl_ciphers = 'HIGH:!aNULL:!MD5:!3DES:!RC4'
# ssl_prefer_server_ciphers = on
EOF
fi

cat >> "$PG_CONF" <<'EOF'

# -----------------------------------------------------------------------------
# LOGGING
# -----------------------------------------------------------------------------
logging_collector = on
log_directory = 'log'
log_filename = 'postgresql-%Y-%m-%d.log'
log_rotation_age = 1d
log_rotation_size = 100MB
log_min_messages = warning
log_min_error_statement = error
log_connections = on
log_disconnections = on
log_duration = off
log_line_prefix = '%t [%p]: user=%u,db=%d,app=%a,client=%h '
log_statement = 'ddl'
log_checkpoints = on
log_lock_waits = on
log_temp_files = 0

# -----------------------------------------------------------------------------
# SECURITY
# -----------------------------------------------------------------------------
row_security = on
shared_preload_libraries = 'pg_stat_statements'

# -----------------------------------------------------------------------------
# RESOURCE LIMITS
# -----------------------------------------------------------------------------
shared_buffers = 256MB
work_mem = 8MB
maintenance_work_mem = 128MB
effective_cache_size = 768MB
temp_file_limit = 1GB
statement_timeout = 60000
idle_in_transaction_session_timeout = 600000
EOF

msg "postgresql.conf written"

# =============================================================================
# 4. HARDEN pg_hba.conf
# =============================================================================

msg "Hardening pg_hba.conf..."

# Back up original
if [[ -f "$PG_HBA" && ! -f "${PG_HBA}.orig" ]]; then
    cp "$PG_HBA" "${PG_HBA}.orig"
    info "Backed up original to ${PG_HBA}.orig"
fi

cat > "$PG_HBA" <<EOF
# =============================================================================
# PostgreSQL Client Authentication Configuration
# Generated by AwesomeArchLinux/hardening/postgresql/postgresql.sh
#
# TYPE  DATABASE  USER  ADDRESS        METHOD
# =============================================================================

# Superuser via Unix socket — peer authentication (OS user must match)
local   all       postgres                          peer

# All other local users — scram-sha-256 password authentication
local   all       all                               scram-sha-256

# IPv4 loopback
host    all       all       127.0.0.1/32            scram-sha-256

# IPv6 loopback
host    all       all       ::1/128                 scram-sha-256
EOF

# Remote mode is validated above to require TLS and one explicit client CIDR.
if [[ "$LOCAL_ONLY" == false ]]; then
    cat >> "$PG_HBA" <<EOF

# Remote connections — SSL required, scram-sha-256 only
hostssl all       all       $REMOTE_CIDR             scram-sha-256
EOF
    info "pg_hba.conf: TLS connections allowed only from $REMOTE_CIDR"
fi

msg "pg_hba.conf written (no 'trust' authentication anywhere)"

# =============================================================================
# 5. CREATE RESTRICTED APPLICATION USER TEMPLATE
# =============================================================================

msg "Application user template:"
echo
echo -e "${C_BLUE}--- Run these commands as the postgres superuser: ---${C_NC}"
echo -e "${C_YELLOW}"
cat <<'SQL'
-- Connect as superuser
sudo -u postgres psql

-- Create a restricted application user
CREATE USER appuser CONNECTION LIMIT 10;
\password appuser

-- Create application database owned by the user
CREATE DATABASE appdb OWNER appuser;

-- Revoke public access (defense in depth)
REVOKE ALL ON DATABASE appdb FROM PUBLIC;

-- Grant only connect privilege
GRANT CONNECT ON DATABASE appdb TO appuser;

-- Inside appdb, restrict schema access:
-- \c appdb
-- REVOKE CREATE ON SCHEMA public FROM PUBLIC;
-- GRANT USAGE ON SCHEMA public TO appuser;
SQL
echo -e "${C_NC}"

# =============================================================================
# 6. HARDEN FILE PERMISSIONS
# =============================================================================

msg "Hardening file permissions..."

# Data directory — only postgres user
chown -R postgres:postgres "$PG_DATA"
chmod 700 "$PG_DATA"

# Config files — readable only by postgres
chmod 600 "$PG_CONF"
chmod 600 "$PG_HBA"

# Ensure log directory exists and is owned by postgres
mkdir -p "$PG_DATA/log"
chown postgres:postgres "$PG_DATA/log"
chmod 700 "$PG_DATA/log"

msg "Permissions set: data=700, configs=600"

# =============================================================================
# 7. HARDEN SYSTEMD SERVICE
# =============================================================================

msg "Hardening PostgreSQL systemd service..."

mkdir -p /etc/systemd/system/postgresql.service.d/
cat > /etc/systemd/system/postgresql.service.d/hardening.conf <<'EOF'
[Service]
# --- Filesystem protection ---
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/postgres /run/postgresql

# --- Privilege escalation ---
NoNewPrivileges=yes

# --- Kernel protection ---
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes

# --- Capability bounding (empty = drop all) ---
CapabilityBoundingSet=

# --- Memory ---
# PostgreSQL JIT compilation requires executable memory
MemoryDenyWriteExecute=no

# --- Network ---
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

# --- System calls ---
SystemCallFilter=@system-service @network-io
SystemCallErrorNumber=EPERM
SystemCallArchitectures=native

# --- Misc hardening ---
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
PrivateDevices=yes
DevicePolicy=closed
EOF

systemctl daemon-reload
msg "systemd hardening override installed"

# =============================================================================
# 8. NFTABLES ACCESS RULE (if not local-only)
# =============================================================================

if [[ "$LOCAL_ONLY" == false ]]; then
    msg "Installing restricted nftables access rule for PostgreSQL..."
    aal_nft_persist_block postgresql-remote-access <<EOF
insert rule inet filter input ip saddr $REMOTE_CIDR tcp dport $PORT ct state new accept comment "awesome-postgresql-remote"
EOF
    aal_nft_remove_live_rules inet filter input awesome-postgresql-remote
    nft insert rule inet filter input ip saddr "$REMOTE_CIDR" tcp dport "$PORT" \
        ct state new accept comment "awesome-postgresql-remote"
    info "nftables permits PostgreSQL only from $REMOTE_CIDR"
else
    # Re-running in local-only mode revokes a remote rule installed by a
    # previous version of this script without requiring a ruleset reload.
    if command -v nft &>/dev/null && nft list chain inet filter input &>/dev/null; then
        aal_nft_remove_live_rules inet filter input awesome-postgresql-remote
    fi
    if [[ -f "$NFT_CONFIG" ]] && \
            grep -Fqx '# BEGIN AwesomeArchLinux: postgresql-remote-access' "$NFT_CONFIG"; then
        aal_nft_persist_block postgresql-remote-access </dev/null
    fi
    info "Local-only mode: no PostgreSQL firewall opening is installed"
fi

# =============================================================================
# 9. ENABLE AND START POSTGRESQL
# =============================================================================

msg "Enabling and starting PostgreSQL..."

# Ensure the run directory exists
mkdir -p /run/postgresql
chown postgres:postgres /run/postgresql

systemctl enable postgresql
systemctl restart postgresql

# Verify it is running
if systemctl is-active --quiet postgresql; then
    msg "PostgreSQL is running"
else
    err "PostgreSQL failed to start. Check: journalctl -xeu postgresql"
fi

# Enable pg_stat_statements extension in the default database
info "Enabling pg_stat_statements extension..."
su - postgres -c "psql -c 'CREATE EXTENSION IF NOT EXISTS pg_stat_statements;'" 2>/dev/null || \
    warn "Could not enable pg_stat_statements — enable it manually after first login"

# =============================================================================
# 10. SUMMARY
# =============================================================================

echo
echo -e "${C_GREEN}========================================================================${C_NC}"
echo -e "${C_GREEN} PostgreSQL production hardening complete!${C_NC}"
echo -e "${C_GREEN}========================================================================${C_NC}"
echo
echo -e "${C_BLUE}Connection:${C_NC}"
echo "  Host:          ${LISTEN_ADDR}"
echo "  Port:          ${PORT}"
echo "  Data Dir:      ${PG_DATA}"
echo "  Version:       ${PG_VER}"
echo "  SSL:           ${ENABLE_SSL}"
echo "  Log:           ${LOGFILE}"
echo
echo -e "${C_BLUE}Configuration Files:${C_NC}"
echo "  postgresql.conf:  ${PG_CONF}"
echo "  pg_hba.conf:      ${PG_HBA}"
echo "  systemd override: /etc/systemd/system/postgresql.service.d/hardening.conf"
if [[ "$LOCAL_ONLY" == false ]]; then
echo "  Allowed CIDR:        ${REMOTE_CIDR} (managed in $NFT_CONFIG)"
fi
echo
echo -e "${C_BLUE}Security Checklist:${C_NC}"
echo "  [x] Data checksums enabled"
echo "  [x] scram-sha-256 authentication (no md5, no trust)"
echo "  [x] Peer auth for local superuser only"
echo "  [x] pg_hba.conf — no trust entries"
echo "  [x] File permissions: data=700, configs=600"
echo "  [x] systemd sandboxing (ProtectSystem, NoNewPrivileges, etc.)"
echo "  [x] Logging: connections, disconnections, DDL, checkpoints, lock waits"
echo "  [x] Resource limits: statement_timeout=60s, idle_in_transaction=10m"
echo "  [x] Row-level security enabled"
echo "  [x] pg_stat_statements loaded for query monitoring"
if [[ "$ENABLE_SSL" == true ]]; then
echo "  [x] SSL/TLS enabled (TLS 1.2+, strong ciphers)"
else
echo "  [ ] SSL/TLS not enabled (local-only mode)"
fi
echo
echo -e "${C_YELLOW}IMPORTANT next steps:${C_NC}"
echo "  1. Change the default postgres superuser password:"
echo "     sudo -u postgres psql -c \"ALTER USER postgres PASSWORD 'your-strong-password';\""
echo "  2. Create application-specific users (see template above)"
echo "  3. Never use the postgres superuser for application connections"
echo "  4. Set up regular backups:"
echo "     pg_dump, pg_basebackup, or WAL archiving"
echo "  5. Consider connection pooling with PgBouncer for production loads"
echo "  6. Monitor queries with pg_stat_statements:"
echo "     SELECT * FROM pg_stat_statements ORDER BY total_exec_time DESC LIMIT 10;"
echo "  7. Review postgresql.conf resource settings for your hardware:"
echo "     https://pgtune.leopard.in.ua/"
echo
echo -e "${C_GREEN}Done.${C_NC}"
