#!/usr/bin/env bash

# =============================================================================
# Script:      proxy.sh
# Description: Installs and configures a hardened transparent Squid proxy on
#              Arch Linux with:
#                - Transparent HTTP interception via nftables REDIRECT
#                - Optional SSL bump (peek-and-splice HTTPS inspection)
#                - Optional DNS filtering via dnsmasq blocklists
#                - Domain blocklists (ads, malware, tracking) with auto-update
#                - Information disclosure prevention (header stripping)
#                - Connection limits and rate limiting
#                - SSD-friendly rock cache store
#                - systemd service hardening
#                - ICAP integration hooks for future AV scanning
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
#
# Usage:       sudo ./proxy.sh -n 192.168.1.0/24 [-p 3128] [-P 3129]
#                              [-c 10000] [-e EMAIL] [--ssl-bump]
#                              [--dns-filter] [--dry-run] [-h]
#
# Requirements:
#   - Arch Linux with pacman
#   - Root privileges
#   - nftables for transparent interception
#   - Gateway/router position (clients route through this host)
#
# What this script does:
#   1.  Installs squid, openssl, nftables (and dnsmasq if --dns-filter)
#   2.  Creates squid directories and verifies the proxy user
#   3.  Generates SSL bump CA certificate (if --ssl-bump)
#   4.  Downloads and formats domain blocklists (ads, malware)
#   5.  Writes hardened /etc/squid/squid.conf (transparent intercept mode)
#   6.  Appends SSL bump configuration (if --ssl-bump)
#   7.  Configures DNS filtering via dnsmasq (if --dns-filter)
#   8.  Applies the required IPv4 forwarding sysctl override
#   9.  Creates source-scoped nftables REDIRECT and input rules
#  10.  Initializes Squid cache directory structure
#  11.  Applies systemd hardening overrides
#  12.  Creates systemd timer for daily blocklist updates
#  13.  Configures log rotation
#  14.  Validates config and starts services
#  15.  Prints summary with verification commands
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

msg()  { printf "%b[+]%b %s\n" "$C_GREEN"  "$C_NC" "$1"; }
info() { printf "%b[*]%b %s\n" "$C_BLUE"   "$C_NC" "$1"; }
warn() { printf "%b[!]%b %s\n" "$C_YELLOW" "$C_NC" "$1"; }
err()  { printf "%b[!]%b %s\n" "$C_RED"    "$C_NC" "$1" >&2; exit 1; }

# --- Defaults ---
NETWORK=""
HTTP_PORT=3128
HTTPS_PORT=3129
CACHE_SIZE_MB=10000
ADMIN_EMAIL=""
SSL_BUMP=false
DNS_FILTER=false
DRY_RUN=false

readonly SQUID_CONF="/etc/squid/squid.conf"
readonly SQUID_SSL_DIR="/etc/squid/ssl"
readonly SQUID_CACHE_DIR="/var/cache/squid"
readonly BLOCKLIST_DIR="/etc/squid/blocklists"

# --- Usage ---
usage() {
    cat <<EOF
Usage: sudo $0 [options]

Required:
  -n CIDR       LAN network CIDR (e.g., 192.168.1.0/24)

Optional:
  -p PORT       HTTP intercept port (default: $HTTP_PORT)
  -P PORT       HTTPS intercept port (default: $HTTPS_PORT)
  -c SIZE_MB    Disk cache size in MB (default: $CACHE_SIZE_MB)
  -e EMAIL      Admin email for cache manager
  --ssl-bump    Enable SSL bump (HTTPS interception with peek-and-splice)
  --dns-filter  Enable DNS-level ad/malware filtering via dnsmasq
  --dry-run     Write configs but do not start services
  -h            Show this help

Examples:
  sudo $0 -n 192.168.1.0/24
  sudo $0 -n 10.0.0.0/8 -c 20000 --ssl-bump --dns-filter
  sudo $0 -n 192.168.0.0/16 --dry-run
EOF
    exit 0
}

# --- Parse Arguments ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        -n)           NETWORK="$2"; shift 2 ;;
        -p)           HTTP_PORT="$2"; shift 2 ;;
        -P)           HTTPS_PORT="$2"; shift 2 ;;
        -c)           CACHE_SIZE_MB="$2"; shift 2 ;;
        -e)           ADMIN_EMAIL="$2"; shift 2 ;;
        --ssl-bump)   SSL_BUMP=true; shift ;;
        --dns-filter) DNS_FILTER=true; shift ;;
        --dry-run)    DRY_RUN=true; shift ;;
        -h|--help)    usage ;;
        *)            err "Unknown option: $1" ;;
    esac
done

# --- Validate ---
[[ $(id -u) -eq 0 ]] || err "Must be run as root"
[[ -n "$NETWORK" ]] || err "Network CIDR is required (-n). Use -h for help."

if ! [[ "$NETWORK" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
    err "Invalid CIDR format: $NETWORK (expected e.g., 192.168.1.0/24)"
fi

IFS='./' read -r NET_O1 NET_O2 NET_O3 NET_O4 NET_PREFIX <<< "$NETWORK"
for octet in "$NET_O1" "$NET_O2" "$NET_O3" "$NET_O4"; do
    (( 10#$octet <= 255 )) || err "Invalid CIDR address: $NETWORK"
done
(( 10#$NET_PREFIX <= 32 )) || err "Invalid CIDR prefix: $NETWORK"
[[ "$HTTP_PORT" =~ ^[0-9]+$ ]] && (( HTTP_PORT >= 1 && HTTP_PORT <= 65535 )) \
    || err "Invalid HTTP port: $HTTP_PORT"
[[ "$HTTPS_PORT" =~ ^[0-9]+$ ]] && (( HTTPS_PORT >= 1 && HTTPS_PORT <= 65535 )) \
    || err "Invalid HTTPS port: $HTTPS_PORT"
[[ "$CACHE_SIZE_MB" =~ ^[0-9]+$ ]] && (( CACHE_SIZE_MB >= 1 )) \
    || err "Invalid cache size: $CACHE_SIZE_MB"

ADMIN_EMAIL="${ADMIN_EMAIL:-admin@$(hostname -f 2>/dev/null || echo localhost)}"

readonly NETWORK HTTP_PORT HTTPS_PORT CACHE_SIZE_MB ADMIN_EMAIL SSL_BUMP DNS_FILTER DRY_RUN

info "Network:       $NETWORK"
info "HTTP port:     $HTTP_PORT"
info "HTTPS port:    $HTTPS_PORT"
info "Cache size:    ${CACHE_SIZE_MB} MB"
info "SSL bump:      $SSL_BUMP"
info "DNS filter:    $DNS_FILTER"
[[ "$DRY_RUN" == true ]] && warn "Dry-run mode: configs will be written but services will not start"

if [[ "$SSL_BUMP" == true ]]; then
    echo
    warn "============================================================"
    warn " SSL BUMP ENABLED — HTTPS traffic will be intercepted."
    warn " This has legal and privacy implications. Ensure you have"
    warn " authorization to inspect traffic on this network."
    warn "============================================================"
    echo
fi

# --- Helper: backup a file before overwriting ---
backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        local bak
        bak="${file}.bak.$(date +%Y%m%d-%H%M%S)"
        cp "$file" "$bak"
        info "Backed up $file → $bak"
    fi
}

# =============================================================================
# 1. INSTALL PACKAGES
# =============================================================================

msg "Installing packages..."

PKGS=(squid openssl nftables curl)
[[ "$DNS_FILTER" == true ]] && PKGS+=(dnsmasq)

for pkg in "${PKGS[@]}"; do
    if pacman -Qi "$pkg" &>/dev/null; then
        info "$pkg is already installed"
    else
        pacman -S --noconfirm --needed "$pkg"
        msg "$pkg installed"
    fi
done

# =============================================================================
# 2. CREATE DIRECTORIES AND VERIFY USER
# =============================================================================

msg "Setting up Squid directories..."

# Squid package on Arch creates the 'proxy' user; verify
if ! getent passwd proxy &>/dev/null; then
    useradd -r -d /var/cache/squid -s /usr/bin/nologin -c "Squid proxy" proxy
    info "Created proxy user"
fi

mkdir -p /etc/squid/conf.d "$SQUID_CACHE_DIR" /var/log/squid "$BLOCKLIST_DIR" "$SQUID_SSL_DIR" /run/squid

chown proxy:proxy "$SQUID_CACHE_DIR" /var/log/squid /run/squid
chmod 750 "$SQUID_CACHE_DIR" /var/log/squid
chmod 700 "$SQUID_SSL_DIR"

# Create empty blocklist files so squid.conf ACLs don't error on missing files
touch "$BLOCKLIST_DIR/ads.txt" "$BLOCKLIST_DIR/malware.txt"
[[ ! -f "$BLOCKLIST_DIR/whitelist.txt" ]] && cat > "$BLOCKLIST_DIR/whitelist.txt" <<'EOF'
# Whitelisted domains — one per line (e.g., .example.com)
# These bypass blocklist filtering
EOF

msg "Directories created"

# =============================================================================
# 3. GENERATE SSL BUMP CA (conditional)
# =============================================================================

if [[ "$SSL_BUMP" == true ]]; then
    msg "Generating SSL bump CA certificate..."

    if [[ -f "$SQUID_SSL_DIR/squid-ca.pem" && -f "$SQUID_SSL_DIR/squid-ca.key" ]]; then
        info "SSL CA already exists, skipping generation"
    else
        openssl req -new -newkey rsa:4096 -sha256 -days 3650 -nodes -x509 \
            -keyout "$SQUID_SSL_DIR/squid-ca.key" \
            -out "$SQUID_SSL_DIR/squid-ca.pem" \
            -subj "/CN=Squid Proxy CA/O=AwesomeArchLinux Transparent Proxy" \
            2>/dev/null

        chmod 600 "$SQUID_SSL_DIR/squid-ca.key"
        chmod 644 "$SQUID_SSL_DIR/squid-ca.pem"

        msg "SSL CA generated (valid 10 years)"
        warn "Deploy $SQUID_SSL_DIR/squid-ca.pem to client trust stores"
    fi

    # Generate DH parameters for SSL bump
    if [[ ! -f "$SQUID_SSL_DIR/dhparam.pem" ]]; then
        openssl dhparam -out "$SQUID_SSL_DIR/dhparam.pem" 2048 2>/dev/null
        chmod 644 "$SQUID_SSL_DIR/dhparam.pem"
        msg "DH parameters generated (2048-bit)"
    fi

    # Initialize SSL certificate database
    if [[ ! -d "$SQUID_CACHE_DIR/ssl_db" ]]; then
        /usr/lib/squid/security_file_certgen -c -s "$SQUID_CACHE_DIR/ssl_db" -M 64MB 2>/dev/null || \
            warn "security_file_certgen failed — SSL bump may not work"
        chown -R proxy:proxy "$SQUID_CACHE_DIR/ssl_db" 2>/dev/null || true
    fi
fi

# =============================================================================
# 4. DOWNLOAD DOMAIN BLOCKLISTS
# =============================================================================

msg "Installing the atomic blocklist updater..."

install -d -m 0755 /usr/local/bin
cat > /usr/local/bin/awesome-squid-blocklist-update <<'BLOCKLIST_UPDATE'
#!/usr/bin/env bash
set -euo pipefail

readonly BLOCKLIST_DIR="${AAL_SQUID_BLOCKLIST_DIR:-/etc/squid/blocklists}"
readonly MIN_ENTRIES="${AAL_MIN_BLOCKLIST_ENTRIES:-1000}"
readonly ADS_URL="${AAL_ADS_BLOCKLIST_URL:-https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts}"
readonly MALWARE_URL="${AAL_MALWARE_BLOCKLIST_URL:-https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn/hosts}"
readonly CURL_BIN="${AAL_CURL_BIN:-/usr/bin/curl}"
readonly SQUID_BIN="${AAL_SQUID_BIN:-/usr/bin/squid}"
readonly DNSMASQ_BLOCKLIST="${AAL_DNSMASQ_BLOCKLIST:-/etc/dnsmasq.d/proxy-blocklist.conf}"
readonly DNSMASQ_BIN="${AAL_DNSMASQ_BIN:-/usr/bin/dnsmasq}"
readonly SYSTEMCTL_BIN="${AAL_SYSTEMCTL_BIN:-/usr/bin/systemctl}"

NO_RECONFIGURE=false
if [[ "${1:-}" == "--no-reconfigure" ]]; then
    NO_RECONFIGURE=true
    shift
fi
(( $# == 0 )) || { printf 'Usage: %s [--no-reconfigure]\n' "$0" >&2; exit 2; }
[[ "$MIN_ENTRIES" =~ ^[1-9][0-9]*$ ]] || {
    printf 'Invalid minimum blocklist size: %s\n' "$MIN_ENTRIES" >&2
    exit 2
}
[[ -d "$BLOCKLIST_DIR" ]] || {
    printf 'Blocklist directory does not exist: %s\n' "$BLOCKLIST_DIR" >&2
    exit 1
}

declare -a TEMP_FILES=() STAGED_FILES=() DESTINATIONS=() BACKUPS=()
REPLACED=0
STAGE_RESULT=""
DNS_ACTIVE=false

rollback() {
    local i
    for (( i = REPLACED - 1; i >= 0; i-- )); do
        if [[ -n "${BACKUPS[$i]}" && -f "${BACKUPS[$i]}" ]]; then
            mv -f -- "${BACKUPS[$i]}" "${DESTINATIONS[$i]}"
            BACKUPS[$i]=""
        else
            rm -f -- "${DESTINATIONS[$i]}"
        fi
    done
}

cleanup() {
    local file
    for file in "${TEMP_FILES[@]}" "${STAGED_FILES[@]}" "${BACKUPS[@]}"; do
        [[ -n "$file" ]] && rm -f -- "$file"
    done
}

finish() {
    local rc=$?
    trap - EXIT
    if (( rc != 0 && REPLACED > 0 )); then
        rollback
        if [[ "$NO_RECONFIGURE" == false ]]; then
            "$SQUID_BIN" -k reconfigure >/dev/null 2>&1 || \
                printf 'Warning: could not reload the restored Squid blocklists.\n' >&2
            if [[ "$DNS_ACTIVE" == true ]]; then
                "$SYSTEMCTL_BIN" reload dnsmasq >/dev/null 2>&1 || \
                    printf 'Warning: could not reload the restored dnsmasq blocklist.\n' >&2
            fi
        fi
    fi
    cleanup
    exit "$rc"
}

trap finish EXIT
trap 'exit 130' HUP INT TERM

stage_blocklist() {
    local url="$1" label="$2" raw compiled count
    raw=$(mktemp "$BLOCKLIST_DIR/.${label}.raw.XXXXXX")
    compiled=$(mktemp "$BLOCKLIST_DIR/.${label}.compiled.XXXXXX")
    TEMP_FILES+=("$raw")
    STAGED_FILES+=("$compiled")

    if ! "$CURL_BIN" -fsSL --max-time 120 "$url" -o "$raw"; then
        printf 'Failed to download %s blocklist; installed lists were not changed.\n' "$label" >&2
        return 1
    fi

    awk '
        $1 == "0.0.0.0" {
            domain = tolower($2)
            if (domain ~ /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/ &&
                domain ~ /[.]/ && domain != "0.0.0.0") {
                print "." domain
            }
        }
    ' "$raw" | sort -u > "$compiled"

    count=$(wc -l < "$compiled")
    if (( count < MIN_ENTRIES )); then
        printf '%s blocklist has only %d valid entries (minimum %d); installed lists were not changed.\n' \
            "$label" "$count" "$MIN_ENTRIES" >&2
        return 1
    fi

    chmod 0644 "$compiled"
    chown root:root "$compiled"
    STAGE_RESULT="$compiled"
    printf 'Validated %s blocklist: %d domains.\n' "$label" "$count"
}

stage_blocklist "$ADS_URL" ads
ads_stage="$STAGE_RESULT"
stage_blocklist "$MALWARE_URL" malware
malware_stage="$STAGE_RESULT"

DESTINATIONS=("$BLOCKLIST_DIR/ads.txt" "$BLOCKLIST_DIR/malware.txt")
STAGED_FILES=("$ads_stage" "$malware_stage")

if [[ -e "$DNSMASQ_BLOCKLIST" ]]; then
    dnsmasq_dir=$(dirname -- "$DNSMASQ_BLOCKLIST")
    [[ -d "$dnsmasq_dir" ]] || {
        printf 'dnsmasq blocklist directory does not exist: %s\n' "$dnsmasq_dir" >&2
        exit 1
    }
    dnsmasq_stage=$(mktemp "$dnsmasq_dir/.proxy-blocklist.compiled.XXXXXX")
    STAGED_FILES+=("$dnsmasq_stage")
    {
        printf '# Auto-generated blocklist for DNS filtering\n'
        printf '# Generated by awesome-squid-blocklist-update\n\n'
        awk '{ domain=$0; sub(/^\./, "", domain); print "address=/" domain "/0.0.0.0" }' \
            "$ads_stage" "$malware_stage" | sort -u
    } > "$dnsmasq_stage"
    chmod 0644 "$dnsmasq_stage"
    chown root:root "$dnsmasq_stage"
    DESTINATIONS+=("$DNSMASQ_BLOCKLIST")
    DNS_ACTIVE=true
fi

for destination in "${DESTINATIONS[@]}"; do
    if [[ -e "$destination" ]]; then
        backup=$(mktemp "$BLOCKLIST_DIR/.blocklist.backup.XXXXXX")
        cp -p -- "$destination" "$backup"
        BACKUPS+=("$backup")
    else
        BACKUPS+=("")
    fi
done

for i in "${!DESTINATIONS[@]}"; do
    mv -f -- "${STAGED_FILES[$i]}" "${DESTINATIONS[$i]}"
    STAGED_FILES[$i]=""
    (( REPLACED += 1 ))
done

if [[ "$NO_RECONFIGURE" == false ]]; then
    "$SQUID_BIN" -k parse
    if [[ "$DNS_ACTIVE" == true ]]; then
        "$DNSMASQ_BIN" --test
    fi
    "$SQUID_BIN" -k reconfigure
    if [[ "$DNS_ACTIVE" == true ]]; then
        "$SYSTEMCTL_BIN" reload dnsmasq
    fi
fi

REPLACED=0
printf 'Squid blocklists updated successfully.\n'
BLOCKLIST_UPDATE
chmod 0755 /usr/local/bin/awesome-squid-blocklist-update

if [[ "$DRY_RUN" == false ]]; then
    /usr/local/bin/awesome-squid-blocklist-update --no-reconfigure
else
    info "Dry-run: skipping blocklist download"
fi

# =============================================================================
# 5. WRITE SQUID CONFIGURATION
# =============================================================================

msg "Writing $SQUID_CONF..."
backup_file "$SQUID_CONF"

cat > "$SQUID_CONF" <<EOF
# =============================================================================
# Squid Transparent Proxy — Hardened Configuration
# Generated by AwesomeArchLinux/hardening/proxy/proxy.sh
# =============================================================================

# --- Ports ---
http_port ${HTTP_PORT} intercept
EOF

# SSL bump port (conditional)
if [[ "$SSL_BUMP" == true ]]; then
    cat >> "$SQUID_CONF" <<EOF
https_port ${HTTPS_PORT} intercept ssl-bump \\
  tls-cert=${SQUID_SSL_DIR}/squid-ca.pem \\
  tls-key=${SQUID_SSL_DIR}/squid-ca.key \\
  generate-host-certificates=on \\
  dynamic_cert_mem_cache_size=16MB \\
  tls-dh=prime256v1:${SQUID_SSL_DIR}/dhparam.pem
EOF
fi

cat >> "$SQUID_CONF" <<EOF

# --- ACLs ---
acl localnet src ${NETWORK}
acl SSL_ports port 443
acl Safe_ports port 80          # HTTP
acl Safe_ports port 21          # FTP
acl Safe_ports port 443         # HTTPS
acl Safe_ports port 70          # Gopher
acl Safe_ports port 210         # WAIS
acl Safe_ports port 1025-65535  # Unprivileged ports
acl Safe_ports port 280         # http-mgmt
acl Safe_ports port 488         # gss-http
acl Safe_ports port 591         # FileMaker
acl Safe_ports port 777         # multiling http
acl CONNECT method CONNECT

# Domain blocklists
acl blocked_ads dstdomain "${BLOCKLIST_DIR}/ads.txt"
acl blocked_malware dstdomain "${BLOCKLIST_DIR}/malware.txt"
acl whitelisted dstdomain "${BLOCKLIST_DIR}/whitelist.txt"

# --- Access Controls (order matters) ---
# Allow localhost manager access
http_access allow localhost manager
http_access deny manager

# Block unsafe ports and CONNECT to non-SSL ports
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports

# Never let a destination whitelist turn this host into an open proxy.
http_access deny !localnet !localhost

# The whitelist overrides domain blocklists only for trusted clients.
http_access allow localnet whitelisted
http_access allow localhost whitelisted

# Block ads, malware, tracking
http_access deny blocked_ads
http_access deny blocked_malware

# Allow trusted clients
http_access allow localnet
http_access allow localhost

# Deny everything else
http_access deny all

# =============================================================================
# INFORMATION DISCLOSURE PREVENTION
# =============================================================================

# Suppress proxy identity headers
via off
forwarded_for delete
httpd_suppress_version_string on
visible_hostname proxy

# Strip outgoing headers that reveal proxy presence
request_header_access X-Forwarded-For deny all

# Strip response headers that reveal cache internals
reply_header_access X-Cache deny all
reply_header_access X-Cache-Lookup deny all
reply_header_access X-Squid-Error deny all
reply_header_access Server deny all

# =============================================================================
# CONNECTION LIMITS AND RATE LIMITING
# =============================================================================

# Max concurrent connections per client IP
client_ip_max_connections 64

# Connection rate limiting (delay pools)
delay_pools 1
delay_class 1 2
delay_access 1 allow localnet
# Aggregate: 100 MB/s total, per-client: 10 MB/s
delay_parameters 1 104857600/104857600 10485760/10485760

# =============================================================================
# CACHE CONFIGURATION
# =============================================================================

# Memory cache
cache_mem 256 MB
maximum_object_size_in_memory 1 MB

# Disk cache (rock store — SSD-friendly)
cache_dir rock ${SQUID_CACHE_DIR}/rock ${CACHE_SIZE_MB} max-size=32768

# Object size limits
maximum_object_size 256 MB
minimum_object_size 0 KB

# Cache thresholds
cache_swap_low 90
cache_swap_high 95

# Collapsed forwarding (deduplicate concurrent requests for same object)
collapsed_forwarding on

# Refresh patterns
refresh_pattern ^ftp:           1440    20%     10080
refresh_pattern -i (/cgi-bin/|\?) 0     0%      0
refresh_pattern .               0       20%     4320

# =============================================================================
# LOGGING
# =============================================================================

access_log daemon:/var/log/squid/access.log squid
cache_log /var/log/squid/cache.log
cache_store_log none

# Privacy: strip query strings from logs
strip_query_terms on
log_mime_hdrs off

# =============================================================================
# DNS
# =============================================================================
EOF

if [[ "$DNS_FILTER" == true ]]; then
    # Point Squid at local dnsmasq for filtered DNS
    echo "dns_nameservers 127.0.0.1" >> "$SQUID_CONF"
else
    cat >> "$SQUID_CONF" <<'EOF'
# Use privacy-respecting DNS resolvers
dns_nameservers 9.9.9.9 149.112.112.112
EOF
fi

cat >> "$SQUID_CONF" <<EOF

# =============================================================================
# ICAP INTEGRATION (placeholder for future AV scanning)
# =============================================================================
# Uncomment to enable ICAP antivirus scanning (e.g., c-icap + ClamAV):
# icap_enable on
# icap_send_client_ip on
# icap_service service_req reqmod_precache icap://127.0.0.1:1344/avscan
# adaptation_access service_req allow all

# =============================================================================
# MISCELLANEOUS
# =============================================================================

shutdown_lifetime 5 seconds
cache_effective_user proxy
cache_effective_group proxy
pid_filename /run/squid/squid.pid
coredump_dir ${SQUID_CACHE_DIR}
EOF

msg "squid.conf written"

# =============================================================================
# 6. SSL BUMP CONFIGURATION (conditional)
# =============================================================================

if [[ "$SSL_BUMP" == true ]]; then
    msg "Appending SSL bump configuration..."

    cat >> "$SQUID_CONF" <<'EOF'

# =============================================================================
# SSL BUMP — Peek-and-Splice Mode
# =============================================================================
# Default: peek at SNI then splice (pass through without decryption).
# To selectively decrypt specific domains, add bump rules before the splice.

acl step1 at_step SslBump1
acl step2 at_step SslBump2
acl step3 at_step SslBump3

# Peek at ClientHello to read SNI
ssl_bump peek step1

# Splice (pass-through) by default — no decryption
ssl_bump splice all

# To inspect specific domains, uncomment and customize:
# acl bump_domains dstdomain .example.com .suspicious-site.org
# ssl_bump bump bump_domains
# ssl_bump splice all

# Dynamic certificate generator
sslcrtd_program /usr/lib/squid/security_file_certgen -s /var/cache/squid/ssl_db -M 64MB
sslcrtd_children 5 startup=1 idle=1

# Outgoing TLS settings (Squid → origin server)
tls_outgoing_options options=NO_SSLv3,NO_TLSv1,NO_TLSv1_1 cipher=ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305
EOF

    msg "SSL bump configured (peek-and-splice mode)"
fi

# =============================================================================
# 7. DNS FILTERING (conditional)
# =============================================================================

if [[ "$DNS_FILTER" == true ]]; then
    msg "Configuring DNS filtering via dnsmasq..."

    # Check for systemd-resolved conflict on port 53
    if systemctl is-active systemd-resolved &>/dev/null; then
        if ss -tlnp | grep -q ':53 '; then
            warn "systemd-resolved is bound to port 53"
            info "Disabling resolved stub listener for dnsmasq..."
            mkdir -p /etc/systemd/resolved.conf.d
            cat > /etc/systemd/resolved.conf.d/disable-stub.conf <<'EOF'
[Resolve]
DNSStubListener=no
EOF
            systemctl restart systemd-resolved 2>/dev/null || true
        fi
    fi

    # Convert both validated blocklists to dnsmasq format
    DNSMASQ_BLOCKLIST="/etc/dnsmasq.d/proxy-blocklist.conf"
    mkdir -p /etc/dnsmasq.d

    info "Converting blocklists to dnsmasq format..."
    {
        echo "# Auto-generated blocklist for DNS filtering"
        echo "# Generated by AwesomeArchLinux/hardening/proxy/proxy.sh"
        echo ""
        # Convert ".domain" → "address=/domain/0.0.0.0"
        if [[ -s "$BLOCKLIST_DIR/ads.txt" && -s "$BLOCKLIST_DIR/malware.txt" ]]; then
            awk '{ domain=$0; sub(/^\./, "", domain); print "address=/" domain "/0.0.0.0" }' \
                "$BLOCKLIST_DIR/ads.txt" "$BLOCKLIST_DIR/malware.txt" | sort -u
        fi
    } > "$DNSMASQ_BLOCKLIST"

    # Write dnsmasq main config override
    cat > /etc/dnsmasq.d/proxy-dns.conf <<'EOF'
# DNS filtering config for transparent proxy
# Forward queries to privacy-respecting upstreams
server=9.9.9.9
server=149.112.112.112

# Logging
log-queries
log-facility=/var/log/dnsmasq.log

# Performance
cache-size=10000
dns-forward-max=1000

# Security
bogus-priv
domain-needed
stop-dns-rebind
rebind-localhost-ok
EOF

    # systemd hardening for dnsmasq
    mkdir -p /etc/systemd/system/dnsmasq.service.d
    cat > /etc/systemd/system/dnsmasq.service.d/hardening.conf <<'EOF'
[Service]
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
NoNewPrivileges=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
PrivateDevices=yes
DevicePolicy=closed
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
ReadWritePaths=/var/run/dnsmasq
EOF

    msg "DNS filtering configured"
fi

# =============================================================================
# 8. SYSCTL — IP FORWARDING
# =============================================================================

msg "Configuring sysctl for transparent interception..."

# Use z- prefix to override the AwesomeArchLinux workstation network layer,
# which sets ip_forward=0.
cat > /etc/sysctl.d/99-z-squid-proxy.conf <<'EOF'
# Squid transparent proxy — override base hardening ip_forward=0
# Required for nftables REDIRECT to intercept client traffic
net.ipv4.ip_forward = 1

# REDIRECT does not require routing 127/8 from non-loopback interfaces.
net.ipv4.conf.all.route_localnet = 0
EOF

sysctl --system &>/dev/null

# Verify
if [[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)" != "1" ]]; then
    warn "ip_forward is not enabled — transparent interception may not work"
fi

msg "sysctl configured (ip_forward=1)"

# =============================================================================
# 9. NFTABLES TRANSPARENT INTERCEPTION
# =============================================================================

msg "Configuring nftables transparent interception rules..."

if ! command -v nft &>/dev/null; then
    err "nftables is required for transparent interception"
fi

# Persist only the rules owned by this script. Never snapshot the live ruleset:
# it can contain transient Docker, Fail2Ban, or CrowdSec state.
SQUID_NFT_BLOCK=$(cat <<EOF
table ip squid_proxy {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        ip saddr $NETWORK tcp dport 80 redirect to :$HTTP_PORT
EOF
)
if [[ "$SSL_BUMP" == true ]]; then
    SQUID_NFT_BLOCK+=$'\n'"        ip saddr $NETWORK tcp dport 443 redirect to :$HTTPS_PORT"
fi
SQUID_NFT_BLOCK+=$'\n    }\n}'
SQUID_NFT_BLOCK+=$'\n'"insert rule inet filter input ip saddr $NETWORK ct state new tcp dport $HTTP_PORT accept comment \"awesome-squid-http\""
if [[ "$SSL_BUMP" == true ]]; then
    SQUID_NFT_BLOCK+=$'\n'"insert rule inet filter input ip saddr $NETWORK ct state new tcp dport $HTTPS_PORT accept comment \"awesome-squid-https\""
fi
aal_nft_persist_block squid-proxy <<< "$SQUID_NFT_BLOCK"

# Replace only this script's live objects. The hyphenated table is the legacy
# table created by older versions of this installer.
nft delete table ip squid-proxy 2>/dev/null || true
nft delete table ip squid_proxy 2>/dev/null || true
nft add table ip squid_proxy
nft add chain ip squid_proxy prerouting "{ type nat hook prerouting priority dstnat; policy accept; }"
nft add rule ip squid_proxy prerouting ip saddr "$NETWORK" tcp dport 80 redirect to :"$HTTP_PORT"
if [[ "$SSL_BUMP" == true ]]; then
    nft add rule ip squid_proxy prerouting ip saddr "$NETWORK" tcp dport 443 redirect to :"$HTTPS_PORT"
fi

if ! nft list chain inet filter input &>/dev/null; then
    err "Required nftables chain inet filter input does not exist"
fi
aal_nft_remove_live_rules inet filter input awesome-squid-http
aal_nft_remove_live_rules inet filter input awesome-squid-https
nft insert rule inet filter input ip saddr "$NETWORK" ct state new tcp dport "$HTTP_PORT" accept comment "awesome-squid-http"
if [[ "$SSL_BUMP" == true ]]; then
    nft insert rule inet filter input ip saddr "$NETWORK" ct state new tcp dport "$HTTPS_PORT" accept comment "awesome-squid-https"
fi

msg "nftables transparent interception configured"

# Document TPROXY alternative in a comment file
cat > /etc/squid/conf.d/tproxy-alternative.txt <<EOF
# =============================================================================
# TPROXY Alternative (preserves client source IP)
# =============================================================================
# TPROXY is more transparent than REDIRECT — the origin server sees the real
# client IP instead of the proxy's IP. However, it requires additional setup.
#
# 1. Add routing rules:
#    ip rule add fwmark 1 lookup 100
#    ip route add local 0.0.0.0/0 dev lo table 100
#
# 2. Replace REDIRECT with TPROXY in nftables:
#    nft add rule ip squid_proxy prerouting tcp dport 80 meta mark set 1 tproxy to :${HTTP_PORT}
#
# 3. Change squid.conf port to:
#    http_port ${HTTP_PORT} tproxy
#
# 4. Squid needs CAP_NET_ADMIN capability (already granted in systemd hardening)
# =============================================================================
EOF

# =============================================================================
# 10. INITIALIZE SQUID CACHE
# =============================================================================

msg "Initializing Squid cache directory..."

# Verify rock store support
if squid -v 2>/dev/null | grep -q "store-id"; then
    info "Squid supports rock store"
fi

squid -z --foreground 2>/dev/null || warn "Cache initialization returned non-zero (may be OK for rock store)"
chown -R proxy:proxy "$SQUID_CACHE_DIR"

msg "Cache initialized"

# =============================================================================
# 11. SYSTEMD HARDENING
# =============================================================================

msg "Applying systemd hardening overrides..."

mkdir -p /etc/systemd/system/squid.service.d
cat > /etc/systemd/system/squid.service.d/hardening.conf <<'EOF'
[Service]
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
# Squid needs NoNewPrivileges=no — it internally drops from root to proxy user
NoNewPrivileges=no
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
PrivateDevices=yes
DevicePolicy=closed
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK

ReadWritePaths=/var/cache/squid /var/log/squid /run/squid
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_NET_ADMIN CAP_IPC_LOCK
AmbientCapabilities=CAP_NET_BIND_SERVICE

LimitNOFILE=65536
EOF

systemctl daemon-reload
msg "systemd hardening applied"

# =============================================================================
# 12. BLOCKLIST UPDATE TIMER
# =============================================================================

msg "Creating blocklist update timer..."

cat > /etc/systemd/system/squid-blocklist-update.service <<EOF
[Unit]
Description=Update Squid proxy domain blocklists
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/awesome-squid-blocklist-update
User=root
UMask=0022
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
NoNewPrivileges=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
CapabilityBoundingSet=CAP_KILL
ReadWritePaths=${BLOCKLIST_DIR} -/etc/dnsmasq.d /run/squid
EOF

cat > /etc/systemd/system/squid-blocklist-update.timer <<'EOF'
[Unit]
Description=Update Squid blocklists daily

[Timer]
OnCalendar=*-*-* 03:00:00
RandomizedDelaySec=1800
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable squid-blocklist-update.timer

msg "Blocklist auto-update timer enabled (daily at 03:00)"

# =============================================================================
# 13. LOG ROTATION
# =============================================================================

msg "Configuring log rotation..."

cat > /etc/logrotate.d/squid <<'EOF'
/var/log/squid/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    sharedscripts
    postrotate
        squid -k rotate 2>/dev/null || true
    endscript
}
EOF

msg "Log rotation configured (14 days, compressed)"

# =============================================================================
# 14. VALIDATE AND START SERVICES
# =============================================================================

if [[ "$DRY_RUN" == true ]]; then
    msg "Dry-run: validating configuration..."

    if squid -k parse 2>/dev/null; then
        msg "Squid config is valid"
    else
        err "Squid config has errors — run: squid -k parse"
    fi

    info "Re-run without --dry-run to start services"
else
    msg "Starting services..."

    systemctl daemon-reload

    # Start dnsmasq first if DNS filtering is enabled
    if [[ "$DNS_FILTER" == true ]]; then
        systemctl enable --now dnsmasq
        if systemctl is-active --quiet dnsmasq; then
            msg "dnsmasq is running"
        else
            warn "dnsmasq failed to start — check: journalctl -u dnsmasq -e"
        fi
    fi

    # Start Squid
    systemctl enable squid
    systemctl restart squid

    sleep 3

    if systemctl is-active --quiet squid; then
        msg "squid is running"
    else
        err "squid failed to start. Check: journalctl -u squid -e"
    fi
fi

# =============================================================================
# 15. SUMMARY
# =============================================================================

echo
echo -e "${C_GREEN}========================================================================${C_NC}"
echo -e "${C_GREEN} Hardened transparent proxy configuration complete!${C_NC}"
echo -e "${C_GREEN}========================================================================${C_NC}"
echo

echo -e "${C_BLUE}Configuration files:${C_NC}"
echo "  Squid config:          $SQUID_CONF"
echo "  Blocklists:            $BLOCKLIST_DIR/{ads,malware,whitelist}.txt"
echo "  Cache directory:       $SQUID_CACHE_DIR/rock"
echo "  Logs:                  /var/log/squid/"
echo "  Log rotation:          /etc/logrotate.d/squid"
echo "  sysctl override:       /etc/sysctl.d/99-z-squid-proxy.conf"
echo "  systemd hardening:     /etc/systemd/system/squid.service.d/hardening.conf"
echo "  Blocklist updater:     /usr/local/bin/awesome-squid-blocklist-update"
echo "  Blocklist timer:       /etc/systemd/system/squid-blocklist-update.timer"
echo "  nftables table:        squid_proxy (ip family)"
if [[ "$SSL_BUMP" == true ]]; then
    echo "  SSL CA cert:           $SQUID_SSL_DIR/squid-ca.pem"
    echo "  SSL CA key:            $SQUID_SSL_DIR/squid-ca.key"
    echo "  SSL cert database:     $SQUID_CACHE_DIR/ssl_db"
fi
if [[ "$DNS_FILTER" == true ]]; then
    echo "  dnsmasq blocklist:     /etc/dnsmasq.d/proxy-blocklist.conf"
    echo "  dnsmasq DNS config:    /etc/dnsmasq.d/proxy-dns.conf"
    echo "  dnsmasq hardening:     /etc/systemd/system/dnsmasq.service.d/hardening.conf"
fi
echo

echo -e "${C_BLUE}Interception:${C_NC}"
echo "  Mode:                  Transparent (nftables REDIRECT)"
echo "  Network:               $NETWORK"
echo "  HTTP port:             $HTTP_PORT (← port 80 redirected)"
if [[ "$SSL_BUMP" == true ]]; then
    echo "  HTTPS port:            $HTTPS_PORT (← port 443 redirected)"
    echo "  SSL bump mode:         Peek-and-splice (SNI inspection, no decrypt by default)"
fi
echo "  Source restriction:    only $NETWORK may reach Squid intercept ports"
echo

echo -e "${C_BLUE}Security features:${C_NC}"
echo "  Headers stripped:      Via, X-Forwarded-For, X-Cache, Server"
echo "  Version suppressed:    httpd_suppress_version_string on"
echo "  Unsafe ports blocked:  CONNECT restricted to SSL ports"
echo "  Domain blocklists:     Ads, malware, tracking (auto-updated daily)"
echo "  Connection limits:     64 max per IP, delay pools enabled"
echo "  Cache:                 ${CACHE_SIZE_MB} MB rock store (SSD-friendly)"
echo "  Collapsed forwarding:  Enabled (deduplicates concurrent requests)"
echo "  Log privacy:           Query strings stripped"
echo "  systemd hardening:     ProtectSystem=strict, PrivateTmp, capabilities restricted"
if [[ "$DNS_FILTER" == true ]]; then
    echo "  DNS filtering:         dnsmasq with domain blocklists"
fi
echo

echo -e "${C_YELLOW}IMPORTANT — Next steps:${C_NC}"
echo "  1. Ensure clients use this host as their default gateway"
echo "  2. Customize blocklist whitelist: $BLOCKLIST_DIR/whitelist.txt"
if [[ "$SSL_BUMP" == true ]]; then
    echo "  3. Deploy CA cert to client trust stores:"
    echo "       cp $SQUID_SSL_DIR/squid-ca.pem /usr/local/share/ca-certificates/"
    echo "       update-ca-trust"
    echo "  4. To bump (decrypt) specific domains, add to squid.conf:"
    echo "       acl bump_domains dstdomain .suspicious-site.org"
    echo "       # Move 'ssl_bump bump bump_domains' BEFORE 'ssl_bump splice all'"
fi
echo "  5. Configure clients or DHCP to use this host as gateway"
echo "  6. Review TPROXY alternative: /etc/squid/conf.d/tproxy-alternative.txt"
echo

echo -e "${C_BLUE}Verification commands:${C_NC}"
echo "  squid -k parse                                # Validate config"
echo "  squidclient -h 127.0.0.1 -p $HTTP_PORT mgr:info    # Proxy status"
echo "  squidclient -h 127.0.0.1 -p $HTTP_PORT mgr:5min    # 5-minute averages"
echo "  squidclient -h 127.0.0.1 -p $HTTP_PORT mgr:utilization  # Cache utilization"
echo "  nft list table ip squid_proxy                  # Interception rules"
echo "  tail -f /var/log/squid/access.log              # Watch traffic"
echo "  curl -x http://127.0.0.1:$HTTP_PORT http://example.com  # Test proxy"
echo

echo -e "${C_BLUE}Cache hit monitoring:${C_NC}"
echo "  squidclient mgr:info | grep 'Hit Ratios'      # Hit ratio"
echo "  squidclient mgr:storedir                       # Cache store stats"
echo

echo -e "${C_GREEN}Done.${C_NC}"
