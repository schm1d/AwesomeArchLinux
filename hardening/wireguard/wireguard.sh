#!/usr/bin/env bash

# =============================================================================
# Script:      wireguard.sh
# Description: Sets up a hardened WireGuard VPN server on Arch Linux with:
#                - Automatic server and client key generation
#                - Pre-shared keys for quantum resistance
#                - nftables NAT masquerade rules
#                - QR codes for mobile client provisioning
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
#
# Usage:       sudo ./wireguard.sh [-p PORT] [-s SUBNET] [-c CLIENT_NAME]
#                                  [-n NUM_CLIENTS] [-d DNS] [-e ENDPOINT]
#                                  [--add-client NAME] [--force] [-h]
#
# Requirements:
#   - Arch Linux with pacman
#   - Root privileges
#   - A public-facing IP (or NAT with port forwarding)
#
# What this script does:
#   1.  Installs wireguard-tools and qrencode
#   2.  Enables IPv4 forwarding via sysctl
#   3.  Generates server private/public keys
#   4.  Creates /etc/wireguard/wg0.conf with nftables NAT
#   5.  Generates client keys with pre-shared keys
#   6.  Writes client config files to /etc/wireguard/clients/
#   7.  Adds clients as [Peer] sections in wg0.conf
#   8.  Sets strict file permissions (600/root:root)
#   9.  Creates nftables include file for WireGuard traffic
#   10. Enables and starts wg-quick@wg0
#   11. Displays QR codes for each client config
#   12. Prints a summary with config file locations
# =============================================================================

set -euo pipefail
umask 022

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck disable=SC1090,SC1091
source "$SCRIPT_DIR/../lib/nftables.sh"
# shellcheck disable=SC1090,SC1091
source "$SCRIPT_DIR/../lib/validation.sh"

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
WG_PORT=51820
WG_SUBNET="10.0.0.0/24"
CLIENT_NAME="client"
NUM_CLIENTS=1
DNS="9.9.9.9,149.112.112.112"
DNS_EXPLICIT=false
ENDPOINT_OVERRIDE=""
ADD_CLIENT_NAME=""
FORCE=false
WG_DIR="/etc/wireguard"
WG_CONF="$WG_DIR/wg0.conf"
CLIENT_DIR="$WG_DIR/clients"
NFTABLES_DIR="/etc/nftables.d"
LOGFILE=""

# --- Usage ---
usage() {
    cat <<EOF
Usage: sudo $0 [options]

Options:
  -p PORT            WireGuard listen port (default: $WG_PORT)
  -s SUBNET          VPN subnet in CIDR notation (default: $WG_SUBNET)
  -c CLIENT_NAME     Base name for client configs (default: $CLIENT_NAME)
  -n NUM_CLIENTS     Number of client configs to generate (default: $NUM_CLIENTS)
  -d DNS             DNS servers for clients (default: $DNS)
  -e ENDPOINT        Public IPv4 or DNS hostname for client Endpoint (overrides auto-detect)
  --add-client NAME  Add a single new client peer to an existing wg0.conf safely
  --force            Back up existing wg0.conf and overwrite existing configs/keys
  -h, --help         Show this help

Examples:
  sudo $0
  sudo $0 -e vpn.example.com -p 443 -n 3 -c laptop
  sudo $0 --add-client tablet
  sudo $0 -s 172.16.0.0/24 -d 1.1.1.1,1.0.0.1
EOF
    exit 0
}

# --- Parse Arguments ---
need_arg() { [[ $# -ge 2 && -n "${2:-}" ]] || err "Option $1 requires a value"; }
while [[ $# -gt 0 ]]; do
    case "$1" in
        -p)           need_arg "$@"; WG_PORT="$2"; shift 2 ;;
        -s)           need_arg "$@"; WG_SUBNET="$2"; shift 2 ;;
        -c)           need_arg "$@"; CLIENT_NAME="$2"; shift 2 ;;
        -n)           need_arg "$@"; NUM_CLIENTS="$2"; shift 2 ;;
        -d)           need_arg "$@"; DNS="$2"; DNS_EXPLICIT=true; shift 2 ;;
        -e)           need_arg "$@"; ENDPOINT_OVERRIDE="$2"; shift 2 ;;
        --add-client) need_arg "$@"; ADD_CLIENT_NAME="$2"; shift 2 ;;
        --force)      FORCE=true; shift ;;
        -h|--help)    usage ;;
        *)            err "Unknown option: $1" ;;
    esac
done

validate_ipv4_addr() {
    local ip="$1" octet
    local -a octets=()
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    IFS=. read -r -a octets <<< "$ip"
    (( ${#octets[@]} == 4 )) || return 1
    for octet in "${octets[@]}"; do
        (( 10#$octet <= 255 )) || return 1
    done
}

validate_ipv6_addr() {
    local ip="$1" left right group
    local -a left_groups=() right_groups=()
    local total=0
    [[ -n "$ip" && "$ip" == *:* && "$ip" =~ ^[0-9A-Fa-f:]+$ ]] || return 1
    [[ "$ip" != *:::* && "$ip" != :[^:]* && "$ip" != *[^:]: ]] || return 1
    if [[ "$ip" == *::* ]]; then
        left=${ip%%::*}
        right=${ip#*::}
        [[ "$right" != *::* ]] || return 1
        if [[ -n "$left" ]]; then
            IFS=: read -r -a left_groups <<< "$left"
            for group in "${left_groups[@]}"; do
                [[ "$group" =~ ^[0-9A-Fa-f]{1,4}$ ]] || return 1
            done
            total=$(( total + ${#left_groups[@]} ))
        fi
        if [[ -n "$right" ]]; then
            IFS=: read -r -a right_groups <<< "$right"
            for group in "${right_groups[@]}"; do
                [[ "$group" =~ ^[0-9A-Fa-f]{1,4}$ ]] || return 1
            done
            total=$(( total + ${#right_groups[@]} ))
        fi
        (( total <= 7 )) || return 1
    else
        IFS=: read -r -a left_groups <<< "$ip"
        (( ${#left_groups[@]} == 8 )) || return 1
        for group in "${left_groups[@]}"; do
            [[ "$group" =~ ^[0-9A-Fa-f]{1,4}$ ]] || return 1
        done
    fi
}

validate_dns_list() {
    local list="$1" entry
    local -a entries=()
    [[ -n "$list" && "$list" != ,* && "$list" != *, && "$list" != *,,* ]] || return 1
    IFS=',' read -r -a entries <<< "$list"
    (( ${#entries[@]} >= 1 )) || return 1
    for entry in "${entries[@]}"; do
        entry="${entry//[[:space:]]/}"
        [[ -n "$entry" ]] || return 1
        if [[ "$entry" == *:* ]]; then
            validate_ipv6_addr "$entry" || return 1
        else
            validate_ipv4_addr "$entry" || return 1
        fi
    done
}

# --- Validate ---
[[ $(id -u) -eq 0 ]] || err "Must be run as root"
[[ "$NUM_CLIENTS" =~ ^[1-9][0-9]*$ ]] || err "NUM_CLIENTS must be a positive integer"
[[ "$WG_PORT" =~ ^[0-9]+$ ]] && (( 10#$WG_PORT >= 1 && 10#$WG_PORT <= 65535 )) || err "PORT must be 1-65535"
[[ "$CLIENT_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$ && "$CLIENT_NAME" != "server" ]] || \
    err "CLIENT_NAME may contain only letters, digits, '_' and '-', and must not be 'server'"
validate_dns_list "$DNS" || err "DNS must be a comma-separated list of valid IPv4/IPv6 addresses: $DNS"
if [[ -n "$ENDPOINT_OVERRIDE" ]]; then
    aal_valid_hostname "$ENDPOINT_OVERRIDE" || err "Invalid endpoint host/IP: $ENDPOINT_OVERRIDE"
fi
if [[ -n "$ADD_CLIENT_NAME" ]]; then
    [[ "$ADD_CLIENT_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$ && "$ADD_CLIENT_NAME" != "server" ]] || \
        err "Invalid --add-client name: $ADD_CLIENT_NAME"
fi

# --- Derive subnet values ---
SUBNET_BASE="${WG_SUBNET%/*}"
SUBNET_PREFIX="${WG_SUBNET#*/}"
[[ "$WG_SUBNET" == */* && "$SUBNET_PREFIX" =~ ^[0-9]+$ ]] || err "Invalid IPv4 CIDR: $WG_SUBNET"
(( 10#$SUBNET_PREFIX >= 8 && 10#$SUBNET_PREFIX <= 30 )) || err "WireGuard subnet prefix must be /8 through /30"

IFS='.' read -r OCT1 OCT2 OCT3 OCT4 <<< "$SUBNET_BASE"
for octet in "$OCT1" "$OCT2" "$OCT3" "$OCT4"; do
    [[ "$octet" =~ ^[0-9]+$ ]] && (( 10#$octet <= 255 )) || err "Invalid IPv4 CIDR: $WG_SUBNET"
done

ipv4_to_int() {
    printf '%u\n' "$(( (10#$1 << 24) | (10#$2 << 16) | (10#$3 << 8) | 10#$4 ))"
}

ipv4_from_int() {
    local value="$1"
    printf '%d.%d.%d.%d\n' \
        "$(( (value >> 24) & 255 ))" "$(( (value >> 16) & 255 ))" \
        "$(( (value >> 8) & 255 ))" "$(( value & 255 ))"
}

SUBNET_INT=$(ipv4_to_int "$OCT1" "$OCT2" "$OCT3" "$OCT4")
HOST_COUNT=$(( 1 << (32 - SUBNET_PREFIX) ))
NETMASK=$(( (0xFFFFFFFF << (32 - SUBNET_PREFIX)) & 0xFFFFFFFF ))
(( (SUBNET_INT & NETMASK) == SUBNET_INT )) || err "$WG_SUBNET is not a network address"

SERVER_IP=$(ipv4_from_int "$(( SUBNET_INT + 1 ))")
SERVER_ADDR="${SERVER_IP}/${SUBNET_PREFIX}"

MAX_CLIENTS=$(( HOST_COUNT - 3 ))
(( NUM_CLIENTS <= MAX_CLIENTS )) || err "Subnet too small for $NUM_CLIENTS clients (max $MAX_CLIENTS)"

# Auto-detect default network interface and public IP (pipefail-safe).
# Error checks run AFTER EXISTING_ENDPOINT_HOST fallback in --add-client mode.
DEFAULT_IF=$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')
DETECTED_IP=""
if [[ -n "$DEFAULT_IF" ]]; then
    DETECTED_IP=$(ip -4 -o addr show dev "$DEFAULT_IF" 2>/dev/null | awk '{ split($4, a, "/"); if (a[1] != "") { print a[1]; exit } }')
fi
if [[ -n "$ENDPOINT_OVERRIDE" ]]; then
    SERVER_PUBLIC_IP="$ENDPOINT_OVERRIDE"
else
    SERVER_PUBLIC_IP="$DETECTED_IP"
fi

# Create a root-only log. Descriptor 3 bypasses tee for credential-bearing QR
# codes so the client private and preshared keys never enter the log file.
install -d -m 0755 /var/log
LOGFILE=$(umask 077; mktemp "/var/log/wireguard-setup-$(date +%Y%m%d-%H%M%S).XXXXXX.log")
chmod 0600 "$LOGFILE"
exec 3>&1
exec > >(tee -a "$LOGFILE") 2>&1

# =============================================================================
# INCREMENTAL PEER ADDITION MODE (--add-client NAME)
# =============================================================================
if [[ -n "$ADD_CLIENT_NAME" ]]; then
    [[ -f "$WG_CONF" && -f "$WG_DIR/server_public.key" ]] || \
        err "Cannot --add-client: $WG_CONF or $WG_DIR/server_public.key not found. Run initial setup first."
    if [[ "$FORCE" != true ]] && [[ -e "$CLIENT_DIR/${ADD_CLIENT_NAME}.conf" || -e "$WG_DIR/${ADD_CLIENT_NAME}_private.key" ]]; then
        err "Client '$ADD_CLIENT_NAME' already exists. Choose a different name or pass --force."
    fi

    EXISTING_ADDR=$(awk -F'=' '/^[[:space:]]*Address[[:space:]]*=/ { gsub(/[[:space:]]/, "", $2); print $2; exit }' "$WG_CONF")
    EXISTING_PORT=$(awk -F'=' '/^[[:space:]]*ListenPort[[:space:]]*=/ { gsub(/[[:space:]]/, "", $2); print $2; exit }' "$WG_CONF")
    [[ "$EXISTING_ADDR" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)/([0-9]+)$ ]] || \
        err "Could not parse IPv4 Address CIDR from $WG_CONF"
    EX_PREFIX="${BASH_REMATCH[5]}"
    (( 10#$EX_PREFIX >= 8 && 10#$EX_PREFIX <= 30 )) || \
        err "WireGuard subnet prefix in $WG_CONF must be /8 through /30 (got /$EX_PREFIX)"
    EX_SERVER_INT=$(ipv4_to_int "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}" "${BASH_REMATCH[4]}")
    EX_MASK=$(( (0xFFFFFFFF << (32 - EX_PREFIX)) & 0xFFFFFFFF ))
    EX_NET_INT=$(( EX_SERVER_INT & EX_MASK ))
    EX_HOST_COUNT=$(( 1 << (32 - EX_PREFIX) ))
    EX_PORT="${EXISTING_PORT:-$WG_PORT}"

    if [[ -z "$ENDPOINT_OVERRIDE" ]]; then
        EXISTING_ENDPOINT_HOST=$(awk -F'=' '/^[[:space:]]*Endpoint[[:space:]]*=/ {
            val = substr($0, index($0, "=") + 1)
            sub(/#.*/, "", val)
            gsub(/[[:space:]]/, "", val)
            sub(/:[0-9]+$/, "", val)
            if (val != "") { print val; exit }
        }' "$CLIENT_DIR"/*.conf 2>/dev/null || true)
        if [[ -n "$EXISTING_ENDPOINT_HOST" ]]; then
            SERVER_PUBLIC_IP="$EXISTING_ENDPOINT_HOST"
        fi
    fi
    [[ -n "$SERVER_PUBLIC_IP" ]] || \
        err "Could not detect server Endpoint IP/hostname; specify -e ENDPOINT"

    if [[ "$DNS_EXPLICIT" == false ]]; then
        EXISTING_DNS=$(awk -F'=' '/^[[:space:]]*DNS[[:space:]]*=/ {
            val = substr($0, index($0, "=") + 1)
            sub(/#.*/, "", val)
            gsub(/[[:space:]]/, "", val)
            if (val != "") { print val; exit }
        }' "$CLIENT_DIR"/*.conf 2>/dev/null || true)
        if [[ -n "$EXISTING_DNS" ]] && validate_dns_list "$EXISTING_DNS"; then
            DNS="$EXISTING_DNS"
        fi
    fi

    # Collect already-allocated IPv4 addresses across all [Peer] blocks in wg0.conf
    # (excluding this client's own [Peer] block when --force is replacing it, while
    # still preserving manually added [Peer] blocks without '# Peer:' comments).
    USED_IPS=$(TARGET_HEADER="# Peer: $ADD_CLIENT_NAME" FORCE_SKIP="$FORCE" awk '
        ENVIRON["FORCE_SKIP"] == "true" && $0 == ENVIRON["TARGET_HEADER"] { skip = 1; next }
        skip == 1 && /^[[:space:]]*\[Peer\][[:space:]]*(#.*)?$/ { skip = 2; next }
        skip && (/^# Peer: / || /^[[:space:]]*\[Interface\][[:space:]]*(#.*)?$/) { skip = 0 }
        skip == 2 && /^[[:space:]]*\[Peer\][[:space:]]*(#.*)?$/ { skip = 0 }
        !skip && /^[[:space:]]*(Address|AllowedIPs)[[:space:]]*=/ {
            line = $0
            sub(/#.*/, "", line)
            sub(/^[^=]*=/, "", line)
            n = split(line, items, /,/)
            for (i = 1; i <= n; i++) {
                item = items[i]
                gsub(/[[:space:]]/, "", item)
                sub(/\/.*/, "", item)
                if (item ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
                    print item
                }
            }
        }
    ' "$WG_CONF")

    NEXT_CLIENT_IP=""
    for (( offset = 2; offset < EX_HOST_COUNT - 1; offset++ )); do
        cand_ip=$(ipv4_from_int "$(( EX_NET_INT + offset ))")
        if ! grep -Fxq "$cand_ip" <<< "$USED_IPS"; then
            NEXT_CLIENT_IP="$cand_ip"
            break
        fi
    done
    [[ -n "$NEXT_CLIENT_IP" ]] || err "No free IPv4 addresses remain in $EXISTING_ADDR"

    WG_BACKUP="${WG_CONF}.bak.$(date +%Y%m%d-%H%M%S)"
    ( umask 077 && cp -a "$WG_CONF" "$WG_BACKUP" )
    chmod 0600 "$WG_BACKUP"
    info "Backed up $WG_CONF to $WG_BACKUP"

    # If --force is replacing an existing peer of the same name, strip only that
    # peer's own [Peer] block (resetting skip on any subsequent [Peer] section).
    if [[ "$FORCE" == true ]]; then
        WG_TMP=$(umask 077; mktemp "$WG_DIR/.wg0.conf.XXXXXX")
        TARGET_HEADER="# Peer: $ADD_CLIENT_NAME" awk '
            $0 == ENVIRON["TARGET_HEADER"] { skip = 1; next }
            skip == 1 && /^[[:space:]]*\[Peer\][[:space:]]*(#.*)?$/ { skip = 2; next }
            skip && (/^# Peer: / || /^[[:space:]]*\[Interface\][[:space:]]*(#.*)?$/) { skip = 0 }
            skip == 2 && /^[[:space:]]*\[Peer\][[:space:]]*(#.*)?$/ { skip = 0 }
            !skip { print }
        ' "$WG_CONF" > "$WG_TMP"
        chmod 0600 "$WG_TMP"
        chown root:root "$WG_TMP"
        mv -f -- "$WG_TMP" "$WG_CONF"
    fi

    install -d -o root -g root -m 0700 "$CLIENT_DIR"
    SERVER_PUBLIC_KEY=$(<"$WG_DIR/server_public.key")
    CLIENT_PRIVATE_KEY=$(wg genkey)
    CLIENT_PUBLIC_KEY=$(printf '%s\n' "$CLIENT_PRIVATE_KEY" | wg pubkey)
    PRESHARED_KEY=$(wg genpsk)
    CLIENT_CONF="$CLIENT_DIR/${ADD_CLIENT_NAME}.conf"

    (
        umask 077
        printf '%s\n' "$CLIENT_PRIVATE_KEY" > "$WG_DIR/${ADD_CLIENT_NAME}_private.key"
        printf '%s\n' "$CLIENT_PUBLIC_KEY"  > "$WG_DIR/${ADD_CLIENT_NAME}_public.key"
        printf '%s\n' "$PRESHARED_KEY"      > "$WG_DIR/${ADD_CLIENT_NAME}_preshared.key"
        cat > "$CLIENT_CONF" <<EOF
# =============================================================================
# WireGuard Client Configuration: $ADD_CLIENT_NAME
# Generated by AwesomeArchLinux/hardening/wireguard/wireguard.sh
# =============================================================================

[Interface]
Address = ${NEXT_CLIENT_IP}/32
PrivateKey = $CLIENT_PRIVATE_KEY
DNS = $DNS

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
PresharedKey = $PRESHARED_KEY
Endpoint = ${SERVER_PUBLIC_IP}:${EX_PORT}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF
        cat >> "$WG_CONF" <<EOF

# Peer: $ADD_CLIENT_NAME
[Peer]
PublicKey = $CLIENT_PUBLIC_KEY
PresharedKey = $PRESHARED_KEY
AllowedIPs = ${NEXT_CLIENT_IP}/32
EOF
    )
    chown root:root "$WG_CONF" "$CLIENT_CONF" \
        "$WG_DIR/${ADD_CLIENT_NAME}_private.key" \
        "$WG_DIR/${ADD_CLIENT_NAME}_public.key" \
        "$WG_DIR/${ADD_CLIENT_NAME}_preshared.key"
    chmod 0600 "$WG_CONF" "$CLIENT_CONF" \
        "$WG_DIR/${ADD_CLIENT_NAME}_private.key" \
        "$WG_DIR/${ADD_CLIENT_NAME}_public.key" \
        "$WG_DIR/${ADD_CLIENT_NAME}_preshared.key"

    if systemctl is-active --quiet wg-quick@wg0 2>/dev/null && command -v wg-quick &>/dev/null; then
        wg syncconf wg0 <(wg-quick strip wg0)
        msg "Synced live wg0 interface without dropping existing peers"
    fi

    if command -v qrencode &>/dev/null; then
        {
            echo
            echo -e "${C_BLUE}--- $ADD_CLIENT_NAME ($NEXT_CLIENT_IP) ---${C_NC}"
            qrencode -t ansiutf8 < "$CLIENT_CONF"
            echo
        } >&3
    fi

    msg "Added WireGuard client '$ADD_CLIENT_NAME' ($NEXT_CLIENT_IP) -> $CLIENT_CONF"
    exit 0
fi

[[ -n "$DEFAULT_IF" ]] || err "Could not detect default IPv4 network interface"
[[ -n "$SERVER_PUBLIC_IP" ]] || err "Could not detect server IPv4 address on $DEFAULT_IF; specify -e ENDPOINT"

# =============================================================================
# PROTECT EXISTING KEYS AND CONFIGS UNLESS --force IS PASSED
# =============================================================================
EXISTING_CONFLICT=false
[[ -f "$WG_CONF" ]] && EXISTING_CONFLICT=true
for i in $(seq 1 "$NUM_CLIENTS"); do
    if (( NUM_CLIENTS == 1 )); then
        CHECK_CNAME="$CLIENT_NAME"
    else
        CHECK_CNAME="${CLIENT_NAME}${i}"
    fi
    if [[ -e "$CLIENT_DIR/${CHECK_CNAME}.conf" || -e "$WG_DIR/${CHECK_CNAME}_private.key" ]]; then
        EXISTING_CONFLICT=true
    fi
done
unset CHECK_CNAME

if [[ "$EXISTING_CONFLICT" == true && "$FORCE" != true ]]; then
    err "Existing WireGuard configuration or client keys found in $WG_DIR. Use --add-client <name> to add a peer safely, or pass --force to back up wg0.conf and regenerate."
fi

info "WireGuard port:    $WG_PORT"
info "VPN subnet:        $WG_SUBNET"
info "Server address:    $SERVER_ADDR"
info "Client endpoint:   ${SERVER_PUBLIC_IP}:${WG_PORT}"
info "Default interface: $DEFAULT_IF"
info "Client base name:  $CLIENT_NAME"
info "Number of clients: $NUM_CLIENTS"
info "DNS servers:       $DNS"
info "Log: $LOGFILE"
if [[ -z "$ENDPOINT_OVERRIDE" && "$SERVER_PUBLIC_IP" =~ ^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.) ]]; then
    warn "Detected private/CGNAT address ($SERVER_PUBLIC_IP) on $DEFAULT_IF; re-run with -e <public-ip-or-dns> if clients connect from the internet."
fi
echo

# =============================================================================
# 1. INSTALL PACKAGES
# =============================================================================

msg "Installing wireguard-tools, qrencode, and nftables..."
pacman -Syu --noconfirm --needed wireguard-tools qrencode nftables

# =============================================================================
# 2. ENABLE IP FORWARDING
# =============================================================================

msg "Enabling IP forwarding..."

install -d -m 0755 /etc/sysctl.d
cat > /etc/sysctl.d/99-wireguard.conf <<'EOF'
# WireGuard VPN — this installer provisions an IPv4-only tunnel.
net.ipv4.ip_forward = 1
EOF
chmod 0644 /etc/sysctl.d/99-wireguard.conf

if [[ -x /usr/lib/systemd/systemd-sysctl ]]; then
    /usr/lib/systemd/systemd-sysctl /etc/sysctl.d/99-wireguard.conf >/dev/null 2>&1 || true
else
    sysctl --ignore --system >/dev/null 2>&1 || true
fi

# Verify
if [[ "$(sysctl -n net.ipv4.ip_forward)" != "1" ]]; then
    err "Failed to enable IPv4 forwarding"
fi
info "IPv4 forwarding: enabled"

# =============================================================================
# 3. GENERATE SERVER KEYS
# =============================================================================

msg "Generating server keys..."

install -d -o root -g root -m 0700 "$WG_DIR"

# Only generate if keys don't already exist
if [[ -f "$WG_DIR/server_private.key" && -f "$WG_DIR/server_public.key" ]]; then
    warn "Server keys already exist, reusing"
else
    (
        umask 077
        wg genkey | tee "$WG_DIR/server_private.key" | wg pubkey > "$WG_DIR/server_public.key"
    )
    chmod 600 "$WG_DIR/server_private.key" "$WG_DIR/server_public.key"
    chown root:root "$WG_DIR/server_private.key" "$WG_DIR/server_public.key"
fi

SERVER_PRIVATE_KEY=$(cat "$WG_DIR/server_private.key")
SERVER_PUBLIC_KEY=$(cat "$WG_DIR/server_public.key")

info "Server public key: $SERVER_PUBLIC_KEY"

# =============================================================================
# 4. CREATE SERVER CONFIG (wg0.conf)
# =============================================================================

msg "Writing server configuration to $WG_CONF..."

if [[ -f "$WG_CONF" ]]; then
    WG_BACKUP="${WG_CONF}.bak.$(date +%Y%m%d-%H%M%S)"
    ( umask 077 && cp -a "$WG_CONF" "$WG_BACKUP" )
    chmod 0600 "$WG_BACKUP"
    info "Backed up existing $WG_CONF to $WG_BACKUP"
fi

(
    umask 077
    cat > "$WG_CONF" <<EOF
# =============================================================================
# WireGuard Server Configuration
# Generated by AwesomeArchLinux/hardening/wireguard/wireguard.sh
# =============================================================================

[Interface]
Address = $SERVER_ADDR
ListenPort = $WG_PORT
PrivateKey = $SERVER_PRIVATE_KEY
SaveConfig = false
EOF
)

chmod 600 "$WG_CONF"
chown root:root "$WG_CONF"

# =============================================================================
# 5–6. GENERATE CLIENT CONFIGS AND ADD PEERS
# =============================================================================

msg "Generating $NUM_CLIENTS client configuration(s)..."

install -d -o root -g root -m 0700 "$CLIENT_DIR"

declare -a CLIENT_CONFIGS=()

for i in $(seq 1 "$NUM_CLIENTS"); do
    if (( NUM_CLIENTS == 1 )); then
        CNAME="$CLIENT_NAME"
    else
        CNAME="${CLIENT_NAME}${i}"
    fi

    # Client IP: server is .1, clients start at .2
    CLIENT_IP=$(ipv4_from_int "$(( SUBNET_INT + 1 + i ))")
    CLIENT_ADDR="${CLIENT_IP}/32"
    CLIENT_CONF="$CLIENT_DIR/${CNAME}.conf"

    if [[ -f "$CLIENT_CONF" ]]; then
        ( umask 077 && cp -a "$CLIENT_CONF" "${CLIENT_CONF}.bak.$(date +%Y%m%d-%H%M%S)" )
    fi

    info "Generating keys for $CNAME ($CLIENT_IP)..."

    # Generate client keys
    CLIENT_PRIVATE_KEY=$(wg genkey)
    CLIENT_PUBLIC_KEY=$(echo "$CLIENT_PRIVATE_KEY" | wg pubkey)

    # Generate pre-shared key for quantum resistance
    PRESHARED_KEY=$(wg genpsk)

    (
        umask 077
        # Save keys
        echo "$CLIENT_PRIVATE_KEY" > "$WG_DIR/${CNAME}_private.key"
        echo "$CLIENT_PUBLIC_KEY"  > "$WG_DIR/${CNAME}_public.key"
        echo "$PRESHARED_KEY"      > "$WG_DIR/${CNAME}_preshared.key"

        # --- Write client config ---
        cat > "$CLIENT_CONF" <<EOF
# =============================================================================
# WireGuard Client Configuration: $CNAME
# Generated by AwesomeArchLinux/hardening/wireguard/wireguard.sh
# =============================================================================

[Interface]
Address = ${CLIENT_IP}/32
PrivateKey = $CLIENT_PRIVATE_KEY
DNS = $DNS

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
PresharedKey = $PRESHARED_KEY
Endpoint = ${SERVER_PUBLIC_IP}:${WG_PORT}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

        # --- Add peer to server config ---
        cat >> "$WG_CONF" <<EOF

# Peer: $CNAME
[Peer]
PublicKey = $CLIENT_PUBLIC_KEY
PresharedKey = $PRESHARED_KEY
AllowedIPs = ${CLIENT_ADDR}
EOF
    )

    chmod 600 "$WG_DIR/${CNAME}_private.key" "$WG_DIR/${CNAME}_public.key" "$WG_DIR/${CNAME}_preshared.key" "$CLIENT_CONF"
    chown root:root "$WG_DIR/${CNAME}_private.key" "$WG_DIR/${CNAME}_public.key" "$WG_DIR/${CNAME}_preshared.key" "$CLIENT_CONF"

    CLIENT_CONFIGS+=("$CLIENT_CONF")

    msg "Client $CNAME configured ($CLIENT_IP)"
done

# =============================================================================
# 7. SET STRICT PERMISSIONS (final pass)
# =============================================================================

msg "Setting strict file permissions..."

chmod 600 "$WG_CONF"
chown root:root "$WG_CONF"
find "$WG_DIR" -name "*.key" -exec chmod 600 {} \;
find "$WG_DIR" -name "*.key" -exec chown root:root {} \;
find "$CLIENT_DIR" -name "*.conf" -exec chmod 600 {} \;
find "$CLIENT_DIR" -name "*.conf" -exec chown root:root {} \;

# =============================================================================
# 8. INTEGRATE WITH THE INSTALLER-OWNED NFTABLES RULESET
# =============================================================================

msg "Integrating WireGuard with nftables..."

WIREGUARD_NFT_BLOCK=$(cat <<EOF
insert rule inet filter input ct state new udp dport $WG_PORT accept comment "awesome-wireguard-input"
insert rule inet filter forward iifname "wg0" accept comment "awesome-wireguard-forward-in"
insert rule inet filter forward oifname "wg0" ct state established,related accept comment "awesome-wireguard-forward-out"

table ip wireguard_nat {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "$DEFAULT_IF" ip saddr $WG_SUBNET masquerade comment "awesome-wireguard-nat"
    }
}
EOF
)

# Older releases asked operators to include this file. Leave it syntactically
# harmless so an existing include cannot recreate the obsolete base chains.
install -d -m 0755 "$NFTABLES_DIR"
cat > "$NFTABLES_DIR/wireguard.conf" <<'EOF'
# WireGuard rules are managed as a marked block in /etc/nftables.conf.
EOF
chown root:root "$NFTABLES_DIR/wireguard.conf"
chmod 644 "$NFTABLES_DIR/wireguard.conf"

aal_nft_persist_block wireguard <<< "$WIREGUARD_NFT_BLOCK"

if ! nft list chain inet filter input &>/dev/null || ! nft list chain inet filter forward &>/dev/null; then
    err "Required nftables chains inet filter input/forward do not exist"
fi

# Remove the two exact tables created by older versions, then replace only this
# script's marked rules and NAT table in the live ruleset.
nft delete table inet wireguard_filter 2>/dev/null || true
nft delete table ip wireguard 2>/dev/null || true
nft delete table ip wireguard_nat 2>/dev/null || true
aal_nft_remove_live_rules inet filter input awesome-wireguard-input
aal_nft_remove_live_rules inet filter forward awesome-wireguard-forward-in
aal_nft_remove_live_rules inet filter forward awesome-wireguard-forward-out
nft insert rule inet filter input ct state new udp dport "$WG_PORT" accept comment "awesome-wireguard-input"
nft insert rule inet filter forward iifname "wg0" accept comment "awesome-wireguard-forward-in"
nft insert rule inet filter forward oifname "wg0" ct state established,related accept comment "awesome-wireguard-forward-out"
nft add table ip wireguard_nat
nft add chain ip wireguard_nat postrouting "{ type nat hook postrouting priority srcnat; policy accept; }"
nft add rule ip wireguard_nat postrouting oifname "$DEFAULT_IF" ip saddr "$WG_SUBNET" masquerade comment "awesome-wireguard-nat"

info "nftables rules are active and persisted in /etc/nftables.conf"

# =============================================================================
# 9. ENABLE AND START WIREGUARD
# =============================================================================

msg "Enabling and starting WireGuard..."

# Stop if already running (ignore errors)
systemctl stop wg-quick@wg0 2>/dev/null || true

systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0

# Verify
if systemctl is-active --quiet wg-quick@wg0; then
    msg "wg-quick@wg0 is active"
else
    err "wg-quick@wg0 failed to start. Check: journalctl -xeu wg-quick@wg0"
fi

info "WireGuard interface status:"
wg show wg0

# =============================================================================
# 10. DISPLAY QR CODES
# =============================================================================

echo
msg "Client QR codes (scan with WireGuard mobile app):"
echo

for conf in "${CLIENT_CONFIGS[@]}"; do
    CNAME=$(basename "$conf" .conf)
    echo -e "${C_BLUE}--- $CNAME ---${C_NC}"
    qrencode -t ansiutf8 < "$conf"
    echo
done >&3

# =============================================================================
# 11. SUMMARY
# =============================================================================

echo
echo -e "${C_GREEN}========================================================================${C_NC}"
echo -e "${C_GREEN} WireGuard VPN server setup complete!${C_NC}"
echo -e "${C_GREEN}========================================================================${C_NC}"
echo
echo -e "${C_BLUE}Server:${C_NC}"
echo "  Interface:      wg0"
echo "  Address:        $SERVER_ADDR"
echo "  Port:           $WG_PORT/udp"
echo "  Public IP:      $SERVER_PUBLIC_IP"
echo "  Public Key:     $SERVER_PUBLIC_KEY"
echo "  Config:         $WG_CONF"
echo
echo -e "${C_BLUE}Network:${C_NC}"
echo "  Subnet:         $WG_SUBNET"
echo "  NAT Interface:  $DEFAULT_IF"
echo "  DNS:            $DNS"
echo
echo -e "${C_BLUE}Client Configs:${C_NC}"
for conf in "${CLIENT_CONFIGS[@]}"; do
    CNAME=$(basename "$conf" .conf)
    echo "  $CNAME:  $conf"
done
echo
echo -e "${C_BLUE}Key Files:${C_NC}         $WG_DIR/*.key"
echo -e "${C_BLUE}nftables Rules:${C_NC}    managed block in /etc/nftables.conf"
echo -e "${C_BLUE}Log:${C_NC}              $LOGFILE"
echo
echo -e "${C_YELLOW}IMPORTANT next steps:${C_NC}"
echo "  1. If behind NAT, forward UDP port $WG_PORT to this server."
echo "  2. Update the Endpoint in client configs if your public IP differs"
echo "     from the detected IP ($SERVER_PUBLIC_IP)."
echo "  3. The nftables rules are already active and persistent."
echo "  4. Transfer client configs securely (QR code, scp, etc.)."
echo "     NEVER send private keys over unencrypted channels."
echo "  5. To add more clients later, run: sudo $0 --add-client <name>"
echo "     (See also: $SCRIPT_DIR/README.md)"
echo
echo -e "${C_GREEN}Done.${C_NC}"
