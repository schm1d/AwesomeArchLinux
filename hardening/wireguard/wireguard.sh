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
#                                  [-n NUM_CLIENTS] [-d DNS] [-h]
#
# Requirements:
#   - Arch Linux with pacman
#   - Root privileges
#   - A public-facing IP (or NAT with port forwarding)
#
# What this script does:
#   1.  Installs wireguard-tools and qrencode
#   2.  Enables IPv4/IPv6 forwarding via sysctl
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
WG_PORT=51820
WG_SUBNET="10.0.0.0/24"
CLIENT_NAME="client"
NUM_CLIENTS=1
DNS="9.9.9.9,149.112.112.112"
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
  -p PORT          WireGuard listen port (default: $WG_PORT)
  -s SUBNET        VPN subnet in CIDR notation (default: $WG_SUBNET)
  -c CLIENT_NAME   Base name for client configs (default: $CLIENT_NAME)
  -n NUM_CLIENTS   Number of client configs to generate (default: $NUM_CLIENTS)
  -d DNS           DNS servers for clients (default: $DNS)
  -h               Show this help

Examples:
  sudo $0
  sudo $0 -p 443 -n 3 -c laptop
  sudo $0 -s 172.16.0.0/24 -d 1.1.1.1,1.0.0.1
EOF
    exit 0
}

# --- Parse Arguments ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        -p) WG_PORT="${2:-}"; [[ -n "$WG_PORT" ]] || err "-p requires a port"; shift 2 ;;
        -s) WG_SUBNET="${2:-}"; [[ -n "$WG_SUBNET" ]] || err "-s requires a subnet"; shift 2 ;;
        -c) CLIENT_NAME="${2:-}"; [[ -n "$CLIENT_NAME" ]] || err "-c requires a client name"; shift 2 ;;
        -n) NUM_CLIENTS="${2:-}"; [[ -n "$NUM_CLIENTS" ]] || err "-n requires a count"; shift 2 ;;
        -d) DNS="${2:-}"; [[ -n "$DNS" ]] || err "-d requires a server list"; shift 2 ;;
        -h|--help) usage ;;
        *)  err "Unknown option: $1" ;;
    esac
done

# --- Validate ---
[[ $(id -u) -eq 0 ]] || err "Must be run as root"
[[ "$NUM_CLIENTS" =~ ^[1-9][0-9]*$ ]] || err "NUM_CLIENTS must be a positive integer"
[[ "$WG_PORT" =~ ^[0-9]+$ ]] && (( WG_PORT >= 1 && WG_PORT <= 65535 )) || err "PORT must be 1-65535"
[[ "$CLIENT_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$ ]] || err "CLIENT_NAME may contain only letters, digits, '_' and '-'"
[[ "$DNS" =~ ^[A-Fa-f0-9:.,]+$ ]] || err "DNS must be a comma-separated IP address list"

# --- Derive subnet values ---
SUBNET_BASE="${WG_SUBNET%/*}"
SUBNET_PREFIX="${WG_SUBNET#*/}"
[[ "$WG_SUBNET" == */* && "$SUBNET_PREFIX" =~ ^[0-9]+$ ]] || err "Invalid IPv4 CIDR: $WG_SUBNET"
(( SUBNET_PREFIX >= 1 && SUBNET_PREFIX <= 30 )) || err "WireGuard subnet prefix must be /1 through /30"

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

# Auto-detect default network interface and public IP
DEFAULT_IF=$(ip -4 route show default | awk '{print $5; exit}')
[[ -n "$DEFAULT_IF" ]] || err "Could not detect default network interface"

SERVER_PUBLIC_IP=$(ip -4 addr show "$DEFAULT_IF" | grep -oP 'inet \K[\d.]+' | head -1)
[[ -n "$SERVER_PUBLIC_IP" ]] || err "Could not detect server public IP"

# Create a root-only log. Descriptor 3 bypasses tee for credential-bearing QR
# codes so the client private and preshared keys never enter the log file.
umask 077
LOGFILE=$(mktemp "/var/log/wireguard-setup-$(date +%Y%m%d-%H%M%S).XXXXXX.log")
chmod 0600 "$LOGFILE"
exec 3>&1
exec > >(tee -a "$LOGFILE") 2>&1

info "WireGuard port:    $WG_PORT"
info "VPN subnet:        $WG_SUBNET"
info "Server address:    $SERVER_ADDR"
info "Server public IP:  $SERVER_PUBLIC_IP"
info "Default interface: $DEFAULT_IF"
info "Client base name:  $CLIENT_NAME"
info "Number of clients: $NUM_CLIENTS"
info "DNS servers:       $DNS"
info "Log: $LOGFILE"
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

cat > /etc/sysctl.d/99-wireguard.conf <<'EOF'
# WireGuard VPN — this installer provisions an IPv4-only tunnel.
net.ipv4.ip_forward = 1
EOF

sysctl --system > /dev/null 2>&1

# Verify
if [[ "$(sysctl -n net.ipv4.ip_forward)" != "1" ]]; then
    err "Failed to enable IPv4 forwarding"
fi
info "IPv4 forwarding: enabled"

# =============================================================================
# 3. GENERATE SERVER KEYS
# =============================================================================

msg "Generating server keys..."

mkdir -p "$WG_DIR"
chmod 700 "$WG_DIR"

# Only generate if keys don't already exist
if [[ -f "$WG_DIR/server_private.key" ]]; then
    warn "Server keys already exist, reusing"
else
    wg genkey | tee "$WG_DIR/server_private.key" | wg pubkey > "$WG_DIR/server_public.key"
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

chmod 600 "$WG_CONF"
chown root:root "$WG_CONF"

# =============================================================================
# 5–6. GENERATE CLIENT CONFIGS AND ADD PEERS
# =============================================================================

msg "Generating $NUM_CLIENTS client configuration(s)..."

mkdir -p "$CLIENT_DIR"
chmod 700 "$CLIENT_DIR"

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

    info "Generating keys for $CNAME ($CLIENT_IP)..."

    # Generate client keys
    CLIENT_PRIVATE_KEY=$(wg genkey)
    CLIENT_PUBLIC_KEY=$(echo "$CLIENT_PRIVATE_KEY" | wg pubkey)

    # Generate pre-shared key for quantum resistance
    PRESHARED_KEY=$(wg genpsk)

    # Save keys
    echo "$CLIENT_PRIVATE_KEY" > "$WG_DIR/${CNAME}_private.key"
    echo "$CLIENT_PUBLIC_KEY"  > "$WG_DIR/${CNAME}_public.key"
    echo "$PRESHARED_KEY"      > "$WG_DIR/${CNAME}_preshared.key"

    chmod 600 "$WG_DIR/${CNAME}_private.key" "$WG_DIR/${CNAME}_public.key" "$WG_DIR/${CNAME}_preshared.key"
    chown root:root "$WG_DIR/${CNAME}_private.key" "$WG_DIR/${CNAME}_public.key" "$WG_DIR/${CNAME}_preshared.key"

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

    chmod 600 "$CLIENT_CONF"
    chown root:root "$CLIENT_CONF"

    CLIENT_CONFIGS+=("$CLIENT_CONF")

    # --- Add peer to server config ---
    cat >> "$WG_CONF" <<EOF

# Peer: $CNAME
[Peer]
PublicKey = $CLIENT_PUBLIC_KEY
PresharedKey = $PRESHARED_KEY
AllowedIPs = ${CLIENT_ADDR}
EOF

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
mkdir -p "$NFTABLES_DIR"
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
echo "  5. To add more clients later, see: $WG_DIR/clients/README"
echo
echo -e "${C_GREEN}Done.${C_NC}"
