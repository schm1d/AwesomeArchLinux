#!/usr/bin/env bash

# =============================================================================
# Script:      crowdsec.sh
# Description: Installs and configures CrowdSec IDS on Arch Linux with
#              optional nftables firewall bouncer and nginx bouncer.
#
# CrowdSec is a modern, collaborative intrusion detection system that
# analyzes visitor behavior and provides an adapted response to attacks.
# It uses a shared threat intelligence network — when one CrowdSec
# instance detects an attack, all participants benefit from the blocklist.
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
#
# Usage:       sudo ./crowdsec.sh [--with-nginx] [--with-nftables] [-h]
#
# Requirements:
#   - Arch Linux with pacman
#   - Root privileges
#   - yay or paru AUR helper (for AUR packages)
#
# What this script does:
#   1. Installs CrowdSec from AUR via yay/paru
#   2. Configures log acquisition (journalctl, syslog, optionally nginx)
#   3. Installs CrowdSec detection collections (linux, sshd, nginx)
#   4. Optionally installs and configures the nftables firewall bouncer
#   5. Optionally installs and configures the nginx bouncer
#   6. Hardens the CrowdSec systemd service
#   7. Enables and starts CrowdSec
#   8. Prints enrollment instructions and status
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
WITH_NGINX=false
WITH_NFTABLES=false
AUR_HELPER=""
ACQUIS_CONF="/etc/crowdsec/acquis.yaml"
BOUNCER_CONF="/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"
LOGFILE="/var/log/crowdsec-setup-$(date +%Y%m%d-%H%M%S).log"

# --- Usage ---
usage() {
    cat <<EOF
Usage: sudo $0 [options]

Options:
  --with-nginx      Install nginx bouncer and add nginx log acquisition
  --with-nftables   Install nftables firewall bouncer for IP blocking
  -h, --help        Show this help

Examples:
  sudo $0                            # Base install (SSH + system detection)
  sudo $0 --with-nftables            # Add nftables IP blocking
  sudo $0 --with-nginx --with-nftables  # Full stack with nginx
EOF
    exit 0
}

# --- Parse Arguments ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --with-nginx)    WITH_NGINX=true; shift ;;
        --with-nftables) WITH_NFTABLES=true; shift ;;
        -h|--help)       usage ;;
        *)               err "Unknown option: $1. Use -h for help." ;;
    esac
done

# --- Validate ---
[[ $(id -u) -eq 0 ]] || err "Must be run as root"

# Redirect output to logfile as well
exec > >(tee -a "$LOGFILE") 2>&1

info "Log: $LOGFILE"
info "Options: nginx=$WITH_NGINX nftables=$WITH_NFTABLES"

# =============================================================================
# 1. DETECT AUR HELPER
# =============================================================================

detect_aur_helper() {
    if command -v yay &>/dev/null; then
        AUR_HELPER="yay"
    elif command -v paru &>/dev/null; then
        AUR_HELPER="paru"
    else
        err "No AUR helper found. Install yay or paru first:
  git clone https://aur.archlinux.org/yay-bin.git && cd yay-bin && makepkg -si"
    fi
    info "Using AUR helper: $AUR_HELPER"
}

# Install an AUR package as the invoking user (AUR helpers refuse to run as root)
aur_install() {
    local pkg="$1"
    local invoking_user="${SUDO_USER:-}"

    if pacman -Qi "$pkg" &>/dev/null; then
        info "$pkg is already installed"
        return 0
    fi

    if [[ -z "$invoking_user" ]]; then
        err "Cannot determine the invoking user (SUDO_USER not set).
Run this script with: sudo ./crowdsec.sh"
    fi

    msg "Installing $pkg from AUR..."
    sudo -u "$invoking_user" "$AUR_HELPER" -S --noconfirm --needed "$pkg"
}

detect_aur_helper

# =============================================================================
# 2. INSTALL CROWDSEC
# =============================================================================

msg "Installing CrowdSec..."

# CrowdSec is available in AUR as 'crowdsec' and 'crowdsec-firewall-bouncer-nftables'
aur_install "crowdsec"

# Verify installation
if ! command -v cscli &>/dev/null; then
    err "CrowdSec installation failed — cscli not found in PATH"
fi

CROWDSEC_VER=$(cscli version 2>&1 | head -1)
info "CrowdSec version: $CROWDSEC_VER"

# =============================================================================
# 3. CONFIGURE ACQUISITION
# =============================================================================

msg "Configuring log acquisition..."

# Back up existing acquis.yaml if present
if [[ -f "$ACQUIS_CONF" ]]; then
    cp "$ACQUIS_CONF" "${ACQUIS_CONF}.bak.$(date +%Y%m%d-%H%M%S)"
    info "Backed up existing $ACQUIS_CONF"
fi

cat > "$ACQUIS_CONF" <<'EOF'
# =============================================================================
# CrowdSec Acquisition Configuration
# Generated by AwesomeArchLinux/hardening/crowdsec/crowdsec.sh
# =============================================================================

# --- SSH: Monitor sshd via journalctl ---
---
source: journalctl
journalctl_filter:
  - "_SYSTEMD_UNIT=sshd.service"
labels:
  type: syslog

# --- System authentication: Monitor systemd-logind ---
---
source: journalctl
journalctl_filter:
  - "_SYSTEMD_UNIT=systemd-logind.service"
labels:
  type: syslog
EOF

# Add auth.log if it exists (some Arch setups use syslog-ng or rsyslog)
if [[ -f /var/log/auth.log ]]; then
    cat >> "$ACQUIS_CONF" <<'EOF'

# --- System authentication: /var/log/auth.log ---
---
filenames:
  - /var/log/auth.log
labels:
  type: syslog
EOF
    info "Added /var/log/auth.log acquisition"
fi

# Add kernel/audit log monitoring
cat >> "$ACQUIS_CONF" <<'EOF'

# --- Kernel messages (audit, firewall logs) ---
---
source: journalctl
journalctl_filter:
  - "_TRANSPORT=kernel"
labels:
  type: syslog
EOF

# Add nginx acquisition if requested
if [[ "$WITH_NGINX" == true ]]; then
    cat >> "$ACQUIS_CONF" <<'EOF'

# --- nginx: Access and error logs ---
---
filenames:
  - /var/log/nginx/access.log
labels:
  type: nginx

---
filenames:
  - /var/log/nginx/error.log
labels:
  type: nginx
EOF
    info "Added nginx log acquisition"
fi

msg "Acquisition config written to $ACQUIS_CONF"

# =============================================================================
# 4. INSTALL COLLECTIONS
# =============================================================================

msg "Installing CrowdSec detection collections..."

cscli hub update

cscli collections install crowdsecurity/linux
info "Installed collection: crowdsecurity/linux"

cscli collections install crowdsecurity/sshd
info "Installed collection: crowdsecurity/sshd"

if [[ "$WITH_NGINX" == true ]]; then
    cscli collections install crowdsecurity/nginx
    info "Installed collection: crowdsecurity/nginx"
fi

# Install useful parsers and scenarios
cscli parsers install crowdsecurity/whitelists
info "Installed parser: crowdsecurity/whitelists"

# =============================================================================
# 5. NFTABLES BOUNCER (optional)
# =============================================================================

if [[ "$WITH_NFTABLES" == true ]]; then
    msg "Installing nftables firewall bouncer..."

    aur_install "crowdsec-firewall-bouncer-nftables"

    # Back up existing bouncer config
    if [[ -f "$BOUNCER_CONF" ]]; then
        cp "$BOUNCER_CONF" "${BOUNCER_CONF}.bak.$(date +%Y%m%d-%H%M%S)"
        info "Backed up existing $BOUNCER_CONF"
    fi

    # Register the bouncer with CrowdSec and capture the API key
    msg "Registering nftables bouncer with CrowdSec..."
    BOUNCER_KEY=$(cscli bouncers add nftables-bouncer -o raw 2>/dev/null || true)

    if [[ -z "$BOUNCER_KEY" ]]; then
        warn "Bouncer 'nftables-bouncer' may already be registered."
        warn "If you need to re-register, run: cscli bouncers delete nftables-bouncer"
        warn "Then re-run this script."
    else
        info "Bouncer API key: $BOUNCER_KEY"
    fi

    # Write bouncer configuration
    cat > "$BOUNCER_CONF" <<EOF
# =============================================================================
# CrowdSec Firewall Bouncer Configuration (nftables)
# Generated by AwesomeArchLinux/hardening/crowdsec/crowdsec.sh
# =============================================================================

mode: nftables
pid_dir: /var/run/
update_frequency: 10s
daemonize: true
log_mode: file
log_dir: /var/log/
log_level: info
log_compression: true
log_max_size: 100
log_max_backups: 3
log_max_age: 30
api_url: http://localhost:8080/
api_key: ${BOUNCER_KEY:-<INSERT_API_KEY_HERE>}
insecure_skip_verify: false
disable_ipv6: false
deny_action: DROP
deny_log: false
supported_decisions_types:
  - ban
  - captcha
  - throttle

# --- nftables configuration ---
nftables:
  ipv4:
    enabled: true
    set-only: false
    table: crowdsec
    chain: crowdsec-chain
    priority: -10
  ipv6:
    enabled: true
    set-only: false
    table: crowdsec6
    chain: crowdsec6-chain
    priority: -10
EOF

    msg "Bouncer config written to $BOUNCER_CONF"

    # Enable the bouncer service
    systemctl enable crowdsec-firewall-bouncer.service
    info "Enabled crowdsec-firewall-bouncer.service"
fi

# =============================================================================
# 6. NGINX BOUNCER (optional)
# =============================================================================

if [[ "$WITH_NGINX" == true ]]; then
    msg "Installing nginx bouncer..."

    aur_install "crowdsec-nginx-bouncer"

    # Register the nginx bouncer
    msg "Registering nginx bouncer with CrowdSec..."
    NGINX_BOUNCER_KEY=$(cscli bouncers add nginx-bouncer -o raw 2>/dev/null || true)

    if [[ -z "$NGINX_BOUNCER_KEY" ]]; then
        warn "Bouncer 'nginx-bouncer' may already be registered."
        warn "If you need to re-register, run: cscli bouncers delete nginx-bouncer"
    else
        info "Nginx bouncer API key: $NGINX_BOUNCER_KEY"
        info "Add this key to your nginx bouncer configuration."
    fi
fi

# =============================================================================
# 7. HARDEN CROWDSEC SYSTEMD SERVICE
# =============================================================================

msg "Hardening CrowdSec systemd service..."

mkdir -p /etc/systemd/system/crowdsec.service.d/
cat > /etc/systemd/system/crowdsec.service.d/hardening.conf <<'EOF'
[Service]
# --- Filesystem protection ---
ProtectSystem=strict
ReadWritePaths=/var/lib/crowdsec /etc/crowdsec /var/log
ProtectHome=yes
PrivateTmp=yes

# --- Kernel protection ---
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes

# --- Capabilities ---
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

# --- System call filtering ---
SystemCallArchitectures=native
SystemCallFilter=@system-service @network-io
SystemCallErrorNumber=EPERM

# --- Network ---
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

# --- Misc hardening ---
NoNewPrivileges=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
PrivateDevices=yes
DevicePolicy=closed

# --- Resource limits ---
LimitNOFILE=65536
LimitNPROC=4096

# --- Restart policy ---
Restart=on-failure
RestartSec=5s
EOF

systemctl daemon-reload
msg "systemd hardening applied to crowdsec.service"

# =============================================================================
# 8. ENABLE AND START CROWDSEC
# =============================================================================

msg "Enabling and starting CrowdSec..."

systemctl enable crowdsec.service
systemctl restart crowdsec.service

# Wait briefly for service to stabilize
sleep 3

if systemctl is-active --quiet crowdsec.service; then
    msg "CrowdSec is running"
else
    warn "CrowdSec service may not have started correctly. Check: journalctl -u crowdsec"
fi

# Start the nftables bouncer if configured
if [[ "$WITH_NFTABLES" == true ]]; then
    systemctl restart crowdsec-firewall-bouncer.service || warn "Could not start firewall bouncer. Check configuration."
    if systemctl is-active --quiet crowdsec-firewall-bouncer.service; then
        msg "nftables firewall bouncer is running"
    fi
fi

# =============================================================================
# 9. SHOW STATUS
# =============================================================================

msg "CrowdSec status:"

echo
echo -e "${C_BLUE}--- Installed Collections ---${C_NC}"
cscli collections list

echo
echo -e "${C_BLUE}--- Registered Bouncers ---${C_NC}"
cscli bouncers list

echo
echo -e "${C_BLUE}--- Metrics ---${C_NC}"
cscli metrics || true

echo
echo -e "${C_BLUE}--- Recent Alerts ---${C_NC}"
cscli alerts list --limit 10 || true

echo
echo -e "${C_BLUE}--- Active Decisions ---${C_NC}"
cscli decisions list || true

# =============================================================================
# 10. SUMMARY
# =============================================================================

echo
echo -e "${C_GREEN}========================================================================${C_NC}"
echo -e "${C_GREEN} CrowdSec IDS setup complete!${C_NC}"
echo -e "${C_GREEN}========================================================================${C_NC}"
echo
echo -e "${C_BLUE}Components installed:${C_NC}"
echo "  - CrowdSec engine (LAPI + agent)"
echo "  - Collections: linux, sshd$([ "$WITH_NGINX" == true ] && echo ', nginx')"
[ "$WITH_NFTABLES" == true ] && echo "  - nftables firewall bouncer"
[ "$WITH_NGINX" == true ]    && echo "  - nginx bouncer"
echo
echo -e "${C_BLUE}Configuration files:${C_NC}"
echo "  Acquisition:    $ACQUIS_CONF"
echo "  Main config:    /etc/crowdsec/config.yaml"
[ "$WITH_NFTABLES" == true ] && echo "  Bouncer config:  $BOUNCER_CONF"
echo "  systemd drop-in: /etc/systemd/system/crowdsec.service.d/hardening.conf"
echo "  Log:            $LOGFILE"
echo
echo -e "${C_BLUE}Useful commands:${C_NC}"
echo "  cscli metrics                    # View parsing/detection metrics"
echo "  cscli alerts list                # View recent alerts"
echo "  cscli decisions list             # View active IP bans"
echo "  cscli decisions add -i X.X.X.X   # Manually ban an IP"
echo "  cscli decisions delete -i X.X.X.X # Unban an IP"
echo "  cscli hub update && cscli hub upgrade # Update all hub content"
echo "  cscli bouncers list              # List registered bouncers"
echo "  journalctl -u crowdsec -f        # Follow CrowdSec logs"
echo
echo -e "${C_YELLOW}OPTIONAL: Enroll in CrowdSec Console (free)${C_NC}"
echo "  The CrowdSec Console provides a web dashboard for monitoring"
echo "  alerts, managing blocklists, and contributing to the community."
echo
echo "  1. Create an account at: https://app.crowdsec.net/"
echo "  2. Get your enrollment key from the console dashboard"
echo "  3. Run: sudo cscli console enroll <YOUR_ENROLLMENT_KEY>"
echo "  4. Approve the enrollment in the web console"
echo
echo -e "${C_YELLOW}RECOMMENDED: Subscribe to community blocklists${C_NC}"
echo "  After enrolling in the console, enable the community blocklist"
echo "  to benefit from shared threat intelligence across all CrowdSec users."
echo
echo -e "${C_GREEN}Done.${C_NC}"
