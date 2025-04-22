#!/usr/bin/env bash
#
# Script: firehol.sh
# Description: Installs and configures Firehol firewall with IP sets from Firehol's blocklist-ipsets repo
# Author: @brulliant (enhanced by ChatGPT)
# Usage: sudo ./firehol.sh [-l LEVEL] [-u] [-h]

set -euo pipefail
IFS=$'\n\t'

# ==============================
# Configuration Defaults
# ==============================
LEVEL=1         # Default FireHOL blocklist level
CRON_SCHEDULE="0 0 * * *"  # daily at midnight
LOGFILE="/var/log/firehol_install.log"

# ==============================
# Color Codes
# ==============================
declare -r BLUE="\033[1;34m"
declare -r RED="\033[1;31m"
declare -r GREEN="\033[1;32m"
declare -r NC="\033[0m"

echo_msg()  { printf "%b %s\n" "${GREEN}[+]${NC}" "\$1"; }
echo_err()  { printf "%b %s\n" "${RED}[!]${NC}" "\$1" >&2; }

# ==============================
# Usage
# ==============================
usage() {
    cat <<EOF
Usage: sudo \$0 [-l level] [-u] [-h]
  -l level   FireHOL blocklist level (default: \$LEVEL)
  -u         Update existing installation only
  -h         Show this help message
EOF
    exit 1
}

# ==============================
# Argument Parsing
# ==============================
UPDATE_ONLY=false
while getopts ":l:uh" opt; do
  case \${opt} in
    l) LEVEL=\${OPTARG} ;;    
    u) UPDATE_ONLY=true ;;    
    h) usage ;;              
    :) echo_err "Option -\$OPTARG requires an argument."; usage ;;  
   \?) echo_err "Invalid option: -\$OPTARG"; usage ;;  
  esac
done

# Ensure running as root
if [[ \${EUID} -ne 0 ]]; then
  echo_err "This script must be run as root."; exit 1
fi

# Redirect all output to logfile
exec > >(tee -a "\$LOGFILE") 2>&1

# ==============================
# Helper Functions
# ==============================

install_pkgs() {
  local pkgs=(wget git cronie iputils iproute2 jq less)
  echo_msg "Installing dependencies: \${pkgs[*]}"
  pacman -Syu --noconfirm "\${pkgs[@]}"
}

install_yay() {
  if ! command -v yay &>/dev/null; then
    echo_msg "Installing yay AUR helper"
    local tmpdir
    tmpdir=$(mktemp -d)
    git clone https://aur.archlinux.org/yay.git "\$tmpdir" \
      && pushd "\$tmpdir" \
      && makepkg -si --noconfirm \
      && popd \
      && rm -rf "\$tmpdir"
  fi
}

install_aur_pkg() {
  local pkg=\$1
  echo_msg "Installing \$pkg from AUR"
  sudo -u "\$SUDO_USER" yay -S --noconfirm "\$pkg"
}

backup_conf() {
  local src=\$1 dst=\$2
  if [[ -f "\$src" ]]; then
    echo_msg "Backing up \$src to \$dst"
    cp "\$src" ‘‘\$dst"
  fi
}

write_firehol_conf() {
  local dest=\$1 level=\$2 tmpconf
  tmpconf=\$(mktemp)
  cat > "\$tmpconf" <<EOF
version 6

# Hardened drop-all policy
interface any world
    policy drop
    protection strong
    server ssh accept
    server http accept
    server https accept
    client all accept

# Blocklists: firehol_level\$level
blacklist fullbogons ipset:firehol_level\$level
EOF
  install -Dm600 "\$tmpconf" "\$dest"
  rm -f "\$tmpconf"
}

setup_cron() {
  local cronfile=/etc/cron.d/firehol-ipsets entry
  entry="\$CRON_SCHEDULE root /usr/bin/update-ipsets && /usr/bin/firehol try"
  echo_msg "Configuring cron job: \$entry"
  echo "\$entry" > /tmp/firehol-ipsets
  install -Dm644 /tmp/firehol-ipsets "\$cronfile"
  systemctl enable --now cronie
}

enable_firehol_service() {
  echo_msg "Enabling and starting FireHOL service"
  systemctl enable firehol
  systemctl restart firehol
}

# ==============================
# Main Logic
# ==============================
if ! \$UPDATE_ONLY; then
  install_pkgs
  install_yay
  install_aur_pkg firehol
  install_aur_pkg update-ipsets
fi

# Validate installation
for bin in firehol update-ipsets; do
  if ! command -v "\$bin" &>/dev/null; then
    echo_err "\$bin not found. Aborting."
    exit 1
  fi
done

# Backup and write config
mkdir -p /etc/firehol
backup_conf /etc/firehol/firehol.conf /etc/firehol/firehol.conf.bak.\$(date +%F_%H%M%S)
write_firehol_conf /etc/firehol/firehol.conf \$LEVEL

# Automate updates
setup_cron

enable_firehol_service

echo_msg "FireHOL installation/configuration complete!"
echo_msg "Blocklist level: \$LEVEL"
echo_msg "Check status: systemctl status firehol"
echo_msg "Logs: journalctl -xeu firehol.service"
