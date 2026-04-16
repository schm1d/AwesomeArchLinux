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

echo_msg()  { printf "%b %s\n" "${GREEN}[+]${NC}" "$1"; }
echo_info() { printf "%b %s\n" "${BLUE}[*]${NC}" "$1"; }
echo_err()  { printf "%b %s\n" "${RED}[!]${NC}" "$1" >&2; }

# ==============================
# Usage
# ==============================
usage() {
    cat <<EOF
Usage: sudo $0 [-l level] [-u] [-h]
  -l level   FireHOL blocklist level (default: $LEVEL)
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
  case ${opt} in
    l) LEVEL=${OPTARG} ;;
    u) UPDATE_ONLY=true ;;
    h) usage ;;
    :) echo_err "Option -$OPTARG requires an argument."; usage ;;
   \?) echo_err "Invalid option: -$OPTARG"; usage ;;
  esac
done

# Validate LEVEL is one of the FireHOL blocklist levels (1-3)
if ! [[ "$LEVEL" =~ ^[1-3]$ ]]; then
  echo_err "Invalid -l level '$LEVEL' (must be 1, 2, or 3)."
  usage
fi

# Ensure running as root
if [[ ${EUID} -ne 0 ]]; then
  echo_err "This script must be run as root."; exit 1
fi

# Redirect all output to logfile
exec > >(tee -a "$LOGFILE") 2>&1

# ==============================
# Helper Functions
# ==============================

install_pkgs() {
  local pkgs=(wget git base-devel cronie iputils iproute2 jq less)
  echo_msg "Installing dependencies: ${pkgs[*]}"
  pacman -Sy --needed --noconfirm "${pkgs[@]}"
}

# Run makepkg as an unprivileged, throwaway build user.
# $1 = build directory (must already contain PKGBUILD)
_run_makepkg_as_build_user() {
  local builddir=$1
  local build_user="_makepkg"

  if [[ ${EUID} -eq 0 ]]; then
    useradd -r -M -d /var/empty -s /usr/bin/nologin "$build_user" 2>/dev/null || true
    chown -R "$build_user":"$build_user" "$builddir"
    ( cd "$builddir" && sudo -u "$build_user" makepkg -si --noconfirm )
    userdel "$build_user" 2>/dev/null || true
  else
    ( cd "$builddir" && makepkg -si --noconfirm )
  fi
}

install_yay() {
  if command -v yay &>/dev/null; then
    return 0
  fi
  echo_msg "Installing yay AUR helper"
  local tmpdir builddir
  tmpdir=$(mktemp -d)
  builddir="$tmpdir/yay"
  git clone https://aur.archlinux.org/yay.git "$builddir"
  _run_makepkg_as_build_user "$builddir"
  rm -rf "$tmpdir"
}

install_aur_pkg() {
  local pkg=$1
  echo_msg "Installing $pkg from AUR"
  # Build AUR packages via makepkg under a throwaway build user instead of
  # relying on $SUDO_USER (which is unset when the script is run as root).
  local tmpdir builddir
  tmpdir=$(mktemp -d)
  builddir="$tmpdir/$pkg"
  git clone "https://aur.archlinux.org/${pkg}.git" "$builddir"
  _run_makepkg_as_build_user "$builddir"
  rm -rf "$tmpdir"
}

backup_conf() {
  local src=$1 dst=$2
  if [[ -f "$src" ]]; then
    echo_msg "Backing up $src to $dst"
    cp "$src" "$dst"
  fi
}

write_firehol_conf() {
  local dest=$1 level=$2 tmpconf
  tmpconf=$(mktemp)
  cat > "$tmpconf" <<EOF
version 6

# Blocklist ipsets must be created before 'blacklist' can reference them.
# update-ipsets must have downloaded these at least once.
ipv4 ipset create firehol_level${level} hash:net
ipv4 ipset addfile firehol_level${level} /etc/firehol/ipsets/firehol_level${level}.netset

ipv4 ipset create fullbogons hash:net
ipv4 ipset addfile fullbogons /etc/firehol/ipsets/fullbogons.netset

# Hardened drop-all policy
interface any world
    policy drop
    protection strong
    server ssh accept
    server http accept
    server https accept
    client all accept

    # Apply blocklists
    blacklist full ipset:firehol_level${level}
    blacklist full ipset:fullbogons
EOF
  install -Dm600 "$tmpconf" "$dest"
  rm -f "$tmpconf"
}

# Prime the ipsets so firehol.conf can load them on first run.
prime_ipsets() {
  echo_msg "Enabling and fetching FireHOL ipsets (level $LEVEL, fullbogons)"
  /usr/bin/update-ipsets enable "firehol_level${LEVEL}" fullbogons || true
  /usr/bin/update-ipsets
}

setup_cron() {
  local cronfile=/etc/cron.d/firehol-ipsets entry
  entry="$CRON_SCHEDULE root /usr/bin/update-ipsets ; /usr/bin/firehol try"
  echo_msg "Configuring cron job: $entry"
  install -Dm644 /dev/stdin "$cronfile" <<<"$entry"
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
if ! $UPDATE_ONLY; then
  install_pkgs
  install_aur_pkg firehol
  install_aur_pkg update-ipsets
fi

# Validate installation
for bin in firehol update-ipsets; do
  if ! command -v "$bin" &>/dev/null; then
    echo_err "$bin not found. Aborting."
    exit 1
  fi
done

# Backup and write config
mkdir -p /etc/firehol
backup_conf /etc/firehol/firehol.conf "/etc/firehol/firehol.conf.bak.$(date +%F_%H%M%S)"
prime_ipsets
write_firehol_conf /etc/firehol/firehol.conf "$LEVEL"

# Automate updates
setup_cron

enable_firehol_service

echo_msg "FireHOL installation/configuration complete!"
echo_msg "Blocklist level: $LEVEL"
echo_msg "Check status: systemctl status firehol"
echo_msg "Logs: journalctl -xeu firehol.service"
