#!/usr/bin/env bash
#
# Script: firehol.sh
# Description: Installs and configures Firehol firewall with IP sets from Firehol's blocklist-ipsets repo
# Author: @brulliant (enhanced by ChatGPT)
# Usage: sudo ./firehol.sh [-l LEVEL] [-u] [--allow-ssh PORT]
#                          [--allow-http] [--allow-https] [--no-inbound] [-h]

set -euo pipefail
umask 022
IFS=$'\n\t'

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck disable=SC1090,SC1091
source "$SCRIPT_DIR/../lib/aur-review.sh"

# ==============================
# Configuration Defaults
# ==============================
LEVEL=1         # Default FireHOL blocklist level
CRON_SCHEDULE="0 0 * * *"  # daily at midnight
LOGFILE="/var/log/firehol_install.log"
FIREHOL_RUN_TMP="/run/firehol-tmp"
TMPCONF=""
ALLOW_SSH=false
SSH_PORT=""
ALLOW_HTTP=false
ALLOW_HTTPS=false
NO_INBOUND=false

cleanup() {
  if [[ -n "${TMPCONF:-}" ]]; then
    rm -f -- "$TMPCONF"
  fi
}
trap cleanup EXIT

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
Usage: sudo $0 [options]
  -l LEVEL          FireHOL blocklist level: 1, 2, or 3 (default: $LEVEL)
  -u, --update-only Update configuration without building packages
  --allow-ssh PORT  Allow inbound SSH on this explicit TCP port
  --allow-http      Allow inbound HTTP (TCP 80)
  --allow-https     Allow inbound HTTPS (TCP 443)
  --no-inbound      Explicitly allow no inbound services
  -h, --help        Show this help message

Exactly one policy choice is required: at least one --allow-* option, or
--no-inbound. FireHOL is an iptables firewall and this script refuses to run
on top of the installer-owned nftables inet/filter chains.
EOF
}

# ==============================
# Argument Parsing
# ==============================
UPDATE_ONLY=false
while [[ $# -gt 0 ]]; do
  case $1 in
    -l)
      [[ $# -ge 2 && -n $2 && $2 != -* ]] || { echo_err "-l requires a level."; exit 1; }
      LEVEL=$2
      shift 2
      ;;
    -u|--update-only) UPDATE_ONLY=true; shift ;;
    --allow-ssh)
      [[ $# -ge 2 && -n $2 && $2 != -* ]] || { echo_err "--allow-ssh requires a port."; exit 1; }
      ALLOW_SSH=true
      SSH_PORT=$2
      shift 2
      ;;
    --allow-http) ALLOW_HTTP=true; shift ;;
    --allow-https) ALLOW_HTTPS=true; shift ;;
    --no-inbound) NO_INBOUND=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo_err "Unknown option: $1"; usage >&2; exit 1 ;;
  esac
done

# Validate LEVEL is one of the FireHOL blocklist levels (1-3)
if ! [[ "$LEVEL" =~ ^[1-3]$ ]]; then
  echo_err "Invalid -l level '$LEVEL' (must be 1, 2, or 3)."
  exit 1
fi

if $ALLOW_SSH && { [[ ! "$SSH_PORT" =~ ^[0-9]+$ ]] || (( 10#$SSH_PORT < 1 || 10#$SSH_PORT > 65535 )); }; then
  echo_err "SSH port must be between 1 and 65535."
  exit 1
fi
if $NO_INBOUND && { $ALLOW_SSH || $ALLOW_HTTP || $ALLOW_HTTPS; }; then
  echo_err "--no-inbound cannot be combined with --allow-* options."
  exit 1
fi
if ! $NO_INBOUND && ! $ALLOW_SSH && ! $ALLOW_HTTP && ! $ALLOW_HTTPS; then
  echo_err "Choose explicit inbound services or pass --no-inbound."
  exit 1
fi

# Ensure running as root
if [[ ${EUID} -ne 0 ]]; then
  echo_err "This script must be run as root."; exit 1
fi

if { command -v nft &>/dev/null && \
    { nft list chain inet filter input &>/dev/null || nft list chain inet filter forward &>/dev/null; }; } || \
    systemctl is-active --quiet nftables.service 2>/dev/null || \
    systemctl is-enabled --quiet nftables.service 2>/dev/null; then
  echo_err "An nftables ruleset or nftables.service is active or enabled."
  echo_err "FireHOL manages iptables and cannot safely coexist with nftables (which can also wipe FireHOL rules on reboot); disable nftables first."
  exit 1
fi

# Redirect all output to logfile
install -o root -g root -m 0600 /dev/null "$LOGFILE"
exec > >(tee -a "$LOGFILE") 2>&1

# ==============================
# Helper Functions
# ==============================

ensure_firehol_tmp() {
  install -d -o root -g root -m 0700 "$FIREHOL_RUN_TMP"
}

run_firehol() {
  ensure_firehol_tmp
  TMPDIR="$FIREHOL_RUN_TMP" FIREHOL_TMP_DIR="$FIREHOL_RUN_TMP" firehol "$@"
}

install_pkgs() {
  local pkgs=(git base-devel help2man cronie curl unzip iputils iproute2 iptables ipset gawk traceroute procps-ng)
  local pkg_list=""
  printf -v pkg_list '%s ' "${pkgs[@]}"
  echo_msg "Installing dependencies: ${pkg_list% }"
  # Arch does not support refreshing package databases without completing the
  # corresponding full upgrade.
  pacman -Syu --needed --noconfirm "${pkgs[@]}"
}

install_aur_pkg() {
  local pkg=$1
  echo_msg "Reviewing $pkg before AUR installation"
  aal_aur_install_reviewed "$pkg"
}

backup_conf() {
  local src=$1 dst=$2
  if [[ -f "$src" ]]; then
    echo_msg "Backing up $src to $dst (mode 0600)"
    install -o root -g root -m 0600 "$src" "$dst"
  fi
}

write_firehol_conf() {
  local dest=$1 level=$2
  install -d -o root -g root -m 0755 /etc/firehol
  TMPCONF=$(umask 077; mktemp /etc/firehol/.firehol.conf.XXXXXX)
  cat > "$TMPCONF" <<EOF
version 6

# Blocklist ipsets must be created before 'blacklist' can reference them.
# update-ipsets must have downloaded these at least once.
ipv4 ipset create firehol_level${level} hash:net
ipv4 ipset addfile firehol_level${level} /etc/firehol/ipsets/firehol_level${level}.netset

ipv4 ipset create fullbogons hash:net
ipv4 ipset addfile fullbogons /etc/firehol/ipsets/fullbogons.netset

# FireHOL requires blacklists before the first interface or router.
ipv4 blacklist full ipset:firehol_level${level}
ipv4 blacklist full ipset:fullbogons

# Hardened drop-all policy
interface any world
    policy drop
    protection strong
    client all accept
EOF
  if $ALLOW_SSH; then
    if [[ "$SSH_PORT" == 22 ]]; then
      printf '    server ssh accept\n' >> "$TMPCONF"
    else
      printf '    server custom awesome_ssh tcp/%s default accept\n' "$SSH_PORT" >> "$TMPCONF"
    fi
  fi
  if $ALLOW_HTTP; then
    printf '    server http accept\n' >> "$TMPCONF"
  fi
  if $ALLOW_HTTPS; then
    printf '    server https accept\n' >> "$TMPCONF"
  fi
  if ! run_firehol "$TMPCONF" debug >/dev/null; then
    rm -f -- "$TMPCONF"
    TMPCONF=""
    echo_err "Generated FireHOL configuration is invalid; keeping the existing configuration."
    return 1
  fi
  chown root:root "$TMPCONF"
  chmod 0600 "$TMPCONF"
  mv -f -- "$TMPCONF" "$dest"
  TMPCONF=""
}

# Prime the ipsets so firehol.conf can load them on first run.
prime_ipsets() {
  echo_msg "Enabling and fetching FireHOL ipsets (level $LEVEL, fullbogons)"
  ensure_firehol_tmp
  TMPDIR="$FIREHOL_RUN_TMP" FIREHOL_TMP_DIR="$FIREHOL_RUN_TMP" /usr/bin/update-ipsets enable "firehol_level${LEVEL}" fullbogons
  TMPDIR="$FIREHOL_RUN_TMP" FIREHOL_TMP_DIR="$FIREHOL_RUN_TMP" /usr/bin/update-ipsets
}

setup_cron() {
  local cronfile=/etc/cron.d/firehol-ipsets
  echo_msg "Configuring cron job in $cronfile ($CRON_SCHEDULE)"
  install -Dm644 /dev/stdin "$cronfile" <<EOF
SHELL=/usr/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
$CRON_SCHEDULE root install -d -o root -g root -m 0700 $FIREHOL_RUN_TMP && TMPDIR=$FIREHOL_RUN_TMP FIREHOL_TMP_DIR=$FIREHOL_RUN_TMP /usr/bin/update-ipsets && TMPDIR=$FIREHOL_RUN_TMP FIREHOL_TMP_DIR=$FIREHOL_RUN_TMP /usr/bin/firehol condrestart
EOF
  systemctl enable --now cronie
}

enable_firehol_service() {
  echo_msg "Validating, enabling, and starting FireHOL service"
  install -d -o root -g root -m 0755 /etc/systemd/system/firehol.service.d
  install -Dm644 /dev/stdin /etc/systemd/system/firehol.service.d/runtime-tmp.conf <<EOF
[Service]
ExecStartPre=/usr/bin/install -d -o root -g root -m 0700 $FIREHOL_RUN_TMP
Environment=TMPDIR=$FIREHOL_RUN_TMP
Environment=FIREHOL_TMP_DIR=$FIREHOL_RUN_TMP
EOF
  systemctl daemon-reload
  run_firehol debug >/dev/null
  systemctl enable firehol
  systemctl restart firehol
}

# ==============================
# Main Logic
# ==============================
if ! $UPDATE_ONLY; then
  install_pkgs
  install_aur_pkg iprange
  install_aur_pkg firehol
fi

# Validate installation
for bin in firehol update-ipsets; do
  if ! command -v "$bin" &>/dev/null; then
    echo_err "$bin not found. Aborting."
    exit 1
  fi
done

# Backup and write config
install -d -m 0755 /etc/firehol
backup_conf /etc/firehol/firehol.conf "/etc/firehol/firehol.conf.bak.$(date +%F_%H%M%S)"
prime_ipsets
write_firehol_conf /etc/firehol/firehol.conf "$LEVEL"

# Automate updates
setup_cron

enable_firehol_service

echo_msg "FireHOL installation/configuration complete!"
echo_msg "Blocklist level: $LEVEL"
if $NO_INBOUND; then
  echo_msg "Inbound services: none"
else
  inbound_services=()
  if $ALLOW_SSH; then inbound_services+=("ssh/tcp:$SSH_PORT"); fi
  if $ALLOW_HTTP; then inbound_services+=("http/tcp:80"); fi
  if $ALLOW_HTTPS; then inbound_services+=("https/tcp:443"); fi
  printf -v inbound_summary '%s, ' "${inbound_services[@]}"
  echo_msg "Inbound services: ${inbound_summary%, }"
fi
echo_msg "Check status: systemctl status firehol"
echo_msg "Logs: journalctl -xeu firehol.service"
