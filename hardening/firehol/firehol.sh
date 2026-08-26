#!/usr/bin/env bash
#
# Script: firehol.sh
# Description: Installs and configures Firehol firewall with IP sets from Firehol's blocklist-ipsets repo
# Author: @brulliant (enhanced by ChatGPT)
# Usage: sudo ./firehol.sh [-l LEVEL] [-u] [--allow-ssh PORT]
#                          [--allow-http] [--allow-https] [--no-inbound] [-h]

set -euo pipefail
IFS=$'\n\t'

# ==============================
# Configuration Defaults
# ==============================
LEVEL=1         # Default FireHOL blocklist level
CRON_SCHEDULE="0 0 * * *"  # daily at midnight
LOGFILE="/var/log/firehol_install.log"
ALLOW_SSH=false
SSH_PORT=""
ALLOW_HTTP=false
ALLOW_HTTPS=false
NO_INBOUND=false

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

if command -v nft &>/dev/null && \
    { nft list chain inet filter input &>/dev/null || nft list chain inet filter forward &>/dev/null; }; then
  echo_err "The installer-owned nftables inet/filter ruleset is active."
  echo_err "FireHOL manages iptables and cannot safely replace or extend those chains; refusing to stack firewalls."
  exit 1
fi

# Redirect all output to logfile
exec > >(tee -a "$LOGFILE") 2>&1

# ==============================
# Helper Functions
# ==============================

install_pkgs() {
  local pkgs=(git base-devel help2man cronie iputils iproute2 iptables ipset gawk traceroute procps-ng)
  echo_msg "Installing dependencies: ${pkgs[*]}"
  # Arch does not support refreshing package databases without completing the
  # corresponding full upgrade.
  pacman -Syu --needed --noconfirm "${pkgs[@]}"
}

# Run makepkg as an unprivileged, throwaway build user.
# $1 = build directory (must already contain PKGBUILD)
_run_makepkg_as_build_user() {
  local builddir=$1
  local build_user="_makepkg"
  local package_file
  local -a package_files=()

  useradd -r -M -d /var/empty -s /usr/bin/nologin "$build_user" 2>/dev/null || true
  install -d -o "$build_user" -g "$build_user" -m 0700 "$builddir/.home"
  chown -R "$build_user":"$build_user" "$builddir"
  (
    cd "$builddir"
    runuser -u "$build_user" -- env HOME="$builddir/.home" \
      makepkg --cleanbuild --noconfirm
    mapfile -t package_files < <(
      runuser -u "$build_user" -- env HOME="$builddir/.home" makepkg --packagelist
    )
    (( ${#package_files[@]} > 0 )) || { echo_err "makepkg produced no package paths"; exit 1; }
    for package_file in "${package_files[@]}"; do
      [[ "$package_file" == "$builddir"/* && -f "$package_file" ]] || {
        echo_err "Refusing unexpected package path: $package_file"
        exit 1
      }
    done
    pacman -U --needed --noconfirm "${package_files[@]}"
  )
  userdel "$build_user" 2>/dev/null || true
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

# FireHOL requires blacklists before the first interface or router.
blacklist full ipset:firehol_level${level}
blacklist full ipset:fullbogons

# Hardened drop-all policy
interface any world
    policy drop
    protection strong
    client all accept
EOF
  if $ALLOW_SSH; then
    if [[ "$SSH_PORT" == 22 ]]; then
      printf '    server ssh accept\n' >> "$tmpconf"
    else
      printf '    server custom awesome_ssh tcp/%s default accept\n' "$SSH_PORT" >> "$tmpconf"
    fi
  fi
  if $ALLOW_HTTP; then
    printf '    server http accept\n' >> "$tmpconf"
  fi
  if $ALLOW_HTTPS; then
    printf '    server https accept\n' >> "$tmpconf"
  fi
  if ! firehol "$tmpconf" debug >/dev/null; then
    rm -f "$tmpconf"
    echo_err "Generated FireHOL configuration is invalid; keeping the existing configuration."
    return 1
  fi
  install -Dm600 "$tmpconf" "$dest"
  rm -f "$tmpconf"
}

# Prime the ipsets so firehol.conf can load them on first run.
prime_ipsets() {
  echo_msg "Enabling and fetching FireHOL ipsets (level $LEVEL, fullbogons)"
  /usr/bin/update-ipsets enable "firehol_level${LEVEL}" fullbogons
  /usr/bin/update-ipsets
}

setup_cron() {
  local cronfile=/etc/cron.d/firehol-ipsets entry
  entry="$CRON_SCHEDULE root /usr/bin/update-ipsets && /usr/bin/firehol condrestart"
  echo_msg "Configuring cron job: $entry"
  install -Dm644 /dev/stdin "$cronfile" <<<"$entry"
  systemctl enable --now cronie
}

enable_firehol_service() {
  echo_msg "Validating, enabling, and starting FireHOL service"
  firehol debug >/dev/null
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
mkdir -p /etc/firehol
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
