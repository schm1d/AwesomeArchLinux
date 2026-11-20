#!/usr/bin/env bash

# Description: VPS chroot script for Arch Linux installation.
# Adapted from chroot.sh — removes physical security (USBGuard, Bluetooth, GPU,
# GRUB encryption TPM), fixes duplicate sections and bugs from the original.
#
# Author: Bruno Schmid @brulliant
# LinkedIn: https://www.linkedin.com/in/schmidbruno/

set -euo pipefail
umask 022
source /root/.install-env || { echo "Failed to source /root/.install-env"; exit 1; }

# Set up the variables
BBlue='\033[1;34m'
# shellcheck disable=SC2034  # Color palette — available for error messages
BRed='\033[1;31m'
BGreen='\033[1;32m'
# shellcheck disable=SC2034
BYellow='\033[1;33m'
NC='\033[0m'

# Ensure the script is run as root
if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root" >&2
  exit 1
fi

# --- Variables from installer (accept both INSTALL_* and _INSTALL_*) ---
DISK="${INSTALL_DISK:-${_INSTALL_DISK:-}}"
USERNAME="${INSTALL_USER:-${_INSTALL_USER:-}}"
HOSTNAME="${INSTALL_HOST:-${_INSTALL_HOST:-}}"
: "${DISK:?Missing INSTALL_DISK/_INSTALL_DISK}"
: "${USERNAME:?Missing INSTALL_USER/_INSTALL_USER}"
: "${HOSTNAME:?Missing INSTALL_HOST/_INSTALL_HOST}"
SSH_PORT="${INSTALL_SSH_PORT:-${_INSTALL_SSH_PORT:-22}}"
SSH_PUBKEY="${INSTALL_SSH_PUBKEY:-${_INSTALL_SSH_PUBKEY:-}}"
ALLOW_NO_SSH_KEY="${INSTALL_ALLOW_NO_SSH_KEY:-${_INSTALL_ALLOW_NO_SSH_KEY:-false}}"
INSTALL_TYPE_VAL="${INSTALL_TYPE:-${_INSTALL_TYPE:-vps}}"
if [[ "$INSTALL_TYPE_VAL" == "vps-harden" ]]; then
    # A live server keeps its timezone, locale and keymap. They are only
    # changed when the caller passes a value explicitly.
    TIMEZONE="${INSTALL_TIMEZONE:-${_INSTALL_TIMEZONE:-}}"
    LOCALE="${INSTALL_LOCALE:-${_INSTALL_LOCALE:-}}"
    KEYMAP="${INSTALL_KEYMAP:-${_INSTALL_KEYMAP:-}}"
else
    TIMEZONE="${INSTALL_TIMEZONE:-${_INSTALL_TIMEZONE:-UTC}}"
    LOCALE="${INSTALL_LOCALE:-${_INSTALL_LOCALE:-en_US.UTF-8}}"
    KEYMAP="${INSTALL_KEYMAP:-${_INSTALL_KEYMAP:-us}}"
fi
SYSCTL_PROFILE="${INSTALL_SYSCTL_PROFILE:-${_INSTALL_SYSCTL_PROFILE:-workstation}}"
SYSCTL_DISABLE_IPV6="${INSTALL_DISABLE_IPV6:-${_INSTALL_DISABLE_IPV6:-false}}"

case "$SYSCTL_DISABLE_IPV6" in
    true|false) ;;
    *)
        echo "Invalid IPv6 policy value: $SYSCTL_DISABLE_IPV6" >&2
        exit 1
        ;;
esac

# shellcheck source=lib/chroot-security.sh
source /usr/local/lib/awesomearchlinux/chroot-security.sh

# --- Other Variables ---
# An account that already exists (live systems) keeps its real home directory
# and primary group: neither /home/<name> nor a group named after the user can
# be assumed there.
USER_HOME="/home/$USERNAME"
USER_GROUP="$USERNAME"
# Prints the passwd database entry of the administrator account, if it exists.
user_account_entry() {
    getent passwd -- "$USERNAME"
}
if USER_PASSWD_ENTRY=$(user_account_entry); then
    USER_UID=$(cut -d: -f3 <<< "$USER_PASSWD_ENTRY")
    if (( USER_UID < 1000 || USER_UID == 65534 )); then
        echo -e "${BRed}ERROR: '$USERNAME' is a system account (uid $USER_UID); it cannot be used as the administrator account.${NC}" >&2
        exit 1
    fi
    USER_HOME=$(cut -d: -f6 <<< "$USER_PASSWD_ENTRY")
    USER_GROUP=$(id -gn "$USERNAME")
    if [[ -z "$USER_HOME" || ! -d "$USER_HOME" ]]; then
        echo -e "${BRed}ERROR: the home directory of '$USERNAME' ('$USER_HOME') does not exist.${NC}" >&2
        exit 1
    fi
elif getent group "$USERNAME" >/dev/null; then
    echo -e "${BRed}ERROR: a group named '$USERNAME' already exists, so the user cannot be created. Choose another username.${NC}" >&2
    exit 1
fi

SSH_CONFIG_FILE="$USER_HOME/.ssh/config"
SSH_KEY_TYPE="ed25519"
SSH_KEY_FILE="$USER_HOME/.ssh/id_$SSH_KEY_TYPE"

CPU_VENDOR_ID=$(lscpu | awk -F: '/Vendor ID/{gsub(/^[ \t]+/, "", $2); print $2}')

###############################################################################
# SAFETY CHECKS (before anything is changed)
###############################################################################

NFT_CONF="/etc/nftables.conf"
# Tag of the firewall rules that keep the ports of the running sshd open while
# it is being moved to another port (live systems only).
SSH_TRANSITION_TAG="awesome-ssh-transition"
BACKUP_STAMP="$(date +%Y%m%d-%H%M%S)"

# install    - installer chroot: this script owns every file it writes
# fresh/own/keep - live system, see classify_live_firewall
FIREWALL_MODE="install"
FIREWALL_KEEP_REASONS=()
CURRENT_SSH_PORTS=()
SSH_TRANSITION_PORTS=()
# Ports of services that are reachable now and stay reachable when a firewall
# is installed on a live system that had none (see find_public_listeners).
KEPT_TCP_PORTS=()
KEPT_UDP_PORTS=()
# Extra environment for the ssh.sh call (see the firewall section).
SSH_HARDEN_ENV=()

# Keep a timestamped copy of a file before a live system's version is changed.
backup_before_change() {
    local file="$1" backup
    [[ -e "$file" || -L "$file" ]] || return 0
    backup="${file}.before-awesome.${BACKUP_STAMP}"
    if [[ ! -e "$backup" && ! -L "$backup" ]]; then
        cp -a -- "$file" "$backup"
        echo -e "${BBlue}Backup: $backup${NC}"
    fi
}

# True when the file holds at least one public key that the sshd_config
# written by ssh.sh accepts (its PubkeyAcceptedAlgorithms line; RSA keys below
# 1024 bits are refused by sshd's RequiredRSASize default). A non-empty
# authorized_keys with only plain ECDSA or DSA keys would pass an emptiness
# test and still lock the user out once passwords are disabled. Same test as
# has_accepted_authorized_key in ssh.sh.
authorized_keys_usable() {
    local key_file="$1" listing
    [[ -s "$key_file" ]] || return 1
    listing=$(ssh-keygen -l -f "$key_file" 2>/dev/null || true)
    awk '
        { type = $NF }
        type == "(ED25519)" || type == "(ED25519-SK)" || type == "(ECDSA-SK)" { ok = 1 }
        type == "(RSA)" && $1 + 0 >= 1024 { ok = 1 }
        END { exit ok ? 0 : 1 }
    ' <<< "$listing"
}

# Ports the running sshd listens on, one per line. When no listening sshd is
# found (stopped, or started through a socket unit) the configured ports are
# used instead, unless "live" is passed as the first argument.
sshd_listen_ports() {
    local ports=""
    if command -v ss >/dev/null 2>&1; then
        ports=$(ss -H -tlnp 2>/dev/null |
            awk '/users:\(\("sshd"/ { n = split($4, part, ":"); print part[n] }' | sort -un || true)
    fi
    if [[ -z "$ports" && "${1:-}" != "live" ]] && command -v sshd >/dev/null 2>&1; then
        # sshd -T prints the keyword as "port" or "Port" depending on the version.
        ports=$(sshd -T 2>/dev/null | awk 'tolower($1) == "port" { print $2 }' | sort -un || true)
    fi
    [[ -z "$ports" ]] || printf '%s\n' "$ports"
}

# True when /etc/nftables.conf is a ruleset written by this installer (any
# version): it owns the complete ruleset and carries the installer's SSH
# comment, or (once ssh.sh has moved the SSH rule into its own block) the
# managed blocks of the hardening scripts.
nft_conf_is_installer_owned() {
    [[ -f "$NFT_CONF" ]] || return 1
    grep -Eq '^[[:space:]]*flush[[:space:]]+ruleset([[:space:]]|$)' "$NFT_CONF" &&
        grep -Eq '^([[:space:]]*# Allow SSH with (per-source )?rate limiting|# BEGIN AwesomeArchLinux: )' "$NFT_CONF"
}

# TCP and UDP ports, other than sshd's, on which this host accepts traffic
# from the network right now. Fills KEPT_TCP_PORTS and KEPT_UDP_PORTS.
# Loopback-only sockets are skipped, and so are the link-local client
# protocols that need no inbound rule of their own (DHCP 68, DHCPv6 546,
# mDNS 5353, LLMNR 5355) and UDP sockets that are bound to one address on an
# ephemeral port (the sockets of clients, not of services).
find_public_listeners() {
    local proto port skip ssh_port ephemeral_low=32768 ephemeral_high=60999
    KEPT_TCP_PORTS=()
    KEPT_UDP_PORTS=()
    command -v ss >/dev/null 2>&1 || return 0
    if [[ -r /proc/sys/net/ipv4/ip_local_port_range ]]; then
        read -r ephemeral_low ephemeral_high < /proc/sys/net/ipv4/ip_local_port_range || true
    fi
    while read -r proto port; do
        [[ "$port" =~ ^[0-9]+$ ]] || continue
        if [[ "$proto" == tcp ]]; then
            skip=0
            for ssh_port in "$SSH_PORT" "${CURRENT_SSH_PORTS[@]}"; do
                if [[ "$port" == "$ssh_port" ]]; then
                    skip=1
                fi
            done
            (( skip )) || KEPT_TCP_PORTS+=("$port")
        else
            case "$port" in
                68|546|5353|5355) ;;
                *) KEPT_UDP_PORTS+=("$port") ;;
            esac
        fi
    done < <(
        {
            ss -H -tln 2>/dev/null | sed 's/^/tcp /' || true
            ss -H -uln 2>/dev/null | sed 's/^/udp /' || true
        } | awk -v low="${ephemeral_low:-32768}" -v high="${ephemeral_high:-60999}" '
            {
                local_addr = $5
                n = split(local_addr, part, ":")
                port = part[n]
                addr = substr(local_addr, 1, length(local_addr) - length(port) - 1)
                if (addr ~ /^127\./ || addr ~ /^\[::1\]/ || addr ~ /^\[::ffff:127\./ || addr ~ /%lo$/) next
                wildcard = (addr == "0.0.0.0" || addr == "*" || addr == "[::]")
                if ($1 == "udp" && !wildcard && port + 0 >= low + 0 && port + 0 <= high + 0) next
                print $1, port
            }
        ' | sort -k1,1 -k2,2n -u || true
    )
}

# Decide what may be done to the firewall of a live system:
#   fresh - no firewall is in use: the installer ruleset is installed
#   own   - the installer ruleset of an earlier run: it is updated in place
#   keep  - another firewall is in use (the reasons are collected in
#           FIREWALL_KEEP_REASONS): it is left alone
classify_live_firewall() {
    local unit live_tables foreign_tables package_info iptables_rules conf_state="absent"
    FIREWALL_KEEP_REASONS=()

    # The file shipped by the nftables package counts as "no firewall yet"
    # as long as pacman reports it unmodified.
    if [[ -f "$NFT_CONF" ]]; then
        package_info=$(LC_ALL=C pacman -Qii nftables 2>/dev/null || true)
        if nft_conf_is_installer_owned; then
            conf_state="own"
        elif [[ "$package_info" == *"$NFT_CONF [unmodified]"* ]]; then
            conf_state="stock"
        else
            conf_state="custom"
            FIREWALL_KEEP_REASONS+=("$NFT_CONF holds a ruleset that this installer did not write")
        fi
    fi
    # Loading the installer ruleset starts with "flush ruleset", which would
    # also delete the tables of Docker, libvirt, iptables-nft and the like.
    live_tables=$(nft list tables 2>/dev/null || true)
    foreign_tables=$(grep -Ev '^table inet (filter|f2b-table)$' <<< "$live_tables" | tr '\n' ' ' || true)
    if [[ -n "${foreign_tables// /}" ]]; then
        FIREWALL_KEEP_REASONS+=("other tools have loaded firewall tables: ${foreign_tables% }")
    fi
    if [[ "$conf_state" == "absent" ]] && grep -Fxq 'table inet filter' <<< "$live_tables"; then
        FIREWALL_KEEP_REASONS+=("a firewall table (inet filter) is loaded that does not come from $NFT_CONF")
    fi
    if ! nft list ruleset &>/dev/null && command -v iptables &>/dev/null; then
        iptables_rules=$(iptables -S 2>/dev/null || true)
        if [[ -n "$iptables_rules" ]] &&
           grep -Evq '^-P (INPUT|FORWARD|OUTPUT) ACCEPT$' <<< "$iptables_rules"; then
            FIREWALL_KEEP_REASONS+=("iptables rules are loaded")
        fi
    fi
    for unit in firewalld ufw iptables ip6tables; do
        if systemctl is-active --quiet "$unit.service" 2>/dev/null ||
           systemctl is-enabled --quiet "$unit.service" 2>/dev/null; then
            FIREWALL_KEEP_REASONS+=("$unit.service is active or enabled")
        fi
    done

    if (( ${#FIREWALL_KEEP_REASONS[@]} > 0 )); then
        FIREWALL_MODE="keep"
    elif nft_conf_is_installer_owned; then
        FIREWALL_MODE="own"
    else
        FIREWALL_MODE="fresh"
    fi
}

# Password logins are disabled further down, so stop now if no key that the
# hardened sshd accepts would be in place by then.
if [[ "$ALLOW_NO_SSH_KEY" != "true" ]]; then
    SSH_KEY_PROBE=$(mktemp)
    {
        cat "$USER_HOME/.ssh/authorized_keys" 2>/dev/null || true
        # The existing file may lack a final newline.
        printf '\n%s\n' "$SSH_PUBKEY"
    } > "$SSH_KEY_PROBE"
    if ! authorized_keys_usable "$SSH_KEY_PROBE"; then
        rm -f -- "$SSH_KEY_PROBE"
        echo -e "${BRed}ERROR: no SSH public key that the hardened sshd accepts was provided or found in $USER_HOME/.ssh/authorized_keys.${NC}" >&2
        echo -e "${BRed}Accepted: ssh-ed25519, sk-ssh-ed25519@openssh.com, sk-ecdsa-sha2-nistp256@openssh.com and ssh-rsa.${NC}" >&2
        echo -e "${BRed}Plain ECDSA (ecdsa-sha2-*) and DSA keys are rejected. Stopped before any SSH or firewall setting was changed.${NC}" >&2
        exit 1
    fi
    rm -f -- "$SSH_KEY_PROBE"
fi

if [[ "$INSTALL_TYPE_VAL" == "vps-harden" ]]; then
    echo -e "${BBlue}Checking the live system before changing anything...${NC}"

    # Everything installed below must be downloadable now. A stale sync
    # database (404 from the mirror) would otherwise abort the run halfway.
    mapfile -t MISSING_PACKAGES < <(pacman -T \
        nftables logrotate rng-tools arch-audit pax-utils lynis clamav rkhunter \
        arpwatch chrony sysstat audit fail2ban sudo zsh zsh-completions pambase \
        pam libpwquality nano-syntax-highlighting pacman-contrib 2>/dev/null || true)
    if (( ${#MISSING_PACKAGES[@]} > 0 )); then
        echo -e "${BBlue}Downloading the packages this run installs: ${MISSING_PACKAGES[*]}${NC}"
        if ! pacman -Sw --noconfirm --needed "${MISSING_PACKAGES[@]}"; then
            echo -e "${BRed}ERROR: pacman could not download the required packages. No software hardening has been applied yet.${NC}" >&2
            echo -e "${BRed}The package database is probably out of date: run 'pacman -Syu', reboot if the kernel${NC}" >&2
            echo -e "${BRed}was upgraded, and start again.${NC}" >&2
            exit 1
        fi
    fi
    # nft is needed to look at the firewall that is loaded now. Installing the
    # package changes nothing by itself: its service stays disabled.
    if ! command -v nft &>/dev/null; then
        pacman -S --needed --noconfirm nftables
    fi

    # sshd must stay reachable on the port(s) it uses now until it has really
    # moved, and another firewall must not be replaced behind the admin's back.
    mapfile -t CURRENT_SSH_PORTS < <(sshd_listen_ports)
    for current_port in "${CURRENT_SSH_PORTS[@]}"; do
        if [[ "$current_port" != "$SSH_PORT" ]]; then
            SSH_TRANSITION_PORTS+=("$current_port")
        fi
    done
    if (( ${#CURRENT_SSH_PORTS[@]} > 0 )); then
        echo -e "${BBlue}sshd currently listens on port(s): ${CURRENT_SSH_PORTS[*]}${NC}"
    fi

    classify_live_firewall
    case "$FIREWALL_MODE" in
        keep)
            echo -e "${BYellow}An existing firewall is in use and will be left untouched:${NC}"
            for keep_reason in "${FIREWALL_KEEP_REASONS[@]}"; do
                echo -e "${BYellow}  - $keep_reason${NC}"
            done
            # ssh.sh opens a new port itself in a ruleset the installer owns.
            # In any other firewall nobody would open it.
            if ! nft_conf_is_installer_owned &&
               (( ${#SSH_TRANSITION_PORTS[@]} > 0 && ${#SSH_TRANSITION_PORTS[@]} == ${#CURRENT_SSH_PORTS[@]} )); then
                echo -e "${BRed}ERROR: sshd would be moved from port ${CURRENT_SSH_PORTS[*]} to $SSH_PORT, but this script cannot open${NC}" >&2
                echo -e "${BRed}port $SSH_PORT in a firewall it does not manage. No software hardening has been applied yet.${NC}" >&2
                echo -e "${BRed}Keep the current port (-p ${CURRENT_SSH_PORTS[0]}), or allow tcp/$SSH_PORT in your firewall and move sshd${NC}" >&2
                echo -e "${BRed}afterwards with hardening/ssh/ssh.sh -u $USERNAME -p $SSH_PORT.${NC}" >&2
                exit 1
            fi
            ;;
        own)
            echo -e "${BBlue}Firewall: $NFT_CONF was written by this installer and will be updated in place.${NC}"
            ;;
        fresh)
            echo -e "${BBlue}Firewall: none in use; the default-deny nftables ruleset will be installed.${NC}"
            # A host without packet filtering serves every listening port
            # today. Those ports stay open, so installing the firewall does
            # not take running services offline. Nothing is opened when a
            # default-deny input chain is already loaded.
            if ! nft list chain inet filter input 2>/dev/null | grep -q 'policy drop'; then
                find_public_listeners
                if (( ${#KEPT_TCP_PORTS[@]} + ${#KEPT_UDP_PORTS[@]} > 0 )); then
                    echo -e "${BYellow}Services are listening on this host. Their ports stay open in the new firewall:${NC}"
                    if (( ${#KEPT_TCP_PORTS[@]} > 0 )); then
                        echo -e "${BYellow}  tcp: ${KEPT_TCP_PORTS[*]}${NC}"
                    fi
                    if (( ${#KEPT_UDP_PORTS[@]} > 0 )); then
                        echo -e "${BYellow}  udp: ${KEPT_UDP_PORTS[*]}${NC}"
                    fi
                    echo -e "${BYellow}Remove the ones that should not be reachable from $NFT_CONF afterwards.${NC}"
                fi
            fi
            ;;
    esac
fi

###############################################################################
# BASIC SYSTEM CONFIGURATION
###############################################################################

pacman-key --init
pacman-key --populate archlinux

# Keep dirmngr aligned with the selected IPv6 policy.
mkdir -p /etc/gnupg
{
  if [[ "$SYSCTL_DISABLE_IPV6" == true ]]; then
    printf '%s\n' 'disable-ipv6'
  fi
  printf '%s\n' 'honor-http-proxy'
} > /etc/gnupg/dirmngr.conf

echo -e "${BBlue}Removing unnecessary users and groups...${NC}"
groupdel games 2>/dev/null || true

# --- Timezone & Locale (set once) ---
# On a live system (vps-harden) these values are empty unless the caller set
# them, and the existing timezone, locale and keymap are left as they are.
if [[ -n "$TIMEZONE" ]]; then
    echo -e "${BBlue}Setting timezone to $TIMEZONE...${NC}"
    ln -sf "/usr/share/zoneinfo/$TIMEZONE" /etc/localtime
    echo "$TIMEZONE" > /etc/timezone
    hwclock --systohc --utc || echo -e "${BYellow}Warning: hwclock --systohc failed (RTC unavailable); continuing.${NC}"
else
    echo -e "${BBlue}Keeping the current timezone.${NC}"
fi

if [[ -n "$LOCALE" ]]; then
    echo -e "${BBlue}Setting up locale to $LOCALE...${NC}"
    sed -i -E "s/^#(${LOCALE//./\\.}[[:space:]])/\1/" /etc/locale.gen
    locale-gen
    echo "LANG=$LOCALE" > /etc/locale.conf
    export LANG="$LOCALE"
else
    echo -e "${BBlue}Keeping the current locale.${NC}"
fi

if [[ -n "$KEYMAP" ]]; then
    echo -e "${BBlue}Setting up console keymap and fonts...${NC}"
    cat > /etc/vconsole.conf <<VCEOF
KEYMAP=$KEYMAP
FONT=lat9w-16
FONT_MAP=8859-1_to_uni
VCEOF
else
    echo -e "${BBlue}Keeping the current console keymap.${NC}"
fi

# --- X11 keyboard configuration ---
# Translate vconsole keymap to X11 layout using systemd's kbd-model-map.
vconsole_to_x11() {
    local keymap="$1"
    local layout="" model="" variant="" line
    local map_file="/usr/share/systemd/kbd-model-map"

    if [[ -f "$map_file" ]]; then
        # Columns: consolelayout xlayout xmodel xvariant xoptions.
        # Match the first column (console keymap) exactly.
        line=$(awk -v km="$keymap" '!/^#/ && $1 == km { print; exit }' "$map_file")
        if [[ -n "$line" ]]; then
            layout=$(awk '{print $2}' <<< "$line")
            model=$(awk '{print $3}' <<< "$line")
            variant=$(awk '{print $4}' <<< "$line")
            # kbd-model-map uses "-" for an empty field
            [[ "$layout" == "-" ]] && layout=""
            [[ "$model" == "-" ]] && model=""
            if [[ "$variant" == '""' || "$variant" == "-" ]]; then
                variant=""
            fi
        fi
    fi

    # Fallback heuristics if map lookup failed
    if [[ -z "$layout" ]]; then
        case "$keymap" in
            *_*-*)
                # e.g. de_CH-latin1 -> layout=ch, variant=de
                layout="${keymap#*_}"
                layout="${layout%%-*}"
                layout="${layout,,}"
                variant="${keymap%%_*}"
                ;;
            *-*)
                # e.g. de-latin1 -> layout=de
                layout="${keymap%%-*}"
                variant=""
                ;;
            *)
                layout="$keymap"
                variant=""
                ;;
        esac
    fi

    # Variant last: it is the only field that may be empty.
    echo "$layout" "${model:-pc105}" "$variant"
}

if [[ -n "$KEYMAP" ]]; then
    echo -e "${BBlue}Writing X11 keyboard configuration...${NC}"
    read -r X11_LAYOUT X11_MODEL X11_VARIANT <<< "$(vconsole_to_x11 "$KEYMAP")"
    install -d /etc/X11/xorg.conf.d
    {
        echo 'Section "InputClass"'
        echo '    Identifier "system-keyboard"'
        echo '    MatchIsKeyboard "on"'
        echo "    Option \"XkbLayout\" \"$X11_LAYOUT\""
        echo "    Option \"XkbModel\" \"${X11_MODEL:-pc105}\""
        if [[ -n "$X11_VARIANT" ]]; then
            echo "    Option \"XkbVariant\" \"$X11_VARIANT\""
        fi
        echo '    Option "XkbOptions" ""'
        echo 'EndSection'
    } > /etc/X11/xorg.conf.d/00-keyboard.conf
fi

# --- Hostname ---
echo -e "${BBlue}Setting hostname...${NC}"
hostnamectl set-hostname "$HOSTNAME" 2>/dev/null || true
echo "$HOSTNAME" > /etc/hostname

echo -e "${BBlue}Configuring /etc/hosts...${NC}"
if [[ "$INSTALL_TYPE_VAL" == "vps-harden" && -e /etc/hosts ]]; then
    # Live system: keep the administrator's entries. Only make sure localhost
    # and the hostname itself resolve locally.
    backup_before_change /etc/hosts
    if ! grep -Eq '^127\.0\.0\.1[[:space:]]' /etc/hosts; then
        echo "127.0.0.1       localhost" >> /etc/hosts
    fi
    if ! grep -Eq '^::1[[:space:]]' /etc/hosts; then
        echo "::1             localhost ip6-localhost ip6-loopback" >> /etc/hosts
    fi
    if ! awk -v host="$HOSTNAME" '
            !/^[[:space:]]*#/ { for (i = 2; i <= NF; i++) if ($i == host) found = 1 }
            END { exit found ? 0 : 1 }
        ' /etc/hosts; then
        echo "127.0.1.1       $HOSTNAME.localdomain $HOSTNAME" >> /etc/hosts
    fi
else
cat > /etc/hosts <<EOF
# Static table lookup for hostnames
# IPv4
127.0.0.1       localhost
127.0.1.1       $HOSTNAME.localdomain $HOSTNAME

# IPv6
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters

# Block some tracking domains at host level
0.0.0.0         googleadservices.com
0.0.0.0         google-analytics.com
0.0.0.0         doubleclick.net
0.0.0.0         facebook.com
0.0.0.0         www.facebook.com
EOF
fi

chmod 644 /etc/hosts
chown root:root /etc/hosts

###############################################################################
# NETWORK CONFIGURATION
###############################################################################

echo -e "${BBlue}Configuring network parameters...${NC}"

# The systemd-networkd profile is only written by the installer. On a live
# system the network is already configured, and "20-wired.network" with
# DHCP=yes would sort before (and so replace) a static profile such as
# 50-static.network at the next boot.
if [[ "$INSTALL_TYPE_VAL" != "vps-harden" ]]; then
mkdir -p /etc/systemd/network/

cat > /etc/systemd/network/20-wired.network <<EOF
[Match]
Name=en*
Name=eth*

[Network]
DHCP=yes
DNSSEC=yes
# DNS-over-TLS is enforced by systemd-resolved via the drop-in at
# /etc/systemd/resolved.conf.d/dns-over-tls.conf — leave networkd unset
# so resolved remains the single source of truth for DoT.
DNSOverTLS=no
IPv6PrivacyExtensions=yes

[DHCPv4]
# systemd does not allow a comment after a value on the same line: the whole
# "no  # ..." string is rejected and the setting silently keeps its default.
# Don't accept DNS from DHCP
UseDNS=no
UseDomains=no
# Use our own NTP configuration
UseNTP=no

[DHCPv6]
UseDNS=no
UseNTP=no

[IPv6AcceptRA]
UseDNS=no
DHCPv6Client=no
EOF
else
    echo -e "${BBlue}Keeping the existing network profiles (live system).${NC}"
fi

# Configure NetworkManager with privacy settings (if installed)
if [ -d /etc/NetworkManager ]; then
    echo -e "${BBlue}Configuring NetworkManager privacy...${NC}"
    mkdir -p /etc/NetworkManager/conf.d/
    cat > /etc/NetworkManager/conf.d/00-privacy.conf <<EOF
[main]
systemd-resolved=true

[connection]
# No per-boot connection.stable-id on a server: with \${CONNECTION}/\${BOOT}
# the stable-privacy IPv6 address changes at every reboot, which breaks AAAA
# records and provider-side source filtering. NetworkManager's default
# (derived from the connection UUID) is stable across reboots and still does
# not expose the MAC address.
EOF
fi

###############################################################################
# DNS-OVER-TLS (systemd-resolved native)
###############################################################################

echo -e "${BBlue}Configuring systemd-resolved with native DNS-over-TLS...${NC}"
# Use systemd-resolved's native DoT. Keeping the DNS stack to a single
# daemon avoids the iwd -> dhcpcd -> NetworkManager -> resolved -> Stubby
# handoff drift that was breaking desktop DNS. Stubby can still be
# installed manually as an opt-in for users who specifically want a
# separate DoT forwarder.
mkdir -p /etc/systemd/resolved.conf.d/
# Remove the legacy underscore filename from prior runs so the directory
# stays clean (merged result is identical either way).
rm -f /etc/systemd/resolved.conf.d/dns_over_tls.conf
cat > /etc/systemd/resolved.conf.d/dns-over-tls.conf <<'EOF'
[Resolve]
DNS=1.1.1.1#cloudflare-dns.com 1.0.0.1#cloudflare-dns.com
FallbackDNS=9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net
DNSOverTLS=yes
DNSSEC=allow-downgrade
Cache=yes
Domains=~.
MulticastDNS=no
LLMNR=no
EOF

# Hand DNS off to systemd-resolved when NetworkManager is present so NM
# does not fight resolved over /etc/resolv.conf.
if [ -d /etc/NetworkManager/conf.d ]; then
    cat > /etc/NetworkManager/conf.d/dns.conf <<'EOF'
[main]
dns=systemd-resolved
EOF
fi

echo -e "${BBlue}Enabling systemd-resolved...${NC}"
systemctl daemon-reload 2>/dev/null || true
if [[ "$INSTALL_TYPE_VAL" == "vps-harden" ]]; then
    echo -e "${BBlue}Pointing /etc/resolv.conf at the resolved stub...${NC}"
    chattr -i /etc/resolv.conf 2>/dev/null || true
    # Keep the provider's resolver list in case DNS-over-TLS is blocked.
    if [[ -f /etc/resolv.conf && ! -L /etc/resolv.conf ]]; then
        backup_before_change /etc/resolv.conf
    fi
    rm -f /etc/resolv.conf
    ln -s /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
    systemctl enable --now systemd-resolved
    if systemctl is-active --quiet NetworkManager 2>/dev/null; then
        systemctl restart NetworkManager
    fi
else
    # In chroot, keep the working resolv.conf so pacman and downloads succeed.
    # The symlink to stub-resolv.conf will be placed right before exiting chroot.
    systemctl enable systemd-resolved
fi

# Prefer IPv4 over IPv6 — many VPS providers lack IPv6 routing, and
# sshd is configured with AddressFamily inet (IPv4 only)
echo -e "${BBlue}Configuring IPv4 preference...${NC}"
grep -qxF 'precedence ::ffff:0:0/96 100' /etc/gai.conf 2>/dev/null || echo "precedence ::ffff:0:0/96 100" >> /etc/gai.conf

echo -e "${BBlue}DNS-over-TLS configuration completed!${NC}"

###############################################################################
# FIREWALL (NFTABLES)
###############################################################################

echo -e "${BBlue}Configuring firewall with nftables...${NC}"
pacman -S --needed --noconfirm nftables

# The ruleset is assembled from fragments so that a ruleset written by an
# earlier run can be brought up to date line by line (see
# update_installer_ruleset) instead of being replaced.

# Table level: the sets behind the per-source SSH rate limit.
nft_ssh_set_definitions() {
    cat <<'EOF'
    # Per-source SSH connection tracking for the rate limit below. A plain
    # "limit rate" is ONE bucket shared by every client, so background scan
    # noise on the SSH port would lock the legitimate admin out.
    set ssh_ratelimit4 {
        type ipv4_addr
        flags dynamic
        timeout 2m
        size 65535
    }

    set ssh_ratelimit6 {
        type ipv6_addr
        flags dynamic
        timeout 2m
        size 65535
    }
EOF
}

# Input chain: ICMP, ICMPv6 and the DHCPv6 client.
nft_icmp_rules() {
    cat <<'EOF'
        # Allow ICMP & ICMPv6 (Path MTU Discovery, IPv6 Neighbor Discovery, MLD).
        # "meta l4proto" also matches ICMPv6 behind extension headers, which
        # "ip6 nexthdr" does not; MLD queries must be answered or switches with
        # MLD snooping stop forwarding neighbour-discovery multicast to us.
        meta l4proto icmp icmp type { echo-request, destination-unreachable, time-exceeded } accept
        meta l4proto ipv6-icmp icmpv6 type { echo-request, destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, mld-listener-query, mld-listener-report, mld-listener-done, mld2-listener-report } accept

        # DHCPv6 client: server replies go to a link-local address that
        # conntrack cannot relate to our multicast solicit.
        ip6 saddr fe80::/10 udp sport 547 udp dport 546 accept
EOF
}

# Input chain: SSH on port $1, rate limited per source address. Any further
# argument is a port the running sshd still listens on (live systems only):
# it stays open, tagged, until finish_ssh_port_move removes it again.
nft_ssh_rules() {
    local ssh_port="$1" old_port
    shift
    cat <<EOF
        # Allow SSH with per-source rate limiting (burst allows legitimate reconnects)
        tcp dport ${ssh_port} ct state new add @ssh_ratelimit4 { ip saddr limit rate over 4/minute burst 8 packets } drop
        tcp dport ${ssh_port} ct state new add @ssh_ratelimit6 { ip6 saddr limit rate over 4/minute burst 8 packets } drop
        tcp dport ${ssh_port} ct state new accept
EOF
    for old_port in "$@"; do
        echo "        # ${SSH_TRANSITION_TAG}: sshd still listens on port ${old_port}; removed once it has moved to port ${ssh_port}"
        echo "        tcp dport ${old_port} ct state new accept comment \"${SSH_TRANSITION_TAG}\""
    done
}

# Input chain: the services that were reachable before this host had a
# firewall (live systems only, see find_public_listeners). Prints nothing when
# there are none.
nft_kept_service_rules() {
    local ports
    (( ${#KEPT_TCP_PORTS[@]} + ${#KEPT_UDP_PORTS[@]} > 0 )) || return 0
    cat <<'EOF'
        # Services that were listening when this firewall was installed on the
        # running system. Remove the ports that should not be reachable.
EOF
    if (( ${#KEPT_TCP_PORTS[@]} > 0 )); then
        ports=$(IFS=,; echo "${KEPT_TCP_PORTS[*]}")
        echo "        tcp dport { ${ports//,/, } } accept"
    fi
    if (( ${#KEPT_UDP_PORTS[@]} > 0 )); then
        ports=$(IFS=,; echo "${KEPT_UDP_PORTS[*]}")
        echo "        udp dport { ${ports//,/, } } accept"
    fi
}

# The complete installer-owned ruleset. Arguments as for nft_ssh_rules.
write_nftables_base_ruleset() {
    local input_rules kept_rules
    input_rules="$(nft_icmp_rules)"$'\n\n'"$(nft_ssh_rules "$@")"
    kept_rules=$(nft_kept_service_rules)
    if [[ -n "$kept_rules" ]]; then
        input_rules+=$'\n\n'"$kept_rules"
    fi
    cat <<EOF
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
$(nft_ssh_set_definitions)

    chain input {
        type filter hook input priority filter; policy drop;

        # Allow loopback
        iif lo accept

        # Allow established connections
        ct state established,related accept

        # Drop invalid connections
        ct state invalid drop

${input_rules}

        # Drop everything else
        counter drop
    }

    chain forward {
        type filter hook forward priority filter; policy drop;
    }

    chain output {
        type filter hook output priority filter; policy accept;
    }
}
EOF
}

# Port of the installer's own SSH rule in /etc/nftables.conf, in the old
# shared-bucket "limit rate" form or the per-source form. Empty when ssh.sh
# has moved sshd since and removed that rule in favour of its managed block.
nft_installer_ssh_port() {
    awk '
        /^# BEGIN AwesomeArchLinux: / { managed = 1 }
        /^# END AwesomeArchLinux: /   { managed = 0; next }
        managed { next }
        /^[[:space:]]*tcp dport [0-9]+ ct state new (limit rate 4\/minute burst 8 packets accept|add @ssh_ratelimit4 )/ {
            print $3
            exit
        }
    ' "$NFT_CONF"
}

# Bring an installer ruleset written by an earlier run up to date
# (stdin -> stdout). Only lines this installer wrote are replaced: its SSH
# rule (the old shared-bucket one, or the per-source ones) becomes the
# per-source rules for port $1, the sets they use are added, and the old ICMP
# lines are replaced by the current ones. Rules the administrator added and
# the managed blocks of the hardening scripts pass through byte for byte.
#   $1 SSH port
#   $2 port of the installer's SSH rule in the file ("" when it has none:
#      the SSH rules then live in ssh.sh's managed block and are not touched)
#   $3... ports the running sshd still listens on (see nft_ssh_rules)
update_installer_ruleset() {
    local ssh_port="$1" owned_port="$2" input have_sets=1 upgrade_icmp=0
    local old_icmp4="ip protocol icmp icmp type { echo-request, destination-unreachable, time-exceeded } accept"
    local old_icmp6="ip6 nexthdr icmpv6 icmpv6 type { echo-request, destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept"
    shift 2

    if [[ -n "$owned_port" ]]; then
        # Tagged rules left over from an interrupted port move are dropped;
        # the ones that are needed now are written again with the SSH rules.
        input=$(grep -Fv -- "$SSH_TRANSITION_TAG" || true)
        if ! grep -Eq '^[[:space:]]*set[[:space:]]+ssh_ratelimit4[[:space:]]' <<< "$input"; then
            have_sets=0
        fi
    else
        input=$(cat)
    fi
    if grep -Fq -- "$old_icmp4" <<< "$input" && grep -Fq -- "$old_icmp6" <<< "$input"; then
        upgrade_icmp=1
    fi

    AAL_OWNED_PORT="$owned_port" \
    AAL_HAVE_SETS="$have_sets" AAL_UPGRADE_ICMP="$upgrade_icmp" \
    AAL_OLD_ICMP4="$old_icmp4" AAL_OLD_ICMP6="$old_icmp6" \
    AAL_SETS="$(nft_ssh_set_definitions)" AAL_ICMP="$(nft_icmp_rules)" \
    AAL_SSH="$(nft_ssh_rules "$ssh_port" "$@")" awk '
        BEGIN {
            owned = ENVIRON["AAL_OWNED_PORT"]
            if (owned != "") {
                head = "tcp dport " owned " ct state new "
                ssh_line[head "limit rate 4/minute burst 8 packets accept"] = 1
                ssh_line[head "add @ssh_ratelimit4 { ip saddr limit rate over 4/minute burst 8 packets } drop"] = 1
                ssh_line[head "add @ssh_ratelimit6 { ip6 saddr limit rate over 4/minute burst 8 packets } drop"] = 1
                ssh_line[head "accept"] = 1
            }
        }
        /^# BEGIN AwesomeArchLinux: / { managed = 1 }
        /^# END AwesomeArchLinux: /   { print; managed = 0; next }
        managed                        { print; next }
        {
            trimmed = $0
            sub(/^[[:space:]]+/, "", trimmed)
            sub(/[[:space:]]+$/, "", trimmed)
        }
        ENVIRON["AAL_HAVE_SETS"] == "0" && !sets_done && /^table inet filter \{[[:space:]]*$/ {
            print
            print ENVIRON["AAL_SETS"]
            print ""
            sets_done = 1
            next
        }
        owned != "" && trimmed ~ /^# Allow SSH with (per-source )?rate limiting/ { next }
        (trimmed in ssh_line) {
            if (!ssh_done) {
                print ENVIRON["AAL_SSH"]
                ssh_done = 1
            }
            next
        }
        ENVIRON["AAL_UPGRADE_ICMP"] == "1" &&
            trimmed == "# Allow ICMP & ICMPv6 (Path MTU Discovery & IPv6 Neighbor Discovery)" { next }
        ENVIRON["AAL_UPGRADE_ICMP"] == "1" &&
            (trimmed == ENVIRON["AAL_OLD_ICMP4"] || trimmed == ENVIRON["AAL_OLD_ICMP6"]) {
            if (!icmp_done) {
                print ENVIRON["AAL_ICMP"]
                icmp_done = 1
            }
            next
        }
        { print }
    ' <<< "$input"
}

# Install a candidate ruleset as /etc/nftables.conf after "nft -c" accepted it
# (when nft works on this kernel). The candidate file is consumed.
install_nftables_conf() {
    local candidate="$1"
    if nft list ruleset &>/dev/null && ! nft -c -f "$candidate"; then
        rm -f -- "$candidate"
        echo -e "${BRed}ERROR: the generated nftables ruleset did not validate; $NFT_CONF was not changed.${NC}" >&2
        return 1
    fi
    install -m 0644 -o root -g root "$candidate" "$NFT_CONF"
    rm -f -- "$candidate"
}

NFT_CONF_CHANGED=false
case "$FIREWALL_MODE" in
    install)
        write_nftables_base_ruleset "$SSH_PORT" > "$NFT_CONF"
        ;;
    fresh)
        # No firewall in use: install the complete ruleset. The port(s) sshd
        # listens on now stay open until it has moved.
        backup_before_change "$NFT_CONF"
        NFT_CANDIDATE=$(mktemp /etc/.nftables.conf.XXXXXX)
        write_nftables_base_ruleset "$SSH_PORT" "${SSH_TRANSITION_PORTS[@]}" > "$NFT_CANDIDATE"
        install_nftables_conf "$NFT_CANDIDATE"
        NFT_CONF_CHANGED=true
        ;;
    own)
        # The installer's ruleset from an earlier run: update it in place.
        NFT_CANDIDATE=$(mktemp /etc/.nftables.conf.XXXXXX)
        update_installer_ruleset "$SSH_PORT" "$(nft_installer_ssh_port)" "${SSH_TRANSITION_PORTS[@]}" \
            < "$NFT_CONF" > "$NFT_CANDIDATE"
        if cmp -s -- "$NFT_CANDIDATE" "$NFT_CONF"; then
            rm -f -- "$NFT_CANDIDATE"
            echo -e "${BBlue}$NFT_CONF is already up to date.${NC}"
        else
            backup_before_change "$NFT_CONF"
            if install_nftables_conf "$NFT_CANDIDATE"; then
                NFT_CONF_CHANGED=true
                echo -e "${BBlue}Updated the installer rules in $NFT_CONF; all other rules were kept.${NC}"
            else
                # ssh.sh opens the SSH port itself before it reloads sshd, so
                # the existing ruleset can stay as it is.
                echo -e "${BYellow}WARNING: $NFT_CONF was left as it is; compare it with the current installer ruleset.${NC}"
            fi
        fi
        ;;
    keep)
        # Another firewall is in use (the reasons were printed at the start).
        # Leave a copy of the installer ruleset for the administrator to compare.
        write_nftables_base_ruleset "$SSH_PORT" > /root/nftables.conf.awesome-proposed
        chmod 0600 /root/nftables.conf.awesome-proposed
        echo -e "${BYellow}Existing firewall kept. The ruleset this installer would use is in /root/nftables.conf.awesome-proposed.${NC}"
        ;;
esac

FAIL2BAN_BANACTION="nftables-multiport"

if [[ "$FIREWALL_MODE" == "keep" ]]; then
    if ! nft list ruleset &>/dev/null; then
        FAIL2BAN_BANACTION="iptables-multiport"
    fi
    if ! nft_conf_is_installer_owned; then
        # Point ssh.sh's ruleset path at a file that does not exist, so that it
        # neither writes into a ruleset somebody else maintains nor aborts on
        # one it cannot edit. (The check at the start made sure sshd keeps a
        # port it already uses.)
        SSH_HARDEN_ENV=(AAL_NFT_CONFIG=/run/awesomearchlinux/no-installer-ruleset)
    fi
elif nft list ruleset &>/dev/null; then
    systemctl enable nftables.service
    # Live systems: load the ruleset now. "nft -f" replaces the ruleset in one
    # transaction, so there is no moment without rules. An unchanged ruleset
    # is only loaded when it is not active yet.
    if [[ "$INSTALL_TYPE_VAL" == "vps-harden" ]]; then
        if [[ "$NFT_CONF_CHANGED" == true ]] || ! nft list chain inet filter input &>/dev/null; then
            nft -f "$NFT_CONF"
            # fail2ban keeps its bans in a table of its own, which the reload flushed.
            systemctl try-restart fail2ban.service 2>/dev/null || true
        fi
    fi
    echo -e "${BGreen}Firewall configuration with nftables completed.${NC}"
elif command -v iptables &>/dev/null && iptables -L -n &>/dev/null; then
    # nft backend unavailable but iptables works (legacy kernel module present).
    # Remove /etc/nftables.conf so ssh.sh does not falsely enter its nft branch.
    echo -e "${BYellow}WARNING: nftables kernel module not available — falling back to iptables.${NC}"
    systemctl disable nftables.service 2>/dev/null || true
    rm -f /etc/nftables.conf
    FAIL2BAN_BANACTION="iptables-multiport"

    # Default-deny input policy for one address family ($1 = iptables or
    # ip6tables). SSH is limited per source address with hashlimit; a plain
    # "-m limit" is one bucket shared by every client and lets background
    # scan noise lock the administrator out.
    apply_iptables_fallback() {
        local ipt="$1" icmp_type port

        # Flush existing rules. The default-deny policies are set last, so a
        # running system is never without its accept rules.
        "$ipt" -F
        "$ipt" -X

        # Allow loopback
        "$ipt" -A INPUT -i lo -j ACCEPT

        # Allow established connections
        "$ipt" -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

        # Drop invalid connections
        "$ipt" -A INPUT -m conntrack --ctstate INVALID -j DROP

        if [[ "$ipt" == "ip6tables" ]]; then
            # ICMPv6: errors, ping, neighbour discovery and MLD (130-132, 143)
            for icmp_type in destination-unreachable packet-too-big time-exceeded parameter-problem \
                echo-request router-solicitation router-advertisement \
                neighbour-solicitation neighbour-advertisement 130 131 132 143; do
                "$ipt" -A INPUT -p ipv6-icmp --icmpv6-type "$icmp_type" -j ACCEPT
            done
            # DHCPv6 client replies (link-local, not tracked as related)
            "$ipt" -A INPUT -s fe80::/10 -p udp --sport 547 --dport 546 -j ACCEPT
        else
            # Allow essential ICMP (ping, PMTUD)
            for icmp_type in echo-request destination-unreachable time-exceeded; do
                "$ipt" -A INPUT -p icmp -m icmp --icmp-type "$icmp_type" -j ACCEPT
            done
        fi

        # Allow SSH with per-source rate limiting (matches nftables: 4/min burst 8)
        if ! "$ipt" -A INPUT -p tcp --dport "$SSH_PORT" -m conntrack --ctstate NEW \
            -m hashlimit --hashlimit-name awesome-ssh-base --hashlimit-mode srcip \
            --hashlimit-above 4/minute --hashlimit-burst 8 --hashlimit-htable-expire 120000 -j DROP; then
            echo -e "${BYellow}WARNING: xt_hashlimit is unavailable; SSH port $SSH_PORT is open without a firewall rate limit ($ipt).${NC}"
        fi
        "$ipt" -A INPUT -p tcp --dport "$SSH_PORT" -m conntrack --ctstate NEW -j ACCEPT

        # Live systems: the port(s) of the running sshd stay open until it has
        # moved, and services that were reachable before stay reachable.
        for port in "${SSH_TRANSITION_PORTS[@]}"; do
            "$ipt" -A INPUT -p tcp --dport "$port" -m conntrack --ctstate NEW -j ACCEPT
        done
        for port in "${KEPT_TCP_PORTS[@]}"; do
            "$ipt" -A INPUT -p tcp --dport "$port" -j ACCEPT
        done
        for port in "${KEPT_UDP_PORTS[@]}"; do
            "$ipt" -A INPUT -p udp --dport "$port" -j ACCEPT
        done

        "$ipt" -P INPUT DROP
        "$ipt" -P FORWARD DROP
        "$ipt" -P OUTPUT ACCEPT
    }

    apply_iptables_fallback iptables

    # Persist rules
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/iptables.rules
    systemctl enable iptables.service 2>/dev/null || true

    # IPv6 gets the same policy; leaving ip6tables untouched would expose every
    # service over IPv6.
    if command -v ip6tables &>/dev/null && ip6tables -L -n &>/dev/null; then
        apply_iptables_fallback ip6tables
        ip6tables-save > /etc/iptables/ip6tables.rules
        systemctl enable ip6tables.service 2>/dev/null || true
    elif [[ "$SYSCTL_DISABLE_IPV6" != true ]]; then
        echo -e "${BYellow}WARNING: ip6tables is not functional on this kernel — IPv6 traffic is NOT filtered.${NC}"
        echo -e "${BYellow}Disable IPv6 or add IPv6 rules manually.${NC}"
    fi

    echo -e "${BGreen}Firewall configured with iptables (legacy fallback).${NC}"
else
    echo -e "${BYellow}WARNING: Neither nftables nor iptables is functional on this kernel.${NC}"
    systemctl enable nftables.service
    echo -e "${BYellow}nftables is enabled and will start if the kernel supports it after reboot.${NC}"
    echo -e "${BYellow}You may need to configure firewall rules manually once the system is booted.${NC}"
    # ssh.sh validates every change to the ruleset with nft, which cannot work
    # here: keep it away from the file (see the "keep" case above).
    SSH_HARDEN_ENV=(AAL_NFT_CONFIG=/run/awesomearchlinux/no-installer-ruleset)
fi

# Live systems: called after ssh.sh has reloaded sshd. Once sshd answers on
# $SSH_PORT and has left its previous port(s), the tagged rules that kept
# those ports open are removed from the saved ruleset and from the running one.
finish_ssh_port_move() {
    local listening="" port handle candidate
    [[ "$FIREWALL_MODE" == "fresh" || "$FIREWALL_MODE" == "own" ]] || return 0
    if (( ${#SSH_TRANSITION_PORTS[@]} == 0 )) &&
       ! grep -Fq -- "$SSH_TRANSITION_TAG" "$NFT_CONF" 2>/dev/null; then
        return 0
    fi

    # Only a listener that is really there counts, not the configured port.
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        listening=$(sshd_listen_ports live)
        if grep -Fqx -- "$SSH_PORT" <<< "$listening"; then
            break
        fi
        sleep 1
    done
    if ! grep -Fqx -- "$SSH_PORT" <<< "$listening"; then
        echo -e "${BYellow}WARNING: could not confirm that sshd listens on port $SSH_PORT. The previous SSH port(s) stay open in the firewall.${NC}"
        echo -e "${BYellow}Once SSH works on port $SSH_PORT, delete the lines tagged \"$SSH_TRANSITION_TAG\" from $NFT_CONF and reload it.${NC}"
        return 0
    fi
    for port in "${SSH_TRANSITION_PORTS[@]}"; do
        if grep -Fqx -- "$port" <<< "$listening"; then
            echo -e "${BYellow}WARNING: sshd still listens on port $port; its firewall rule is kept.${NC}"
            return 0
        fi
    done

    if [[ -f "$NFT_CONF" ]] && grep -Fq -- "$SSH_TRANSITION_TAG" "$NFT_CONF"; then
        candidate=$(mktemp /etc/.nftables.conf.XXXXXX)
        grep -Fv -- "$SSH_TRANSITION_TAG" "$NFT_CONF" > "$candidate" || true
        install_nftables_conf "$candidate" || return 0
    fi
    if nft list chain inet filter input &>/dev/null; then
        while IFS= read -r handle; do
            [[ "$handle" =~ ^[0-9]+$ ]] || continue
            nft delete rule inet filter input handle "$handle" 2>/dev/null || true
        done < <(nft -a list chain inet filter input 2>/dev/null |
            AAL_MARKER="comment \"${SSH_TRANSITION_TAG}\"" awk '
                index($0, ENVIRON["AAL_MARKER"]) {
                    for (i = 1; i <= NF; i++) if ($i == "handle") print $(i + 1)
                }
            ' || true)
    elif command -v iptables &>/dev/null && iptables -L -n &>/dev/null; then
        for port in "${SSH_TRANSITION_PORTS[@]}"; do
            iptables -D INPUT -p tcp --dport "$port" -m conntrack --ctstate NEW -j ACCEPT 2>/dev/null || true
            ip6tables -D INPUT -p tcp --dport "$port" -m conntrack --ctstate NEW -j ACCEPT 2>/dev/null || true
        done
        if [[ -f /etc/iptables/iptables.rules ]]; then
            iptables-save > /etc/iptables/iptables.rules
        fi
        if [[ -f /etc/iptables/ip6tables.rules ]]; then
            ip6tables-save > /etc/iptables/ip6tables.rules
        fi
    fi
    echo -e "${BGreen}sshd listens on port $SSH_PORT; the previous SSH port(s) are closed in the firewall again.${NC}"
}

###############################################################################
# LOGGING & ENTROPY
###############################################################################

echo -e "${BBlue}Installing and configuring logrotate...${NC}"
pacman -S --needed --noconfirm logrotate
cat <<EOF > /etc/logrotate.d/custom
/var/log/messages /var/log/secure /var/log/auth.log /var/log/boot.log /var/log/sudo.log /var/log/pacman-updates.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 640 root adm
}
EOF

echo -e "${BBlue}Installing and configuring rng-tools...${NC}"
pacman -S --needed --noconfirm rng-tools
systemctl enable rngd

echo -e "${BBlue}Installing file security utility pax-utils & arch-audit...${NC}"
pacman -S --needed --noconfirm arch-audit pax-utils

echo -e "${BBlue}Installing lynis...${NC}"
pacman -S --needed --noconfirm lynis

###############################################################################
# CLAMAV CONFIGURATION
###############################################################################

echo -e "${BBlue}Installing and configuring ClamAV...${NC}"
pacman -S --needed --noconfirm clamav

echo -e "${BBlue}Configuring ClamAV...${NC}"

install -d -m 0755 /etc/clamav
for clam_cfg in freshclam.conf clamd.conf clamav-milter.conf; do
  if [ ! -f "/etc/clamav/$clam_cfg" ]; then
    clamconf -g "$clam_cfg" | sed 's/^Example/#Example/' > "/etc/clamav/$clam_cfg"
  else
    sed -i 's/^Example/#Example/' "/etc/clamav/$clam_cfg"
  fi
done

CLAMD_CONF="/etc/clamav/clamd.conf"

ensure_clamd_option() {
  local KEY="$1"
  local VALUE="$2"
  # If the key exists, replace it; otherwise, append it. The option name is
  # matched as a whole word: a bare prefix match let "Bytecode" overwrite the
  # BytecodeSecurity/BytecodeTimeout lines and "AlertEncrypted" the
  # AlertEncryptedArchive/AlertEncryptedDoc ones.
  if grep -Eq "^#?\s*${KEY}(\s|\$)" "$CLAMD_CONF"; then
    sed -Ei "s|^#?\s*${KEY}(\s.*)?\$|${KEY} ${VALUE}|" "$CLAMD_CONF"
  else
    echo "${KEY} ${VALUE}" >> "$CLAMD_CONF"
  fi
}

ensure_clamd_option LogTime "yes"
ensure_clamd_option ExtendedDetectionInfo "yes"
ensure_clamd_option User "clamav"
ensure_clamd_option MaxDirectoryRecursion "20"
ensure_clamd_option DetectPUA "yes"
ensure_clamd_option HeuristicAlerts "yes"
ensure_clamd_option ScanPE "yes"
ensure_clamd_option ScanELF "yes"
ensure_clamd_option ScanOLE2 "yes"
ensure_clamd_option ScanPDF "yes"
ensure_clamd_option ScanSWF "yes"
ensure_clamd_option ScanXMLDOCS "yes"
ensure_clamd_option ScanHWP3 "yes"
ensure_clamd_option ScanOneNote "yes"
ensure_clamd_option ScanMail "yes"
ensure_clamd_option ScanHTML "yes"
ensure_clamd_option ScanArchive "yes"
ensure_clamd_option Bytecode "yes"
ensure_clamd_option AlertBrokenExecutables "yes"
ensure_clamd_option AlertBrokenMedia "yes"
ensure_clamd_option AlertEncrypted "yes"
ensure_clamd_option AlertEncryptedArchive "yes"
ensure_clamd_option AlertEncryptedDoc "yes"
ensure_clamd_option AlertOLE2Macros "yes"
ensure_clamd_option AlertPartitionIntersection "yes"

mkdir -p /var/log/clamav
touch /var/log/clamav/freshclam.log
chmod 600 /var/log/clamav/freshclam.log
chown clamav:clamav /var/log/clamav/freshclam.log

systemctl enable clamav-freshclam.service
systemctl enable clamav-daemon.service
if [[ "$INSTALL_TYPE_VAL" == "vps-harden" ]]; then
    systemctl start clamav-freshclam.service || true
    freshclam || true
    systemctl start clamav-daemon.service || true
fi

echo -e "${BBlue}ClamAV configuration completed!${NC}"

###############################################################################
# RKHUNTER (rkhunter --propupd runs near the end after all packages and
# binary permission adjustments are finalized)
###############################################################################

echo -e "${BBlue}Installing and configuring rkhunter...${NC}"
pacman -S --needed --noconfirm rkhunter

cat <<EOF > /etc/systemd/system/rkhunter-check.service
[Unit]
Description=Run rkhunter daily check
[Service]
Type=oneshot
ExecStart=/usr/bin/rkhunter --check --cronjob --rwo
SuccessExitStatus=0 1
EOF
cat <<EOF > /etc/systemd/system/rkhunter-check.timer
[Unit]
Description=Run rkhunter daily check
[Timer]
OnCalendar=daily
Persistent=true
[Install]
WantedBy=timers.target
EOF
systemctl enable rkhunter-check.timer

###############################################################################
# ARPWATCH
###############################################################################

echo -e "${BBlue}Installing and configuring arpwatch...${NC}"
pacman -S --needed --noconfirm arpwatch

###############################################################################
# NOTE: USBGuard and Bluetooth skipped — not relevant on VPS
###############################################################################

###############################################################################
# LOGIN.DEFS HARDENING
###############################################################################

echo -e "${BBlue}Hardening /etc/login.defs...${NC}"

sed -i 's/^UMASK[[:space:]]\+022/UMASK\t\t027/' /etc/login.defs
sed -i '/#SHA_CRYPT_MIN_ROUNDS 5000/s/^#//;/#SHA_CRYPT_MAX_ROUNDS 5000/s/^#//' /etc/login.defs
sed -i 's/^FAIL_DELAY[[:space:]]\+3/FAIL_DELAY\t\t5/' /etc/login.defs
sed -i 's/^LOGIN_RETRIES[[:space:]]\+5/LOGIN_RETRIES\t\t3/' /etc/login.defs
sed -i 's/^LOGIN_TIMEOUT[[:space:]]\+60/LOGIN_TIMEOUT\t\t30/' /etc/login.defs
sed -i 's/^ENCRYPT_METHOD[[:space:]]\+.*$/ENCRYPT_METHOD YESCRYPT/' /etc/login.defs
sed -i 's/^#YESCRYPT_COST_FACTOR[[:space:]]\+.*$/YESCRYPT_COST_FACTOR 7/' /etc/login.defs
sed -i 's/^#MAX_MEMBERS_PER_GROUP[[:space:]]\+0/MAX_MEMBERS_PER_GROUP\t100/' /etc/login.defs
sed -i 's/^#HMAC_CRYPTO_ALGO[[:space:]]\+.*$/HMAC_CRYPTO_ALGO SHA512/' /etc/login.defs
sed -i '/^PASS_MAX_DAYS/c\PASS_MAX_DAYS 730' /etc/login.defs

# HOME_MODE 0700 so new user homes aren't world-readable.
# The value is replaced in-place if present, appended otherwise.
if grep -qE '^[#[:space:]]*HOME_MODE' /etc/login.defs; then
    sed -i 's/^[#[:space:]]*HOME_MODE.*/HOME_MODE\t\t0700/' /etc/login.defs
else
    echo -e "HOME_MODE\t\t0700" >> /etc/login.defs
fi

# Additional UMASK hardening
grep -qxF 'umask 027' /etc/profile || echo "umask 027" >> /etc/profile
grep -qxF 'umask 027' /etc/bash.bashrc || echo "umask 027" >> /etc/bash.bashrc

# Disable unwanted protocols
echo -e "${BBlue}Disabling unwanted protocols...${NC}"
cat > /etc/modprobe.d/disable-protocols.conf << 'MODPROBE_EOF'
blacklist dccp
blacklist sctp
blacklist rds
blacklist tipc
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false
MODPROBE_EOF

# Disable core dumps
echo -e "${BBlue}Disabling core dump...${NC}"
grep -qxF '* hard core 0' /etc/security/limits.conf 2>/dev/null || echo "* hard core 0" >> /etc/security/limits.conf

###############################################################################
# NTP — chrony only (no conflict with ntpd)
###############################################################################

echo -e "${BBlue}Installing chrony for NTP...${NC}"
pacman -S --needed --noconfirm chrony
install -d -o chrony -g chrony -m 0750 /var/log/chrony
systemctl enable chronyd

###############################################################################
# SYSTEM MONITORING & AUDITING
###############################################################################

echo -e "${BBlue}Enabling sysstat...${NC}"
pacman -S --needed --noconfirm sysstat
systemctl enable sysstat

echo -e "${BBlue}Enabling auditd...${NC}"
pacman -S --needed --noconfirm audit
configure_audit_rules
# Loading audit rules here would change the live installer kernel.
systemctl enable auditd

###############################################################################
# SERVICES
###############################################################################

# Enable networking — NetworkManager or systemd-networkd (VPS providers vary)
if systemctl list-unit-files NetworkManager.service &>/dev/null; then
    echo -e "${BBlue}Enabling NetworkManager...${NC}"
    systemctl enable NetworkManager
else
    echo -e "${BBlue}NetworkManager not installed — ensuring systemd-networkd is enabled...${NC}"
    systemctl enable systemd-networkd 2>/dev/null || true
fi

echo -e "${BBlue}Enabling OpenSSH...${NC}"
systemctl enable sshd

# dhcpcd conflicts with NetworkManager — do not enable both.
# NetworkManager (or systemd-networkd) handles DHCP already.

# Enable serial console for VPS provider access
echo -e "${BBlue}Enabling serial console (for VPS provider console)...${NC}"
systemctl enable serial-getty@ttyS0.service

# Prevent boot-blocking services from hanging indefinitely:
# - cloud-init is required for provider networking but can hang if the metadata
#   endpoint is slow or unreachable — cap it with TimeoutStartSec
# - systemd-time-wait-sync blocks until NTP sync completes (chrony handles this)
# NOTE: Use direct file writes — systemctl doesn't work inside chroot.
echo -e "${BBlue}Adding boot timeouts for cloud-init and disabling time-wait-sync...${NC}"
for svc in cloud-init-local.service cloud-init.service cloud-config.service cloud-final.service; do
    mkdir -p "/etc/systemd/system/${svc}.d"
    cat > "/etc/systemd/system/${svc}.d/timeout.conf" <<'CEOF'
[Service]
TimeoutStartSec=30s
CEOF
done
ln -sf /dev/null /etc/systemd/system/systemd-time-wait-sync.service 2>/dev/null || true

###############################################################################
# FAIL2BAN
###############################################################################

echo -e "${BBlue}Installing and configuring Fail2ban...${NC}"
pacman -S --needed --noconfirm fail2ban

install -d -m 0755 /etc/fail2ban/filter.d /etc/fail2ban/jail.d
cat <<'EOF' > /etc/fail2ban/filter.d/sshd.local
[Definition]
_daemon = sshd(?:-session|-auth)?

[Init]
journalmatch = _SYSTEMD_UNIT=sshd.service
EOF

cat <<EOF > /etc/fail2ban/jail.d/sshd.conf
[sshd]
enabled = true
port    = ${SSH_PORT}
maxretry = 5
banaction = ${FAIL2BAN_BANACTION}
# OpenSSH 10.x splits into sshd, sshd-auth, sshd-session — match all via journal
backend = systemd
journalmatch = _SYSTEMD_UNIT=sshd.service
EOF

systemctl enable fail2ban

###############################################################################
# JOURNALD
###############################################################################

echo -e "${BBlue}Improving journald configuration...${NC}"
configure_journal_sealing
# Key setup and journal rotation run on the installed system at boot.

###############################################################################
# SUDO HARDENING
###############################################################################

echo -e "${BBlue}Hardening sudo...${NC}"
groupadd -r proc 2>/dev/null || true
groupadd sudo 2>/dev/null || true

# visudo ships with sudo, which a minimal live image may not have.
if ! command -v visudo &>/dev/null; then
    pacman -S --needed --noconfirm sudo
fi

# The Defaults shared by the installer's /etc/sudoers and by the drop-in used
# on live systems.
sudoers_hardening_defaults() {
    cat << 'SUDOERS_EOF'
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Defaults !rootpw
Defaults umask=077
Defaults editor=/usr/bin/vim:/usr/bin/nvim:/usr/bin/nano:/usr/bin/vi
Defaults env_reset
Defaults env_keep="COLORS DISPLAY HOSTNAME HISTSIZE INPUTRC KDEDIR LS_COLORS"
Defaults env_keep += "MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE"
Defaults env_keep += "LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES"
Defaults env_keep += "LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE"
Defaults env_keep += "LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY"
Defaults timestamp_timeout=30
Defaults !visiblepw
Defaults always_set_home
Defaults match_group_by_gid
Defaults always_query_group_plugin
Defaults passwd_timeout=10
Defaults passwd_tries=3
Defaults loglinelen=0
Defaults insults
Defaults lecture=once
Defaults logfile=/var/log/sudo.log
Defaults log_input, log_output
# log_input records everything typed under sudo. Keep passwords entered at
# prompts of the commands being run (passwd, cryptsetup, ssh, ...) out of
# /var/log/sudo-io, and cap the number of session logs so they cannot fill /var.
Defaults !log_passwords
Defaults maxseq=10000
SUDOERS_EOF
}

if [[ "$INSTALL_TYPE_VAL" == "vps-harden" && -f /etc/sudoers ]]; then
    # Live system: /etc/sudoers keeps the administrator's rules (%wheel,
    # NOPASSWD entries, aliases). The hardening is added as a drop-in; a file
    # name with a dot or a trailing "~" would be skipped by sudo.
    backup_before_change /etc/sudoers
    install -d -m 0750 -o root -g root /etc/sudoers.d
    if ! grep -Eq '^[#@]includedir[[:space:]]+/etc/sudoers\.d/?[[:space:]]*$' /etc/sudoers; then
        SUDOERS_TMP=$(mktemp /etc/.sudoers.XXXXXX)
        chmod 0440 "$SUDOERS_TMP"
        {
            cat /etc/sudoers
            printf '\n@includedir /etc/sudoers.d\n'
        } > "$SUDOERS_TMP"
        if visudo -c -f "$SUDOERS_TMP" >/dev/null; then
            install -m 0440 -o root -g root "$SUDOERS_TMP" /etc/sudoers
            echo -e "${BBlue}Added '@includedir /etc/sudoers.d' to /etc/sudoers.${NC}"
        else
            echo -e "${BRed}ERROR: could not add '@includedir /etc/sudoers.d' to /etc/sudoers; it was left unchanged.${NC}" >&2
        fi
        rm -f "$SUDOERS_TMP"
    fi

    SUDOERS_DROPIN="/etc/sudoers.d/00-awesome-hardening"
    SUDOERS_TMP=$(mktemp /etc/.sudoers.XXXXXX)
    chmod 0440 "$SUDOERS_TMP"
    {
        echo "# sudo hardening — generated by vps-chroot.sh"
        echo "# Rules in /etc/sudoers and in the other files of this directory still apply."
        echo
        sudoers_hardening_defaults
        echo
        echo "%sudo ALL=(ALL:ALL) ALL"
    } > "$SUDOERS_TMP"
    if visudo -c -f "$SUDOERS_TMP" >/dev/null; then
        SUDOERS_DROPIN_OLD=""
        if [[ -f "$SUDOERS_DROPIN" ]]; then
            SUDOERS_DROPIN_OLD=$(mktemp /etc/.sudoers.XXXXXX)
            cp -a -- "$SUDOERS_DROPIN" "$SUDOERS_DROPIN_OLD"
        fi
        install -m 0440 -o root -g root "$SUDOERS_TMP" "$SUDOERS_DROPIN"
        # The drop-in must also be valid together with the existing rules.
        if visudo -c >/dev/null; then
            echo -e "${BGreen}Sudo hardening installed as $SUDOERS_DROPIN; /etc/sudoers was kept.${NC}"
        else
            if [[ -n "$SUDOERS_DROPIN_OLD" ]]; then
                install -m 0440 -o root -g root "$SUDOERS_DROPIN_OLD" "$SUDOERS_DROPIN"
            else
                rm -f -- "$SUDOERS_DROPIN"
            fi
            echo -e "${BRed}ERROR: the sudo configuration did not validate with $SUDOERS_DROPIN; the drop-in was removed again.${NC}" >&2
        fi
        [[ -z "$SUDOERS_DROPIN_OLD" ]] || rm -f -- "$SUDOERS_DROPIN_OLD"
    else
        echo -e "${BRed}ERROR: sudoers validation failed! Keeping the existing sudo configuration.${NC}" >&2
    fi
    rm -f "$SUDOERS_TMP"
else
    # Write sudoers atomically via private /etc temp file + visudo validation
    SUDOERS_TMP=$(mktemp /etc/.sudoers.XXXXXX)
    chmod 0440 "$SUDOERS_TMP"
    {
        echo "# Hardened sudoers — generated by vps-chroot.sh"
        echo
        sudoers_hardening_defaults
        echo
        echo "root ALL=(ALL:ALL) ALL"
        echo "%sudo ALL=(ALL:ALL) ALL"
        echo
        echo "@includedir /etc/sudoers.d"
    } > "$SUDOERS_TMP"

    # Validate before installing
    if visudo -c -f "$SUDOERS_TMP"; then
        install -m 0440 -o root -g root "$SUDOERS_TMP" /etc/sudoers
        echo -e "${BGreen}Sudoers validated and installed successfully.${NC}"
    else
        echo -e "${BRed}ERROR: sudoers validation failed! Keeping original file.${NC}" >&2
    fi
    rm -f "$SUDOERS_TMP"
fi

###############################################################################
# ARCH-AUDIT
###############################################################################

# arch-audit was installed above; enable the scheduled check for first boot.
configure_vulnerability_check
systemctl enable arch-audit.timer

###############################################################################
# USER CREATION
###############################################################################

# Ensure zsh is installed (installed by pacstrap in vps-install.sh, may be missing on live VPS)
if ! command -v zsh &>/dev/null; then
    echo -e "${BBlue}Installing zsh...${NC}"
    pacman -S --needed --noconfirm zsh zsh-completions
fi

echo -e "${BBlue}Adding the user $USERNAME...${NC}"
if ! id -u "$USERNAME" >/dev/null 2>&1; then
  # `proc` group is required because /proc is mounted with
  # hidepid=2,gid=proc (see archinstall.sh). Without it a non-root
  # user can only see their own /proc entries, which breaks PID
  # tracking in logind and systemd-user. Same root cause as the
  # NixOS GNOME-45 Wayland startup failure reported on Discourse.
  useradd -m -G sudo,wheel,uucp,proc -s /bin/zsh "$USERNAME"
  # Use what useradd really created (HOME and USERGROUPS_ENAB can be changed
  # in /etc/default/useradd and /etc/login.defs on a live system).
  USER_HOME=$(user_account_entry | cut -d: -f6)
  USER_GROUP=$(id -gn "$USERNAME")
  SSH_CONFIG_FILE="$USER_HOME/.ssh/config"
  SSH_KEY_FILE="$USER_HOME/.ssh/id_$SSH_KEY_TYPE"
  chown "$USERNAME:$USER_GROUP" "$USER_HOME"
  chmod 700 "$USER_HOME"                   # Private home (not world-readable)
  echo -e "${BBlue}User $USERNAME created.${NC}"
else
    echo "User $USERNAME already exists." >&2
    # An existing administrator keeps the groups, shell and home it has. It is
    # added to the group the sudo policy above grants ("sudo") and to "proc"
    # (/proc is mounted with hidepid=2,gid=proc), so sudo keeps working even
    # when its old access came from a rule this run does not carry over.
    usermod -aG sudo,proc "$USERNAME"
fi

# Pre-create private user cache directories (including nano backups)
install -d -m 0700 -o "$USERNAME" -g "$USER_GROUP" \
    "$USER_HOME/.cache" \
    "$USER_HOME/.cache/nano" \
    "$USER_HOME/.cache/nano/backups"

# Set passwords
echo -e "${BBlue}Configuring password policy before setting passwords...${NC}"
pacman -S --needed --noconfirm pambase pam libpwquality
configure_password_policy

set +e
while true; do
    echo -e "${BBlue}Setting password for user $USERNAME...${NC}"
    echo -e "${BBlue}Password should be at least 12 characters long, contain 1 symbol, 1 number, upper and lowercase letters.${NC}"
    if passwd "$USERNAME"; then
        break
    else
        echo -e "${BBlue}Password change failed. Please try again.${NC}"
        sleep 1
    fi
done

while true; do
    echo -e "${BBlue}Setting root password...${NC}"
    if passwd root; then
        break
    else
        echo -e "${BBlue}Root password change failed. Please try again.${NC}"
        sleep 1
    fi
done
set -e

# Install nano syntax highlighting (packaged version) and write .nanorc idempotently
echo -e "${BBlue}Installing nano syntax highlighting...${NC}"
pacman -S --needed --noconfirm nano-syntax-highlighting 2>/dev/null || true

if [[ "$INSTALL_TYPE_VAL" == "vps-harden" && -e "$USER_HOME/.nanorc" ]]; then
    # Live system: the user's own editor settings are not replaced.
    echo -e "${BBlue}Keeping the existing $USER_HOME/.nanorc.${NC}"
else
{
    cat << 'NANO_EOF'
set backup
set backupdir "~/.cache/nano/backups/"
set constantshow
set locking
set nohelp
set nonewlines
set nowrap
set minibar
set zap
set linenumbers
set tabsize 4
set tabstospaces
NANO_EOF
    if compgen -G '/usr/share/nano-syntax-highlighting/*.nanorc' >/dev/null; then
        echo 'include "/usr/share/nano-syntax-highlighting/*.nanorc"'
    fi
} > "$USER_HOME/.nanorc"
chown "$USERNAME:$USER_GROUP" "$USER_HOME/.nanorc"
chmod 600 "$USER_HOME/.nanorc"
fi

###############################################################################
# SSH CONFIGURATION
###############################################################################

echo -e "${BBlue}Staging SSH access for $USERNAME (authorized_keys first)...${NC}"

configure_ssh() {
  mkdir -p "$USER_HOME/.ssh"

  if [ ! -f "$SSH_KEY_FILE" ]; then
    echo -e "${BBlue}Generating a new SSH key pair ($SSH_KEY_TYPE)...${NC}"
    ssh-keygen -t "$SSH_KEY_TYPE" -C "$USERNAME@$HOSTNAME" -f "$SSH_KEY_FILE" -q -N ""
  else
    echo -e "${BBlue}SSH key ($SSH_KEY_FILE) already exists.${NC}"
  fi

  if [[ "$INSTALL_TYPE_VAL" == "vps-harden" && -e "$SSH_CONFIG_FILE" ]]; then
    # Live system: the user's own client configuration (jump hosts, other
    # identities) is not replaced.
    echo -e "${BBlue}Keeping the existing $SSH_CONFIG_FILE.${NC}"
  else
  echo -e "${BBlue}Configuring SSH client settings in $SSH_CONFIG_FILE...${NC}"

  if [ -f "$SSH_CONFIG_FILE" ] && [ ! -f "$SSH_CONFIG_FILE.bak" ]; then
    cp "$SSH_CONFIG_FILE" "$SSH_CONFIG_FILE.bak"
  fi

  # Values must NOT be quoted in SSH config
  install -Dm644 /dev/stdin "$SSH_CONFIG_FILE" <<EOF
Host ${HOSTNAME}
  HostName ${HOSTNAME}
  Port ${SSH_PORT}
  User ${USERNAME}
  IdentityFile ${SSH_KEY_FILE}
  HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
  KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group18-sha512,diffie-hellman-group16-sha512
  Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
  MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
EOF

  echo "SSH client configuration updated."
  fi

  echo -e "${BBlue}Hashing known_hosts file...${NC}"
  ssh-keygen -H -f "$USER_HOME/.ssh/known_hosts" 2>/dev/null || true

  touch "$USER_HOME/.ssh/authorized_keys"
  if [[ -n "$SSH_PUBKEY" ]]; then
      # An existing file may lack its final newline; appending to it as it is
      # would glue the new key onto the comment of the last one.
      if [[ -s "$USER_HOME/.ssh/authorized_keys" && -n "$(tail -c 1 "$USER_HOME/.ssh/authorized_keys")" ]]; then
          echo >> "$USER_HOME/.ssh/authorized_keys"
      fi
      grep -qxF "$SSH_PUBKEY" "$USER_HOME/.ssh/authorized_keys" 2>/dev/null || \
          printf '%s\n' "$SSH_PUBKEY" >> "$USER_HOME/.ssh/authorized_keys"
      echo -e "${BGreen}SSH public key installed for $USERNAME.${NC}"
  elif [[ -s "$USER_HOME/.ssh/authorized_keys" ]]; then
      echo -e "${BGreen}Existing SSH authorized_keys preserved for $USERNAME.${NC}"
  else
      echo -e "${BYellow}No SSH public key provided — add one manually via console before disconnecting.${NC}"
  fi
  chmod 700 "$USER_HOME/.ssh"
  chmod 600 "$USER_HOME/.ssh/authorized_keys"
  if [[ "$INSTALL_TYPE_VAL" == "vps-harden" ]]; then
    # Live system: only the files handled here change owner, not everything
    # the home directory holds.
    chown -R "$USERNAME:$USER_GROUP" "$USER_HOME/.ssh"
  else
    chown -R "$USERNAME:$USER_GROUP" "$USER_HOME"
  fi
}

configure_ssh

# Harden sshd — defer shredding /ssh.sh until the end of vps-chroot.sh so
# recovery/resume can retry cleanly if a subsequent step fails.
echo -e "${BBlue}Hardening sshd on port $SSH_PORT...${NC}"
# The key must be one the hardened sshd accepts, not merely a non-empty file:
# an authorized_keys with only plain ECDSA keys would lock the user out.
# SSH_HARDEN_ENV is set in the firewall section.
if authorized_keys_usable "$USER_HOME/.ssh/authorized_keys"; then
    env "${SSH_HARDEN_ENV[@]}" /ssh.sh -u "$USERNAME" -p "$SSH_PORT"
elif [[ "$ALLOW_NO_SSH_KEY" == "true" ]]; then
    echo -e "${BYellow}Proceeding without a usable authorized_keys because console-only access was explicitly confirmed (-k).${NC}"
    env "${SSH_HARDEN_ENV[@]}" /ssh.sh -u "$USERNAME" -p "$SSH_PORT" -k
else
    echo -e "${BRed}ERROR: $USER_HOME/.ssh/authorized_keys holds no key the hardened sshd accepts and console-only override was not confirmed.${NC}" >&2
    exit 1
fi

# Live systems: close the previous sshd port(s) once sshd has really moved.
finish_ssh_port_move

sleep 1

###############################################################################
# COMPILER HARDENING
###############################################################################

echo -e "${BBlue}Applying hardened compiler flags...${NC}"
harden_makepkg_conf() {
    local conf="/etc/makepkg.conf"
    [[ -f "$conf" ]] || return 0
    if ! grep -q -- '-fstack-protector-strong' "$conf"; then
        awk '
            /^CFLAGS="/ { in_cflags = 1 }
            in_cflags && /"[[:space:]]*$/ {
                sub(/"[[:space:]]*$/, " -fstack-protector-strong\"")
                in_cflags = 0
            }
            { print }
        ' "$conf" > "${conf}.tmp" && cat "${conf}.tmp" > "$conf" && rm -f "${conf}.tmp"
    fi
    if ! grep -q -- '_FORTIFY_SOURCE' "$conf"; then
        awk '
            /^CFLAGS="/ { in_cflags = 1 }
            in_cflags && /"[[:space:]]*$/ {
                sub(/"[[:space:]]*$/, " -Wp,-D_FORTIFY_SOURCE=3\"")
                in_cflags = 0
            }
            { print }
        ' "$conf" > "${conf}.tmp" && cat "${conf}.tmp" > "$conf" && rm -f "${conf}.tmp"
    fi
    if ! grep -q -- '-z,now' "$conf"; then
        awk '
            /^LDFLAGS="/ { in_ldflags = 1 }
            in_ldflags && /"[[:space:]]*$/ {
                sub(/"[[:space:]]*$/, " -Wl,-z,relro,-z,now\"")
                in_ldflags = 0
            }
            { print }
        ' "$conf" > "${conf}.tmp" && cat "${conf}.tmp" > "$conf" && rm -f "${conf}.tmp"
    fi
    sed -i '/^OPTIONS=/ s/!pie/pie/' "$conf"
}
harden_makepkg_conf

echo -e "${BBlue}Restricting access to compilers using a 'compilers' group...${NC}"
groupadd compilers 2>/dev/null || true
usermod -aG compilers "$USERNAME"

install -Dm0755 /dev/stdin /usr/local/lib/awesomearchlinux/fix-compilers-perms.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
getent group compilers >/dev/null 2>&1 || exit 0
for compiler in gcc g++ clang make as ld ld.bfd ld.lld; do
    compiler_path=$(command -v "$compiler" 2>/dev/null) || continue
    resolved=$(realpath -e "$compiler_path" 2>/dev/null) || continue
    [[ -f "$resolved" ]] || continue
    chown root:compilers "$resolved"
    chmod 0750 "$resolved"
done
EOF

install -Dm0644 /dev/stdin /etc/pacman.d/hooks/90-awesome-compilers.hook <<'EOF'
[Trigger]
Operation = Install
Operation = Upgrade
Type = Path
Target = usr/bin/gcc
Target = usr/bin/g++
Target = usr/bin/clang
Target = usr/bin/make
Target = usr/bin/as
Target = usr/bin/ld
Target = usr/bin/ld.bfd
Target = usr/bin/ld.lld

[Action]
Description = Restoring compiler group permissions (root:compilers 0750)...
When = PostTransaction
Exec = /usr/local/lib/awesomearchlinux/fix-compilers-perms.sh
EOF

/usr/local/lib/awesomearchlinux/fix-compilers-perms.sh

# Keep /root private (0700) without default ACLs, and exclude ~/.cache/{yay,paru}
# from default ACL inheritance so AUR makepkg builds never create broken packages.
echo -e "${BBlue}Configuring /root permissions and default ACLs on $USER_HOME...${NC}"
chmod 0700 /root
setfacl -b -k /root 2>/dev/null || true
setfacl -d -m u::rwx,g::---,o::--- "$USER_HOME"
mkdir -p "$USER_HOME/.cache/yay" "$USER_HOME/.cache/paru" "$USER_HOME/.cache/nano/backups"
chmod 0700 "$USER_HOME/.cache" "$USER_HOME/.cache/nano" "$USER_HOME/.cache/nano/backups"
setfacl -b -k "$USER_HOME/.cache" "$USER_HOME/.cache/yay" "$USER_HOME/.cache/paru"
chown -hR "$USERNAME:$USER_GROUP" "$USER_HOME/.cache"

###############################################################################
# GRUB SETUP (NO ENCRYPTION — VPS)
###############################################################################

# Skip GRUB/mkinitcpio on live systems — bootloader is already configured
if [[ "$INSTALL_TYPE_VAL" != "vps-harden" ]]; then

echo -e "${BBlue}Setting up GRUB (no encryption for VPS)...${NC}"
pacman -S --needed --noconfirm grub efibootmgr os-prober

# mkinitcpio — simple, no encrypt/lvm hooks needed
echo -e "${BBlue}Adjusting /etc/mkinitcpio.conf...${NC}"
sed -i "s|^HOOKS=.*|HOOKS=(base udev autodetect keyboard keymap modconf block filesystems fsck)|g" /etc/mkinitcpio.conf
mkinitcpio -p linux

# Kernel security boot params (no LUKS-related params)
echo -e "${BBlue}Hardening kernel boot options...${NC}"
GRUBSEC="\"slab_nomerge init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 pti=on randomize_kstack_offset=on vsyscall=none quiet loglevel=3 console=tty0 console=ttyS0,115200n8\""

sed -i "s|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT=${GRUBSEC}|" /etc/default/grub
sed -i "s|^GRUB_CMDLINE_LINUX=.*|GRUB_CMDLINE_LINUX=\"\"|" /etc/default/grub

# Enable serial console in GRUB idempotently for VPS provider console access
if ! grep -q '^GRUB_TERMINAL="console serial"' /etc/default/grub; then
    sed -i -E '/^#?GRUB_TERMINAL=/d; /^#?GRUB_SERIAL_COMMAND=/d' /etc/default/grub
    cat >> /etc/default/grub <<'EOF'

# VPS serial console support
GRUB_TERMINAL="console serial"
GRUB_SERIAL_COMMAND="serial --speed=115200 --unit=0 --word=8 --parity=no --stop=1"
EOF
fi

# CPU Microcode
echo -e "${BBlue}Installing CPU microcode...${NC}"
if [[ "$CPU_VENDOR_ID" =~ "GenuineIntel" ]]; then
    pacman -S --needed --noconfirm intel-ucode 2>/dev/null || true
elif [[ "$CPU_VENDOR_ID" =~ "AuthenticAMD" ]]; then
    pacman -S --needed --noconfirm amd-ucode 2>/dev/null || true
fi

# NOTE: GPU detection skipped — VPS doesn't have physical GPUs

# Install and configure GRUB
echo -e "${BBlue}Installing GRUB...${NC}"
mkdir -p /boot/grub

if [ -d "/sys/firmware/efi/efivars" ]; then
    # Many hypervisors do not keep (or do not accept) UEFI NVRAM entries: the
    # variable store is lost when the VM is re-created or migrated, and
    # efibootmgr can fail outright. The removable-media fallback loader at
    # /efi/EFI/BOOT/BOOTX64.EFI is what such firmware boots, so it is always
    # installed (as base/bootloader.sh does for bare metal), and a failed NVRAM
    # registration only aborts the install when the fallback failed as well.
    GRUB_NVRAM_ENTRY=true
    grub-install --target=x86_64-efi --bootloader-id=GRUB --efi-directory=/efi --recheck || GRUB_NVRAM_ENTRY=false
    if grub-install --target=x86_64-efi --efi-directory=/efi --removable --recheck; then
        if [[ "$GRUB_NVRAM_ENTRY" != true ]]; then
            echo -e "${BYellow}Warning: the \"GRUB\" UEFI boot entry could not be written; the firmware will start the fallback loader EFI/BOOT/BOOTX64.EFI.${NC}"
        fi
    elif [[ "$GRUB_NVRAM_ENTRY" == true ]]; then
        echo -e "${BYellow}Warning: fallback loader install failed; the UEFI NVRAM entry is the only boot path.${NC}"
    else
        echo -e "${BRed}ERROR: GRUB could not be installed to the EFI system partition.${NC}" >&2
        exit 1
    fi
else
    grub-install --target=i386-pc "$DISK" --recheck
fi


grub-mkconfig -o /boot/grub/grub.cfg

else
    echo -e "${BBlue}Skipping GRUB/mkinitcpio (live system — bootloader already configured)${NC}"
fi # end INSTALL_TYPE_VAL guard

###############################################################################
# LOGIN BANNER & FILE PERMISSIONS
###############################################################################

echo -e "${BBlue}Creating Banners (/etc/issue and /etc/issue.net).${NC}"

cat > /etc/issue.net << 'EOF'
********************************************************************
*                                                                  *
* This system is for the use of authorized users only. Usage of    *
* this system may be monitored and recorded by system personnel.   *
*                                                                  *
* Anyone using this system expressly consents to such monitoring   *
* and is advised that if such monitoring reveals possible          *
* evidence of criminal activity, system personnel may provide the  *
* evidence from such monitoring to law enforcement officials.      *
*                                                                  *
********************************************************************
EOF
cp /etc/issue.net /etc/issue

echo -e "${BBlue}Setting permissions on config files...${NC}"

chmod 0700 /boot
# /home is traversable (users can reach their own dir) but not listable:
# `ls /home` reveals no usernames to non-root observers. Per-user dirs
# stay 700 via HOME_MODE in login.defs.
# See chroot.sh for rationale on the tmpfiles.d rule.
chmod 0711 /home
install -Dm644 /dev/stdin /etc/tmpfiles.d/home-perms.conf <<'EOF'
# Keep /home traversable-but-not-listable across boots.
d /home 0711 root root -
EOF
chmod 644 /etc/passwd
chown root:root /etc/passwd
chmod 644 /etc/group
chown root:root /etc/group
chmod 600 /etc/shadow
chown root:root /etc/shadow
chmod 600 /etc/gshadow
chown root:root /etc/gshadow
chown root:root /etc/ssh/sshd_config
chmod 600 /etc/ssh/sshd_config
chown root:root /etc/fstab
chmod 644 /etc/fstab
chown root:root /etc/issue /etc/issue.net
chmod 644 /etc/issue /etc/issue.net
if [[ -f /boot/grub/grub.cfg ]]; then
    chown root:root /boot/grub/grub.cfg
    chmod og-rwx /boot/grub/grub.cfg
fi
install -d -m 0750 -o root -g root /etc/sudoers.d
chown -c root:root /etc/sudoers
chmod -c 0440 /etc/sudoers
# Never set the 2000 setgid bit on root-owned binaries or break normal user ping/whereis.
if [[ -g /usr/bin/ping ]]; then
    chmod 00755 /usr/bin/ping
    setcap cap_net_raw=ep /usr/bin/ping 2>/dev/null || true
fi
chmod 00755 /usr/bin/whereis
chown root:proc /usr/bin/w /usr/bin/who
chmod 00750 /usr/bin/w /usr/bin/who
chmod 0644 /etc/login.defs

###############################################################################
# PAM HARDENING
###############################################################################

# Password policy is configured before the initial passwd calls above.


###############################################################################
# AUTOMATIC SECURITY UPDATES
###############################################################################

echo -e "${BBlue}Setting up daily package update checks...${NC}"
pacman -S --needed --noconfirm pacman-contrib
cat <<'EOF' > /etc/systemd/system/pacman-autoupdate.timer
[Unit]
Description=Run package update check daily

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF
cat <<'EOF' > /etc/systemd/system/pacman-autoupdate.service
[Unit]
Description=Check for available package updates (notification only)
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
# checkupdates syncs a temporary database, leaving pacman's live sync database
# untouched. Exit 2 means there are no pending updates and is not an error.
ExecStart=/usr/bin/checkupdates
# truncate: (not file:) so a shorter list does not keep the tail of an older one.
StandardOutput=truncate:/var/log/pacman-updates.log
StandardError=inherit
SuccessExitStatus=2
EOF
systemctl enable pacman-autoupdate.timer

sleep 2

###############################################################################
# SYSTEMD SERVICES HARDENING
###############################################################################

echo -e "${BBlue}Hardening systemd services...${NC}"

# SSH Service
echo -e "${BBlue}Hardening SSH service...${NC}"
mkdir -p /etc/systemd/system/sshd.service.d/
cat > /etc/systemd/system/sshd.service.d/hardening.conf <<'EOF'
[Service]
# sshd spawns interactive user sessions: PrivateTmp=yes and ProtectControlGroups=yes
# isolate local /tmp IPC sockets and break rootless container cgroup delegation.
PrivateTmp=no
NoNewPrivileges=no
ProtectSystem=no
ProtectHome=no
ProtectKernelTunables=no
ProtectKernelModules=no
ProtectKernelLogs=no
ProtectControlGroups=no
# RestrictAddressFamilies=, LockPersonality= and RestrictRealtime= are seccomp
# filters. They are inherited by every process sshd starts, i.e. by each login
# session, and not even sudo can lift them: tcpdump, nmap, AF_ALG users and
# setarch would all fail over SSH. They are therefore deliberately not set.
IPAddressAllow=any
IPAddressDeny=
PrivateDevices=no
DevicePolicy=auto
Restart=on-failure
RestartSec=5s
EOF

# NetworkManager hardening
echo -e "${BBlue}Hardening NetworkManager...${NC}"
mkdir -p /etc/systemd/system/NetworkManager.service.d/
cat > /etc/systemd/system/NetworkManager.service.d/hardening.conf <<'EOF'
[Service]
RuntimeDirectory=NetworkManager
# Keep /run/NetworkManager across a restart: it holds the state NM uses to
# take its devices over again without tearing the connections down.
RuntimeDirectoryPreserve=yes
StateDirectory=NetworkManager
ProtectSystem=strict
ReadWritePaths=-/etc/NetworkManager -/etc/resolv.conf
# read-only like the upstream unit, not "yes": 802.1X and VPN profiles
# commonly reference certificates and keys stored under /home.
ProtectHome=read-only
ProtectKernelTunables=no
ProtectKernelModules=no
ProtectControlGroups=yes
ProtectKernelLogs=yes
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_DAC_OVERRIDE CAP_SETUID CAP_SETGID CAP_SYS_MODULE
NoNewPrivileges=no
PrivateDevices=no
DevicePolicy=auto
RestrictRealtime=yes
LockPersonality=yes
Restart=on-failure
RestartSec=5s
EOF

# Auditd hardening
echo -e "${BBlue}Hardening auditd...${NC}"
mkdir -p /etc/systemd/system/auditd.service.d/
cat > /etc/systemd/system/auditd.service.d/hardening.conf <<'EOF'
[Service]
# auditd manages the kernel audit subsystem — ProtectControlGroups=yes breaks
# /proc audit rule operations and is explicitly unsupported upstream.
ProtectSystem=full
ProtectHome=yes
ReadWritePaths=/var/log/audit /run
CapabilityBoundingSet=CAP_AUDIT_CONTROL CAP_AUDIT_READ CAP_AUDIT_WRITE CAP_DAC_READ_SEARCH CAP_SYS_NICE CAP_SYS_RESOURCE
PrivateDevices=yes
PrivateTmp=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
EOF

# ClamAV hardening
echo -e "${BBlue}Hardening ClamAV services...${NC}"
mkdir -p /etc/systemd/system/clamav-daemon.service.d/
cat > /etc/systemd/system/clamav-daemon.service.d/hardening.conf <<'EOF'
[Service]
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/lib/clamav /var/log/clamav /run
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictRealtime=yes
LockPersonality=yes
LimitNOFILE=8192
# clamd's default MaxThreads is 10, plus the listener, a database-reload
# thread and helpers; 16 made multi-threaded scans fail to spawn workers.
TasksMax=64
Restart=on-failure
RestartSec=10s
EOF

# Fail2ban hardening
echo -e "${BBlue}Hardening fail2ban...${NC}"
mkdir -p /etc/systemd/system/fail2ban.service.d/
cat > /etc/systemd/system/fail2ban.service.d/hardening.conf <<'EOF'
[Service]
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/fail2ban /var/log /run/fail2ban
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
CapabilityBoundingSet=
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_READ_SEARCH CAP_DAC_OVERRIDE
NoNewPrivileges=no
PrivateTmp=yes
PrivateDevices=yes
RestrictAddressFamilies=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
RestrictRealtime=yes
LockPersonality=yes
Restart=on-failure
RestartSec=5s
EOF

# Stubby is no longer part of the default install — native systemd-resolved
# DoT is used instead (see the DNS section above). Users who want Stubby
# can install and harden it manually as a server-side opt-in.

# systemd-resolved is already well-hardened by its upstream unit file.
# A custom drop-in would replace (not extend) its tuned SystemCallFilter,
# which can break resolved. Trust the upstream hardening.

# Chrony NTP hardening
echo -e "${BBlue}Hardening Chrony NTP...${NC}"
install -d -o chrony -g chrony -m 0750 /var/log/chrony
mkdir -p /etc/systemd/system/chronyd.service.d/
cat > /etc/systemd/system/chronyd.service.d/hardening.conf <<'EOF'
[Service]
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=
ReadWritePaths=/run /var/lib/chrony -/var/log/chrony
ProtectKernelTunables=no
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=no
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=no
CapabilityBoundingSet=
CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_CHOWN CAP_DAC_OVERRIDE CAP_SYS_TIME CAP_NET_BIND_SERVICE
SystemCallFilter=
SystemCallFilter=@system-service @clock
SystemCallErrorNumber=EPERM
RestrictAddressFamilies=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
RestrictRealtime=yes
LockPersonality=yes
Restart=on-failure
RestartSec=5s
EOF

# NOTE: systemd-journald and rngd are NOT hardened via the generic template.
# journald is already well-hardened upstream; the generic template breaks logging.
# rngd needs direct device access (/dev/hwrng) which the generic template blocks.

# Reload systemd
echo -e "${BBlue}Reloading systemd daemon to apply hardening...${NC}"
systemctl daemon-reload

# Validate the merged upstream units and local drop-ins before first boot.
# systemd-analyze verify does not require systemd to be PID 1, so this also
# works in the arch-chroot installer path.
SYSTEMD_HARDENING_CANDIDATES=(
    sshd.service
    NetworkManager.service
    auditd.service
    audit-rules.service
    awesome-journal-sealing.service
    systemd-journal-flush.service
    clamav-daemon.service
    fail2ban.service
    chronyd.service
    arch-audit.service
    arch-audit-alert.service
    arch-audit.timer
    rkhunter-check.service
    rkhunter-check.timer
    pacman-autoupdate.service
    pacman-autoupdate.timer
)
SYSTEMD_HARDENED_UNITS=()
for unit in "${SYSTEMD_HARDENING_CANDIDATES[@]}"; do
    if [[ -e "/etc/systemd/system/$unit" || -L "/etc/systemd/system/$unit" ||
          -e "/usr/local/lib/systemd/system/$unit" || -L "/usr/local/lib/systemd/system/$unit" ||
          -e "/usr/lib/systemd/system/$unit" || -L "/usr/lib/systemd/system/$unit" ]]; then
        SYSTEMD_HARDENED_UNITS+=("$unit")
    fi
done
# --man=no: the units' Documentation=man: entries are not looked up. A system
# without man-db (minimal images) would otherwise fail verification here.
if ! systemd-analyze verify --man=no "${SYSTEMD_HARDENED_UNITS[@]}"; then
    echo -e "${BRed}Systemd unit verification failed; refusing to leave broken service configuration.${NC}" >&2
    exit 1
fi

echo -e "${BGreen}Systemd services hardening completed!${NC}"

sleep 2

###############################################################################
# SYSCTL HARDENING
###############################################################################

harden_sysctl() {
  echo -e "${BBlue}Applying sysctl profile: ${SYSCTL_PROFILE}...${NC}"

  if [ -x "/sysctl-profile/sysctl.sh" ]; then
    local -a sysctl_args=("$SYSCTL_PROFILE")
    if [[ "$INSTALL_TYPE_VAL" != "vps-harden" ]]; then
      sysctl_args+=("--no-apply")
    fi
    if [[ "$SYSCTL_DISABLE_IPV6" == true ]]; then
      sysctl_args+=("--disable-ipv6")
    fi
    /sysctl-profile/sysctl.sh "${sysctl_args[@]}"
    rm -rf -- /sysctl-profile
    sleep 2
    return
  fi

  # Compatibility with installers from before the composable profile bundle.
  if [ -f "/sysctl-profile.conf" ]; then
    install -m 0644 /sysctl-profile.conf /etc/sysctl.d/99-sysctl.conf
    sysctl --load=/etc/sysctl.d/99-sysctl.conf
    rm -f /sysctl-profile.conf
    sleep 2
    return
  fi

  if [ -x "/sysctl.sh" ]; then
    /sysctl.sh
    sleep 2
    shred -u /sysctl.sh
    return
  fi

  echo "Error: no sysctl profile or sysctl.sh found" >&2
  exit 1
}

harden_sysctl

# Finalize rkhunter file property baseline AFTER all packages and binary
# permission changes (compilers group, w/who, sshd, bootloaders) are in place.
echo -e "${BBlue}Updating rkhunter file property database...${NC}"
rkhunter --propupd

sleep 2

if [[ "$INSTALL_TYPE_VAL" != "vps-harden" ]]; then
    echo -e "${BBlue}Pointing /etc/resolv.conf at the resolved stub for first boot...${NC}"
    chattr -i /etc/resolv.conf 2>/dev/null || true
    umount /etc/resolv.conf 2>/dev/null || true
    rm -f /etc/resolv.conf
    ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
fi

if [[ "$INSTALL_TYPE_VAL" == "vps-harden" ]]; then
    echo -e "${BBlue}Kept as they were: timezone, locale and keymap, the network profiles, the entries of${NC}"
    echo -e "${BBlue}/etc/hosts, the rules in /etc/sudoers, and an existing .nanorc and .ssh/config of $USERNAME.${NC}"
    if [[ "$FIREWALL_MODE" == "keep" ]]; then
        echo -e "${BBlue}The existing firewall was kept as well (see /root/nftables.conf.awesome-proposed).${NC}"
    fi
    echo -e "${BBlue}Copies from before this run: <file>.before-awesome.$BACKUP_STAMP next to /etc/hosts, /etc/resolv.conf,${NC}"
    echo -e "${BBlue}/etc/sudoers and /etc/nftables.conf (where they were changed), and /etc/ssh/sshd_config.bak.<time>.${NC}"
fi

echo -e "${BGreen}VPS chroot configuration completed! You can reboot the system now.${NC}"
shred -u /ssh.sh 2>/dev/null || true
shred -u /nftables.sh 2>/dev/null || true
# Leave a small permanent record of the install profile. /root/.install-env is
# removed below (it holds install-time details), and utils/audit-check.sh must
# not have to guess from "runs in a VM" whether this is a workstation or a VPS.
printf 'INSTALL_TYPE=%s\n' "$INSTALL_TYPE_VAL" > /etc/awesome-install-profile
chmod 0644 /etc/awesome-install-profile
shred -u /root/.install-env 2>/dev/null || true
[[ -f /vps-chroot.sh ]] && shred -u /vps-chroot.sh 2>/dev/null || true
exit
