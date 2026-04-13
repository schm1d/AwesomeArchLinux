#!/usr/bin/env bash

# Description: VPS chroot script for Arch Linux installation.
# Adapted from chroot.sh — removes physical security (USBGuard, Bluetooth, GPU,
# GRUB encryption TPM), fixes duplicate sections and bugs from the original.
#
# Author: Bruno Schmid @brulliant
# LinkedIn: https://www.linkedin.com/in/schmidbruno/

set -euo pipefail
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

# --- Variables from installer ---
DISK="${_INSTALL_DISK}"
USERNAME="${_INSTALL_USER}"
HOSTNAME="${_INSTALL_HOST}"
SSH_PORT="${_INSTALL_SSH_PORT:-22}"
SSH_PUBKEY="${_INSTALL_SSH_PUBKEY:-}"
# shellcheck disable=SC2034  # Cross-script env vars from installer
TIMEZONE="${_INSTALL_TIMEZONE:-UTC}"
# shellcheck disable=SC2034
LOCALE="${_INSTALL_LOCALE:-en_US.UTF-8}"
# shellcheck disable=SC2034
KEYMAP="${_INSTALL_KEYMAP:-us}"
SYSCTL_PROFILE="${_INSTALL_SYSCTL_PROFILE:-${INSTALL_SYSCTL_PROFILE:-security}}"

# --- Other Variables ---
RULES_URL='https://raw.githubusercontent.com/schm1d/AwesomeArchLinux/refs/heads/main/utils/auditd-attack.rules'
LOCAL_RULES_FILE="/etc/audit/rules.d/auditd-attack.rules"
SSH_CONFIG_FILE="/home/$USERNAME/.ssh/config"
SSH_KEY_TYPE="ed25519"
SSH_KEY_FILE="/home/$USERNAME/.ssh/id_$SSH_KEY_TYPE"

CPU_VENDOR_ID=$(lscpu | awk -F: '/Vendor ID/{gsub(/^[ \t]+/, "", $2); print $2}')

###############################################################################
# BASIC SYSTEM CONFIGURATION
###############################################################################

pacman-key --init
pacman-key --populate archlinux

# Tell GnuPG dirmngr to skip IPv6 — we disable IPv6 in sysctl, and the
# default IPv6-first keyserver lookup logs "Network is unreachable"
# noise on every key fetch before falling back to IPv4.
mkdir -p /etc/gnupg
cat > /etc/gnupg/dirmngr.conf <<'EOF'
disable-ipv6
honor-http-proxy
EOF

echo -e "${BBlue}Removing unnecessary users and groups...${NC}"
groupdel games 2>/dev/null || true

# --- Timezone & Locale (set once) ---
echo -e "${BBlue}Setting timezone to $TIMEZONE...${NC}"
ln -sf "/usr/share/zoneinfo/$TIMEZONE" /etc/localtime
hwclock --systohc --utc

echo -e "${BBlue}Setting up locale to $LOCALE...${NC}"
sed -i "s/#$LOCALE/$LOCALE/" /etc/locale.gen
locale-gen
echo "LANG=$LOCALE" > /etc/locale.conf
export LANG="$LOCALE"

echo -e "${BBlue}Setting up console keymap and fonts...${NC}"
cat > /etc/vconsole.conf <<VCEOF
KEYMAP=$KEYMAP
FONT=lat9w-16
FONT_MAP=8859-1_to_uni
VCEOF

# --- X11 keyboard configuration ---
# Translate vconsole keymap to X11 layout using systemd's kbd-model-map.
vconsole_to_x11() {
    local keymap="$1"
    local layout="" variant="" line
    local map_file="/usr/share/systemd/kbd-model-map"

    if [[ -f "$map_file" ]]; then
        # Match the first column (console keymap) exactly
        line=$(awk -v km="$keymap" '$1 == km { print; exit }' "$map_file")
        if [[ -n "$line" ]]; then
            layout=$(echo "$line" | awk '{print $3}')
            variant=$(echo "$line" | awk '{print $4}')
            # kbd-model-map uses "" for empty variant
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

    echo "$layout" "$variant"
}

echo -e "${BBlue}Writing X11 keyboard configuration...${NC}"
read -r X11_LAYOUT X11_VARIANT <<< "$(vconsole_to_x11 "$KEYMAP")"
install -d /etc/X11/xorg.conf.d
{
    echo 'Section "InputClass"'
    echo '    Identifier "system-keyboard"'
    echo '    MatchIsKeyboard "on"'
    echo "    Option \"XkbLayout\" \"$X11_LAYOUT\""
    echo '    Option "XkbModel" "pc105"'
    if [[ -n "$X11_VARIANT" ]]; then
        echo "    Option \"XkbVariant\" \"$X11_VARIANT\""
    fi
    echo '    Option "XkbOptions" ""'
    echo 'EndSection'
} > /etc/X11/xorg.conf.d/00-keyboard.conf

# --- Hostname ---
echo -e "${BBlue}Setting hostname...${NC}"
hostnamectl set-hostname "$HOSTNAME"
echo "$HOSTNAME" > /etc/hostname

echo -e "${BBlue}Configuring /etc/hosts...${NC}"
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

chmod 644 /etc/hosts
chown root:root /etc/hosts

###############################################################################
# NETWORK CONFIGURATION
###############################################################################

echo -e "${BBlue}Configuring network parameters...${NC}"
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
UseDNS=no  # Don't accept DNS from DHCP
UseDomains=no
UseNTP=no  # Use our own NTP configuration

[DHCPv6]
UseDNS=no
UseNTP=no

[IPv6AcceptRA]
UseDNS=no
DHCPv6Client=no
EOF

# Configure NetworkManager with privacy settings (if installed)
if [ -d /etc/NetworkManager ]; then
    echo -e "${BBlue}Configuring NetworkManager privacy...${NC}"
    mkdir -p /etc/NetworkManager/conf.d/
    cat > /etc/NetworkManager/conf.d/00-privacy.conf <<EOF
[main]
systemd-resolved=true

[connection]
# VPS typically uses static MAC, but keep privacy for safety
connection.stable-id=\${CONNECTION}/\${BOOT}
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

echo -e "${BBlue}Pointing /etc/resolv.conf at the resolved stub...${NC}"
# Drop any previous immutable flag from a prior run before overwriting.
chattr -i /etc/resolv.conf 2>/dev/null || true
# Inside arch-chroot, /etc/resolv.conf is bind-mounted from the host.
# Unmount it first so we can replace it with our symlink.
umount /etc/resolv.conf 2>/dev/null || true
rm -f /etc/resolv.conf
ln -s /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf

echo -e "${BBlue}Enabling systemd-resolved...${NC}"
systemctl daemon-reload
# vps-chroot.sh is invoked from two contexts:
#   1. vps-install.sh via arch-chroot — no running systemd, only enable.
#   2. vps-harden.sh on a live system — start/restart is expected.
# _INSTALL_TYPE=vps-harden is exported by vps-harden.sh; use it to pick
# the right activation verb.
if [ "${_INSTALL_TYPE:-}" = "vps-harden" ]; then
    systemctl enable --now systemd-resolved
    # Ensure NetworkManager picks up the new dns= backend if it is running.
    if systemctl is-active --quiet NetworkManager 2>/dev/null; then
        systemctl restart NetworkManager
    fi
else
    systemctl enable systemd-resolved
fi

# Prefer IPv4 over IPv6 — many VPS providers lack IPv6 routing, and
# sshd is configured with AddressFamily inet (IPv4 only)
echo -e "${BBlue}Configuring IPv4 preference...${NC}"
echo "precedence ::ffff:0:0/96 100" >> /etc/gai.conf

echo -e "${BBlue}DNS-over-TLS configuration completed!${NC}"

###############################################################################
# FIREWALL (NFTABLES)
###############################################################################

echo -e "${BBlue}Configuring firewall with nftables...${NC}"
pacman -S --noconfirm nftables

cat <<'EOF' > /etc/nftables.conf
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;

        # Allow loopback
        iif lo accept

        # Allow established connections
        ct state established,related accept

        # Drop invalid connections
        ct state invalid drop

        # Allow SSH with rate limiting (burst allows legitimate reconnects)
        tcp dport $SSH_PORT ct state new limit rate 4/minute burst 8 packets accept

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

sed -i "s/\$SSH_PORT/$SSH_PORT/g" /etc/nftables.conf

systemctl enable nftables.service

# Start nftables — may fail on VPS kernels without nf_tables module support
if nft list ruleset &>/dev/null; then
    systemctl start nftables.service
    echo -e "${BGreen}Firewall configuration with nftables completed.${NC}"
elif command -v iptables &>/dev/null && iptables -L -n &>/dev/null; then
    # nft backend unavailable but iptables works (legacy kernel module present)
    echo -e "${BYellow}WARNING: nftables kernel module not available — falling back to iptables.${NC}"
    systemctl disable nftables.service 2>/dev/null || true

    # Flush existing rules and set default deny
    iptables -F
    iptables -X
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT

    # Allow loopback
    iptables -A INPUT -i lo -j ACCEPT

    # Allow established connections
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Drop invalid connections
    iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

    # Allow SSH with rate limiting (matches nftables: 4/min burst 8)
    iptables -A INPUT -p tcp --dport "$SSH_PORT" -m conntrack --ctstate NEW \
        -m limit --limit 4/min --limit-burst 8 -j ACCEPT
    iptables -A INPUT -p tcp --dport "$SSH_PORT" -m conntrack --ctstate NEW -j DROP

    # Persist rules
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/iptables.rules
    systemctl enable iptables.service 2>/dev/null || true

    echo -e "${BGreen}Firewall configured with iptables (legacy fallback).${NC}"
else
    echo -e "${BYellow}WARNING: Neither nftables nor iptables is functional on this kernel.${NC}"
    echo -e "${BYellow}nftables is enabled and will start if the kernel supports it after reboot.${NC}"
    echo -e "${BYellow}You may need to configure firewall rules manually once the system is booted.${NC}"
fi

###############################################################################
# LOGGING & ENTROPY
###############################################################################

echo -e "${BBlue}Installing and configuring logrotate...${NC}"
pacman -S --noconfirm logrotate
cat <<EOF > /etc/logrotate.d/custom
/var/log/*.log {
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
pacman -S --noconfirm rng-tools
systemctl enable rngd

echo -e "${BBlue}Installing file security utility pax-utils & arch-audit...${NC}"
pacman -S --noconfirm arch-audit pax-utils

echo -e "${BBlue}Installing lynis...${NC}"
pacman -S --noconfirm lynis

###############################################################################
# CLAMAV CONFIGURATION
###############################################################################

echo -e "${BBlue}Installing and configuring ClamAV...${NC}"
pacman -S --noconfirm clamav

echo -e "${BBlue}Configuring ClamAV...${NC}"

if [ ! -f /etc/clamav/freshclam.conf ]; then
  clamconf -g freshclam.conf > freshclam.conf
  mv freshclam.conf /etc/clamav/freshclam.conf
fi

if [ ! -f /etc/clamav/clamd.conf ]; then
  clamconf -g clamd.conf > clamd.conf
  mv clamd.conf /etc/clamav/clamd.conf
fi

if [ ! -f /etc/clamav/clamav-milter.conf ]; then
  clamconf -g clamav-milter.conf > clamav-milter.conf
  mv clamav-milter.conf /etc/clamav/clamav-milter.conf
fi

CLAMD_CONF="/etc/clamav/clamd.conf"

ensure_clamd_option() {
  local KEY="$1"
  local VALUE="$2"
  if grep -Eq "^#?\s*${KEY}\s" "$CLAMD_CONF"; then
    sed -i "s|^#\?\s*${KEY}.*|${KEY} ${VALUE}|" "$CLAMD_CONF"
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
systemctl start clamav-freshclam.service || true
freshclam || true

systemctl enable clamav-daemon.service
systemctl start clamav-daemon.service || true

echo -e "${BBlue}ClamAV configuration completed!${NC}"

###############################################################################
# RKHUNTER
###############################################################################

echo -e "${BBlue}Installing and configuring rkhunter...${NC}"
pacman -S --noconfirm rkhunter

rkhunter --propupd
cat <<EOF > /etc/systemd/system/rkhunter-check.service
[Unit]
Description=Run rkhunter daily check
[Service]
Type=oneshot
ExecStart=/usr/bin/rkhunter --check --cronjob --rwo
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
pacman -S --noconfirm arpwatch

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
sed -i '/^PASS_MIN_DAYS/c\PASS_MIN_DAYS 2' /etc/login.defs

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
grep -qxF 'install dccp /bin/false' /etc/modprobe.d/disable-protocols.conf 2>/dev/null || echo "install dccp /bin/false" >> /etc/modprobe.d/disable-protocols.conf
grep -qxF 'install sctp /bin/false' /etc/modprobe.d/disable-protocols.conf 2>/dev/null || echo "install sctp /bin/false" >> /etc/modprobe.d/disable-protocols.conf
grep -qxF 'install rds /bin/false' /etc/modprobe.d/disable-protocols.conf 2>/dev/null || echo "install rds /bin/false" >> /etc/modprobe.d/disable-protocols.conf
grep -qxF 'install tipc /bin/false' /etc/modprobe.d/disable-protocols.conf 2>/dev/null || echo "install tipc /bin/false" >> /etc/modprobe.d/disable-protocols.conf

# Disable core dumps
echo -e "${BBlue}Disabling core dump...${NC}"
grep -qxF '* hard core 0' /etc/security/limits.conf || echo "* hard core 0" >> /etc/security/limits.conf

###############################################################################
# NTP — chrony only (no conflict with ntpd)
###############################################################################

echo -e "${BBlue}Installing chrony for NTP...${NC}"
pacman -S --noconfirm chrony
systemctl enable chronyd

###############################################################################
# SYSTEM MONITORING & AUDITING
###############################################################################

echo -e "${BBlue}Enabling sysstat...${NC}"
pacman -S --noconfirm sysstat
systemctl enable sysstat

echo -e "${BBlue}Enabling auditd...${NC}"
pacman -S --noconfirm audit

if ! command -v wget &> /dev/null; then
    echo "wget could not be found, please install wget and try again."
    exit 1
fi

echo "Downloading auditd rules from $RULES_URL..."
wget -O "$LOCAL_RULES_FILE" "$RULES_URL"

if [ $? -ne 0 ]; then
    echo "Failed to download auditd rules."
    exit 1
else
    echo "Auditd rules downloaded successfully."
fi

systemctl restart auditd || true
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
pacman -S --noconfirm fail2ban

cat <<EOF > /etc/fail2ban/jail.d/sshd.conf
[sshd]
enabled = true
port    = ${SSH_PORT}
maxretry = 5
# OpenSSH 10.x splits into sshd, sshd-auth, sshd-session — match all via journal
backend = systemd
journalmatch = _SYSTEMD_UNIT=sshd.service
EOF

systemctl enable fail2ban

###############################################################################
# JOURNALD
###############################################################################

echo -e "${BBlue}Improving journald configuration...${NC}"
cat <<EOF > /etc/systemd/journald.conf
[Journal]
Storage=persistent
Compress=yes
Seal=yes
SplitMode=login
ForwardToSyslog=no
SystemMaxUse=200M
EOF
systemctl restart systemd-journald

###############################################################################
# SUDO HARDENING
###############################################################################

echo -e "${BBlue}Hardening sudo...${NC}"
groupadd -r proc 2>/dev/null || true
groupadd sudo 2>/dev/null || true

# Write sudoers atomically via temp file + visudo validation
cat > /tmp/sudoers.new << 'SUDOERS_EOF'
# Hardened sudoers — generated by vps-chroot.sh

Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Defaults !rootpw
Defaults umask=077
Defaults editor=/usr/bin/vim
Defaults env_reset
Defaults env_reset,env_keep="COLORS DISPLAY HOSTNAME HISTSIZE INPUTRC KDEDIR LS_COLORS"
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
Defaults requiretty
Defaults logfile=/var/log/sudo.log
Defaults log_input, log_output

root ALL=(ALL:ALL) ALL
%sudo ALL=(ALL) ALL

@includedir /etc/sudoers.d
SUDOERS_EOF

# Validate before installing
if visudo -c -f /tmp/sudoers.new; then
    install -m 0440 -o root -g root /tmp/sudoers.new /etc/sudoers
    echo -e "${BGreen}Sudoers validated and installed successfully.${NC}"
else
    echo -e "${BRed}ERROR: sudoers validation failed! Keeping original file.${NC}" >&2
fi
rm -f /tmp/sudoers.new

###############################################################################
# ARCH-AUDIT
###############################################################################

echo -e "${BBlue}Installing arch-audit for vulnerability scanning...${NC}"
pacman -S --noconfirm arch-audit

cat <<EOF > /usr/local/bin/arch-audit-check
#!/bin/bash
arch-audit | tee /var/log/arch-audit.log
EOF
chmod +x /usr/local/bin/arch-audit-check

cat <<EOF > /etc/systemd/system/arch-audit.service
[Unit]
Description=Arch Audit Service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/arch-audit-check
EOF

cat <<EOF > /etc/systemd/system/arch-audit.timer
[Unit]
Description=Run arch-audit daily

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl enable arch-audit.timer
systemctl start arch-audit.timer

###############################################################################
# USER CREATION
###############################################################################

# Ensure zsh is installed (installed by pacstrap in vps-install.sh, may be missing on live VPS)
if ! command -v zsh &>/dev/null; then
    echo -e "${BBlue}Installing zsh...${NC}"
    pacman -S --noconfirm zsh zsh-completions
fi

echo -e "${BBlue}Adding the user $USERNAME...${NC}"
if ! id -u "$USERNAME" >/dev/null 2>&1; then
  useradd -m -G sudo,wheel,uucp -s /bin/zsh "$USERNAME"
  chown "$USERNAME:$USERNAME" /home/"$USERNAME"
  chmod 700 /home/"$USERNAME"                   # Private home (not world-readable)
  echo -e "${BBlue}User $USERNAME created.${NC}"
else
    echo "User $USERNAME already exists." >&2
fi

# Nano config
echo "set backup" >> /home/"$USERNAME"/.nanorc
echo "set backupdir \"~/.cache/nano/backups/\"" >> /home/"$USERNAME"/.nanorc
chmod 600 /home/"$USERNAME"/.nanorc

# Set passwords
set +e
while true; do
    echo -e "${BBlue}Setting password for user $USERNAME...${NC}"
    echo -e "${BBlue}Password should be at least 12 characters long, contain 1 symbol, 1 number, upper and lowercase letters.${NC}"
    passwd "$USERNAME"
    if [ $? -eq 0 ]; then
        break
    else
        echo -e "${BBlue}Password change failed. Please try again.${NC}"
        sleep 1
    fi
done

while true; do
    echo -e "${BBlue}Setting root password...${NC}"
    passwd root
    if [ $? -eq 0 ]; then
        break
    else
        echo -e "${BBlue}Root password change failed. Please try again.${NC}"
        sleep 1
    fi
done
set -e

# Install nano syntax highlighting (packaged version)
echo -e "${BBlue}Installing nano syntax highlighting...${NC}"
pacman -S --noconfirm nano-syntax-highlighting

echo "set constantshow" >> /home/"$USERNAME"/.nanorc
echo "set locking" >> /home/"$USERNAME"/.nanorc
echo "set nohelp" >> /home/"$USERNAME"/.nanorc
echo "set nonewlines" >> /home/"$USERNAME"/.nanorc
echo "set nowrap" >> /home/"$USERNAME"/.nanorc
echo "set minibar" >> /home/"$USERNAME"/.nanorc
echo "set zap" >> /home/"$USERNAME"/.nanorc
echo "set linenumbers" >> /home/"$USERNAME"/.nanorc
echo "set tabsize 4" >> /home/"$USERNAME"/.nanorc
echo "set tabstospaces" >> /home/"$USERNAME"/.nanorc
echo "set wordbounds punct,alnum" >> /home/"$USERNAME"/.nanorc
echo "set regexp ^[A-Za-z_][A-Za-z0-9_]*$" >> /home/"$USERNAME"/.nanorc

###############################################################################
# SSH CONFIGURATION
###############################################################################

echo -e "${BBlue}Staging SSH access for $USERNAME (authorized_keys first)...${NC}"

configure_ssh() {
  mkdir -p "/home/$USERNAME/.ssh"

  if [ ! -f "$SSH_KEY_FILE" ]; then
    echo -e "${BBlue}Generating a new SSH key pair ($SSH_KEY_TYPE)...${NC}"
    ssh-keygen -t "$SSH_KEY_TYPE" -C "$USERNAME@$HOSTNAME" -f "$SSH_KEY_FILE" -q -N ""
  else
    echo -e "${BBlue}SSH key ($SSH_KEY_FILE) already exists.${NC}"
  fi

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

  echo -e "${BBlue}Hashing known_hosts file...${NC}"
  ssh-keygen -H -f "/home/$USERNAME/.ssh/known_hosts" 2>/dev/null || true

  touch "/home/$USERNAME/.ssh/authorized_keys"
  if [[ -n "$SSH_PUBKEY" ]]; then
      echo "$SSH_PUBKEY" >> "/home/$USERNAME/.ssh/authorized_keys"
      echo -e "${BGreen}SSH public key installed for $USERNAME.${NC}"
  else
      echo -e "${BYellow}No SSH public key provided — add one manually before disconnecting.${NC}"
  fi
  chmod 700 "/home/$USERNAME/.ssh"
  chmod 600 "/home/$USERNAME/.ssh/authorized_keys"
  chown -R "$USERNAME:$USERNAME" "/home/$USERNAME"
}

configure_ssh

# Now harden sshd — authorized_keys is already in place, so disabling
# password auth won't cause a lockout.
echo -e "${BBlue}Hardening sshd on port $SSH_PORT...${NC}"
/ssh.sh -u "$USERNAME" -p "$SSH_PORT"
shred -u /ssh.sh 2>/dev/null || true

sleep 2

# SSH key rotation script (FIXED: private key chmod 600 not overwritten)
echo -e "${BBlue}Setting up SSH key rotation...${NC}"
cat <<EOF > /usr/local/bin/rotate-ssh-keys.sh
#!/bin/bash
AUTH_KEYS="/home/$USERNAME/.ssh/authorized_keys"

# Save old public key before rotation
OLD_PUBKEY=""
if [ -f "$SSH_KEY_FILE.pub" ]; then
    OLD_PUBKEY=\$(cat "$SSH_KEY_FILE.pub")
fi

# Generate new key pair
ssh-keygen -t "$SSH_KEY_TYPE" -f "$SSH_KEY_FILE" -q -N "" -C "$USERNAME@$HOSTNAME-\$(date +%Y%m%d)"
chown "$USERNAME:$USERNAME" "$SSH_KEY_FILE" "$SSH_KEY_FILE.pub"
chmod 600 "$SSH_KEY_FILE"
chmod 644 "$SSH_KEY_FILE.pub"

# Update authorized_keys: remove old pubkey, add new one
if [ -f "\$AUTH_KEYS" ]; then
    if [ -n "\$OLD_PUBKEY" ]; then
        grep -vF "\$OLD_PUBKEY" "\$AUTH_KEYS" > "\$AUTH_KEYS.tmp" || true
        mv "\$AUTH_KEYS.tmp" "\$AUTH_KEYS"
    fi
    cat "$SSH_KEY_FILE.pub" >> "\$AUTH_KEYS"
    chown "$USERNAME:$USERNAME" "\$AUTH_KEYS"
    chmod 600 "\$AUTH_KEYS"
fi
EOF
chmod +x /usr/local/bin/rotate-ssh-keys.sh
echo "0 0 1 */3 * root /usr/local/bin/rotate-ssh-keys.sh" >> /etc/crontab

sleep 1

###############################################################################
# COMPILER HARDENING
###############################################################################

echo -e "${BBlue}Applying hardened compiler flags...${NC}"
sed -i '/^CFLAGS=/ s/"$/ -fstack-protector-strong -D_FORTIFY_SOURCE=2"/' /etc/makepkg.conf
sed -i '/^CXXFLAGS=/ s/"$/ -fstack-protector-strong -D_FORTIFY_SOURCE=2"/' /etc/makepkg.conf
sed -i '/^LDFLAGS=/ s/"$/ -Wl,-z,relro,-z,now"/' /etc/makepkg.conf
sed -i '/^OPTIONS=/ s/!/!pie /' /etc/makepkg.conf

echo -e "${BBlue}Restricting access to compilers using a 'compilers' group...${NC}"
groupadd compilers 2>/dev/null || true
usermod -aG compilers "$USERNAME"
for compiler in gcc g++ clang make as ld; do
    compiler_path=$(command -v "$compiler" 2>/dev/null) || continue
    chown root:compilers "$compiler_path"
    chmod 750 "$compiler_path"
done

# Set default ACLs on home directories
echo -e "${BBlue}Setting default ACLs on root and home directory${NC}"
setfacl -d -m u::rwx,g::---,o::--- ~
setfacl -d -m u::rwx,g::---,o::--- "/home/$USERNAME"

###############################################################################
# GRUB SETUP (NO ENCRYPTION — VPS)
###############################################################################

# Skip GRUB/mkinitcpio on live systems — bootloader is already configured
# _INSTALL_TYPE is set via env export, INSTALL_TYPE via /root/.install-env
if [[ "${_INSTALL_TYPE:-${INSTALL_TYPE:-}}" != "vps-harden" ]]; then

echo -e "${BBlue}Setting up GRUB (no encryption for VPS)...${NC}"
pacman -S grub efibootmgr os-prober --noconfirm

# mkinitcpio — simple, no encrypt/lvm hooks needed
echo -e "${BBlue}Adjusting /etc/mkinitcpio.conf...${NC}"
sed -i "s|^HOOKS=.*|HOOKS=(base udev autodetect keyboard keymap modconf block filesystems fsck)|g" /etc/mkinitcpio.conf
mkinitcpio -p linux

# Kernel security boot params (no LUKS-related params)
echo -e "${BBlue}Hardening kernel boot options...${NC}"
GRUBSEC="\"slab_nomerge init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 pti=on randomize_kstack_offset=on vsyscall=none quiet loglevel=3 console=tty0 console=ttyS0,115200n8\""

sed -i "s|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT=${GRUBSEC}|" /etc/default/grub
sed -i "s|^GRUB_CMDLINE_LINUX=.*|GRUB_CMDLINE_LINUX=\"\"|" /etc/default/grub

# Enable serial console in GRUB for VPS provider console access
cat >> /etc/default/grub <<EOF

# VPS serial console support
GRUB_TERMINAL="console serial"
GRUB_SERIAL_COMMAND="serial --speed=115200 --unit=0 --word=8 --parity=no --stop=1"
EOF

# CPU Microcode
echo -e "${BBlue}Installing CPU microcode...${NC}"
if [[ "$CPU_VENDOR_ID" =~ "GenuineIntel" ]]; then
    pacman -S --noconfirm intel-ucode 2>/dev/null || true
elif [[ "$CPU_VENDOR_ID" =~ "AuthenticAMD" ]]; then
    pacman -S --noconfirm amd-ucode 2>/dev/null || true
fi

# NOTE: GPU detection skipped — VPS doesn't have physical GPUs

# Install and configure GRUB
echo -e "${BBlue}Installing GRUB...${NC}"
mkdir -p /boot/grub

if [ -d "/sys/firmware/efi/efivars" ]; then
    grub-install --target=x86_64-efi --bootloader-id=GRUB --efi-directory=/efi --recheck
else
    grub-install --target=i386-pc "$DISK" --recheck
fi

# GRUB password
set +e
GRUB_PASS_TMPFILE=$(mktemp /tmp/grubpass.XXXXXX)
chmod 600 "$GRUB_PASS_TMPFILE"
while true; do
  echo -e "${BBlue}Setting GRUB password...${NC}"
  grub-mkpasswd-pbkdf2 | tee "$GRUB_PASS_TMPFILE"
  GRUB_PASS=$(grep 'grub.pbkdf2' "$GRUB_PASS_TMPFILE" | awk '{print $NF}')
  rm -f "$GRUB_PASS_TMPFILE"
  if [[ -n "$GRUB_PASS" ]]; then
     break
  else
      echo -e "${BBlue}GRUB password generation failed. Please try again.${NC}"
      sleep 1
  fi
done
set -e

cat <<EOF >> /etc/grub.d/40_custom
set superusers="$USERNAME"
password_pbkdf2 "$USERNAME" "$GRUB_PASS"
EOF

grub-mkconfig -o /boot/grub/grub.cfg

else
    echo -e "${BBlue}Skipping GRUB/mkinitcpio (live system — bootloader already configured)${NC}"
fi # end _INSTALL_TYPE guard

###############################################################################
# FILE PERMISSIONS
###############################################################################

echo -e "${BBlue}Setting permissions on config files...${NC}"

chmod 0700 /boot
# /home is traversable (users can reach their own dir) but not listable:
# `ls /home` reveals no usernames to non-root observers. Per-user dirs
# stay 700 via HOME_MODE in login.defs.
chmod 0711 /home
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
chown root:root /etc/issue
chmod 644 /etc/issue
chown root:root /boot/grub/grub.cfg
chmod og-rwx /boot/grub/grub.cfg
chown root:root /etc/sudoers.d/
chmod 750 /etc/sudoers.d
chown -c root:root /etc/sudoers
chmod -c 0440 /etc/sudoers
chmod 02750 /bin/ping
chmod 02750 /usr/bin/w
chmod 02750 /usr/bin/who
chmod 02750 /usr/bin/whereis
chmod 0644 /etc/login.defs

###############################################################################
# LOGIN BANNER
###############################################################################

echo -e "${BBlue}Creating Banner (/etc/issue.net).${NC}"

cat > /etc/issue.net << EOF
Arch Linux \r (\l)

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

###############################################################################
# PAM HARDENING
###############################################################################

echo -e "${BBlue}Removing deprecated pam_tally2.so references...${NC}"
sed -i '/pam_tally2.so/d' /etc/pam.d/system-auth
rm -f /etc/pam.d/common-auth

echo -e "${BBlue}Installing necessary PAM modules...${NC}"
pacman -S --noconfirm pambase pam libpwquality

echo -e "${BBlue}Configuring account lockout policy with pam_faillock...${NC}"
cp /etc/pam.d/system-auth /etc/pam.d/system-auth.bak

sed -i '/^auth.*required.*pam_unix\.so/i auth required pam_faillock.so preauth silent deny=5 unlock_time=900' /etc/pam.d/system-auth
sed -i '/^auth.*include.*system-auth/i auth \[default=die\] pam_faillock.so authfail deny=5 unlock_time=900' /etc/pam.d/system-auth
sed -i '/^account.*required.*pam_unix\.so/a account required pam_faillock.so' /etc/pam.d/system-auth

echo -e "${BBlue}Configuring password quality requirements...${NC}"
cp /etc/security/pwquality.conf /etc/security/pwquality.conf.bak
cat <<EOF > /etc/security/pwquality.conf
minlen = 12
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
difok = 5
enforce_for_root
EOF

if ! grep -q "pam_pwquality.so" /etc/pam.d/system-auth; then
    sed -i '/^password.*required.*pam_unix.so/a password required pam_pwquality.so retry=3' /etc/pam.d/system-auth
fi

###############################################################################
# AUTOMATIC SECURITY UPDATES
###############################################################################

echo -e "${BBlue}Setting up daily package update checks...${NC}"
pacman -S --noconfirm pacman-contrib
cat <<EOF > /etc/systemd/system/pacman-autoupdate.timer
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

[Service]
Type=oneshot
# Sync databases and log available updates without automatically installing them.
ExecStart=/bin/sh -c '/usr/bin/pacman -Sy && /usr/bin/pacman -Qu > /var/log/pacman-updates.log 2>&1 || true'
EOF
systemctl enable pacman-autoupdate.timer

sleep 2

###############################################################################
# SYSTEMD SERVICES HARDENING
###############################################################################

echo -e "${BBlue}Hardening systemd services...${NC}"

harden_systemd_service() {
    local service=$1
    local override_dir="/etc/systemd/system/${service}.d"

    if ! systemctl list-unit-files | grep -q "^${service}"; then
        return
    fi

    mkdir -p "$override_dir"

    cat > "${override_dir}/hardening.conf" <<EOF
[Service]
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
PrivateDevices=yes
DevicePolicy=closed
ProtectProc=invisible
ProcSubset=pid
CapabilityBoundingSet=
AmbientCapabilities=
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
IPAddressDeny=any
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RemoveIPC=yes
RestrictNamespaces=yes
UMask=0077
LimitNOFILE=1024
LimitNPROC=512
EOF
}

# SSH Service
echo -e "${BBlue}Hardening SSH service...${NC}"
mkdir -p /etc/systemd/system/sshd.service.d/
cat > /etc/systemd/system/sshd.service.d/hardening.conf <<'EOF'
[Service]
PrivateTmp=yes
# sshd spawns user shells that need sudo/su and PTY allocation.
# NoNewPrivileges/RestrictSUIDSGID break sudo; PrivateDevices breaks PTYs;
# RemoveIPC destroys shared memory on last session close;
# RestrictNamespaces blocks containers/unshare in SSH sessions.
NoNewPrivileges=no
# sshd spawns interactive user sessions — ProtectSystem/ProtectHome must be
# 'no' or users can't install packages, write to /var, /etc, or /home.
ProtectSystem=no
ProtectHome=no
# ProtectKernel*=yes bind-mounts /run/systemd/inaccessible/dir over
# /usr/lib/modules, /proc/kcore, /proc/kallsyms, /proc/kmsg, /dev/kmsg
# in sshd's mount namespace. PAM-spawned user sessions inherit that
# namespace, breaking modinfo/nvidia-modprobe/DKMS/GTK GSK device probes
# in every SSH login. Must be off on sshd for the same reason
# ProtectSystem and ProtectHome are off here: sshd spawns interactive
# user sessions that need normal kernel-info access.
ProtectKernelTunables=no
ProtectKernelModules=no
ProtectKernelLogs=no
ProtectControlGroups=yes
# AF_NETLINK is required for PAM/auditd communication during session setup.
# Without it, sshd drops connections immediately after authentication.
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
IPAddressAllow=any
IPAddressDeny=
PrivateDevices=no
DevicePolicy=auto
LockPersonality=yes
RestrictRealtime=yes
Restart=on-failure
RestartSec=5s
EOF

# NetworkManager hardening
echo -e "${BBlue}Hardening NetworkManager...${NC}"
mkdir -p /etc/systemd/system/NetworkManager.service.d/
cat > /etc/systemd/system/NetworkManager.service.d/hardening.conf <<'EOF'
[Service]
# RuntimeDirectory= / StateDirectory= make systemd create /run/NetworkManager
# and /var/lib/NetworkManager (with correct ownership) before ExecStart runs.
# Listing them in ReadWritePaths= instead would fail on first boot because
# ProtectSystem=strict bind-mounts every ReadWritePaths= entry, and those
# directories do not yet exist. The remaining ReadWritePaths= entries are
# prefixed with "-" so a missing path is treated as optional rather than a
# namespacing failure (relevant when /etc/resolv.conf is a symlink managed
# by systemd-resolved).
RuntimeDirectory=NetworkManager
StateDirectory=NetworkManager
ProtectSystem=strict
ReadWritePaths=-/etc/NetworkManager -/etc/resolv.conf
ProtectHome=yes
ProtectKernelTunables=no
ProtectKernelModules=no
ProtectControlGroups=yes
ProtectKernelLogs=yes
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_DAC_OVERRIDE CAP_SETUID CAP_SETGID
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
# auditd manages the kernel audit subsystem — it needs broad access to
# /proc, /sys/kernel, and netlink sockets. Heavy sandboxing breaks it.
ProtectSystem=full
ProtectHome=yes
ProtectControlGroups=yes
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
TasksMax=16
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
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_READ_SEARCH
NoNewPrivileges=no
PrivateTmp=yes
PrivateDevices=yes
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
mkdir -p /etc/systemd/system/chronyd.service.d/
cat > /etc/systemd/system/chronyd.service.d/hardening.conf <<'EOF'
[Service]
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/chrony /var/log/chrony /run
ProtectKernelTunables=no
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=no
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
CapabilityBoundingSet=CAP_SYS_TIME CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_SYS_TIME
SystemCallFilter=@system-service @clock
SystemCallErrorNumber=EPERM
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
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

echo -e "${BGreen}Systemd services hardening completed!${NC}"

sleep 2

###############################################################################
# SYSCTL HARDENING
###############################################################################

harden_sysctl() {
  echo -e "${BBlue}Applying sysctl profile: ${SYSCTL_PROFILE}...${NC}"

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

sleep 2

echo -e "${BGreen}VPS chroot configuration completed! You can reboot the system now.${NC}"
shred -u /vps-chroot.sh 2>/dev/null || true
exit
