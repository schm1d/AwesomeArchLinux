#!/usr/bin/env bash

# Description: This is the chroot script for Arch Linux installation.
# Author: Bruno Schmid @brulliant
# LinkedIn: https://www.linkedin.com/in/schmidbruno/

set -euo pipefail
source /root/.install-env || { echo "Failed to source /root/.install-env"; exit 1; }

# Set up the variables
BBlue='\033[1;34m'
BRed='\033[1;31m'
BGreen='\033[1;32m'
BYellow='\033[1;33m'
NC='\033[0m'

# Ensure the script is run as root
if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root" >&2
  exit 1
fi

# --- These values MUST be replaced by archinstall.sh ---
DISK="${_INSTALL_DISK}"       # Example: /dev/sda or /dev/nvme0n1
USERNAME="${_INSTALL_USER}" # Example: myuser
HOSTNAME="${_INSTALL_HOST}" # Example: myhostname
TIMEZONE="Europe/Zurich"
LOCALE="en_US.UTF-8"
LUKS_KEYS='/etc/luksKeys/boot.key' # Location of the root partition key
SSH_PORT=22
SSH_PUBKEY="${_INSTALL_SSH_PUBKEY:-}"
# shellcheck disable=SC2034  # Referenced in GRUB config and comments
CRYPT_NAME="crypt_lvm"     # must match luksOpen in archinstall.sh
LVM_NAME="lvm_arch"
INSTALL_TPM="${INSTALL_TPM:-false}"

# --- Other Variables ---
RULES_URL='https://raw.githubusercontent.com/schm1d/AwesomeArchLinux/refs/heads/main/utils/auditd-attack.rules'
LOCAL_RULES_FILE="/etc/audit/rules.d/auditd-attack.rules"
SSH_CONFIG_FILE="/home/$USERNAME/.ssh/config"
SSH_KEY_TYPE="ed25519"
SSH_KEY_FILE="/home/$USERNAME/.ssh/id_$SSH_KEY_TYPE"

# --- Partition Handling ---
if [[ "$DISK" =~ [0-9]$ ]]; then
    PART_SUFFIX="p"
else
    PART_SUFFIX=""
fi

#PARTITION1="${DISK}${PART_SUFFIX}1"
#PARTITION2="${DISK}${PART_SUFFIX}2"
PARTITION3="${DISK}${PART_SUFFIX}3"

LUKS_UUID=$(cryptsetup luksUUID "$PARTITION3")

CPU_VENDOR_ID=$(lscpu | awk -F: '/Vendor ID/{gsub(/^[ \t]+/, "", $2); print $2}')

# --- Basic System Configuration ---
pacman-key --init
pacman-key --populate archlinux

echo -e "${BBlue}Removing unnecessary users and groups...${NC}"
# games is a group on Arch, not a user — userdel not needed
groupdel games 2>/dev/null || true

timedatectl set-timezone "$TIMEZONE"
hwclock --systohc --utc

sed -i "s/#$LOCALE/$LOCALE/" /etc/locale.gen
locale-gen
echo "LANG=$LOCALE" > /etc/locale.conf
export LANG="$LOCALE"

echo 'KEYMAP=de_CH-latin1' > /etc/vconsole.conf
echo 'FONT=lat9w-16' >> /etc/vconsole.conf
echo 'FONT_MAP=8859-1_to_uni' >> /etc/vconsole.conf

# Set hostname
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

# Set proper permissions
chmod 644 /etc/hosts
chown root:root /etc/hosts

echo -e "${BBlue}Configuring network parameters...${NC}"
# Create networkd configuration for better network management
mkdir -p /etc/systemd/network/

# Configure network hardening via networkd
cat > /etc/systemd/network/20-wired.network <<EOF
[Match]
Name=en*
Name=eth*

[Network]
DHCP=yes
DNSSEC=yes
DNSOverTLS=no  # We use Stubby for this
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
# Use systemd-resolved
systemd-resolved=true

[connection]
# Generate random MAC addresses for privacy
wifi.cloned-mac-address=random
ethernet.cloned-mac-address=random
connection.stable-id=\${CONNECTION}/\${BOOT}
EOF
fi


echo -e "${BBlue}Installing Stubby for DNS-over-TLS...${NC}"
pacman -S --noconfirm dnssec-anchors stubby

echo -e "${BBlue}Configuring Stubby for secure DNS...${NC}"
cat <<EOF > /etc/stubby/stubby.yml
# Stubby configuration for DNS-over-TLS with privacy focus
resolution_type: GETDNS_RESOLUTION_STUB
dns_transport_list:
  - GETDNS_TRANSPORT_TLS
tls_authentication: GETDNS_AUTHENTICATION_REQUIRED
tls_query_padding_blocksize: 128
edns_client_subnet_private: 1
dnssec_return_status: GETDNS_EXTENSION_TRUE
appdata_dir: "/var/cache/stubby"
round_robin_upstreams: 1
idle_timeout: 10000
tls_connection_retries: 5
tls_backoff_time: 900
timeout: 2000

# Local listening addresses
listen_addresses:
  - 127.0.0.1@5353
  - ::1@5353

# DNS servers (privacy-focused order)
upstream_recursive_servers:
  # Quad9 - Blocks malicious domains, no logging
  - address_data: 9.9.9.9
    tls_auth_name: "dns.quad9.net"
    tls_port: 853
  - address_data: 149.112.112.112
    tls_auth_name: "dns.quad9.net"
    tls_port: 853
  # Quad9 IPv6
  - address_data: 2620:fe::fe
    tls_auth_name: "dns.quad9.net"
    tls_port: 853
    
  # Cloudflare - Fast, decent privacy policy
  - address_data: 1.1.1.1
    tls_auth_name: "cloudflare-dns.com"
    tls_port: 853
  - address_data: 1.0.0.1
    tls_auth_name: "cloudflare-dns.com"
    tls_port: 853
  # Cloudflare IPv6
  - address_data: 2606:4700:4700::1111
    tls_auth_name: "cloudflare-dns.com"
    tls_port: 853
    
  # Google - As fallback only
  - address_data: 8.8.8.8
    tls_auth_name: "dns.google"
    tls_port: 853
  - address_data: 8.8.4.4
    tls_auth_name: "dns.google"
    tls_port: 853
EOF

echo -e "${BBlue}Setting up Stubby cache directory...${NC}"
useradd -r -s /usr/bin/nologin stubby 2>/dev/null || true
mkdir -p /var/cache/stubby
chown stubby:stubby /var/cache/stubby
chmod 750 /var/cache/stubby

# Configure systemd-resolved to use Stubby
echo -e "${BBlue}Configuring systemd-resolved to use Stubby...${NC}"
mkdir -p /etc/systemd/resolved.conf.d/
cat <<EOF > /etc/systemd/resolved.conf.d/dns_over_tls.conf
[Resolve]
# Use Stubby as the only DNS resolver
DNS=127.0.0.1#5353
FallbackDNS=::1#5353
Domains=~.
DNSSEC=allow-downgrade
DNSOverTLS=no
MulticastDNS=no
LLMNR=no
Cache=yes
DNSStubListener=yes
ReadEtcHosts=yes
EOF

# Ensure proper service ordering
echo -e "${BBlue}Configuring service dependencies...${NC}"
mkdir -p /etc/systemd/system/systemd-resolved.service.d/
cat <<EOF > /etc/systemd/system/systemd-resolved.service.d/stubby.conf
[Unit]
After=stubby.service
Wants=stubby.service

[Service]
Restart=on-failure
RestartSec=5
EOF

echo -e "${BBlue}Setting up resolv.conf...${NC}"
# In chroot environment, resolv.conf handling is tricky
# Just create a temporary one for chroot operations
if [ -e /etc/resolv.conf ]; then
    mv -f /etc/resolv.conf /etc/resolv.conf.old 2>/dev/null || true
fi

# Create temporary resolv.conf for chroot
cat > /etc/resolv.conf <<EOF
# Temporary resolv.conf for chroot
nameserver 9.9.9.9
nameserver 1.1.1.1
EOF

# Create post-boot fix script
cat > /usr/local/bin/fix-resolv-conf.sh <<'RESOLV_SCRIPT'
#!/bin/bash
# Fix resolv.conf symlink after first boot
if [ -f /etc/resolv.conf ] && [ ! -L /etc/resolv.conf ]; then
    rm -f /etc/resolv.conf
fi
if [ ! -e /etc/resolv.conf ]; then
    ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
fi
RESOLV_SCRIPT
chmod +x /usr/local/bin/fix-resolv-conf.sh

# Create oneshot service for first boot
cat > /etc/systemd/system/fix-resolv-conf.service <<EOF
[Unit]
Description=Fix resolv.conf symlink
After=systemd-resolved.service
Before=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/fix-resolv-conf.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl enable fix-resolv-conf.service

# Reload systemd and enable services
echo -e "${BBlue}Enabling DNS services...${NC}"
systemctl daemon-reload
systemctl enable stubby
systemctl enable systemd-resolved

# Start services (will work after chroot)
systemctl start stubby 2>/dev/null || true
systemctl start systemd-resolved 2>/dev/null || true

# Prefer IPv4 over IPv6 — many VPS providers lack IPv6 routing, and
# sshd is configured with AddressFamily inet (IPv4 only)
echo -e "${BBlue}Configuring IPv4 preference...${NC}"
echo "precedence ::ffff:0:0/96 100" >> /etc/gai.conf

echo -e "${BBlue}DNS-over-TLS configuration completed!${NC}"

echo -e "${BBlue}Configuring firewall with nftables...${NC}"

pacman -S --noconfirm nftables

cat <<EOF > /etc/nftables.conf
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

        # Allow SSH with rate limiting
        tcp dport ${SSH_PORT} ct state new limit rate 2/minute accept

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

systemctl enable nftables.service

echo -e "${BBlue}Firewall configuration with nftables completed.${NC}"

echo -e "${BBlue}Installing and configuring logrotate...${NC}"
pacman -S --noconfirm logrotate
echo -e "${BBlue}Enhancing logging configuration...${NC}"
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
# NOTE: haveged is NOT installed — rng-tools is sufficient and haveged is
# considered insecure in VM environments. Modern kernels (5.6+) have adequate
# entropy from the jitterentropy module.

echo -e "${BBlue}Installing file security utility pax-utils & arch-audit...${NC}"
pacman -S --noconfirm arch-audit pax-utils

echo -e "${BBlue}Installing lynis...${NC}"
pacman -S --noconfirm lynis

###############################################################################
# CLAMAV CONFIGURATION
###############################################################################

# ClamAV anti-virus
echo -e "${BBlue}Installing and configuring Clamav...${NC}"
pacman -S --noconfirm clamav

echo -e "${BBlue}Configuring ClamAV...${NC}"

# 1) Generate default configuration files if they do not exist.
#    clamconf creates freshclam.conf, clamd.conf, and clamav-milter.conf
#    into the current directory. Then we can move them to /etc/clamav/.
if [ ! -f /etc/clamav/freshclam.conf ]; then
  echo "Generating /etc/clamav/freshclam.conf..."
  clamconf -g freshclam.conf
  mv freshclam.conf /etc/clamav/freshclam.conf
fi

if [ ! -f /etc/clamav/clamd.conf ]; then
  echo "Generating /etc/clamav/clamd.conf..."
  clamconf -g clamd.conf
  mv clamd.conf /etc/clamav/clamd.conf
fi

if [ ! -f /etc/clamav/clamav-milter.conf ]; then
  echo "Generating /etc/clamav/clamav-milter.conf..."
  clamconf -g clamav-milter.conf
  mv clamav-milter.conf /etc/clamav/clamav-milter.conf
fi

# 2) Update /etc/clamav/clamd.conf with recommended settings.
#    You can fine-tune or remove options you do not need.
CLAMD_CONF="/etc/clamav/clamd.conf"

# Helper function to ensure a line is present in /etc/clamav/clamd.conf
ensure_clamd_option() {
  local KEY="$1"
  local VALUE="$2"
  # If the key exists, replace it; otherwise, append it
  if grep -Eq "^#?\s*${KEY}\s" "$CLAMD_CONF"; then
    sed -Ei "s|^#?\s*${KEY}.*|${KEY} ${VALUE}|" "$CLAMD_CONF"
  else
    echo "${KEY} ${VALUE}" >> "$CLAMD_CONF"
  fi
}

# Apply recommended options (comment out any you do not need)
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

# 3) Create freshclam log file and lock down permissions
echo "Creating and securing /var/log/clamav/freshclam.log..."
mkdir -p /var/log/clamav
touch /var/log/clamav/freshclam.log
chmod 600 /var/log/clamav/freshclam.log
chown clamav:clamav /var/log/clamav/freshclam.log

# 4) Enable daily updates of virus definitions.
#    You can choose either:
#       - 'clamav-freshclam.service': runs as a daemon every 2 hours (12/day).
#       - 'clamav-freshclam-once.timer': runs once a day (24h).
#
# Uncomment whichever you prefer. For example:
systemctl enable clamav-freshclam.service
# systemctl enable clamav-freshclam-once.timer

# 5) Enable freshclam and clamd (will start on first boot)
echo "Enabling ClamAV services..."
systemctl enable clamav-freshclam.service
systemctl enable clamav-daemon.service

# freshclam update will run on first boot — cannot reliably update in chroot
echo -e "${BYellow}ClamAV definitions will update on first boot via freshclam.${NC}"

# If it's not in the official repos, install from AUR (requires e.g. yay):
#if ! pacman -Qi clamav-unofficial-sigs &>/dev/null; then
#  echo "Installing clamav-unofficial-sigs from AUR..."
#  yay -S --noconfirm clamav-unofficial-sigs
#fi

# 9) Final check of ClamAV config
echo -e "${BBlue}Running clamconf to check ClamAV configuration...${NC}"
clamconf
echo -e "${BBlue}ClamAV + Unofficial Signatures configuration completed!\n${NC}"

###############################################################################
# END OF CLAMAV CONFIGURATION
###############################################################################

# Rootkit Hunter
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

echo -e "${BBlue}Installing and configuring arpwatch...${NC}"
pacman -S --noconfirm arpwatch

echo -e "${BBlue}Configuring usbguard...${NC}"
pacman -S --noconfirm usbguard

echo -e "${BBlue}Enhancing usbguard configuration...${NC}"
cat <<EOF > /etc/usbguard/usbguard-daemon.conf
RuleFile=/etc/usbguard/rules.conf
ImplicitPolicyTarget=block
PresentDevicePolicy=apply-policy
PresentControllerPolicy=keep
InsertedDevicePolicy=apply-policy
RestoreControllerDeviceState=false
DeviceRulesWithPort=false
EOF

sh -c 'usbguard generate-policy > /etc/usbguard/rules.conf'
systemctl enable usbguard.service

# Hardening /etc/login.defs
echo -e "${BBlue}Changing the value of UMASK from 022 to 027...${NC}"
sed -i 's/^UMASK[[:space:]]\+022/UMASK\t\t027/' /etc/login.defs

echo -e "${BBlue}Configuring Password Hashing Rounds...${NC}"
sed -i '/#SHA_CRYPT_MIN_ROUNDS 5000/s/^#//;/#SHA_CRYPT_MAX_ROUNDS 5000/s/^#//' /etc/login.defs

echo -e "${BBlue}Increasing Fail Delay to 5 Seconds...${NC}"
sed -i 's/^FAIL_DELAY[[:space:]]\+3/FAIL_DELAY\t\t5/' /etc/login.defs

echo -e "${BBlue}Lowering Login Retries to 3...${NC}"
sed -i 's/^LOGIN_RETRIES[[:space:]]\+5/LOGIN_RETRIES\t\t3/' /etc/login.defs

echo -e "${BBlue}Reducing Login Timeout to 30 Seconds...${NC}"
sed -i 's/^LOGIN_TIMEOUT[[:space:]]\+60/LOGIN_TIMEOUT\t\t30/' /etc/login.defs

echo -e "${BBlue}Ensuring the Strongest Encryption Method is Used...${NC}"
sed -i 's/^ENCRYPT_METHOD[[:space:]]\+.*$/ENCRYPT_METHOD YESCRYPT/' /etc/login.defs

echo -e "${BBlue}Increasing YESCRYPT Cost Factor...${NC}"
sed -i 's/^#YESCRYPT_COST_FACTOR[[:space:]]\+.*$/YESCRYPT_COST_FACTOR 7/' /etc/login.defs

echo -e "${BBlue}Setting Maximum Members Per Group...${NC}"
sed -i 's/^#MAX_MEMBERS_PER_GROUP[[:space:]]\+0/MAX_MEMBERS_PER_GROUP\t100/' /etc/login.defs

echo -e "${BBlue}Setting HMAC Crypto Algorithm to SHA512...${NC}"
sed -i 's/^#HMAC_CRYPTO_ALGO[[:space:]]\+.*$/HMAC_CRYPTO_ALGO SHA512/' /etc/login.defs

echo -e "${BBlue}Setting password expiring dates...${NC}"
sed -i '/^PASS_MAX_DAYS/c\PASS_MAX_DAYS 730' /etc/login.defs # modify here the amount of MAX days
sed -i '/^PASS_MIN_DAYS/c\PASS_MIN_DAYS 2' /etc/login.defs

# Logging Failed Login Attempts
echo -e "${BBlue}Configuring PAM to Log Failed Attempts...${NC}"


# More umasking
echo -e "${BBlue}Setting additional UMASK 027s...${NC}"
echo "umask 027" >> /etc/profile
echo "umask 027" >> /etc/bash.bashrc

# Disable unwanted protocols (truncate to avoid duplicates on re-run)
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

# Disabling core dump. Please feel free to comment if you need it.
echo -e "${BBlue}Disabling core dump...${NC}"
echo "* hard core 0" >> /etc/security/limits.conf

# Using chrony for NTP (preferred over ntpd — lighter, more accurate, handles VM clock drift)
echo -e "${BBlue}Installing chrony for NTP...${NC}"
pacman -S --noconfirm chrony
systemctl enable chronyd

# Sysstem monitoring tool
echo -e "${BBlue}Enabling sysstat to Collect Accounting...${NC}"
pacman -S --noconfirm sysstat
systemctl enable sysstat

# System auditing tool
echo -e "${BBlue}Enabling auditd to Collect Audit Information...${NC}"
pacman -S --noconfirm audit

# Download the auditd rules (prefer curl, fall back to wget)
echo "Downloading auditd rules from $RULES_URL..."
if command -v curl &>/dev/null; then
    curl -fsSL -o "$LOCAL_RULES_FILE" "$RULES_URL"
elif command -v wget &>/dev/null; then
    wget -q -O "$LOCAL_RULES_FILE" "$RULES_URL"
else
    echo "ERROR: Neither curl nor wget found. Install one to download auditd rules." >&2
    exit 1
fi
echo "Auditd rules downloaded successfully."

# Enable auditd (restart not possible in chroot — rules apply on first boot)
echo "Auditd rules installed. Will be active on first boot."

systemctl enable auditd

# Enable and configure necessary services
echo -e "${BBlue}Enabling NetworkManager...${NC}"
systemctl enable NetworkManager

echo -e "${BBlue}Enabling OpenSSH...${NC}"
systemctl enable sshd

# NOTE: dhcpcd is NOT enabled — NetworkManager handles DHCP.
# Enabling both causes conflicts (duplicate IP requests, route fighting).

# Installing Fail2ban
echo -e "${BBlue}Installing and configuring Fail2ban...${NC}"
pacman -S --noconfirm fail2ban

cat <<EOF > /etc/fail2ban/jail.d/sshd.conf
[sshd]
enabled = true
port    = ${SSH_PORT}
logpath = %(sshd_log)s
maxretry = 5
EOF

systemctl enable fail2ban

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
# journald restart not possible in chroot — config applies on first boot

# Configure sudo
echo -e "${BBlue}Hardening sudo...${NC}"
# Create a group for sudo
groupadd sudo 2>/dev/null || true

# Write sudoers atomically via temp file + visudo validation
cat > /tmp/sudoers.new << 'SUDOERS_EOF'
# Hardened sudoers — generated by chroot.sh

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

# Allow root and sudo group full access
root ALL=(ALL:ALL) ALL
%sudo ALL=(ALL:ALL) ALL

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

# arch-audit was already installed above with pax-utils — just set up the scheduled scan
# Create a script to run arch-audit and log results
cat <<EOF > /usr/local/bin/arch-audit-check
#!/bin/bash
arch-audit | tee /var/log/arch-audit.log
EOF
chmod +x /usr/local/bin/arch-audit-check

# Create a systemd service for arch-audit
cat <<EOF > /etc/systemd/system/arch-audit.service
[Unit]
Description=Arch Audit Service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/arch-audit-check
EOF

# Create a systemd timer to run daily
cat <<EOF > /etc/systemd/system/arch-audit.timer
[Unit]
Description=Run arch-audit daily

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF

# Enable and start the timer
systemctl enable arch-audit.timer
systemctl start arch-audit.timer

# --- IMPORTANT: User creation MUST come before home directory configuration ---
# Add the user
echo -e "${BBlue}Adding the user $USERNAME...${NC}"
if ! id -u "$USERNAME" >/dev/null 2>&1; then
  useradd -m -G sudo,wheel,uucp -s /bin/zsh "$USERNAME"  # Create user
  chown "$USERNAME:$USERNAME" /home/"$USERNAME"  # Fix home dir ownership right away.
  echo -e "${BBlue}User $USERNAME created.${NC}"

else
    echo "User $USERNAME already exists." >&2
fi

# Enable and set a working backup directory
echo "set backup" >> /home/"$USERNAME"/.nanorc           # Creates backups of your current file.
echo "set backupdir \"~/.cache/nano/backups/\"" >> /home/"$USERNAME"/.nanorc # The location of the backups.

# Set permissions on the configuration file to prevent unauthorized changes
chmod 600 /home/"$USERNAME"/.nanorc

# Set password for user (with loop for incorrect input)
set +e # Disable 'exit on error' temporarily
while true; do
    echo -e "${BBlue}Setting password for user $USERNAME...${NC}"
    echo -e "${BBlue}Password should be at least 12 characters long, contain 1 symbol, 1 number, upper and lowercase letters.${NC}"
    passwd "$USERNAME"
    if [ $? -eq 0 ]; then
        break # Exit loop if password change successful
    else
        echo -e "${BBlue}Password change failed. Please try again.${NC}"
        sleep 1
    fi
done

# Set password for root (with loop for incorrect input)
while true; do
    echo -e "${BBlue}Setting root password...${NC}"
    passwd root
    if [ $? -eq 0 ]; then
        break # Exit loop if password change successful
    else
        echo -e "${BBlue}Root password change failed. Please try again.${NC}"
        sleep 1
    fi
done
set -e # Re-enable 'exit on error'

# --- Now configure Nano settings (after user creation) ---
echo -e "${BBlue}Installing nano syntax highlighting...${NC}"
# Use the Arch package instead of piping curl to sh (security best practice)
pacman -S --noconfirm nano-syntax-highlighting 2>/dev/null || true

# Append nano settings (after backup/backupdir lines already written above)
cat >> /home/"$USERNAME"/.nanorc << 'NANO_EOF'
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
include "/usr/share/nano-syntax-highlighting/*.nanorc"
NANO_EOF

echo -e "${BBlue}Configuring and hardening SSH or port $SSH_PORT...${NC}"
/ssh.sh -u "$USERNAME" -p "$SSH_PORT"

# --- SSH Configuration ---
configure_ssh() {
  # --- SSH Key Generation ---

  mkdir -p "/home/$USERNAME/.ssh"  # Ensure directory exists

  if [ ! -f "$SSH_KEY_FILE" ]; then
    echo -e "${BBlue}Generating a new SSH key pair ($SSH_KEY_TYPE)...${NC}"
    ssh-keygen -t "$SSH_KEY_TYPE" -C "$USERNAME@$HOSTNAME" -f "$SSH_KEY_FILE" -q -N "" # -q for quiet, -N for no passphrase
  else
    echo -e "${BBlue}SSH key ($SSH_KEY_FILE) already exists.${NC}"
  fi

  # --- SSH Client Configuration ---
  echo -e "${BBlue}Configuring SSH client settings in $SSH_CONFIG_FILE...${NC}"

  # Backup existing config (improved)
  if [ -f "$SSH_CONFIG_FILE" ] && [ ! -f "$SSH_CONFIG_FILE.bak" ]; then
    cp "$SSH_CONFIG_FILE" "$SSH_CONFIG_FILE.bak"
  fi

  # Use 'install' for atomic file writing — values must NOT be quoted in SSH config
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

# --- SSH Server Configuration (Optional) ---
# ... (Add server-side configuration here if needed) ...

# --- SSH Finalization ---
echo -e "${BBlue}Hashing known_hosts file...${NC}"
ssh-keygen -H -f "/home/$USERNAME/.ssh/known_hosts" 2>/dev/null || true # Suppress stderr if file doesn't exist

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

if [ -f "/ssh.sh" ]; then
    shred -u /ssh.sh  # Only shred if /ssh.sh exists
fi

} # End of configure_ssh() function


configure_ssh # Call the SSH configuration function

sleep 2

echo -e "${BBlue}Setting up SSH key rotation...${NC}"
# Heredoc uses 'EOF' (quoted) to prevent expansion of $(date) at write time
cat > /usr/local/bin/rotate-ssh-keys.sh <<'ROTATE_EOF'
#!/bin/bash
set -euo pipefail
KEY_TYPE="ed25519"
KEY_FILE="/home/REPLACE_USER/.ssh/id_${KEY_TYPE}"
USERNAME="REPLACE_USER"
HOSTNAME="REPLACE_HOST"
ssh-keygen -t "$KEY_TYPE" -f "$KEY_FILE" -q -N "" -C "${USERNAME}@${HOSTNAME}-$(date +%Y%m%d)"
chown "$USERNAME:$USERNAME" "$KEY_FILE" "$KEY_FILE.pub"
chmod 600 "$KEY_FILE"
chmod 644 "$KEY_FILE.pub"
ROTATE_EOF
# Substitute placeholders with actual values (sed is safe here — controlled values)
sed -i "s/REPLACE_USER/${USERNAME}/g; s/REPLACE_HOST/${HOSTNAME}/g" /usr/local/bin/rotate-ssh-keys.sh
chmod +x /usr/local/bin/rotate-ssh-keys.sh
echo "0 0 1 */3 * root /usr/local/bin/rotate-ssh-keys.sh" >> /etc/crontab

sleep 1

echo -e "${BBlue}Applying hardened compiler flags...${NC}"
sed -i '/^CFLAGS=/ s/"$/ -fstack-protector-strong -D_FORTIFY_SOURCE=2"/' /etc/makepkg.conf
sed -i '/^CXXFLAGS=/ s/"$/ -fstack-protector-strong -D_FORTIFY_SOURCE=2"/' /etc/makepkg.conf
sed -i '/^LDFLAGS=/ s/"$/ -Wl,-z,relro,-z,now"/' /etc/makepkg.conf
# Enable PIE: replace !pie with pie (if present), otherwise no change needed
sed -i '/^OPTIONS=/ s/!pie/pie/' /etc/makepkg.conf

# Harden Compilers by Restricting Access to Root User Only
echo -e "${BBlue}Restricting access to compilers using a 'compilers' group...${NC}"

# Alternative approach using a 'compilers' group
groupadd compilers 2>/dev/null || true
usermod -aG compilers "$USERNAME"
for compiler in gcc g++ clang make as ld; do
    compiler_path=$(command -v "$compiler" 2>/dev/null) || continue
    chown root:compilers "$compiler_path"
    chmod 750 "$compiler_path"
done

# Set default ACLs on home directory
echo -e "${BBlue}Setting default ACLs on root and home directory${NC}"
setfacl -d -m u::rwx,g::---,o::--- ~
setfacl -d -m u::rwx,g::---,o::--- "/home/$USERNAME"

echo -e "${BBlue}Adding GRUB package...${NC}"
pacman -S grub efibootmgr os-prober --noconfirm

# GRUB hardening setup and encryption
echo -e "${BBlue}Adjusting /etc/mkinitcpio.conf for encryption...${NC}"
sed -i "s|^HOOKS=.*|HOOKS=(base udev autodetect keyboard keymap modconf block encrypt lvm2 filesystems fsck)|g" /etc/mkinitcpio.conf
sed -i "s|^FILES=.*|FILES=(${LUKS_KEYS})|g" /etc/mkinitcpio.conf
# NOTE: mkinitcpio is called AFTER the TPM/non-TPM HOOKS are finalized below

echo -e "${BBlue}Adjusting etc/default/grub for encryption...${NC}"
sed -ri 's|^#?GRUB_PRELOAD_MODULES=.*|GRUB_PRELOAD_MODULES="part_gpt part_msdos lvm"|' /etc/default/grub
sed -ri 's|^#?GRUB_ENABLE_CRYPTODISK=.*|GRUB_ENABLE_CRYPTODISK=y|' /etc/default/grub

chmod 400 /etc/luksKeys/boot.key

sleep 1

echo -e "${BBlue}Hardening GRUB and Kernel boot options...${NC}"

# GRUBSEC Hardening explanation:
# slab_nomerge: This disables slab merging, which significantly increases the difficulty of heap exploitation
# init_on_alloc=1 Init_on_free=1: enables zeroing of memory during allocation and free time, which can help mitigate use-after-free vulnerabilities and erase sensitive information in memory.
# page_alloc.shuffle=1: Randomises page allocator freelists, improving security by making page allocations less predictable. This also improves performance.
# pti=on: Enables Kernel Page Table Isolation, which mitigates Meltdown and prevents some KASLR bypasses.
# randomize_kstack_offset=on: Randomises the kernel stack offset on each syscall, which makes attacks that rely on deterministic kernel stack layout significantly more difficult
# vsyscall=none: Disables vsyscalls, as they are obsolete and have been replaced with vDSO. vsyscalls are also at fixed addresses in memory, making them a potential target for ROP attacks.
# lockdown=confidentiality: Eliminate many methods that user space code could abuse to escalate to kernel privileges and extract sensitive information.
# lockdown=confidentiality - This was removed because it locked nvidia and vmware module so they couldn't be loaded.
GRUBSEC="\"slab_nomerge init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 pti=on randomize_kstack_offset=on vsyscall=none quiet loglevel=3\""
#GRUBCMD="\"cryptdevice=UUID=$UUID:$LVM_NAME root=/dev/mapper/$LVM_NAME-root cryptkey=rootfs:$LUKS_KEYS\""
if [ "$INSTALL_TPM" = true ]; then
    sed -i "s|^HOOKS=.*|HOOKS=(base systemd autodetect keyboard sd-vconsole modconf block sd-encrypt lvm2 filesystems fsck)|g" /etc/mkinitcpio.conf
    GRUBCMD="\"rd.luks.name=${LUKS_UUID}=${LVM_NAME} rd.lvm.lv=${LVM_NAME}/root root=/dev/mapper/${LVM_NAME}-root\""
    # No cryptkey needed for sd-encrypt; TPM handles unlock post-enroll
    sed -i "s|^MODULES=.*|MODULES=(tpm tpm_tis tpm_crb)|" /etc/mkinitcpio.conf
else
    
    GRUBCMD="\"cryptdevice=UUID=${LUKS_UUID}:${LVM_NAME} root=/dev/mapper/${LVM_NAME}-root cryptkey=rootfs:/etc/luksKeys/boot.key\""
    sed -ri 's|^HOOKS=.*|HOOKS=(base udev autodetect keyboard keymap modconf block encrypt lvm2 filesystems fsck)|' /etc/mkinitcpio.conf
    sed -ri 's|^FILES=.*|FILES=(/etc/luksKeys/boot.key)|' /etc/mkinitcpio.conf
fi

# Generate initramfs AFTER final HOOKS/FILES are configured
echo -e "${BBlue}Generating initramfs with final HOOKS configuration...${NC}"
mkinitcpio -P

sed -i "s|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT=${GRUBSEC}|" /etc/default/grub
sed -i "s|^GRUB_CMDLINE_LINUX=.*|GRUB_CMDLINE_LINUX=${GRUBCMD}|" /etc/default/grub

sleep 1

# --- CPU Microcode Installation ---
install_cpu_microcode() {
  echo -e "${BBlue}Installing CPU ucode...${NC}"

  if [[ "$CPU_VENDOR_ID" =~ "GenuineIntel" ]]; then
    if ! pacman -Qi intel-ucode &>/dev/null; then  # Check if already installed
      pacman -S --noconfirm intel-ucode
    fi
  elif [[ "$CPU_VENDOR_ID" =~ "AuthenticAMD" ]]; then
    if ! pacman -Qi amd-ucode &>/dev/null; then  # Check if already installed
      pacman -S --noconfirm amd-ucode
    fi
  else
    echo -e "${BBlue}Unknown CPU vendor: $CPU_VENDOR_ID. Skipping microcode installation.${NC}"
  fi
}

install_cpu_microcode # Call the function

sleep 1

# --- Bluetooth Configuration ---
configure_bluetooth() {
  if lsusb | grep -iq "bluetooth" || lspci | grep -iq "bluetooth"; then  # Improved detection
    echo -e "${BBlue}Bluetooth hardware detected.${NC}"

    if ! pacman -Qi bluez bluez-utils &>/dev/null; then # Check if already installed
      pacman -S --noconfirm bluez bluez-utils
    fi

    # Backup main.conf (using install -Dm)
    install -Dm644 /etc/bluetooth/main.conf{,.bak} 2>/dev/null || true # Safer backup, ignore errors if file doesn't exist

cat <<EOF >/etc/bluetooth/main.conf
[General]
# Hardening and Auto-Enable settings
AutoEnable=true             # Enable automatic Bluetooth activation
DiscoverableTimeout=0
PairableTimeout=0
Privacy=device              # Enhanced privacy
JustWorksRepairing=confirm   # Require confirmation for pairing repairs
MinEncryptionKeySize=16      # Minimum encryption key size
SecureConnectionsOnly=true   # Enforce secure connections
ControllerMode=le           # Use Low Energy mode
Name=$HOSTNAME-Bluetooth    # Use hostname in Bluetooth device name
EOF

  # Systemd override (using install -Dm)
  mkdir -p /etc/systemd/system/bluetooth.service.d
cat <<EOF | install -Dm644 /dev/stdin /etc/systemd/system/bluetooth.service.d/override.conf # Install with correct permissions
[Service]
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
NoNewPrivileges=true
CapabilityBoundingSet=~CAP_SYS_ADMIN
RestrictAddressFamilies=AF_UNIX AF_BLUETOOTH
MemoryDenyWriteExecute=true
EOF

    systemctl daemon-reload
    systemctl enable bluetooth  # Enable and start Bluetooth
    echo -e "${BBlue}Bluetooth installation, configuration, and hardening complete.${NC}"
  else
    echo -e "${BBlue}No Bluetooth hardware detected.${NC}"
  fi
}

configure_bluetooth  # Call the function

sleep 2

# --- Variables ---
NVIDIA_CARD=false
AMD_CARD=false
KERNEL="$(uname -r)"

# --- Detect NVIDIA ---
if lspci | grep -E "VGA|3D" | grep -i nvidia &>/dev/null; then
    NVIDIA_CARD=true
    echo -e "${BBlue}Found an NVIDIA GPU...${NC}"
fi

# --- If NVIDIA is found, handle NVIDIA drivers ---
if [[ "$NVIDIA_CARD" == true ]]; then
    echo -e "${BBlue}Installing NVIDIA drivers...${NC}"
    # Blacklist nouveau
    mkdir -p /etc/modprobe.d
    touch /etc/modprobe.d/blacklist-nouveau.conf
    if ! grep -q "blacklist nouveau" /etc/modprobe.d/blacklist-nouveau.conf; then
        echo "blacklist nouveau" >> /etc/modprobe.d/blacklist-nouveau.conf
    fi

    gpu_model=$(lspci | grep -i 'vga\|3d\|2d' | grep -i nvidia | cut -d ':' -f3)
    echo "Detected GPU: $gpu_model"
    echo "Running Kernel: $KERNEL"

    # Choose correct NVIDIA driver package based on model:
    case $gpu_model in
        *"Tesla"*|"*NV50"*|"*G80"*|"*G90"*|"*GT2XX"*)
            pacman -S --noconfirm nvidia-340xx-dkms nvidia-340xx-utils
            ;;
        *"GeForce 400"*|"*GeForce 500"*|"*600"*|"*NVCx"*|"*NVDx"*)
            pacman -S --noconfirm nvidia-390xx-dkms nvidia-390xx-utils
            ;;
        *"Kepler"*|"*NVE0"*)
            pacman -S --noconfirm nvidia-470xx-dkms nvidia-470xx-utils
            ;;
        # Maxwell, Pascal, Turing, Ampere, Ada, etc.:
        *"Maxwell"*|*"NV110"*|*"GA102"*)  # Maxwell fallback: Usually the standard driver works
            if [[ "$KERNEL" == *"lts"* || "$KERNEL" == *"linux"* ]]; then
                pacman -S --noconfirm nvidia nvidia-utils
            else
                pacman -S --noconfirm nvidia-dkms nvidia-utils
            fi
            ;;
        *"Pascal"*|*"GTX 10"*|*"GP10"*|*"Turing"*|*"RTX 20"*|*"TU10"*|\
         *"Ampere"*|*"RTX 30"*|*"GA10"*|*"Ada"*|*"RTX 40"*|*"AD10"*|*"RTX 50"* )
            if [[ "$KERNEL" == *"lts"* || "$KERNEL" == *"linux"* ]]; then
                pacman -S --noconfirm nvidia nvidia-utils
            else
                pacman -S --noconfirm nvidia-dkms nvidia-utils
            fi
            ;;
        *)
            echo "No matching NVIDIA driver found for: $gpu_model"
            echo "Installing standard nvidia driver as a fallback..."
            pacman -S --noconfirm nvidia nvidia-utils
            ;;
    esac

    # Adjust mkinitcpio.conf
    echo -e "${BBlue}Adjusting /etc/mkinitcpio.conf for NVIDIA...${NC}"
    sed -ri 's|^MODULES=.*|MODULES=(nvidia nvidia_drm nvidia_uvm nvidia_modeset)|' /etc/mkinitcpio.conf

    # Optional but recommended: early KMS for smoother boot
    if ! grep -Eq '(^|\s)kms(\s|\))' /etc/mkinitcpio.conf; then
      sed -ri 's/(HOOKS=\(.*modconf) /\1 kms /' /etc/mkinitcpio.conf
    fi
    
    # Re-generate initramfs
    mkinitcpio -P  # -P regenerates all presets for all installed kernels

    # Adjust GRUB
    echo -e "${BBlue}Adjusting /etc/default/grub for NVIDIA...${NC}"
    sed -i 's|\(^GRUB_CMDLINE_LINUX_DEFAULT="[^"]*\)\(".*\)|\1 nvidia-drm.modeset=1\2|' /etc/default/grub

    # Update GRUB config
    if [[ -f /boot/grub/grub.cfg ]]; then
        grub-mkconfig -o /boot/grub/grub.cfg
    fi
fi

# --- If not NVIDIA, check for AMD/Radeon ---
if [[ "$NVIDIA_CARD" == false ]]; then
    if lspci | grep -E "VGA|3D" | grep -Ei 'amd|radeon' &>/dev/null; then
        AMD_CARD=true
        echo -e "${BBlue}Found an AMD/Radeon GPU...${NC}"
    fi

    if [[ "$AMD_CARD" == true ]]; then
        # Extract AMD GPU model
        gpu_model=$(lspci | grep -Ei 'vga|3d|2d' | grep -Ei 'amd|radeon' | cut -d ':' -f3)
        echo "Detected GPU: $gpu_model"

        # A simple case for AMD/Radeon
        case "$gpu_model" in
            *"Radeon"*|*"RX 500"*|*"RX Vega"*|*"RDNA"*|*"RX 6000"*|*"RX 7000"*)
                pacman -S --noconfirm xf86-video-amdgpu mesa vulkan-radeon lib32-mesa lib32-vulkan-radeon
                ;;
            *"APU"*|*"Ryzen"*|*"Athlon"*|*"PRO"*)
                # Typically these APUs work fine with mesa + integrated AMD driver
                pacman -S --noconfirm mesa lib32-mesa
                ;;
            *)
                echo "Unknown AMD GPU. Installing default AMD drivers (xf86-video-amdgpu, mesa)."
                pacman -S --noconfirm xf86-video-amdgpu mesa
                ;;
        esac
    fi
fi

# --- If neither NVIDIA nor AMD/Radeon was found, install basic drivers ---
if [[ "$NVIDIA_CARD" == false && "$AMD_CARD" == false ]]; then
    echo -e "${BBlue}No supported NVIDIA or AMD GPU detected. Installing basic drivers...${NC}"
    pacman -S --noconfirm xf86-video-vesa mesa
    # Do NOT touch mkinitcpio or grub in this fallback.
fi

sleep 2

configure_grub() {
  echo -e "${BBlue}Improving GRUB screen performance (if supported by hardware)...${NC}"

  echo -e "${BBlue}Setting up GRUB...${NC}"
  mkdir -p /boot/grub

  grub-install --target=x86_64-efi --bootloader-id=GRUB --efi-directory=/efi --recheck

  # --- Set GRUB Password ---
set +e  # Temporarily disable 'exit on error'

while true; do
  echo -e "${BBlue}Setting GRUB password...${NC}"
  grub-mkpasswd-pbkdf2 | tee /tmp/grubpass
  GRUB_PASS=$(grep 'grub.pbkdf2' /tmp/grubpass | awk '{print $NF}')
  rm /tmp/grubpass
  if [[ -n "$GRUB_PASS" ]]; then
     break # Exit loop if the password was correctly created
  else
      echo -e "${BBlue}GRUB password generation failed. Please try again.${NC}"
      sleep 1 # Add a delay
  fi
done

set -e # Re-enable 'exit on error'

# Use a generic "admin" superuser instead of leaking the system username
cat <<EOF >> /etc/grub.d/40_custom
set superusers="admin"
password_pbkdf2 admin $GRUB_PASS
EOF

grub-mkconfig -o /boot/grub/grub.cfg

}

configure_grub

sleep 2

chmod 600 "$LUKS_KEYS"

# Creating a cool /etc/issue
echo -e "${BBlue}Creating Banner (/etc/issue).${NC}"

cat > /etc/issue.net << EOF
Arch Linux \r (\l)

                     .ed"""" """\$\$\$\$be.
                   -"           ^""**\$\$\$e.
                 ."                   '\$\$\$c
                /                      "4\$\$b
               d  3                     \$\$\$\$
               \$  *                   .\$\$\$\$\$\$
              .\$  ^c           \$\$\$\$\$e\$\$\$\$\$\$\$\$.
              d\$L  4.         4\$\$\$\$\$\$\$\$\$\$\$\$\$\$b
              \$\$\$\$b ^ceeeee. 4\$\$ECL.F*\$\$\$\$\$\$\$
  e\$""=.      \$\$\$\$P d\$\$\$\$F \$ \$\$\$\$\$\$\$\$- \$\$\$\$\$\$
 z\$\$b. ^c     3\$\$\$F "\$\$\$\$b   \$"\$\$\$\$\$\$\$  \$\$\$\$*"      .=""\$c
4\$\$\$\$L   \     \$\$P"  "\$\$b   .\$ \$\$\$\$\$...e\$\$        .=  e\$\$\$.
^*\$\$\$\$\$c  %..   *c    ..    \$\$ 3\$\$\$\$\$\$\$\$\$\$eF     zP  d\$\$\$\$\$
  "**\$\$\$ec   "\   %ce""    \$\$\$  \$\$\$\$\$\$\$\$\$\$*    .r" =\$\$\$\$P""
        "*\$b. "c  *\$e.    *** d\$\$\$\$\$"L\$\$    .d"  e\$\$***"
          ^*\$\$c ^\$c \$\$\$      4J\$\$\$\$\$% \$\$\$ .e*".eeP"
             "\$\$\$\$\$\$"'\$=e....\$*\$\$**\$cz\$\$" "..d\$*"
               "*\$\$\$  *=%4.\$ L L\$ P3\$\$\$F \$\$\$P"
                  "\$   "%*ebJLzb\$e\$\$\$\$\$b \$P"
                    %..      4\$\$\$\$\$\$\$\$\$\$ "
                     \$\$\$e   z\$\$\$\$\$\$\$\$\$\$%
                      "*\$c  "\$\$\$\$\$\$\$P"
                       ."""*\$\$\$\$\$\$\$\$bc
                    .-"    .\$***\$\$\$"""*e.
                 .-"    .e\$"     "*\$c  ^*b.
          .=*""""    .e\$*"          "*bc  "*\$e..
        .\$"        .z*"               ^*\$e.   "*****e.
        \$\$ee\$c   .d"                     "*\$.        3.
        ^*\$E")\$..\$"                         *   .ee==d%
           \$.d\$\$\$*                           *  J\$\$\$e*
            """""                             "\$\$\$"

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

echo -e "${BBlue}Setting permission on config files...${NC}"

chmod 0700 /boot
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

sleep 1

# Remove deprecated PAM modules
echo -e "${BBlue}Removing deprecated pam_tally2.so references...${NC}"
sed -i '/pam_tally2.so/d' /etc/pam.d/system-auth
rm -f /etc/pam.d/common-auth

# Install necessary PAM modules
echo -e "${BBlue}Installing necessary PAM modules...${NC}"
pacman -S --noconfirm pambase pam libpwquality

# Configure account lockout with pam_faillock
echo -e "${BBlue}Configuring account lockout policy with pam_faillock...${NC}"

# Backup the original system-auth file
cp /etc/pam.d/system-auth /etc/pam.d/system-auth.bak

# Insert pam_faillock.so lines with escaped square brackets
sed -i '/^auth.*required.*pam_unix\.so/i auth required pam_faillock.so preauth silent deny=5 unlock_time=900' /etc/pam.d/system-auth
sed -i '/^auth.*include.*system-auth/i auth \[default=die\] pam_faillock.so authfail deny=5 unlock_time=900' /etc/pam.d/system-auth

# Add account required pam_faillock.so
sed -i '/^account.*required.*pam_unix\.so/a account required pam_faillock.so' /etc/pam.d/system-auth

# Configure password quality requirements
echo -e "${BBlue}Configuring password quality requirements...${NC}"

# Update /etc/security/pwquality.conf
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

# Ensure pam_pwquality.so is included
if ! grep -q "pam_pwquality.so" /etc/pam.d/system-auth; then
    sed -i '/^password.*required.*pam_unix.so/a password required pam_pwquality.so retry=3' /etc/pam.d/system-auth
fi

echo -e "${BBlue}Setting up automatic security updates...${NC}"
pacman -S --noconfirm pacman-contrib
cat <<EOF > /etc/systemd/system/pacman-autoupdate.timer
[Unit]
Description=Run pacman autoupdate daily

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
# Sync databases and check for updates — do NOT auto-install (--noconfirm -Syu
# can break a system with partial upgrades or ABI changes).
ExecStart=/bin/sh -c '/usr/bin/pacman -Sy && /usr/bin/pacman -Qu > /var/log/pacman-updates.log 2>&1 || true'
EOF
systemctl enable pacman-autoupdate.timer

sleep 2

# --- Systemd Services Hardening ---
echo -e "${BBlue}Hardening systemd services...${NC}"

# Create a function to apply hardening to services
harden_systemd_service() {
    local service=$1
    local override_dir="/etc/systemd/system/${service}.d"
    
    # Skip if service doesn't exist
    if ! systemctl list-unit-files | grep -q "^${service}"; then
        return
    fi
    
    mkdir -p "$override_dir"
    
    cat > "${override_dir}/hardening.conf" <<EOF
[Service]
# Process isolation
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes

# Kernel protection
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes

# Filesystem restrictions
PrivateDevices=yes
DevicePolicy=closed
ProtectProc=invisible
ProcSubset=pid

# Capabilities
CapabilityBoundingSet=
AmbientCapabilities=

# System calls
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
SystemCallArchitectures=native

# Network
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
IPAddressDeny=any

# Misc security
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RemoveIPC=yes
RestrictNamespaces=yes
UMask=0077

# Resource limits
LimitNOFILE=1024
LimitNPROC=512
EOF
}

# SSH Service - Already partially done, but let's enhance it
echo -e "${BBlue}Hardening SSH service...${NC}"
mkdir -p /etc/systemd/system/sshd.service.d/
cat > /etc/systemd/system/sshd.service.d/hardening.conf <<'EOF'
[Service]
# SSH-specific hardening
PrivateTmp=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only  # SSH needs to read authorized_keys
ReadWritePaths=/var/log /run

# Kernel protections
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes

# Network restrictions
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
IPAddressAllow=any
IPAddressDeny=

# Device access
PrivateDevices=yes
DevicePolicy=closed

# System call filtering
SystemCallFilter=@system-service @privileged @resources
SystemCallErrorNumber=EPERM

# Additional security
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RemoveIPC=yes

# Restart on failure
Restart=on-failure
RestartSec=5s
EOF

# NetworkManager hardening
echo -e "${BBlue}Hardening NetworkManager...${NC}"
mkdir -p /etc/systemd/system/NetworkManager.service.d/
cat > /etc/systemd/system/NetworkManager.service.d/hardening.conf <<'EOF'
[Service]
# NetworkManager needs some privileges for network management
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectKernelLogs=yes

# Network operations need certain capabilities
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_DAC_OVERRIDE CAP_SETUID CAP_SETGID
NoNewPrivileges=no  # NM needs to acquire privileges

# Device access for network interfaces
PrivateDevices=no
DevicePolicy=auto

# System calls - NM needs broader access
SystemCallFilter=@system-service @module @raw-io @privileged
SystemCallErrorNumber=EPERM

RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictSUIDSGID=yes

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
ProtectHome=yes
ReadWritePaths=/var/lib/clamav /var/log/clamav /run

ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes

NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes

SystemCallFilter=@system-service @file-system @io-event
SystemCallErrorNumber=EPERM

RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictSUIDSGID=yes

# Resource limits for scanning
LimitNICE=19
LimitNOFILE=8192
TasksMax=4

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

# fail2ban needs CAP_NET_ADMIN and CAP_NET_RAW for iptables
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_READ_SEARCH
NoNewPrivileges=yes

PrivateTmp=yes
PrivateDevices=yes

SystemCallFilter=@system-service @network-io @privileged
SystemCallErrorNumber=EPERM

RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictSUIDSGID=yes

Restart=on-failure
RestartSec=5s
EOF

# Stubby DNS hardening (already in DNS section but let's ensure it's complete)
echo -e "${BBlue}Hardening Stubby DNS...${NC}"
mkdir -p /etc/systemd/system/stubby.service.d/
cat > /etc/systemd/system/stubby.service.d/hardening.conf <<'EOF'
[Service]
User=stubby
Group=stubby

ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/cache/stubby /run

ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes

NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
DevicePolicy=closed

SystemCallFilter=@system-service @network-io
SystemCallErrorNumber=EPERM
SystemCallArchitectures=native

RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictSUIDSGID=yes

# DNS specific
IPAddressAllow=any
IPAddressDeny=

Restart=always
RestartSec=5s
EOF

# systemd-resolved hardening
echo -e "${BBlue}Hardening systemd-resolved...${NC}"
mkdir -p /etc/systemd/system/systemd-resolved.service.d/
cat > /etc/systemd/system/systemd-resolved.service.d/hardening.conf <<'EOF'
[Service]
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/run/systemd/resolve

ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes

NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes

SystemCallFilter=@system-service @network-io
SystemCallErrorNumber=EPERM

RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictSUIDSGID=yes

Restart=on-failure
RestartSec=5s
EOF

# Chrony NTP hardening
echo -e "${BBlue}Hardening Chrony NTP...${NC}"
mkdir -p /etc/systemd/system/chronyd.service.d/
cat > /etc/systemd/system/chronyd.service.d/hardening.conf <<'EOF'
[Service]
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/chrony /var/log/chrony /run

ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=no  # Chrony needs to set system time

NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes

# Chrony needs CAP_SYS_TIME
CapabilityBoundingSet=CAP_SYS_TIME CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_SYS_TIME

SystemCallFilter=@system-service @clock
SystemCallErrorNumber=EPERM

RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictSUIDSGID=yes

Restart=on-failure
RestartSec=5s
EOF

# Apply hardening to other common services
for service in rngd.service systemd-journald.service; do
    echo -e "${BBlue}Hardening ${service}...${NC}"
    harden_systemd_service "$service"
done

# Reload systemd to apply all changes
echo -e "${BBlue}Reloading systemd daemon to apply hardening...${NC}"
systemctl daemon-reload

echo -e "${BGreen}Systemd services hardening completed!${NC}"

sleep 2

# --- System Hardening (sysctl) ---
harden_sysctl() {

  echo -e "${BBlue}Applying sysctl hardening settings...${NC}"

  if [ ! -x "/sysctl.sh" ]; then #Check if the file exists and is executable
    echo "Error: /sysctl.sh not found or not executable" >&2
    exit 1
  fi

  # Execute sysctl.sh and write output to sysctl config file.
  /sysctl.sh

  sleep 2
  
  shred -u /sysctl.sh
}

harden_sysctl

sleep 2

echo -e "${BBlue}Installation completed! You can reboot the system now.${NC}"
# Securely remove sensitive files
shred -u /root/.install-env 2>/dev/null || true
shred -u /chroot.sh
exit
