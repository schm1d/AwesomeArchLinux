#!/usr/bin/env bash

# Description: VPS chroot script for Arch Linux installation.
# Adapted from chroot.sh — removes physical security (USBGuard, Bluetooth, GPU,
# GRUB encryption, TPM), fixes duplicate sections and bugs from the original.
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
TIMEZONE="Europe/Zurich"
LOCALE="en_US.UTF-8"

# --- Other Variables ---
RULES_URL='https://raw.githubusercontent.com/schm1d/AwesomeArchLinux/refs/heads/main/utils/auditd-attack.rules'
LOCAL_RULES_FILE="/etc/audit/rules.d/auditd-attack.rules"
SSH_CONFIG_FILE="/home/$USERNAME/.ssh/config"
SSH_KEY_TYPE="ed25519"
SSH_KEY_FILE="/home/$USERNAME/.ssh/id_$SSH_KEY_TYPE"

CPU_VENDOR_ID=$(lscpu | grep 'Vendor ID' | awk '{print $3}')

###############################################################################
# BASIC SYSTEM CONFIGURATION
###############################################################################

pacman-key --init
pacman-key --populate archlinux

echo -e "${BBlue}Removing unnecessary users and groups...${NC}"
userdel -r games 2>/dev/null || true
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
cat > /etc/vconsole.conf <<EOF
KEYMAP=de_CH-latin1
FONT=lat9w-16
FONT_MAP=8859-1_to_uni
EOF

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
systemd-resolved=true

[connection]
# VPS typically uses static MAC, but keep privacy for safety
connection.stable-id=\${CONNECTION}/\${BOOT}
EOF
fi

###############################################################################
# DNS-OVER-TLS (STUBBY)
###############################################################################

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
if [ -e /etc/resolv.conf ]; then
    mv -f /etc/resolv.conf /etc/resolv.conf.old 2>/dev/null || true
fi

# Temporary resolv.conf for chroot
cat > /etc/resolv.conf <<EOF
nameserver 9.9.9.9
nameserver 1.1.1.1
EOF

# Create post-boot fix script
cat > /usr/local/bin/fix-resolv-conf.sh <<'RESOLV_SCRIPT'
#!/bin/bash
if [ -f /etc/resolv.conf ] && [ ! -L /etc/resolv.conf ]; then
    rm -f /etc/resolv.conf
fi
if [ ! -e /etc/resolv.conf ]; then
    ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
fi
RESOLV_SCRIPT
chmod +x /usr/local/bin/fix-resolv-conf.sh

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

echo -e "${BBlue}Enabling DNS services...${NC}"
systemctl daemon-reload
systemctl enable stubby
systemctl enable systemd-resolved
systemctl start stubby 2>/dev/null || true
systemctl start systemd-resolved 2>/dev/null || true

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

        # Allow SSH with rate limiting
        tcp dport $SSH_PORT ct state new limit rate 2/minute accept

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
    echo -e "${BBlue}Firewall configuration with nftables completed.${NC}"
else
    echo -e "${BYellow}WARNING: nftables not supported by this kernel (common on VPS).${NC}"
    echo -e "${BYellow}nftables is enabled and will start if the kernel supports it after reboot.${NC}"
    echo -e "${BYellow}If your VPS uses iptables instead, configure iptables rules manually.${NC}"
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

# Additional UMASK hardening
echo "umask 027" >> /etc/profile
echo "umask 027" >> /etc/bash.bashrc

# Disable unwanted protocols
echo -e "${BBlue}Disabling unwanted protocols...${NC}"
echo "install dccp /bin/true" >> /etc/modprobe.d/disable-protocols.conf
echo "install sctp /bin/true" >> /etc/modprobe.d/disable-protocols.conf
echo "install rds /bin/true" >> /etc/modprobe.d/disable-protocols.conf
echo "install tipc /bin/true" >> /etc/modprobe.d/disable-protocols.conf

# Disable core dumps
echo -e "${BBlue}Disabling core dump...${NC}"
echo "* hard core 0" >> /etc/security/limits.conf

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

# dhcpcd may not be installed on VPS with systemd-networkd
if systemctl list-unit-files dhcpcd.service &>/dev/null; then
    echo -e "${BBlue}Enabling DHCP...${NC}"
    systemctl enable dhcpcd.service
fi

# Enable serial console for VPS provider access
echo -e "${BBlue}Enabling serial console (for VPS provider console)...${NC}"
systemctl enable serial-getty@ttyS0.service

###############################################################################
# FAIL2BAN
###############################################################################

echo -e "${BBlue}Installing and configuring Fail2ban...${NC}"
pacman -S --noconfirm fail2ban

cat <<EOF > /etc/fail2ban/jail.d/sshd.conf
[sshd]
enabled = true
port    = "$SSH_PORT"
logpath = %(sshd_log)s
maxretry = 5
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
groupadd sudo 2>/dev/null || true

echo "Defaults secure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"" > /etc/sudoers
echo "Defaults !rootpw" >> /etc/sudoers
echo "Defaults umask=077" >> /etc/sudoers
echo "Defaults editor=/usr/bin/vim" >> /etc/sudoers
echo "Defaults env_reset" >> /etc/sudoers
echo "Defaults env_reset,env_keep=\"COLORS DISPLAY HOSTNAME HISTSIZE INPUTRC KDEDIR LS_COLORS\"" >> /etc/sudoers
echo "Defaults env_keep += \"MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE\"" >> /etc/sudoers
echo "Defaults env_keep += \"LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES\"" >> /etc/sudoers
echo "Defaults env_keep += \"LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE\"" >> /etc/sudoers
echo "Defaults env_keep += \"LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY\"" >> /etc/sudoers
echo "Defaults timestamp_timeout=30" >> /etc/sudoers
echo "Defaults !visiblepw" >> /etc/sudoers
echo "Defaults always_set_home" >> /etc/sudoers
echo "Defaults match_group_by_gid" >> /etc/sudoers
echo "Defaults always_query_group_plugin" >> /etc/sudoers
echo "Defaults passwd_timeout=10" >> /etc/sudoers
echo "Defaults passwd_tries=3" >> /etc/sudoers
echo "Defaults loglinelen=0" >> /etc/sudoers
echo "Defaults insults" >> /etc/sudoers
echo "Defaults lecture=once" >> /etc/sudoers
echo "Defaults requiretty" >> /etc/sudoers
echo "Defaults logfile=/var/log/sudo.log" >> /etc/sudoers
echo "Defaults log_input, log_output" >> /etc/sudoers
echo "%sudo ALL=(ALL) ALL" >> /etc/sudoers
echo "@includedir /etc/sudoers.d" >> /etc/sudoers

chmod 440 /etc/sudoers
chown root:root /etc/sudoers

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

# Ensure unzip is available (installed by pacstrap in vps-install.sh, may be missing on live VPS)
if ! command -v unzip &>/dev/null; then
    echo -e "${BBlue}Installing unzip (required for nanorc)...${NC}"
    pacman -S --noconfirm unzip
fi

# Download nanorc
echo -e "${BBlue}Downloading nanorc...${NC}"
curl -sL https://raw.githubusercontent.com/scopatz/nanorc/master/install.sh | sh -s -- -y

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

echo -e "${BBlue}Configuring and hardening SSH on port $SSH_PORT...${NC}"
/ssh.sh

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

  install -Dm644 /dev/stdin "$SSH_CONFIG_FILE" <<EOF
 Host "$HOSTNAME"
  HostName "$HOSTNAME"
  Port "$SSH_PORT"
  User "$USERNAME"
  IdentityFile "$SSH_KEY_FILE"
  HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
  KexAlgorithms curve25519-sha256@libssh.org,curve25519-sha256,diffie-hellman-group18-sha512,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256,diffie-hellman-group-exchange-sha256
  Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr
  MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
EOF

  echo "SSH client configuration updated."

  echo -e "${BBlue}Hashing known_hosts file...${NC}"
  ssh-keygen -H -f "/home/$USERNAME/.ssh/known_hosts" 2>/dev/null || true

  touch "/home/$USERNAME/.ssh/authorized_keys"
  chmod 700 "/home/$USERNAME/.ssh"
  chmod 600 "/home/$USERNAME/.ssh/authorized_keys"
  chown -R "$USERNAME:$USERNAME" "/home/$USERNAME"

  if [ -f "/ssh.sh" ]; then
      shred -u /ssh.sh
  fi
}

configure_ssh

sleep 2

# SSH key rotation script (FIXED: private key chmod 600 not overwritten)
echo -e "${BBlue}Setting up SSH key rotation...${NC}"
cat <<EOF > /usr/local/bin/rotate-ssh-keys.sh
#!/bin/bash
ssh-keygen -t "$SSH_KEY_TYPE" -f "$SSH_KEY_FILE" -q -N "" -C "$USERNAME@$HOSTNAME-\$(date +%Y%m%d)"
chown "$USERNAME:$USERNAME" "$SSH_KEY_FILE" "$SSH_KEY_FILE.pub"
chmod 600 "$SSH_KEY_FILE"
chmod 644 "$SSH_KEY_FILE.pub"
EOF
chmod +x /usr/local/bin/rotate-ssh-keys.sh
echo "0 0 1 */3 * /usr/local/bin/rotate-ssh-keys.sh" >> /etc/crontab

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
groupadd compilers
usermod -aG compilers "$USERNAME"
for compiler in gcc g++ clang make as ld; do
    if command -v "$compiler" &> /dev/null; then
        chown root:compilers "$(which $compiler)"
        chmod 750 "$(which $compiler)"
    fi
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
while true; do
  echo -e "${BBlue}Setting GRUB password...${NC}"
  grub-mkpasswd-pbkdf2 | tee /tmp/grubpass
  GRUB_PASS=$(grep 'grub.pbkdf2' /tmp/grubpass | awk '{print $NF}')
  rm /tmp/grubpass
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
chmod 0600 /etc/login.defs

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
cat <<EOF > /etc/systemd/system/pacman-autoupdate.service
[Unit]
Description=Update system packages automatically

[Service]
Type=oneshot
ExecStart=/usr/bin/pacman -Syu --noconfirm
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
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/log
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
IPAddressAllow=any
IPAddressDeny=
PrivateDevices=yes
DevicePolicy=closed
SystemCallFilter=@system-service @privileged @resources
SystemCallErrorNumber=EPERM
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RemoveIPC=yes
Restart=on-failure
RestartSec=5s
EOF

# NetworkManager hardening
echo -e "${BBlue}Hardening NetworkManager...${NC}"
mkdir -p /etc/systemd/system/NetworkManager.service.d/
cat > /etc/systemd/system/NetworkManager.service.d/hardening.conf <<'EOF'
[Service]
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectKernelLogs=yes
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_DAC_OVERRIDE CAP_SETUID CAP_SETGID
NoNewPrivileges=no
PrivateDevices=no
DevicePolicy=auto
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
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ReadWritePaths=/var/log/audit
CapabilityBoundingSet=CAP_AUDIT_CONTROL CAP_AUDIT_READ CAP_AUDIT_WRITE CAP_DAC_READ_SEARCH
NoNewPrivileges=yes
PrivateDevices=yes
PrivateTmp=yes
SystemCallFilter=@system-service @privileged
SystemCallErrorNumber=EPERM
RestrictAddressFamilies=AF_UNIX AF_NETLINK
RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictSUIDSGID=yes
Restart=on-failure
RestartSec=5s
EOF

# ClamAV hardening
echo -e "${BBlue}Hardening ClamAV services...${NC}"
mkdir -p /etc/systemd/system/clamav-daemon.service.d/
cat > /etc/systemd/system/clamav-daemon.service.d/hardening.conf <<'EOF'
[Service]
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/clamav /var/log/clamav
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

# Stubby DNS hardening
echo -e "${BBlue}Hardening Stubby DNS...${NC}"
mkdir -p /etc/systemd/system/stubby.service.d/
cat > /etc/systemd/system/stubby.service.d/hardening.conf <<'EOF'
[Service]
User=stubby
Group=stubby
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/cache/stubby
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
ReadWritePaths=/var/lib/chrony /var/log/chrony
ProtectKernelTunables=yes
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

# Reload systemd
echo -e "${BBlue}Reloading systemd daemon to apply hardening...${NC}"
systemctl daemon-reload

echo -e "${BGreen}Systemd services hardening completed!${NC}"

sleep 2

###############################################################################
# SYSCTL HARDENING
###############################################################################

harden_sysctl() {
  echo -e "${BBlue}Applying sysctl hardening settings...${NC}"

  if [ ! -x "/sysctl.sh" ]; then
    echo "Error: /sysctl.sh not found or not executable" >&2
    exit 1
  fi

  /sysctl.sh

  sleep 2

  shred -u /sysctl.sh
}

harden_sysctl

sleep 2

echo -e "${BGreen}VPS chroot configuration completed! You can reboot the system now.${NC}"
shred -u /vps-chroot.sh 2>/dev/null || true
exit
