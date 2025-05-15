#!/usr/bin/env bash

# Description: This is the chroot script for Arch Linux installation.
# Author: Bruno Schmid @brulliant
# LinkedIn: https://www.linkedin.com/in/schmidbruno/

set -euo pipefail

# Set up the variables
BBlue='\033[1;34m'
NC='\033[0m'

# Ensure the script is run as root
if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root" >&2
  exit 1
fi

# --- These values MUST be replaced by archinstall.sh ---
DISK="${_INSTALL_DISK}"       # Example: /dev/sda or /dev/nvme0n1
#CRYPT_NAME="crypt_lvm"
LVM_NAME="lvm_arch"
USERNAME="${_INSTALL_USER}" # Example: myuser
HOSTNAME="${_INSTALL_HOST}" # Example: myhostname
TIMEZONE="Europe/Zurich"
LOCALE="en_US.UTF-8"
LUKS_KEYS='/etc/luksKeys/boot.key' # Location of the root partition key
SSH_PORT=22

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

UUID=$(cryptsetup luksUUID "$PARTITION3")

CPU_VENDOR_ID=$(lscpu | grep 'Vendor ID' | awk '{print $3}')

# --- Basic System Configuration ---
pacman-key --init
pacman-key --populate archlinux

echo -e "${BBlue}Removing unnecessary users and groups...${NC}"
userdel -r games 2>/dev/null || true
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
echo "$HOSTNAME" > /etc/hostname

echo -e "${BBlue}Setting /etc/hosts...${NC}"
echo "127.0.0.1 localhost" > /etc/hosts
echo "::1       localhost" >> /etc/hosts
echo "127.0.0.1 localhost localhost.localdomain $HOSTNAME.localdomain $HOSTNAME" >> /etc/hosts

# --- Network Configuration ---
echo -e "${BBlue}Configuring systemd-resolved to use Stubby...${NC}"
echo "[Resolve]" > /etc/systemd/resolved.conf
echo "DNS=127.0.0.1:5353" >> /etc/systemd/resolved.conf
echo "FallbackDNS=127.0.0.1:5353" >> /etc/systemd/resolved.conf
echo "DNSSEC=yes" >> /etc/systemd/resolved.conf
echo "DNSOverTLS=no" >> /etc/systemd/resolved.conf

echo -e "${BBlue}Installing Stubby for DNS-over-TLS...${NC}"
pacman -S dnssec-anchors --noconfirm
pacman -S stubby --noconfirm

echo -e "${BBlue}Configuring Stubby...${NC}"
cat <<EOF > /etc/stubby/stubby.yml
resolution_type: GETDNS_RESOLUTION_STUB
dns_transport_list:
  - GETDNS_TRANSPORT_TLS
tls_authentication: GETDNS_AUTHENTICATION_REQUIRED
dnssec_return_status: GETDNS_EXTENSION_TRUE
appdata_dir: "/var/cache/stubby"
listen_addresses:
  - 127.0.0.1@5353
  - 0::1@5353
upstream_recursive_servers:
  - address_data: 8.8.8.8
    tls_auth_name: "dns.google"
    tls_port: 853
  - address_data: 8.8.4.4
    tls_auth_name: "dns.google"
    tls_port: 853
  - address_data: 1.1.1.1
    tls_auth_name: "cloudflare-dns.com"
    tls_port: 853
  - address_data: 9.9.9.9
    tls_auth_name: "dns.quad9.net"
    tls_port: 853
EOF

echo -e "${BBlue}Enabling and starting Stubby service...${NC}"
systemctl enable stubby

systemctl enable systemd-resolved.service  # Enable and start

# Set the timezone
echo -e "${BBlue}Setting the timezone to $TIMEZONE...${NC}"
ln -sf "/usr/share/zoneinfo/$TIMEZONE" /etc/localtime
hwclock --systohc --utc

# Set up locale
echo -e "${BBlue}Setting up locale to $LOCALE...${NC}"
sed -i "s/#$LOCALE/$LOCALE/" /etc/locale.gen
locale-gen
echo "LANG=$LOCALE" > /etc/locale.conf
export LANG="$LOCALE"

echo -e "${BBlue}Setting up console keymap and fonts...${NC}"
echo 'KEYMAP=de_CH-latin1' > /etc/vconsole.conf &&
echo 'FONT=lat9w-16' >> /etc/vconsole.conf &&
echo 'FONT_MAP=8859-1_to_uni' >> /etc/vconsole.conf

echo -e "${BBlue}Configuring IPtables...${NC}"
# Set default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback interface traffic (localhost communication)
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established and related incoming connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow SSH on custom port ($SSH_PORT) with rate limiting
iptables -A INPUT -p tcp --dport "$SSH_PORT" -m conntrack --ctstate NEW -m limit --limit 2/min --limit-burst 5 -j ACCEPT

# Drop any other new connections to the custom SSH port beyond the rate limit
iptables -A INPUT -p tcp --dport "$SSH_PORT" -m conntrack --ctstate NEW -j DROP

# Drop invalid packets
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# Save rules for persistency
iptables-save > /etc/iptables/rules.v4

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

echo -e "${BBlue}Installing and configuring haveged...${NC}"
pacman -S --noconfirm haveged
systemctl enable haveged.service

echo -e "${BBlue}Installing file security utility pax-utils & arch-audit...${NC}"
pacman -S --noconfirm 	arch-audit pax-utils

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
  clamconf -g freshclam.conf > freshclam.conf
  mv freshclam.conf /etc/clamav/freshclam.conf
fi

if [ ! -f /etc/clamav/clamd.conf ]; then
  echo "Generating /etc/clamav/clamd.conf..."
  clamconf -g clamd.conf > clamd.conf
  mv clamd.conf /etc/clamav/clamd.conf
fi

if [ ! -f /etc/clamav/clamav-milter.conf ]; then
  echo "Generating /etc/clamav/clamav-milter.conf..."
  clamconf -g clamav-milter.conf > clamav-milter.conf
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
    sed -i "s|^#\?\s*${KEY}.*|${KEY} ${VALUE}|" "$CLAMD_CONF"
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

# 5) (Optional) Start the freshclam service so definitions update immediately
echo "Starting clamav-freshclam.service..."
systemctl start clamav-freshclam.service || true

# 6) Update definitions manually now (optional)
echo "Updating ClamAV definitions once..."
freshclam

# 7) Enable and start clamd for on-demand scanning
echo "Enabling and starting clamd.service..."
systemctl enable clamav-daemon.service
systemctl start clamav-daemon.service || true

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
echo "auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900" >> /etc/pam.d/common-auth

# More umasking
echo -e "${BBlue}Setting additional UMASK 027s...${NC}"
echo "umask 027" | sudo tee -a /etc/profile
echo "umask 027" | sudo tee -a /etc/bash.bashrc

# Disable unwanted protocols
echo -e "${BBlue}Disabling unwanted protocols...${NC}"
echo "install dccp /bin/true" >> /etc/modprobe.d/disable-protocols.conf
echo "install sctp /bin/true" >> /etc/modprobe.d/disable-protocols.conf
echo "install rds /bin/true" >> /etc/modprobe.d/disable-protocols.conf
echo "install tipc /bin/true" >> /etc/modprobe.d/disable-protocols.conf

# Disabling core dump. Please feel free to comment if you need it.
echo -e "${BBlue}Disabling core dump...${NC}"
echo "* hard core 0" >> /etc/security/limits.conf

# Using NTP for better reliability
echo -e "${BBlue}Using NTP Daemon or NTP Client to Prevent Time Issues...${NC}"
pacman -S --noconfirm chrony
pacman -S --noconfirm ntp
systemctl enable chronyd
systemctl enable ntpd

# Sysstem monitoring tool
echo -e "${BBlue}Enabling sysstat to Collect Accounting...${NC}"
pacman -S --noconfirm sysstat
systemctl enable sysstat

# System auditing tool
echo -e "${BBlue}Enabling auditd to Collect Audit Information...${NC}"
pacman -S --noconfirm audit

# Check if wget is installed
if ! command -v wget &> /dev/null; then
    echo "wget could not be found, please install wget and try again."
    exit 1
fi

# Download the auditd rules
echo "Downloading auditd rules from $RULES_URL..."
wget -O "$LOCAL_RULES_FILE" "$RULES_URL"

# Verify download success
if [ $? -ne 0 ]; then
    echo "Failed to download auditd rules."
    exit 1
else
    echo "Auditd rules downloaded successfully."
fi

# Restart auditd to apply the new rules
echo "Restarting auditd to apply the new rules..."
systemctl restart auditd

if [ $? -ne 0 ]; then
    echo "Failed to restart auditd. Check the service status for details."
    exit 1
else
    echo "Auditd restarted successfully. New rules are now active."
fi

systemctl enable auditd

# Enable and configure necessary services
echo -e "${BBlue}Enabling NetworkManager...${NC}"
systemctl enable NetworkManager

echo -e "${BBlue}Enabling OpenSSH...${NC}"
systemctl enable sshd

echo -e "${BBlue}Enabling DHCP...${NC}"
systemctl enable dhcpcd.service

# Installing Fail2ban
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

# Configure sudo
echo -e "${BBlue}Hardening sudo...${NC}"
# Create a group for sudo
groupadd sudo

# Set the secure path for sudo.
echo "Defaults secure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"" > /etc/sudoers

# Disable the ability to run commands with root password.
echo "Defaults !rootpw" >> /etc/sudoers

# Set the default umask for sudo.
echo "Defaults umask=077" >> /etc/sudoers

# Set the default editor for sudo.
echo "Defaults editor=/usr/bin/vim" >> /etc/sudoers

# Set the default environment variables for sudo.
echo "Defaults env_reset" >> /etc/sudoers
echo "Defaults env_reset,env_keep=\"COLORS DISPLAY HOSTNAME HISTSIZE INPUTRC KDEDIR LS_COLORS\"" >> /etc/sudoers
echo "Defaults env_keep += \"MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE\"" >> /etc/sudoers
echo "Defaults env_keep += \"LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES\"" >> /etc/sudoers
echo "Defaults env_keep += \"LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE\"" >> /etc/sudoers
echo "Defaults env_keep += \"LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY\"" >> /etc/sudoers

# Set the security tweaks for sudoers file
echo "Defaults timestamp_timeout=30" >> /etc/sudoers
echo "Defaults !visiblepw" >> /etc/sudoers
echo "Defaults always_set_home" >> /etc/sudoers
echo "Defaults match_group_by_gid" >> /etc/sudoers
echo "Defaults always_query_group_plugin" >> /etc/sudoers
echo "Defaults passwd_timeout=10" >> /etc/sudoers # 10 minutes before sudo times out
echo "Defaults passwd_tries=3" >> /etc/sudoers # Nr of attempts to enter password
echo "Defaults loglinelen=0" >> /etc/sudoers
echo "Defaults insults" >> /etc/sudoers # Insults user when wrong password is entered :)
echo "Defaults lecture=once" >> /etc/sudoers
echo "Defaults requiretty" >> /etc/sudoers # Forces to use real tty and not cron or cgi-bin
echo "Defaults logfile=/var/log/sudo.log" >> /etc/sudoers
echo "Defaults log_input, log_output" >> /etc/sudoers # Log input and output of sudo commands
echo "%sudo ALL=(ALL) ALL" >> /etc/sudoers
echo "@includedir /etc/sudoers.d" >> /etc/sudoers

# Set permissions for /etc/sudoers
echo -e "${BBlue}Setting permissions for /etc/sudoers${NC}"
chmod 440 /etc/sudoers
chown root:root /etc/sudoers

# Install arch-audit to Determine Vulnerable Packages
echo -e "${BBlue}Installing arch-audit for vulnerability scanning...${NC}"
pacman -S --noconfirm arch-audit

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
echo -e "${BBlue}Downloading nanorc...${NC}"
curl -sL https://raw.githubusercontent.com/scopatz/nanorc/master/install.sh | sh -s -- -y

# Add the following settings to the nano configuration file to harden it
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

echo -e "${BBlue}Configuring and hardening SSH or port $SSH_PORT...${NC}"
/ssh.sh

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

  # Use 'install' for atomic file writing
  install -Dm644 /dev/stdin "$SSH_CONFIG_FILE" <<EOF
 Host "$HOSTNAME"  # Use hostname for Host entry
  HostName "$HOSTNAME" # or IP if needed
  Port "$SSH_PORT"
  User "$USERNAME"
  IdentityFile "$SSH_KEY_FILE"
  # ... other SSH options as needed ...
  HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
  KexAlgorithms curve25519-sha256@libssh.org,curve25519-sha256,diffie-hellman-group18-sha512,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256,diffie-hellman-group-exchange-sha256
  Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr
  MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
EOF

echo "SSH client configuration updated."

# --- SSH Server Configuration (Optional) ---
# ... (Add server-side configuration here if needed) ...

# --- SSH Finalization ---
echo -e "${BBlue}Hashing known_hosts file...${NC}"
ssh-keygen -H -f "/home/$USERNAME/.ssh/known_hosts" 2>/dev/null || true # Suppress stderr if file doesn't exist

touch "/home/$USERNAME/.ssh/authorized_keys"
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
cat <<EOF > /usr/local/bin/rotate-ssh-keys.sh
#!/bin/bash
ssh-keygen -t "$SSH_KEY_TYPE" -f "$SSH_KEY_FILE" -q -N "" -C "$USERNAME@$HOSTNAME-$(date +%Y%m%d)"
chown "$USERNAME:$USERNAME" "$SSH_KEY_FILE" "$SSH_KEY_FILE.pub"
chmod 600 "$SSH_KEY_FILE" "$SSH_KEY_FILE.pub"
EOF
chmod +x /usr/local/bin/rotate-ssh-keys.sh
echo "0 0 1 */3 * /usr/local/bin/rotate-ssh-keys.sh" >> /etc/crontab

sleep 1

echo -e "${BBlue}Applying hardened compiler flags...${NC}"
sed -i '/^CFLAGS=/ s/"$/ -fstack-protector-strong -D_FORTIFY_SOURCE=2"/' /etc/makepkg.conf
sed -i '/^CXXFLAGS=/ s/"$/ -fstack-protector-strong -D_FORTIFY_SOURCE=2"/' /etc/makepkg.conf
sed -i '/^LDFLAGS=/ s/"$/ -Wl,-z,relro,-z,now"/' /etc/makepkg.conf
sed -i '/^OPTIONS=/ s/!/!pie /' /etc/makepkg.conf

# Harden Compilers by Restricting Access to Root User Only
echo -e "${BBlue}Restricting access to compilers using a 'compilers' group...${NC}"

# Alternative approach using a 'compilers' group
groupadd compilers
usermod -aG compilers "$USERNAME"
for compiler in gcc g++ clang make as ld; do
    if command -v "$compiler" &> /dev/null; then
        chown root:compilers "$(which $compiler)"
        chmod 750 "$(which $compiler)"
    fi
done

# Set default ACLs on home directory
echo -e "${BBlue}Setting default ACLs on home directory${NC}"
setfacl -d -m u::rwx,g::---,o::--- ~

echo -e "${BBlue}Adding GRUB package...${NC}"
pacman -S grub efibootmgr os-prober --noconfirm

# GRUB hardening setup and encryption
echo -e "${BBlue}Adjusting /etc/mkinitcpio.conf for encryption...${NC}"
sed -i "s|^HOOKS=.*|HOOKS=(base udev autodetect keyboard keymap modconf block encrypt lvm2 filesystems fsck)|g" /etc/mkinitcpio.conf
sed -i "s|^FILES=.*|FILES=(${LUKS_KEYS})|g" /etc/mkinitcpio.conf
mkinitcpio -p linux &&\

echo -e "${BBlue}Adjusting etc/default/grub for encryption...${NC}"
sed -i '/GRUB_ENABLE_CRYPTODISK/s/^#//g' /etc/default/grub

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
GRUBCMD="\"cryptdevice=UUID=$UUID:$LVM_NAME root=/dev/mapper/$LVM_NAME-root cryptkey=rootfs:$LUKS_KEYS\""
sed -i "s|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT=${GRUBSEC}|g" /etc/default/grub
sed -i "s|^GRUB_CMDLINE_LINUX=.*|GRUB_CMDLINE_LINUX=${GRUBCMD}|g" /etc/default/grub

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
    sed -i 's|^MODULES=.*|MODULES=(nvidia nvidia_drm nvidia_uvm nvidia_modeset)|' /etc/mkinitcpio.conf
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

  # Set GRUB_GFXMODE and GRUB_GFXPAYLOAD_LINUX
  sed -i -E \
    -e 's/^#?(GRUB_GFXMODE=).*/\1"1024x768x32,auto"/' \
    -e 's/^#?(GRUB_GFXPAYLOAD_LINUX=).*/\1"keep"/' \
    /etc/default/grub

  echo -e "${BBlue}Setting up GRUB...${NC}"
  mkdir -p /boot/grub

  # Generate initial grub.cfg BEFORE installing
  grub-mkconfig -o /boot/grub/grub.cfg

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

cat <<EOF >> /etc/grub.d/40_custom
set superusers="$USERNAME"
password_pbkdf2 "$USERNAME" "$GRUB_PASS"
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
chmod 0600 /etc/login.defs
chown root:root /etc/issue
chmod 644 /etc/issue

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
cat <<EOF > /etc/systemd/system/pacman-autoupdate.service
[Unit]
Description=Update system packages automatically

[Service]
Type=oneshot
ExecStart=/usr/bin/pacman -Syu --noconfirm
EOF
systemctl enable pacman-autoupdate.timer

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
shred -u /chroot.sh
exit
