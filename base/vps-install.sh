#!/bin/bash

# Description: Arch Linux VPS Security-Hardened Installation
# Adapted from archinstall.sh for VPS/cloud environments
# - No LUKS/GRUB encryption (VPS providers handle disk encryption)
# - No TPM (not available on VPS)
# - Simplified partitioning (single root + swap, or provider-managed)
# - Skips physical security (USBGuard, Bluetooth, GPU drivers)
# - Keeps all software hardening (sysctl, nftables, SSH, PAM, etc.)
#
# Author: Bruno Schmid @brulliant
# LinkedIn: https://www.linkedin.com/in/schmidbruno/

set -euo pipefail

# --- Color variables ---
# shellcheck disable=SC2034  # Color palette — all referenced in echo -e strings
BBlue='\033[1;34m'
BRed='\033[1;31m'
BGreen='\033[1;32m'
BYellow='\033[1;33m'
NC='\033[0m'

# --- Logging setup ---
INSTALL_LOG="/tmp/vps-install-$(date +%Y%m%d-%H%M%S).log"
exec 2> >(tee -a "$INSTALL_LOG")

log_action() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$INSTALL_LOG"
}

# --- Check requirements ---
if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root." >&2
   exit 1
fi

if [ ! -d "/sys/firmware/efi/efivars" ]; then
  echo -e "${BYellow}UEFI not detected. Will use BIOS/MBR boot.${NC}"
  BOOT_MODE="bios"
else
  echo -e "${BBlue}UEFI detected, proceeding...${NC}"
  BOOT_MODE="uefi"
fi
log_action "Boot mode: $BOOT_MODE"

# -----------------------
# 1. HELPER FUNCTIONS
# -----------------------

ask_yes_no() {
    local prompt_msg="$1"
    local choice
    while true; do
        read -p "$prompt_msg (y/n): " choice
        case "$choice" in
            [Yy]) echo "y"; return 0 ;;
            [Nn]) echo "n"; return 0 ;;
            *) echo -e "${BRed}Invalid choice. Please type 'y' or 'n'.\n${NC}" >&2 ;;
        esac
    done
}

ask_for_disk() {
    local disk
    while true; do
        read -p "Select the target disk (e.g., sda, vda, nvme0n1): " disk
        if [[ -b "/dev/$disk" ]]; then
            echo "$disk"
            return 0
        else
            echo -e "${BRed}Error: Disk /dev/$disk does not exist or is not a block device.\n${NC}" >&2
        fi
    done
}

ask_for_numeric() {
    local prompt_msg="$1"
    local input_val
    while true; do
        read -p "$prompt_msg " input_val
        if [[ "$input_val" =~ ^[0-9]+$ ]]; then
            echo "$input_val"
            return 0
        else
            echo -e "${BRed}Invalid input: '$input_val'. Please enter a positive number.\n${NC}" >&2
        fi
    done
}

ask_for_username() {
    local username
    while true; do
        read -p "Enter the new username: " username
        if [[ "$username" =~ ^[a-z_][a-z0-9_-]*$ ]] && [[ ${#username} -le 32 ]]; then
            echo "$username"
            return 0
        else
            echo -e "${BRed}Invalid username. Must begin with [a-z_], contain only [a-z0-9_-], max 32 chars.\n${NC}" >&2
        fi
    done
}

ask_for_hostname() {
    local hostname
    while true; do
        read -p "Enter the new hostname: " hostname
        if [[ "$hostname" =~ ^[a-zA-Z0-9][a-zA-Z0-9\.-]*$ ]] && [[ ${#hostname} -le 64 ]]; then
            echo "$hostname"
            return 0
        else
            echo -e "${BRed}Invalid hostname. Must begin with alphanumeric, contain only [a-zA-Z0-9.-], max 64 chars.\n${NC}" >&2
        fi
    done
}

validate_network() {
    echo -e "${BBlue}Checking network connection...${NC}"
    if ! ping -c 1 archlinux.org &>/dev/null; then
        echo -e "${BRed}Warning: No network connection detected.${NC}"
        if [[ $(ask_yes_no "Continue anyway?") == "n" ]]; then
            exit 1
        fi
    fi
}

# -----------------------
# 2. MAIN EXECUTION
# -----------------------

log_action "Starting Arch Linux VPS installation script"

echo -e "${BBlue}Syncing system time...${NC}"
timedatectl set-ntp true
sleep 2

# Configure secure DNS for installation
echo -e "${BBlue}Configuring secure DNS...${NC}"
cat > /etc/resolv.conf <<EOF
nameserver 9.9.9.9
nameserver 1.1.1.1
nameserver 8.8.8.8
EOF

validate_network

# Select mirrors
echo -e "${BBlue}Selecting fastest HTTPS mirrors...${NC}"
cp /etc/pacman.d/mirrorlist /etc/pacman.d/mirrorlist.backup
curl -s "https://archlinux.org/mirrorlist/?country=all&protocol=https&ip_version=4" | \
    sed -e 's/^#Server/Server/' -e '/^#/d' > /tmp/mirrorlist.tmp
head -20 /tmp/mirrorlist.tmp > /etc/pacman.d/mirrorlist
rm -f /tmp/mirrorlist.tmp

# -----------------------
# 3. GATHER USER INPUT
# -----------------------

echo -e "${BBlue}Available disks:\n${NC}"
lsblk -d -o NAME,SIZE,TYPE,MODEL | grep "disk"
echo

TARGET_DISK=$(ask_for_disk)
DISK="/dev/$TARGET_DISK"
echo -e "${BGreen}Selected: $DISK${NC}\n"
log_action "Selected disk: $DISK"

# Partition sizes
echo -e "${BBlue}Partition sizes:\n${NC}"
SIZE_OF_SWAP=$(ask_for_numeric "SWAP size in GB (recommended: 1-2 for VPS):")
echo

# Ask about separate /var partition
CREATE_VAR_PART=$(ask_yes_no "Create separate /var partition? (recommended for web servers)")
VAR_SIZE=""
SIZE_OF_VAR=0
if [[ "$CREATE_VAR_PART" == "y" ]]; then
    SIZE_OF_VAR=$(ask_for_numeric "/var size in GB:")
    VAR_SIZE="${SIZE_OF_VAR}G"
fi

# User configuration
echo -e "${BBlue}\nUser configuration:\n${NC}"
USERNAME=$(ask_for_username)
HOSTNAME=$(ask_for_hostname)

# Ask for SSH port
read -p "SSH port (default 22): " SSH_PORT_INPUT
SSH_PORT="${SSH_PORT_INPUT:-22}"

echo -e "\nUsername: $USERNAME"
echo -e "Hostname: $HOSTNAME"
echo -e "SSH Port: $SSH_PORT\n"

log_action "User: $USERNAME, Hostname: $HOSTNAME, SSH Port: $SSH_PORT"

# -----------------------
# 4. DISK PREPARATION
# -----------------------

# Partition suffix for nvme/mmc devices
if [[ "$DISK" =~ [0-9]$ ]]; then
    PART_SUFFIX="p"
else
    PART_SUFFIX=""
fi

echo -e "${BBlue}Creating partitions...${NC}"
log_action "Creating partition table"

sgdisk -Z "$DISK"
sgdisk -o "$DISK"

if [ "$BOOT_MODE" = "uefi" ]; then
    # UEFI: EFI partition + root
    sgdisk -n 1:2048:2101247 -t 1:ef00 -c 1:"EFI_System" "$DISK"
    sgdisk -n 2:2101248:0 -t 2:8300 -c 2:"Linux_Root" "$DISK"
    BOOT_PART="${DISK}${PART_SUFFIX}1"
    ROOT_PART="${DISK}${PART_SUFFIX}2"
else
    # BIOS: BIOS boot partition + root
    sgdisk -n 1:2048:4095 -t 1:ef02 -c 1:"BIOS_Boot" "$DISK"
    sgdisk -n 2:4096:0 -t 2:8300 -c 2:"Linux_Root" "$DISK"
    BOOT_PART="${DISK}${PART_SUFFIX}1"
    ROOT_PART="${DISK}${PART_SUFFIX}2"
fi

partprobe "$DISK"
sleep 2

# -----------------------
# 5. FILESYSTEM SETUP
# -----------------------

echo -e "${BBlue}Formatting filesystems...${NC}"
log_action "Formatting filesystems"

mkfs.ext4 -F -m 1 -E lazy_itable_init=0,lazy_journal_init=0 "$ROOT_PART"

# Mount root
mount --verbose "$ROOT_PART" /mnt

# Create swap file (simpler than LVM for VPS)
echo -e "${BBlue}Creating swap file...${NC}"
dd if=/dev/zero of=/mnt/swapfile bs=1G count="$SIZE_OF_SWAP" status=progress
chmod 600 /mnt/swapfile
mkswap /mnt/swapfile
swapon /mnt/swapfile

# Create /var if requested
if [[ -n "$VAR_SIZE" ]]; then
    echo -e "${BYellow}Note: Separate /var requires manual partitioning or LVM.${NC}"
    echo -e "${BYellow}Using a single partition with /var on root for VPS simplicity.${NC}"
fi

# Prepare EFI (if UEFI)
if [ "$BOOT_MODE" = "uefi" ]; then
    echo -e "${BBlue}Preparing EFI partition...${NC}"
    mkfs.vfat -F32 -n "EFI" "$BOOT_PART"
    mkdir --verbose -p /mnt/efi
    mount --verbose "$BOOT_PART" /mnt/efi
fi

# -----------------------
# 6. BASE INSTALLATION
# -----------------------

echo -e "${BBlue}Updating keyring...${NC}"
pacman -Sy --noconfirm archlinux-keyring

echo -e "${BBlue}Installing base system...${NC}"
log_action "Installing base system"

pacstrap /mnt base base-devel archlinux-keyring \
    linux linux-headers linux-hardened linux-hardened-headers \
    linux-firmware \
    grub efibootmgr \
    networkmanager openssh \
    iptables-nft nftables \
    apparmor audit rng-tools \
    lynis arch-audit rkhunter \
    firejail bubblewrap \
    git wget curl rsync \
    neovim vim nano nano-syntax-highlighting \
    zsh zsh-completions \
    unzip unrar p7zip zip \
    mtools dosfstools \
    net-tools usbutils pciutils \
    dialog \
    noto-fonts ttf-dejavu ttf-liberation \
    man-db man-pages texinfo

# -----------------------
# 7. SYSTEM CONFIGURATION
# -----------------------

echo -e "${BBlue}Generating fstab...${NC}"
genfstab -U /mnt > /mnt/etc/fstab

# Add swap file to fstab
echo "/swapfile none swap defaults 0 0" >> /mnt/etc/fstab

# Add security mount options
cat >> /mnt/etc/fstab <<EOF

# Security-hardened mount options
tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,relatime,size=2G 0 0
tmpfs /dev/shm tmpfs rw,nosuid,nodev,noexec,relatime,size=2G 0 0
proc /proc proc nosuid,nodev,noexec,hidepid=2,gid=proc 0 0
EOF

# Setup systemd for hidepid
mkdir -p /mnt/etc/systemd/system/systemd-logind.service.d
cat <<EOF > /mnt/etc/systemd/system/systemd-logind.service.d/hidepid.conf
[Service]
SupplementaryGroups=proc
EOF

# Create installation info
cat > /mnt/root/.install-env <<EOF
export INSTALL_DISK="$DISK"
export INSTALL_USER="$USERNAME"
export INSTALL_HOST="$HOSTNAME"
export INSTALL_DATE="$(date)"
export INSTALL_TYPE="vps"
export INSTALL_SSH_PORT="$SSH_PORT"
EOF
chmod 600 /mnt/root/.install-env

cat > /mnt/set-install-vars.sh <<EOF
export _INSTALL_DISK="$DISK"
export _INSTALL_USER="$USERNAME"
export _INSTALL_HOST="$HOSTNAME"
export _INSTALL_SSH_PORT="$SSH_PORT"
export _INSTALL_TYPE="vps"
EOF

chmod +x /mnt/set-install-vars.sh
cp ./vps-chroot.sh /mnt/
chmod +x /mnt/vps-chroot.sh

# Copy hardening scripts
if [ -f ../hardening/sysctl/sysctl.sh ]; then
    cp ../hardening/sysctl/sysctl.sh /mnt/
    chmod +x /mnt/sysctl.sh
fi

if [ -f ../hardening/ssh/ssh.sh ]; then
    cp ../hardening/ssh/ssh.sh /mnt/
    chmod +x /mnt/ssh.sh
fi

# Create AUR installation script
cat > /mnt/root/install-aur-packages.sh <<'AURSCRIPT'
#!/bin/bash
set -euo pipefail

BBlue='\033[1;34m'
NC='\033[0m'

echo -e "${BBlue}Installing yay AUR helper...${NC}"
YAY_BUILD="/tmp/yay"
git clone https://aur.archlinux.org/yay.git "$YAY_BUILD"
cd "$YAY_BUILD"
makepkg -si --noconfirm
cd /
rm -rf "$YAY_BUILD"

echo -e "${BBlue}Installing AUR security packages...${NC}"
yay -S --noconfirm aide
yay -S --noconfirm acct

echo -e "${BBlue}Initializing AIDE...${NC}"
aide --config=/etc/aide.conf --init
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

systemctl enable psacct.service
systemctl start psacct.service

echo -e "${BBlue}AUR packages installed successfully${NC}"
shred -vzu /root/install-aur-packages.sh
AURSCRIPT

chmod 700 /mnt/root/install-aur-packages.sh

# Create post-installation README
cat > /mnt/root/POST_INSTALL_README.txt <<EOF
================================================================================
ARCH LINUX VPS SECURITY-HARDENED INSTALLATION
================================================================================

Installation Date: $(date)
Hostname: $HOSTNAME
Username: $USERNAME
Disk: $DISK
SSH Port: $SSH_PORT
Boot Mode: $BOOT_MODE

CRITICAL POST-INSTALLATION STEPS:
=================================

1. IMMEDIATE ACTIONS:
   - Run: /root/install-aur-packages.sh
   - Configure your SSH authorized_keys
   - Test SSH access before closing current session

2. SECURITY SERVICES:
   systemctl enable --now apparmor
   systemctl enable --now auditd
   systemctl enable --now rkhunter.timer
   systemctl enable --now arch-audit.timer

3. FIREWALL:
   - nftables is pre-configured for SSH on port $SSH_PORT
   - Add application-specific rules as needed

4. MAINTENANCE:
   - Weekly: arch-audit
   - Weekly: rkhunter --check
   - Weekly: aide --check
   - Check logs: journalctl -p err -b

5. SERIAL CONSOLE (if VPS provides one):
   - Already configured via systemd-getty

Installation log: $INSTALL_LOG
================================================================================
EOF

# Copy installation log
cp "$INSTALL_LOG" /mnt/root/ 2>/dev/null || true

# -----------------------
# 8. CHROOT CONFIGURATION
# -----------------------

echo -e "${BBlue}Entering chroot...${NC}"
log_action "Entering chroot environment"

arch-chroot /mnt bash -c "source /set-install-vars.sh && /vps-chroot.sh"

# -----------------------
# 9. CLEANUP
# -----------------------

echo -e "${BBlue}Performing cleanup...${NC}"
log_action "Performing cleanup"

# Clean up scripts
shred -vzu /mnt/vps-chroot.sh 2>/dev/null || true
shred -vzu /mnt/set-install-vars.sh 2>/dev/null || true
shred -vzu /mnt/sysctl.sh 2>/dev/null || true
shred -vzu /mnt/ssh.sh 2>/dev/null || true

# Clear pacman cache
arch-chroot /mnt bash -c "pacman -Scc --noconfirm"

# Clear bash history
arch-chroot /mnt bash -c "history -c && rm -f /root/.bash_history"

# -----------------------
# 10. COMPLETION
# -----------------------

echo -e "${BGreen}=================================================================================${NC}"
echo -e "${BGreen}VPS Installation completed successfully!${NC}"
echo -e "${BGreen}=================================================================================${NC}"
echo
echo -e "${BBlue}Next steps:${NC}"
echo "1. Reboot: reboot"
echo "2. Login as root"
echo "3. Run: /root/install-aur-packages.sh"
echo "4. Add your SSH public key to /home/$USERNAME/.ssh/authorized_keys"
echo "5. Test SSH access, then disable password authentication"
echo "6. Review: /root/POST_INSTALL_README.txt"
echo
echo -e "${BGreen}SSH is configured on port $SSH_PORT${NC}"

log_action "VPS installation completed successfully"
