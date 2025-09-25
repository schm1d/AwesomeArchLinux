#!/bin/bash

# Description: Fully encrypted LVM2 on LUKS with UEFI and TPM2 - Security Hardened
# Author: Bruno Schmid @brulliant
# LinkedIn: https://www.linkedin.com/in/schmidbruno/

set -euo pipefail

# --- Color variables ---
BBlue='\033[1;34m'
BRed='\033[1;31m'
BGreen='\033[1;32m'
BYellow='\033[1;33m'
NC='\033[0m'

# --- Global variables ---
TPM_AVAILABLE=false
TPM_VERSION=""
TPM_DEVICE=""
USE_TPM_LUKS=false
TPM_PCR_BANK="sha256"
TPM_PCRS="0+7"

# --- Logging setup ---
INSTALL_LOG="/tmp/installation-audit-$(date +%Y%m%d-%H%M%S).log"
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
  echo -e "${BRed}UEFI is not supported. Exiting.${NC}"
  exit 1
fi

echo -e "${BBlue}\nUEFI is supported, proceeding...\n${NC}"
log_action "UEFI support confirmed"

# -----------------------
# 1. HELPER FUNCTIONS
# -----------------------

# Prompt user yes/no question
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

# Prompt user for a valid block device
ask_for_disk() {
    local disk
    while true; do
        read -p "Select the target disk (e.g., sda, nvme0n1): " disk
        if [[ -b "/dev/$disk" ]]; then
            echo "$disk"
            return 0
        else
            echo -e "${BRed}Error: Disk /dev/$disk does not exist or is not a block device.\n${NC}" >&2
        fi
    done
}

# Prompt user for numeric input
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

# Prompt user for username
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

# Prompt user for hostname
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

# Loop until cryptsetup open succeeds
ask_luks_password_until_success() {
    local partition="$1"
    local crypt_name="$2"

    while true; do
        echo -e "${BBlue}\nTesting LUKS password...${NC}"
        if cryptsetup -v luksOpen "$partition" "$crypt_name"; then
            cryptsetup -v luksClose "$crypt_name"
            break
        else
            echo -e "${BRed}\nWrong password. Please try again.\n${NC}" >&2
        fi
    done
}

# Validate disk space
validate_disk_space() {
    local disk="$1"
    local swap="$2"
    local root="$3"
    local var="${4:-0}"
    
    local disk_size=$(lsblk -b -d -o SIZE -n "$disk" 2>/dev/null || echo 0)
    local required=$((($swap + $root + $var + 10) * 1073741824))
    
    if [[ $disk_size -lt $required ]]; then
        echo -e "${BRed}Error: Insufficient disk space. Need at least $(($required / 1073741824))GB${NC}" >&2
        return 1
    fi
    return 0
}

# Validate network connection
validate_network() {
    echo -e "${BBlue}Checking network connection...${NC}"
    if ! ping -c 1 archlinux.org &>/dev/null; then
        echo -e "${BRed}Warning: No network connection detected.${NC}"
        if [[ $(ask_yes_no "Continue anyway?") == "n" ]]; then
            exit 1
        fi
    fi
}

# Check entropy levels
check_entropy() {
    local entropy=$(cat /proc/sys/kernel/random/entropy_avail)
    if [ "$entropy" -lt 256 ]; then
        echo -e "${BBlue}Low entropy detected ($entropy). Generating additional entropy...${NC}"
        dd if=/dev/urandom of=/dev/null bs=1M count=100 status=progress 2>/dev/null
    fi
    echo -e "${BGreen}Entropy level: $(cat /proc/sys/kernel/random/entropy_avail)${NC}"
}

# Detect if device is SSD
detect_device_type() {
    local disk="$1"
    local device_name=$(basename "$disk")
    
    if [ -f "/sys/block/$device_name/queue/rotational" ]; then
        if [ "$(cat /sys/block/$device_name/queue/rotational)" = "0" ]; then
            echo "SSD"
        else
            echo "HDD"
        fi
    else
        echo "UNKNOWN"
    fi
}

# -----------------------
# 2. TPM FUNCTIONS
# -----------------------

detect_tpm() {
    echo -e "${BBlue}Detecting TPM device...${NC}"
    
    if [ -c /dev/tpm0 ] || [ -c /dev/tpmrm0 ]; then
        TPM_AVAILABLE=true
        TPM_VERSION="2.0"
        
        if [ -c /dev/tpmrm0 ]; then
            TPM_DEVICE="/dev/tpmrm0"
        else
            TPM_DEVICE="/dev/tpm0"
        fi
        
        echo -e "${BGreen}TPM 2.0 detected at $TPM_DEVICE${NC}"
        log_action "TPM 2.0 detected at $TPM_DEVICE"
        return 0
    else
        echo -e "${BYellow}No TPM device detected${NC}"
        log_action "No TPM device detected"
        return 1
    fi
}

setup_tpm_tools() {
    if [ "$TPM_AVAILABLE" = true ]; then
        echo -e "${BBlue}Installing TPM2 tools...${NC}"
        pacman -Sy --needed --noconfirm tpm2-tools tpm2-tss
        
        systemctl start tpm2-abrmd.service 2>/dev/null || true
        
        if [[ $(ask_yes_no "Do you want to clear the TPM? (requires physical presence)") == "y" ]]; then
            echo -e "${BYellow}Attempting to clear TPM...${NC}"
            tpm2_clear -c platform 2>/dev/null || echo -e "${BRed}TPM clear failed or not permitted${NC}"
        fi
    fi
}

test_tpm_functionality() {
    if [ "$TPM_AVAILABLE" = true ]; then
        echo -e "${BBlue}Testing TPM functionality...${NC}"
        
        if tpm2_getrandom 8 --hex 2>/dev/null; then
            echo -e "${BGreen}TPM random number generation successful${NC}"
        else
            echo -e "${BRed}TPM test failed${NC}"
            TPM_AVAILABLE=false
            return 1
        fi
        
        echo -e "${BBlue}Available PCR banks:${NC}"
        tpm2_pcrread sha256:0 2>/dev/null || true
    fi
}

setup_tpm_in_chroot() {
    if [ "$USE_TPM_LUKS" = true ]; then
        echo -e "${BBlue}Configuring TPM2 in chroot environment...${NC}"
        
        arch-chroot /mnt pacman -S --needed --noconfirm \
            tpm2-tools tpm2-tss tpm2-abrmd tpm2-pkcs11
        
        if [ -f ./tpm_luks.conf ]; then
            cp ./tpm_luks.conf /mnt/etc/tpm_luks.conf
            chmod 600 /mnt/etc/tpm_luks.conf
        fi
        
        # Configure mkinitcpio for TPM2
        arch-chroot /mnt bash -c '
            sed -i "s/^MODULES=.*/MODULES=(tpm tpm_tis tpm_crb)/" /etc/mkinitcpio.conf
            sed -i "s/^HOOKS=.*/HOOKS=(base systemd autodetect keyboard sd-vconsole modconf block sd-encrypt lvm2 filesystems fsck)/" /etc/mkinitcpio.conf
            mkinitcpio -P
        '
        
        # Create PCR check tool
        cat > /mnt/usr/local/bin/check-tpm-pcrs <<'TPMCHECK'
#!/bin/bash
echo "Current PCR values:"
tpm2_pcrread sha256:0+1+4+7+9
echo
echo "If system fails to unlock automatically after updates:"
echo "1. Boot with recovery key"
echo "2. Re-enroll TPM: systemd-cryptenroll --wipe-slot=tpm2 --tpm2-device=auto --tpm2-pcrs=0+7 /dev/[device]"
TPMCHECK
        chmod +x /mnt/usr/local/bin/check-tpm-pcrs
    fi
}

# -----------------------
# 3. MAIN EXECUTION
# -----------------------

log_action "Starting Arch Linux installation script"

# Initial setup
echo -e "${BBlue}Syncing system time...${NC}"
timedatectl set-ntp true
sleep 2

# Configure secure DNS
echo -e "${BBlue}Configuring secure DNS...${NC}"
cat > /etc/resolv.conf <<EOF
nameserver 9.9.9.9
nameserver 1.1.1.1
nameserver 8.8.8.8
EOF

# Validate network
validate_network

# Select mirrors - avoid SIGPIPE from head
echo -e "${BBlue}Selecting fastest HTTPS mirrors...${NC}"
cp /etc/pacman.d/mirrorlist /etc/pacman.d/mirrorlist.backup
curl -s "https://archlinux.org/mirrorlist/?country=all&protocol=https&ip_version=4" | \
    sed -e 's/^#Server/Server/' -e '/^#/d' > /tmp/mirrorlist.tmp
head -20 /tmp/mirrorlist.tmp > /etc/pacman.d/mirrorlist
rm -f /tmp/mirrorlist.tmp

# Detect and setup TPM
detect_tpm || true
if [ "$TPM_AVAILABLE" = true ]; then
    setup_tpm_tools
    test_tpm_functionality || true
    
    if [ "$TPM_AVAILABLE" = true ]; then
        echo -e "${BGreen}TPM2 is available for encryption${NC}"
        if [[ $(ask_yes_no "Use TPM2 for LUKS encryption?") == "y" ]]; then
            USE_TPM_LUKS=true
            
            echo -e "${BBlue}Select PCRs to bind:${NC}"
            echo "  0+7 - Firmware and Secure Boot (Recommended)"
            echo "  0+1+7 - Plus BIOS config (More secure)"
            echo "  0+1+4+7+9 - Plus bootloader and kernel (Most secure)"
            
            read -p "Enter PCRs (default: 0+7): " TPM_PCRS
            TPM_PCRS=${TPM_PCRS:-"0+7"}
            echo -e "${BGreen}Will bind to PCRs: $TPM_PCRS${NC}"
            log_action "TPM2 binding configured for PCRs: $TPM_PCRS"
        fi
    fi
fi

# -----------------------
# 4. GATHER USER INPUT
# -----------------------

echo -e "${BBlue}Available disks:\n${NC}"
lsblk -d -o NAME,SIZE,TYPE,MODEL | grep "disk"
echo

TARGET_DISK=$(ask_for_disk)
DISK="/dev/$TARGET_DISK"
DEVICE_TYPE=$(detect_device_type "$DISK")

echo -e "${BGreen}Selected: $DISK (Type: $DEVICE_TYPE)${NC}\n"
log_action "Selected disk: $DISK (Type: $DEVICE_TYPE)"

# Partition sizes
echo -e "${BBlue}Partition sizes:\n${NC}"
SIZE_OF_SWAP=$(ask_for_numeric "SWAP size in GB:")
SIZE_OF_ROOT=$(ask_for_numeric "Root (/) size in GB:")

echo
CREATE_VAR_PART=$(ask_yes_no "Create separate /var partition?")
VAR_SIZE=""
SIZE_OF_VAR=0
if [[ "$CREATE_VAR_PART" == "y" ]]; then
    SIZE_OF_VAR=$(ask_for_numeric "/var size in GB:")
    VAR_SIZE="${SIZE_OF_VAR}G"
fi

# Validate disk space
if ! validate_disk_space "$DISK" "$SIZE_OF_SWAP" "$SIZE_OF_ROOT" "$SIZE_OF_VAR"; then
    exit 1
fi

# User configuration
echo -e "${BBlue}\nUser configuration:\n${NC}"
USERNAME=$(ask_for_username)
HOSTNAME=$(ask_for_hostname)
echo -e "\nUsername: $USERNAME"
echo -e "Hostname: $HOSTNAME\n"

log_action "User: $USERNAME, Hostname: $HOSTNAME"

SWAP_SIZE="${SIZE_OF_SWAP}G"
ROOT_SIZE="${SIZE_OF_ROOT}G"
CRYPT_NAME='crypt_lvm'
LVM_NAME='lvm_arch'
LUKS_KEYS='/etc/luksKeys'

# -----------------------
# 5. DISK PREPARATION
# -----------------------

# Partition suffix
if [[ "$DISK" =~ [0-9]$ ]]; then
    PART_SUFFIX="p"
else
    PART_SUFFIX=""
fi

PARTITION1="${DISK}${PART_SUFFIX}1"
PARTITION2="${DISK}${PART_SUFFIX}2"
PARTITION3="${DISK}${PART_SUFFIX}3"

# Optional secure wipe
if [[ $(ask_yes_no "Securely wipe disk before encryption?") == "y" ]]; then
    if [[ $(ask_yes_no "Use fast wipe (less secure)?") == "y" ]]; then
        echo -e "${BBlue}Fast wiping disk...${NC}"
        dd if=/dev/zero of="$DISK" bs=1M status=progress conv=fsync
    else
        echo -e "${BBlue}Secure wiping disk (this will take time)...${NC}"
        dd if=/dev/urandom of="$DISK" bs=1M status=progress conv=fsync
    fi
fi

echo -e "${BBlue}Creating partitions...${NC}"
log_action "Creating partition table"

sgdisk -Z "$DISK"
sgdisk -o "$DISK"

if [ "$DEVICE_TYPE" = "SSD" ]; then
    sgdisk -a 2048 "$DISK"
fi

sgdisk -n 1:2048:4095 -t 1:ef02 -c 1:"BIOS_Boot" "$DISK"
sgdisk -n 2:4096:2101247 -t 2:ef00 -c 2:"EFI_System" "$DISK"
sgdisk -n 3:2101248:0 -t 3:8309 -c 3:"Linux_LUKS" "$DISK"

partprobe "$DISK"
sleep 2

# -----------------------
# 6. LUKS SETUP
# -----------------------

check_entropy

echo -e "${BBlue}\nCreating LUKS container...${NC}"
log_action "Creating LUKS container"

# Create LUKS container
cryptsetup -v \
    --type luks1 \
    --cipher aes-xts-plain64 \
    --key-size 512 \
    --hash sha512 \
    --iter-time 3000 \
    --use-random \
    --verify-passphrase \
    luksFormat "$PARTITION3"

# Test password
ask_luks_password_until_success "$PARTITION3" "$CRYPT_NAME"

# Create keys
echo -e "${BBlue}Creating encryption keys...${NC}"
check_entropy
dd if=/dev/random of=./boot.key bs=512 count=8 iflag=fullblock
dd if=/dev/random of=./recovery.key bs=512 count=8 iflag=fullblock

# Add keys to LUKS
cryptsetup -v luksAddKey --key-slot 1 "$PARTITION3" ./boot.key
cryptsetup -v luksAddKey --key-slot 2 "$PARTITION3" ./recovery.key

echo -e "${BGreen}IMPORTANT: Save recovery.key externally NOW!${NC}"
read -p "Press Enter after saving recovery.key..."

# TPM2 enrollment (if selected)
if [ "$USE_TPM_LUKS" = true ]; then
    echo -e "${BBlue}Setting up TPM2 enrollment...${NC}"
    
    # Get UUID for later configuration
    UUID=$(cryptsetup luksUUID "$PARTITION3")
    
    # Create config for later enrollment
    cat > ./tpm_luks.conf <<EOF
CRYPTDEVICE=UUID=$UUID:$CRYPT_NAME
TPM2_PCRS=$TPM_PCRS
TPM2_DEVICE=$TPM_DEVICE
EOF
    
    echo -e "${BYellow}Note: TPM2 enrollment will be completed after system installation${NC}"
fi

# Backup LUKS header
echo -e "${BBlue}Backing up LUKS header...${NC}"
cryptsetup luksHeaderBackup "$PARTITION3" --header-backup-file ./luks-header-backup.img
echo -e "${BGreen}IMPORTANT: Also save luks-header-backup.img externally!${NC}"
read -p "Press Enter after saving header backup..."

# Open LUKS container
echo -e "${BBlue}Opening LUKS container...${NC}"
cryptsetup -v luksOpen "$PARTITION3" "$CRYPT_NAME" --key-file ./boot.key

# -----------------------
# 7. LVM SETUP
# -----------------------

echo -e "${BBlue}Creating LVM volumes...${NC}"
log_action "Setting up LVM"

pvcreate --verbose "/dev/mapper/$CRYPT_NAME"
vgcreate --verbose "$LVM_NAME" "/dev/mapper/$CRYPT_NAME"

lvcreate --verbose -L "$ROOT_SIZE" "$LVM_NAME" -n root
lvcreate --verbose -L "$SWAP_SIZE" "$LVM_NAME" -n swap

if [[ -n "$VAR_SIZE" ]]; then
    lvcreate --verbose -L "$VAR_SIZE" "$LVM_NAME" -n var
fi
lvcreate --verbose -l 100%FREE "$LVM_NAME" -n home

# -----------------------
# 8. FORMAT & MOUNT
# -----------------------

echo -e "${BBlue}Formatting filesystems...${NC}"
log_action "Formatting filesystems"

mkfs.ext4 -m 1 -E lazy_itable_init=0,lazy_journal_init=0 "/dev/mapper/${LVM_NAME}-root"
mkfs.ext4 -m 0 -E lazy_itable_init=0,lazy_journal_init=0 "/dev/mapper/${LVM_NAME}-home"

if [[ -n "$VAR_SIZE" ]]; then
    mkfs.ext4 -m 5 -E lazy_itable_init=0,lazy_journal_init=0 "/dev/mapper/${LVM_NAME}-var"
fi

mkswap "/dev/mapper/${LVM_NAME}-swap"
swapon "/dev/mapper/${LVM_NAME}-swap"

# Optimize filesystems
echo -e "${BBlue}Optimizing filesystems...${NC}"
tune2fs -O has_journal,extent,huge_file,flex_bg,metadata_csum,64bit,dir_index "/dev/mapper/${LVM_NAME}-root"
tune2fs -O has_journal,extent,huge_file,flex_bg,metadata_csum,64bit,dir_index "/dev/mapper/${LVM_NAME}-home"
tune2fs -c 30 -i 180d "/dev/mapper/${LVM_NAME}-root"
tune2fs -c 30 -i 180d "/dev/mapper/${LVM_NAME}-home"

# Mount filesystems
echo -e "${BBlue}Mounting filesystems...${NC}"
mount --verbose "/dev/mapper/${LVM_NAME}-root" /mnt
mkdir --verbose /mnt/home
mount --verbose "/dev/mapper/${LVM_NAME}-home" /mnt/home

if [[ -n "$VAR_SIZE" ]]; then
    mkdir --verbose /mnt/var
    mount --verbose "/dev/mapper/${LVM_NAME}-var" /mnt/var
fi

mkdir --verbose -p /mnt/tmp

# Prepare EFI
echo -e "${BBlue}Preparing EFI partition...${NC}"
mkfs.vfat -F32 -n "EFI" "$PARTITION2"
mkdir --verbose /mnt/efi
mount --verbose "$PARTITION2" /mnt/efi

# -----------------------
# 9. BASE INSTALLATION
# -----------------------

echo -e "${BBlue}Updating keyring...${NC}"
pacman -Sy --noconfirm archlinux-keyring

echo -e "${BBlue}Installing base system...${NC}"
log_action "Installing base system"

pacstrap /mnt base base-devel archlinux-keyring \
    linux linux-headers linux-hardened linux-hardened-headers \
    linux-firmware intel-ucode amd-ucode \
    lvm2 cryptsetup device-mapper \
    grub efibootmgr os-prober \
    networkmanager iwd dhcpcd openssh \
    iptables-nft nftables \
    apparmor audit rng-tools haveged \
    lynis arch-audit rkhunter \
    firejail bubblewrap \
    git wget curl rsync \
    neovim vim nano nano-syntax-highlighting \
    zsh zsh-completions \
    unzip unrar p7zip zip unarj arj cabextract xz pbzip2 pixz lrzip cpio \
    mtools dosfstools ntfs-3g fuse3 \
    gdisk parted \
    net-tools usbutils pciutils \
    go rust nasm \
    dialog \
    sbctl \
    noto-fonts noto-fonts-cjk noto-fonts-emoji ttf-dejavu ttf-liberation \
    man-db man-pages texinfo

# Install TPM tools if TPM is being used
if [ "$USE_TPM_LUKS" = true ]; then
    pacstrap /mnt tpm2-tools tpm2-tss tpm2-abrmd tpm2-pkcs11
fi

# -----------------------
# 10. SYSTEM CONFIGURATION
# -----------------------

echo -e "${BBlue}Generating fstab...${NC}"
genfstab -U /mnt > /mnt/etc/fstab

# Add security mount options
cat >> /mnt/etc/fstab <<EOF

# Security-hardened mount options
tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,relatime,size=2G 0 0
tmpfs /dev/shm tmpfs rw,nosuid,nodev,noexec,relatime,size=2G 0 0
proc /proc proc nosuid,nodev,noexec,hidepid=2,gid=proc 0 0
EOF

# Configure encrypted swap
echo "swap /dev/mapper/${LVM_NAME}-swap /dev/urandom swap,cipher=aes-xts-plain64,size=512" >> /mnt/etc/crypttab

# Setup systemd for hidepid
mkdir -p /mnt/etc/systemd/system/systemd-logind.service.d
cat <<EOF > /mnt/etc/systemd/system/systemd-logind.service.d/hidepid.conf
[Service]
SupplementaryGroups=proc
EOF

# Copy LUKS key
echo -e "${BBlue}Setting up LUKS keys...${NC}"
mkdir --verbose -p "/mnt$LUKS_KEYS"
cp ./boot.key "/mnt$LUKS_KEYS/boot.key"
chmod 400 "/mnt$LUKS_KEYS/boot.key"
chown -R root:root "/mnt$LUKS_KEYS"
chmod 700 "/mnt$LUKS_KEYS"

# Copy TPM config if used
if [ "$USE_TPM_LUKS" = true ] && [ -f ./tpm_luks.conf ]; then
    cp ./tpm_luks.conf /mnt/etc/
    chmod 600 /mnt/etc/tpm_luks.conf
fi

# Create installation info
cat > /mnt/root/.install-env <<EOF
export INSTALL_DISK="$DISK"
export INSTALL_USER="$USERNAME"
export INSTALL_HOST="$HOSTNAME"
export INSTALL_CRYPT="$CRYPT_NAME"
export INSTALL_LVM="$LVM_NAME"
export INSTALL_VAR_SIZE="${VAR_SIZE:-}"
export INSTALL_TPM="$USE_TPM_LUKS"
export INSTALL_DATE="$(date)"
EOF
chmod 600 /mnt/root/.install-env

cat > /mnt/set-install-vars.sh <<EOF
export _INSTALL_DISK="$DISK"
export _INSTALL_USER="$USERNAME"
export _INSTALL_HOST="$HOSTNAME"
export _INSTALL_CRYPT="$CRYPT_NAME"
export _INSTALL_LVM="$LVM_NAME"
EOF

chmod +x /mnt/set-install-vars.sh
cp ./chroot.sh /mnt/
chmod +x /mnt/chroot.sh

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
cd /tmp
git clone https://aur.archlinux.org/yay.git
cd yay
makepkg -si --noconfirm
cd /
rm -rf /tmp/yay

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
ARCH LINUX SECURITY-HARDENED INSTALLATION
================================================================================

Installation Date: $(date)
Hostname: $HOSTNAME
Username: $USERNAME
Disk: $DISK (Type: $DEVICE_TYPE)
TPM2 Enabled: $USE_TPM_LUKS

CRITICAL POST-INSTALLATION STEPS:
=================================

1. IMMEDIATE ACTIONS:
   - Run: /root/install-aur-packages.sh
   - Secure backups of recovery.key and luks-header-backup.img

2. SECURITY SERVICES:
   systemctl enable --now apparmor
   systemctl enable --now auditd
   systemctl enable --now rkhunter.timer
   systemctl enable --now arch-audit.timer

3. TPM2 ENROLLMENT (if TPM enabled):
   - After first boot, enroll TPM:
     systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=$TPM_PCRS $PARTITION3
   - Test with: systemctl restart systemd-cryptsetup@*.service

4. SECURE BOOT:
   sbctl status
   sbctl sign -s /efi/EFI/GRUB/grubx64.efi
   sbctl sign -s /boot/vmlinuz-linux
   sbctl sign -s /boot/vmlinuz-linux-hardened

5. MAINTENANCE:
   - Weekly: arch-audit
   - Weekly: rkhunter --check
   - Weekly: aide --check
   - Check logs: journalctl -p err -b

EMERGENCY RECOVERY:
==================
- LUKS recovery key is in slot 2
- Boot from live USB and use recovery.key
- Restore header: cryptsetup luksHeaderRestore $PARTITION3 --header-backup-file=luks-header-backup.img

Installation log: $INSTALL_LOG
================================================================================
EOF

# Backup LUKS header
cp ./luks-header-backup.img /mnt/root/
chmod 600 /mnt/root/luks-header-backup.img

# Copy installation log
cp "$INSTALL_LOG" /mnt/root/

# -----------------------
# 11. CHROOT CONFIGURATION
# -----------------------

echo -e "${BBlue}Entering chroot...${NC}"
log_action "Entering chroot environment"

# Setup TPM in chroot if used
if [ "$USE_TPM_LUKS" = true ]; then
    setup_tpm_in_chroot
fi

arch-chroot /mnt bash -c "source /set-install-vars.sh && /chroot.sh"

# -----------------------
# 12. FINAL TPM ENROLLMENT
# -----------------------

if [ "$USE_TPM_LUKS" = true ]; then
    echo -e "${BBlue}Finalizing TPM2 enrollment...${NC}"
    echo -e "${BYellow}TPM2 enrollment will be completed on first boot${NC}"
    echo -e "${BYellow}The system will initially require password, then you can enroll TPM${NC}"
fi

# -----------------------
# 13. CLEANUP
# -----------------------

echo -e "${BBlue}Performing secure cleanup...${NC}"
log_action "Performing cleanup"

# Secure deletion of sensitive files
shred -vzu ./boot.key 2>/dev/null || true
shred -vzu ./recovery.key 2>/dev/null || true
shred -vzu ./luks-header-backup.img 2>/dev/null || true
shred -vzu ./tpm_luks.conf 2>/dev/null || true

# Clean up scripts
shred -vzu /mnt/chroot.sh 2>/dev/null || true
shred -vzu /mnt/set-install-vars.sh 2>/dev/null || true
shred -vzu /mnt/sysctl.sh 2>/dev/null || true
shred -vzu /mnt/ssh.sh 2>/dev/null || true

# Clear pacman cache
arch-chroot /mnt bash -c "pacman -Scc --noconfirm"

# Clear bash history
arch-chroot /mnt bash -c "history -c && rm -f /root/.bash_history"

# -----------------------
# 14. COMPLETION
# -----------------------

echo -e "${BGreen}=================================================================================${NC}"
echo -e "${BGreen}Installation completed successfully!${NC}"
echo -e "${BGreen}=================================================================================${NC}"
echo
echo -e "${BBlue}Next steps:${NC}"
echo "1. Reboot: reboot"
echo "2. Login as root"
echo "3. Run: /root/install-aur-packages.sh"
if [ "$USE_TPM_LUKS" = true ]; then
    echo "4. Enroll TPM: systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=$TPM_PCRS $PARTITION3"
fi
echo "5. Review: /root/POST_INSTALL_README.txt"
echo
echo -e "${BGreen}Remember to securely store recovery.key and luks-header-backup.img!${NC}"

log_action "Installation completed successfully"
