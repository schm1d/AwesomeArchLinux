#!/bin/bash

# Description: Fully encrypted LVM2 on LUKS with UEFI Arch installation script.
# Author: Bruno Schmid @brulliant 
# LinkedIn: https://www.linkedin.com/in/schmidbruno/

set -euo pipefail

# --- Color variables ---
BBlue='\033[1;34m'
NC='\033[0m'

# --- Check if user is root ---
if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root." >&2
   exit 1
fi

# --- Check if UEFI is supported ---
if [ ! -d "/sys/firmware/efi/efivars" ]; then
  echo -e "${BBlue}UEFI is not supported.${NC}"
  exit 1
else
  echo -e "${BBlue}\nUEFI is supported, proceeding...\n${NC}"
fi

# -----------------------
# 1. HELPER FUNCTIONS
# -----------------------

# Prompt user for a valid block device (e.g., sda, nvme0n1, etc.)
ask_for_disk() {
    local disk
    while true; do
        echo -e "${BBlue}The following disks are available on your system:\n${NC}"
        lsblk -d -o NAME,SIZE,TYPE,MODEL | grep "disk"
        echo

        read -p "Select the target disk (e.g., sda): " disk
        if [[ -b "/dev/$disk" ]]; then
            echo "$disk"
            return 0
        else
            echo -e "Error: Disk /dev/$disk does not exist or is not a block device. Please try again.\n" >&2
        fi
    done
}

# Prompt user for a numeric input (like size in GB).
ask_for_numeric() {
    local prompt_msg="$1"
    local input_val
    while true; do
        read -p "$prompt_msg " input_val
        # Check if strictly numeric
        if [[ "$input_val" =~ ^[0-9]+$ ]]; then
            echo "$input_val"
            return 0
        else
            echo -e "Invalid input: '$input_val'. Please enter a positive number.\n" >&2
        fi
    done
}

# Prompt user for a valid username (basic validation).
ask_for_username() {
    local username
    while true; do
        read -p "Enter the new username: " username
        if [[ "$username" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
            echo "$username"
            return 0
        else
            echo -e "Invalid username: '$username'. Must begin with [a-z_] and contain only [a-z0-9_-].\n" >&2
        fi
    done
}

# Prompt user for a valid hostname.
ask_for_hostname() {
    local hostname
    while true; do
        read -p "Enter the new hostname: " hostname
        if [[ "$hostname" =~ ^[a-zA-Z0-9][a-zA-Z0-9\.-]*$ ]]; then
            echo "$hostname"
            return 0
        else
            echo -e "Invalid hostname: '$hostname'. Must begin with alphanumeric and contain only alphanumerics, dots, or hyphens.\n" >&2
        fi
    done
}

# Prompt user yes/no question.
ask_yes_no() {
    local prompt_msg="$1"
    local choice
    while true; do
        read -p "$prompt_msg (y/n): " choice
        case "$choice" in
            [Yy]) echo "y"; return 0 ;;
            [Nn]) echo "n"; return 0 ;;
            *) echo -e "Invalid choice. Please type 'y' or 'n'.\n" >&2 ;;
        esac
    done
}

# Loop until cryptsetup open succeeds (or user cancels).
ask_luks_password_until_success() {
    local partition="$1"
    local crypt_name="$2"

    while true; do
        echo -e "${BBlue}\nOpening the LUKS container to test password...${NC}"
        if cryptsetup -v luksOpen "$partition" "$crypt_name"; then
            # If it opens successfully, close it and break the loop
            cryptsetup -v luksClose "$crypt_name"
            break
        else
            echo -e "\nWrong password or operation canceled. Please try again.\n" >&2
        fi
    done
}

# -----------------------
# 2. GATHER USER INPUT
# -----------------------

# Prompt for disk
TARGET_DISK=$(ask_for_disk)
DISK="/dev/$TARGET_DISK"
echo -e "\nSelected disk: $DISK\n"

# Prompt for username and hostname
echo -e "${BBlue}Choosing a username and a hostname:\n${NC}"
USERNAME=$(ask_for_username)
HOSTNAME=$(ask_for_hostname)
echo -e "\nUsername: $USERNAME"
echo -e "Hostname: $HOSTNAME\n"

# Prompt for partition sizes
echo -e "${BBlue}Set / and Swap partition size:\n${NC}"
SIZE_OF_SWAP=$(ask_for_numeric "Enter the size of SWAP in GB:")
SIZE_OF_ROOT=$(ask_for_numeric "Enter the size of / in GB (the remaining space will go to /home):")

# Ask about /var
echo
CREATE_VAR_PART=$(ask_yes_no "Do you want a separate /var partition?")
VAR_SIZE=""
if [[ "$CREATE_VAR_PART" == "y" ]]; then
    SIZE_OF_VAR=$(ask_for_numeric "Enter the size of /var in GB:")
    VAR_SIZE="${SIZE_OF_VAR}G"
fi


SWAP_SIZE="${SIZE_OF_SWAP}G"
ROOT_SIZE="${SIZE_OF_ROOT}G"
CRYPT_NAME='crypt_lvm'
LVM_NAME='lvm_arch'
LUKS_KEYS='/etc/luksKeys'

# Determine the partition suffix (p for NVMe devices)
if [[ "$DISK" =~ [0-9]$ ]]; then
    PART_SUFFIX="p"
else
    PART_SUFFIX=""
fi

PARTITION1="${DISK}${PART_SUFFIX}1"  # BIOS boot partition
PARTITION2="${DISK}${PART_SUFFIX}2"  # EFI partition
PARTITION3="${DISK}${PART_SUFFIX}3"  # LUKS partition

# Setting time correctly before installation
timedatectl set-ntp true

# Partition the disk
echo -e "${BBlue}Preparing disk $DISK for UEFI and Encryption...${NC}"
sgdisk -og "$DISK"
partprobe $DISK

# Create a 1MiB BIOS boot partition
echo -e "${BBlue}Creating a 1MiB BIOS boot partition...${NC}"
sgdisk -n 1:2048:4095 -t 1:ef02 -c 1:"BIOS boot Partition" "$DISK"
partprobe $DISK

# Create a UEFI partition
echo -e "${BBlue}Creating a UEFI partition...${NC}"
sgdisk -n 2:4096:1130495 -t 2:ef00 -c 2:"EFI" "$DISK"
partprobe $DISK

# Create a LUKS partition
echo -e "${BBlue}Creating a LUKS partition...${NC}"
sgdisk -n 3:1130496:$(sgdisk -E "$DISK") -t 3:8309 -c 3:"Linux LUKS" "$DISK"
partprobe $DISK

# -----------------------
# 3. LUKS OPERATIONS
# -----------------------

PARTITION3="/dev/${TARGET_DISK}3"       # Example usage, adapt to your partition layout
CRYPT_NAME="cryptroot"

echo -e "${BBlue}\nCreating the LUKS container on $PARTITION3...${NC}"
cryptsetup -q --cipher aes-xts-plain64 --key-size 512 --hash sha512 \
  --iter-time 3000 --use-random --type luks1 luksFormat "$PARTITION3"

# Prompt repeatedly for the correct LUKS passphrase
ask_luks_password_until_success "$PARTITION3" "$CRYPT_NAME"

# Create a LUKS key of size 2048 and save it as boot.key
echo -e "${BBlue}\nCreating the LUKS key for $CRYPT_NAME...${NC}"
dd if=/dev/urandom of=./boot.key bs=2048 count=1
cryptsetup -v luksAddKey -i 1 "$PARTITION3" ./boot.key

# Test the LUKS key
echo -e "${BBlue}\nTesting the LUKS key for $CRYPT_NAME...${NC}"
cryptsetup -v luksOpen "$PARTITION3" "$CRYPT_NAME" --key-file ./boot.key

# Create the LVM physical volume, volume group and logical volumes
echo -e "${BBlue}Creating LVM logical volumes on $LVM_NAME...${NC}"
pvcreate --verbose "/dev/mapper/$CRYPT_NAME"
vgcreate --verbose "$LVM_NAME" "/dev/mapper/$CRYPT_NAME"

lvcreate --verbose -L "$ROOT_SIZE" "$LVM_NAME" -n root
lvcreate --verbose -L "$SWAP_SIZE" "$LVM_NAME" -n swap

# If the user wants a separate /var, create it
if [[ -n "$VAR_SIZE" ]]; then
  lvcreate --verbose -L "$VAR_SIZE" "$LVM_NAME" -n var
  # The remaining space goes to /home
  lvcreate --verbose -l 100%FREE "$LVM_NAME" -n home
else
  # Allocate all remaining space to /home if no separate /var
  lvcreate --verbose -l 100%FREE "$LVM_NAME" -n home
fi

# Format the partitions 
echo -e "${BBlue}Formatting filesystems...${NC}"
mkfs.ext4 "/dev/mapper/${LVM_NAME}-root"
mkfs.ext4 "/dev/mapper/${LVM_NAME}-home"
mkswap "/dev/mapper/${LVM_NAME}-swap"
swapon "/dev/mapper/${LVM_NAME}-swap"

# Format /var if created
if [[ -n "$VAR_SIZE" ]]; then
  mkfs.ext4 "/dev/mapper/${LVM_NAME}-var"
fi

# Mount filesystem
echo -e "${BBlue}Mounting filesystems...${NC}"
mount --verbose "/dev/mapper/${LVM_NAME}-root" /mnt

mkdir --verbose /mnt/home
mount --verbose "/dev/mapper/${LVM_NAME}-home" /mnt/home

# Mount /var if created
if [[ -n "$VAR_SIZE" ]]; then
  mkdir --verbose /mnt/var
  mount --verbose "/dev/mapper/${LVM_NAME}-var" /mnt/var
fi

mkdir --verbose -p /mnt/tmp

# Prepare the EFI partition
echo -e "${BBlue}Preparing the EFI partition...${NC}"
mkfs.vfat -F32 "$PARTITION2"

mkdir --verbose /mnt/efi

mount --verbose "$PARTITION2" /mnt/efi

# Update the keyring for the packages
echo -e "${BBlue}Updating Arch Keyrings...${NC}" 
pacman -Sy archlinux-keyring --noconfirm

# Install Arch Linux base system. Add or remove packages as you wish.
echo -e "${BBlue}Installing Arch Linux base system...${NC}" 
pacstrap /mnt base base-devel archlinux-keyring linux linux-headers \
         linux-firmware zsh lvm2 mtools networkmanager iwd dhcpcd wget curl git \
         openssh neovim unzip unrar p7zip zip unarj arj cabextract xz pbzip2 pixz \
         alsa-firmware alsa-tools alsa-utils fuse3 ntfs-3g zsh-completions net-tools sbctl \
         lrzip cpio gdisk go rust nasm rsync vim nano dosfstools nano-syntax-highlighting usbutils

# Generate fstab file 
echo -e "${BBlue}Generating fstab file...${NC}" 
genfstab -pU /mnt >> /mnt/etc/fstab

echo -e "${BBlue}Copying the $CRYPT_NAME key to $LUKS_KEYS ...${NC}" 
mkdir --verbose "/mnt$LUKS_KEYS"
cp ./boot.key "/mnt$LUKS_KEYS/boot.key"

# Securely delete the key file from the local file system.
echo -e "${BBlue}Securely erasing the local key file...${NC}" 
shred -u ./boot.key

# Add an entry to fstab so the new mountpoint will be mounted on boot
echo -e "${BBlue}Adding tmpfs to fstab...${NC}" 
echo "tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,relatime,size=2G 0 0" >> /mnt/etc/fstab

echo -e "${BBlue}Adding proc to fstab and hardening it...${NC}" 
echo "proc /proc proc nosuid,nodev,noexec,hidepid=2,gid=proc 0 0" >> /mnt/etc/fstab
mkdir -p /mnt/etc/systemd/system/systemd-logind.service.d
cat <<EOF > /mnt/etc/systemd/system/systemd-logind.service.d/hidepid.conf
[Service]
SupplementaryGroups=proc
EOF

echo -e "${BBlue}Reloading systemd daemon...${NC}"
arch-chroot /mnt systemctl daemon-reload

# Preparing the chroot script to be executed
echo -e "${BBlue}Preparing the chroot script to be executed...${NC}"
# Escape slashes in DISK for sed
ESCAPED_DISK="${DISK//\//\\/}"
sed -i "s|^DISK=.*|DISK='${ESCAPED_DISK}'|g" ./chroot.sh
sed -i "s|^USERNAME=.*|USERNAME='${USERNAME}'|g" ./chroot.sh
sed -i "s|^HOSTNAME=.*|HOSTNAME='${HOSTNAME}'|g" ./chroot.sh
cp ./chroot.sh /mnt
chmod +x /mnt/chroot.sh
cp ../hardening/sysctl/sysctl.sh /mnt
chmod +x /mnt/sysctl.sh
shred -u ./chroot.sh

# Chroot into the new system and configure it 
echo -e "${BBlue}Chrooting into new system and configuring it...${NC}"
arch-chroot /mnt /bin/bash ./chroot.sh
