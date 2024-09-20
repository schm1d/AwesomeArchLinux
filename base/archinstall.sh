#!/bin/bash

#Description    : Fully encrypted LVM2 on LUKS with UEFI Arch installation script.
#Author         : @brulliant
#Linkedin       : https://www.linkedin.com/in/schmidbruno/

set -euo pipefail

# Set up the color variables
BBlue='\033[1;34m'
NC='\033[0m'

# Check if user is root
if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root." >&2
   exit 1
fi

# Check if UEFI is supported
if [ ! -d "/sys/firmware/efi/efivars" ]; then
  echo -e "${BBlue}UEFI is not supported.${NC}"
  exit 1
else
  echo -e "${BBlue}\nUEFI is supported, proceeding...\n${NC}"
fi

# Function to validate numeric input
validate_numeric_input() {
  if ! [[ "$1" =~ ^[0-9]+$ ]]; then
    echo "Invalid input: $1. Please enter a positive number." >&2
    exit 1
  fi
}

# Get user input for the settings
echo -e "${BBlue}The following disks are available on your system:\n${NC}"
lsblk -d | grep -v 'rom' | grep -v 'loop'
echo -e "\n"

read -p 'Select the target disk: ' TARGET_DISK
echo -e "\n"

echo -e "${BBlue}Choosing a username and a hostname:\n${NC}"

read -p 'Enter the new user: ' NEW_USER
read -p 'Enter the new hostname: ' NEW_HOST
echo -e "\n"

echo -e "${BBlue}Set / and Swap partition size:\n${NC}"

read -p 'Enter the size of SWAP in GB: ' SIZE_OF_SWAP
read -p 'Enter the size of / in GB, the remaining space will be allocated to /home: ' SIZE_OF_ROOT
echo -e "\n"

# Use the correct variable name for the target disk
DISK="/dev/$TARGET_DISK"
USERNAME="$NEW_USER"
HOSTNAME="$NEW_HOST"
SWAP_SIZE="${SIZE_OF_SWAP}G" # Modern systems don't really need swap.
ROOT_SIZE="${SIZE_OF_ROOT}G"
CRYPT_NAME='crypt_lvm' # the name of the LUKS container.
LVM_NAME='lvm_arch' # the name of the logical volume.
LUKS_KEYS='/etc/luksKeys' # Where you will store the root partition key


# Setting time correctly before installation
timedatectl set-ntp true

# Partition the disk
echo -e "${BBlue}Preparing disk $DISK for UEFI and Encryption...${NC}"
sgdisk -og $DISK

# Create a 1MiB BIOS boot partition
echo -e "${BBlue}Creating a 1MiB BIOS boot partition...${NC}"
sgdisk -n 1:2048:4095 -t 1:ef02 -c 1:"BIOS boot Partition" $DISK

# Create a UEFI partition
echo -e "${BBlue}Creating a UEFI partition...${NC}"
sgdisk -n 2:4096:1130495 -t 2:ef00 -c 2:"EFI" $DISK

# Create a LUKS partition
echo -e "${BBlue}Creating a LUKS partition...${NC}"
sgdisk -n 3:1130496:$(sgdisk -E $DISK) -t 3:8309 -c 3:"Linux LUKS" $DISK

# Create the LUKS container
echo -e "${BBlue}Creating the LUKS container...${NC}"
#read -ps 'Enter a password for the LUKS container: ' LUKS_PASS

# Encrypts with the best key size.
cryptsetup -q --cipher aes-xts-plain64 --key-size 512 --hash sha512 --iter-time 3000 --use-random --type luks1 luksFormat $DISK"p3"

# Opening LUKS container to test
echo -e "${BBlue}Opening the LUKS container to test password...${NC}"
cryptsetup -v luksOpen $DISK"p3" $CRYPT_NAME &&\
cryptsetup -v luksClose $CRYPT_NAME

# create a LUKS key of size 2048 and save it as boot.key
echo -e "${BBlue}Creating the LUKS key for $CRYPT_NAME...${NC}"
dd if=/dev/urandom of=./boot.key bs=2048 count=1 &&\
cryptsetup -v luksAddKey -i 1 $DISK"p3" ./boot.key &&\

# unlock LUKS container with the boot.key file
echo -e "${BBlue}Testing the LUKS keys for $CRYPT_NAME...${NC}"
cryptsetup -v luksOpen $DISK"p3" $CRYPT_NAME --key-file ./boot.key &&\
echo -e "\n"

# Create the LVM physical volume, volume group and logical volume
echo -e "${BBlue}Creating LVM logical volumes on $LVM_NAME...${NC}"
pvcreate --verbose /dev/mapper/$CRYPT_NAME &&\
vgcreate --verbose $LVM_NAME /dev/mapper/$CRYPT_NAME &&\
lvcreate --verbose -L $ROOT_SIZE $LVM_NAME -n root &&\
lvcreate --verbose -L $SWAP_SIZE $LVM_NAME -n swap &&\
lvcreate --verbose -l 100%FREE $LVM_NAME -n home &&\

# Format the partitions 
echo -e "${BBlue}Formating filesystems...${NC}"
mkfs.ext4 /dev/mapper/$LVM_NAME-root &&\
mkfs.ext4 /dev/mapper/$LVM_NAME-home &&\
mkswap /dev/mapper/$LVM_NAME-swap &&\
swapon /dev/mapper/$LVM_NAME-swap &&\

# Mount filesystem
echo -e "${BBlue}Mounting filesystems...${NC}"
mount --verbose /dev/mapper/$LVM_NAME-root /mnt &&\
mkdir --verbose /mnt/home &&\
mount --verbose /dev/mapper/$LVM_NAME-home /mnt/home &&\
mkdir --verbose -p /mnt/tmp &&\

# Mount efi
echo -e "${BBlue}Preparing the EFI partition...${NC}"
mkfs.vfat -F32 $DISK"p2"
sleep 2
mkdir --verbose /mnt/efi
sleep 1
mount --verbose $DISK"p2" /mnt/efi

# Update the keyring for the packages
echo -e "${BBlue}Updating Arch Keyrings...${NC}" 
pacman -Sy archlinux-keyring --noconfirm

# Install Arch Linux base system. Add or remove packages as you wish.
echo -e "${BBlue}Installing Arch Linux base system...${NC}" 
echo -ne "\n\n\n" | pacstrap -i /mnt base base-devel archlinux-keyring linux linux-headers \
                    linux-firmware zsh lvm2 mtools networkmanager iwd dhcpcd wget curl git \
                    openssh neovim unzip unrar p7zip zip unarj arj cabextract xz pbzip2 pixz \
                    alsa-firmware alsa-tools alsa-utils fuse3 ntfs-3g zsh-completions net-tools sbctl \
                    lrzip cpio gdisk go rust nasm rsync vim nano dosfstools nano-syntax-highlighting usbutils

# Generate fstab file 
echo -e "${BBlue}Generating fstab file...${NC}" 
genfstab -pU /mnt >> /mnt/etc/fstab &&\

echo -e "${BBlue}Copying the $CRYPT_NAME key to $LUKS_KEYS ...${NC}" 
mkdir --verbose /mnt$LUKS_KEYS
cp ./boot.key /mnt$LUKS_KEYS/boot.key

# Securely delete the key file from the local file system.
echo -e "${BBlue}Securely erasing the local key file...${NC}" 
shred -u ./boot.key

# Add an entry to fstab so the new mountpoint will be mounted on boot
echo -e "${BBlue}Adding tmpfs to fstab...${NC}" 
echo "tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,relatime,size=2G 0 0" >> /mnt/etc/fstab &&\

echo -e "${BBlue}Adding proc to fstab and harndening it...${NC}" 
echo "proc /proc proc nosuid,nodev,noexec,hidepid=2,gid=proc 0 0" >> /mnt/etc/fstab &&\
mkdir /mnt/etc/systemd/system/systemd-logind.service.d &&\
touch /mnt/etc/systemd/system/systemd-logind.service.d/hidepid.conf &&\
echo "[Service]" >> /mnt/etc/systemd/system/systemd-logind.service.d/hidepid.conf &&\
echo "SupplementaryGroups=proc" >> /mnt/etc/systemd/system/systemd-logind.service.d/hidepid.conf &&\

echo -e "${BBlue}Reloading fstab...${NC}"
systemctl daemon-reload

# Preparing the chroot script to be executed
echo -e "${BBlue}Preparing the chroot script to be executed...${NC}"
sed -i "s|^DISK=.*|DISK='${DISK}'|g" ./chroot.sh
sed -i "s|^USERNAME=.*|USERNAME='${USERNAME}'|g" ./chroot.sh
sed -i "s|^HOSTNAME=.*|HOSTNAME='${HOSTNAME}'|g" ./chroot.sh
cp ./chroot.sh /mnt &&\
chmod +x /mnt/chroot.sh &&\
shred -u ./chroot.sh

# Chroot into new system and configure it 
echo -e "${BBlue}Chrooting into new system and configuring it...${NC}"
arch-chroot /mnt /bin/bash ./chroot.sh
