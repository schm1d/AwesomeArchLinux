
#!/bin/bash 

##########################################################################################
#Script Name    : archinstall.sh                                   
#Description    : Fully encrypted LVM2 on LUKS with UEFI Arch installation script.                                                                                         
#Author         : Bruno Schmid                                                
#Email          : schmid.github@gmail.com
#Twitter        : @brulliant
#Linkedin       : https://www.linkedin.com/in/schmidbruno/                     
############################################################################################


# Check if user is root
if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root." 1>&2
   exit 1
fi

# Take action if UEFI is supported.
if [ ! -d "/sys/firmware/efi/efivars" ]; then 
  echo -e "${BBlue}UEFI is not supported.${NC}"
  exit 1
else
   echo -e "${BBlue}UEFI is supported, proceding...${NC}"
fi

# Set up the variables
BBlue='\033[1;34m'
NC='\033[0m'

# Change this to fit your environment
DISK='<your_target_disk>' # Change this to your target disk.
SWAP_SIZE='8G' # Swap size in GB
ROOT_SIZE='35G' # Root partition size in GB
CRYPT_NAME='crypt_lvm' 
LVM_NAME='lvm_arch'
LUKS_KEYS='/mnt/etc/luksKeys' # Where you will store the root partition key

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
# Encrypts withthe best key size.
cryptsetup -q --cipher aes-xts-plain64 --key-size 512 --hash sha512 --iter-time 3000 --use-random  luksFormat --type luks1 $DISK"3" &&\

# Opening LUKS container to test
echo -e "${BBlue}Opening the LUKS container to test password...${NC}"
cryptsetup -v luksOpen $DISK"3" $CRYPT_NAME &&\
cryptsetup -v luksClose $CRYPT_NAME

# create a LUKS key of size 2048 and save it as boot.key
echo -e "${BBlue}Creating the LUKS key for $CRYPT_NAME...${NC}"
dd if=/dev/urandom of=./boot.key bs=2048 count=1 &&\
cryptsetup -v luksAddKey -i 1 $DISK"3" ./boot.key &&\

# unlock LUKS container with the boot.key file
echo -e "${BBlue}Testing the LUKS keys for $CRYPT_NAME...${NC}"
cryptsetup -v luksOpen $DISK"3" $CRYPT_NAME --key-file ./boot.key &&\

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
mkfs.vfat -F32 $DISK"2" &&\
mkdir --verbose /mnt/efi &&\
mount --verbose $DISK"2" /mnt/efi &&\

# Update the keyring for the packages
echo -e "${BBlue}Updating Arch Keyrings...${NC}" 
pacman -Sy archlinux-keyring --noconfirm

# Install Arch Linux base system. Add or remove packages as you wish.
echo -e "${BBlue}Installing Arch Linux base system...${NC}" 
echo -ne "\n\n\n" | pacstrap -i /mnt base base-devel archlinux-keyring linux linux-headers linux-firmware zsh lvm2 grub efibootmgr dosfstools os-prober mtools\
           networkmanager wget curl git vim nano openssh neovim unzip unrar p7zip zip unarj arj cabextract xz pbzip2 pixz lrzip cpio &&\

# Generate fstab file 
echo -e "${BBlue}Generating fstab file...${NC}" 
genfstab -pU /mnt >> /mnt/etc/fstab &&\

echo -e "${BBlue}Copying the $CRYPT_NAME key to $LUKS_KEYS ...${NC}" 
mkdir --verbose $LUKS_KEYS
cp ./boot.key $LUKS_KEYS/boot.key
rm ./boot.key

# Add an entry to fstab so the new mountpoint will be mounted on boot
echo -e "${BBlue}Adding tmpfs to fstab...${NC}" 
echo "tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,relatime,size=2G 0 0" >> /mnt/etc/fstab &&\


# Preparing the chroot script to be executed
echo -e "${BBlue}Preparing the chroot script to be executed...${NC}" 
cp ./chroot.sh /mnt &&\
chmod +x /mnt/chroot.sh &&\
rm ./chroot.sh

# Chroot into new system and configure it 
echo -e "${BBlue}Chrooting into new system and configuring it...${NC}" &&\
arch-chroot /mnt /bin/bash ./chroot.sh
