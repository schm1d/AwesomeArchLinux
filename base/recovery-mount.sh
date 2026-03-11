#!/bin/bash
# recovery-mount.sh - Safely unmount/remount encrypted Arch installation

set -euo pipefail

# Configurable names (override via environment variables)
VG_NAME="${VG_NAME:-lvm_arch}"
LUKS_NAME="${LUKS_NAME:-crypt_lvm}"

# Colors
BBlue='\033[1;34m'
BRed='\033[1;31m'
BGreen='\033[1;32m'
NC='\033[0m'

# Check root
if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root." >&2
   exit 1
fi

# Function to show current status
show_status() {
    echo -e "${BBlue}Current mounts:${NC}"
    mount | grep "/mnt" || echo "No /mnt mounts found"
    echo
    echo -e "${BBlue}Active LVM:${NC}"
    lvs 2>/dev/null || echo "No LVM volumes active"
    echo
    echo -e "${BBlue}Open LUKS:${NC}"
    find /dev/mapper/ -mindepth 1 -not -name control -printf '%f\n' 2>/dev/null || echo "No LUKS containers open"
}

# Function to unmount everything
unmount_all() {
    echo -e "${BBlue}Unmounting all /mnt filesystems...${NC}"
    
    # Unmount in reverse order
    umount /mnt/efi 2>/dev/null || true
    umount /mnt/var 2>/dev/null || true
    umount /mnt/home 2>/dev/null || true
    umount /mnt/boot 2>/dev/null || true
    umount /mnt 2>/dev/null || true
    
    # Deactivate swap
    swapoff /dev/mapper/${VG_NAME}-swap 2>/dev/null || true

    # Deactivate LVM
    echo -e "${BBlue}Deactivating LVM...${NC}"
    vgchange -an "$VG_NAME" 2>/dev/null || true

    # Close LUKS
    echo -e "${BBlue}Closing LUKS container...${NC}"
    cryptsetup close "$LUKS_NAME" 2>/dev/null || true
    
    echo -e "${BGreen}Everything unmounted successfully${NC}"
}

# Function to remount everything
remount_all() {
    # Get disk info
    echo -e "${BBlue}Available disks:${NC}"
    lsblk -d -o NAME,SIZE,TYPE,MODEL | grep "disk"
    echo
    read -p "Enter disk device (e.g., sda, nvme0n1): " DISK_NAME
    DISK="/dev/$DISK_NAME"
    
    # Determine partition suffix
    if [[ "$DISK" =~ [0-9]$ ]]; then
        PART_SUFFIX="p"
    else
        PART_SUFFIX=""
    fi
    
    # Detect partition count to handle both 3-partition (desktop/LUKS)
    # and 2-partition (VPS) layouts
    local part_count
    part_count=$(lsblk -ln -o TYPE "$DISK" | grep -c '^part$' || echo 0)

    if [[ "$part_count" -ge 3 ]]; then
        # 3-partition layout: EFI(1) + boot(2) + LUKS(3)
        EFI_PART="${DISK}${PART_SUFFIX}2"
        LUKS_PART="${DISK}${PART_SUFFIX}3"
    else
        # 2-partition layout: EFI(1) + LUKS(2) or VPS layout
        EFI_PART="${DISK}${PART_SUFFIX}1"
        LUKS_PART="${DISK}${PART_SUFFIX}2"
    fi

    # Open LUKS
    echo -e "${BBlue}Opening LUKS container...${NC}"
    if [ -f /root/boot.key ]; then
        cryptsetup luksOpen "$LUKS_PART" "$LUKS_NAME" --key-file /root/boot.key
    elif [ -f ./boot.key ]; then
        cryptsetup luksOpen "$LUKS_PART" "$LUKS_NAME" --key-file ./boot.key
    else
        echo "No keyfile found, using password:"
        cryptsetup luksOpen "$LUKS_PART" "$LUKS_NAME"
    fi

    # Activate LVM
    echo -e "${BBlue}Activating LVM...${NC}"
    vgscan
    vgchange -ay "$VG_NAME"

    # Mount filesystems
    echo -e "${BBlue}Mounting filesystems...${NC}"
    mount /dev/mapper/${VG_NAME}-root /mnt
    mount /dev/mapper/${VG_NAME}-home /mnt/home

    # Check if var exists
    if [ -b /dev/mapper/${VG_NAME}-var ]; then
        mkdir -p /mnt/var
        mount /dev/mapper/${VG_NAME}-var /mnt/var
    fi

    # Mount EFI
    mkdir -p /mnt/efi
    mount "$EFI_PART" /mnt/efi

    # Activate swap
    swapon /dev/mapper/${VG_NAME}-swap 2>/dev/null || true
    
    echo -e "${BGreen}Everything mounted successfully${NC}"
}

# Function to continue installation
continue_install() {
    echo -e "${BBlue}Continuing installation...${NC}"
    
    # Check if scripts exist
    if [ -f /mnt/set-install-vars.sh ] && [ -f /mnt/chroot.sh ]; then
        # Fix the typo if it exists
        sed -i 's/exp ort/export/' /mnt/set-install-vars.sh 2>/dev/null || true
        
        echo -e "${BBlue}Running chroot script...${NC}"
        arch-chroot /mnt bash -c "source /set-install-vars.sh && /chroot.sh"
    else
        echo -e "${BRed}Installation scripts not found in /mnt${NC}"
        echo "You may need to copy them again or run the installation from scratch"
    fi
}

# Main menu
while true; do
    echo -e "\n${BBlue}=== Arch Installation Recovery Menu ===${NC}"
    echo "1) Show current status"
    echo "2) Unmount everything"
    echo "3) Remount everything"
    echo "4) Continue installation (after remount)"
    echo "5) Exit"
    echo
    read -p "Select option [1-5]: " choice
    
    case $choice in
        1)
            show_status
            ;;
        2)
            unmount_all
            ;;
        3)
            remount_all
            ;;
        4)
            continue_install
            ;;
        5)
            echo "Exiting..."
            exit 0
            ;;
        *)
            echo -e "${BRed}Invalid option${NC}"
            ;;
    esac
    
    echo
    read -p "Press Enter to continue..."
done
