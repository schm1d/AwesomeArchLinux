#!/usr/bin/env bash
# recovery-mount.sh - Safely unmount/remount encrypted or VPS Arch installations

set -euo pipefail

# Configurable names (override via environment variables)
VG_NAME="${VG_NAME:-lvm_arch}"
LUKS_NAME="${LUKS_NAME:-crypt_lvm}"

# Colors
BBlue='\033[1;34m'
BRed='\033[1;31m'
BGreen='\033[1;32m'
BYellow='\033[1;33m'
NC='\033[0m'

# Check root
if [[ "$(id -u)" != "0" ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# Show current mount, LVM, and LUKS status
show_status() {
    echo -e "${BBlue}Current mounts:${NC}"
    findmnt -R /mnt 2>/dev/null || echo "No /mnt mounts found"
    echo
    echo -e "${BBlue}Active LVM:${NC}"
    lvs 2>/dev/null || echo "No LVM volumes active"
    echo
    echo -e "${BBlue}Open device-mapper / LUKS:${NC}"
    find /dev/mapper/ -mindepth 1 -not -name control -printf '%f\n' 2>/dev/null || echo "No mapper devices open"
}

# Unmount everything in safe order (swapoff before umount -R)
unmount_all() {
    echo -e "${BBlue}Deactivating swap and unmounting /mnt filesystems...${NC}"

    swapoff "/dev/mapper/${VG_NAME}-swap" 2>/dev/null || true
    swapoff /mnt/swapfile 2>/dev/null || true

    if findmnt -rn /mnt >/dev/null 2>&1; then
        if ! umount -R /mnt; then
            echo -e "${BRed}Failed to unmount /mnt (filesystems may still be busy).${NC}" >&2
            return 1
        fi
    fi

    echo -e "${BBlue}Deactivating LVM...${NC}"
    vgchange -an "$VG_NAME" 2>/dev/null || true

    echo -e "${BBlue}Closing LUKS container...${NC}"
    cryptsetup close "$LUKS_NAME" 2>/dev/null || true

    echo -e "${BGreen}Everything unmounted successfully${NC}"
}

# Remount encrypted LVM or unencrypted VPS installation
remount_all() {
    local disk_name disk part_suffix part_count efi_part main_part efi_fstype

    echo -e "${BBlue}Available disks:${NC}"
    lsblk -d -o NAME,SIZE,TYPE,MODEL | awk 'NR==1 || $3=="disk"'
    echo

    while true; do
        read -r -p "Enter disk device (e.g., sda, nvme0n1): " disk_name
        disk_name="${disk_name#/dev/}"
        if [[ -n "$disk_name" && "$disk_name" != */* && -b "/dev/$disk_name" &&
              "$(lsblk -dn -o TYPE "/dev/$disk_name" 2>/dev/null)" == "disk" ]]; then
            disk="/dev/$disk_name"
            break
        fi
        echo -e "${BRed}Error: /dev/$disk_name does not exist or is not a whole disk device.${NC}" >&2
    done

    if [[ "$disk" =~ [0-9]$ ]]; then
        part_suffix="p"
    else
        part_suffix=""
    fi

    part_count=$(lsblk -ln -o TYPE "$disk" | grep -c '^part$' || true)
    if [[ "$part_count" -lt 2 ]]; then
        echo -e "${BRed}Error: Expected at least 2 partitions on $disk (found $part_count).${NC}" >&2
        return 1
    fi

    if [[ "$part_count" -ge 3 ]]; then
        # Bare-metal 3-partition layout: BIOS_Boot(1) + EFI_System(2) + Linux_LUKS(3)
        efi_part="${disk}${part_suffix}2"
        main_part="${disk}${part_suffix}3"
    else
        # 2-partition layout: EFI/BIOS_Boot(1) + LUKS or Linux_Root(2)
        efi_part="${disk}${part_suffix}1"
        main_part="${disk}${part_suffix}2"
    fi

    if cryptsetup isLuks "$main_part" 2>/dev/null; then
        echo -e "${BBlue}Opening LUKS container on $main_part...${NC}"
        if [[ -b "/dev/mapper/$LUKS_NAME" ]]; then
            echo -e "${BYellow}Mapper /dev/mapper/$LUKS_NAME is already open.${NC}"
        elif [[ -f /root/boot.key ]]; then
            cryptsetup luksOpen "$main_part" "$LUKS_NAME" --key-file /root/boot.key
        elif [[ -f ./boot.key ]]; then
            cryptsetup luksOpen "$main_part" "$LUKS_NAME" --key-file ./boot.key
        else
            echo "No keyfile found, prompting for LUKS passphrase:"
            cryptsetup luksOpen "$main_part" "$LUKS_NAME"
        fi

        echo -e "${BBlue}Activating LVM...${NC}"
        vgscan
        vgchange -ay "$VG_NAME"

        echo -e "${BBlue}Mounting LVM filesystems...${NC}"
        mount "/dev/mapper/${VG_NAME}-root" /mnt
        mkdir -p /mnt/home
        mount "/dev/mapper/${VG_NAME}-home" /mnt/home

        if [[ -b "/dev/mapper/${VG_NAME}-var" ]]; then
            mkdir -p /mnt/var
            mount "/dev/mapper/${VG_NAME}-var" /mnt/var
        fi

        if [[ -b "/dev/mapper/${VG_NAME}-tmp" ]]; then
            mkdir -p /mnt/tmp
            mount -o rw,nosuid,nodev,noexec,relatime "/dev/mapper/${VG_NAME}-tmp" /mnt/tmp
        fi

        swapon "/dev/mapper/${VG_NAME}-swap" 2>/dev/null || true
    else
        echo -e "${BBlue}Mounting unencrypted root partition $main_part...${NC}"
        mount "$main_part" /mnt
        if [[ -f /mnt/swapfile ]]; then
            swapon /mnt/swapfile 2>/dev/null || true
        fi
    fi

    efi_fstype=$(blkid -s TYPE -o value "$efi_part" 2>/dev/null || true)
    if [[ "$efi_fstype" == "vfat" ]]; then
        mkdir -p /mnt/efi
        mount "$efi_part" /mnt/efi
    fi

    echo -e "${BGreen}Everything mounted successfully${NC}"
}

# Continue interrupted chroot installation
continue_install() {
    echo -e "${BBlue}Continuing installation...${NC}"

    if ! findmnt -rn /mnt >/dev/null 2>&1; then
        echo -e "${BRed}/mnt is not mounted. Run option 3 (Remount everything) first.${NC}" >&2
        return 1
    fi

    local chroot_target=""
    if [[ -f /mnt/chroot.sh ]]; then
        chroot_target="/chroot.sh"
    elif [[ -f /mnt/vps-chroot.sh ]]; then
        chroot_target="/vps-chroot.sh"
    fi

    if [[ -n "$chroot_target" ]] && [[ -f /mnt/set-install-vars.sh || -f /mnt/root/.install-env ]]; then
        if [[ -f /mnt/set-install-vars.sh ]]; then
            sed -i 's/exp ort/export/' /mnt/set-install-vars.sh 2>/dev/null || true
            echo -e "${BBlue}Running $chroot_target with /set-install-vars.sh...${NC}"
            arch-chroot /mnt bash -c "source /set-install-vars.sh && $chroot_target"
        else
            echo -e "${BBlue}Running $chroot_target with /root/.install-env...${NC}"
            arch-chroot /mnt "$chroot_target"
        fi
    else
        echo -e "${BRed}Installation scripts or environment not found in /mnt${NC}" >&2
        echo "You may need to copy them again or run option 5 to repair manually." >&2
    fi
}

# Enter interactive arch-chroot for manual repairs
enter_chroot() {
    if ! findmnt -rn /mnt >/dev/null 2>&1; then
        echo -e "${BRed}/mnt is not mounted. Run option 3 (Remount everything) first.${NC}" >&2
        return 1
    fi
    echo -e "${BBlue}Entering arch-chroot at /mnt (type 'exit' to return)...${NC}"
    arch-chroot /mnt /bin/bash
}

# Main menu
while true; do
    echo -e "\n${BBlue}=== Arch Installation Recovery Menu ===${NC}"
    echo "1) Show current status"
    echo "2) Unmount everything"
    echo "3) Remount everything"
    echo "4) Continue installation (after remount)"
    echo "5) Enter arch-chroot (/mnt) for manual repair"
    echo "6) Exit"
    echo
    read -r -p "Select option [1-6]: " choice

    case "$choice" in
        1) show_status ;;
        2) unmount_all ;;
        3) remount_all ;;
        4) continue_install ;;
        5) enter_chroot ;;
        6)
            echo "Exiting..."
            exit 0
            ;;
        *)
            echo -e "${BRed}Invalid option${NC}"
            ;;
    esac

    echo
    read -r -p "Press Enter to continue..."
done
