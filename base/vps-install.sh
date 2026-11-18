#!/usr/bin/env bash

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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CLEANUP_ENABLED=0
cleanup() {
    if [[ "$CLEANUP_ENABLED" -eq 0 ]]; then
        return
    fi
    echo "Cleanup triggered, unmounting partial VPS setup..." >&2
    swapoff /mnt/swapfile 2>/dev/null || true
    umount -R /mnt 2>/dev/null || true
}
trap cleanup EXIT

# --- Color variables (all used in echo -e strings) ---
# shellcheck disable=SC2034
BBlue='\033[1;34m'
# shellcheck disable=SC2034
BRed='\033[1;31m'
# shellcheck disable=SC2034
BGreen='\033[1;32m'
# shellcheck disable=SC2034
BYellow='\033[1;33m'
# shellcheck disable=SC2034
NC='\033[0m'

readonly LARGE_DISK_THRESHOLD_BYTES=1000000000000
readonly DEFAULT_TMP_SIZE_GB=10
readonly LARGE_DISK_TMP_SIZE_GB=25

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

SYSCTL_SOURCE_DIR="$SCRIPT_DIR/../hardening/sysctl"
SYSCTL_BUNDLE_FILES=(
    sysctl.sh
    60-awesome-security-core.conf
    70-awesome-workstation-network.conf
    80-awesome-performance.conf
    80-awesome-bbr.modules
    90-awesome-strict.conf
    90-awesome-ipv6-disabled.conf
)

for installer_component in "$SCRIPT_DIR/vps-chroot.sh" \
    "$SCRIPT_DIR/../hardening/ssh/ssh.sh" "$SCRIPT_DIR/../hardening/lib/nftables.sh" \
    "$SCRIPT_DIR/install-aur-packages.sh" "$SCRIPT_DIR/../hardening/lib/aur-review.sh" \
    "$SCRIPT_DIR/../utils/aide-config.sh" "$SCRIPT_DIR/lib/chroot-security.sh" \
    "$SCRIPT_DIR/../utils/auditd-attack.rules"; do
    if [[ ! -r "$installer_component" ]]; then
        echo -e "${BRed}Missing required installer component: $installer_component${NC}" >&2
        exit 1
    fi
done
for sysctl_file in "${SYSCTL_BUNDLE_FILES[@]}"; do
    if [[ ! -r "$SYSCTL_SOURCE_DIR/$sysctl_file" ]]; then
        echo -e "${BRed}Missing required sysctl bundle file: $SYSCTL_SOURCE_DIR/$sysctl_file${NC}" >&2
        exit 1
    fi
done

# -----------------------
# 1. HELPER FUNCTIONS
# -----------------------

ask_yes_no() {
    local prompt_msg="$1"
    local choice
    while true; do
        read -r -p "$prompt_msg (y/n): " choice
        case "$choice" in
            [Yy]) echo "y"; return 0 ;;
            [Nn]) echo "n"; return 0 ;;
            *) echo -e "${BRed}Invalid choice. Please type 'y' or 'n'.\n${NC}" >&2 ;;
        esac
    done
}

recommended_tmp_size_gb() {
    local disk="$1"
    local disk_size_bytes

    disk_size_bytes=$(lsblk -b -d -n -o SIZE "$disk" 2>/dev/null || true)
    if [[ "$disk_size_bytes" =~ ^[0-9]+$ ]] &&
       ((disk_size_bytes >= LARGE_DISK_THRESHOLD_BYTES)); then
        printf '%s\n' "$LARGE_DISK_TMP_SIZE_GB"
    else
        printf '%s\n' "$DEFAULT_TMP_SIZE_GB"
    fi
}

ask_for_disk() {
    local disk
    while true; do
        read -r -p "Select the target disk (e.g., sda, vda, nvme0n1): " disk
        disk="${disk#/dev/}"
        if [[ -n "$disk" && "$disk" != */* && -b "/dev/$disk" &&
              "$(lsblk -dn -o TYPE "/dev/$disk" 2>/dev/null)" == "disk" ]]; then
            echo "$disk"
            return 0
        else
            echo -e "${BRed}Error: /dev/$disk does not exist or is not a whole disk device.\n${NC}" >&2
        fi
    done
}

ask_for_numeric() {
    local prompt_msg="$1"
    local input_val
    while true; do
        read -r -p "$prompt_msg " input_val
        if [[ "$input_val" =~ ^[1-9][0-9]*$ ]]; then
            echo "$input_val"
            return 0
        else
            echo -e "${BRed}Invalid input: '$input_val'. Please enter a positive integer.\n${NC}" >&2
        fi
    done
}

ask_for_ssh_port() {
    local port_input port
    while true; do
        read -r -p "SSH port (default 22): " port_input
        port="${port_input:-22}"
        if [[ "$port" =~ ^[1-9][0-9]*$ ]] && (( 10#$port >= 1 && 10#$port <= 65535 )); then
            echo "$port"
            return 0
        else
            echo -e "${BRed}Invalid SSH port: '$port'. Must be 1-65535.\n${NC}" >&2
        fi
    done
}

validate_ssh_pubkey() {
    local key="$1"
    if [[ -z "$key" ]]; then
        return 0
    fi
    if [[ "$key" =~ [\$\`\(\)\{\}\;\|\&\<\>\"\'\\] ]] || [[ "$key" == *$'\n'* ]] || [[ "$key" == *$'\r'* ]]; then
        echo -e "${BRed}ERROR: SSH public key contains invalid characters.${NC}" >&2
        return 1
    fi
    if ! [[ "$key" =~ ^(ssh-rsa|ssh-ed25519|ecdsa-sha2-|sk-ssh-|sk-ecdsa-) ]]; then
        echo -e "${BRed}ERROR: SSH public key must start with ssh-rsa, ssh-ed25519, ecdsa-sha2-, sk-ssh-, or sk-ecdsa-.${NC}" >&2
        return 1
    fi
    return 0
}

ask_for_username() {
    local username
    while true; do
        read -r -p "Enter the new username: " username
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
        read -r -p "Enter the new hostname: " hostname
        if [[ "$hostname" =~ ^[a-zA-Z0-9][a-zA-Z0-9\.-]*$ ]] && [[ ${#hostname} -le 64 ]]; then
            echo "$hostname"
            return 0
        else
            echo -e "${BRed}Invalid hostname. Must begin with alphanumeric, contain only [a-zA-Z0-9.-], max 64 chars.\n${NC}" >&2
        fi
    done
}

ask_for_sysctl_profile() {
    local choice
    while true; do
        echo -e "${BBlue}Select sysctl profile:${NC}" >&2
        echo "1) workstation - compatible security baseline (recommended)" >&2
        echo "2) strict      - disables unprivileged user namespaces, io_uring, kexec, and debugging" >&2
        echo "3) performance - workstation baseline plus fq + BBR" >&2
        read -r -p "Choice [1]: " choice
        choice="${choice:-1}"
        case "$choice" in
            1) echo "workstation"; return 0 ;;
            2) echo "strict"; return 0 ;;
            3) echo "performance"; return 0 ;;
            *) echo -e "${BRed}Invalid choice. Please enter 1, 2, or 3.\n${NC}" >&2 ;;
        esac
    done
}

ask_for_ipv6_policy() {
    local choice
    while true; do
        echo -e "${BBlue}Select IPv6 policy:${NC}" >&2
        echo "1) enabled and hardened (recommended; preserves SLAAC)" >&2
        echo "2) disabled by explicit sysctl overlay" >&2
        read -r -p "Choice [1]: " choice
        choice="${choice:-1}"
        case "$choice" in
            1) echo "false"; return 0 ;;
            2) echo "true"; return 0 ;;
            *) echo -e "${BRed}Invalid choice. Please enter 1 or 2.\n${NC}" >&2 ;;
        esac
    done
}

describe_sysctl_profile() {
    case "$1" in
        workstation) echo "workstation (compatible security baseline)" ;;
        strict) echo "strict (compatibility-breaking hardening)" ;;
        performance) echo "performance (workstation + fq/BBR)" ;;
        *) echo "$1" ;;
    esac
}

# Prompt user for timezone
ask_for_timezone() {
    local tz
    while true; do
        echo -e "${BBlue}Select timezone:${NC}" >&2
        echo "Common: UTC, US/Eastern, US/Pacific, Europe/London, Europe/Berlin," >&2
        echo "        Europe/Zurich, Asia/Tokyo, Asia/Shanghai, Australia/Sydney" >&2
        read -r -p "Timezone [UTC]: " tz
        tz="${tz:-UTC}"
        if [ -f "/usr/share/zoneinfo/$tz" ]; then
            echo "$tz"
            return 0
        else
            echo -e "${BRed}Invalid timezone: '$tz'. Must be a valid path under /usr/share/zoneinfo.\n${NC}" >&2
        fi
    done
}

# Prompt user for locale
ask_for_locale() {
    local loc choice
    local -a locales=(
        "en_US.UTF-8"
        "en_GB.UTF-8"
        "de_DE.UTF-8"
        "de_CH.UTF-8"
        "fr_FR.UTF-8"
        "es_ES.UTF-8"
        "it_IT.UTF-8"
        "pt_BR.UTF-8"
        "ja_JP.UTF-8"
        "zh_CN.UTF-8"
    )
    while true; do
        echo -e "${BBlue}Select locale:${NC}" >&2
        local i=1
        for loc in "${locales[@]}"; do
            printf "  %2d) %s\n" "$i" "$loc" >&2
            (( ++i ))
        done
        echo "   0) Other -- type a locale name" >&2
        read -r -p "Choice [1]: " choice
        choice="${choice:-1}"
        if [[ "$choice" == "0" ]]; then
            read -r -p "Enter locale (e.g. nl_NL.UTF-8): " loc
            if [[ "$loc" =~ ^[A-Za-z0-9_.@-]+$ ]] && grep -Eq "^#?${loc//./\\.}[[:space:]]" /etc/locale.gen 2>/dev/null; then
                echo "$loc"
                return 0
            else
                echo -e "${BRed}Locale '$loc' not found in /etc/locale.gen.\n${NC}" >&2
            fi
        elif [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#locales[@]} )); then
            echo "${locales[$((choice-1))]}"
            return 0
        else
            echo -e "${BRed}Invalid choice.\n${NC}" >&2
        fi
    done
}

# Prompt user for console keymap
ask_for_keymap() {
    local km choice
    local -a keymaps=(
        "us"
        "uk"
        "de-latin1"
        "de_CH-latin1"
        "fr"
        "es"
        "it"
        "pt-latin1"
        "fr-latin1"
        "se-lat6"
        "br-abnt2"
        "pl"
        "ru"
        "jp106"
        "kr"
    )
    while true; do
        echo -e "${BBlue}Select console keymap:${NC}" >&2
        local i=1
        for km in "${keymaps[@]}"; do
            printf "  %2d) %s\n" "$i" "$km" >&2
            (( ++i ))
        done
        echo "   0) Other -- type a keymap name" >&2
        read -r -p "Choice [1]: " choice
        choice="${choice:-1}"
        if [[ "$choice" == "0" ]]; then
            read -r -p "Enter keymap name: " km
            if localectl list-keymaps 2>/dev/null | grep -qx "$km"; then
                loadkeys "$km" 2>/dev/null || true
                echo "$km"
                return 0
            else
                echo -e "${BRed}Keymap '$km' not found. Run 'localectl list-keymaps' for options.\n${NC}" >&2
            fi
        elif [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#keymaps[@]} )); then
            km="${keymaps[$((choice-1))]}"
            loadkeys "$km" 2>/dev/null || true
            echo "$km"
            return 0
        else
            echo -e "${BRed}Invalid choice.\n${NC}" >&2
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

# Select mirrors safely without predictable /tmp paths or empty-response clobbering
echo -e "${BBlue}Selecting fastest HTTPS mirrors...${NC}"
cp /etc/pacman.d/mirrorlist /etc/pacman.d/mirrorlist.backup
MIRROR_TMP=$(mktemp /etc/pacman.d/.mirrorlist.XXXXXX)
if curl -fsSL "https://archlinux.org/mirrorlist/?country=all&protocol=https&ip_version=4" | \
    sed -e 's/^#Server/Server/' -e '/^#/d' > "$MIRROR_TMP" && \
    grep -q '^Server[[:space:]]*=' "$MIRROR_TMP"; then
    sed -n '1,20p' "$MIRROR_TMP" > /etc/pacman.d/mirrorlist
    chmod 0644 /etc/pacman.d/mirrorlist
else
    echo -e "${BYellow}Warning: Failed to fetch remote mirrorlist; keeping existing /etc/pacman.d/mirrorlist.${NC}" >&2
fi
rm -f "$MIRROR_TMP"

# -----------------------
# 3. GATHER USER INPUT
# -----------------------

echo -e "${BBlue}Available disks:\n${NC}"
lsblk -d -o NAME,SIZE,TYPE,MODEL | awk 'NR==1 || $3=="disk"'
echo

TARGET_DISK=$(ask_for_disk)
DISK="/dev/$TARGET_DISK"
TMP_SIZE_GB=$(recommended_tmp_size_gb "$DISK")
echo -e "${BGreen}Selected: $DISK${NC}\n"
echo -e "${BGreen}/tmp tmpfs ceiling: ${TMP_SIZE_GB} GiB${NC}\n"
log_action "Selected disk: $DISK, /tmp tmpfs ceiling: ${TMP_SIZE_GB} GiB"

# Partition sizes
echo -e "${BBlue}Partition sizes:\n${NC}"
SIZE_OF_SWAP=$(ask_for_numeric "SWAP size in GB (recommended: 1-2 for VPS):")
echo

DISK_SIZE_BYTES=$(lsblk -b -d -n -o SIZE "$DISK" 2>/dev/null || echo 0)
REQUIRED_VPS_BYTES=$(((SIZE_OF_SWAP + 8) * 1073741824))
if [[ "$DISK_SIZE_BYTES" =~ ^[0-9]+$ ]] && (( DISK_SIZE_BYTES < REQUIRED_VPS_BYTES )); then
    echo -e "${BRed}Error: Insufficient disk space on $DISK. Need at least $((REQUIRED_VPS_BYTES / 1073741824)) GiB.${NC}" >&2
    exit 1
fi

# User configuration
echo -e "${BBlue}\nUser configuration:\n${NC}"
USERNAME=$(ask_for_username)
HOSTNAME=$(ask_for_hostname)

# Regional settings
echo -e "\n${BBlue}Regional settings:\n${NC}"
TIMEZONE=$(ask_for_timezone)
LOCALE=$(ask_for_locale)
KEYMAP=$(ask_for_keymap)

# Ask for SSH port
SSH_PORT=$(ask_for_ssh_port)

# Ask for SSH public key (critical: password auth will be disabled)
ALLOW_NO_SSH_KEY=false
echo -e "\n${BYellow}Password authentication and root SSH login will be disabled after installation.${NC}"
while true; do
    echo -e "${BYellow}Paste your SSH public key (from ~/.ssh/id_ed25519.pub on your local machine):${NC}"
    read -r SSH_PUBKEY
    SSH_PUBKEY="${SSH_PUBKEY%$'\r'}"
    if [[ -z "$SSH_PUBKEY" ]]; then
        echo -e "${BRed}WARNING: No SSH public key provided! Remote SSH login will be impossible until a key is added via VPS console.${NC}"
        if [[ $(ask_yes_no "Do you confirm you have out-of-band VPS console access and want to proceed WITHOUT an SSH key?") == "y" ]]; then
            ALLOW_NO_SSH_KEY=true
            break
        fi
        continue
    fi
    if validate_ssh_pubkey "$SSH_PUBKEY"; then
        break
    fi
done

echo -e "\n${BBlue}Kernel sysctl profile:${NC}"
SYSCTL_PROFILE=$(ask_for_sysctl_profile)
SYSCTL_PROFILE_LABEL=$(describe_sysctl_profile "$SYSCTL_PROFILE")
DISABLE_IPV6=$(ask_for_ipv6_policy)

echo -e "\nUsername: $USERNAME"
echo -e "Hostname: $HOSTNAME"
echo -e "Timezone: $TIMEZONE"
echo -e "Locale: $LOCALE"
echo -e "Keymap: $KEYMAP"
echo -e "SSH Port: $SSH_PORT"
echo -e "Sysctl Profile: $SYSCTL_PROFILE_LABEL"
echo -e "IPv6: $([[ "$DISABLE_IPV6" == true ]] && echo disabled || echo 'enabled and hardened')"
echo -e "SSH Key:  ${SSH_PUBKEY:+(provided)}${SSH_PUBKEY:-(none)}\n"

log_action "User: $USERNAME, Hostname: $HOSTNAME, Timezone: $TIMEZONE, Locale: $LOCALE, Keymap: $KEYMAP, SSH Port: $SSH_PORT, Sysctl Profile: $SYSCTL_PROFILE_LABEL, Disable IPv6: $DISABLE_IPV6"

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

CLEANUP_ENABLED=1

mkfs.ext4 -F -m 1 -E lazy_itable_init=0,lazy_journal_init=0 "$ROOT_PART"

# Mount root
mount --verbose "$ROOT_PART" /mnt

# Create swap file (simpler than LVM for VPS)
echo -e "${BBlue}Creating swap file...${NC}"
dd if=/dev/zero of=/mnt/swapfile bs=1G count="$SIZE_OF_SWAP" status=progress
chmod 600 /mnt/swapfile
mkswap /mnt/swapfile
swapon /mnt/swapfile

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
    linux linux-headers \
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
# /tmp: noexec omitted — npm, Node.js, and build tools execute from /tmp
tmpfs /tmp tmpfs rw,nosuid,nodev,relatime,size=${TMP_SIZE_GB}G 0 0
tmpfs /dev/shm tmpfs rw,nosuid,nodev,noexec,relatime,size=2G 0 0
proc /proc proc nosuid,nodev,noexec,hidepid=2,gid=proc 0 0
EOF

# Setup systemd for hidepid
mkdir -p /mnt/etc/systemd/system/systemd-logind.service.d
cat <<EOF > /mnt/etc/systemd/system/systemd-logind.service.d/hidepid.conf
[Service]
SupplementaryGroups=proc
EOF

# Create installation info safely with printf %q
INSTALL_DATE_VAL="$(date)"
{
    printf 'export %s=%q\n' \
        INSTALL_DISK "$DISK" \
        INSTALL_USER "$USERNAME" \
        INSTALL_HOST "$HOSTNAME" \
        INSTALL_DATE "$INSTALL_DATE_VAL" \
        INSTALL_TYPE "vps" \
        INSTALL_SSH_PORT "$SSH_PORT" \
        INSTALL_SSH_PUBKEY "$SSH_PUBKEY" \
        INSTALL_ALLOW_NO_SSH_KEY "$ALLOW_NO_SSH_KEY" \
        INSTALL_SYSCTL_PROFILE "$SYSCTL_PROFILE" \
        INSTALL_DISABLE_IPV6 "$DISABLE_IPV6" \
        INSTALL_TMP_SIZE "${TMP_SIZE_GB}G" \
        INSTALL_TIMEZONE "$TIMEZONE" \
        INSTALL_LOCALE "$LOCALE" \
        INSTALL_KEYMAP "$KEYMAP"
} > /mnt/root/.install-env
chmod 600 /mnt/root/.install-env

{
    printf 'export %s=%q\n' \
        _INSTALL_DISK "$DISK" \
        _INSTALL_USER "$USERNAME" \
        _INSTALL_HOST "$HOSTNAME" \
        _INSTALL_SSH_PORT "$SSH_PORT" \
        _INSTALL_SSH_PUBKEY "$SSH_PUBKEY" \
        _INSTALL_ALLOW_NO_SSH_KEY "$ALLOW_NO_SSH_KEY" \
        _INSTALL_SYSCTL_PROFILE "$SYSCTL_PROFILE" \
        _INSTALL_DISABLE_IPV6 "$DISABLE_IPV6" \
        _INSTALL_TMP_SIZE "${TMP_SIZE_GB}G" \
        _INSTALL_TYPE "vps" \
        _INSTALL_TIMEZONE "$TIMEZONE" \
        _INSTALL_LOCALE "$LOCALE" \
        _INSTALL_KEYMAP "$KEYMAP"
} > /mnt/set-install-vars.sh
chmod 700 /mnt/set-install-vars.sh

install -m 0755 "$SCRIPT_DIR/vps-chroot.sh" /mnt/vps-chroot.sh

# Stage the complete sysctl bundle. The chroot helper selects and installs the
# requested layers without applying them to the live ISO kernel.
SYSCTL_STAGING_DIR="/mnt/sysctl-profile"
install -d -m 0755 "$SYSCTL_STAGING_DIR"
for sysctl_file in "${SYSCTL_BUNDLE_FILES[@]}"; do
    install -m 0644 "$SYSCTL_SOURCE_DIR/$sysctl_file" "$SYSCTL_STAGING_DIR/$sysctl_file"
done
chmod 0755 "$SYSCTL_STAGING_DIR/sysctl.sh"

# ssh.sh resolves the helper beside itself when staged at the chroot root.
install -m 0644 "$SCRIPT_DIR/../hardening/lib/nftables.sh" /mnt/nftables.sh
install -m 0755 "$SCRIPT_DIR/../hardening/ssh/ssh.sh" /mnt/ssh.sh

install -Dm0644 "$SCRIPT_DIR/lib/chroot-security.sh" /mnt/usr/local/lib/awesomearchlinux/chroot-security.sh
install -Dm0644 "$SCRIPT_DIR/../utils/auditd-attack.rules" /mnt/usr/local/share/awesomearchlinux/auditd-attack.rules

# Stage reviewed AUR installation and AIDE configuration for root after reboot.
install -m 0700 "$SCRIPT_DIR/install-aur-packages.sh" /mnt/root/install-aur-packages.sh
install -m 0600 "$SCRIPT_DIR/../hardening/lib/aur-review.sh" /mnt/root/aur-review.sh
install -m 0700 "$SCRIPT_DIR/../utils/aide-config.sh" /mnt/root/aide-config.sh
# End post-install package staging.

# Create post-installation README
cat > /mnt/root/POST_INSTALL_README.txt <<EOF
================================================================================
ARCH LINUX VPS SECURITY-HARDENED INSTALLATION
================================================================================

Installation Date: $(date)
Hostname: $HOSTNAME
Username: $USERNAME
Disk: $DISK
/tmp tmpfs ceiling: ${TMP_SIZE_GB} GiB
SSH Port: $SSH_PORT
Boot Mode: $BOOT_MODE
Sysctl Profile: $SYSCTL_PROFILE_LABEL
IPv6 Disabled: $DISABLE_IPV6

CRITICAL POST-INSTALLATION STEPS:
=================================

1. IMMEDIATE ACTIONS:
   - Run as root: sudo /root/install-aur-packages.sh (review each AUR recipe)
   - Configure your SSH authorized_keys
   - Test SSH access before closing current session

2. SECURITY SERVICES:
   systemctl enable --now apparmor
   systemctl enable --now auditd
   systemctl enable --now rkhunter-check.timer
   systemctl enable --now arch-audit.timer
   systemctl status audit-rules.service awesome-journal-sealing.service
   - Move /root/journal-sealing/verification-*.txt to trusted off-machine storage.
   - Verify the saved copy, then remove the local verification file.
   - Keep /var/log/journal/*/fss on this machine; never regenerate with --force.

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

CLEANUP_ENABLED=0

echo -e "${BBlue}Performing cleanup...${NC}"
log_action "Performing cleanup."

# Clean up scripts copied into chroot
for f in /mnt/vps-chroot.sh /mnt/set-install-vars.sh /mnt/sysctl.sh /mnt/sysctl-profile.conf /mnt/ssh.sh /mnt/nftables.sh; do
    [[ -f "$f" ]] && shred -vzu "$f" 2>/dev/null || true
done
rm -rf -- /mnt/sysctl-profile

# Clear pacman cache
arch-chroot /mnt bash -c "pacman -Scc --noconfirm"

# Clear bash history
arch-chroot /mnt bash -c 'history -c && rm -f "$HOME/.bash_history"'

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
echo "3. Run as root: sudo /root/install-aur-packages.sh (review each AUR recipe)"
if [[ -n "$SSH_PUBKEY" ]]; then
    echo "4. SSH key already installed — test: ssh -p $SSH_PORT $USERNAME@<server_ip>"
else
    echo "4. Add your SSH public key to /home/$USERNAME/.ssh/authorized_keys"
fi
echo "5. Review: /root/POST_INSTALL_README.txt"
echo
echo -e "${BGreen}SSH is configured on port $SSH_PORT${NC}"

log_action "VPS installation completed successfully"
