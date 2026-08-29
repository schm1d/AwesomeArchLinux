#!/bin/bash

# Description: Fully encrypted LVM2 on LUKS with UEFI and TPM2 - Security Hardened
# Author: Bruno Schmid @brulliant
# LinkedIn: https://www.linkedin.com/in/schmidbruno/

set -euo pipefail

# --- Cleanup on failure ---
CLEANUP_ENABLED=0

cleanup() {
    if [[ "$CLEANUP_ENABLED" -eq 0 ]]; then
        return
    fi
    echo "Cleanup triggered, undoing partial disk setup..." >&2
    swapoff "/dev/mapper/${LVM_NAME:-lvm_arch}-swap" 2>/dev/null || true
    umount -R /mnt 2>/dev/null || true
    vgchange -an "${LVM_NAME:-lvm_arch}" 2>/dev/null || true
    cryptsetup close "${CRYPT_NAME:-crypt_lvm}" 2>/dev/null || true
    shred -zu ./boot.key 2>/dev/null || true
    shred -zu ./recovery.key 2>/dev/null || true
    shred -zu ./luks-header-backup.img 2>/dev/null || true
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

# --- Global variables ---
TPM_AVAILABLE=false
TPM_VERSION=""
TPM_DEVICE=""
USE_TPM_LUKS=false
# shellcheck disable=SC2034  # Used by TPM enrollment commands
TPM_PCR_BANK="sha256"
TPM_PCRS="7"
readonly LARGE_DISK_THRESHOLD_BYTES=1000000000000
readonly DEFAULT_TMP_SIZE_GB=10
readonly LARGE_DISK_TMP_SIZE_GB=25

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

for installer_component in ./chroot.sh ./bootloader.sh; do
    if [[ ! -r "$installer_component" ]]; then
        echo -e "${BRed}Missing required installer component: $installer_component${NC}" >&2
        exit 1
    fi
done

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

ask_for_sysctl_profile() {
    local choice
    while true; do
        echo -e "${BBlue}Select sysctl profile:${NC}" >&2
        echo "1) workstation - compatible security baseline (recommended)" >&2
        echo "2) strict      - disables unprivileged user namespaces, io_uring, kexec, and debugging" >&2
        echo "3) performance - workstation baseline plus fq + BBR" >&2
        read -p "Choice [1]: " choice
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
        read -p "Choice [1]: " choice
        choice="${choice:-1}"
        case "$choice" in
            1) echo "false"; return 0 ;;
            2) echo "true"; return 0 ;;
            *) echo -e "${BRed}Invalid choice. Please enter 1 or 2.\n${NC}" >&2 ;;
        esac
    done
}

ask_for_bootloader_profile() {
    local choice
    while true; do
        echo -e "${BBlue}Select the boot profile:${NC}" >&2
        echo "1) grub - encrypted /boot, PBKDF2 LUKS, embedded boot key" >&2
        echo "2) uki  - signed UKIs on the ESP, Argon2id LUKS, no embedded key" >&2
        read -p "Choice (1 or 2): " choice
        case "$choice" in
            1) echo "grub"; return 0 ;;
            2) echo "uki"; return 0 ;;
            *) echo -e "${BRed}Invalid choice. Please enter 1 or 2; there is no default.\n${NC}" >&2 ;;
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
        read -p "Timezone [UTC]: " tz
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
            ((i++))
        done
        echo "   0) Other -- type a locale name" >&2
        read -p "Choice [1]: " choice
        choice="${choice:-1}"
        if [[ "$choice" == "0" ]]; then
            read -p "Enter locale (e.g. nl_NL.UTF-8): " loc
            if grep -q "^#\?${loc} " /etc/locale.gen 2>/dev/null; then
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
            ((i++))
        done
        echo "   0) Other -- type a keymap name" >&2
        read -p "Choice [1]: " choice
        choice="${choice:-1}"
        if [[ "$choice" == "0" ]]; then
            read -p "Enter keymap name: " km
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
    local tmp="${5:-$DEFAULT_TMP_SIZE_GB}"
    
    local disk_size
    disk_size=$(lsblk -b -d -o SIZE -n "$disk" 2>/dev/null || echo 0)
    local required=$(((swap + root + var + tmp + 10) * 1073741824))
    
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
    local entropy
    entropy=$(cat /proc/sys/kernel/random/entropy_avail)
    if [ "$entropy" -lt 256 ]; then
        echo -e "${BBlue}Low entropy detected ($entropy). Generating additional entropy...${NC}"
        dd if=/dev/urandom of=/dev/null bs=1M count=100 status=progress 2>/dev/null
    fi
    echo -e "${BGreen}Entropy level: $(cat /proc/sys/kernel/random/entropy_avail)${NC}"
}

# Detect if device is SSD
detect_device_type() {
    local disk="$1"
    local device_name
    device_name=$(basename "$disk")
    
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
        # shellcheck disable=SC2034  # Referenced in TPM enrollment logic
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
        
        arch-chroot /mnt pacman -S --needed --noconfirm tpm2-tools
        
        if [ -f ./tpm_luks.conf ]; then
            cp ./tpm_luks.conf /mnt/etc/tpm_luks.conf
            chmod 600 /mnt/etc/tpm_luks.conf
        fi
        
        # Create PCR check tool
        cat > /mnt/usr/local/bin/check-tpm-pcrs <<TPMCHECK
#!/bin/bash
echo "Current PCR values:"
tpm2_pcrread sha256:0+1+4+7+9
echo
echo "If system fails to unlock automatically after updates:"
echo "1. Boot with recovery key"
echo "2. Re-enroll TPM: systemd-cryptenroll --wipe-slot=tpm2 --tpm2-device=auto --tpm2-pcrs=$TPM_PCRS /dev/[device]"
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

# The profiles have materially different boot and key-handling threat models,
# so the operator must make an explicit choice. There is intentionally no
# default selection.
echo
INSTALL_BOOTLOADER=$(ask_for_bootloader_profile)
echo -e "${BGreen}Selected boot profile: $INSTALL_BOOTLOADER${NC}"
log_action "Selected boot profile: $INSTALL_BOOTLOADER"

# Select mirrors - avoid SIGPIPE from head
echo -e "${BBlue}Selecting fastest HTTPS mirrors...${NC}"
pacman -Sy --noconfirm reflector
reflector --protocol https --latest 20 --sort rate --save /etc/pacman.d/mirrorlist

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
            echo "  7 - Secure Boot state (Recommended)"
            echo "  0+7 - Plus firmware code"
            echo "  0+1+4+7+9 - Plus firmware config, bootloader, and kernel"
            
            while true; do
                read -p "Enter PCRs (default: 7): " TPM_PCRS
                TPM_PCRS=${TPM_PCRS:-"7"}
                if [[ "$TPM_PCRS" =~ ^([0-9]|1[0-9]|2[0-3])(\+([0-9]|1[0-9]|2[0-3]))*$ ]]; then
                    break
                fi
                echo -e "${BRed}Invalid PCR list. Use plus-separated indexes from 0 to 23.${NC}" >&2
            done
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
# Informational only -- see the partitioning section for why there is no
# drive-type-specific behaviour.
DEVICE_TYPE=$(detect_device_type "$DISK")

echo -e "${BGreen}Selected: $DISK (Type: $DEVICE_TYPE)${NC}\n"
log_action "Selected disk: $DISK (Type: $DEVICE_TYPE)"

SIZE_OF_TMP=$(recommended_tmp_size_gb "$DISK")
echo -e "${BGreen}/tmp allocation: ${SIZE_OF_TMP} GiB encrypted LVM volume${NC}\n"
log_action "Selected /tmp size: ${SIZE_OF_TMP} GiB"

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
if ! validate_disk_space "$DISK" "$SIZE_OF_SWAP" "$SIZE_OF_ROOT" "$SIZE_OF_VAR" "$SIZE_OF_TMP"; then
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

# Ask for SSH public key (critical: password auth will be disabled)
echo -e "\n${BYellow}Password authentication will be disabled after installation.${NC}"
echo -e "${BYellow}Paste your SSH public key (from ~/.ssh/id_ed25519.pub on your local machine):${NC}"
read -r SSH_PUBKEY
if [[ -z "$SSH_PUBKEY" ]]; then
    echo -e "${BRed}WARNING: No SSH public key provided!${NC}"
    echo -e "${BRed}You will need console access to add one after installation.${NC}"
fi

# Validate SSH public key to prevent shell injection when embedded in sourced files
validate_ssh_pubkey() {
    local key="$1"
    if [[ -z "$key" ]]; then
        return 0
    fi
    # Reject keys containing shell metacharacters that could enable injection
    if [[ "$key" =~ [\$\`\(\)\{\}\;\|\&\<\>] ]] || [[ "$key" == *$'\n'* ]]; then
        echo -e "${BRed}Error: SSH public key contains invalid characters.${NC}" >&2
        return 1
    fi
    # Verify key starts with a known SSH key type prefix
    if ! [[ "$key" =~ ^(ssh-rsa|ssh-ed25519|ecdsa-sha2|sk-) ]]; then
        echo -e "${BRed}Error: SSH public key must start with ssh-rsa, ssh-ed25519, ecdsa-sha2, or sk-.${NC}" >&2
        return 1
    fi
    return 0
}

if [[ -n "$SSH_PUBKEY" ]]; then
    if ! validate_ssh_pubkey "$SSH_PUBKEY"; then
        echo -e "${BRed}Invalid SSH public key. Aborting.${NC}"
        exit 1
    fi
fi

echo -e "\n${BBlue}Kernel sysctl profile:${NC}"
SYSCTL_PROFILE=$(ask_for_sysctl_profile)
SYSCTL_PROFILE_LABEL=$(describe_sysctl_profile "$SYSCTL_PROFILE")
DISABLE_IPV6=$(ask_for_ipv6_policy)

echo -e "\nUsername: $USERNAME"
echo -e "Hostname: $HOSTNAME"
echo -e "Timezone: $TIMEZONE"
echo -e "Locale: $LOCALE"
echo -e "Keymap: $KEYMAP"
echo -e "Sysctl Profile: $SYSCTL_PROFILE_LABEL"
echo -e "IPv6: $([[ "$DISABLE_IPV6" == true ]] && echo disabled || echo 'enabled and hardened')"
echo -e "Boot Profile: $INSTALL_BOOTLOADER"
echo -e "/tmp: ${SIZE_OF_TMP} GiB encrypted LVM volume"
echo -e "SSH Key:  ${SSH_PUBKEY:+(provided)}${SSH_PUBKEY:-(none)}\n"

log_action "User: $USERNAME, Hostname: $HOSTNAME, Timezone: $TIMEZONE, Locale: $LOCALE, Keymap: $KEYMAP, Sysctl Profile: $SYSCTL_PROFILE_LABEL, Disable IPv6: $DISABLE_IPV6, Boot Profile: $INSTALL_BOOTLOADER"

SWAP_SIZE="${SIZE_OF_SWAP}G"
ROOT_SIZE="${SIZE_OF_ROOT}G"
TMP_SIZE="${SIZE_OF_TMP}G"
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

# shellcheck disable=SC2034  # Used in partition formatting below
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

# No drive-type-specific partitioning: sgdisk already aligns to 2048 sectors
# (1 MiB) by default, so an explicit "-a 2048" for SSDs was a no-op. DEVICE_TYPE
# is informational only -- it is reported to the operator at disk selection and
# in the install summary. Do not re-add a drive-type branch here without a real
# behavioural difference to put in it.
#
# TRIM/discard is deliberately NOT enabled anywhere in this installer (no LUKS
# --allow-discards, no LVM issue_discards, no fstrim.timer). Passing discards
# through a LUKS container leaks filesystem usage patterns into the ciphertext,
# which this project treats as an unacceptable trade for SSD wear levelling.

sgdisk -n 1:2048:4095 -t 1:ef02 -c 1:"BIOS_Boot" "$DISK"
sgdisk -n 2:4096:2101247 -t 2:ef00 -c 2:"EFI_System" "$DISK"
sgdisk -n 3:2101248:0 -t 3:8309 -c 3:"Linux_LUKS" "$DISK"

partprobe "$DISK"
sleep 2

# -----------------------
# 6. LUKS SETUP
# -----------------------

check_entropy

CLEANUP_ENABLED=1

echo -e "${BBlue}\nCreating LUKS container...${NC}"
log_action "Creating LUKS container"

LUKS_PBKDF_ARGS=()
if [[ "$INSTALL_BOOTLOADER" == "grub" ]]; then
    # GRUB can read LUKS2 but cannot derive Argon2id keys.
    LUKS_PBKDF_ARGS=(--pbkdf pbkdf2)
else
    LUKS_PBKDF_ARGS=(--pbkdf argon2id)
fi

# Create LUKS container
cryptsetup -v \
    --type luks2 \
    "${LUKS_PBKDF_ARGS[@]}" \
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
umask 077
dd if=/dev/random of=./boot.key bs=512 count=8 iflag=fullblock
dd if=/dev/random of=./recovery.key bs=512 count=8 iflag=fullblock
umask 022

# Add keys to LUKS
echo -e "${BBlue}Adding keyfiles to LUKS container...${NC}"
echo "You'll need to enter your LUKS passphrase twice (once for each key)"
cryptsetup -v luksAddKey "$PARTITION3" ./boot.key --key-slot 1
cryptsetup -v luksAddKey "$PARTITION3" ./recovery.key --key-slot 2

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
lvcreate --verbose -L "$TMP_SIZE" "$LVM_NAME" -n tmp

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
mkfs.ext4 -m 0 -E lazy_itable_init=0,lazy_journal_init=0 "/dev/mapper/${LVM_NAME}-tmp"

if [[ -n "$VAR_SIZE" ]]; then
    mkfs.ext4 -m 5 -E lazy_itable_init=0,lazy_journal_init=0 "/dev/mapper/${LVM_NAME}-var"
fi

mkswap "/dev/mapper/${LVM_NAME}-swap"
swapon "/dev/mapper/${LVM_NAME}-swap"

# Optimize filesystems
echo -e "${BBlue}Optimizing filesystems...${NC}"
tune2fs -O has_journal,extent,huge_file,flex_bg,metadata_csum,64bit,dir_index "/dev/mapper/${LVM_NAME}-root"
tune2fs -O has_journal,extent,huge_file,flex_bg,metadata_csum,64bit,dir_index "/dev/mapper/${LVM_NAME}-home"
tune2fs -O has_journal,extent,huge_file,flex_bg,metadata_csum,64bit,dir_index "/dev/mapper/${LVM_NAME}-tmp"
tune2fs -c 30 -i 180d "/dev/mapper/${LVM_NAME}-root"
tune2fs -c 30 -i 180d "/dev/mapper/${LVM_NAME}-home"
tune2fs -c 30 -i 180d "/dev/mapper/${LVM_NAME}-tmp"

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
mount --verbose -o rw,nosuid,nodev,noexec,relatime \
    "/dev/mapper/${LVM_NAME}-tmp" /mnt/tmp
chmod 1777 /mnt/tmp

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

BOOT_PACKAGES=(efibootmgr)
case "$INSTALL_BOOTLOADER" in
    grub)
        BOOT_PACKAGES+=(grub os-prober)
        ;;
    uki)
        BOOT_PACKAGES+=(sbctl tpm2-tools)
        ;;
esac

pacstrap /mnt base base-devel archlinux-keyring \
    linux linux-headers \
    linux-firmware wireless-regdb fwupd intel-ucode amd-ucode \
    lvm2 cryptsetup device-mapper \
    "${BOOT_PACKAGES[@]}" \
    networkmanager modemmanager iwd dhcpcd openssh \
    iptables-nft nftables \
    apparmor audit rng-tools \
    lynis arch-audit rkhunter \
    firejail bubblewrap \
    git wget curl rsync reflector \
    neovim vim nano nano-syntax-highlighting \
    zsh zsh-completions \
    unzip unrar p7zip zip unarj arj cabextract xz pbzip2 pixz lrzip cpio \
    mtools dosfstools ntfs-3g fuse3 \
    gdisk parted \
    net-tools usbutils pciutils \
    go rust nasm \
    dialog \
    noto-fonts noto-fonts-cjk noto-fonts-emoji ttf-dejavu ttf-liberation \
    man-db man-pages texinfo

# The UKI package set always includes tpm2-tools. Add it separately only when
# the optional TPM flow is selected with GRUB.
if [[ "$USE_TPM_LUKS" == true && "$INSTALL_BOOTLOADER" == "grub" ]]; then
    pacstrap /mnt tpm2-tools
fi

# -----------------------
# 10. SYSTEM CONFIGURATION
# -----------------------

echo -e "${BBlue}Generating fstab...${NC}"
genfstab -U /mnt > /mnt/etc/fstab

# Write the dedicated /tmp entry explicitly so its capacity and security flags
# do not depend on which mount options a particular genfstab version emits.
TMP_UUID=$(blkid -s UUID -o value "/dev/mapper/${LVM_NAME}-tmp")
if [[ -z "$TMP_UUID" ]]; then
    echo -e "${BRed}Could not determine the /tmp filesystem UUID.${NC}" >&2
    exit 1
fi
sed -i '\|[[:space:]]/tmp[[:space:]]|d' /mnt/etc/fstab
echo "UUID=$TMP_UUID /tmp ext4 rw,nosuid,nodev,noexec,relatime 0 2" >> /mnt/etc/fstab

# Add security mount options
cat >> /mnt/etc/fstab <<EOF

# Security-hardened mount options
tmpfs /dev/shm tmpfs rw,nosuid,nodev,noexec,relatime,size=2G 0 0
proc /proc proc nosuid,nodev,noexec,hidepid=2,gid=proc 0 0
EOF

# Configure swap
# The swap LV already lives inside the LUKS2-encrypted LVM container, so it
# is encrypted end-to-end at rest. An additional plain dm-crypt wrapper with
# a random key only adds erase-on-reboot semantics (useful for hibernation
# attack resistance, which we don't use) at the cost of a fragile systemd
# unit dependency chain — systemd-cryptsetup-generator races against LVM
# activation and frequently fails with "dev-mapper-swap.device dependency
# failed" on first boot. Point fstab at the LVM mapper directly. Match the
# filesystem type as the third fstab field because genfstab aligns columns
# with a variable mixture of tabs and spaces.
sed -Ei '/^[[:space:]]*[^#[:space:]][^[:space:]]*[[:space:]]+[^[:space:]]+[[:space:]]+swap([[:space:]]|$)/d' /mnt/etc/fstab
echo "/dev/mapper/${LVM_NAME}-swap none swap defaults 0 0" >> /mnt/etc/fstab

# Setup systemd for hidepid
mkdir -p /mnt/etc/systemd/system/systemd-logind.service.d
cat <<EOF > /mnt/etc/systemd/system/systemd-logind.service.d/hidepid.conf
[Service]
SupplementaryGroups=proc
EOF

# GRUB reads /boot from inside the encrypted container, so its initramfs may
# safely carry the keyfile. A UKI lives on the unencrypted ESP and must never
# receive this key.
if [[ "$INSTALL_BOOTLOADER" == "grub" ]]; then
    echo -e "${BBlue}Setting up the GRUB initramfs LUKS key...${NC}"
    mkdir --verbose -p "/mnt$LUKS_KEYS"
    cp ./boot.key "/mnt$LUKS_KEYS/boot.key"
    chmod 400 "/mnt$LUKS_KEYS/boot.key"
    chown -R root:root "/mnt$LUKS_KEYS"
    chmod 700 "/mnt$LUKS_KEYS"
fi

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
export INSTALL_TMP_SIZE="$TMP_SIZE"
export INSTALL_TPM="$USE_TPM_LUKS"
export _INSTALL_TPM_PCRS="$TPM_PCRS"
export INSTALL_SSH_PUBKEY="$SSH_PUBKEY"
export INSTALL_SYSCTL_PROFILE="$SYSCTL_PROFILE"
export INSTALL_DISABLE_IPV6="$DISABLE_IPV6"
export INSTALL_TIMEZONE="$TIMEZONE"
export INSTALL_LOCALE="$LOCALE"
export INSTALL_KEYMAP="$KEYMAP"
export _INSTALL_BOOTLOADER="$INSTALL_BOOTLOADER"
export INSTALL_DATE="$(date)"
EOF
chmod 600 /mnt/root/.install-env

cat > /mnt/set-install-vars.sh <<EOF
export _INSTALL_DISK="$DISK"
export _INSTALL_USER="$USERNAME"
export _INSTALL_HOST="$HOSTNAME"
export _INSTALL_CRYPT="$CRYPT_NAME"
export _INSTALL_LVM="$LVM_NAME"
export _INSTALL_TMP_SIZE="$TMP_SIZE"
export INSTALL_TPM="$USE_TPM_LUKS"
export _INSTALL_TPM_PCRS="$TPM_PCRS"
export _INSTALL_SSH_PUBKEY="$SSH_PUBKEY"
export _INSTALL_SYSCTL_PROFILE="$SYSCTL_PROFILE"
export _INSTALL_DISABLE_IPV6="$DISABLE_IPV6"
export _INSTALL_TIMEZONE="$TIMEZONE"
export _INSTALL_LOCALE="$LOCALE"
export _INSTALL_KEYMAP="$KEYMAP"
export _INSTALL_BOOTLOADER="$INSTALL_BOOTLOADER"
EOF

chmod +x /mnt/set-install-vars.sh
cp ./chroot.sh /mnt/
chmod +x /mnt/chroot.sh
cp ./bootloader.sh /mnt/
chmod +x /mnt/bootloader.sh

# Stage the complete sysctl bundle. The chroot helper selects and installs the
# requested layers without applying them to the live ISO kernel.
SYSCTL_SOURCE_DIR="../hardening/sysctl"
SYSCTL_STAGING_DIR="/mnt/sysctl-profile"
SYSCTL_BUNDLE_FILES=(
    sysctl.sh
    60-awesome-security-core.conf
    70-awesome-workstation-network.conf
    80-awesome-performance.conf
    80-awesome-bbr.modules
    90-awesome-strict.conf
    90-awesome-ipv6-disabled.conf
)
install -d -m 0755 "$SYSCTL_STAGING_DIR"
for sysctl_file in "${SYSCTL_BUNDLE_FILES[@]}"; do
    if [[ ! -f "$SYSCTL_SOURCE_DIR/$sysctl_file" ]]; then
        echo -e "${BRed}Missing sysctl bundle file: $SYSCTL_SOURCE_DIR/$sysctl_file${NC}" >&2
        exit 1
    fi
    install -m 0644 "$SYSCTL_SOURCE_DIR/$sysctl_file" "$SYSCTL_STAGING_DIR/$sysctl_file"
done
chmod 0755 "$SYSCTL_STAGING_DIR/sysctl.sh"

if [ -f ../hardening/ssh/ssh.sh ]; then
    cp ../hardening/ssh/ssh.sh /mnt/
    chmod +x /mnt/ssh.sh
fi

if [ -f ../hardening/lib/nftables.sh ]; then
    cp ../hardening/lib/nftables.sh /mnt/nftables.sh
    chmod 0644 /mnt/nftables.sh
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

if [[ "$INSTALL_BOOTLOADER" == "uki" ]]; then
    BOOT_PROFILE_GUIDANCE=$(cat <<EOF
   - Inspect the signed boot chain: awesome-secureboot status
   - Put firmware in Secure Boot Setup Mode, then run:
       awesome-secureboot enroll-keys
   - Reboot with Secure Boot enabled.
   - If TPM unlock was selected, bind it only after Secure Boot is active:
       awesome-secureboot bind-tpm
   - Reboot once more and confirm unattended LUKS unlock.
EOF
)
else
    BOOT_PROFILE_GUIDANCE=$(cat <<EOF
   - GRUB and its initramfs live inside the encrypted root container.
   - The GRUB menu is protected by the password created during installation.
   - Secure Boot provisioning is not performed by the GRUB profile.
EOF
)
    if [[ "$USE_TPM_LUKS" == true ]]; then
        BOOT_PROFILE_GUIDANCE+=$(cat <<EOF

   - Enroll TPM unlock after first boot:
       systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=$TPM_PCRS $PARTITION3
   - GRUB still requires its passphrase to decrypt /boot.
EOF
)
    fi
fi

# Create post-installation README
cat > /mnt/root/POST_INSTALL_README.txt <<EOF
================================================================================
ARCH LINUX SECURITY-HARDENED INSTALLATION
================================================================================

Installation Date: $(date)
Hostname: $HOSTNAME
Username: $USERNAME
Disk: $DISK (Type: $DEVICE_TYPE)
/tmp: ${SIZE_OF_TMP} GiB encrypted LVM volume
TPM2 Enabled: $USE_TPM_LUKS
Sysctl Profile: $SYSCTL_PROFILE_LABEL
IPv6 Disabled: $DISABLE_IPV6
Boot Profile: $INSTALL_BOOTLOADER

CRITICAL POST-INSTALLATION STEPS:
=================================

1. IMMEDIATE ACTIONS:
   - Run: /root/install-aur-packages.sh
   - Secure backups of recovery.key and luks-header-backup.img

2. SECURITY SERVICES:
   systemctl enable --now apparmor
   systemctl enable --now auditd
   systemctl enable --now rkhunter-check.timer
   systemctl enable --now arch-audit.timer

3. BOOT SECURITY:
$BOOT_PROFILE_GUIDANCE

4. MAINTENANCE:
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

# The UKI initramfs is stored in cleartext on the ESP. Slot 1 exists only to
# unlock the container during installation and is removed as soon as chroot
# configuration has completed successfully.
if [[ "$INSTALL_BOOTLOADER" == "uki" ]]; then
    echo -e "${BBlue}Removing the install-session LUKS keyslot...${NC}"
    cryptsetup -v luksRemoveKey "$PARTITION3" ./boot.key
    log_action "Removed UKI install-session key from LUKS slot 1"
fi

# -----------------------
# 12. FINAL TPM ENROLLMENT
# -----------------------

if [ "$USE_TPM_LUKS" = true ]; then
    echo -e "${BBlue}TPM2 enrollment is ready for first boot.${NC}"
    if [[ "$INSTALL_BOOTLOADER" == "uki" ]]; then
        echo -e "${BYellow}Boot once with the passphrase, establish the final Secure Boot state, then bind the TPM.${NC}"
    else
        echo -e "${BYellow}Boot once with the passphrase, then enroll the TPM from the installed system.${NC}"
    fi
fi

# -----------------------
# 13. CLEANUP
# -----------------------

# Disable cleanup trap; we are handling cleanup manually from here
CLEANUP_ENABLED=0

echo -e "${BBlue}Performing secure cleanup...${NC}"
log_action "Performing cleanup"

# Secure deletion of sensitive files
shred -vzu ./boot.key 2>/dev/null || true
shred -vzu ./recovery.key 2>/dev/null || true
shred -vzu ./luks-header-backup.img 2>/dev/null || true
shred -vzu ./tpm_luks.conf 2>/dev/null || true

# Clean up scripts
shred -vzu /mnt/chroot.sh 2>/dev/null || true
shred -vzu /mnt/bootloader.sh 2>/dev/null || true
shred -vzu /mnt/set-install-vars.sh 2>/dev/null || true
shred -vzu /mnt/sysctl.sh 2>/dev/null || true
shred -vzu /mnt/sysctl-profile.conf 2>/dev/null || true
rm -rf -- /mnt/sysctl-profile
shred -vzu /mnt/ssh.sh 2>/dev/null || true

# Clear pacman cache
arch-chroot /mnt bash -c "pacman -Scc --noconfirm"

# Clear bash history
arch-chroot /mnt bash -c 'history -c && rm -f "$HOME/.bash_history"'

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
    if [[ "$INSTALL_BOOTLOADER" == "uki" ]]; then
        echo "4. After enabling Secure Boot: awesome-secureboot bind-tpm"
    else
        echo "4. Enroll TPM: systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=$TPM_PCRS $PARTITION3"
    fi
fi
echo "5. Review: /root/POST_INSTALL_README.txt"
echo
echo -e "${BGreen}Remember to securely store recovery.key and luks-header-backup.img!${NC}"

log_action "Installation completed successfully"
