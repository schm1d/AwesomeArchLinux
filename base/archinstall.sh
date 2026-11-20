#!/usr/bin/env bash

# Description: Fully encrypted LVM2 on LUKS with UEFI and TPM2 - Security Hardened
# Author: Bruno Schmid @brulliant
# LinkedIn: https://www.linkedin.com/in/schmidbruno/

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- Cleanup on failure ---
CLEANUP_ENABLED=0

cleanup() {
    if [[ "$CLEANUP_ENABLED" -eq 0 ]]; then
        # Nothing to undo on disk, but never leave key material behind.
        remove_install_secrets
        return
    fi
    echo "Cleanup triggered, undoing partial disk setup..." >&2
    swapoff "/dev/mapper/${LVM_NAME:-lvm_arch}-swap" 2>/dev/null || true
    umount -R /mnt 2>/dev/null || true
    vgchange -an "${LVM_NAME:-lvm_arch}" 2>/dev/null || true
    cryptsetup close "${CRYPT_NAME:-crypt_lvm}" 2>/dev/null || true
    remove_install_secrets
}

# Key material, the LUKS header backup and the TPM hand-off file live in a
# private RAM-backed directory (see create_install_secrets_dir), never in the
# current working directory: the installer is often started from a checkout on
# a USB stick, where shred cannot reliably destroy flash/FAT contents.
SECRETS_DIR=""

remove_install_secrets() {
    local secret
    [[ -n "${SECRETS_DIR:-}" && -d "$SECRETS_DIR" ]] || return 0
    for secret in boot.key recovery.key luks-header-backup.img tpm_luks.conf; do
        shred -zu "$SECRETS_DIR/$secret" 2>/dev/null || true
    done
    rm -rf -- "$SECRETS_DIR"
    SECRETS_DIR=""
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
INSTALL_GPU_UNLOCK=false
GPU_UNLOCK_TARGETS="all"
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

for installer_component in "$SCRIPT_DIR/chroot.sh" "$SCRIPT_DIR/bootloader.sh" \
    "$SCRIPT_DIR/../hardening/ssh/ssh.sh" "$SCRIPT_DIR/../hardening/lib/nftables.sh" \
    "$SCRIPT_DIR/install-aur-packages.sh" "$SCRIPT_DIR/../hardening/lib/aur-review.sh" \
    "$SCRIPT_DIR/../utils/aide-config.sh" "$SCRIPT_DIR/lib/chroot-security.sh" \
    "$SCRIPT_DIR/../utils/auditd-attack.rules" "$SCRIPT_DIR/../utils/board-health.sh" \
    "$SCRIPT_DIR/../utils/gpu-unlock.sh"; do
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

echo -e "${BBlue}\nUEFI is supported, proceeding...\n${NC}"
log_action "UEFI support confirmed"

# -----------------------
# 1. HELPER FUNCTIONS
# -----------------------

# read wrapper for the ask_* helpers below. They run inside $(...), where
# errexit is off, so a closed stdin (EOF) used to make every "ask until valid"
# loop spin forever. Exit the subshell instead: the caller's assignment then
# fails and set -e stops the installer. Callers must therefore capture the
# answer with a plain assignment (answer=$(ask_...)), never inside [[ ... ]].
prompt_read() {
    local prompt_msg="$1" var_name="$2"
    if ! read -r -p "$prompt_msg" "${var_name?}"; then
        echo -e "\n${BRed}No input available (stdin closed). Aborting.${NC}" >&2
        exit 1
    fi
}

# Prompt user yes/no question
ask_yes_no() {
    local prompt_msg="$1"
    local choice
    while true; do
        prompt_read "$prompt_msg (y/n): " choice
        case "$choice" in
            [Yy]) echo "y"; return 0 ;;
            [Nn]) echo "n"; return 0 ;;
            *) echo -e "${BRed}Invalid choice. Please type 'y' or 'n'.\n${NC}" >&2 ;;
        esac
    done
}

wipe_disk() {
    local disk="$1" source="$2" size_bytes
    size_bytes=$(blockdev --getsize64 "$disk") || return 1
    if [[ ! "$size_bytes" =~ ^[1-9][0-9]*$ ]]; then
        echo "Cannot wipe $disk: invalid device size '$size_bytes'." >&2
        return 1
    fi
    # Stop at the exact device boundary, including a partial final MiB.
    # Unbounded dd exits with ENOSPC on a successful full-device overwrite.
    dd if="$source" of="$disk" bs=1M count="${size_bytes}B" \
        iflag=fullblock status=progress conv=fsync
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

# Prompt user for a valid whole disk block device
ask_for_disk() {
    local disk
    while true; do
        prompt_read "Select the target disk (e.g., sda, nvme0n1): " disk
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

# Refuse a target that is in use. Wiping a disk with mounted filesystems,
# active swap, or open LUKS/LVM/RAID devices on top of it (the live medium, a
# data disk, a previous half-finished attempt) destroys data and then fails
# halfway through repartitioning.
assert_disk_not_in_use() {
    local disk="$1" mounts holders
    mounts=$(lsblk -nrpo NAME,MOUNTPOINTS "$disk" 2>/dev/null | awk 'NF > 1' || true)
    if [[ -n "$mounts" ]]; then
        echo -e "${BRed}Refusing to use $disk: it has mounted filesystems or active swap:${NC}" >&2
        sed 's/^/  /' <<< "$mounts" >&2
        echo "Unmount them first. The live medium itself cannot be the install target." >&2
        return 1
    fi
    holders=$(lsblk -nrpo NAME,TYPE "$disk" 2>/dev/null | awk '$2 != "disk" && $2 != "part"' || true)
    if [[ -n "$holders" ]]; then
        echo -e "${BRed}Refusing to use $disk: LUKS/LVM/RAID devices on it are still active:${NC}" >&2
        sed 's/^/  /' <<< "$holders" >&2
        echo "Deactivate them first (vgchange -an <vg>; cryptsetup close <name>), or use base/recovery-mount.sh option 2." >&2
        return 1
    fi
    return 0
}

# Last stop before anything is written: the operator must type the disk name.
confirm_disk_erase() {
    local disk="$1" disk_name="${1#/dev/}" answer
    echo -e "${BRed}\nWARNING: ALL DATA ON $disk WILL BE PERMANENTLY ERASED.${NC}" >&2
    lsblk -o NAME,SIZE,TYPE,FSTYPE,LABEL,MODEL "$disk" >&2 || true
    while true; do
        prompt_read "Type the disk name ($disk_name) to erase it, or 'abort' to quit: " answer
        answer="${answer#/dev/}"
        if [[ "$answer" == "$disk_name" ]]; then
            return 0
        elif [[ "$answer" == "abort" ]]; then
            return 1
        fi
        echo -e "${BRed}That does not match '$disk_name'.\n${NC}" >&2
    done
}

# Private RAM-backed directory for key material (see remove_install_secrets).
create_install_secrets_dir() {
    local base
    for base in /run /dev/shm; do
        if [[ "$(findmnt -n -o FSTYPE --target "$base" 2>/dev/null || true)" =~ ^(tmpfs|ramfs)$ ]]; then
            SECRETS_DIR=$(mktemp -d "$base/awesome-install.XXXXXX")
            chmod 700 "$SECRETS_DIR"
            return 0
        fi
    done
    echo -e "${BRed}No RAM-backed filesystem (/run or /dev/shm) is available for the installation keys.${NC}" >&2
    return 1
}

# Prompt user for positive integer input
ask_for_numeric() {
    local prompt_msg="$1"
    local input_val
    while true; do
        prompt_read "$prompt_msg " input_val
        if [[ "$input_val" =~ ^[1-9][0-9]*$ ]]; then
            echo "$input_val"
            return 0
        else
            echo -e "${BRed}Invalid input: '$input_val'. Please enter a positive integer.\n${NC}" >&2
        fi
    done
}

# Prompt user for username
ask_for_username() {
    local username
    while true; do
        prompt_read "Enter the new username: " username
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
        prompt_read "Enter the new hostname: " hostname
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
        prompt_read "Choice [1]: " choice
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
        prompt_read "Choice [1]: " choice
        choice="${choice:-1}"
        case "$choice" in
            1) echo "false"; return 0 ;;
            2) echo "true"; return 0 ;;
            *) echo -e "${BRed}Invalid choice. Please enter 1 or 2.\n${NC}" >&2 ;;
        esac
    done
}

ask_for_gpu_unlock() {
    local choice gpu_summary=""
    gpu_summary=$(
        # shellcheck disable=SC1090,SC1091
        source "$SCRIPT_DIR/../utils/gpu-unlock.sh"
        scan_nvidia_gpus 2>/dev/null || true
    )
    if [[ -n "$gpu_summary" ]]; then
        echo -e "${BBlue}Detected NVIDIA GPU(s):${NC}" >&2
        local bdf dev_id tier family _driver model
        while IFS='|' read -r bdf dev_id tier family _driver model; do
            [[ -n "$bdf" ]] || continue
            echo "  - $bdf [10de:$dev_id] $model -> gpu-unlock: $tier ($family)" >&2
        done <<< "$gpu_summary"
    fi
    while true; do
        echo -e "${BBlue}Optional NVIDIA tensor-core unlock (Zagitta/gpu-unlock — GeForce RTX 20/30/40):${NC}" >&2
        echo "1) disabled (default)" >&2
        echo "2) enabled  - build & install gpu-unlock DKMS + firmware for full-rate FP16/BF16/TF32" >&2
        prompt_read "Choice [1]: " choice
        choice="${choice:-1}"
        case "$choice" in
            1) echo "false"; return 0 ;;
            2) echo "true"; return 0 ;;
            *) echo -e "${BRed}Invalid choice. Please enter 1 or 2.\n${NC}" >&2 ;;
        esac
    done
}

ask_for_gpu_unlock_targets() {
    local choice targets_input
    local bdf_re='^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7](,[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7])*$'
    while true; do
        echo -e "${BBlue}Select gpu_unlock.targets kernel parameter:${NC}" >&2
        echo "1) all - unlock every supported unbound RTX 20/30/40 GPU (default)" >&2
        echo "2) specific PCI address(es) - comma-separated BDFs (e.g. 0000:01:00.0)" >&2
        prompt_read "Choice [1]: " choice
        choice="${choice:-1}"
        case "$choice" in
            1) echo "all"; return 0 ;;
            2)
                prompt_read "Enter PCI address(es) (DDDD:BB:DD.F[,DDDD:BB:DD.F...]): " targets_input
                if [[ "$targets_input" =~ $bdf_re ]]; then
                    echo "$targets_input"
                    return 0
                fi
                echo -e "${BRed}Invalid PCI address list. Use full lspci -D format (e.g. 0000:01:00.0).\n${NC}" >&2
                ;;
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
        prompt_read "Choice (1 or 2): " choice
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

# A timezone is a zone name (no "..", no absolute path) whose file under
# /usr/share/zoneinfo is a compiled TZif zone. A bare "-f" test also accepted
# path traversal and data files such as zone.tab or tzdata.zi, which then
# became a broken /etc/localtime symlink.
valid_timezone() {
    local tz="$1" zone_file magic
    [[ "$tz" =~ ^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+)*$ ]] || return 1
    zone_file="/usr/share/zoneinfo/$tz"
    [[ -f "$zone_file" ]] || return 1
    magic=$(head -c 4 "$zone_file" 2>/dev/null | tr -d '\0') || return 1
    [[ "$magic" == "TZif" ]]
}

# Prompt user for timezone
ask_for_timezone() {
    local tz
    while true; do
        echo -e "${BBlue}Select timezone:${NC}" >&2
        echo "Common: UTC, US/Eastern, US/Pacific, Europe/London, Europe/Berlin," >&2
        echo "        Europe/Zurich, Asia/Tokyo, Asia/Shanghai, Australia/Sydney" >&2
        prompt_read "Timezone [UTC]: " tz
        tz="${tz:-UTC}"
        if valid_timezone "$tz"; then
            echo "$tz"
            return 0
        else
            echo -e "${BRed}Invalid timezone: '$tz'. Use a zone name from 'timedatectl list-timezones' (e.g. Europe/Zurich).\n${NC}" >&2
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
        prompt_read "Choice [1]: " choice
        choice="${choice:-1}"
        if [[ "$choice" == "0" ]]; then
            prompt_read "Enter locale (e.g. nl_NL.UTF-8): " loc
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

# True when the name is an installed console keymap. The list is captured
# first: piping localectl into "grep -q" under pipefail can report failure
# (SIGPIPE) for a keymap that does exist, and the name is matched literally.
console_keymap_exists() {
    local km="$1" available
    [[ -n "$km" ]] || return 1
    available=$(localectl list-keymaps 2>/dev/null || true)
    if [[ -z "$available" ]]; then
        # No localectl data (minimal environment): fall back to the kbd tree.
        available=$(find /usr/share/kbd/keymaps -type f -name '*.map*' -printf '%f\n' 2>/dev/null |
            sed -E 's/\.map(\.gz|\.zst|\.xz|\.bz2)?$//' || true)
    fi
    grep -Fqx -- "$km" <<< "$available"
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
    )
    while true; do
        echo -e "${BBlue}Select console keymap:${NC}" >&2
        local i=1
        for km in "${keymaps[@]}"; do
            printf "  %2d) %s\n" "$i" "$km" >&2
            (( ++i ))
        done
        echo "   0) Other -- type a keymap name" >&2
        prompt_read "Choice [1]: " choice
        choice="${choice:-1}"
        if [[ "$choice" == "0" ]]; then
            prompt_read "Enter keymap name: " km
            if console_keymap_exists "$km"; then
                loadkeys "$km" 2>/dev/null || true
                echo "$km"
                return 0
            else
                echo -e "${BRed}Keymap '$km' not found. Run 'localectl list-keymaps' for options.\n${NC}" >&2
            fi
        elif [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#keymaps[@]} )); then
            km="${keymaps[$((choice-1))]}"
            if console_keymap_exists "$km"; then
                loadkeys "$km" 2>/dev/null || true
                echo "$km"
                return 0
            fi
            echo -e "${BRed}Keymap '$km' is not available on this system. Pick another one.\n${NC}" >&2
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
        echo -e "${BRed}Error: Insufficient disk space. Need at least $((required / 1073741824))GB${NC}" >&2
        return 1
    fi
    return 0
}

# Validate network connection
validate_network() {
    echo -e "${BBlue}Checking network connection...${NC}"
    if ! ping -c 1 archlinux.org &>/dev/null; then
        echo -e "${BRed}Warning: No network connection detected.${NC}"
        local continue_offline
        continue_offline=$(ask_yes_no "Continue anyway?")
        if [[ "$continue_offline" == "n" ]]; then
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
        if [ "$(cat /sys/block/"$device_name"/queue/rotational)" = "0" ]; then
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
        
        local clear_tpm
        clear_tpm=$(ask_yes_no "Do you want to clear the TPM? (requires physical presence)")
        if [[ "$clear_tpm" == "y" ]]; then
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
        
        if [ -f "$SECRETS_DIR/tpm_luks.conf" ]; then
            cp "$SECRETS_DIR/tpm_luks.conf" /mnt/etc/tpm_luks.conf
            chmod 600 /mnt/etc/tpm_luks.conf
        fi
        
        # Create PCR check tool
        cat > /mnt/usr/local/bin/check-tpm-pcrs <<TPMCHECK
#!/usr/bin/env bash
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
        USE_TPM_ANSWER=$(ask_yes_no "Use TPM2 for LUKS encryption?")
        if [[ "$USE_TPM_ANSWER" == "y" ]]; then
            USE_TPM_LUKS=true
            
            echo -e "${BBlue}Select PCRs to bind:${NC}"
            echo "  7 - Secure Boot state (Recommended)"
            echo "  0+7 - Plus firmware code"
            echo "  0+1+4+7+9 - Plus firmware config, bootloader, and kernel"
            
            while true; do
                read -r -p "Enter PCRs (default: 7): " TPM_PCRS
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
lsblk -d -o NAME,SIZE,TYPE,MODEL | awk 'NR==1 || $3=="disk"'
echo

TARGET_DISK=$(ask_for_disk)
DISK="/dev/$TARGET_DISK"
assert_disk_not_in_use "$DISK"
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

# Validate SSH public key to prevent shell injection when embedded in sourced files
validate_ssh_pubkey() {
    local key="$1"
    if [[ -z "$key" ]]; then
        return 0
    fi
    # Reject keys containing quotes, backslashes, newlines, or shell metacharacters
    if [[ "$key" =~ [\$\`\(\)\{\}\;\|\&\<\>\"\'\\] ]] || [[ "$key" == *$'\n'* ]] || [[ "$key" == *$'\r'* ]]; then
        echo -e "${BRed}Error: SSH public key contains invalid characters.${NC}" >&2
        return 1
    fi
    # Accept only key types the hardened sshd will accept afterwards
    # (PubkeyAcceptedAlgorithms in hardening/ssh/ssh.sh). Password logins are
    # disabled, so a key sshd refuses -- plain ecdsa-sha2-* in particular --
    # would lock the operator out of the freshly installed machine.
    local key_type="${key%% *}"
    case "$key_type" in
        ssh-ed25519|sk-ssh-ed25519@openssh.com|sk-ecdsa-sha2-nistp256@openssh.com|ssh-rsa) ;;
        ecdsa-sha2-*)
            echo -e "${BRed}Error: plain ECDSA keys ($key_type) are not accepted by the hardened sshd configuration.${NC}" >&2
            echo -e "${BRed}Use an Ed25519 key (ssh-keygen -t ed25519), a FIDO2 key, or RSA.${NC}" >&2
            return 1
            ;;
        *)
            echo -e "${BRed}Error: unsupported SSH key type '${key_type}'. Accepted: ssh-ed25519, sk-ssh-ed25519@openssh.com, sk-ecdsa-sha2-nistp256@openssh.com, ssh-rsa.${NC}" >&2
            return 1
            ;;
    esac
    # Check the whole key, not just its prefix: a truncated paste must fail
    # here rather than at the first login attempt.
    if command -v ssh-keygen >/dev/null 2>&1; then
        local key_file
        key_file=$(mktemp) || return 1
        printf '%s\n' "$key" > "$key_file"
        if ! ssh-keygen -l -f "$key_file" >/dev/null 2>&1; then
            rm -f -- "$key_file"
            echo -e "${BRed}Error: that is not a complete, valid SSH public key (ssh-keygen could not parse it).${NC}" >&2
            return 1
        fi
        rm -f -- "$key_file"
    fi
    return 0
}

# Ask for SSH public key (critical: password auth will be disabled)
echo -e "\n${BYellow}Password authentication will be disabled after installation.${NC}"
while true; do
    echo -e "${BYellow}Paste your SSH public key (from ~/.ssh/id_ed25519.pub, or press Enter for local console setup later):${NC}"
    read -r SSH_PUBKEY
    SSH_PUBKEY="${SSH_PUBKEY%$'\r'}"
    if [[ -z "$SSH_PUBKEY" ]]; then
        echo -e "${BRed}WARNING: No SSH public key provided!${NC}"
        echo -e "${BRed}You will need physical console access to add one after installation.${NC}"
        break
    fi
    if validate_ssh_pubkey "$SSH_PUBKEY"; then
        break
    fi
done

echo -e "\n${BBlue}Kernel sysctl profile:${NC}"
SYSCTL_PROFILE=$(ask_for_sysctl_profile)
SYSCTL_PROFILE_LABEL=$(describe_sysctl_profile "$SYSCTL_PROFILE")
DISABLE_IPV6=$(ask_for_ipv6_policy)
echo
INSTALL_GPU_UNLOCK=$(ask_for_gpu_unlock)
if [[ "$INSTALL_GPU_UNLOCK" == "true" ]]; then
    GPU_UNLOCK_TARGETS=$(ask_for_gpu_unlock_targets)
fi

echo -e "\nUsername: $USERNAME"
echo -e "Hostname: $HOSTNAME"
echo -e "Timezone: $TIMEZONE"
echo -e "Locale: $LOCALE"
echo -e "Keymap: $KEYMAP"
echo -e "Sysctl Profile: $SYSCTL_PROFILE_LABEL"
echo -e "IPv6: $([[ "$DISABLE_IPV6" == true ]] && echo disabled || echo 'enabled and hardened')"
echo -e "Boot Profile: $INSTALL_BOOTLOADER"
echo -e "GPU Unlock: $([[ "$INSTALL_GPU_UNLOCK" == true ]] && echo "enabled (gpu_unlock.targets=$GPU_UNLOCK_TARGETS)" || echo disabled)"
echo -e "/tmp: ${SIZE_OF_TMP} GiB encrypted LVM volume"
echo -e "SSH Key:  $([[ -n "$SSH_PUBKEY" ]] && echo "(provided, ${SSH_PUBKEY%% *})" || echo "(none)")\n"

log_action "User: $USERNAME, Hostname: $HOSTNAME, Timezone: $TIMEZONE, Locale: $LOCALE, Keymap: $KEYMAP, Sysctl Profile: $SYSCTL_PROFILE_LABEL, Disable IPv6: $DISABLE_IPV6, Boot Profile: $INSTALL_BOOTLOADER, GPU Unlock: $INSTALL_GPU_UNLOCK ($GPU_UNLOCK_TARGETS)"

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

# Nothing has been written so far. Re-check that the disk is still idle and
# make the operator confirm the target explicitly before the first write.
assert_disk_not_in_use "$DISK"
if ! confirm_disk_erase "$DISK"; then
    echo -e "${BYellow}Aborted before any change was made to $DISK.${NC}"
    exit 1
fi
log_action "Operator confirmed erasing $DISK"

# Optional secure wipe
WIPE_ANSWER=$(ask_yes_no "Securely wipe disk before encryption?")
if [[ "$WIPE_ANSWER" == "y" ]]; then
    FAST_WIPE_ANSWER=$(ask_yes_no "Use fast wipe (less secure)?")
    if [[ "$FAST_WIPE_ANSWER" == "y" ]]; then
        echo -e "${BBlue}Fast wiping disk...${NC}"
        wipe_disk "$DISK" /dev/zero
    else
        echo -e "${BBlue}Secure wiping disk (this will take time)...${NC}"
        wipe_disk "$DISK" /dev/urandom
    fi
fi

echo -e "${BBlue}Creating partitions...${NC}"
log_action "Creating partition table"

# Drop filesystem/LUKS/LVM/RAID signatures of the previous layout first. Zapping
# only the partition table leaves them on disk, and a stale LVM PV or LUKS
# header that ends up inside one of the new partitions is picked up again by
# udev and LVM (duplicate VG names, wrong blkid types).
while read -r old_partition; do
    [[ -b "$old_partition" ]] || continue
    wipefs -a "$old_partition" >/dev/null 2>&1 || true
done < <(lsblk -nrpo NAME,TYPE "$DISK" 2>/dev/null | awk '$2 == "part" { print $1 }')
wipefs -a "$DISK" >/dev/null 2>&1 || true

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

# Sizes, not sector numbers: fixed sector ranges assume 512-byte logical
# sectors and turn the 1 GiB ESP into 8 GiB on 4Kn drives. With sgdisk's 1 MiB
# alignment these produce the same layout as before on 512-byte disks
# (1 MiB BIOS boot at 1 MiB, 1 GiB ESP, LUKS on the rest).
sgdisk -n 1:0:+1M -t 1:ef02 -c 1:"BIOS_Boot" "$DISK"
sgdisk -n 2:0:+1G -t 2:ef00 -c 2:"EFI_System" "$DISK"
sgdisk -n 3:0:0 -t 3:8309 -c 3:"Linux_LUKS" "$DISK"

partprobe "$DISK"
udevadm settle --timeout=30 || true
for new_partition in "$PARTITION1" "$PARTITION2" "$PARTITION3"; do
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        [[ -b "$new_partition" ]] && break
        sleep 1
    done
    if [[ ! -b "$new_partition" ]]; then
        echo -e "${BRed}Partition $new_partition did not appear after partitioning $DISK.${NC}" >&2
        exit 1
    fi
    # Clear whatever old signature now sits at the start of the new partition.
    wipefs -a "$new_partition" >/dev/null 2>&1 || true
done
udevadm settle --timeout=30 || true

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
create_install_secrets_dir
umask 077
dd if=/dev/random of="$SECRETS_DIR/boot.key" bs=512 count=8 iflag=fullblock
dd if=/dev/random of="$SECRETS_DIR/recovery.key" bs=512 count=8 iflag=fullblock
umask 022

# Add keys to LUKS
echo -e "${BBlue}Adding keyfiles to LUKS container...${NC}"
echo "You'll need to enter your LUKS passphrase twice (once for each key)"
cryptsetup -v luksAddKey "$PARTITION3" "$SECRETS_DIR/boot.key" --key-slot 1
cryptsetup -v luksAddKey "$PARTITION3" "$SECRETS_DIR/recovery.key" --key-slot 2

echo -e "${BGreen}IMPORTANT: Copy $SECRETS_DIR/recovery.key to external off-machine storage NOW (live-ISO copy will be shredded at cleanup)!${NC}"
read -r -p "Press Enter after saving recovery.key..."

# TPM2 enrollment (if selected)
if [ "$USE_TPM_LUKS" = true ]; then
    echo -e "${BBlue}Setting up TPM2 enrollment...${NC}"
    
    # Get UUID for later configuration
    UUID=$(cryptsetup luksUUID "$PARTITION3")
    
    # Create config for later enrollment
    (
        umask 077
        cat > "$SECRETS_DIR/tpm_luks.conf" <<EOF
CRYPTDEVICE=UUID=$UUID:$CRYPT_NAME
TPM2_PCRS=$TPM_PCRS
TPM2_DEVICE=$TPM_DEVICE
EOF
    )
    
    echo -e "${BYellow}Note: TPM2 enrollment will be completed after system installation${NC}"
fi

# Backup LUKS header
echo -e "${BBlue}Backing up LUKS header...${NC}"
(umask 077; cryptsetup luksHeaderBackup "$PARTITION3" --header-backup-file "$SECRETS_DIR/luks-header-backup.img")
echo -e "${BGreen}IMPORTANT: Copy $SECRETS_DIR/luks-header-backup.img to external off-machine storage NOW (live-ISO copy will be shredded at cleanup)!${NC}"
read -r -p "Press Enter after saving header backup..."

# Open LUKS container
echo -e "${BBlue}Opening LUKS container...${NC}"
cryptsetup -v luksOpen "$PARTITION3" "$CRYPT_NAME" --key-file "$SECRETS_DIR/boot.key"

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
    cp "$SECRETS_DIR/boot.key" "/mnt$LUKS_KEYS/boot.key"
    chmod 400 "/mnt$LUKS_KEYS/boot.key"
    chown -R root:root "/mnt$LUKS_KEYS"
    chmod 700 "/mnt$LUKS_KEYS"
fi

# Copy TPM config if used
if [ "$USE_TPM_LUKS" = true ] && [ -f "$SECRETS_DIR/tpm_luks.conf" ]; then
    cp "$SECRETS_DIR/tpm_luks.conf" /mnt/etc/
    chmod 600 /mnt/etc/tpm_luks.conf
fi

# Create installation info safely with printf %q
INSTALL_DATE_VAL="$(date)"
{
    printf 'export %s=%q\n' \
        INSTALL_DISK "$DISK" \
        INSTALL_USER "$USERNAME" \
        INSTALL_HOST "$HOSTNAME" \
        INSTALL_CRYPT "$CRYPT_NAME" \
        INSTALL_LVM "$LVM_NAME" \
        INSTALL_VAR_SIZE "${VAR_SIZE:-}" \
        INSTALL_TMP_SIZE "$TMP_SIZE" \
        INSTALL_TPM "$USE_TPM_LUKS" \
        INSTALL_TPM_PCRS "$TPM_PCRS" \
        _INSTALL_TPM_PCRS "$TPM_PCRS" \
        INSTALL_SSH_PUBKEY "$SSH_PUBKEY" \
        INSTALL_SYSCTL_PROFILE "$SYSCTL_PROFILE" \
        INSTALL_DISABLE_IPV6 "$DISABLE_IPV6" \
        INSTALL_TIMEZONE "$TIMEZONE" \
        INSTALL_LOCALE "$LOCALE" \
        INSTALL_KEYMAP "$KEYMAP" \
        INSTALL_BOOTLOADER "$INSTALL_BOOTLOADER" \
        _INSTALL_BOOTLOADER "$INSTALL_BOOTLOADER" \
        INSTALL_GPU_UNLOCK "$INSTALL_GPU_UNLOCK" \
        _INSTALL_GPU_UNLOCK "$INSTALL_GPU_UNLOCK" \
        INSTALL_GPU_UNLOCK_TARGETS "$GPU_UNLOCK_TARGETS" \
        _INSTALL_GPU_UNLOCK_TARGETS "$GPU_UNLOCK_TARGETS" \
        INSTALL_DATE "$INSTALL_DATE_VAL"
} > /mnt/root/.install-env
chmod 600 /mnt/root/.install-env

{
    printf 'export %s=%q\n' \
        _INSTALL_DISK "$DISK" \
        _INSTALL_USER "$USERNAME" \
        _INSTALL_HOST "$HOSTNAME" \
        _INSTALL_CRYPT "$CRYPT_NAME" \
        _INSTALL_LVM "$LVM_NAME" \
        _INSTALL_TMP_SIZE "$TMP_SIZE" \
        INSTALL_TPM "$USE_TPM_LUKS" \
        _INSTALL_TPM "$USE_TPM_LUKS" \
        _INSTALL_TPM_PCRS "$TPM_PCRS" \
        _INSTALL_SSH_PUBKEY "$SSH_PUBKEY" \
        _INSTALL_SYSCTL_PROFILE "$SYSCTL_PROFILE" \
        _INSTALL_DISABLE_IPV6 "$DISABLE_IPV6" \
        _INSTALL_TIMEZONE "$TIMEZONE" \
        _INSTALL_LOCALE "$LOCALE" \
        _INSTALL_KEYMAP "$KEYMAP" \
        _INSTALL_BOOTLOADER "$INSTALL_BOOTLOADER" \
        INSTALL_GPU_UNLOCK "$INSTALL_GPU_UNLOCK" \
        _INSTALL_GPU_UNLOCK "$INSTALL_GPU_UNLOCK" \
        INSTALL_GPU_UNLOCK_TARGETS "$GPU_UNLOCK_TARGETS" \
        _INSTALL_GPU_UNLOCK_TARGETS "$GPU_UNLOCK_TARGETS"
} > /mnt/set-install-vars.sh
chmod 700 /mnt/set-install-vars.sh

install -m 0755 "$SCRIPT_DIR/chroot.sh" /mnt/chroot.sh
install -m 0755 "$SCRIPT_DIR/bootloader.sh" /mnt/bootloader.sh

# Stage the complete sysctl bundle. The chroot helper selects and installs the
# requested layers without applying them to the live ISO kernel.
SYSCTL_STAGING_DIR="/mnt/sysctl-profile"
install -d -m 0755 "$SYSCTL_STAGING_DIR"
for sysctl_file in "${SYSCTL_BUNDLE_FILES[@]}"; do
    install -m 0644 "$SYSCTL_SOURCE_DIR/$sysctl_file" "$SYSCTL_STAGING_DIR/$sysctl_file"
done
chmod 0755 "$SYSCTL_STAGING_DIR/sysctl.sh"

install -m 0755 "$SCRIPT_DIR/../hardening/ssh/ssh.sh" /mnt/ssh.sh
install -m 0644 "$SCRIPT_DIR/../hardening/lib/nftables.sh" /mnt/nftables.sh

install -Dm0644 "$SCRIPT_DIR/lib/chroot-security.sh" /mnt/usr/local/lib/awesomearchlinux/chroot-security.sh
install -Dm0644 "$SCRIPT_DIR/../utils/auditd-attack.rules" /mnt/usr/local/share/awesomearchlinux/auditd-attack.rules
install -Dm0755 "$SCRIPT_DIR/../utils/board-health.sh" /mnt/usr/local/lib/awesomearchlinux/board-health.sh
install -Dm0755 "$SCRIPT_DIR/../utils/gpu-unlock.sh" /mnt/usr/local/lib/awesomearchlinux/gpu-unlock.sh
install -d -m 0755 /mnt/usr/local/sbin
ln -sfn /usr/local/lib/awesomearchlinux/gpu-unlock.sh /mnt/usr/local/sbin/awesome-gpu-unlock

# Stage reviewed AUR installation and AIDE configuration for root after reboot.
install -m 0700 "$SCRIPT_DIR/install-aur-packages.sh" /mnt/root/install-aur-packages.sh
install -m 0600 "$SCRIPT_DIR/../hardening/lib/aur-review.sh" /mnt/root/aur-review.sh
install -m 0700 "$SCRIPT_DIR/../utils/aide-config.sh" /mnt/root/aide-config.sh
# End post-install package staging.

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
GPU Unlock (Zagitta/gpu-unlock): $([[ "$INSTALL_GPU_UNLOCK" == true ]] && echo "enabled (gpu_unlock.targets=$GPU_UNLOCK_TARGETS; check with 'awesome-gpu-unlock --status')" || echo "disabled (optional; install later with 'sudo awesome-gpu-unlock --install')")

CRITICAL POST-INSTALLATION STEPS:
=================================

1. IMMEDIATE ACTIONS:
   - Run as root: sudo /root/install-aur-packages.sh (review each AUR recipe)
   - Secure backups of recovery.key and luks-header-backup.img

2. SECURITY SERVICES:
   Already enabled by the installer (check with 'systemctl is-enabled <unit>'):
     auditd, rkhunter-check.timer, arch-audit.timer
   AppArmor is installed but NOT active yet. Enabling apparmor.service alone
   does nothing: the kernel also needs its LSM parameters. From a checkout of
   the repository run
       sudo ./hardening/apparmor/apparmor.sh
   (see hardening/apparmor/README.md) and reboot. Then:
     - 'cat /sys/kernel/security/lsm' must list apparmor; 'aa-status' shows
       the loaded profiles.
     - The sshd profile starts in complain (log-only) mode. Log in over SSH
       as you normally do, look for apparmor="ALLOWED" lines for sshd in
       'journalctl -k' / the audit log, and when there are none run
           sudo ./hardening/apparmor/apparmor.sh --enforce
   systemctl status audit-rules.service awesome-journal-sealing.service
   - Move /root/journal-sealing/verification-*.txt to trusted off-machine storage.
   - Verify the saved copy, then remove the local verification file.
   - Keep /var/log/journal/*/fss on this machine; never regenerate with --force.

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

Installation log: /root/$(basename "$INSTALL_LOG")
================================================================================
EOF

# Backup LUKS header
cp "$SECRETS_DIR/luks-header-backup.img" /mnt/root/
chmod 600 /mnt/root/luks-header-backup.img

# Copy installation log (refreshed at the very end; this early copy is what
# remains if the chroot phase fails)
install -m 0600 "$INSTALL_LOG" "/mnt/root/$(basename "$INSTALL_LOG")"

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
    cryptsetup -v luksRemoveKey "$PARTITION3" "$SECRETS_DIR/boot.key"
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
remove_install_secrets

# Clean up scripts
shred -vzu /mnt/chroot.sh 2>/dev/null || true
shred -vzu /mnt/bootloader.sh 2>/dev/null || true
shred -vzu /mnt/set-install-vars.sh 2>/dev/null || true
rm -rf -- /mnt/sysctl-profile
shred -vzu /mnt/ssh.sh 2>/dev/null || true
shred -vzu /mnt/nftables.sh 2>/dev/null || true

# Clear pacman cache. "pacman -Scc --noconfirm" answers the default N to
# "remove ALL files from cache?" and removes nothing, so answer explicitly.
arch-chroot /mnt bash -c "printf 'y\ny\n' | pacman -Scc" >/dev/null ||
    echo -e "${BYellow}Could not clear the pacman package cache; run 'pacman -Scc' after first boot.${NC}" >&2

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
echo "3. Run as root: sudo /root/install-aur-packages.sh (review each AUR recipe)"
if [ "$USE_TPM_LUKS" = true ]; then
    if [[ "$INSTALL_BOOTLOADER" == "uki" ]]; then
        echo "4. After enabling Secure Boot: awesome-secureboot bind-tpm"
    else
        echo "4. Enroll TPM: systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=$TPM_PCRS $PARTITION3"
    fi
fi
echo "5. Review: /root/POST_INSTALL_README.txt"
echo
echo -e "${BGreen}Verify your external off-machine backups of recovery.key and luks-header-backup.img!${NC}"
echo -e "${BYellow}(Live-ISO copies have been shredded; an encrypted copy of luks-header-backup.img is also at /root/luks-header-backup.img on the installed system, which should be moved off-machine.)${NC}"

log_action "Installation completed successfully"

# The copy taken before the chroot phase stops there; replace it with the
# complete log now that everything has run.
install -m 0600 "$INSTALL_LOG" "/mnt/root/$(basename "$INSTALL_LOG")" 2>/dev/null || true
