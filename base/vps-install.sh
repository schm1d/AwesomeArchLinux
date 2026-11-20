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
readonly SHM_SIZE_MB=2048
readonly MIN_TMPFS_SIZE_MB=64

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

# tmpfs is backed by RAM and swap, not by the disk. The value passed in is only
# an upper bound: the size is never more than half of physical memory (the
# kernel's own tmpfs default), so filling /tmp or /dev/shm cannot exhaust the
# memory of a 1-2 GB VPS. Prints a size in MiB.
tmpfs_size_mb() {
    local ceiling_mb="$1" mem_kb half_ram_mb

    mem_kb=$(awk '/^MemTotal:/ { print $2; exit }' /proc/meminfo 2>/dev/null || true)
    if [[ "$mem_kb" =~ ^[0-9]+$ ]] && ((mem_kb > 0)); then
        half_ram_mb=$((mem_kb / 2048))
        ((half_ram_mb >= MIN_TMPFS_SIZE_MB)) || half_ram_mb=$MIN_TMPFS_SIZE_MB
        if ((half_ram_mb < ceiling_mb)); then
            printf '%s\n' "$half_ram_mb"
            return 0
        fi
    fi
    printf '%s\n' "$ceiling_mb"
}

# /tmp ceiling in MiB: half of RAM, capped at 10 GiB (25 GiB when the disk is
# at least 1 TB, the previous disk-only rule).
recommended_tmp_size_mb() {
    local disk="$1"
    local disk_size_bytes ceiling_gb="$DEFAULT_TMP_SIZE_GB"

    disk_size_bytes=$(lsblk -b -d -n -o SIZE "$disk" 2>/dev/null || true)
    if [[ "$disk_size_bytes" =~ ^[0-9]+$ ]] &&
       ((disk_size_bytes >= LARGE_DISK_THRESHOLD_BYTES)); then
        ceiling_gb="$LARGE_DISK_TMP_SIZE_GB"
    fi
    tmpfs_size_mb "$((ceiling_gb * 1024))"
}

ask_for_disk() {
    local disk
    while true; do
        prompt_read "Select the target disk (e.g., sda, vda, nvme0n1): " disk
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

ask_for_ssh_port() {
    local port_input port
    while true; do
        prompt_read "SSH port (default 22): " port_input
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
    # Accept only key types the hardened sshd will accept afterwards
    # (PubkeyAcceptedAlgorithms in hardening/ssh/ssh.sh). Password logins are
    # disabled, so a key sshd refuses -- plain ecdsa-sha2-* in particular --
    # would lock the operator out of the freshly installed machine.
    local key_type="${key%% *}"
    case "$key_type" in
        ssh-ed25519|sk-ssh-ed25519@openssh.com|sk-ecdsa-sha2-nistp256@openssh.com|ssh-rsa) ;;
        ecdsa-sha2-*)
            echo -e "${BRed}ERROR: plain ECDSA keys ($key_type) are not accepted by the hardened sshd configuration.${NC}" >&2
            echo -e "${BRed}Use an Ed25519 key (ssh-keygen -t ed25519), a FIDO2 key, or RSA.${NC}" >&2
            return 1
            ;;
        *)
            echo -e "${BRed}ERROR: unsupported SSH key type '${key_type}'. Accepted: ssh-ed25519, sk-ssh-ed25519@openssh.com, sk-ecdsa-sha2-nistp256@openssh.com, ssh-rsa.${NC}" >&2
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
            echo -e "${BRed}ERROR: that is not a complete, valid SSH public key (ssh-keygen could not parse it).${NC}" >&2
            return 1
        fi
        rm -f -- "$key_file"
    fi
    return 0
}

# True for names that belong to system accounts or groups on the installed
# system, or that the installer creates itself. vps-chroot.sh would otherwise
# adopt the system account as the administrator ("already exists"), or useradd
# would fail on the existing group, after the disk has been wiped.
username_is_reserved() {
    local name="$1" reserved entry_id
    for reserved in root nobody sudo wheel proc compilers clamav chrony git arpwatch polkitd; do
        [[ "$name" == "$reserved" ]] && return 0
    done
    [[ "$name" == systemd-* ]] && return 0
    # The live system carries the same base accounts and groups as the target.
    entry_id=$(getent passwd "$name" 2>/dev/null | cut -d: -f3 || true)
    if [[ "$entry_id" =~ ^[0-9]+$ ]] && (( entry_id < 1000 || entry_id == 65534 )); then
        return 0
    fi
    entry_id=$(getent group "$name" 2>/dev/null | cut -d: -f3 || true)
    if [[ "$entry_id" =~ ^[0-9]+$ ]] && (( entry_id < 1000 || entry_id == 65534 )); then
        return 0
    fi
    return 1
}

ask_for_username() {
    local username
    while true; do
        prompt_read "Enter the new username: " username
        if ! [[ "$username" =~ ^[a-z_][a-z0-9_-]*$ ]] || [[ ${#username} -gt 32 ]]; then
            echo -e "${BRed}Invalid username. Must begin with [a-z_], contain only [a-z0-9_-], max 32 chars.\n${NC}" >&2
        elif username_is_reserved "$username"; then
            echo -e "${BRed}'$username' is a system account or group name. Choose a different username.\n${NC}" >&2
        else
            echo "$username"
            return 0
        fi
    done
}

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
assert_disk_not_in_use "$DISK"
TMP_SIZE_MB=$(recommended_tmp_size_mb "$DISK")
SHM_TMPFS_SIZE_MB=$(tmpfs_size_mb "$SHM_SIZE_MB")
echo -e "${BGreen}Selected: $DISK${NC}\n"
echo -e "${BGreen}/tmp tmpfs ceiling: ${TMP_SIZE_MB} MiB (at most half of RAM)${NC}\n"
log_action "Selected disk: $DISK, /tmp tmpfs ceiling: ${TMP_SIZE_MB} MiB, /dev/shm ceiling: ${SHM_TMPFS_SIZE_MB} MiB"

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
    prompt_read "" SSH_PUBKEY
    SSH_PUBKEY="${SSH_PUBKEY%$'\r'}"
    if [[ -z "$SSH_PUBKEY" ]]; then
        echo -e "${BRed}WARNING: No SSH public key provided! Remote SSH login will be impossible until a key is added via VPS console.${NC}"
        NO_SSH_KEY_ANSWER=$(ask_yes_no "Do you confirm you have out-of-band VPS console access and want to proceed WITHOUT an SSH key?")
        if [[ "$NO_SSH_KEY_ANSWER" == "y" ]]; then
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
echo -e "SSH Key:  $([[ -n "$SSH_PUBKEY" ]] && echo "(provided, ${SSH_PUBKEY%% *})" || echo "(none)")\n"

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

# Nothing has been written so far. Re-check that the disk is still idle and
# make the operator confirm the target explicitly before the first write.
assert_disk_not_in_use "$DISK"
if ! confirm_disk_erase "$DISK"; then
    echo -e "${BYellow}Aborted before any change was made to $DISK.${NC}"
    exit 1
fi
log_action "Operator confirmed erasing $DISK"

echo -e "${BBlue}Creating partitions...${NC}"
log_action "Creating partition table"

# Drop filesystem/LUKS/LVM/RAID signatures of the previous layout first. Zapping
# only the partition table leaves them on disk, and a stale signature that ends
# up inside one of the new partitions is picked up again by udev and blkid.
while read -r old_partition; do
    [[ -b "$old_partition" ]] || continue
    wipefs -a "$old_partition" >/dev/null 2>&1 || true
done < <(lsblk -nrpo NAME,TYPE "$DISK" 2>/dev/null | awk '$2 == "part" { print $1 }')
wipefs -a "$DISK" >/dev/null 2>&1 || true

sgdisk -Z "$DISK"
sgdisk -o "$DISK"

# Sizes, not sector numbers: fixed sector ranges assume 512-byte logical
# sectors and turn the ESP into 8 GiB on 4Kn disks. With sgdisk's 1 MiB
# alignment these produce the same layout as before on 512-byte disks (the
# old sector range made the ESP 1025 MiB, so that size is kept).
if [ "$BOOT_MODE" = "uefi" ]; then
    # UEFI: EFI partition + root
    sgdisk -n 1:0:+1025M -t 1:ef00 -c 1:"EFI_System" "$DISK"
    sgdisk -n 2:0:0 -t 2:8300 -c 2:"Linux_Root" "$DISK"
    BOOT_PART="${DISK}${PART_SUFFIX}1"
    ROOT_PART="${DISK}${PART_SUFFIX}2"
else
    # BIOS: BIOS boot partition + root
    sgdisk -n 1:0:+1M -t 1:ef02 -c 1:"BIOS_Boot" "$DISK"
    sgdisk -n 2:0:0 -t 2:8300 -c 2:"Linux_Root" "$DISK"
    BOOT_PART="${DISK}${PART_SUFFIX}1"
    ROOT_PART="${DISK}${PART_SUFFIX}2"
fi

partprobe "$DISK"
udevadm settle --timeout=30 || true
for new_partition in "$BOOT_PART" "$ROOT_PART"; do
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
# 5. FILESYSTEM SETUP
# -----------------------

echo -e "${BBlue}Formatting filesystems...${NC}"
log_action "Formatting filesystems"

CLEANUP_ENABLED=1

mkfs.ext4 -F -m 1 -E lazy_itable_init=0,lazy_journal_init=0 "$ROOT_PART"

# Mount root
mount --verbose "$ROOT_PART" /mnt

# Create swap file (simpler than LVM for VPS)
# 1 MiB blocks: dd allocates its whole block size as a buffer, and bs=1G does
# not fit into the memory of a 1 GB VPS (there is no swap yet at this point).
echo -e "${BBlue}Creating swap file...${NC}"
dd if=/dev/zero of=/mnt/swapfile bs=1M count="$((SIZE_OF_SWAP * 1024))" status=progress
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

# The swap file is already active, so genfstab has written its entry. Add it
# only if that did not happen: a second /swapfile line makes
# systemd-fstab-generator fail ("Duplicate entry") on every boot.
if ! grep -Eq '^/swapfile[[:space:]]' /mnt/etc/fstab; then
    echo "/swapfile none swap defaults 0 0" >> /mnt/etc/fstab
fi

# Add security mount options
cat >> /mnt/etc/fstab <<EOF

# Security-hardened mount options
# /tmp: noexec omitted — npm, Node.js, and build tools execute from /tmp
# tmpfs sizes are capped at half of the RAM present at install time
tmpfs /tmp tmpfs rw,nosuid,nodev,relatime,size=${TMP_SIZE_MB}M 0 0
tmpfs /dev/shm tmpfs rw,nosuid,nodev,noexec,relatime,size=${SHM_TMPFS_SIZE_MB}M 0 0
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
        INSTALL_TMP_SIZE "${TMP_SIZE_MB}M" \
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
        _INSTALL_TMP_SIZE "${TMP_SIZE_MB}M" \
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
/tmp tmpfs ceiling: ${TMP_SIZE_MB} MiB
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
   Already enabled by the installer (check with 'systemctl is-enabled <unit>'):
     auditd, rkhunter-check.timer, arch-audit.timer
   AppArmor is installed but NOT active yet. Enabling apparmor.service alone
   does nothing: the kernel also needs its LSM parameters (apparmor=1 and
   apparmor in the lsm= list). From a checkout of the repository run
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

# Clear pacman cache. "pacman -Scc --noconfirm" answers the default N to
# "remove ALL files from cache?" and removes nothing, so answer explicitly.
arch-chroot /mnt bash -c "printf 'y\ny\n' | pacman -Scc" >/dev/null ||
    echo -e "${BYellow}Could not clear the pacman package cache; run 'pacman -Scc' after first boot.${NC}" >&2

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
