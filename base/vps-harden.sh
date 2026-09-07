#!/usr/bin/env bash

# =============================================================================
# Script:      vps-harden.sh
# Description: Filesystem hardening for a live, running Arch Linux VPS.
#              Creates hardened mount points (/tmp, /dev/shm, /proc, /var/tmp),
#              prepares storage for offline /var migration, hardens
#              existing fstab entries, and generates a rollback script.
#              Can optionally invoke vps-chroot.sh for software hardening.
#
#              Runs on the installed OS. Optional /var storage preparation
#              formats the selected destination, but data migration must be
#              completed offline from a rescue environment.
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
#
# Usage:       sudo ./vps-harden.sh [OPTIONS]
#              sudo ./vps-harden.sh --dry-run
#              sudo ./vps-harden.sh --skip-var --skip-sw
#              sudo ./vps-harden.sh -t 25 -v 20 -u myuser -p 2222
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# --- Colors ---
# shellcheck disable=SC2034  # Color palette — all available for use
readonly C_OK='\033[1;32m'
readonly C_INFO='\033[1;34m'
readonly C_WARN='\033[1;33m'
readonly C_ERR='\033[1;31m'
readonly C_NC='\033[0m'
readonly LARGE_DISK_THRESHOLD_BYTES=1000000000000
readonly DEFAULT_TMP_SIZE_GB=10
readonly LARGE_DISK_TMP_SIZE_GB=25
readonly SHM_SIZE_GB=2

msg()  { printf "%b[+]%b %s\n" "$C_OK"   "$C_NC" "$1"; }
info() { printf "%b[*]%b %s\n" "$C_INFO"  "$C_NC" "$1"; }
warn() { printf "%b[!]%b %s\n" "$C_WARN"  "$C_NC" "$1"; }
err()  { printf "%b[!]%b %s\n" "$C_ERR"   "$C_NC" "$1" >&2; exit 1; }

# --- Logging ---
LOGFILE="/var/log/vps-harden-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOGFILE") 2>&1

log_action() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOGFILE"
}

# --- Defaults ---
TMP_SIZE="$DEFAULT_TMP_SIZE_GB" # tmpfs /tmp ceiling in GB
TMP_SIZE_EXPLICIT=false
VAR_LOOP_SIZE=10            # /var loop image size in GB
USERNAME=""                 # interactive or -u flag
NEW_HOSTNAME=""             # interactive or -H flag
SSH_PORT=22
SKIP_VAR=false
SKIP_SW=false
DRY_RUN=false
SYSCTL_PROFILE="workstation"
SYSCTL_DISABLE_IPV6=false
ROLLBACK_SCRIPT="/root/undo-vps-harden.sh"
VAR_MIGRATION_GUIDE="/root/MIGRATE_VAR_OFFLINE.txt"
FSTAB_BACKUP=""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# State tracking
VAR_STRATEGY="skip"        # partition | volume | loop | skip
VAR_DEVICE=""
ROOT_DEVICE=""
PARENT_DISK=""

###############################################################################
# HELPER FUNCTIONS
###############################################################################

ask_yes_no() {
    local prompt_msg="$1"
    local choice
    while true; do
        read -r -p "$prompt_msg (y/n): " choice
        case "$choice" in
            [Yy]) return 0 ;;
            [Nn]) return 1 ;;
            *) warn "Invalid choice. Please type 'y' or 'n'." ;;
        esac
    done
}

# --- Usage ---
usage() {
    cat <<EOF
Usage: sudo $0 [OPTIONS]

Harden filesystem mount points on a live, running Arch Linux VPS.
Optional /var preparation formats selected storage; migration requires rescue downtime.

Options:
  -t SIZE     tmpfs size for /tmp in GB (minimum: 10; automatic default: 10,
              or 25 when the root disk is at least 1 TB)
  -v SIZE     /var loop image size in GB, if using loop device (default: $VAR_LOOP_SIZE)
  -u USER     Username for vps-chroot.sh (prompted if not given)
  -H HOST     Hostname to set (prompted if not given)
  -p PORT     SSH port for vps-chroot.sh (default: $SSH_PORT)
  --skip-var  Skip storage preparation for offline /var migration
  --skip-sw   Skip software hardening (only do filesystem mounts)
  --sysctl-profile PROFILE
              Select workstation, strict, or performance (default: workstation)
  --disable-ipv6
              Install the explicit IPv6-disable sysctl overlay
  --dry-run   Show planned changes without executing
  -h          Show this help

Examples:
  sudo $0                                # Full hardening (interactive prompts)
  sudo $0 --dry-run                      # Preview changes
  sudo $0 --skip-var --skip-sw           # Only tmpfs/shm/proc/var-tmp
  sudo $0 -u admin -H myvps -p 2222     # Non-interactive with all values
EOF
    exit 0
}

###############################################################################
# ARGUMENT PARSING
###############################################################################

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -t)
                [[ $# -ge 2 ]] || err "-t requires a size in GB"
                TMP_SIZE="$2"
                if ! [[ "$TMP_SIZE" =~ ^[0-9]+$ ]] || [[ "$TMP_SIZE" -lt "$DEFAULT_TMP_SIZE_GB" ]]; then
                    err "Invalid tmpfs size: $TMP_SIZE (minimum ${DEFAULT_TMP_SIZE_GB} GB)"
                fi
                TMP_SIZE_EXPLICIT=true
                shift 2
                ;;
            -v)
                VAR_LOOP_SIZE="$2"
                if ! [[ "$VAR_LOOP_SIZE" =~ ^[0-9]+$ ]] || [[ "$VAR_LOOP_SIZE" -lt 5 ]]; then
                    err "Invalid /var size: $VAR_LOOP_SIZE (minimum 5 GB)"
                fi
                shift 2
                ;;
            -u)
                USERNAME="$2"
                shift 2
                ;;
            -H)
                NEW_HOSTNAME="$2"
                shift 2
                ;;
            -p)
                SSH_PORT="$2"
                if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || [[ "$SSH_PORT" -lt 1 ]] || [[ "$SSH_PORT" -gt 65535 ]]; then
                    err "Invalid SSH port: $SSH_PORT"
                fi
                shift 2
                ;;
            --skip-var) SKIP_VAR=true; shift ;;
            --skip-sw)  SKIP_SW=true; shift ;;
            --sysctl-profile)
                [[ $# -ge 2 ]] || err "--sysctl-profile requires a value"
                SYSCTL_PROFILE="$2"
                case "$SYSCTL_PROFILE" in
                    workstation|strict|performance) ;;
                    *) err "Invalid sysctl profile: $SYSCTL_PROFILE" ;;
                esac
                shift 2
                ;;
            --disable-ipv6) SYSCTL_DISABLE_IPV6=true; shift ;;
            --dry-run)  DRY_RUN=true; shift ;;
            -h|--help)  usage ;;
            *)          err "Unknown option: $1 (see $0 -h)" ;;
        esac
    done
}

###############################################################################
# PREFLIGHT CHECKS
###############################################################################

preflight_checks() {
    info "Running preflight checks..."

    # Must be root
    if [[ $(id -u) -ne 0 ]]; then
        err "This script must be run as root"
    fi

    # Must be Arch Linux
    if [[ ! -f /etc/arch-release ]]; then
        err "This script is designed for Arch Linux only"
    fi

    # Must NOT be a live ISO (no real root filesystem)
    if findmnt -n -o FSTYPE / | grep -qE "^(squashfs|overlay|tmpfs)$"; then
        err "Detected live ISO environment. Use vps-install.sh instead"
    fi

    # Check required tools
    local required_tools=(mount umount findmnt lsblk rsync mkfs.ext4 losetup)
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            err "Required tool not found: $tool — install it first"
        fi
    done

    # Ensure SSH is running (safety — never lose remote access)
    if ! systemctl is-active --quiet sshd; then
        warn "sshd is not running! Starting it now for safety..."
        systemctl start sshd
    fi

    msg "Preflight checks passed"
}

###############################################################################
# DISK LAYOUT DETECTION
###############################################################################

detect_disk_layout() {
    info "Detecting disk layout..."

    # Find root device and parent disk
    ROOT_DEVICE=$(findmnt -n -o SOURCE /)
    info "Root device: $ROOT_DEVICE"

    # Resolve to parent disk (strip partition number)
    if [[ "$ROOT_DEVICE" =~ ^/dev/([a-z]+)[0-9]+$ ]]; then
        PARENT_DISK="/dev/${BASH_REMATCH[1]}"
    elif [[ "$ROOT_DEVICE" =~ ^/dev/(nvme[0-9]+n[0-9]+)p[0-9]+$ ]]; then
        PARENT_DISK="/dev/${BASH_REMATCH[1]}"
    elif [[ "$ROOT_DEVICE" =~ ^/dev/(vd[a-z]+)[0-9]+$ ]]; then
        PARENT_DISK="/dev/${BASH_REMATCH[1]}"
    else
        PARENT_DISK="$ROOT_DEVICE"
        warn "Could not determine parent disk from $ROOT_DEVICE"
    fi
    info "Parent disk: $PARENT_DISK"

    if [[ "$TMP_SIZE_EXPLICIT" == false ]]; then
        local disk_size_bytes
        disk_size_bytes=$(lsblk -b -d -n -o SIZE "$PARENT_DISK" 2>/dev/null || true)
        if [[ "$disk_size_bytes" =~ ^[0-9]+$ ]] &&
           ((disk_size_bytes >= LARGE_DISK_THRESHOLD_BYTES)); then
            TMP_SIZE="$LARGE_DISK_TMP_SIZE_GB"
        else
            TMP_SIZE="$DEFAULT_TMP_SIZE_GB"
        fi
        info "Automatic /tmp tmpfs ceiling: ${TMP_SIZE}G"
    fi

    # Show current layout
    echo
    lsblk -o NAME,SIZE,FSTYPE,MOUNTPOINTS,TYPE "$PARENT_DISK" 2>/dev/null || lsblk
    echo
}

###############################################################################
# DETECT EXISTING MOUNTS
###############################################################################

detect_existing_mounts() {
    info "Checking existing mount points..."

    local already_hardened=()

    if findmnt -n /tmp &>/dev/null; then
        local tmp_opts
        tmp_opts=$(findmnt -n -o OPTIONS /tmp)
        if echo "$tmp_opts" | grep -q "noexec"; then
            already_hardened+=("/tmp (already hardened)")
        else
            already_hardened+=("/tmp (mounted but not hardened)")
        fi
    fi

    if findmnt -n /var &>/dev/null && [[ "$(findmnt -n -o SOURCE /var)" != "$(findmnt -n -o SOURCE /)" ]]; then
        already_hardened+=("/var (already separate)")
        SKIP_VAR=true
    fi

    if [[ ${#already_hardened[@]} -gt 0 ]]; then
        info "Existing mounts detected:"
        for m in "${already_hardened[@]}"; do
            info "  - $m"
        done
    fi
}

###############################################################################
# SHOW PLAN
###############################################################################

show_plan() {
    echo
    echo -e "${C_INFO}============================================================${C_NC}"
    echo -e "${C_INFO} VPS Live Hardening Plan${C_NC}"
    echo -e "${C_INFO}============================================================${C_NC}"
    echo
    echo -e "${C_OK}Filesystem hardening:${C_NC}"
    echo "  1. /tmp      → tmpfs (${TMP_SIZE}G, noexec,nosuid,nodev)"
    echo "  2. /dev/shm  → remount with noexec,nosuid,nodev"
    echo "  3. /proc     → remount with hidepid=2,gid=proc"
    echo "  4. /var/tmp  → bind mount to /tmp (inherits hardened options)"

    if [[ "$SKIP_VAR" == false ]]; then
        echo
        echo -e "${C_OK}/var separation:${C_NC}"
        echo "  Prepare an empty destination (volume, partition, or loop image)"
        echo "  Copy and cutover must be performed offline from rescue media"
    else
        echo
        echo -e "${C_WARN}/var separation:${C_NC} SKIPPED"
    fi

    echo
    echo -e "${C_OK}fstab hardening:${C_NC}"
    echo "  Add nosuid,nodev to /home and other existing mounts"
    echo
    echo -e "${C_OK}Safety:${C_NC}"
    echo "  - fstab backed up before changes"
    echo "  - Rollback script generated at $ROLLBACK_SCRIPT"
    echo "  - mount -a --fake validation after every fstab change"
    echo "  - SSH stays up throughout the entire process"

    if [[ "$SKIP_SW" == false ]]; then
        echo
        echo -e "${C_OK}Software hardening:${C_NC}"
        echo "  Will run vps-chroot.sh (SSH, nftables, sysctl, PAM, etc.)"
        echo "  Username and hostname will be prompted before running"
        echo "  SSH port: $SSH_PORT"
        echo "  Sysctl profile: $SYSCTL_PROFILE"
        echo "  IPv6 disabled: $SYSCTL_DISABLE_IPV6"
    else
        echo
        echo -e "${C_WARN}Software hardening:${C_NC} SKIPPED"
    fi

    echo
    echo -e "${C_INFO}Log file:${C_NC} $LOGFILE"
    echo -e "${C_INFO}============================================================${C_NC}"
    echo
}

###############################################################################
# BACKUP & ROLLBACK
###############################################################################

create_backup() {
    info "Creating backups..."

    # Backup fstab
    FSTAB_BACKUP="/root/fstab.backup.$(date +%Y%m%d-%H%M%S)"
    cp /etc/fstab "$FSTAB_BACKUP"
    chmod 600 "$FSTAB_BACKUP"
    msg "fstab backed up to $FSTAB_BACKUP"

    # Snapshot current mount state
    findmnt --raw > "/root/mount-state.$(date +%Y%m%d-%H%M%S).txt"

    # Snapshot lsblk
    lsblk -o NAME,SIZE,FSTYPE,MOUNTPOINTS,TYPE > "/root/lsblk-state.$(date +%Y%m%d-%H%M%S).txt"

    log_action "Backups created: fstab, mount state, lsblk state"
}

create_rollback_script() {
    info "Generating rollback script at $ROLLBACK_SCRIPT..."

    cat > "$ROLLBACK_SCRIPT" <<'ROLLBACK_HEADER'
#!/usr/bin/env bash
# Auto-generated rollback script for vps-harden.sh
# Restores the system to pre-hardening state.
#
# Usage: sudo /root/undo-vps-harden.sh

set -euo pipefail

C_OK='\033[1;32m'
C_INFO='\033[1;34m'
C_WARN='\033[1;33m'
C_NC='\033[0m'

msg()  { printf "%b[+]%b %s\n" "$C_OK"   "$C_NC" "$1"; }
info() { printf "%b[*]%b %s\n" "$C_INFO"  "$C_NC" "$1"; }
warn() { printf "%b[!]%b %s\n" "$C_WARN"  "$C_NC" "$1"; }

if [[ $(id -u) -ne 0 ]]; then
    echo "Must be run as root" >&2
    exit 1
fi

# A migrated /var must be reconciled in rescue mode before restoring fstab.
# Never swap live directories or silently revert to an outdated /var.old.
if [[ -e /var.old ]]; then
    echo "Refusing live rollback: /var.old exists. Use rescue mode to reconcile /var data and fstab." >&2
    exit 1
fi

echo
echo -e "${C_WARN}This will undo VPS filesystem hardening.${C_NC}"
echo
read -r -p "Continue? (y/n): " choice
[[ "$choice" =~ ^[Yy]$ ]] || exit 0

ROLLBACK_HEADER

    # Add fstab restoration
    cat >> "$ROLLBACK_SCRIPT" <<EOF

# --- Restore original fstab ---
info "Restoring original fstab..."
if [[ -f "$FSTAB_BACKUP" ]]; then
    cp "$FSTAB_BACKUP" /etc/fstab
    msg "fstab restored from $FSTAB_BACKUP"
else
    warn "Backup fstab not found at $FSTAB_BACKUP — skipping"
fi
EOF

    # Unmount hardened mounts
    cat >> "$ROLLBACK_SCRIPT" <<'EOF'

# --- Unmount hardened mount points ---
info "Unmounting hardened mount points..."

# /var/tmp bind mount
if findmnt -n /var/tmp &>/dev/null; then
    umount /var/tmp && msg "Unmounted /var/tmp" || warn "Failed to unmount /var/tmp"
fi

# /tmp tmpfs
if findmnt -n -o FSTYPE /tmp 2>/dev/null | grep -q "tmpfs"; then
    umount /tmp && msg "Unmounted /tmp tmpfs" || warn "Failed to unmount /tmp (files may be in use)"
fi
EOF

    # Remove proc group if we created it
    cat >> "$ROLLBACK_SCRIPT" <<'EOF'

# --- Remove hidepid logind override ---
if [[ -f /etc/systemd/system/systemd-logind.service.d/hidepid.conf ]]; then
    rm -f /etc/systemd/system/systemd-logind.service.d/hidepid.conf
    rmdir /etc/systemd/system/systemd-logind.service.d 2>/dev/null || true
    systemctl daemon-reload
    msg "Removed hidepid logind override"
fi

# --- Remove loop module autoload ---
rm -f /etc/modules-load.d/loop.conf

echo
msg "Rollback complete. Reboot to fully restore original mount state."
echo
EOF

    chmod 700 "$ROLLBACK_SCRIPT"
    msg "Rollback script generated: $ROLLBACK_SCRIPT"
}

###############################################################################
# FSTAB VALIDATION (critical safety check)
###############################################################################

validate_fstab() {
    info "Validating fstab with mount -a --fake..."
    local fstab_err
    if fstab_err=$(mount -a --fake 2>&1); then
        msg "fstab validation passed"
        return 0
    else
        warn "fstab validation FAILED! Restoring backup..."
        warn "Error: $fstab_err"
        cp "$FSTAB_BACKUP" /etc/fstab
        err "fstab was restored from backup. Please investigate manually."
    fi
}

###############################################################################
# HARDEN /tmp (tmpfs)
###############################################################################

harden_tmp() {
    info "Hardening /tmp → tmpfs (${TMP_SIZE}G, noexec,nosuid,nodev)..."

    if [[ "$DRY_RUN" == true ]]; then
        info "[DRY-RUN] Would mount tmpfs on /tmp"
        info "[DRY-RUN] Would add fstab entry for /tmp"
        return 0
    fi

    # Remove any existing /tmp entry from fstab
    sed -i '\|^[^#].*[[:space:]]/tmp[[:space:]]|d' /etc/fstab

    # Add hardened entry
    echo "tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,relatime,size=${TMP_SIZE}G 0 0" >> /etc/fstab

    # Mount (preserve existing files by copying first)
    if findmnt -n /tmp &>/dev/null; then
        # Already mounted — remount with new options
        mount -o remount,nosuid,nodev,noexec,relatime,size="${TMP_SIZE}G" /tmp 2>/dev/null || {
            # If remount fails, do a fresh mount (preserve existing files)
            local tmp_backup
            tmp_backup=$(mktemp -d /root/tmp_backup.XXXXXX) || {
                warn "mktemp failed — mounting /tmp without preserving contents"
                mount -t tmpfs -o rw,nosuid,nodev,noexec,relatime,size="${TMP_SIZE}G" tmpfs /tmp
                return 0
            }
            cp -a /tmp/. "$tmp_backup/" 2>/dev/null || true
            mount -t tmpfs -o rw,nosuid,nodev,noexec,relatime,size="${TMP_SIZE}G" tmpfs /tmp
            cp -a "$tmp_backup/." /tmp/ 2>/dev/null || true
            rm -rf "$tmp_backup"
        }
    else
        mount -t tmpfs -o rw,nosuid,nodev,noexec,relatime,size="${TMP_SIZE}G" tmpfs /tmp
    fi

    validate_fstab
    msg "/tmp hardened (tmpfs, ${TMP_SIZE}G)"
    log_action "Hardened /tmp as tmpfs"
}

###############################################################################
# HARDEN /dev/shm
###############################################################################

harden_dev_shm() {
    info "Hardening /dev/shm → noexec,nosuid,nodev..."

    if [[ "$DRY_RUN" == true ]]; then
        info "[DRY-RUN] Would remount /dev/shm with noexec,nosuid,nodev"
        info "[DRY-RUN] Would add/update fstab entry for /dev/shm"
        return 0
    fi

    # Remove any existing /dev/shm entry from fstab
    sed -i '\|^[^#].*[[:space:]]/dev/shm[[:space:]]|d' /etc/fstab

    # Add hardened entry
    echo "tmpfs /dev/shm tmpfs rw,nosuid,nodev,noexec,relatime,size=${SHM_SIZE_GB}G 0 0" >> /etc/fstab

    # Remount with hardened options
    mount -o remount,nosuid,nodev,noexec /dev/shm 2>/dev/null || \
        warn "/dev/shm remount failed (will apply on next boot)"

    validate_fstab
    msg "/dev/shm hardened"
    log_action "Hardened /dev/shm"
}

###############################################################################
# HARDEN /proc
###############################################################################

harden_proc() {
    info "Hardening /proc → hidepid=2..."

    if [[ "$DRY_RUN" == true ]]; then
        info "[DRY-RUN] Would create proc group"
        info "[DRY-RUN] Would add fstab entry for /proc with hidepid=2"
        info "[DRY-RUN] Would create logind hidepid override"
        return 0
    fi

    # Create proc group if it doesn't exist
    if ! getent group proc &>/dev/null; then
        groupadd proc
        msg "Created 'proc' group"
    fi

    # Remove any existing /proc hardening entry from fstab (leave kernel's default)
    sed -i '\|^proc[[:space:]].*hidepid|d' /etc/fstab

    # Add hardened entry
    echo "proc /proc proc nosuid,nodev,noexec,hidepid=2,gid=proc 0 0" >> /etc/fstab

    # Setup systemd logind override so it can still see processes
    mkdir -p /etc/systemd/system/systemd-logind.service.d
    cat > /etc/systemd/system/systemd-logind.service.d/hidepid.conf <<EOF
[Service]
SupplementaryGroups=proc
EOF

    # Remount /proc with hidepid
    mount -o remount,hidepid=2,gid="$(getent group proc | cut -d: -f3)" /proc 2>/dev/null || \
        warn "/proc remount failed (will apply on next boot)"

    # Add current user to proc group if applicable
    if [[ -n "$USERNAME" ]] && id "$USERNAME" &>/dev/null; then
        usermod -aG proc "$USERNAME" 2>/dev/null || true
    fi

    systemctl daemon-reload

    validate_fstab
    msg "/proc hardened (hidepid=2)"
    log_action "Hardened /proc with hidepid=2"
}

###############################################################################
# HARDEN /var/tmp (bind mount to /tmp)
###############################################################################

harden_var_tmp() {
    info "Hardening /var/tmp → bind mount to /tmp..."

    if [[ "$DRY_RUN" == true ]]; then
        info "[DRY-RUN] Would bind mount /var/tmp to /tmp"
        info "[DRY-RUN] Would add fstab entry for /var/tmp"
        return 0
    fi

    # Remove any existing /var/tmp entry from fstab
    sed -i '\|^[^#].*[[:space:]]/var/tmp[[:space:]]|d' /etc/fstab

    # Add bind mount entry
    echo "/tmp /var/tmp none bind 0 0" >> /etc/fstab

    # Clear /var/tmp and bind mount
    if ! findmnt -n /var/tmp &>/dev/null; then
        # Move any existing files to /tmp
        if [[ -d /var/tmp ]] && [[ "$(ls -A /var/tmp 2>/dev/null)" ]]; then
            cp -a /var/tmp/. /tmp/ 2>/dev/null || true
        fi
        mount --bind /tmp /var/tmp
    fi

    validate_fstab
    msg "/var/tmp bind-mounted to /tmp"
    log_action "Bind-mounted /var/tmp to /tmp"
}

###############################################################################
# /var SEPARATION — STRATEGY DETECTION
###############################################################################

choose_var_strategy() {
    info "Detecting /var separation options..."

    # Check if /var is already separate
    if findmnt -n /var &>/dev/null && [[ "$(findmnt -n -o SOURCE /var)" != "$(findmnt -n -o SOURCE /)" ]]; then
        info "/var is already on a separate filesystem"
        VAR_STRATEGY="skip"
        return 0
    fi

    # Option 1: Check for extra attached volumes (e.g., /dev/vdb, /dev/sdb)
    local extra_disks
    extra_disks=$(lsblk -d -n -o NAME,TYPE | awk '$2=="disk" {print "/dev/"$1}' | while read -r disk; do
        # Skip the root disk
        [[ "$disk" == "$PARENT_DISK" ]] && continue
        # Check if disk has no partitions/filesystems in use
        if ! lsblk -n -o MOUNTPOINTS "$disk" 2>/dev/null | grep -q '[^[:space:]]'; then
            echo "$disk"
        fi
    done)

    if [[ -n "$extra_disks" ]]; then
        local first_disk
        first_disk=$(echo "$extra_disks" | head -1)
        local disk_size
        disk_size=$(lsblk -d -n -o SIZE "$first_disk" 2>/dev/null)
        echo
        info "Found unmounted disk: $first_disk ($disk_size)"
        if ask_yes_no "Erase $first_disk to prepare storage for offline /var migration?"; then
            VAR_STRATEGY="volume"
            VAR_DEVICE="$first_disk"
            return 0
        fi
    fi

    # Option 2: Check for free unpartitioned space on root disk
    local free_space_sectors
    free_space_sectors=$(sfdisk -F "$PARENT_DISK" 2>/dev/null | grep -oP '\d+ bytes' | head -1 | awk '{print $1}')
    local min_bytes=$((VAR_LOOP_SIZE * 1073741824))  # GB to bytes

    if [[ -n "${free_space_sectors:-}" ]] && [[ "$free_space_sectors" -gt "$min_bytes" ]]; then
        local free_gb=$((free_space_sectors / 1073741824))
        echo
        info "Found ${free_gb}G free space on $PARENT_DISK"
        if ask_yes_no "Create a new partition for /var?"; then
            VAR_STRATEGY="partition"
            return 0
        fi
    fi

    # Option 3: File-backed loop device
    # First check if loop devices are supported (blocked on OpenVZ/LXC containers)
    local loop_supported=false
    if losetup --find &>/dev/null && touch /root/.loop-test 2>/dev/null; then
        rm -f /root/.loop-test
        loop_supported=true
    else
        rm -f /root/.loop-test 2>/dev/null
    fi

    if [[ "$loop_supported" == true ]]; then
        local root_avail
        root_avail=$(df --output=avail / | tail -1 | tr -d ' ')  # in KB
        local loop_kb=$((VAR_LOOP_SIZE * 1048576))

        if [[ "$root_avail" -gt $((loop_kb + 2097152)) ]]; then  # Need loop size + 2GB headroom
            echo
            info "No free disk/partition available"
            info "Can create a ${VAR_LOOP_SIZE}G file-backed loop device (/root/var.img)"
            if ask_yes_no "Create loop device for /var? (${VAR_LOOP_SIZE}G from root filesystem)"; then
                VAR_STRATEGY="loop"
                return 0
            fi
        else
            warn "Insufficient disk space for loop device (need ${VAR_LOOP_SIZE}G + 2G headroom)"
        fi
    else
        warn "Loop devices not supported on this VPS (container-based virtualization)"
        warn "/var separation requires a dedicated disk or partition"
    fi

    # User declined all options
    VAR_STRATEGY="skip"
    info "/var separation skipped"
}

###############################################################################
# /var FILESYSTEM CREATION
###############################################################################

create_var_filesystem() {
    case "$VAR_STRATEGY" in
        volume)
            info "Formatting $VAR_DEVICE as ext4 for /var..."
            if [[ "$DRY_RUN" == true ]]; then
                info "[DRY-RUN] Would format $VAR_DEVICE and mount as /var"
                return 0
            fi
            mkfs.ext4 -F -m 1 -L var "$VAR_DEVICE"
            msg "Formatted $VAR_DEVICE as ext4"
            ;;

        partition)
            info "Creating new partition on $PARENT_DISK for /var..."
            if [[ "$DRY_RUN" == true ]]; then
                info "[DRY-RUN] Would create partition and format for /var"
                return 0
            fi
            # GPT numbers can contain gaps. Select an unused number explicitly,
            # then identify the created partition by a fresh GUID, never by count.
            local partition_table next_part=1 partition_guid actual_guid
            partition_table=$(LC_ALL=C sgdisk --print "$PARENT_DISK")
            while awk -v number="$next_part" '$1 == number { found = 1 } END { exit !found }' <<< "$partition_table"; do
                ((next_part += 1))
            done
            partition_guid=$(uuidgen)
            partition_guid=${partition_guid,,}
            [[ "$partition_guid" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] ||
                err "Could not generate a partition GUID"
            sgdisk -n "${next_part}:0:+${VAR_LOOP_SIZE}G" \
                -t "${next_part}:8300" -c "${next_part}:var" \
                -u "${next_part}:${partition_guid}" "$PARENT_DISK"
            partprobe "$PARENT_DISK"
            udevadm settle
            VAR_DEVICE="/dev/disk/by-partuuid/$partition_guid"
            [[ -b "$VAR_DEVICE" ]] || err "New partition has not appeared: $VAR_DEVICE"
            actual_guid=$(blkid -s PARTUUID -o value "$VAR_DEVICE")
            [[ "${actual_guid,,}" == "$partition_guid" ]] ||
                err "Partition GUID mismatch; refusing to format $VAR_DEVICE"
            mkfs.ext4 -F -m 1 -L var "$VAR_DEVICE"
            msg "Created and formatted $VAR_DEVICE"
            ;;

        loop)
            info "Creating ${VAR_LOOP_SIZE}G loop device at /root/var.img..."
            if [[ "$DRY_RUN" == true ]]; then
                info "[DRY-RUN] Would create /root/var.img and mount as /var"
                return 0
            fi
            # A previous preparation or offline migration may contain data.
            [[ ! -e /root/var.img ]] || err "Refusing to overwrite existing /root/var.img; inspect it in rescue mode"

            # Create image file — try fallocate, then dd (truncate often blocked on VPS)
            if fallocate -l "${VAR_LOOP_SIZE}G" /root/var.img 2>/dev/null; then
                msg "Image allocated with fallocate"
            elif dd if=/dev/zero of=/root/var.img bs=1M count=$((VAR_LOOP_SIZE * 1024)) status=progress 2>&1; then
                msg "Image created with dd"
            else
                rm -f /root/var.img 2>/dev/null || true
                err "Failed to create /root/var.img — filesystem may not support large file allocation"
            fi
            mkfs.ext4 -F -m 1 -L var /root/var.img
            VAR_DEVICE="/root/var.img"

            # The loop backing file must stay writable for the offline copy.
            # Reruns refuse to overwrite it; restrict direct access to root.
            chmod 0600 /root/var.img

            # Ensure loop module loads on boot
            echo "loop" > /etc/modules-load.d/loop.conf

            msg "Loop image created: /root/var.img (${VAR_LOOP_SIZE}G)"
            ;;

        skip)
            return 0
            ;;
    esac
}

###############################################################################
# OFFLINE /var MIGRATION INSTRUCTIONS
###############################################################################

prepare_var_migration() {
    [[ "$VAR_STRATEGY" != "skip" ]] || return 0
    if [[ "$DRY_RUN" == true ]]; then
        info "[DRY-RUN] Would write rescue instructions for offline /var migration"
        return 0
    fi

    # Never copy or switch a live /var. Unknown services, containers, timers and
    # open file descriptors make a fixed stop-list insufficient for consistency.
    local root_uuid var_uuid target mount_options="nosuid,nodev"
    root_uuid=$(blkid -s UUID -o value "$ROOT_DEVICE")
    var_uuid=$(blkid -s UUID -o value "$VAR_DEVICE")
    [[ "$root_uuid" =~ ^[0-9a-fA-F-]+$ && "$var_uuid" =~ ^[0-9a-fA-F-]+$ ]] ||
        err "Could not identify the source and destination filesystems"
    [[ "$root_uuid" != "$var_uuid" ]] || err "Source and destination must be different filesystems"
    target="/dev/disk/by-uuid/$var_uuid"
    if [[ "$VAR_STRATEGY" == "loop" ]]; then
        target="/mnt/awesome-root/root/var.img"
        mount_options="loop,nosuid,nodev"
    fi

    (umask 077; cat <<EOF
OFFLINE /var MIGRATION — destination prepared, live /var unchanged

Copy these notes externally. Schedule downtime, shut down the installed OS,
and boot a rescue ISO (or attach its disk to a rescue machine). Do not run
these commands on the installed system or inside a chroot. Ensure no other
machine, container or process is using either filesystem. Back up your data.

Root UUID: $root_uuid
Destination UUID: $var_uuid
Strategy: $VAR_STRATEGY

Run the following in a separate root Bash shell in the rescue environment.
Stop on any error; do not bypass the guards or the checksum comparison.

set -euo pipefail
[[ \$(id -u) -eq 0 ]]
[[ \$(findmnt -n -o UUID /) != '$root_uuid' ]]
[[ -z \$(findmnt -rn -S '/dev/disk/by-uuid/$root_uuid') ]]
[[ -z \$(findmnt -rn -S '/dev/disk/by-uuid/$var_uuid') ]]
[[ ! -e /mnt/awesome-root && ! -e /mnt/awesome-var ]]
mkdir /mnt/awesome-root /mnt/awesome-var
mount '/dev/disk/by-uuid/$root_uuid' /mnt/awesome-root
mount -o '$mount_options' '$target' /mnt/awesome-var
[[ \$(findmnt -n -o UUID /mnt/awesome-var) == '$var_uuid' ]]
[[ ! -e /mnt/awesome-root/var.old ]]
[[ ! -e /mnt/awesome-root/etc/fstab.before-var-migration ]]
# This procedure supports /var currently residing on the root filesystem.
awk '\$1 !~ /^#/ && \$2 == "/var" { found=1 } END { exit found }' /mnt/awesome-root/etc/fstab
# The destination must still be empty except for ext4's lost+found directory.
[[ -z \$(find /mnt/awesome-var -mindepth 1 -maxdepth 1 ! -name lost+found -print -quit) ]]
rsync -aHAXx --numeric-ids --delete /mnt/awesome-root/var/ /mnt/awesome-var/
changes=\$(rsync -aHAXxnc --numeric-ids --delete --itemize-changes /mnt/awesome-root/var/ /mnt/awesome-var/)
[[ -z \$changes ]]
cp -a /mnt/awesome-root/etc/fstab /mnt/awesome-root/etc/fstab.before-var-migration
EOF
    if [[ "$VAR_STRATEGY" == "loop" ]]; then
        echo "echo '/root/var.img /var ext4 loop,nosuid,nodev 0 2' >> /mnt/awesome-root/etc/fstab"
    else
        echo "echo 'UUID=$var_uuid /var ext4 nosuid,nodev 0 2' >> /mnt/awesome-root/etc/fstab"
    fi
    cat <<'EOF'
mv /mnt/awesome-root/var /mnt/awesome-root/var.old
mkdir -m 0755 /mnt/awesome-root/var
sync
umount /mnt/awesome-var
umount /mnt/awesome-root
rmdir /mnt/awesome-var /mnt/awesome-root

Boot the installed OS and verify /var mounts correctly and applications work.
Keep /var.old and fstab.before-var-migration until the migration is verified.
Rollback must also be offline. /var.old becomes stale once applications write
to the new /var: preserve and reconcile newer data before reverting fstab or
restoring the old directory. The live hardening rollback will refuse this case.
EOF
    ) > "$VAR_MIGRATION_GUIDE"
    chmod 0600 "$VAR_MIGRATION_GUIDE"
    msg "Prepared /var destination; offline migration instructions: $VAR_MIGRATION_GUIDE"
    warn "Live /var has not been copied or switched. Rescue downtime is required."
    log_action "Prepared offline /var migration (strategy: $VAR_STRATEGY)"
}

###############################################################################
# HARDEN EXISTING FSTAB ENTRIES
###############################################################################

harden_fstab_options() {
    info "Hardening existing fstab entries..."

    if [[ "$DRY_RUN" == true ]]; then
        info "[DRY-RUN] Would add nosuid,nodev to /home and other mounts"
        return 0
    fi

    # Add nosuid,nodev to /home if it's a separate mount
    if findmnt -n /home &>/dev/null && [[ "$(findmnt -n -o SOURCE /home)" != "$(findmnt -n -o SOURCE /)" ]]; then
        local home_opts
        home_opts=$(findmnt -n -o OPTIONS /home)
        if ! echo "$home_opts" | grep -q "nosuid"; then
            info "Adding nosuid,nodev to /home fstab entry"
            sed -i '/[[:space:]]\/home[[:space:]]/ s/defaults/defaults,nosuid,nodev/' /etc/fstab
            mount -o remount,nosuid,nodev /home 2>/dev/null || true
        fi
    fi

    validate_fstab
    msg "fstab entries hardened"
    log_action "Hardened fstab options"
}

###############################################################################
# SOFTWARE HARDENING (vps-chroot.sh integration)
###############################################################################

prompt_user_config() {
    echo
    echo -e "${C_INFO}User configuration for software hardening:${C_NC}"
    echo

    # Prompt for username if not provided via -u
    if [[ -z "$USERNAME" ]]; then
        local default_user
        default_user=$(find /home -maxdepth 1 -mindepth 1 -type d -printf '%f\n' 2>/dev/null | head -1)

        while true; do
            if [[ -n "$default_user" ]]; then
                read -r -p "Username [${default_user}]: " USERNAME
                USERNAME="${USERNAME:-$default_user}"
            else
                read -r -p "Username: " USERNAME
            fi
            if [[ "$USERNAME" =~ ^[a-z_][a-z0-9_-]*$ ]] && [[ ${#USERNAME} -le 32 ]]; then
                break
            else
                warn "Invalid username. Must begin with [a-z_], contain only [a-z0-9_-], max 32 chars."
            fi
        done
    fi

    # Prompt for hostname if not provided via -H
    if [[ -z "$NEW_HOSTNAME" ]]; then
        local current_host
        current_host=$(cat /etc/hostname 2>/dev/null || echo "archlinux")

        while true; do
            read -r -p "Hostname [${current_host}]: " NEW_HOSTNAME
            NEW_HOSTNAME="${NEW_HOSTNAME:-$current_host}"
            if [[ "$NEW_HOSTNAME" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*$ ]] && [[ ${#NEW_HOSTNAME} -le 64 ]]; then
                break
            else
                warn "Invalid hostname. Must begin with alphanumeric, contain only [a-zA-Z0-9.-], max 64 chars."
            fi
        done
    fi

    # Prompt for SSH public key
    echo -e "\n${C_WARN}Password authentication will be disabled after hardening.${C_NC}"
    echo -e "${C_WARN}Paste your SSH public key (from ~/.ssh/id_ed25519.pub on your local machine):${C_NC}"
    read -r SSH_PUBKEY
    if [[ -z "$SSH_PUBKEY" ]]; then
        warn "No SSH public key provided — add one manually before disconnecting."
    fi

    echo
    info "Username:  $USERNAME"
    info "Hostname:  $NEW_HOSTNAME"
    info "SSH port:  $SSH_PORT"
    info "SSH key:   ${SSH_PUBKEY:+(provided)}${SSH_PUBKEY:-(none)}"
    echo
}

create_install_env() {
    info "Creating install environment for vps-chroot.sh..."

    if [[ "$DRY_RUN" == true ]]; then
        info "[DRY-RUN] Would create /root/.install-env"
        return 0
    fi

    cat > /root/.install-env <<EOF
export INSTALL_DISK="$PARENT_DISK"
export INSTALL_USER="$USERNAME"
export INSTALL_HOST="$NEW_HOSTNAME"
export INSTALL_DATE="$(date)"
export INSTALL_TYPE="vps-harden"
export INSTALL_SSH_PORT="$SSH_PORT"
export INSTALL_SSH_PUBKEY="$SSH_PUBKEY"
export INSTALL_SYSCTL_PROFILE="$SYSCTL_PROFILE"
export INSTALL_DISABLE_IPV6="$SYSCTL_DISABLE_IPV6"
EOF
    chmod 600 /root/.install-env
    msg "Created /root/.install-env (INSTALL_TYPE=vps-harden)"
}

run_software_hardening() {
    info "Running software hardening via vps-chroot.sh..."

    if [[ "$DRY_RUN" == true ]]; then
        info "[DRY-RUN] Would download and run vps-chroot.sh"
        return 0
    fi

    local chroot_script=""

    # Try local copy first
    if [[ -f "$SCRIPT_DIR/vps-chroot.sh" ]]; then
        chroot_script="$SCRIPT_DIR/vps-chroot.sh"
        info "Using local vps-chroot.sh from $SCRIPT_DIR"
    else
        # Download from repository
        # Note: curl -f (--fail) ensures a non-zero exit on HTTP errors (4xx/5xx)
        info "Downloading vps-chroot.sh from repository..."
        chroot_script="/tmp/vps-chroot.sh"
        curl -fsSL \
            "https://raw.githubusercontent.com/schm1d/AwesomeArchLinux/main/base/vps-chroot.sh" \
            -o "$chroot_script" || err "Failed to download vps-chroot.sh"

        # Basic integrity checks on the downloaded script
        warn "vps-chroot.sh was downloaded from a remote source — review before trusting"
        if ! head -1 "$chroot_script" | grep -qE '^#!.*bash'; then
            err "Downloaded vps-chroot.sh does not start with a valid bash shebang"
        fi
        if ! grep -q '_INSTALL_USER' "$chroot_script"; then
            err "Downloaded vps-chroot.sh is missing expected markers (_INSTALL_USER) — file may be corrupt"
        fi
        info "Integrity checks passed (shebang and expected markers present)"
    fi

    chmod +x "$chroot_script"

    # Stage the complete sysctl bundle. vps-chroot.sh applies it immediately on
    # this live system, unlike the install-from-ISO paths which use --no-apply.
    local sysctl_stage="/sysctl-profile"
    local -a sysctl_files=(
        sysctl.sh
        60-awesome-security-core.conf
        70-awesome-workstation-network.conf
        80-awesome-performance.conf
        80-awesome-bbr.modules
        90-awesome-strict.conf
        90-awesome-ipv6-disabled.conf
    )
    local sysctl_file
    install -d -m 0755 "$sysctl_stage"
    for sysctl_file in "${sysctl_files[@]}"; do
        if [[ -f "$SCRIPT_DIR/../hardening/sysctl/$sysctl_file" ]]; then
            install -m 0644 \
                "$SCRIPT_DIR/../hardening/sysctl/$sysctl_file" \
                "$sysctl_stage/$sysctl_file"
        else
            curl -fsSL \
                "https://raw.githubusercontent.com/schm1d/AwesomeArchLinux/main/hardening/sysctl/$sysctl_file" \
                -o "$sysctl_stage/$sysctl_file" || err "Could not fetch sysctl bundle file: $sysctl_file"
            chmod 0644 "$sysctl_stage/$sysctl_file"
        fi
    done
    chmod 0755 "$sysctl_stage/sysctl.sh"

    if [[ -f "$SCRIPT_DIR/../hardening/ssh/ssh.sh" ]]; then
        cp "$SCRIPT_DIR/../hardening/ssh/ssh.sh" /ssh.sh
    else
        curl -fsSL \
            "https://raw.githubusercontent.com/schm1d/AwesomeArchLinux/main/hardening/ssh/ssh.sh" \
            -o /ssh.sh || warn "Could not fetch ssh.sh"
    fi
    [[ -f /ssh.sh ]] && chmod +x /ssh.sh

    # Set up environment variables and run
    export _INSTALL_DISK="$PARENT_DISK"
    export _INSTALL_USER="$USERNAME"
    export _INSTALL_HOST="$NEW_HOSTNAME"
    export _INSTALL_SSH_PORT="$SSH_PORT"
    export _INSTALL_SSH_PUBKEY="$SSH_PUBKEY"
    export _INSTALL_SYSCTL_PROFILE="$SYSCTL_PROFILE"
    export _INSTALL_DISABLE_IPV6="$SYSCTL_DISABLE_IPV6"
    export _INSTALL_TYPE="vps-harden"

    info "Executing vps-chroot.sh (this will take several minutes)..."
    bash "$chroot_script"

    # Cleanup
    [[ "$chroot_script" == /tmp/* ]] && shred -zu "$chroot_script" 2>/dev/null || true
    shred -zu /sysctl.sh 2>/dev/null || true
    shred -zu /ssh.sh 2>/dev/null || true
    rm -rf -- /sysctl-profile

    msg "Software hardening complete"
    log_action "Software hardening via vps-chroot.sh completed"
}

###############################################################################
# SUMMARY
###############################################################################

show_summary() {
    echo
    echo -e "${C_OK}============================================================${C_NC}"
    echo -e "${C_OK} VPS Hardening Complete!${C_NC}"
    echo -e "${C_OK}============================================================${C_NC}"
    echo
    echo -e "${C_INFO}Mount point status:${C_NC}"

    local mark
    for mp in /tmp /dev/shm /proc /var/tmp; do
        if findmnt -n "$mp" &>/dev/null; then
            local opts
            opts=$(findmnt -n -o OPTIONS "$mp" | head -1)
            mark="${C_OK}[OK]${C_NC}"
            echo -e "  $mark $mp  ($opts)"
        else
            mark="${C_WARN}[--]${C_NC}"
            echo -e "  $mark $mp  (not mounted — will apply on reboot)"
        fi
    done

    if [[ "$VAR_STRATEGY" != "skip" ]]; then
        echo "  /var destination prepared; migration requires rescue downtime"
        echo "  Instructions: $VAR_MIGRATION_GUIDE"
    fi

    echo
    echo -e "${C_INFO}Files created:${C_NC}"
    echo "  Rollback script:  $ROLLBACK_SCRIPT"
    echo "  fstab backup:     $FSTAB_BACKUP"
    echo "  Log file:         $LOGFILE"
    [[ "$VAR_STRATEGY" == "loop" ]] && echo "  Loop image:       /root/var.img"

    echo
    echo -e "${C_INFO}Checklist:${C_NC}"
    echo "  [ ] Verify SSH access in a NEW terminal before closing this one"
    echo "  [ ] Review fstab: cat /etc/fstab"
    echo "  [ ] Check mounts: findmnt --real"
    [[ "$VAR_STRATEGY" != "skip" ]] && \
        echo "  [ ] Copy $VAR_MIGRATION_GUIDE externally and schedule offline /var migration"
    echo "  [ ] Run security audit: sudo lynis audit system"

    echo
    echo -e "${C_WARN}Rollback:${C_NC} sudo $ROLLBACK_SCRIPT"
    echo
    echo -e "${C_OK}Done.${C_NC}"
}

###############################################################################
# MAIN
###############################################################################

main() {
    echo
    echo -e "${C_INFO}============================================================${C_NC}"
    echo -e "${C_INFO} VPS Live Hardening Script${C_NC}"
    echo -e "${C_INFO} Arch Linux — filesystem & mount point hardening${C_NC}"
    echo -e "${C_INFO}============================================================${C_NC}"
    echo

    parse_args "$@"
    preflight_checks
    detect_disk_layout
    detect_existing_mounts
    show_plan

    # Confirm or exit
    if [[ "$DRY_RUN" == true ]]; then
        info "Dry run complete — no changes were made."
        exit 0
    fi

    if ! ask_yes_no "Proceed with hardening?"; then
        info "Aborted by user."
        exit 0
    fi

    create_backup
    create_rollback_script

    # Filesystem hardening
    harden_tmp
    harden_dev_shm
    harden_proc
    harden_var_tmp

    # /var separation
    if [[ "$SKIP_VAR" == false ]]; then
        choose_var_strategy
        create_var_filesystem
        prepare_var_migration
    fi

    # Harden existing fstab entries
    harden_fstab_options

    # Software hardening
    if [[ "$SKIP_SW" == false ]]; then
        prompt_user_config
        create_install_env
        run_software_hardening
    fi

    show_summary
}

main "$@"
