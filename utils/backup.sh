#!/usr/bin/env bash

# =============================================================================
# Script:      backup.sh
# Description: Encrypted backup system for Arch Linux using BorgBackup with:
#                - Authenticated encryption (repokey-blake2)
#                - Configurable retention policies
#                - systemd timer for daily automated backups
#                - Logrotate integration
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
#
# Usage:       sudo ./backup.sh [-r REPO_PATH] [-p PASSPHRASE_FILE]
#                                [-k KEEP_DAILY] [-K KEEP_WEEKLY]
#                                [-M KEEP_MONTHLY] [--init] [--backup]
#                                [--prune] [--list] [--restore ARCHIVE] [-h]
#
# Requirements:
#   - Arch Linux with pacman
#   - Root privileges
#
# What this script does:
#   1. Installs BorgBackup
#   2. Initializes an encrypted borg repository
#   3. Creates compressed, deduplicated backups of system directories
#   4. Prunes old archives with configurable retention
#   5. Lists and restores archives
#   6. Sets up a systemd timer for daily automated backups
#   7. Configures logrotate for backup logs
# =============================================================================

set -euo pipefail

# --- Colors ---
readonly C_BLUE='\033[1;34m'
readonly C_RED='\033[1;31m'
readonly C_GREEN='\033[1;32m'
readonly C_YELLOW='\033[1;33m'
readonly C_NC='\033[0m'

msg()  { printf "%b[+]%b %s\n" "$C_GREEN" "$C_NC" "$1"; }
info() { printf "%b[*]%b %s\n" "$C_BLUE"  "$C_NC" "$1"; }
warn() { printf "%b[!]%b %s\n" "$C_YELLOW" "$C_NC" "$1"; }
err()  { printf "%b[!]%b %s\n" "$C_RED"   "$C_NC" "$1" >&2; exit 1; }

# --- Defaults ---
REPO="/var/backups/borg"
PASSPHRASE_FILE="/root/.borg-passphrase"
KEEP_DAILY=7
KEEP_WEEKLY=4
KEEP_MONTHLY=6
DO_INIT=false
DO_BACKUP=false
DO_PRUNE=false
DO_LIST=false
DO_RESTORE=false
RESTORE_ARCHIVE=""
LOGFILE="/var/log/borg-backup.log"
SCRIPT_PATH="$(readlink -f "$0")"

# --- Usage ---
usage() {
    cat <<EOF
Usage: sudo $0 [options]

Options:
  -r REPO_PATH        Borg repository path (default: $REPO)
  -p PASSPHRASE_FILE  Path to passphrase file (default: $PASSPHRASE_FILE)
  -k KEEP_DAILY       Daily archives to keep (default: $KEEP_DAILY)
  -K KEEP_WEEKLY      Weekly archives to keep (default: $KEEP_WEEKLY)
  -M KEEP_MONTHLY     Monthly archives to keep (default: $KEEP_MONTHLY)

Modes (at least one required):
  --init              Initialize a new borg repository
  --backup            Create a new backup archive
  --prune             Prune old archives per retention policy
  --list              List all archives in the repository
  --restore ARCHIVE   Restore a specific archive to /tmp/borg-restore/

Other:
  -h, --help          Show this help

Examples:
  sudo $0 --init
  sudo $0 --backup --prune
  sudo $0 --list
  sudo $0 --restore myhost-2026-02-24_02:00
  sudo $0 -r /mnt/external/borg --init --backup
EOF
    exit 0
}

# --- Parse Arguments ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        -r)          REPO="$2"; shift 2 ;;
        -p)          PASSPHRASE_FILE="$2"; shift 2 ;;
        -k)          KEEP_DAILY="$2"; shift 2 ;;
        -K)          KEEP_WEEKLY="$2"; shift 2 ;;
        -M)          KEEP_MONTHLY="$2"; shift 2 ;;
        --init)      DO_INIT=true; shift ;;
        --backup)    DO_BACKUP=true; shift ;;
        --prune)     DO_PRUNE=true; shift ;;
        --list)      DO_LIST=true; shift ;;
        --restore)   DO_RESTORE=true; RESTORE_ARCHIVE="$2"; shift 2 ;;
        -h|--help)   usage ;;
        *)           err "Unknown option: $1" ;;
    esac
done

# --- Validate ---
[[ $(id -u) -eq 0 ]] || err "Must be run as root"

if [[ "$DO_INIT" == false && "$DO_BACKUP" == false && "$DO_PRUNE" == false \
   && "$DO_LIST" == false && "$DO_RESTORE" == false ]]; then
    err "No mode selected. Use --init, --backup, --prune, --list, or --restore ARCHIVE. See -h for help."
fi

# Redirect output to logfile as well
exec > >(tee -a "$LOGFILE") 2>&1

info "Repository: $REPO"
info "Passphrase file: $PASSPHRASE_FILE"
info "Log: $LOGFILE"

# =============================================================================
# 1. INSTALL BORGBACKUP
# =============================================================================

msg "Ensuring BorgBackup is installed..."
pacman -Syu --noconfirm --needed borg

BORG_VER=$(borg --version)
info "BorgBackup version: $BORG_VER"

# =============================================================================
# HELPER: Load passphrase from file
# =============================================================================

load_passphrase() {
    if [[ ! -f "$PASSPHRASE_FILE" ]]; then
        err "Passphrase file not found: $PASSPHRASE_FILE. Run --init first or specify -p."
    fi
    export BORG_PASSPHRASE
    BORG_PASSPHRASE="$(cat "$PASSPHRASE_FILE")"
}

# =============================================================================
# 2. INIT MODE
# =============================================================================

if [[ "$DO_INIT" == true ]]; then
    msg "Initializing borg repository..."

    # Generate passphrase if file does not exist
    if [[ ! -f "$PASSPHRASE_FILE" ]]; then
        info "Generating random passphrase..."
        head -c 32 /dev/urandom | base64 -w 0 > "$PASSPHRASE_FILE"
        chmod 600 "$PASSPHRASE_FILE"
        chown root:root "$PASSPHRASE_FILE"
        msg "Passphrase saved to $PASSPHRASE_FILE (mode 600)"
    else
        info "Using existing passphrase file: $PASSPHRASE_FILE"
    fi

    export BORG_PASSPHRASE
    BORG_PASSPHRASE="$(cat "$PASSPHRASE_FILE")"

    # Create repository directory
    mkdir -p "$(dirname "$REPO")"

    if [[ -d "$REPO" && -f "$REPO/config" ]]; then
        warn "Repository already exists at $REPO — skipping init"
    else
        borg init --encryption=repokey-blake2 "$REPO"
        msg "Repository initialized at $REPO (encryption: repokey-blake2)"
    fi

    # Export repository key for disaster recovery
    KEY_BACKUP="/root/.borg-key-backup"
    borg key export "$REPO" "$KEY_BACKUP"
    chmod 600 "$KEY_BACKUP"
    chown root:root "$KEY_BACKUP"
    msg "Repository key exported to $KEY_BACKUP"

    echo
    echo -e "${C_YELLOW}========================================================================${C_NC}"
    echo -e "${C_YELLOW} WARNING: Store these files EXTERNALLY for disaster recovery!${C_NC}"
    echo -e "${C_YELLOW}========================================================================${C_NC}"
    echo
    echo -e "${C_YELLOW}  1. Passphrase file:  $PASSPHRASE_FILE${C_NC}"
    echo -e "${C_YELLOW}  2. Key backup file:  $KEY_BACKUP${C_NC}"
    echo
    echo -e "${C_YELLOW}  Without BOTH files, you CANNOT decrypt your backups.${C_NC}"
    echo -e "${C_YELLOW}  Copy them to a USB drive, password manager, or other${C_NC}"
    echo -e "${C_YELLOW}  secure offline storage NOW.${C_NC}"
    echo
fi

# =============================================================================
# 3. BACKUP MODE
# =============================================================================

if [[ "$DO_BACKUP" == true ]]; then
    msg "Creating backup archive..."

    load_passphrase

    ARCHIVE_NAME="$(hostname)-$(date +%Y-%m-%d_%H:%M)"
    info "Archive name: $ARCHIVE_NAME"

    borg create                                         \
        --verbose                                       \
        --filter AME                                    \
        --list                                          \
        --stats                                         \
        --show-rc                                       \
        --compression zstd,6                            \
        --one-file-system                               \
        --exclude-caches                                \
        --exclude-if-present .nobackup                  \
        --exclude '/var/lib/pacman/sync'                \
        --exclude '/var/cache'                          \
        --exclude '/var/tmp'                            \
        --exclude '**/.cache'                           \
        --exclude '**/node_modules'                     \
        --exclude '**/__pycache__'                      \
        --exclude '**/.local/share/Trash'               \
        --exclude '**/lost+found'                       \
        "${REPO}::${ARCHIVE_NAME}"                      \
        /etc                                            \
        /home                                           \
        /root                                           \
        /var/lib                                        \
        /var/log                                        \
        /var/spool/cron                                 \
        /opt

    msg "Backup archive created: $ARCHIVE_NAME"
fi

# =============================================================================
# 4. PRUNE MODE
# =============================================================================

if [[ "$DO_PRUNE" == true ]]; then
    msg "Pruning old archives..."

    load_passphrase

    info "Retention policy: daily=$KEEP_DAILY, weekly=$KEEP_WEEKLY, monthly=$KEEP_MONTHLY"

    borg prune                                          \
        --list                                          \
        --stats                                         \
        --show-rc                                       \
        --glob-archives "$(hostname)-*"                 \
        --keep-daily    "$KEEP_DAILY"                   \
        --keep-weekly   "$KEEP_WEEKLY"                  \
        --keep-monthly  "$KEEP_MONTHLY"                 \
        "$REPO"

    msg "Compacting repository..."
    borg compact "$REPO"

    msg "Prune and compact complete"
fi

# =============================================================================
# 5. LIST MODE
# =============================================================================

if [[ "$DO_LIST" == true ]]; then
    msg "Listing archives in $REPO..."

    load_passphrase

    borg list --format '{archive:<40} {time} {size:>12}{NL}' "$REPO"
fi

# =============================================================================
# 6. RESTORE MODE
# =============================================================================

if [[ "$DO_RESTORE" == true ]]; then
    if [[ -z "$RESTORE_ARCHIVE" ]]; then
        err "No archive name specified. Usage: --restore ARCHIVE_NAME"
    fi

    msg "Restoring archive: $RESTORE_ARCHIVE"

    load_passphrase

    RESTORE_DIR="/tmp/borg-restore/${RESTORE_ARCHIVE}"
    mkdir -p "$RESTORE_DIR"

    info "Extracting to $RESTORE_DIR..."

    cd "$RESTORE_DIR"
    borg extract --list "${REPO}::${RESTORE_ARCHIVE}"

    echo
    echo -e "${C_GREEN}========================================================================${C_NC}"
    echo -e "${C_GREEN} Archive extracted successfully${C_NC}"
    echo -e "${C_GREEN}========================================================================${C_NC}"
    echo
    echo -e "${C_BLUE}Restored to:${C_NC}  $RESTORE_DIR"
    echo
    echo -e "${C_BLUE}To restore specific files, copy them from the extract directory:${C_NC}"
    echo "  cp -a ${RESTORE_DIR}/etc/nginx/nginx.conf /etc/nginx/nginx.conf"
    echo
    echo -e "${C_BLUE}To restore everything (CAUTION — will overwrite current system files):${C_NC}"
    echo "  cp -a ${RESTORE_DIR}/* /"
    echo
    echo -e "${C_YELLOW}Review extracted files before overwriting system files!${C_NC}"
    echo
fi

# =============================================================================
# 7. SYSTEMD TIMER FOR DAILY BACKUPS
# =============================================================================

msg "Setting up systemd timer for daily backups..."

cat > /etc/systemd/system/borg-backup.service <<EOF
[Unit]
Description=BorgBackup — create archive and prune old backups
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${SCRIPT_PATH} -r ${REPO} -p ${PASSPHRASE_FILE} -k ${KEEP_DAILY} -K ${KEEP_WEEKLY} -M ${KEEP_MONTHLY} --backup --prune
Nice=19
IOSchedulingClass=idle
PrivateTmp=false

# Logging
StandardOutput=append:${LOGFILE}
StandardError=append:${LOGFILE}
EOF

cat > /etc/systemd/system/borg-backup.timer <<EOF
[Unit]
Description=Daily BorgBackup at 2:00 AM

[Timer]
OnCalendar=*-*-* 02:00:00
RandomizedDelaySec=1800
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable borg-backup.timer
systemctl start borg-backup.timer

msg "systemd timer enabled: borg-backup.timer (daily at 02:00, +30min jitter)"

# =============================================================================
# 8. LOGROTATE CONFIG
# =============================================================================

msg "Setting up logrotate for borg backup logs..."

cat > /etc/logrotate.d/borg-backup <<EOF
/var/log/borg-backup.log {
    weekly
    rotate 8
    compress
    delaycompress
    missingok
    notifempty
    create 640 root root
}
EOF

msg "Logrotate configured for $LOGFILE"

# =============================================================================
# 9. SUMMARY
# =============================================================================

echo
echo -e "${C_GREEN}========================================================================${C_NC}"
echo -e "${C_GREEN} BorgBackup setup complete!${C_NC}"
echo -e "${C_GREEN}========================================================================${C_NC}"
echo
echo -e "${C_BLUE}Repository:${C_NC}        $REPO"
echo -e "${C_BLUE}Passphrase file:${C_NC}   $PASSPHRASE_FILE"
echo -e "${C_BLUE}Encryption:${C_NC}        repokey-blake2"
echo -e "${C_BLUE}Compression:${C_NC}       zstd level 6"
echo -e "${C_BLUE}Log file:${C_NC}          $LOGFILE"
echo
echo -e "${C_BLUE}Backup includes:${C_NC}"
echo "  /etc  /home  /root  /var/lib  /var/log  /var/spool/cron  /opt"
echo
echo -e "${C_BLUE}Backup excludes:${C_NC}"
echo "  /var/lib/pacman/sync  /var/cache  /var/tmp  .cache"
echo "  node_modules  __pycache__  Trash  lost+found"
echo
echo -e "${C_BLUE}Retention policy:${C_NC}"
echo "  Daily:   $KEEP_DAILY"
echo "  Weekly:  $KEEP_WEEKLY"
echo "  Monthly: $KEEP_MONTHLY"
echo
echo -e "${C_BLUE}Schedule:${C_NC}          Daily at 02:00 AM (+30min random delay)"
echo "  Check timer:     systemctl list-timers borg-backup.timer"
echo "  Manual backup:   sudo $0 --backup --prune"
echo "  List archives:   sudo $0 --list"
echo
echo -e "${C_YELLOW}IMPORTANT: Store your key and passphrase externally!${C_NC}"
echo -e "${C_YELLOW}  Passphrase:  $PASSPHRASE_FILE${C_NC}"
echo -e "${C_YELLOW}  Key backup:  /root/.borg-key-backup${C_NC}"
echo
echo -e "${C_GREEN}Done.${C_NC}"
