#!/usr/bin/env bash

# =============================================================================
# Script:      backup.sh
# Description: Encrypted backup system for Arch Linux using BorgBackup with
#              repokey-blake2 encryption, configurable retention, systemd timer,
#              and logrotate integration.
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
#
# Usage:       sudo ./backup.sh [-r REPO_PATH] [-p PASSPHRASE_FILE]
#                                [-k KEEP_DAILY] [-K KEEP_WEEKLY]
#                                [-M KEEP_MONTHLY] [--init] [--backup]
#                                [--prune] [--list] [--restore ARCHIVE] [-h]
# =============================================================================

set -euo pipefail

umask 077

readonly C_BLUE='\033[1;34m'
readonly C_RED='\033[1;31m'
readonly C_GREEN='\033[1;32m'
readonly C_YELLOW='\033[1;33m'
readonly C_NC='\033[0m'

msg()  { printf "%b[+]%b %s\n" "$C_GREEN" "$C_NC" "$1"; }
info() { printf "%b[*]%b %s\n" "$C_BLUE"  "$C_NC" "$1"; }
warn() { printf "%b[!]%b %s\n" "$C_YELLOW" "$C_NC" "$1"; }
err()  { printf "%b[!]%b %s\n" "$C_RED"   "$C_NC" "$1" >&2; exit 1; }

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
RESTORE_TARGET=""
LOGFILE="/var/log/borg-backup.log"
SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"

resolve_hostname() {
    if [[ -n "${HOSTNAME:-}" ]]; then
        printf '%s' "$HOSTNAME"
    elif [[ -r /etc/hostname ]]; then
        tr -d '[:space:]' < /etc/hostname
    else
        uname -n
    fi
}

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
  --init              Initialize a repository and configure its backup timer
  --backup            Create a new backup archive
  --prune             Prune old archives per retention policy
  --list              List all archives in the repository
  --restore ARCHIVE   Restore a specific archive
  --restore-dir DIR   Extraction directory for --restore

Other:
  -h, --help          Show this help
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -r)
            [[ $# -ge 2 && -n "${2:-}" ]] || err "-r requires a repository path"
            REPO="$2"; shift 2 ;;
        -p)
            [[ $# -ge 2 && -n "${2:-}" ]] || err "-p requires a passphrase file path"
            PASSPHRASE_FILE="$2"; shift 2 ;;
        -k)
            [[ $# -ge 2 && "${2:-}" =~ ^[1-9][0-9]*$ ]] || err "-k requires a positive integer"
            KEEP_DAILY="$2"; shift 2 ;;
        -K)
            [[ $# -ge 2 && "${2:-}" =~ ^[1-9][0-9]*$ ]] || err "-K requires a positive integer"
            KEEP_WEEKLY="$2"; shift 2 ;;
        -M)
            [[ $# -ge 2 && "${2:-}" =~ ^[1-9][0-9]*$ ]] || err "-M requires a positive integer"
            KEEP_MONTHLY="$2"; shift 2 ;;
        --init)      DO_INIT=true; shift ;;
        --backup)    DO_BACKUP=true; shift ;;
        --prune)     DO_PRUNE=true; shift ;;
        --list)      DO_LIST=true; shift ;;
        --restore)
            [[ $# -ge 2 && -n "${2:-}" ]] || err "--restore requires an ARCHIVE name"
            DO_RESTORE=true; RESTORE_ARCHIVE="$2"; shift 2 ;;
        --restore-dir)
            [[ $# -ge 2 && -n "${2:-}" ]] || err "--restore-dir requires a directory path"
            RESTORE_TARGET="$2"; shift 2 ;;
        -h|--help)   usage ;;
        *)           err "Unknown option: $1" ;;
    esac
done

[[ $(id -u) -eq 0 ]] || err "Must be run as root"

if [[ "$DO_INIT" == false && "$DO_BACKUP" == false && "$DO_PRUNE" == false \
   && "$DO_LIST" == false && "$DO_RESTORE" == false ]]; then
    err "No mode selected. Use --init, --backup, --prune, --list, or --restore ARCHIVE. See -h for help."
fi

mkdir -p "$(dirname "$LOGFILE")"
# Avoid duplicate log lines when systemd already redirects stdout/stderr to LOGFILE
if [[ -z "${INVOCATION_ID:-}" ]]; then
    exec > >(tee -a "$LOGFILE") 2>&1
fi

info "Repository: $REPO"
info "Passphrase file: $PASSPHRASE_FILE"
info "Log: $LOGFILE"

# This script is also the timer's entry point. Package installation and system
# upgrades must remain an explicit maintenance action, never a backup step.
command -v borg >/dev/null 2>&1 || \
    err "BorgBackup is not installed. Install it separately (sudo pacman -Syu borg), then retry."

BORG_VER=$(borg --version)
info "BorgBackup version: $BORG_VER"

HOST_PREFIX="$(resolve_hostname)"

load_passphrase() {
    if [[ ! -f "$PASSPHRASE_FILE" ]]; then
        err "Passphrase file not found: $PASSPHRASE_FILE. Run --init first or specify -p."
    fi
    export BORG_PASSPHRASE
    BORG_PASSPHRASE="$(cat "$PASSPHRASE_FILE")"
}

# =============================================================================
# INIT MODE
# =============================================================================

if [[ "$DO_INIT" == true ]]; then
    msg "Initializing borg repository..."

    if [[ ! -f "$PASSPHRASE_FILE" ]]; then
        info "Generating random passphrase..."
        mkdir -p "$(dirname "$PASSPHRASE_FILE")"
        head -c 32 /dev/urandom | base64 -w 0 > "$PASSPHRASE_FILE"
        chmod 600 "$PASSPHRASE_FILE"
        chown root:root "$PASSPHRASE_FILE"
        msg "Passphrase saved to $PASSPHRASE_FILE (mode 600)"
    else
        info "Using existing passphrase file: $PASSPHRASE_FILE"
    fi

    export BORG_PASSPHRASE
    BORG_PASSPHRASE="$(cat "$PASSPHRASE_FILE")"

    mkdir -p "$(dirname "$REPO")"

    if [[ -d "$REPO" && -f "$REPO/config" ]]; then
        warn "Repository already exists at $REPO — skipping init"
    else
        borg init --encryption=repokey-blake2 "$REPO"
        msg "Repository initialized at $REPO (encryption: repokey-blake2)"
    fi

    KEY_BACKUP="/root/.borg-key-backup"
    mkdir -p "$(dirname "$KEY_BACKUP")"
    borg key export "$REPO" "$KEY_BACKUP"
    chmod 600 "$KEY_BACKUP"
    chown root:root "$KEY_BACKUP"
    msg "Repository key exported to $KEY_BACKUP"

    echo
    echo -e "${C_YELLOW}========================================================================${C_NC}"
    echo -e "${C_YELLOW} WARNING: Store these files EXTERNALLY for disaster recovery!${C_NC}"
    echo -e "${C_YELLOW}  1. Passphrase file:  $PASSPHRASE_FILE${C_NC}"
    echo -e "${C_YELLOW}  2. Key backup file:  $KEY_BACKUP${C_NC}"
    echo -e "${C_YELLOW}========================================================================${C_NC}"
    echo
fi

# =============================================================================
# BACKUP MODE
# =============================================================================

if [[ "$DO_BACKUP" == true ]]; then
    msg "Creating backup archive..."

    load_passphrase

    ARCHIVE_NAME="${HOST_PREFIX}-$(date +%Y-%m-%d_%H:%M)"
    info "Archive name: $ARCHIVE_NAME"

    # Exclude the active logfile, journal, and the repo itself so mid-backup
    # writes do not cause exit code 1 warnings to abort --prune.
    borg_rc=0
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
        --exclude "$LOGFILE"                            \
        --exclude "$REPO"                               \
        --exclude '/var/log/journal'                    \
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
        /opt || borg_rc=$?

    if (( borg_rc == 1 )); then
        warn "Borg completed with warnings (rc=1; e.g., file changed while reading)."
    elif (( borg_rc >= 2 )); then
        err "Borg backup failed with exit code ${borg_rc}."
    fi

    msg "Backup archive created: $ARCHIVE_NAME"
fi

# =============================================================================
# PRUNE MODE
# =============================================================================

if [[ "$DO_PRUNE" == true ]]; then
    msg "Pruning old archives..."

    load_passphrase

    info "Retention policy: daily=$KEEP_DAILY, weekly=$KEEP_WEEKLY, monthly=$KEEP_MONTHLY"

    borg prune                                          \
        --list                                          \
        --stats                                         \
        --show-rc                                       \
        --glob-archives "${HOST_PREFIX}-*"              \
        --keep-daily    "$KEEP_DAILY"                   \
        --keep-weekly   "$KEEP_WEEKLY"                  \
        --keep-monthly  "$KEEP_MONTHLY"                 \
        "$REPO"

    msg "Compacting repository..."
    borg compact "$REPO"

    msg "Prune and compact complete"
fi

# =============================================================================
# LIST MODE
# =============================================================================

if [[ "$DO_LIST" == true ]]; then
    msg "Listing archives in $REPO..."

    load_passphrase

    borg list --format '{archive:<40} {time} {size:>12}{NL}' "$REPO"
fi

# =============================================================================
# RESTORE MODE
# =============================================================================

if [[ "$DO_RESTORE" == true ]]; then
    if [[ -z "$RESTORE_ARCHIVE" || "$RESTORE_ARCHIVE" == */* || "$RESTORE_ARCHIVE" == *..* ]]; then
        err "Invalid archive name specified. Usage: --restore ARCHIVE_NAME"
    fi

    msg "Restoring archive: $RESTORE_ARCHIVE"

    load_passphrase

    RESTORE_DIR="${RESTORE_TARGET:-/tmp/borg-restore/${RESTORE_ARCHIVE}}"
    mkdir -p -m 0700 "$RESTORE_DIR"
    chmod 0700 "$RESTORE_DIR"

    if command -v findmnt >/dev/null 2>&1; then
        restore_mnt_opts="$(findmnt -n -o OPTIONS -T "$RESTORE_DIR" 2>/dev/null || true)"
        if [[ ",$restore_mnt_opts," == *,nosuid,* ]]; then
            warn "$RESTORE_DIR is on a nosuid mount — pass --restore-dir /var/backups/borg-restore/${RESTORE_ARCHIVE} if restoring SUID system binaries."
        fi
    fi

    info "Extracting to $RESTORE_DIR..."
    (
        cd "$RESTORE_DIR"
        borg extract --list "${REPO}::${RESTORE_ARCHIVE}"
    )

    msg "Restored to: $RESTORE_DIR"
fi

# Only explicit --init may change scheduling or service configuration.
if [[ "$DO_INIT" != true ]]; then
    msg "Requested Borg operation(s) completed."
    exit 0
fi

# =============================================================================
# SYSTEMD TIMER & LOGROTATE (--init only)
# =============================================================================

msg "Setting up systemd timer for daily backups..."

if [[ "$(stat -c '%u' "$SCRIPT_PATH" 2>/dev/null || echo 0)" != "0" ]]; then
    warn "$SCRIPT_PATH is not owned by root; copy backup.sh to /usr/local/sbin/backup.sh (0755 root:root) before relying on unattended root execution."
fi

printf -v Q_SCRIPT '%q' "$SCRIPT_PATH"
printf -v Q_REPO   '%q' "$REPO"
printf -v Q_PASS   '%q' "$PASSPHRASE_FILE"

cat > /etc/systemd/system/borg-backup.service <<EOF
[Unit]
Description=BorgBackup — create archive and prune old backups
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
UMask=0077
ExecStart=${Q_SCRIPT} -r ${Q_REPO} -p ${Q_PASS} -k ${KEEP_DAILY} -K ${KEEP_WEEKLY} -M ${KEEP_MONTHLY} --backup --prune
Nice=19
IOSchedulingClass=idle
PrivateTmp=false
StandardOutput=append:${LOGFILE}
StandardError=append:${LOGFILE}
EOF
chmod 0644 /etc/systemd/system/borg-backup.service

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
chmod 0644 /etc/systemd/system/borg-backup.timer

systemctl daemon-reload
systemctl enable borg-backup.timer
systemctl start borg-backup.timer

msg "systemd timer enabled: borg-backup.timer (daily at 02:00, +30min jitter)"

msg "Setting up logrotate for borg backup logs..."
cat > /etc/logrotate.d/borg-backup <<EOF
/var/log/borg-backup.log {
    weekly
    rotate 8
    compress
    delaycompress
    missingok
    notifempty
    create 600 root root
}
EOF
chmod 0644 /etc/logrotate.d/borg-backup

msg "Logrotate configured for $LOGFILE"
echo -e "${C_GREEN}Done.${C_NC}"
