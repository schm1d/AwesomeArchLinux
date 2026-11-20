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
umask 022
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
readonly MIN_TMP_SIZE_GB=1
readonly SHM_SIZE_GB=2
readonly MIN_TMPFS_SIZE_MB=64

msg()  { printf "%b[+]%b %s\n" "$C_OK"   "$C_NC" "$1"; }
info() { printf "%b[*]%b %s\n" "$C_INFO"  "$C_NC" "$1"; }
warn() { printf "%b[!]%b %s\n" "$C_WARN"  "$C_NC" "$1"; }
err()  { printf "%b[!]%b %s\n" "$C_ERR"   "$C_NC" "$1" >&2; exit 1; }

# --- Logging ---
LOGFILE="/var/log/vps-harden-$(date +%Y%m%d-%H%M%S).log"

setup_logging() {
    install -d -m 0755 /var/log
    install -m 0600 /dev/null "$LOGFILE"
    exec > >(tee -a "$LOGFILE") 2>&1
}

log_action() {
    if [[ -w "$LOGFILE" ]]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOGFILE"
    fi
}

# --- Defaults ---
TMP_SIZE="$DEFAULT_TMP_SIZE_GB" # tmpfs /tmp ceiling in GB
TMP_SIZE_EXPLICIT=false
# size= values actually used for the tmpfs mounts. tmpfs pages live in RAM and
# swap, so the automatic values never exceed half of the installed memory
# (set in detect_disk_layout).
TMP_SIZE_ARG="${DEFAULT_TMP_SIZE_GB}G"
SHM_SIZE_ARG="${SHM_SIZE_GB}G"
VAR_LOOP_SIZE=10            # /var loop image size in GB
USERNAME=""                 # interactive or -u flag
NEW_HOSTNAME=""             # interactive or -H flag
SSH_PORT=22                 # replaced by the port sshd uses now unless -p is given
SSH_PORT_EXPLICIT=false
CURRENT_SSH_PORT=""         # port sshd uses now (preflight)
CURRENT_SSH_PORTS=""        # all of them, space separated
SSH_PUBKEY=""
ALLOW_NO_SSH_KEY=false
SKIP_VAR=false
SKIP_SW=false
DRY_RUN=false
SYSCTL_PROFILE="workstation"
SYSCTL_DISABLE_IPV6=false
ROLLBACK_SCRIPT="/root/undo-vps-harden.sh"
VAR_MIGRATION_GUIDE="/root/MIGRATE_VAR_OFFLINE.txt"
FSTAB_BACKUP=""
# Physical path (no symbolic links): verify_local_components checks who can
# write to this directory and the ones above it.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# Components that are not used from a local checkout are downloaded from this
# branch, tag or commit of the repository (--ref).
COMPONENT_REF="main"
RAW_BASE_URL="https://raw.githubusercontent.com/schm1d/AwesomeArchLinux/${COMPONENT_REF}"
# Set by verify_local_components: true only when the files next to this script
# are a checkout that nobody but root or the owner of this script can write to.
USE_LOCAL_COMPONENTS=false

# State tracking
VAR_STRATEGY="skip"        # partition | volume | loop | skip
VAR_DEVICE=""
ROOT_DEVICE=""
PARENT_DISK=""

###############################################################################
# HELPER FUNCTIONS
###############################################################################

# Read one line of input into the variable named by $2. A closed stdin (cron,
# CI, "< /dev/null") ends the run: every caller loops until it gets a valid
# answer, and a failing read would otherwise repeat the question forever while
# the output is copied into the log file.
prompt_read() {
    local prompt_msg="$1" var_name="$2"
    if ! read -r -p "$prompt_msg" "${var_name?}"; then
        echo
        err "No input available (stdin is closed). This step needs an interactive answer; nothing further was changed."
    fi
}

ask_yes_no() {
    local prompt_msg="$1"
    local choice
    while true; do
        prompt_read "$prompt_msg (y/n): " choice
        case "$choice" in
            [Yy]) return 0 ;;
            [Nn]) return 1 ;;
            *) warn "Invalid choice. Please type 'y' or 'n'." ;;
        esac
    done
}

validate_username() {
    local user="$1"
    [[ "$user" =~ ^[a-z_][a-z0-9_-]*$ ]] && [[ ${#user} -le 32 ]] && [[ "$user" != "root" ]]
}

# Prints why the account cannot be used as the administrator, or nothing when
# it can: an existing system account must not be turned into the SSH/sudo
# login, and a new user cannot be created when a group already has its name.
username_problem() {
    local user="$1" uid
    if uid=$(id -u -- "$user" 2>/dev/null); then
        if (( uid < 1000 || uid == 65534 )); then
            echo "'$user' is a system account (uid $uid)"
        fi
    elif getent group -- "$user" >/dev/null 2>&1; then
        echo "a group named '$user' already exists, so that user cannot be created"
    fi
}

validate_hostname() {
    local host="$1"
    [[ "$host" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*$ ]] && [[ ${#host} -le 64 ]]
}

validate_ssh_port() {
    local port="$1"
    [[ "$port" =~ ^[1-9][0-9]*$ ]] && (( 10#$port >= 1 && 10#$port <= 65535 ))
}

validate_ssh_pubkey() {
    local key="$1"
    if [[ -z "$key" ]]; then
        return 0
    fi
    if [[ "$key" =~ [\$\`\(\)\{\}\;\|\&\<\>\"\'\\] ]] || [[ "$key" == *$'\n'* ]] || [[ "$key" == *$'\r'* ]]; then
        warn "The SSH public key contains invalid characters."
        return 1
    fi
    # Accept only key types the hardened sshd will accept afterwards
    # (PubkeyAcceptedAlgorithms in hardening/ssh/ssh.sh). Password logins are
    # disabled, so a key sshd refuses -- plain ecdsa-sha2-* in particular --
    # would lock the operator out of the server.
    local key_type="${key%% *}"
    case "$key_type" in
        ssh-ed25519|sk-ssh-ed25519@openssh.com|sk-ecdsa-sha2-nistp256@openssh.com|ssh-rsa) ;;
        ecdsa-sha2-*)
            warn "Plain ECDSA keys ($key_type) are not accepted by the hardened sshd configuration."
            warn "Use an Ed25519 key (ssh-keygen -t ed25519), a FIDO2 key, or RSA."
            return 1
            ;;
        *)
            warn "Unsupported SSH key type '${key_type}'. Accepted: ssh-ed25519, sk-ssh-ed25519@openssh.com, sk-ecdsa-sha2-nistp256@openssh.com, ssh-rsa."
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
            warn "That is not a complete, valid SSH public key (ssh-keygen could not parse it)."
            return 1
        fi
        rm -f -- "$key_file"
    fi
    return 0
}

# True when the file holds at least one public key that the sshd_config
# written by ssh.sh accepts (same test as has_accepted_authorized_key there).
# A non-empty authorized_keys with only plain ECDSA or DSA keys would pass an
# emptiness test and still lock the user out once passwords are disabled.
authorized_keys_usable() {
    local key_file="$1" listing
    [[ -s "$key_file" ]] || return 1
    listing=$(ssh-keygen -l -f "$key_file" 2>/dev/null || true)
    awk '
        { type = $NF }
        type == "(ED25519)" || type == "(ED25519-SK)" || type == "(ECDSA-SK)" { ok = 1 }
        type == "(RSA)" && $1 + 0 >= 1024 { ok = 1 }
        END { exit ok ? 0 : 1 }
    ' <<< "$listing"
}

# Ports the running sshd listens on, one per line in ascending order; the
# configured ports when no listening sshd is found (socket activation, sshd
# stopped). Prints nothing when neither can be determined.
detect_sshd_ports() {
    local ports=""
    if command -v ss &>/dev/null; then
        ports=$(ss -H -tlnp 2>/dev/null |
            awk '/users:\(\("sshd"/ { n = split($4, part, ":"); print part[n] }' | sort -un || true)
    fi
    if [[ -z "$ports" ]] && command -v sshd &>/dev/null; then
        # sshd -T prints the keyword as "port" or "Port" depending on the version.
        ports=$(sshd -T 2>/dev/null | awk 'tolower($1) == "port" { print $2 }' | sort -un || true)
    fi
    grep -E '^[0-9]+$' <<< "$ports" || true
}

# tmpfs pages live in RAM and swap, so a tmpfs must not be sized from the disk
# alone: on a 1 GB VPS a 10G /tmp (with /var/tmp bound onto it) lets any user
# exhaust the memory. Prints the size= value for a ceiling given in GB: the
# ceiling itself, or half of the installed memory when that is less (the
# kernel's own tmpfs default), but at least MIN_TMPFS_SIZE_MB.
tmpfs_size_arg() {
    local ceiling_gb="$1" mem_kb half_ram_mb
    mem_kb=$(awk '/^MemTotal:/ { print $2; exit }' /proc/meminfo 2>/dev/null || true)
    if [[ "$mem_kb" =~ ^[0-9]+$ ]] && (( mem_kb > 0 )); then
        half_ram_mb=$((mem_kb / 2048))
        (( half_ram_mb >= MIN_TMPFS_SIZE_MB )) || half_ram_mb=$MIN_TMPFS_SIZE_MB
        if (( half_ram_mb < ceiling_gb * 1024 )); then
            printf '%sM\n' "$half_ram_mb"
            return 0
        fi
    fi
    printf '%sG\n' "$ceiling_gb"
}

# Prints why PATH could have been written by somebody other than root or the
# owner of this script, or nothing when it could not. KIND is "file",
# "directory" (holds a component directly) or "ancestor" (further up).
untrusted_path_reason() {
    local path="$1" kind="$2" trusted_uid="$3" owner mode
    if ! owner=$(stat -L -c %u -- "$path" 2>/dev/null) || ! mode=$(stat -L -c %a -- "$path" 2>/dev/null); then
        echo "$path cannot be examined"
        return 0
    fi
    if [[ "$owner" != 0 && "$owner" != "$trusted_uid" ]]; then
        echo "$path belongs to uid $owner"
        return 0
    fi
    if (( 8#$mode & 8#022 )); then
        # A root-owned sticky directory such as /tmp is fine further up the
        # path: nobody can replace another user's entry in it.
        if [[ "$kind" == "ancestor" && "$owner" == 0 ]] && (( 8#$mode & 8#1000 )); then
            return 0
        fi
        echo "$path is writable by its group or by others (mode $mode)"
    fi
}

# Decide whether the repository files next to this script may be used.
# Everything staged from there is executed or sourced as root, so a local copy
# is only trusted when nobody else could have written it: each file, its
# directory and every directory above must belong to root or to the owner of
# this script and must not be writable by group or others. Otherwise a local
# user could plant, say, vps-chroot.sh next to a vps-harden.sh that was
# downloaded into /tmp. Without any such file (single-file download) the
# components are fetched from the repository instead.
verify_local_components() {
    local -a candidates=(
        "$SCRIPT_DIR/vps-chroot.sh"
        "$SCRIPT_DIR/lib/chroot-security.sh"
        "$SCRIPT_DIR/install-aur-packages.sh"
        "$SCRIPT_DIR/../utils/auditd-attack.rules"
        "$SCRIPT_DIR/../utils/aide-config.sh"
        "$SCRIPT_DIR/../hardening/lib/aur-review.sh"
        "$SCRIPT_DIR/../hardening/lib/nftables.sh"
        "$SCRIPT_DIR/../hardening/ssh/ssh.sh"
    )
    local -A checked=() reported=()
    local -a problems=()
    local path real link_dir dir kind reason script_owner found=false

    USE_LOCAL_COMPONENTS=false
    for path in "$SCRIPT_DIR"/../hardening/sysctl/*; do
        candidates+=("$path")
    done
    script_owner=$(stat -L -c %u -- "${BASH_SOURCE[0]}" 2>/dev/null || echo 0)

    for path in "${candidates[@]}"; do
        [[ -e "$path" || -L "$path" ]] || continue
        found=true
        if ! real=$(realpath -e -- "$path" 2>/dev/null); then
            problems+=("$path cannot be resolved")
            continue
        fi
        reason=$(untrusted_path_reason "$real" file "$script_owner")
        [[ -z "$reason" ]] || problems+=("$reason")
        # Walk up from the directory that holds the file and, when the entry is
        # a symbolic link, also from the directory that holds the link.
        link_dir=$(realpath -e -- "$(dirname -- "$path")" 2>/dev/null || true)
        for dir in "$(dirname -- "$real")" "$link_dir"; do
            [[ -n "$dir" ]] || continue
            kind="directory"
            while true; do
                if [[ -z "${checked[$kind:$dir]:-}" ]]; then
                    checked[$kind:$dir]=1
                    reason=$(untrusted_path_reason "$dir" "$kind" "$script_owner")
                    if [[ -n "$reason" && -z "${reported[$reason]:-}" ]]; then
                        reported[$reason]=1
                        problems+=("$reason")
                    fi
                fi
                [[ "$dir" != "/" ]] || break
                dir=$(dirname -- "$dir")
                kind="ancestor"
            done
        done
    done

    if [[ "$found" == false ]]; then
        info "No repository files next to this script: components are downloaded (ref: $COMPONENT_REF)"
        return 0
    fi
    if (( ${#problems[@]} > 0 )); then
        warn "Repository files were found next to this script, but they cannot be trusted:"
        for reason in "${problems[@]}"; do
            warn "  - $reason"
        done
        warn "These files would be executed as root. Use a checkout that only you (or root) can"
        warn "write to (for example: chmod -R go-w <checkout>), or copy vps-harden.sh alone into"
        warn "an empty directory owned by root to have the components downloaded instead."
        err "Refusing to use repository files that other users could have written."
    fi
    USE_LOCAL_COMPONENTS=true
    info "Using the repository files next to this script (${SCRIPT_DIR%/*})"
}

# --- Usage ---
usage() {
    cat <<EOF
Usage: sudo $0 [OPTIONS]

Harden filesystem mount points on a live, running Arch Linux VPS.
Optional /var preparation formats selected storage; migration requires rescue downtime.

Options:
  -t SIZE     tmpfs size for /tmp in GB (minimum: $MIN_TMP_SIZE_GB). tmpfs is backed by RAM
              and swap. Automatic default: half of the installed memory, but
              at most 10 GB (25 GB when the root disk is at least 1 TB)
  -v SIZE     /var loop image size in GB, if using loop device (default: $VAR_LOOP_SIZE)
  -u USER     Non-root username for vps-chroot.sh (prompted if not given)
  -H HOST     Hostname to set (prompted if not given)
  -p PORT     SSH port for vps-chroot.sh (default: the port sshd uses now,
              22 if that cannot be determined)
  --ssh-key KEY
              SSH public key to install for USER (ssh-ed25519, ssh-rsa,
              sk-ssh-ed25519@openssh.com or sk-ecdsa-sha2-nistp256@openssh.com)
  -k, --allow-no-ssh-key
              Allow disabling SSH password auth without an authorized_keys entry
              (ONLY if you have verified out-of-band VPS console access)
  --skip-var  Skip storage preparation for offline /var migration
  --skip-sw   Skip software hardening (only do filesystem mounts)
  --sysctl-profile PROFILE
              Select workstation, strict, or performance (default: workstation)
  --disable-ipv6
              Install the explicit IPv6-disable sysctl overlay
  --ref REF   Branch, tag or commit of the repository that components are
              downloaded from when this script runs without a local checkout
              (default: $COMPONENT_REF). Pass a tag or commit to pin what is run.
  --dry-run   Show planned changes without executing
  -h, --help  Show this help

Examples:
  sudo $0                                # Full hardening (interactive prompts)
  sudo $0 --dry-run                      # Preview changes
  sudo $0 --skip-var --skip-sw           # Only tmpfs/shm/proc/var-tmp
  sudo $0 -u admin -H myvps -p 2222      # Non-interactive host/user/port flags
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
                if ! [[ "$TMP_SIZE" =~ ^[1-9][0-9]*$ ]] || (( 10#$TMP_SIZE < MIN_TMP_SIZE_GB )); then
                    err "Invalid tmpfs size: $TMP_SIZE (whole GB, minimum ${MIN_TMP_SIZE_GB})"
                fi
                TMP_SIZE_EXPLICIT=true
                shift 2
                ;;
            -v)
                [[ $# -ge 2 ]] || err "-v requires a size in GB"
                VAR_LOOP_SIZE="$2"
                if ! [[ "$VAR_LOOP_SIZE" =~ ^[1-9][0-9]*$ ]] || (( 10#$VAR_LOOP_SIZE < 5 )); then
                    err "Invalid /var size: $VAR_LOOP_SIZE (minimum 5 GB)"
                fi
                shift 2
                ;;
            -u)
                [[ $# -ge 2 ]] || err "-u requires a username"
                USERNAME="$2"
                validate_username "$USERNAME" ||
                    err "Invalid username '$USERNAME'. Must be non-root, begin with [a-z_], contain only [a-z0-9_-], max 32 chars."
                shift 2
                ;;
            -H)
                [[ $# -ge 2 ]] || err "-H requires a hostname"
                NEW_HOSTNAME="$2"
                validate_hostname "$NEW_HOSTNAME" ||
                    err "Invalid hostname '$NEW_HOSTNAME'. Must begin with alphanumeric, contain only [a-zA-Z0-9.-], max 64 chars."
                shift 2
                ;;
            -p)
                [[ $# -ge 2 ]] || err "-p requires an SSH port"
                SSH_PORT="$2"
                validate_ssh_port "$SSH_PORT" || err "Invalid SSH port: $SSH_PORT (must be 1-65535)"
                SSH_PORT_EXPLICIT=true
                shift 2
                ;;
            --ssh-key)
                [[ $# -ge 2 ]] || err "--ssh-key requires an SSH public key value"
                SSH_PUBKEY="${2%$'\r'}"
                [[ -n "$SSH_PUBKEY" ]] && validate_ssh_pubkey "$SSH_PUBKEY" ||
                    err "Invalid SSH public key supplied to --ssh-key"
                shift 2
                ;;
            --ref)
                [[ $# -ge 2 ]] || err "--ref requires a branch, tag or commit"
                COMPONENT_REF="$2"
                if ! [[ "$COMPONENT_REF" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]*$ ]] || [[ "$COMPONENT_REF" == *..* ]]; then
                    err "Invalid --ref value: $COMPONENT_REF"
                fi
                RAW_BASE_URL="https://raw.githubusercontent.com/schm1d/AwesomeArchLinux/${COMPONENT_REF}"
                shift 2
                ;;
            -k|--allow-no-ssh-key)
                ALLOW_NO_SSH_KEY=true
                shift
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

    setup_logging

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

    # Everything the software hardening needs is checked now, before the first
    # filesystem change, not after the mounts have already been reworked.
    if [[ "$SKIP_SW" == false ]]; then
        local -a software_tools=(pacman ssh-keygen sshd ss sha256sum)
        verify_local_components
        if [[ "$USE_LOCAL_COMPONENTS" == false ]]; then
            software_tools+=(curl)
        elif [[ "$COMPONENT_REF" != "main" ]]; then
            warn "--ref $COMPONENT_REF only applies to downloads; the local checkout is used as it is"
        fi
        for tool in "${software_tools[@]}"; do
            if ! command -v "$tool" &>/dev/null; then
                err "Required tool for the software hardening not found: $tool — install it first, or pass --skip-sw"
            fi
        done
        if [[ -e /var/lib/pacman/db.lck ]]; then
            err "pacman is in use (/var/lib/pacman/db.lck exists). Let it finish, or remove a stale lock, then run this script again."
        fi
        if [[ "$USE_LOCAL_COMPONENTS" == false ]] &&
           ! curl -fsSL --max-time 30 -o /dev/null "${RAW_BASE_URL}/base/vps-chroot.sh"; then
            if [[ "$DRY_RUN" == true ]]; then
                warn "Cannot download ${RAW_BASE_URL}/base/vps-chroot.sh (network, or a wrong --ref); a real run would stop here"
            else
                err "Cannot download ${RAW_BASE_URL}/base/vps-chroot.sh — check the network connection and --ref, or pass --skip-sw"
            fi
        fi

        # sshd stays on the port it uses now unless -p asks for another one.
        # With several ports, the one this very session came in through is
        # known to be reachable; otherwise the lowest one is taken.
        local -a sshd_ports=()
        local sshd_port session_port="${SSH_CONNECTION:-}"
        session_port="${session_port##* }"
        mapfile -t sshd_ports < <(detect_sshd_ports)
        CURRENT_SSH_PORT="${sshd_ports[0]:-}"
        CURRENT_SSH_PORTS=""
        for sshd_port in "${sshd_ports[@]}"; do
            CURRENT_SSH_PORTS+="${CURRENT_SSH_PORTS:+ }$sshd_port"
            [[ "$sshd_port" != "$session_port" ]] || CURRENT_SSH_PORT="$sshd_port"
        done
        if [[ "$SSH_PORT_EXPLICIT" == false && -n "$CURRENT_SSH_PORT" ]]; then
            SSH_PORT="$CURRENT_SSH_PORT"
        fi
    fi

    msg "Preflight checks passed"
}

###############################################################################
# DISK LAYOUT DETECTION
###############################################################################

detect_disk_layout() {
    info "Detecting disk layout..."

    # Find root device and resolve parent disk via kernel block hierarchy (PKNAME)
    ROOT_DEVICE=$(findmnt -n -o SOURCE /)
    info "Root device: $ROOT_DEVICE"

    local resolved_root cur parent
    resolved_root=$(readlink -f -- "$ROOT_DEVICE" 2>/dev/null || printf '%s' "$ROOT_DEVICE")
    cur="$resolved_root"
    PARENT_DISK=""
    while parent=$(lsblk -ndo PKNAME "$cur" 2>/dev/null | head -n1 | tr -d '[:space:]') &&
          [[ -n "$parent" && -b "/dev/$parent" ]]; do
        cur="/dev/$parent"
        if [[ "$(lsblk -ndo TYPE "$cur" 2>/dev/null)" == "disk" ]]; then
            PARENT_DISK="$cur"
            break
        fi
    done

    if [[ -z "$PARENT_DISK" ]]; then
        if [[ "$resolved_root" =~ ^(/dev/(nvme[0-9]+n[0-9]+|mmcblk[0-9]+|loop[0-9]+))p[0-9]+$ ]]; then
            PARENT_DISK="${BASH_REMATCH[1]}"
        elif [[ "$resolved_root" =~ ^(/dev/[a-zA-Z]+)[0-9]+$ ]]; then
            PARENT_DISK="${BASH_REMATCH[1]}"
        else
            PARENT_DISK="$resolved_root"
            warn "Could not determine parent disk from $ROOT_DEVICE"
        fi
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
        TMP_SIZE_ARG=$(tmpfs_size_arg "$TMP_SIZE")
        info "Automatic /tmp tmpfs size: ${TMP_SIZE_ARG} (half of the RAM, at most ${TMP_SIZE}G)"
    else
        TMP_SIZE_ARG="${TMP_SIZE}G"
        local mem_total_kb
        mem_total_kb=$(awk '/^(MemTotal|SwapTotal):/ { sum += $2 } END { print sum + 0 }' /proc/meminfo 2>/dev/null || true)
        if [[ "$mem_total_kb" =~ ^[0-9]+$ ]] && (( mem_total_kb > 0 && 10#$TMP_SIZE * 1048576 > mem_total_kb )); then
            warn "-t ${TMP_SIZE} is more than this system's RAM and swap together ($((mem_total_kb / 1024)) MiB)."
            warn "tmpfs lives in memory: filling /tmp (or /var/tmp) can then exhaust it."
        fi
    fi
    SHM_SIZE_ARG=$(tmpfs_size_arg "$SHM_SIZE_GB")

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
    echo "  1. /tmp      → tmpfs (${TMP_SIZE_ARG}, noexec,nosuid,nodev)"
    echo "  2. /dev/shm  → remount with noexec,nosuid,nodev (${SHM_SIZE_ARG} from the next boot)"
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
    echo "  Add nosuid,nodev to the /home entry (when /home is a separate mount)"
    echo
    echo -e "${C_OK}Safety:${C_NC}"
    echo "  - fstab backed up before changes"
    echo "  - Rollback script generated at $ROLLBACK_SCRIPT"
    echo "  - mount -a --fake validation after every fstab change"
    echo "  - SSH stays up throughout the entire process"
    echo "  - Tip: run this inside tmux or screen, so that a dropped SSH session"
    echo "    cannot stop the run half-way"

    if [[ "$SKIP_SW" == false ]]; then
        echo
        echo -e "${C_OK}Software hardening (vps-chroot.sh, run on this live system):${C_NC}"
        echo "  Username, hostname and SSH key are asked for before anything is changed"
        if [[ -z "$CURRENT_SSH_PORTS" ]]; then
            echo "  SSH port: $SSH_PORT (the port sshd uses now could not be determined)"
        elif [[ "$CURRENT_SSH_PORTS" == "$SSH_PORT" ]]; then
            echo "  SSH port: $SSH_PORT (unchanged)"
        else
            echo -e "  SSH port: ${C_WARN}sshd listens on ${CURRENT_SSH_PORTS} now and on ${SSH_PORT} ONLY afterwards${C_NC}"
            echo "            (a port it leaves stays open in an installed firewall until sshd"
            echo "            answers on $SSH_PORT)"
        fi
        echo "  Changes:"
        echo "    - sshd: new /etc/ssh/sshd_config — key-only logins, no root login, and"
        echo "      SSH access for the chosen user ONLY (AllowUsers); other accounts can"
        echo "      no longer log in over SSH"
        echo "    - new passwords are set for that user and for root (asked for)"
        echo "    - firewall: a default-deny nftables ruleset is installed when the host"
        echo "      has no firewall (ports with a listening service stay open). An"
        echo "      existing firewall (own nftables.conf, firewalld, ufw, iptables rules,"
        echo "      Docker/libvirt tables) is left as it is"
        echo "    - sudo: hardened defaults added as /etc/sudoers.d/00-awesome-hardening;"
        echo "      the user joins the 'sudo' group; /etc/sudoers keeps its rules"
        echo "    - DNS: systemd-resolved with DNS-over-TLS; /etc/resolv.conf is replaced"
        echo "    - packages: nftables fail2ban clamav rkhunter audit lynis arpwatch chrony"
        echo "      sysstat arch-audit and a few small tools"
        echo "    - PAM password policy, auditd rules, systemd unit hardening, login banner"
        echo "    - sysctl profile: $SYSCTL_PROFILE (IPv6 disabled: $SYSCTL_DISABLE_IPV6); it turns"
        echo "      packet forwarding off — do not use it on a router, VPN or container host"
        echo "  Kept: timezone, locale, keymap, network profiles, the entries in /etc/hosts,"
        echo "        existing ~/.nanorc and ~/.ssh/config"
        echo "  Backups: /etc/hosts, /etc/resolv.conf, /etc/sudoers and /etc/nftables.conf are copied"
        echo "        to <file>.before-awesome.<time> before they are changed; the old sshd_config is"
        echo "        kept as /etc/ssh/sshd_config.bak.<time>. Other files get no backup copy."
        if [[ "$USE_LOCAL_COMPONENTS" == true ]]; then
            echo "  Components: the repository checkout at ${SCRIPT_DIR%/*}"
        else
            echo "  Components: downloaded from $RAW_BASE_URL"
            if [[ "$COMPONENT_REF" == "main" ]]; then
                echo "              (the moving 'main' branch; pass --ref <tag|commit> to pin them)"
            fi
        fi
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
    # A rollback script left by an earlier run restores the fstab from before
    # this system was hardened. While the entries of that run are still in
    # /etc/fstab it remains the way back: regenerating it would make "rollback"
    # restore the already hardened fstab that was backed up a moment ago.
    local earlier_backup=""
    if [[ -f "$ROLLBACK_SCRIPT" ]]; then
        earlier_backup=$(grep -o '/root/fstab\.backup\.[0-9-]*' "$ROLLBACK_SCRIPT" | head -n1 || true)
    fi
    if [[ -n "$earlier_backup" && -f "$earlier_backup" ]] &&
       grep -Eq '^/tmp[[:space:]]+/var/tmp[[:space:]]+none[[:space:]]+bind' /etc/fstab; then
        info "Keeping the rollback script of the earlier run: $ROLLBACK_SCRIPT"
        info "It restores the fstab from before the first hardening: $earlier_backup"
        return 0
    fi

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
    info "Hardening /tmp → tmpfs (${TMP_SIZE_ARG}, noexec,nosuid,nodev)..."

    if [[ "$DRY_RUN" == true ]]; then
        info "[DRY-RUN] Would mount tmpfs on /tmp"
        info "[DRY-RUN] Would add fstab entry for /tmp"
        return 0
    fi

    # Remove any existing /tmp entry from fstab
    sed -i '\|^[^#].*[[:space:]]/tmp[[:space:]]|d' /etc/fstab

    # Add hardened entry
    echo "tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,relatime,size=${TMP_SIZE_ARG} 0 0" >> /etc/fstab

    # Mount (preserve existing files by copying first)
    if findmnt -n /tmp &>/dev/null; then
        # Already mounted — remount with new options
        mount -o remount,nosuid,nodev,noexec,relatime,size="${TMP_SIZE_ARG}" /tmp 2>/dev/null || {
            # If remount fails, do a fresh mount (preserve existing files)
            local tmp_backup
            tmp_backup=$(mktemp -d /root/tmp_backup.XXXXXX) || {
                warn "mktemp failed — mounting /tmp without preserving contents"
                mount -t tmpfs -o rw,nosuid,nodev,noexec,relatime,size="${TMP_SIZE_ARG}" tmpfs /tmp
                return 0
            }
            rsync -aHAX --exclude='lost+found' /tmp/ "$tmp_backup/" 2>/dev/null || true
            mount -t tmpfs -o rw,nosuid,nodev,noexec,relatime,size="${TMP_SIZE_ARG}" tmpfs /tmp
            rsync -aHAX --exclude='lost+found' "$tmp_backup/" /tmp/ 2>/dev/null || true
            rm -rf "$tmp_backup"
        }
    else
        mount -t tmpfs -o rw,nosuid,nodev,noexec,relatime,size="${TMP_SIZE_ARG}" tmpfs /tmp
    fi

    validate_fstab
    msg "/tmp hardened (tmpfs, ${TMP_SIZE_ARG})"
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
    echo "tmpfs /dev/shm tmpfs rw,nosuid,nodev,noexec,relatime,size=${SHM_SIZE_ARG} 0 0" >> /etc/fstab

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
        # Move any existing files to /tmp (excluding ext4 lost+found)
        if [[ -d /var/tmp ]] && [[ -n "$(find /var/tmp -mindepth 1 -maxdepth 1 ! -name lost+found -print -quit 2>/dev/null)" ]]; then
            rsync -aHAX --exclude='lost+found' /var/tmp/ /tmp/ 2>/dev/null || true
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

# Whole disks that could be given to /var: not the root disk, no zram, ramdisk,
# network block or loop device, writable, at least 1 GiB, and with nothing on
# them in use -- no mounted filesystem or active swap, and no LVM, LUKS or RAID
# device stacked on the disk or one of its partitions. "Not mounted" alone is
# not "unused": a disk can hold a volume group or an unmounted data filesystem.
list_spare_disks() {
    local disk mounts types
    while IFS= read -r disk; do
        [[ -n "$disk" && "$disk" != "$PARENT_DISK" && -b "$disk" ]] || continue
        mounts=$(lsblk -n -o MOUNTPOINTS "$disk" 2>/dev/null || true)
        [[ ! "$mounts" =~ [^[:space:]] ]] || continue
        # Anything but the disk and its partitions in the device tree (lvm,
        # crypt, raid*, mpath ...) means the disk is in use. An empty answer
        # (lsblk failed) is treated the same way.
        types=$(lsblk -n -o TYPE "$disk" 2>/dev/null || true)
        if grep -qvE '^[[:space:]]*(disk|part)[[:space:]]*$' <<< "$types"; then
            continue
        fi
        printf '%s\n' "$disk"
    done < <(lsblk -d -n -b -o NAME,TYPE,RO,SIZE 2>/dev/null | awk '
        $2 == "disk" && $3 == 0 && $4 >= 1073741824 && $1 !~ /^(zram|ram|nbd|loop)/ { print "/dev/" $1 }
    ' || true)
}

# True when the disk carries a partition table or a filesystem/LVM/RAID/LUKS
# signature, i.e. erasing it may destroy data.
disk_has_signature() {
    local disk="$1" signatures
    signatures=$(lsblk -n -o FSTYPE,PTTYPE "$disk" 2>/dev/null | tr -d '[:space:]' || true)
    [[ -n "$signatures" ]]
}

choose_var_strategy() {
    info "Detecting /var separation options..."

    # Check if /var is already separate
    if findmnt -n /var &>/dev/null && [[ "$(findmnt -n -o SOURCE /var)" != "$(findmnt -n -o SOURCE /)" ]]; then
        info "/var is already on a separate filesystem"
        VAR_STRATEGY="skip"
        return 0
    fi

    # Option 1: Check for extra attached volumes (e.g., /dev/vdb, /dev/sdb)
    local -a spare_disks=()
    local spare_disk typed_name
    mapfile -t spare_disks < <(list_spare_disks)

    for spare_disk in "${spare_disks[@]}"; do
        echo
        info "Found a disk that is not in use: $spare_disk"
        lsblk -o NAME,SIZE,FSTYPE,LABEL,UUID,MOUNTPOINTS "$spare_disk" 2>/dev/null || true
        if disk_has_signature "$spare_disk"; then
            warn "$spare_disk is NOT blank: it carries a partition table or a filesystem (see above)."
            warn "Using it for /var ERASES everything on it."
            prompt_read "Type the device name ($spare_disk) to erase it, or press Enter to leave it alone: " typed_name
            if [[ "${typed_name%$'\r'}" == "$spare_disk" ]]; then
                VAR_STRATEGY="volume"
                VAR_DEVICE="$spare_disk"
                return 0
            fi
            info "$spare_disk left untouched"
        elif ask_yes_no "Format the blank disk $spare_disk to prepare storage for offline /var migration?"; then
            VAR_STRATEGY="volume"
            VAR_DEVICE="$spare_disk"
            return 0
        fi
    done

    # Option 2: Check for free unpartitioned space on root disk. The partition
    # is created with sgdisk, which would convert an MBR (DOS) disk to GPT in
    # place and leave a BIOS-booted server unbootable, so this is offered on
    # GPT disks only.
    local free_space_bytes parent_pttype partition_tool partition_tools_ok=true
    parent_pttype=$(lsblk -d -n -o PTTYPE "$PARENT_DISK" 2>/dev/null | tr -d '[:space:]' || true)
    for partition_tool in sgdisk partprobe uuidgen; do
        command -v "$partition_tool" &>/dev/null || partition_tools_ok=false
    done
    free_space_bytes=$(LC_ALL=C sfdisk -F "$PARENT_DISK" 2>/dev/null | awk '
        match($0, /[0-9]+ bytes/) {
            s = substr($0, RSTART, RLENGTH)
            sub(/ bytes$/, "", s)
            print s
            exit
        }
    ' || true)
    local min_bytes=$((VAR_LOOP_SIZE * 1073741824))  # GB to bytes

    if [[ "${free_space_bytes:-}" =~ ^[0-9]+$ ]] && (( free_space_bytes > min_bytes )); then
        local free_gb=$((free_space_bytes / 1073741824))
        echo
        info "Found ${free_gb}G free space on $PARENT_DISK"
        if [[ "$parent_pttype" != "gpt" ]]; then
            info "Not offering a new partition: $PARENT_DISK has a '${parent_pttype:-unknown}' partition table (GPT is required)"
        elif [[ "$partition_tools_ok" == false ]]; then
            info "Not offering a new partition: sgdisk (gptfdisk), partprobe (parted) and uuidgen are needed for it"
        elif ask_yes_no "Create a new partition for /var?"; then
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

    # Add nosuid,nodev to /home if it's a separate mount. Only the options
    # field of the /home entry is rewritten, whatever it contains ("defaults",
    # "rw,relatime", ...); comments and every other line stay as they are.
    if findmnt -n /home &>/dev/null && [[ "$(findmnt -n -o SOURCE /home)" != "$(findmnt -n -o SOURCE /)" ]]; then
        local fstab_new
        fstab_new=$(mktemp /etc/fstab.XXXXXX)
        awk '
            /^[[:space:]]*#/ || NF < 4 || $2 != "/home" { print; next }
            {
                opts = $4
                if (("," opts ",") !~ /,nosuid,/) opts = opts ",nosuid"
                if (("," opts ",") !~ /,nodev,/) opts = opts ",nodev"
                if (opts != $4 && match($0, /^[[:space:]]*[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+/)) {
                    rest = substr($0, RLENGTH + 1)
                    sub(/^[^[:space:]]+/, "", rest)
                    print substr($0, 1, RLENGTH) opts rest
                    next
                }
                print
            }
        ' /etc/fstab > "$fstab_new"
        if cmp -s -- "$fstab_new" /etc/fstab; then
            rm -f -- "$fstab_new"
            if awk '!/^[[:space:]]*#/ && $2 == "/home" { found = 1 } END { exit found ? 0 : 1 }' /etc/fstab; then
                info "/home fstab entry already has nosuid,nodev"
            else
                warn "/home is a separate mount without an /etc/fstab entry; add nosuid,nodev where it is defined"
            fi
        else
            info "Adding nosuid,nodev to /home fstab entry"
            chmod 0644 "$fstab_new"
            mv -f -- "$fstab_new" /etc/fstab
        fi
        mount -o remount,nosuid,nodev /home 2>/dev/null ||
            warn "/home remount with nosuid,nodev failed (will apply on next boot)"
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

    # Prompt for username if not provided via -u, and always validate
    local user_problem
    if [[ -z "$USERNAME" ]]; then
        # Suggest the account that called sudo; failing that, the first home
        # directory that belongs to a regular account.
        local default_user="" home_name
        if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
            default_user="$SUDO_USER"
        else
            while IFS= read -r home_name; do
                if validate_username "$home_name" && id -u -- "$home_name" &>/dev/null &&
                   [[ -z "$(username_problem "$home_name")" ]]; then
                    default_user="$home_name"
                    break
                fi
            done < <(find /home -maxdepth 1 -mindepth 1 -type d -printf '%f\n' 2>/dev/null | sort || true)
        fi
        if [[ -n "$default_user" ]] &&
           { ! validate_username "$default_user" || [[ -n "$(username_problem "$default_user")" ]]; }; then
            default_user=""
        fi

        while true; do
            if [[ -n "$default_user" ]]; then
                prompt_read "Username [${default_user}]: " USERNAME
                USERNAME="${USERNAME:-$default_user}"
            else
                prompt_read "Username: " USERNAME
            fi
            USERNAME="${USERNAME%$'\r'}"
            if ! validate_username "$USERNAME"; then
                warn "Invalid username. Must be non-root, begin with [a-z_], contain only [a-z0-9_-], max 32 chars."
                continue
            fi
            user_problem=$(username_problem "$USERNAME")
            if [[ -n "$user_problem" ]]; then
                warn "Cannot use that name: $user_problem."
                continue
            fi
            break
        done
    else
        validate_username "$USERNAME" ||
            err "Invalid username '$USERNAME'. Must be non-root, begin with [a-z_], contain only [a-z0-9_-], max 32 chars."
        user_problem=$(username_problem "$USERNAME")
        [[ -z "$user_problem" ]] || err "Cannot use '$USERNAME' as the administrator account: $user_problem."
    fi
    if id -u -- "$USERNAME" &>/dev/null; then
        info "Account '$USERNAME' exists: it is kept and added to the sudo and proc groups"
    else
        info "Account '$USERNAME' does not exist yet: it will be created"
    fi

    # Prompt for hostname if not provided via -H, and always validate
    if [[ -z "$NEW_HOSTNAME" ]]; then
        local current_host
        current_host=$(cat /etc/hostname 2>/dev/null | tr -d '\r\n' || echo "archlinux")
        [[ -n "$current_host" ]] || current_host="archlinux"

        while true; do
            prompt_read "Hostname [${current_host}]: " NEW_HOSTNAME
            NEW_HOSTNAME="${NEW_HOSTNAME:-$current_host}"
            NEW_HOSTNAME="${NEW_HOSTNAME%$'\r'}"
            if validate_hostname "$NEW_HOSTNAME"; then
                break
            else
                warn "Invalid hostname. Must begin with alphanumeric, contain only [a-zA-Z0-9.-], max 64 chars."
            fi
        done
    else
        validate_hostname "$NEW_HOSTNAME" ||
            err "Invalid hostname '$NEW_HOSTNAME'. Must begin with alphanumeric, contain only [a-zA-Z0-9.-], max 64 chars."
    fi

    validate_ssh_port "$SSH_PORT" || err "Invalid SSH port: $SSH_PORT (must be 1-65535)"

    # The account's real home directory (not always /home/<name>), and a key
    # check that matches what the hardened sshd accepts: a non-empty file with
    # only plain ECDSA or DSA keys would not let anybody in.
    local user_home existing_auth_keys
    user_home=$(getent passwd -- "$USERNAME" 2>/dev/null | cut -d: -f6 || true)
    [[ -n "$user_home" ]] || user_home="/home/$USERNAME"
    existing_auth_keys="$user_home/.ssh/authorized_keys"
    local has_existing_keys=false
    if authorized_keys_usable "$existing_auth_keys"; then
        has_existing_keys=true
    elif [[ -s "$existing_auth_keys" ]]; then
        warn "$existing_auth_keys holds no key that the hardened sshd accepts"
        warn "(accepted: Ed25519, FIDO2 sk-* keys, RSA of at least 1024 bits)."
    fi

    # Validate or prompt for SSH public key (critical: password auth will be disabled)
    if [[ -n "$SSH_PUBKEY" ]]; then
        validate_ssh_pubkey "$SSH_PUBKEY" || err "Invalid SSH public key."
    else
        echo -e "\n${C_WARN}Password authentication and root SSH login will be disabled after hardening.${C_NC}"
        if [[ "$has_existing_keys" == true ]]; then
            info "Usable keys found in $existing_auth_keys (press Enter to keep them, or paste an additional key)."
        fi
        while true; do
            echo -e "${C_WARN}Paste your SSH public key (from ~/.ssh/id_ed25519.pub on your local machine):${C_NC}"
            prompt_read "" SSH_PUBKEY
            SSH_PUBKEY="${SSH_PUBKEY%$'\r'}"
            if [[ -z "$SSH_PUBKEY" ]]; then
                if [[ "$has_existing_keys" == true || "$ALLOW_NO_SSH_KEY" == true ]]; then
                    break
                fi
                warn "No SSH public key provided and $existing_auth_keys has no usable key!"
                if ask_yes_no "Confirm out-of-band VPS console access and proceed WITHOUT an SSH key?"; then
                    ALLOW_NO_SSH_KEY=true
                    break
                fi
                continue
            fi
            # validate_ssh_pubkey explains what is wrong with the key.
            if validate_ssh_pubkey "$SSH_PUBKEY"; then
                break
            fi
        done
    fi

    echo
    info "Username:  $USERNAME"
    info "Hostname:  $NEW_HOSTNAME"
    if [[ -n "$CURRENT_SSH_PORTS" && "$CURRENT_SSH_PORTS" != "$SSH_PORT" ]]; then
        info "SSH port:  $SSH_PORT (sshd listens on $CURRENT_SSH_PORTS now)"
    else
        info "SSH port:  $SSH_PORT"
    fi
    if [[ -n "$SSH_PUBKEY" ]]; then
        info "SSH key:   (provided)"
    elif [[ "$has_existing_keys" == true ]]; then
        info "SSH key:   (preserving existing $existing_auth_keys)"
    else
        info "SSH key:   (none — console-only access confirmed)"
    fi
    echo
}

create_install_env() {
    info "Creating install environment for vps-chroot.sh..."

    if [[ "$DRY_RUN" == true ]]; then
        info "[DRY-RUN] Would create /root/.install-env"
        return 0
    fi

    local install_date
    install_date="$(date)"
    {
        printf 'export %s=%q\n' \
            INSTALL_DISK "$PARENT_DISK" \
            INSTALL_USER "$USERNAME" \
            INSTALL_HOST "$NEW_HOSTNAME" \
            INSTALL_DATE "$install_date" \
            INSTALL_TYPE "vps-harden" \
            INSTALL_SSH_PORT "$SSH_PORT" \
            INSTALL_SSH_PUBKEY "$SSH_PUBKEY" \
            INSTALL_ALLOW_NO_SSH_KEY "$ALLOW_NO_SSH_KEY" \
            INSTALL_SYSCTL_PROFILE "$SYSCTL_PROFILE" \
            INSTALL_DISABLE_IPV6 "$SYSCTL_DISABLE_IPV6"
    } > /root/.install-env
    chmod 600 /root/.install-env
    msg "Created /root/.install-env (INSTALL_TYPE=vps-harden)"
}

stage_ssh_components() {
    local target_root="$1"
    # Stage both SSH components before vps-chroot.sh can change authentication.
    # The single-file download workflow needs the same helper as a local clone.
    # Local files are used only once verify_local_components has accepted them.
    local ssh_component ssh_target
    for ssh_component in lib/nftables.sh ssh/ssh.sh; do
        ssh_target="${target_root%/}/${ssh_component##*/}"
        if [[ "${USE_LOCAL_COMPONENTS:-false}" == true && -r "$SCRIPT_DIR/../hardening/$ssh_component" ]]; then
            install -m 0644 "$SCRIPT_DIR/../hardening/$ssh_component" "$ssh_target"
        else
            curl -fsSL \
                "${RAW_BASE_URL:-https://raw.githubusercontent.com/schm1d/AwesomeArchLinux/main}/hardening/$ssh_component" \
                -o "$ssh_target" || err "Could not fetch required SSH component: $ssh_component"
            chmod 0644 "$ssh_target"
        fi
        [[ -s "$ssh_target" ]] || err "Empty SSH component: $ssh_component"
        bash -n "$ssh_target" || err "Invalid SSH component: $ssh_component"
    done
    chmod 0755 "${target_root%/}/ssh.sh"
}

stage_repo_component() {
    local local_rel="$1" remote_rel="$2" dest="$3" mode="$4" verify_bash="${5:-false}"
    local src="$SCRIPT_DIR/$local_rel" tmp_dest

    install -d -m 0755 "$(dirname "$dest")"
    tmp_dest=$(mktemp "${dest}.XXXXXX")
    if [[ "${USE_LOCAL_COMPONENTS:-false}" == true && -r "$src" ]]; then
        cat "$src" > "$tmp_dest"
    else
        if ! curl -fsSL "${RAW_BASE_URL}/${remote_rel}" -o "$tmp_dest"; then
            rm -f "$tmp_dest"
            err "Could not fetch required component: $remote_rel"
        fi
    fi

    if [[ ! -s "$tmp_dest" ]]; then
        rm -f "$tmp_dest"
        err "Staged component is empty: $remote_rel"
    fi

    if [[ "$verify_bash" == true ]] && ! bash -n "$tmp_dest"; then
        rm -f "$tmp_dest"
        err "Syntax validation failed for component: $remote_rel"
    fi

    chmod "$mode" "$tmp_dest"
    mv -f -- "$tmp_dest" "$dest"
}

run_software_hardening() {
    info "Running software hardening via vps-chroot.sh..."

    if [[ "$DRY_RUN" == true ]]; then
        info "[DRY-RUN] Would stage components and run vps-chroot.sh"
        return 0
    fi

    local chroot_script
    chroot_script=$(mktemp /root/vps-chroot.XXXXXX.sh)
    chmod 0700 "$chroot_script"

    # Use the local copy when preflight accepted the checkout (see
    # verify_local_components), otherwise fetch into a private /root mktemp file
    if [[ "$USE_LOCAL_COMPONENTS" == true && -r "$SCRIPT_DIR/vps-chroot.sh" ]]; then
        info "Staging local vps-chroot.sh from $SCRIPT_DIR"
        cat "$SCRIPT_DIR/vps-chroot.sh" > "$chroot_script"
    else
        info "Downloading vps-chroot.sh from repository..."
        if ! curl -fsSL "${RAW_BASE_URL}/base/vps-chroot.sh" -o "$chroot_script"; then
            rm -f "$chroot_script"
            err "Failed to download vps-chroot.sh"
        fi
        warn "vps-chroot.sh was downloaded from a remote source — review before trusting"
    fi

    if [[ ! -s "$chroot_script" ]] || ! head -1 "$chroot_script" | grep -qE '^#!.*bash'; then
        rm -f "$chroot_script"
        err "Staged vps-chroot.sh is empty or missing a valid bash shebang"
    fi
    if ! grep -q 'INSTALL_USER' "$chroot_script" || ! bash -n "$chroot_script"; then
        rm -f "$chroot_script"
        err "Staged vps-chroot.sh failed marker or syntax validation"
    fi
    chmod 0700 "$chroot_script"

    # Stage shared chroot security library, audit rules, and post-install AUR/AIDE bundle
    stage_repo_component "lib/chroot-security.sh" "base/lib/chroot-security.sh" \
        "/usr/local/lib/awesomearchlinux/chroot-security.sh" 0644 true
    stage_repo_component "../utils/auditd-attack.rules" "utils/auditd-attack.rules" \
        "/usr/local/share/awesomearchlinux/auditd-attack.rules" 0644 false
    stage_repo_component "install-aur-packages.sh" "base/install-aur-packages.sh" \
        "/root/install-aur-packages.sh" 0700 true
    stage_repo_component "../hardening/lib/aur-review.sh" "hardening/lib/aur-review.sh" \
        "/root/aur-review.sh" 0600 true
    stage_repo_component "../utils/aide-config.sh" "utils/aide-config.sh" \
        "/root/aide-config.sh" 0700 true

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
    local sysctl_file is_script
    install -d -m 0755 "$sysctl_stage"
    for sysctl_file in "${sysctl_files[@]}"; do
        is_script=false
        [[ "$sysctl_file" == *.sh ]] && is_script=true
        stage_repo_component "../hardening/sysctl/$sysctl_file" \
            "hardening/sysctl/$sysctl_file" \
            "$sysctl_stage/$sysctl_file" 0644 "$is_script"
    done
    chmod 0755 "$sysctl_stage/sysctl.sh"

    stage_ssh_components /

    # Record exactly what is about to run as root. For components downloaded
    # from a moving branch the log is the only trace of which version ran.
    info "Staged components (sha256):"
    sha256sum -- "$chroot_script" \
        /usr/local/lib/awesomearchlinux/chroot-security.sh \
        /usr/local/share/awesomearchlinux/auditd-attack.rules \
        /root/install-aur-packages.sh /root/aur-review.sh /root/aide-config.sh \
        "$sysctl_stage"/* /ssh.sh /nftables.sh || true

    # Set up environment variables and run
    export _INSTALL_DISK="$PARENT_DISK"
    export _INSTALL_USER="$USERNAME"
    export _INSTALL_HOST="$NEW_HOSTNAME"
    export _INSTALL_SSH_PORT="$SSH_PORT"
    export _INSTALL_SSH_PUBKEY="$SSH_PUBKEY"
    export _INSTALL_ALLOW_NO_SSH_KEY="$ALLOW_NO_SSH_KEY"
    export _INSTALL_SYSCTL_PROFILE="$SYSCTL_PROFILE"
    export _INSTALL_DISABLE_IPV6="$SYSCTL_DISABLE_IPV6"
    export _INSTALL_TYPE="vps-harden"

    info "Executing vps-chroot.sh (this will take several minutes)..."
    local chroot_rc=0
    bash "$chroot_script" || chroot_rc=$?

    # Always clean up staged one-shot scripts
    shred -zu "$chroot_script" 2>/dev/null || rm -f "$chroot_script"
    shred -zu /sysctl.sh 2>/dev/null || true
    shred -zu /ssh.sh 2>/dev/null || true
    shred -zu /nftables.sh 2>/dev/null || true
    rm -rf -- /sysctl-profile

    if (( chroot_rc != 0 )); then
        err "Software hardening via vps-chroot.sh exited with status $chroot_rc"
    fi

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
    if [[ "$SKIP_SW" == false ]]; then
        echo "  [ ] Verify SSH access in a NEW terminal before closing this one:"
        echo "        ssh -p $SSH_PORT $USERNAME@<this server>   (key login; root and passwords are refused)"
        echo "  [ ] Pre-hardening copies: <file>.before-awesome.<time> next to /etc/hosts, /etc/resolv.conf,"
        echo "        /etc/sudoers and /etc/nftables.conf; /etc/ssh/sshd_config.bak.<time>"
    else
        echo "  [ ] Verify SSH access in a NEW terminal before closing this one"
    fi
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

    # Ask for everything the software hardening needs before the first change,
    # so that a wrong answer or a missing SSH key cannot leave the server half
    # converted.
    if [[ "$SKIP_SW" == false ]]; then
        prompt_user_config
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
        create_install_env
        run_software_hardening
    fi

    show_summary
}

main "$@"
