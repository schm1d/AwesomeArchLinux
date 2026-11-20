#!/usr/bin/env bash

# =============================================================================
# Script:      totp.sh
# Description: Sets up TOTP two-factor authentication for SSH on Arch Linux
#              using Google Authenticator PAM module. Configures sshd to
#              require both a public key and a TOTP code for login.
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
#
# Usage:       sudo ./totp.sh [-u USERNAME] [--allow-missing-totp]
#                             [--allow-no-ssh-key] [--require-password]
#                             [--rotate] [-h]
#
# Requirements:
#   - Arch Linux with pacman
#   - Root privileges
#   - SSH server (sshd) installed and running
#   - Public key authentication already configured for the target user
#
# What this script does:
#   1. Validates a candidate sshd configuration before anything is changed
#   2. Installs libpam-google-authenticator and qrencode
#   3. Creates the target user's TOTP secret (an existing one is kept unless
#      --rotate is passed)
#   4. Configures fail-closed PAM authentication (unless explicitly staged)
#   5. Configures sshd for keyboard-interactive (publickey + TOTP), using a
#      drop-in when sshd_config includes /etc/ssh/sshd_config.d
#   6. Validates the live configuration and reloads sshd without dropping
#      existing sessions; any failure restores the previous PAM/sshd files
#   7. Prints emergency scratch codes and instructions
# =============================================================================

set -euo pipefail
umask 022

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
USERNAME=""
ALLOW_MISSING_TOTP=false
ALLOW_NO_SSH_KEY=false
REQUIRE_PASSWORD=false
ROTATE_SECRET=false
SSHD_DIR="/etc/ssh"
SSHD_CONFIG="${SSHD_DIR}/sshd_config"
SSHD_DROPIN_DIR="${SSHD_DIR}/sshd_config.d"
SSHD_DROPIN="${SSHD_DROPIN_DIR}/00-awesome-totp.conf"
PAM_SSHD="/etc/pam.d/sshd"
LOGFILE=""

# --- Usage ---
usage() {
    cat <<EOF
Usage: sudo $0 [options]

Options:
  -u USERNAME   Target user to configure TOTP for
                (default: \$SUDO_USER, or first non-root user)
  --allow-missing-totp
                Staged rollout: permit SSH users without a TOTP secret
  --allow-no-ssh-key
                Proceed even if ~/.ssh/authorized_keys is missing or empty
  --require-password
                Keep system-remote-login PAM password prompt in addition to SSH key + TOTP
  --rotate      Replace the user's existing TOTP secret and scratch codes
                (default: an existing secret is kept as it is)
  -h            Show this help

Examples:
  sudo $0                    # Configure TOTP for current sudo user
  sudo $0 -u alice           # Configure TOTP for user 'alice'
  sudo $0 -u alice --allow-missing-totp  # Explicit staged rollout
  sudo $0 -u alice --rotate  # Issue a new secret for 'alice'
EOF
    exit 0
}

# --- Parse Arguments ---
need_arg() { [[ $# -ge 2 && -n "${2:-}" ]] || err "Option $1 requires a value"; }
while [[ $# -gt 0 ]]; do
    case "$1" in
        -u)                    need_arg "$@"; USERNAME="$2"; shift 2 ;;
        --allow-missing-totp)  ALLOW_MISSING_TOTP=true; shift ;;
        --allow-no-ssh-key)    ALLOW_NO_SSH_KEY=true; shift ;;
        --require-password)    REQUIRE_PASSWORD=true; shift ;;
        --rotate)              ROTATE_SECRET=true; shift ;;
        -h|--help)             usage ;;
        *)                     err "Unknown option: $1" ;;
    esac
done

# --- Validate root & SSH preflight (prevent lockout before touching packages/PAM) ---
[[ $(id -u) -eq 0 ]] || err "Must be run as root"
command -v sshd >/dev/null 2>&1 || err "sshd binary not found. Install openssh before configuring SSH TOTP."
[[ -f "$SSHD_CONFIG" ]] || err "sshd configuration not found: $SSHD_CONFIG"
[[ -f "$PAM_SSHD" ]] || err "PAM sshd configuration not found: $PAM_SSHD"

# --- Resolve target user ---
if [[ -z "$USERNAME" ]]; then
    if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
        USERNAME="$SUDO_USER"
    else
        # Find the first non-root user with a login shell and UID >= 1000
        USERNAME=$(awk -F: '$3 >= 1000 && $3 < 65534 && $7 !~ /(nologin|false)/ { print $1; exit }' /etc/passwd)
        [[ -n "$USERNAME" ]] || err "Could not determine target user. Specify with -u USERNAME"
    fi
fi

# Verify the user exists
id "$USERNAME" &>/dev/null || err "User '$USERNAME' does not exist"

USER_HOME=$(getent passwd "$USERNAME" | cut -d: -f6)
[[ -n "$USER_HOME" ]] || err "Could not resolve home directory for user '$USERNAME'"
[[ -d "$USER_HOME" ]] || err "Home directory '$USER_HOME' does not exist for user '$USERNAME'"

TOTP_SECRET="$USER_HOME/.google_authenticator"

# Refuse to enforce publickey,keyboard-interactive if target user has no authorized_keys
if [[ ! -s "$USER_HOME/.ssh/authorized_keys" ]]; then
    if [[ "$ALLOW_NO_SSH_KEY" != true ]]; then
        err "Missing or empty $USER_HOME/.ssh/authorized_keys for '$USERNAME'. Configure SSH public-key authentication first (or pass --allow-no-ssh-key to override)."
    fi
fi

# Create the log without a predictable filename or permissive caller umask.
# File descriptor 3 remains terminal-only for QR codes and recovery codes.
install -d -m 0755 /var/log
LOGFILE=$(umask 077; mktemp "/var/log/totp-setup-$(date +%Y%m%d-%H%M%S).XXXXXX.log")
chmod 0600 "$LOGFILE"
exec 3>&1
exec > >(tee -a "$LOGFILE") 2>&1

info "Target user: $USERNAME"
info "Home directory: $USER_HOME"
info "TOTP secret file: $TOTP_SECRET"
info "Log: $LOGFILE"

if [[ ! -s "$USER_HOME/.ssh/authorized_keys" ]]; then
    warn "No SSH public keys found in $USER_HOME/.ssh/authorized_keys (--allow-no-ssh-key enabled)"
fi

# Warn if global AllowUsers in sshd_config (or drop-ins) excludes $USERNAME
check_allow_users() {
    local user="$1" token pattern matched=false f
    local -a allow_tokens=() files=("$SSHD_CONFIG")
    shopt -s nullglob
    for f in /etc/ssh/sshd_config.d/*.conf; do
        files+=("$f")
    done
    shopt -u nullglob

    mapfile -t allow_tokens < <(
        awk '
            /^[[:space:]]*[Mm][Aa][Tt][Cc][Hh]([[:space:]]|$)/ { in_match = 1 }
            !in_match && /^[[:space:]]*[Aa][Ll][Ll][Oo][Ww][Uu][Ss][Ee][Rr][Ss][[:space:]]+/ {
                line = $0
                sub(/#.*/, "", line)
                sub(/^[[:space:]]*[Aa][Ll][Ll][Oo][Ww][Uu][Ss][Ee][Rr][Ss][[:space:]]+/, "", line)
                n = split(line, toks, /[[:space:]]+/)
                for (i = 1; i <= n; i++) {
                    if (toks[i] != "") print toks[i]
                }
            }
        ' "${files[@]}" 2>/dev/null
    )

    if (( ${#allow_tokens[@]} > 0 )); then
        for token in "${allow_tokens[@]}"; do
            pattern="${token%%@*}"
            # shellcheck disable=SC2053
            if [[ "$user" == $pattern ]]; then
                matched=true
                break
            fi
        done
        if [[ "$matched" == false ]]; then
            warn "AllowUsers is active (${allow_tokens[*]}) and excludes '$user' — add '$user' to AllowUsers or SSH login will be denied."
        fi
    fi
}
check_allow_users "$USERNAME"

# =============================================================================
# ROLLBACK AND CLEANUP
# =============================================================================
# Candidates and rollback copies live in a root-private work directory. Once
# ROLLBACK_ARMED is true, any failure or interruption before completion puts
# the PAM and sshd files back as they were when this run started.

WORK_DIR=""
KEEP_WORK_DIR=false
INSTALL_TMP=""
ROLLBACK_ARMED=false
DROPIN_CREATED=false
SSHD_RELOAD_ATTEMPTED=false
PAM_BACKUP=""
SSHD_BACKUP=""

# Rollback messages bypass the tee pipe, which may already be gone (Ctrl-C).
rollback_note() {
    { printf '%b[!]%b %s\n' "$C_YELLOW" "$C_NC" "$1" >&3; } 2>/dev/null
    { printf '[!] %s\n' "$1" >> "$LOGFILE"; } 2>/dev/null
    return 0
}

# Atomically replace $2 with a copy of $1 (same owner, mode and timestamps).
restore_file() {
    local tmp
    tmp=$(umask 077; mktemp "${2}.XXXXXX") || return 1
    if cp -p -- "$1" "$tmp" && mv -f -- "$tmp" "$2"; then
        return 0
    fi
    rm -f -- "$tmp"
    return 1
}

rollback() {
    local failed=false
    rollback_note "Setup did not complete. Restoring the PAM and sshd files changed by this run..."
    if [[ -f "$WORK_DIR/rollback.pam" ]]; then
        restore_file "$WORK_DIR/rollback.pam" "$PAM_SSHD" || failed=true
    fi
    if [[ -f "$WORK_DIR/rollback.sshd_config" ]]; then
        restore_file "$WORK_DIR/rollback.sshd_config" "$SSHD_CONFIG" || failed=true
    fi
    if [[ -f "$WORK_DIR/rollback.dropin" ]]; then
        restore_file "$WORK_DIR/rollback.dropin" "$SSHD_DROPIN" || failed=true
    elif [[ "$DROPIN_CREATED" == true ]]; then
        rm -f -- "$SSHD_DROPIN" || failed=true
    fi

    if [[ "$failed" == true ]]; then
        KEEP_WORK_DIR=true
        rollback_note "AUTOMATIC RESTORE FAILED. Do not restart sshd or close this session before restoring the files by hand."
        rollback_note "Copies of the previous files are kept in $WORK_DIR (rollback.pam, rollback.sshd_config, rollback.dropin)."
        return 0
    fi
    rollback_note "Restored $PAM_SSHD and the sshd configuration to their previous state."

    if ! sshd -t >/dev/null 2>&1; then
        rollback_note "The restored sshd configuration does not pass 'sshd -t': it was already invalid before this run. Fix it before sshd is restarted."
    elif [[ "$SSHD_RELOAD_ATTEMPTED" == true ]]; then
        # sshd may have loaded the new configuration; put the restored one back in memory.
        if systemctl is-active --quiet sshd; then
            if systemctl reload sshd >/dev/null 2>&1; then
                rollback_note "Reloaded sshd with the restored configuration."
            else
                rollback_note "Could not reload sshd with the restored configuration; check 'systemctl status sshd'."
            fi
        elif systemctl start sshd >/dev/null 2>&1; then
            rollback_note "sshd was not running after the failed reload; started it with the restored configuration."
        else
            rollback_note "sshd is NOT running and could not be started; check 'systemctl status sshd' from the console."
        fi
    fi
}

on_exit() {
    local rc=$?
    trap - EXIT
    trap '' INT TERM HUP PIPE
    set +e
    if [[ -n "$INSTALL_TMP" ]]; then
        rm -f -- "$INSTALL_TMP"
    fi
    if [[ "$ROLLBACK_ARMED" == true ]]; then
        (( rc != 0 )) || rc=1
        rollback
    fi
    if [[ -n "$WORK_DIR" && "$KEEP_WORK_DIR" != true ]]; then
        rm -rf -- "$WORK_DIR"
    fi
    exit "$rc"
}

# Atomically install a copy of $1 at $2 with mode $3, owned by root.
install_file() {
    local src="$1" dst="$2" mode="$3"
    INSTALL_TMP=$(umask 077; mktemp "${dst}.XXXXXX")
    cat -- "$src" > "$INSTALL_TMP"
    chown root:root "$INSTALL_TMP"
    chmod "$mode" "$INSTALL_TMP"
    mv -f -- "$INSTALL_TMP" "$dst"
    INSTALL_TMP=""
}

# Run a command as the target user. Root never reads, chmods or chowns paths
# inside the user's home: the user controls them and could swap in a symlink.
as_user() { runuser -u "$USERNAME" -- env HOME="$USER_HOME" "$@"; }
user_has_secret() { as_user test -f "$TOTP_SECRET" && as_user test -s "$TOTP_SECRET"; }

# =============================================================================
# SSHD HELPERS: decide where the settings go and validate a candidate
# =============================================================================
# sshd keeps the FIRST value it reads for each keyword. Stock Arch starts
# sshd_config with "Include /etc/ssh/sshd_config.d/*.conf" and ships
# 99-archlinux.conf with "KbdInteractiveAuthentication no", so settings written
# further down the main file lose. In that layout the settings go into a
# drop-in that sorts first; without such an Include the main file is edited.

SSHD_STRATEGY=""
SSHD_VALIDATE_ERROR=""
SSHD_INCLUDE_PATTERNS=()

# Scan the Include directives of sshd config file $2.
#   list             print the file-name pattern of every Include before the
#                    first Match block that points into $SSHD_DROPIN_DIR
#   redirect NEWDIR  print the file with every such Include pointed at NEWDIR,
#                    so a candidate can be tested without touching the live dir
# Relative Include paths are relative to $SSHD_DIR, as in sshd itself.
sshd_include_scan() {
    local mode="$1" file="$2" newdir="${3:-}"
    SCAN_MODE="$mode" SCAN_SSHD_DIR="$SSHD_DIR" SCAN_DROPIN_DIR="$SSHD_DROPIN_DIR" SCAN_NEWDIR="$newdir" awk '
        BEGIN { mode = ENVIRON["SCAN_MODE"] }
        /^[[:space:]]*[Mm][Aa][Tt][Cc][Hh]([[:space:]]|$)/ { in_match = 1 }
        {
            line = $0
            sub(/^[[:space:]]+/, "", line)
            if (tolower(line) !~ /^include[[:space:]=]/ || (mode == "list" && in_match)) {
                if (mode == "redirect") print
                next
            }
            sub(/^[A-Za-z]+[[:space:]]*=?[[:space:]]*/, "", line)
            n = split(line, toks, /[[:space:]]+/)
            out = "Include"
            changed = 0
            for (i = 1; i <= n; i++) {
                path = toks[i]
                if (path ~ /^#/) break
                gsub(/"/, "", path)
                if (path == "") continue
                first = substr(path, 1, 1)
                if (first != "/" && first != "~") path = ENVIRON["SCAN_SSHD_DIR"] "/" path
                dir = path
                sub(/\/[^\/]*$/, "", dir)
                base = path
                sub(/^.*\//, "", base)
                if (dir == ENVIRON["SCAN_DROPIN_DIR"]) {
                    if (mode == "list") print base
                    path = ENVIRON["SCAN_NEWDIR"] "/" base
                    changed = 1
                }
                out = out " \"" path "\""
            }
            if (mode == "redirect") print (changed ? out : $0)
        }
    ' "$file"
}

sshd_dropin_content() {
    cat <<EOF
# Managed by totp.sh: SSH public key + TOTP (keyboard-interactive via PAM).
# sshd keeps the first value it reads for each keyword, so this file must sort
# before the other files in ${SSHD_DROPIN_DIR}. Re-running totp.sh rewrites it.
AuthenticationMethods publickey,keyboard-interactive
KbdInteractiveAuthentication yes
UsePAM yes
EOF
}

# Helper: set or update a global directive in sshd config file $1 BEFORE any Match block
sshd_set() {
    local file="$1"
    local key="$2"
    local value="$3"
    local tmp mode
    tmp=$(umask 077; mktemp "${file}.XXXXXX")

    mode=$(SSHD_KEY="$key" awk '
        BEGIN { key_low = tolower(ENVIRON["SSHD_KEY"]) }
        /^[[:space:]]*[Mm][Aa][Tt][Cc][Hh]([[:space:]]|$)/ { exit }
        {
            line = $0
            sub(/^[[:space:]]+/, "", line)
            if (line ~ /^#/) {
                sub(/^#[[:space:]]*/, "", line)
                nc = split(line, cparts, /[[:space:]]+/)
                if (!has_comment && tolower(cparts[1]) == key_low && nc >= 2) {
                    has_comment = 1
                }
                next
            }
            np = split(line, parts, /[[:space:]]+/)
            if (np >= 1 && tolower(parts[1]) == key_low) {
                has_active = 1
                exit
            }
        }
        END {
            if (has_active) print "active"
            else if (has_comment) print "comment"
            else print "insert"
        }
    ' "$file")

    SSHD_KEY="$key" SSHD_VAL="$value" SSHD_MODE="$mode" awk '
        BEGIN {
            key_low = tolower(ENVIRON["SSHD_KEY"])
            mode = ENVIRON["SSHD_MODE"]
            in_match = 0
            done = 0
        }
        !in_match && /^[[:space:]]*[Mm][Aa][Tt][Cc][Hh]([[:space:]]|$)/ {
            if (!done) {
                print ENVIRON["SSHD_KEY"] " " ENVIRON["SSHD_VAL"]
                print ""
                done = 1
            }
            in_match = 1
        }
        !in_match {
            line = $0
            sub(/^[[:space:]]+/, "", line)
            if (mode == "active" && line !~ /^#/) {
                np = split(line, parts, /[[:space:]]+/)
                if (np >= 1 && tolower(parts[1]) == key_low) {
                    if (!done) {
                        print ENVIRON["SSHD_KEY"] " " ENVIRON["SSHD_VAL"]
                        done = 1
                    }
                    next
                }
            } else if (mode == "comment" && !done && line ~ /^#/) {
                sub(/^#[[:space:]]*/, "", line)
                nc = split(line, cparts, /[[:space:]]+/)
                if (nc >= 2 && tolower(cparts[1]) == key_low) {
                    print ENVIRON["SSHD_KEY"] " " ENVIRON["SSHD_VAL"]
                    done = 1
                    next
                }
            }
        }
        { print }
        END {
            if (!done) {
                print ENVIRON["SSHD_KEY"] " " ENVIRON["SSHD_VAL"]
            }
        }
    ' "$file" > "$tmp"

    chown root:root "$tmp"
    chmod 0600 "$tmp"
    mv -f -- "$tmp" "$file"
    case "$mode" in
        active)  info "Updated: ${key} ${value}" ;;
        comment) info "Uncommented and set: ${key} ${value}" ;;
        insert)  info "Added (before any Match block): ${key} ${value}" ;;
    esac
}

# Apply the three settings to a copy of the main sshd config ($1).
sshd_edit_main() {
    local file="$1"
    # Remove deprecated ChallengeResponseAuthentication if present
    sed -i -E 's|^([[:space:]]*ChallengeResponseAuthentication[[:space:]]+.*)$|# \1 # deprecated; replaced by KbdInteractiveAuthentication|' "$file"

    sshd_set "$file" "AuthenticationMethods" "publickey,keyboard-interactive"
    sshd_set "$file" "KbdInteractiveAuthentication" "yes"

    # Ensure UsePAM is enabled (required for PAM-based TOTP)
    sshd_set "$file" "UsePAM" "yes"
}

# Build a candidate for strategy $1 (dropin|main) under $WORK_DIR/$1 without
# touching the live files.
#   dropin  unchanged main file whose Include points at a copy of the drop-in
#           directory that also holds our drop-in
#   main    main file with the settings applied; its Includes still read the
#           live drop-ins, which this strategy does not change
sshd_build_candidate() {
    local strategy="$1" dir="$WORK_DIR/$1" f
    rm -rf -- "$dir"
    mkdir -- "$dir"
    if [[ "$strategy" == "dropin" ]]; then
        mkdir -- "$dir/sshd_config.d"
        shopt -s nullglob
        for f in "$SSHD_DROPIN_DIR"/*; do
            if [[ -f "$f" ]]; then
                cp -L -- "$f" "$dir/sshd_config.d/"
            fi
        done
        shopt -u nullglob
        sshd_dropin_content > "$dir/sshd_config.d/${SSHD_DROPIN##*/}"
        sshd_include_scan redirect "$SSHD_CONFIG" "$dir/sshd_config.d" > "$dir/sshd_config"
    else
        cp -- "$SSHD_CONFIG" "$dir/sshd_config"
        sshd_edit_main "$dir/sshd_config" > "$dir/edits.log"
    fi
}

# Check "sshd -T" output ($1) for the settings publickey + TOTP needs. On a
# mismatch, describe it in SSHD_VALIDATE_ERROR and return 1.
sshd_effective_check() {
    local eff="$1" methods kbd pam
    local -a bad=()
    # sshd -T prints the keywords in lowercase in older OpenSSH releases and in
    # CamelCase in newer ones (seen with 10.6), so compare case-insensitively.
    methods=$(awk 'tolower($1) == "authenticationmethods" { $1 = ""; sub(/^[[:space:]]+/, ""); print; exit }' <<< "$eff")
    kbd=$(awk 'tolower($1) == "kbdinteractiveauthentication" { print $2; exit }' <<< "$eff")
    pam=$(awk 'tolower($1) == "usepam" { print $2; exit }' <<< "$eff")
    if [[ "$methods" != "publickey,keyboard-interactive" ]]; then
        bad+=("effective AuthenticationMethods is '${methods:-unset}' (expected 'publickey,keyboard-interactive')")
    fi
    if [[ "$kbd" != "yes" ]]; then
        bad+=("effective KbdInteractiveAuthentication is '${kbd:-unset}' (expected 'yes')")
    fi
    if [[ "$pam" != "yes" ]]; then
        bad+=("effective UsePAM is '${pam:-unset}' (expected 'yes')")
    fi
    if (( ${#bad[@]} > 0 )); then
        SSHD_VALIDATE_ERROR=$(printf '%s; ' "${bad[@]}")
        SSHD_VALIDATE_ERROR=${SSHD_VALIDATE_ERROR%; }
        return 1
    fi
    return 0
}

# Validate sshd config file $1 (a candidate or the live file): it must pass
# "sshd -t" and give the target user the effective settings checked above.
sshd_validate() {
    local cfg="$1" out eff
    SSHD_VALIDATE_ERROR=""
    if ! out=$(sshd -t -f "$cfg" 2>&1); then
        SSHD_VALIDATE_ERROR="sshd -t failed: ${out//$'\n'/; }"
        return 1
    fi
    eff=$(sshd -T -f "$cfg" -C "user=${USERNAME},host=localhost,addr=127.0.0.1" 2>/dev/null \
        || sshd -T -f "$cfg" 2>/dev/null || true)
    if [[ -z "$eff" ]]; then
        SSHD_VALIDATE_ERROR="sshd -T did not print the effective settings"
        return 1
    fi
    sshd_effective_check "$eff"
}

# Rewrite candidate paths in an sshd message ($1) back to the live file names.
sshd_live_paths() {
    local text="$1" edited="${SSHD_CONFIG} (edited copy)"
    text=${text//"$WORK_DIR/dropin/sshd_config.d"/$SSHD_DROPIN_DIR}
    text=${text//"$WORK_DIR/dropin/sshd_config"/$SSHD_CONFIG}
    text=${text//"$WORK_DIR/main/sshd_config"/$edited}
    printf '%s' "$text"
}

# Name the lines that keep the settings from taking effect, for the error
# message. $1 is the strategy that was expected to work:
#   dropin  only what is read before our drop-in can override it: the main
#           file up to its first Include, drop-ins that sort before ours, and
#           Match blocks
#   main    what is left in the edited copy of the main file (Match blocks)
#           and every included drop-in
sshd_list_conflicts() {
    local view="$1" main="$SSHD_CONFIG" f pat
    local LC_ALL=C
    local -a files=()
    if [[ "$view" == "main" ]]; then
        main="$WORK_DIR/main/sshd_config"
    fi
    files=("$main")
    shopt -s nullglob
    for f in "$SSHD_DROPIN_DIR"/*; do
        [[ -f "$f" && "$f" != "$SSHD_DROPIN" ]] || continue
        if [[ "$view" == "dropin" && "$f" > "$SSHD_DROPIN" ]]; then
            continue
        fi
        for pat in "${SSHD_INCLUDE_PATTERNS[@]}"; do
            # shellcheck disable=SC2053
            if [[ "${f##*/}" == $pat ]]; then
                files+=("$f")
                break
            fi
        done
    done
    shopt -u nullglob
    CONFLICT_VIEW="$view" CONFLICT_MAIN="$main" CONFLICT_LIVE="$SSHD_CONFIG" awk '
        FNR == 1 { in_match = 0; seen_include = 0 }
        {
            line = $0
            sub(/^[[:space:]]+/, "", line)
            if (line == "" || line ~ /^#/) next
            n = split(line, parts, /[[:space:]=]+/)
            key = tolower(parts[1])
            if (key == "match") in_match = 1
            if (key == "include") seen_include = 1
            if (key == "authenticationmethods") want = "publickey,keyboard-interactive"
            else if (key == "kbdinteractiveauthentication" || key == "challengeresponseauthentication" || key == "usepam") want = "yes"
            else next
            extra = (n > 2 && parts[3] != "" && parts[3] !~ /^#/)
            if (tolower(parts[2]) == want && !(key == "authenticationmethods" && extra)) next
            is_main = (FILENAME == ENVIRON["CONFLICT_MAIN"])
            if (is_main && ENVIRON["CONFLICT_VIEW"] == "dropin" && seen_include && !in_match) next
            printf "%s: %s\n", (is_main ? ENVIRON["CONFLICT_LIVE"] : FILENAME), $0
        }
    ' "${files[@]}" 2>/dev/null || true
}

# Decide where the three settings must go so that they win, and prove it on a
# candidate before anything live is touched. Sets SSHD_STRATEGY (dropin|main),
# or exits with nothing changed when neither candidate gives the right result.
sshd_plan() {
    local pat line conflicts view=main covered=false
    local -a reasons=()
    SSHD_STRATEGY=""
    SSHD_INCLUDE_PATTERNS=()
    if [[ -d "$SSHD_DROPIN_DIR" ]]; then
        mapfile -t SSHD_INCLUDE_PATTERNS < <(sshd_include_scan list "$SSHD_CONFIG")
    fi
    for pat in "${SSHD_INCLUDE_PATTERNS[@]}"; do
        # shellcheck disable=SC2053
        if [[ "${SSHD_DROPIN##*/}" == $pat ]]; then
            covered=true
            break
        fi
    done

    if [[ "$covered" == true ]]; then
        view=dropin
        sshd_build_candidate dropin
        if sshd_validate "$WORK_DIR/dropin/sshd_config"; then
            SSHD_STRATEGY="dropin"
            return 0
        fi
        reasons+=("With a drop-in at ${SSHD_DROPIN}: $(sshd_live_paths "$SSHD_VALIDATE_ERROR")")
    fi
    sshd_build_candidate main
    if sshd_validate "$WORK_DIR/main/sshd_config"; then
        SSHD_STRATEGY="main"
        return 0
    fi
    reasons+=("With the settings written to ${SSHD_CONFIG}: $(sshd_live_paths "$SSHD_VALIDATE_ERROR")")

    warn "sshd cannot be made to require publickey + TOTP for '$USERNAME' (needs AuthenticationMethods publickey,keyboard-interactive, KbdInteractiveAuthentication yes, UsePAM yes):"
    for line in "${reasons[@]}"; do
        warn "  $line"
    done
    conflicts=$(sshd_list_conflicts "$view")
    if [[ -n "$conflicts" ]]; then
        warn "Overriding settings (sshd keeps the first value it reads; Match blocks apply per user):"
        while IFS= read -r line; do
            warn "  $line"
        done <<< "$conflicts"
    fi
    err "No PAM or sshd file was changed. Remove the override and re-run."
}

sshd_plan_report() {
    if [[ "$SSHD_STRATEGY" == "dropin" ]]; then
        info "sshd plan: $SSHD_CONFIG includes $SSHD_DROPIN_DIR, so the settings go into $SSHD_DROPIN (read first)"
    else
        info "sshd plan: the settings go into $SSHD_CONFIG"
    fi
    info "Candidate passed 'sshd -t' and the effective-settings check ('sshd -T') for '$USERNAME'"
}

# =============================================================================
# PAM HELPERS: bring /etc/pam.d/sshd to the policy the flags ask for
# =============================================================================

PAM_LINE="auth required pam_google_authenticator.so secret=\${HOME}/.google_authenticator"
if [[ "$ALLOW_MISSING_TOTP" == true ]]; then
    PAM_LINE="auth required pam_google_authenticator.so nullok secret=\${HOME}/.google_authenticator"
fi
PAM_MODULE_RE='^[[:space:]]*auth[[:space:]]+.*pam_google_authenticator\.so'
PAM_NULLOK_RE='^[[:space:]]*auth[[:space:]]+.*pam_google_authenticator\.so.*[[:space:]]nullok([[:space:]]|$)'
# With nullok the module returns PAM_IGNORE for users without a secret, and a
# PAM stack in which no module succeeds is denied. The staged rollout without
# a password prompt therefore needs a rule that succeeds; a failed TOTP code
# from an enrolled user stays fatal because the TOTP rule is "required".
PAM_PERMIT_LINE="auth required pam_permit.so # added by totp.sh (staged rollout: lets users without a TOTP secret pass; removed again together with nullok)"
PAM_PERMIT_RE='^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_permit\.so[[:space:]]+# added by totp\.sh'

# Edit PAM file $1 (a copy of /etc/pam.d/sshd) so that it ends up in the state
# the current flags ask for, whatever an earlier run left behind.
pam_configure() {
    local file="$1" tmp others line

    if [[ "$REQUIRE_PASSWORD" == false ]]; then
        # Comment out 'auth include system-remote-login' so keyboard-interactive
        # prompts ONLY for TOTP (not a Linux account password, which locks out
        # passwordless SSH-key accounts).
        # ('/' delimiters: the pattern itself needs '|' for the alternation.)
        sed -i -E 's/^([[:space:]]*auth[[:space:]]+(include|substack)[[:space:]]+system-remote-login([[:space:]].*)?)$/# \1 # disabled by totp.sh (publickey + TOTP without password)/' "$file"
        info "Disabled PAM password prompt (system-remote-login auth) for publickey + TOTP flow"
    else
        sed -i -E -e 's/^#[[:space:]]*([[:space:]]*auth[[:space:]]+(include|substack)[[:space:]]+system-remote-login[^#]*)# disabled by totp\.sh.*/\1/' \
            -e 'T' -e 's/[[:space:]]+$//' "$file"
        info "Retained PAM password prompt (--require-password)"
    fi

    # The staged-rollout pam_permit rule is put back below only when needed.
    sed -i -E "/${PAM_PERMIT_RE}/d" "$file"

    if grep -Eq "$PAM_MODULE_RE" "$file"; then
        if [[ "$ALLOW_MISSING_TOTP" == true ]]; then
            sed -i -E "/${PAM_MODULE_RE}/ { /${PAM_NULLOK_RE}/! s/pam_google_authenticator\\.so/& nullok/; }" "$file"
            info "Existing pam_google_authenticator rule kept; nullok is set (staged rollout)"
        else
            # Default to fail closed. Preserve other PAM options while removing nullok
            # from active google-authenticator auth lines.
            sed -i -E '/^[[:space:]]*auth[[:space:]]+.*pam_google_authenticator\.so/ s/[[:space:]]+nullok([[:space:]]|$)/\1/g' "$file"
            info "Existing pam_google_authenticator rule kept; nullok is not set (mandatory)"
        fi
    else
        # Append the TOTP auth line after existing auth lines
        echo "" >> "$file"
        echo "# TOTP two-factor authentication (added by totp.sh)" >> "$file"
        echo "$PAM_LINE" >> "$file"
        info "Added pam_google_authenticator to the sshd PAM auth stack"
    fi

    if [[ "$ALLOW_MISSING_TOTP" == true && "$REQUIRE_PASSWORD" == false ]]; then
        tmp=$(umask 077; mktemp "${file}.XXXXXX")
        PAM_PERMIT="$PAM_PERMIT_LINE" awk '
            { lines[NR] = $0 }
            /^[[:space:]]*auth[[:space:]]+.*pam_google_authenticator\.so/ { last = NR }
            END {
                for (i = 1; i <= NR; i++) {
                    print lines[i]
                    if (i == last) print ENVIRON["PAM_PERMIT"]
                }
            }
        ' "$file" > "$tmp"
        mv -f -- "$tmp" "$file"
        info "Added 'auth required pam_permit.so' after the TOTP rule so users without a secret are not denied"
        others=$(grep -E '^[[:space:]]*-?auth[[:space:]]' "$file" \
            | grep -Ev 'pam_google_authenticator\.so|pam_permit\.so[[:space:]]+# added by totp\.sh' || true)
        if [[ -n "$others" ]]; then
            warn "Other active auth rules remain in $PAM_SSHD; with pam_permit after them, rules that are not 'required'/'requisite' no longer decide the result:"
            while IFS= read -r line; do
                warn "  $line"
            done <<< "$others"
        fi
    fi
}

# Exit unless PAM file $1 matches the policy the current flags ask for.
pam_verify() {
    local file="$1" total with_nullok
    total=$(grep -Ec "$PAM_MODULE_RE" "$file" || true)
    with_nullok=$(grep -Ec "$PAM_NULLOK_RE" "$file" || true)
    (( total > 0 )) || err "No active TOTP PAM rule was installed"
    if [[ "$ALLOW_MISSING_TOTP" == false ]]; then
        (( with_nullok == 0 )) || err "Could not remove nullok from the active TOTP PAM rule"
        if grep -Eq "$PAM_PERMIT_RE" "$file"; then
            err "Could not remove the staged-rollout pam_permit rule"
        fi
    else
        (( with_nullok == total )) || err "Could not add nullok to the active TOTP PAM rule"
        if [[ "$REQUIRE_PASSWORD" == false ]] && ! grep -Eq "$PAM_PERMIT_RE" "$file"; then
            err "Could not add the staged-rollout pam_permit rule"
        fi
    fi
}

# =============================================================================
# 1. VALIDATE A CANDIDATE SSHD CONFIGURATION (nothing is changed yet)
# =============================================================================

WORK_DIR=$(umask 077; mktemp -d /run/totp-setup.XXXXXX 2>/dev/null || mktemp -d /tmp/totp-setup.XXXXXX)
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
trap 'exit 141' PIPE

msg "Checking that sshd can enforce publickey + TOTP before changing anything..."
sshd_plan
sshd_plan_report
PLANNED_STRATEGY="$SSHD_STRATEGY"

# =============================================================================
# 2. INSTALL PACKAGES
# =============================================================================

msg "Installing libpam-google-authenticator and qrencode..."

pacman -Syu --noconfirm --needed libpam-google-authenticator qrencode

info "google-authenticator version: $(google-authenticator --version 2>&1 || echo 'unknown')"

# =============================================================================
# 3. CREATE THE USER'S TOTP SECRET
# =============================================================================

# Create and verify the user's secret before changing PAM or sshd. A failed
# enrollment therefore cannot leave SSH in either a fail-open or lockout state.
# An existing secret is kept: re-running the script (for example to end a
# staged rollout) must not invalidate the user's authenticator app and scratch
# codes. Only --rotate replaces it.
if user_has_secret && [[ "$ROTATE_SECRET" != true ]]; then
    SECRET_CREATED=false
    msg "User '$USERNAME' already has a TOTP secret; keeping it (secret and scratch codes are unchanged)"
    info "Pass --rotate to replace it. The authenticator app must then be enrolled again."
else
    if user_has_secret; then
        warn "--rotate: replacing the existing TOTP secret and scratch codes of '$USERNAME'"
    fi
    SECRET_CREATED=true
    msg "Running google-authenticator for user '$USERNAME'..."
    info "A QR code will be displayed below. Scan it with your authenticator app."
    echo

    # -t time-based, -d no token reuse, -r/-R rate limit, -w clock-skew window,
    # -f force-write, and -Q UTF8 for terminal QR rendering.
    ( cd "$USER_HOME" && runuser -u "$USERNAME" -- env HOME="$USER_HOME" google-authenticator -t -d -r 3 -R 30 -w 3 -f -Q UTF8 ) >&3 2>&3
    echo
fi

# Check and fix the secret file as the user. A root chmod/chown here would
# follow a symlink planted in the user's home directory.
msg "Checking the TOTP secret file as '$USERNAME'..."
user_has_secret || err "TOTP secret file was not created at $TOTP_SECRET"
as_user chmod 600 -- "$TOTP_SECRET" || err "Could not set mode 600 on $TOTP_SECRET as '$USERNAME'"
SECRET_STAT=$(as_user stat -L -c '%u %a' -- "$TOTP_SECRET") || err "Could not stat $TOTP_SECRET as '$USERNAME'"
if [[ "$SECRET_STAT" != "$(id -u "$USERNAME") 600" ]]; then
    err "$TOTP_SECRET must be owned by '$USERNAME' with mode 600 (found uid and mode: $SECRET_STAT)"
fi
info "$TOTP_SECRET — mode 600, owned by $USERNAME"

# =============================================================================
# 4. PREPARE THE PAM AND SSHD CHANGES (still nothing live is changed)
# =============================================================================

msg "Preparing the PAM and sshd changes..."

# Plan again: the package upgrade above may have changed the sshd files.
sshd_plan
if [[ "$SSHD_STRATEGY" == "$PLANNED_STRATEGY" ]]; then
    info "sshd candidate validated again after the package step"
else
    warn "The sshd files changed during the package step; the plan was updated"
    sshd_plan_report
fi

cp -- "$PAM_SSHD" "$WORK_DIR/pam.sshd"
pam_configure "$WORK_DIR/pam.sshd"
pam_verify "$WORK_DIR/pam.sshd"

# =============================================================================
# 5. APPLY TO PAM AND SSHD (restored automatically if anything fails)
# =============================================================================

# Keep exact copies for the rollback before the first live change. PAM goes
# first: a TOTP-only PAM stack is harmless while sshd still asks for the key
# alone, the reverse order would prompt key-only accounts for a password.
BACKUP_STAMP=$(date +%Y%m%d-%H%M%S)
cp -p -- "$PAM_SSHD" "$WORK_DIR/rollback.pam"
if [[ "$SSHD_STRATEGY" == "main" ]]; then
    cp -p -- "$SSHD_CONFIG" "$WORK_DIR/rollback.sshd_config"
elif [[ -e "$SSHD_DROPIN" ]]; then
    cp -p -- "$SSHD_DROPIN" "$WORK_DIR/rollback.dropin"
else
    DROPIN_CREATED=true
fi
ROLLBACK_ARMED=true

msg "Configuring PAM for SSH TOTP..."
PAM_BACKUP="${PAM_SSHD}.bak.${BACKUP_STAMP}"
cp -- "$PAM_SSHD" "$PAM_BACKUP"
info "Backed up $PAM_SSHD to $PAM_BACKUP"
install_file "$WORK_DIR/pam.sshd" "$PAM_SSHD" 0644
msg "Updated $PAM_SSHD"

msg "Configuring sshd for keyboard-interactive authentication..."
if [[ "$SSHD_STRATEGY" == "main" ]]; then
    # Back up sshd_config
    SSHD_BACKUP="${SSHD_CONFIG}.bak.${BACKUP_STAMP}"
    cp -- "$SSHD_CONFIG" "$SSHD_BACKUP"
    chmod 0600 "${SSHD_CONFIG}.bak."* 2>/dev/null || true
    info "Backed up $SSHD_CONFIG to $SSHD_BACKUP"
    install_file "$WORK_DIR/main/sshd_config" "$SSHD_CONFIG" 0600
    cat -- "$WORK_DIR/main/edits.log"
else
    install_file "$WORK_DIR/dropin/sshd_config.d/${SSHD_DROPIN##*/}" "$SSHD_DROPIN" 0600
    info "Installed $SSHD_DROPIN ($SSHD_CONFIG itself is not modified)"
fi
msg "sshd configuration updated"

# =============================================================================
# 6. VALIDATE THE LIVE CONFIGURATION AND RELOAD SSHD
# =============================================================================

# Validate the live files the same way as the candidate (sshd -t, then the
# effective settings for the target user: detects overrides in
# /etc/ssh/sshd_config.d/*.conf or Match blocks). A failure here rolls back.
info "Validating sshd configuration..."
if sshd_validate "$SSHD_CONFIG"; then
    msg "sshd configuration test passed (effective for '$USERNAME': AuthenticationMethods publickey,keyboard-interactive, KbdInteractiveAuthentication yes, UsePAM yes)"
else
    err "sshd configuration check failed after the change: ${SSHD_VALIDATE_ERROR}"
fi

pam_verify "$PAM_SSHD"
if [[ "$ALLOW_MISSING_TOTP" == false ]]; then
    TOTP_ENFORCEMENT="mandatory"
    msg "TOTP is mandatory for SSH users (fail-closed PAM policy)"
else
    TOTP_ENFORCEMENT="staged"
    warn "Staged rollout enabled: SSH users without TOTP secrets remain exempt via nullok"
fi

sshd -t || err "sshd configuration test failed before reload"
if systemctl is-active --quiet sshd; then
    msg "Reloading sshd without dropping existing sessions..."
    SSHD_RELOAD_ATTEMPTED=true
    systemctl reload sshd || err "systemctl reload sshd failed"
    systemctl is-active --quiet sshd && msg "sshd is running" || err "sshd is not active after the reload"
else
    warn "sshd.service is not currently active — skipping live reload (changes apply when sshd starts)"
fi

# PAM and sshd are consistent and live from here on: nothing left to roll back.
ROLLBACK_ARMED=false

# =============================================================================
# 7. PRINT EMERGENCY SCRATCH CODES AND INSTRUCTIONS
# =============================================================================

echo
echo -e "${C_GREEN}========================================================================${C_NC}"
echo -e "${C_GREEN} TOTP Two-Factor Authentication Setup Complete!${C_NC}"
echo -e "${C_GREEN}========================================================================${C_NC}"
echo
echo -e "${C_BLUE}User:${C_NC}              $USERNAME"
echo -e "${C_BLUE}Secret file:${C_NC}       $TOTP_SECRET"
echo -e "${C_BLUE}Auth method:${C_NC}       publickey + TOTP (keyboard-interactive)"
echo -e "${C_BLUE}Log:${C_NC}               $LOGFILE"
echo

# Extract and display emergency scratch codes (read as the user, not as root)
if user_has_secret; then
    if [[ "$SECRET_CREATED" == true ]]; then
        echo -e "${C_YELLOW}EMERGENCY SCRATCH CODES (save these in a secure location!):${C_NC}"
    else
        echo -e "${C_YELLOW}EMERGENCY SCRATCH CODES (existing secret kept; these are its unused codes):${C_NC}"
    fi
    echo -e "${C_YELLOW}Each code can only be used once.${C_NC}"
    echo
    # Scratch codes are the 8-digit numbers at the end of the file
    # (after the config lines that start with " or contain known options)
    mapfile -t SCRATCH_CODES < <(as_user grep -E '^[0-9]{8}$' "$TOTP_SECRET" || true)
    for code in "${SCRATCH_CODES[@]}"; do
        echo -e "  ${C_RED}$code${C_NC}"
    done
    echo
fi >&3

echo -e "${C_YELLOW}IMPORTANT — Test before closing this session:${C_NC}"
echo "  1. Open a NEW terminal window"
echo "  2. SSH into this server:  ssh $USERNAME@<server-ip>"
echo "  3. You will be prompted for your key passphrase, then a verification code"
echo "  4. Enter the 6-digit code from your authenticator app"
echo "  5. Only close THIS session after confirming the new one works"
echo
echo -e "${C_YELLOW}If locked out:${C_NC}"
echo "  - Use one of the emergency scratch codes above"
echo "  - Or access the server via console/physical access and undo this run:"
echo "    copy ${PAM_BACKUP} back to ${PAM_SSHD}"
if [[ "$SSHD_STRATEGY" == "main" ]]; then
    echo "    copy ${SSHD_BACKUP} back to ${SSHD_CONFIG}"
else
    echo "    remove ${SSHD_DROPIN}"
fi
echo "    then: systemctl restart sshd"
echo
if [[ "$TOTP_ENFORCEMENT" == "staged" ]]; then
    echo -e "${C_BLUE}To end the staged rollout and require TOTP:${C_NC}"
    echo "  Re-run without --allow-missing-totp after provisioning every SSH user."
    echo
else
    echo -e "${C_BLUE}TOTP enforcement:${C_NC} mandatory (nullok is absent)"
    echo
fi
echo -e "${C_BLUE}To add TOTP for another user:${C_NC}"
echo "  sudo $0 -u <username>"
echo
echo -e "${C_GREEN}Done.${C_NC}"
