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
#                             [--allow-no-ssh-key] [--require-password] [-h]
#
# Requirements:
#   - Arch Linux with pacman
#   - Root privileges
#   - SSH server (sshd) installed and running
#   - Public key authentication already configured for the target user
#
# What this script does:
#   1. Installs libpam-google-authenticator and qrencode
#   2. Creates and verifies the target user's TOTP secret
#   3. Configures fail-closed PAM authentication (unless explicitly staged)
#   4. Configures sshd for keyboard-interactive (publickey + TOTP)
#   5. Validates the complete SSH configuration
#   6. Reloads sshd without dropping existing sessions
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
SSHD_CONFIG="/etc/ssh/sshd_config"
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
  -h            Show this help

Examples:
  sudo $0                    # Configure TOTP for current sudo user
  sudo $0 -u alice           # Configure TOTP for user 'alice'
  sudo $0 -u alice --allow-missing-totp  # Explicit staged rollout
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
USER_GROUP=$(id -gn "$USERNAME")

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
# 1. INSTALL PACKAGES
# =============================================================================

msg "Installing libpam-google-authenticator and qrencode..."

pacman -Syu --noconfirm --needed libpam-google-authenticator qrencode

info "google-authenticator version: $(google-authenticator --version 2>&1 || echo 'unknown')"

# Create and verify the user's secret before changing PAM or sshd. A failed
# enrollment therefore cannot leave SSH in either a fail-open or lockout state.
msg "Running google-authenticator for user '$USERNAME'..."
info "A QR code will be displayed below. Scan it with your authenticator app."
echo

# -t time-based, -d no token reuse, -r/-R rate limit, -w clock-skew window,
# -f force-write, and -Q UTF8 for terminal QR rendering.
( cd "$USER_HOME" && runuser -u "$USERNAME" -- env HOME="$USER_HOME" google-authenticator -t -d -r 3 -R 30 -w 3 -f -Q UTF8 ) >&3 2>&3
echo

msg "Setting permissions on TOTP secret file..."
if [[ -f "$TOTP_SECRET" && -s "$TOTP_SECRET" ]]; then
    chmod 600 "$TOTP_SECRET"
    chown "$USERNAME:$USER_GROUP" "$TOTP_SECRET"
    info "$TOTP_SECRET — mode 600, owned by $USERNAME:$USER_GROUP"
else
    err "TOTP secret file was not created at $TOTP_SECRET"
fi

# =============================================================================
# 3. CONFIGURE PAM FOR SSH TOTP
# =============================================================================

msg "Configuring PAM for SSH TOTP..."

PAM_LINE="auth required pam_google_authenticator.so secret=\${HOME}/.google_authenticator"
if [[ "$ALLOW_MISSING_TOTP" == true ]]; then
    PAM_LINE="auth required pam_google_authenticator.so nullok secret=\${HOME}/.google_authenticator"
fi
PAM_MODULE_RE='^[[:space:]]*auth[[:space:]]+.*pam_google_authenticator\.so'
PAM_NULLOK_RE='^[[:space:]]*auth[[:space:]]+.*pam_google_authenticator\.so.*[[:space:]]nullok([[:space:]]|$)'

cp "$PAM_SSHD" "${PAM_SSHD}.bak.$(date +%Y%m%d-%H%M%S)"
info "Backed up $PAM_SSHD"

if [[ "$REQUIRE_PASSWORD" == false ]]; then
    # Comment out 'auth include system-remote-login' so keyboard-interactive
    # prompts ONLY for TOTP (not a Linux account password, which locks out
    # passwordless SSH-key accounts).
    sed -i -E 's|^([[:space:]]*auth[[:space:]]+(include|substack)[[:space:]]+system-remote-login([[:space:]].*)?)$|# \1 # disabled by totp.sh (publickey + TOTP without password)|' "$PAM_SSHD"
    info "Disabled PAM password prompt (system-remote-login auth) for publickey + TOTP flow"
else
    sed -i -E 's|^#[[:space:]]*([[:space:]]*auth[[:space:]]+(include|substack)[[:space:]]+system-remote-login[^#]*)# disabled by totp\.sh.*|\1|' "$PAM_SSHD"
    info "Retained PAM password prompt (--require-password)"
fi

if grep -Eq "$PAM_MODULE_RE" "$PAM_SSHD" 2>/dev/null; then
    warn "PAM is already configured for google-authenticator in $PAM_SSHD"
    info "Existing line:"
    { grep "pam_google_authenticator" "$PAM_SSHD" || true; } | while IFS= read -r line; do
        info "  $line"
    done
else
    # Append the TOTP auth line after existing auth lines
    echo "" >> "$PAM_SSHD"
    echo "# TOTP two-factor authentication (added by totp.sh)" >> "$PAM_SSHD"
    echo "$PAM_LINE" >> "$PAM_SSHD"

    msg "Added pam_google_authenticator to $PAM_SSHD"
fi
chown root:root "$PAM_SSHD"
chmod 0644 "$PAM_SSHD"

# =============================================================================
# 4. CONFIGURE SSHD FOR KEYBOARD-INTERACTIVE (PUBLICKEY + TOTP)
# =============================================================================

msg "Configuring sshd for keyboard-interactive authentication..."

# Back up sshd_config
cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak.$(date +%Y%m%d-%H%M%S)"
chmod 0600 "${SSHD_CONFIG}.bak."* 2>/dev/null || true
info "Backed up $SSHD_CONFIG"

# Helper: set or update a global directive in sshd_config BEFORE any Match block
sshd_set() {
    local key="$1"
    local value="$2"
    local tmp mode
    tmp=$(umask 077; mktemp "${SSHD_CONFIG}.XXXXXX")

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
    ' "$SSHD_CONFIG")

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
    ' "$SSHD_CONFIG" > "$tmp"

    chown root:root "$tmp"
    chmod 0600 "$tmp"
    mv -f -- "$tmp" "$SSHD_CONFIG"
    case "$mode" in
        active)  info "Updated: ${key} ${value}" ;;
        comment) info "Uncommented and set: ${key} ${value}" ;;
        insert)  info "Added (before any Match block): ${key} ${value}" ;;
    esac
}

# Remove deprecated ChallengeResponseAuthentication if present
sed -i -E 's|^([[:space:]]*ChallengeResponseAuthentication[[:space:]]+.*)$|# \1 # deprecated; replaced by KbdInteractiveAuthentication|' "$SSHD_CONFIG"

sshd_set "AuthenticationMethods" "publickey,keyboard-interactive"
sshd_set "KbdInteractiveAuthentication" "yes"

# Ensure UsePAM is enabled (required for PAM-based TOTP)
sshd_set "UsePAM" "yes"
chown root:root "$SSHD_CONFIG"
chmod 0600 "$SSHD_CONFIG"

msg "sshd configuration updated"

# Validate sshd config before proceeding
info "Validating sshd configuration..."
if sshd -t; then
    msg "sshd configuration test passed"
else
    err "sshd configuration test failed! Check $SSHD_CONFIG and restore from backup."
fi

# Verify effective sshd settings (detect overrides in /etc/ssh/sshd_config.d/*.conf or Match blocks)
SSHD_EFFECTIVE=$(sshd -T -C "user=${USERNAME},host=localhost,addr=127.0.0.1" 2>/dev/null || sshd -T 2>/dev/null || true)
if [[ -n "$SSHD_EFFECTIVE" ]]; then
    EFF_AUTH_METHODS=$(awk '$1 == "authenticationmethods" { $1 = ""; sub(/^[[:space:]]+/, ""); print; exit }' <<< "$SSHD_EFFECTIVE")
    EFF_KBD_INT=$(awk '$1 == "kbdinteractiveauthentication" { print $2; exit }' <<< "$SSHD_EFFECTIVE")
    if [[ "$EFF_AUTH_METHODS" != "publickey,keyboard-interactive" ]]; then
        warn "Effective sshd AuthenticationMethods is '${EFF_AUTH_METHODS:-unset}' (expected 'publickey,keyboard-interactive'). Check /etc/ssh/sshd_config.d/*.conf or Match blocks for overrides."
    fi
    if [[ "$EFF_KBD_INT" != "yes" ]]; then
        warn "Effective sshd KbdInteractiveAuthentication is '${EFF_KBD_INT:-unset}' (expected 'yes'). Check /etc/ssh/sshd_config.d/*.conf or Match blocks for overrides."
    fi
fi

if [[ "$ALLOW_MISSING_TOTP" == false ]]; then
    # Default to fail closed. Preserve other PAM options while removing nullok
    # from active google-authenticator auth lines.
    sed -i -E '/^[[:space:]]*auth[[:space:]]+.*pam_google_authenticator\.so/ s/[[:space:]]+nullok([[:space:]]|$)/\1/g' "$PAM_SSHD"
    if grep -Eq "$PAM_NULLOK_RE" "$PAM_SSHD"; then
        err "Could not remove nullok from the active TOTP PAM rule"
    fi
    grep -Eq "$PAM_MODULE_RE" "$PAM_SSHD" || err "No active TOTP PAM rule was installed"
    TOTP_ENFORCEMENT="mandatory"
    msg "TOTP is mandatory for SSH users (fail-closed PAM policy)"
elif grep -Eq "$PAM_NULLOK_RE" "$PAM_SSHD"; then
    TOTP_ENFORCEMENT="staged"
    warn "Staged rollout enabled: SSH users without TOTP secrets remain exempt via nullok"
else
    TOTP_ENFORCEMENT="mandatory"
    info "Existing PAM policy is already mandatory; it was not weakened with nullok"
fi

# =============================================================================
# 6. RELOAD SSHD
# =============================================================================

sshd -t || err "sshd configuration test failed before reload"
if systemctl is-active --quiet sshd; then
    msg "Reloading sshd without dropping existing sessions..."
    systemctl reload sshd
    systemctl is-active --quiet sshd && msg "sshd is running" || err "sshd is not active; restore the saved configuration from console"
else
    warn "sshd.service is not currently active — skipping live reload (changes apply when sshd starts)"
fi

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

# Extract and display emergency scratch codes
if [[ -f "$TOTP_SECRET" ]]; then
    echo -e "${C_YELLOW}EMERGENCY SCRATCH CODES (save these in a secure location!):${C_NC}"
    echo -e "${C_YELLOW}Each code can only be used once.${C_NC}"
    echo
    # Scratch codes are the 8-digit numbers at the end of the file
    # (after the config lines that start with " or contain known options)
    mapfile -t SCRATCH_CODES < <(grep -E '^[0-9]{8}$' "$TOTP_SECRET" || true)
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
echo "  - Or access the server via console/physical access and restore:"
echo "    ${SSHD_CONFIG}.bak.* and ${PAM_SSHD}.bak.*"
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
