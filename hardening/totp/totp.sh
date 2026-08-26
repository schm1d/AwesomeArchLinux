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
# Usage:       sudo ./totp.sh [-u USERNAME] [--allow-missing-totp] [-h]
#
# Requirements:
#   - Arch Linux with pacman
#   - Root privileges
#   - SSH server (sshd) installed and running
#   - Public key authentication already configured for the target user
#
# What this script does:
#   1. Installs libpam_google_authenticator and qrencode
#   2. Creates and verifies the target user's TOTP secret
#   3. Configures fail-closed PAM authentication (unless explicitly staged)
#   4. Configures sshd for challenge-response (publickey + TOTP)
#   5. Validates the complete SSH configuration
#   6. Reloads sshd without dropping existing sessions
#   7. Prints emergency scratch codes and instructions
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
USERNAME=""
ALLOW_MISSING_TOTP=false
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
  -h            Show this help

Examples:
  sudo $0                    # Configure TOTP for current sudo user
  sudo $0 -u alice           # Configure TOTP for user 'alice'
  sudo $0 -u alice --allow-missing-totp  # Explicit staged rollout
EOF
    exit 0
}

# --- Parse Arguments ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        -u)                    USERNAME="${2:-}"; [[ -n "$USERNAME" ]] || err "-u requires a username"; shift 2 ;;
        --allow-missing-totp)  ALLOW_MISSING_TOTP=true; shift ;;
        -h|--help)             usage ;;
        *)                     err "Unknown option: $1" ;;
    esac
done

# --- Validate root ---
[[ $(id -u) -eq 0 ]] || err "Must be run as root"

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

# Create the log without a predictable filename or permissive caller umask.
# File descriptor 3 remains terminal-only for QR codes and recovery codes.
umask 077
LOGFILE=$(mktemp "/var/log/totp-setup-$(date +%Y%m%d-%H%M%S).XXXXXX.log")
chmod 0600 "$LOGFILE"
exec 3>&1
exec > >(tee -a "$LOGFILE") 2>&1

info "Target user: $USERNAME"
info "Home directory: $USER_HOME"
info "TOTP secret file: $TOTP_SECRET"
info "Log: $LOGFILE"

# =============================================================================
# 1. INSTALL PACKAGES
# =============================================================================

msg "Installing libpam_google_authenticator and qrencode..."

pacman -Syu --noconfirm --needed libpam_google_authenticator qrencode

info "google-authenticator version: $(google-authenticator --version 2>&1 || echo 'unknown')"

# Create and verify the user's secret before changing PAM or sshd. A failed
# enrollment therefore cannot leave SSH in either a fail-open or lockout state.
msg "Running google-authenticator for user '$USERNAME'..."
info "A QR code will be displayed below. Scan it with your authenticator app."
echo

# -t time-based, -d no token reuse, -r/-R rate limit, -w clock-skew window,
# -f force-write, and -Q UTF8 for terminal QR rendering.
su - "$USERNAME" -c "google-authenticator -t -d -r 3 -R 30 -w 3 -f -Q UTF8" >&3 2>&3
echo

msg "Setting permissions on TOTP secret file..."
if [[ -f "$TOTP_SECRET" && -s "$TOTP_SECRET" ]]; then
    chmod 600 "$TOTP_SECRET"
    chown "$USERNAME:$USERNAME" "$TOTP_SECRET"
    info "$TOTP_SECRET — mode 600, owned by $USERNAME"
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

if grep -Eq "$PAM_MODULE_RE" "$PAM_SSHD" 2>/dev/null; then
    warn "PAM is already configured for google-authenticator in $PAM_SSHD"
    info "Existing line:"
    grep "pam_google_authenticator" "$PAM_SSHD" | while IFS= read -r line; do
        info "  $line"
    done
else
    # Back up the original PAM config
    cp "$PAM_SSHD" "${PAM_SSHD}.bak.$(date +%Y%m%d-%H%M%S)"
    info "Backed up $PAM_SSHD"

    # Append the TOTP auth line after existing auth lines
    echo "" >> "$PAM_SSHD"
    echo "# TOTP two-factor authentication (added by totp.sh)" >> "$PAM_SSHD"
    echo "$PAM_LINE" >> "$PAM_SSHD"

    msg "Added pam_google_authenticator to $PAM_SSHD"
fi

# =============================================================================
# 4. CONFIGURE SSHD FOR CHALLENGE-RESPONSE
# =============================================================================

msg "Configuring sshd for challenge-response authentication..."

# Back up sshd_config
cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak.$(date +%Y%m%d-%H%M%S)"
info "Backed up $SSHD_CONFIG"

# Helper: set or update a directive in sshd_config
sshd_set() {
    local key="$1"
    local value="$2"

    if grep -qE "^\s*${key}\s+" "$SSHD_CONFIG"; then
        # Update existing (uncommented) directive
        sed -i "s|^\s*${key}\s\+.*|${key} ${value}|" "$SSHD_CONFIG"
        info "Updated: ${key} ${value}"
    elif grep -qE "^\s*#\s*${key}\s+" "$SSHD_CONFIG"; then
        # Uncomment and set value
        sed -i "s|^\s*#\s*${key}\s\+.*|${key} ${value}|" "$SSHD_CONFIG"
        info "Uncommented and set: ${key} ${value}"
    else
        # Append new directive
        echo "${key} ${value}" >> "$SSHD_CONFIG"
        info "Added: ${key} ${value}"
    fi
}

sshd_set "ChallengeResponseAuthentication" "yes"
sshd_set "AuthenticationMethods" "publickey,keyboard-interactive"
sshd_set "KbdInteractiveAuthentication" "yes"

# Ensure UsePAM is enabled (required for PAM-based TOTP)
sshd_set "UsePAM" "yes"

msg "sshd configuration updated"

# Validate sshd config before proceeding
info "Validating sshd configuration..."
if sshd -t; then
    msg "sshd configuration test passed"
else
    err "sshd configuration test failed! Check $SSHD_CONFIG and restore from backup."
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

msg "Reloading sshd without dropping existing sessions..."

sshd -t || err "sshd configuration test failed before reload"
systemctl reload sshd
systemctl is-active --quiet sshd && msg "sshd is running" || err "sshd is not active; restore the saved configuration from console"

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
    grep -E '^[0-9]{8}$' "$TOTP_SECRET" | while IFS= read -r code; do
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
