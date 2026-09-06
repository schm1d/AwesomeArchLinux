#!/usr/bin/env bash
# =============================================================================
# Script:      brave.sh
# Description: Installs and fixes permissions for Brave Browser on Arch Linux.
#              Corrects restrictive umask issues (077/027) on /opt/brave-bin,
#              properly configures the chrome-sandbox SUID binary (4755),
#              secures user config/cache (0700/0600), and optionally applies
#              privacy-hardened enterprise policies. Never uses 777.
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
#
# Usage:       ./brave.sh [options]
# Options:
#   --fix-permissions  Only fix permissions on an existing Brave installation
#   --policy           Apply hardened enterprise policy (/etc/brave/policies/managed)
#   --status           Inspect Brave binary, sandbox, and directory permissions
#   -h, --help         Show this help
# =============================================================================

set -euo pipefail

readonly C_BLUE='\033[1;34m'
readonly C_RED='\033[1;31m'
readonly C_GREEN='\033[1;32m'
readonly C_YELLOW='\033[1;33m'
readonly C_NC='\033[0m'

msg()  { printf "%b[+]%b %s\n" "$C_GREEN" "$C_NC" "$1"; }
info() { printf "%b[*]%b %s\n" "$C_BLUE"  "$C_NC" "$1"; }
warn() { printf "%b[!]%b %s\n" "$C_YELLOW" "$C_NC" "$1"; }
err()  { printf "%b[!]%b %s\n" "$C_RED"   "$C_NC" "$1" >&2; exit 1; }

DO_FIX_ONLY=false
DO_POLICY=false
DO_STATUS=false

usage() {
    cat <<EOU
Usage: $0 [options]

Installs Brave browser (brave-bin) and secures all permissions.

Options:
  --fix-permissions   Only fix permissions on existing Brave files (no install)
  --policy            Deploy hardened enterprise policies to /etc/brave/policies/managed
  --status            Check Brave paths, permissions, and sandbox health
  -h, --help          Show this help

Note: Never uses 777. System files stay root:root (0755/0644, 4755 for sandbox),
user profile directories stay USER:USER (0700/0600).
EOU
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --fix-permissions) DO_FIX_ONLY=true; shift ;;
        --policy)          DO_POLICY=true; shift ;;
        --status)          DO_STATUS=true; shift ;;
        -h|--help)         usage ;;
        *)                 err "Unknown option: $1" ;;
    esac
done

REAL_USER="${SUDO_USER:-${USER:-$(id -un)}}"
if [[ "$REAL_USER" == "root" ]]; then
    REAL_HOME="${HOME:-/root}"
else
    REAL_HOME="$(getent passwd "$REAL_USER" | cut -d: -f6)"
    REAL_HOME="${REAL_HOME:-/home/$REAL_USER}"
fi

sudo_run() {
    if [[ $(id -u) -eq 0 ]]; then
        "$@"
    else
        command -v sudo >/dev/null 2>&1 || err "sudo is required for root operations"
        sudo "$@"
    fi
}

as_user() {
    if [[ $(id -u) -eq 0 && "$REAL_USER" != "root" ]]; then
        sudo -u "$REAL_USER" "$@"
    else
        "$@"
    fi
}

find_brave_dir() {
    local candidate
    for candidate in /opt/brave-bin /opt/brave.com/brave /usr/lib/brave-bin; do
        if [[ -d "$candidate" ]]; then
            printf '%s' "$candidate"
            return 0
        fi
    done
    return 1
}

check_status() {
    echo
    info "Inspecting Brave Browser installation..."
    local b_path
    if b_path=$(command -v brave 2>/dev/null); then
        msg "Brave launcher: $b_path ($(readlink -f "$b_path" 2>/dev/null || echo "$b_path"))"
    else
        warn "Brave binary not found in PATH"
    fi

    local b_dir
    if b_dir=$(find_brave_dir); then
        msg "Brave install directory: $b_dir"
        local b_mode s_mode p_mode
        b_mode=$(stat -c '%a (%A)' "$b_dir/brave" 2>/dev/null || echo "missing")
        s_mode=$(stat -c '%a (%A)' "$b_dir/chrome-sandbox" 2>/dev/null || echo "missing")
        p_mode=$(stat -c '%a (%A)' "$b_dir/resources.pak" 2>/dev/null || echo "missing")
        
        info "Permissions check:"
        echo "  - Main executable (brave):       $b_mode"
        echo "  - SUID Sandbox (chrome-sandbox):  $s_mode"
        echo "  - Resource pack (resources.pak): $p_mode"

        if [[ -r "$b_dir/resources.pak" ]]; then
            msg "Resource pack is readable by current user ($REAL_USER)"
        else
            warn "Resource pack is NOT readable by $REAL_USER (Permission Denied bug!)"
        fi
    else
        warn "No standard Brave installation directory located in /opt or /usr/lib"
    fi

    local u_conf="$REAL_HOME/.config/BraveSoftware"
    local u_cache="$REAL_HOME/.cache/BraveSoftware"
    if [[ -d "$u_conf" ]]; then
        msg "User config ($u_conf): $(stat -c '%a %U:%G' "$u_conf")"
    else
        info "User config not yet created: $u_conf"
    fi
    if [[ -d "$u_cache" ]]; then
        msg "User cache ($u_cache): $(stat -c '%a %U:%G' "$u_cache")"
    fi
    echo
}

fix_permissions() {
    local b_dir
    b_dir=$(find_brave_dir) || err "Cannot find Brave installation directory (/opt/brave-bin). Is it installed?"

    info "Fixing permissions on Brave installation in $b_dir (no 777)..."

    # 1. Base directory ownership and directory traversal
    sudo_run chown -R root:root "$b_dir"
    sudo_run find "$b_dir" -type d -exec chmod 755 {} +

    # 2. General data files, shared libraries, and resources (0644)
    sudo_run find "$b_dir" -type f -exec chmod 644 {} +

    # 3. Executable binaries and helper scripts (0755)
    local exes=(
        "$b_dir/brave"
        "$b_dir/brave-browser"
        "$b_dir/chrome_crashpad_handler"
        "$b_dir/chrome-management-service"
    )
    for exe in "${exes[@]}"; do
        if [[ -f "$exe" ]]; then
            sudo_run chmod 755 "$exe"
        fi
    done

    # 4. Chromium SUID Sandbox MUST be 4755 owned by root:root
    if [[ -f "$b_dir/chrome-sandbox" ]]; then
        info "Setting SUID bit on Chromium sandbox (mode 4755, root:root)..."
        sudo_run chown root:root "$b_dir/chrome-sandbox"
        sudo_run chmod 4755 "$b_dir/chrome-sandbox"
    fi

    # 5. Desktop launcher and system integration
    if [[ -L /usr/bin/brave || -f /usr/bin/brave ]]; then
        sudo_run chmod 755 /usr/bin/brave 2>/dev/null || true
    fi

    local desktop_sys="/usr/share/applications/brave-browser.desktop"
    if [[ -f "$desktop_sys" ]]; then
        sudo_run chown root:root "$desktop_sys"
        sudo_run chmod 644 "$desktop_sys"
        sudo_run update-desktop-database /usr/share/applications 2>/dev/null || true
    fi

    # 6. User profile and cache permissions (0700 for dirs, 0600 for files)
    local u_conf="$REAL_HOME/.config/BraveSoftware"
    local u_cache="$REAL_HOME/.cache/BraveSoftware"

    if [[ -d "$u_conf" ]]; then
        info "Securing user config in $u_conf (0700/0600, $REAL_USER:$REAL_USER)..."
        sudo_run chown -R "$REAL_USER:$REAL_USER" "$u_conf"
        sudo_run find "$u_conf" -type d -exec chmod 700 {} +
        sudo_run find "$u_conf" -type f -exec chmod 600 {} +
    fi

    if [[ -d "$u_cache" ]]; then
        info "Securing user cache in $u_cache (0700/0600, $REAL_USER:$REAL_USER)..."
        sudo_run chown -R "$REAL_USER:$REAL_USER" "$u_cache"
        sudo_run find "$u_cache" -type d -exec chmod 700 {} +
        sudo_run find "$u_cache" -type f -exec chmod 600 {} +
    fi

    msg "Permissions successfully hardened across all Brave locations."
}

apply_policy() {
    info "Applying hardened enterprise policy for Brave..."
    local pol_dir="/etc/brave/policies/managed"
    sudo_run mkdir -p "$pol_dir"

    sudo_run tee "$pol_dir/10-security.json" >/dev/null <<'EOP'
{
  "PasswordManagerEnabled": false,
  "AutofillAddressEnabled": false,
  "AutofillCreditCardEnabled": false,
  "MetricsReportingEnabled": false,
  "SafeBrowsingProtectionLevel": 1,
  "SearchSuggestEnabled": false,
  "BackgroundModeEnabled": false,
  "WebRtcIPHandlingPolicy": "disable_non_proxied_udp",
  "HardwareAccelerationModeEnabled": true,
  "HttpsOnlyMode": "force_enabled",
  "BlockThirdPartyCookies": true,
  "DefaultGeolocationSetting": 2,
  "DefaultNotificationsSetting": 2,
  "DefaultSensorsSetting": 2,
  "BraveRewardsDisabled": true,
  "BraveWalletDisabled": true,
  "BraveVPNDisabled": true,
  "BraveAIChatEnabled": false
}
EOP

    sudo_run chown -R root:root "/etc/brave"
    sudo_run find "/etc/brave" -type d -exec chmod 755 {} +
    sudo_run chmod 644 "$pol_dir/10-security.json"
    msg "Enterprise policy installed to $pol_dir/10-security.json (mode 0644)"
}

install_brave() {
    if pacman -Qi brave-bin &>/dev/null || pacman -Qi brave &>/dev/null; then
        msg "Brave is already installed ($(pacman -Q brave-bin 2>/dev/null || pacman -Q brave))."
        return 0
    fi

    info "Installing brave-bin from AUR..."
    
    # Check for AUR helper
    local helper=""
    for h in yay paru; do
        if command -v "$h" &>/dev/null; then
            helper="$h"
            break
        fi
    done

    if [[ -n "$helper" ]]; then
        info "Building brave-bin with $helper..."
        # Build without inherited restrictive umask
        as_user bash -c "umask 022 && $helper -S --needed --noconfirm brave-bin"
    else
        info "No AUR helper found. Building manually with makepkg..."
        sudo_run pacman -S --needed --noconfirm base-devel git
        local b_tmp
        b_tmp=$(as_user mktemp -d /tmp/brave-build.XXXXXX)
        # shellcheck disable=SC2064
        trap "rm -rf '$b_tmp'" EXIT

        as_user git clone https://aur.archlinux.org/brave-bin.git "$b_tmp/brave-bin"
        (
            cd "$b_tmp/brave-bin"
            as_user bash -c "umask 022 && makepkg -si --noconfirm"
        )
    fi

    msg "brave-bin installation finished."
}

# --- Main execution ---
if [[ "$DO_STATUS" == true ]]; then
    check_status
    exit 0
fi

if [[ "$DO_FIX_ONLY" == true ]]; then
    fix_permissions
    if [[ "$DO_POLICY" == true ]]; then
        apply_policy
    fi
    check_status
    exit 0
fi

install_brave
fix_permissions

if [[ "$DO_POLICY" == true ]]; then
    apply_policy
fi

check_status
msg "Brave installation and permission verification completed successfully!"
