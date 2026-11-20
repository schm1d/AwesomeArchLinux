#!/usr/bin/env bash
# =============================================================================
# Script:      brave.sh
# Description: Installs and fixes permissions for Brave Browser on Arch Linux.
#              Corrects restrictive umask (027/077) and inherited home default
#              POSIX ACL issues on /opt/brave-bin, configures chrome-sandbox
#              SUID (4755), installs a pacman PostTransaction hook so future
#              upgrades self-heal without null-byte or mtree warnings, secures
#              user config/cache without breaking component binaries or
#              dangling SingletonLock symlinks, and optionally deploys hardened
#              enterprise policies. Never uses 777.
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
#
# Usage:       ./brave.sh [options]
# Options:
#   --fix-permissions  Fix permissions & install pacman hook on existing Brave
#   --install-hook     Install/refresh the pacman PostTransaction hook only
#   --policy           Apply hardened enterprise policy (/etc/brave/policies/managed)
#   --status           Inspect Brave binary, sandbox, ACLs, and permissions
#   -h, --help         Show this help
# =============================================================================

set -euo pipefail

umask 022

readonly C_BLUE='\033[1;34m'
readonly C_RED='\033[1;31m'
readonly C_GREEN='\033[1;32m'
readonly C_YELLOW='\033[1;33m'
readonly C_NC='\033[0m'

msg()  { printf "%b[+]%b %s\n" "$C_GREEN"  "$C_NC" "$1"; }
info() { printf "%b[*]%b %s\n" "$C_BLUE"   "$C_NC" "$1"; }
warn() { printf "%b[!]%b %s\n" "$C_YELLOW" "$C_NC" "$1"; }
err()  { printf "%b[!]%b %s\n" "$C_RED"    "$C_NC" "$1" >&2; exit 1; }

readonly HOOK_HELPER="/usr/local/lib/awesomearchlinux/brave-fix-permissions.sh"
readonly PACMAN_HOOK="/etc/pacman.d/hooks/99-awesome-brave-permissions.hook"

DO_FIX_ONLY=false
DO_HOOK_ONLY=false
DO_POLICY=false
DO_STATUS=false

usage() {
    cat <<EOU
Usage: $0 [options]

Installs Brave browser (brave-bin), repairs /opt/brave-bin permissions and
POSIX ACLs, and installs a pacman PostTransaction hook so future AUR upgrades
stay working automatically.

Options:
  --fix-permissions   Fix permissions and refresh pacman hook (no install)
  --install-hook      Install/refresh only the pacman PostTransaction hook
  --policy            Deploy hardened enterprise policies to /etc/brave/policies/managed
  --status            Check Brave paths, permissions, ACLs, hook, and sandbox health
  -h, --help          Show this help

brave-bin is an AUR recipe. It is built through the reviewed builder in
hardening/lib/aur-review.sh: the recipe is shown first and a typed confirmation
on the terminal is required, so the install step cannot run unattended.

Note: Never uses 777. System files stay root:root (0755/0644, 4755 for sandbox),
user profile directories stay USER:GROUP (0700 dirs, go-rwx files with u+x preserved).
EOU
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --fix-permissions) DO_FIX_ONLY=true; shift ;;
        --install-hook)    DO_HOOK_ONLY=true; shift ;;
        --policy)          DO_POLICY=true; shift ;;
        --status)          DO_STATUS=true; shift ;;
        -h|--help)         usage ;;
        *)                 err "Unknown option: $1" ;;
    esac
done

resolve_target_user() {
    local candidate="${SUDO_USER:-}"
    if [[ -z "$candidate" || "$candidate" == "root" ]]; then
        if [[ "$(id -u)" -ne 0 ]]; then
            candidate="$(id -un)"
        else
            candidate="$(awk -F: '$3 >= 1000 && $3 < 65534 && $7 !~ /(nologin|false)/ { print $1; exit }' /etc/passwd)"
        fi
    fi
    printf '%s' "${candidate:-root}"
}

REAL_USER="$(resolve_target_user)"
REAL_GROUP="root"
if [[ "$REAL_USER" == "root" ]]; then
    REAL_HOME="${HOME:-/root}"
else
    REAL_GROUP="$(id -gn "$REAL_USER" 2>/dev/null || printf '%s' "$REAL_USER")"
    REAL_HOME="$(getent passwd "$REAL_USER" | cut -d: -f6)"
    REAL_HOME="${REAL_HOME:-/home/$REAL_USER}"
fi

sudo_run() {
    if [[ "$(id -u)" -eq 0 ]]; then
        "$@"
    else
        command -v sudo >/dev/null 2>&1 || err "sudo is required for root operations"
        sudo "$@"
    fi
}

as_user() {
    if [[ "$(id -u)" -eq 0 && "$REAL_USER" != "root" ]]; then
        if command -v runuser >/dev/null 2>&1; then
            runuser -u "$REAL_USER" -- "$@"
        else
            sudo -u "$REAL_USER" "$@"
        fi
    else
        "$@"
    fi
}

find_brave_dir() {
    local candidate
    for candidate in /opt/brave-bin /opt/brave.com/brave /usr/lib/brave-bin /opt/brave-beta-bin /opt/brave-nightly-bin; do
        if [[ -d "$candidate" && ! -L "$candidate" ]]; then
            printf '%s' "$candidate"
            return 0
        fi
    done
    return 1
}

# Strip inherited Default POSIX ACLs on AUR helper caches (~/.cache/yay, ~/.cache/paru).
# Because base/chroot.sh applies `setfacl -d -m u::rwx,g::---,o::--- /home/$USER`,
# any directory created under $HOME ignores makepkg's `umask 0022` and forces
# 0700/0600 + default ACLs into $pkgdir when PKGBUILDs use `cp -a`.
sanitize_aur_cache_acls() {
    [[ "$REAL_USER" != "root" && -d "$REAL_HOME" ]] || return 0
    command -v setfacl >/dev/null 2>&1 || return 0

    local cache_root="$REAL_HOME/.cache"
    if [[ ! -d "$cache_root" ]]; then
        as_user mkdir -p -m 0700 "$cache_root"
    fi

    local helper_cache
    for helper_cache in "$cache_root/yay" "$cache_root/paru"; do
        if [[ -d "$helper_cache" && ! -L "$helper_cache" ]]; then
            sudo_run setfacl -b -k "$helper_cache" 2>/dev/null || true
            if [[ -d "$helper_cache/brave-bin" && ! -L "$helper_cache/brave-bin" ]]; then
                sudo_run setfacl -bR "$helper_cache/brave-bin" 2>/dev/null || true
            fi
        fi
    done
}

install_pacman_hook() {
    info "Installing pacman PostTransaction hook for Brave permissions..."

    local helper_content hook_content
    helper_content="$(cat <<'EOF'
#!/usr/bin/env bash
# Automatically repairs /opt/brave* permissions and strips leaked build-time
# POSIX ACLs after brave-bin installs or upgrades. Pure Bash + coreutils/acl;
# never reads binary file contents into command substitutions.
set -euo pipefail

umask 022

fix_dir() {
    local b_dir="$1"
    [[ -d "$b_dir" && ! -L "$b_dir" ]] || return 0

    if command -v setfacl >/dev/null 2>&1; then
        setfacl -bR "$b_dir" 2>/dev/null || true
    fi

    chown -hR root:root "$b_dir"
    find -P "$b_dir" -type d -exec chmod 0755 {} +

    # Data files and shared libraries in brave-bin belong at 0644 (matching
    # pacman mtree); files with owner execute bit become 0755 via capital X.
    find -P "$b_dir" -type f \( \
        -name '*.so' -o -name '*.so.*' -o -name '*.pak' -o -name '*.dat' \
        -o -name '*.bin' -o -name '*.json' -o -name '*.png' -o -name 'LICENSE*' \
    \) -exec chmod 0644 {} +

    find -P "$b_dir" -type f ! -name 'chrome-sandbox' -exec chmod u+rw,go+rX,go-w {} +

    local exe
    for exe in \
        "$b_dir/brave" \
        "$b_dir/brave-browser" \
        "$b_dir/brave-browser-beta" \
        "$b_dir/brave-browser-nightly" \
        "$b_dir/chrome_crashpad_handler" \
        "$b_dir/chrome-management-service" \
        "$b_dir/cron/brave-browser" \
        "$b_dir/xdg-mime" \
        "$b_dir/xdg-settings"; do
        if [[ -f "$exe" && ! -L "$exe" ]]; then
            chmod 0755 "$exe"
        fi
    done

    if [[ -f "$b_dir/chrome-sandbox" && ! -L "$b_dir/chrome-sandbox" ]]; then
        chown root:root "$b_dir/chrome-sandbox"
        chmod 4755 "$b_dir/chrome-sandbox"
    fi
}

for candidate in /opt/brave-bin /opt/brave.com/brave /usr/lib/brave-bin /opt/brave-beta-bin /opt/brave-nightly-bin; do
    fix_dir "$candidate"
done

for launcher in /usr/bin/brave /usr/bin/brave-beta /usr/bin/brave-nightly; do
    if [[ -f "$launcher" && ! -L "$launcher" ]]; then
        if command -v setfacl >/dev/null 2>&1; then
            setfacl -b "$launcher" 2>/dev/null || true
        fi
        chown root:root "$launcher"
        chmod 0755 "$launcher"
    fi
done

for desktop in /usr/share/applications/brave-browser*.desktop; do
    if [[ -f "$desktop" && ! -L "$desktop" ]]; then
        if command -v setfacl >/dev/null 2>&1; then
            setfacl -b "$desktop" 2>/dev/null || true
        fi
        chown root:root "$desktop"
        chmod 0644 "$desktop"
    fi
done
EOF
)"

    hook_content="$(cat <<EOF
[Trigger]
Operation = Install
Operation = Upgrade
Type = Path
Target = opt/brave-bin/*
Target = opt/brave.com/brave/*
Target = opt/brave-beta-bin/*
Target = opt/brave-nightly-bin/*

[Action]
Description = Hardening Brave Browser permissions and SUID sandbox...
When = PostTransaction
Exec = ${HOOK_HELPER}
EOF
)"

    sudo_run install -d -m 0755 -o root -g root "$(dirname "$HOOK_HELPER")"
    sudo_run install -d -m 0755 -o root -g root "$(dirname "$PACMAN_HOOK")"
    printf '%s\n' "$helper_content" | sudo_run install -m 0755 -o root -g root /dev/stdin "$HOOK_HELPER"
    printf '%s\n' "$hook_content"   | sudo_run install -m 0644 -o root -g root /dev/stdin "$PACMAN_HOOK"

    # Remove obsolete ad-hoc helper directory if present and empty/superseded
    if [[ -f /usr/local/lib/awesomearch/brave-fix-permissions.sh ]]; then
        sudo_run rm -f /usr/local/lib/awesomearch/brave-fix-permissions.sh
        sudo_run rmdir /usr/local/lib/awesomearch 2>/dev/null || true
    fi

    msg "Installed pacman hook: $PACMAN_HOOK -> $HOOK_HELPER"
}

check_status() {
    echo
    info "Inspecting Brave Browser installation..."
    local b_path
    if b_path=$(command -v brave 2>/dev/null); then
        msg "Brave launcher: $b_path ($(readlink -f "$b_path" 2>/dev/null || printf '%s' "$b_path"))"
    else
        warn "Brave binary not found in PATH"
    fi

    local b_dir
    if b_dir=$(find_brave_dir); then
        msg "Brave install directory: $b_dir"
        local b_mode s_mode s_owner p_mode mount_opts
        b_mode=$(stat -c '%a (%A)' "$b_dir/brave" 2>/dev/null || printf 'missing')
        s_mode=$(stat -c '%a (%A)' "$b_dir/chrome-sandbox" 2>/dev/null || printf 'missing')
        s_owner=$(stat -c '%U:%G' "$b_dir/chrome-sandbox" 2>/dev/null || printf 'missing')
        p_mode=$(stat -c '%a (%A)' "$b_dir/resources.pak" 2>/dev/null || printf 'missing')

        info "Permissions check:"
        echo "  - Main executable (brave):       $b_mode"
        echo "  - SUID Sandbox (chrome-sandbox): $s_mode ($s_owner)"
        echo "  - Resource pack (resources.pak): $p_mode"

        if [[ "${s_mode%% *}" == "4755" && "$s_owner" == "root:root" ]]; then
            msg "chrome-sandbox SUID permissions verified (4755 root:root)"
        else
            warn "chrome-sandbox should be 4755 root:root (got: $s_mode $s_owner)"
        fi

        if command -v findmnt >/dev/null 2>&1; then
            mount_opts=$(findmnt -n -o OPTIONS -T "$b_dir" 2>/dev/null || true)
            if [[ ",$mount_opts," == *,nosuid,* || ",$mount_opts," == *,noexec,* ]]; then
                warn "$b_dir is mounted with restrictive options ($mount_opts) — SUID/exec may fail"
            fi
        fi

        if command -v getfacl >/dev/null 2>&1; then
            if getfacl -p "$b_dir" 2>/dev/null | grep -qE '^default:'; then
                warn "$b_dir still has inherited default POSIX ACLs (run --fix-permissions)"
            else
                msg "No leaked default POSIX ACLs on $b_dir"
            fi
        fi

        if [[ "$REAL_USER" != "root" ]]; then
            if as_user test -r "$b_dir/resources.pak" && as_user test -x "$b_dir/brave"; then
                msg "Brave binary and resources.pak verified accessible by user '$REAL_USER'"
            else
                warn "Brave binary or resources.pak is NOT accessible by '$REAL_USER' (Permission Denied!)"
            fi
        elif [[ -r "$b_dir/resources.pak" && -x "$b_dir/brave" ]]; then
            msg "Brave binary and resources.pak exist"
        fi
    else
        warn "No standard Brave installation directory located in /opt or /usr/lib"
    fi

    if [[ -f "$PACMAN_HOOK" && -x "$HOOK_HELPER" ]]; then
        msg "Pacman upgrade hook active ($PACMAN_HOOK)"
    else
        warn "Pacman upgrade hook not installed — future Brave updates may break permissions"
    fi

    local userns
    userns=$(sysctl -n kernel.unprivileged_userns_clone 2>/dev/null || printf '1')
    if [[ "$userns" == "0" ]]; then
        warn "kernel.unprivileged_userns_clone=0 (strict sysctl profile): Brave relies on SUID chrome-sandbox"
    fi

    if [[ "$REAL_USER" != "root" ]]; then
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
    fi
    echo
}

secure_user_dir() {
    local dir="$1"
    local label="$2"
    [[ "$REAL_USER" != "root" && -d "$dir" && ! -L "$dir" ]] || return 0

    info "Securing user $label in $dir (0700 dirs, go-rwx files, $REAL_USER:$REAL_GROUP)..."
    # Fix any root-owned entries without ever following symlinks (SingletonLock
    # in Brave-Browser is a dangling symlink `hostname-PID`, and chown -R
    # without -h both fails on dangling symlinks and creates a symlink LPE).
    sudo_run find -P "$dir" \( ! -user "$REAL_USER" -o ! -group "$REAL_GROUP" \) \
        -exec chown -h "$REAL_USER:$REAL_GROUP" {} +
    as_user find -P "$dir" -type d -exec chmod 0700 {} +
    # Preserve u+x on component binaries (e.g. Brave Tor daemon / ScreenAI)
    # while removing all group/other permissions.
    as_user find -P "$dir" -type f -exec chmod u+rw,go-rwx {} +
}

fix_permissions() {
    local b_dir
    b_dir=$(find_brave_dir) || err "Cannot find Brave installation directory (/opt/brave-bin). Is it installed?"

    sanitize_aur_cache_acls
    install_pacman_hook

    info "Fixing permissions on Brave installation in $b_dir (no 777)..."
    sudo_run "$HOOK_HELPER"

    if command -v update-desktop-database >/dev/null 2>&1 && [[ -d /usr/share/applications ]]; then
        sudo_run update-desktop-database /usr/share/applications 2>/dev/null || true
    fi

    secure_user_dir "$REAL_HOME/.config/BraveSoftware" "config"
    secure_user_dir "$REAL_HOME/.cache/BraveSoftware" "cache"

    msg "Permissions successfully hardened across all Brave locations."
}

apply_policy() {
    info "Applying hardened enterprise policy for Brave..."
    local pol_dir="/etc/brave/policies/managed"
    sudo_run install -d -m 0755 -o root -g root /etc/brave /etc/brave/policies "$pol_dir"

    # Remove legacy policy filenames so /etc/brave/policies/managed has a single
    # authoritative policy without conflicting overrides.
    sudo_run rm -f "$pol_dir/10-security.json" "$pol_dir/awesome-hardening.json"

    local policy_json
    policy_json="$(cat <<'EOP'
{
  "PasswordManagerEnabled": false,
  "AutofillAddressEnabled": false,
  "AutofillCreditCardEnabled": false,
  "CloudReportingEnabled": false,
  "MetricsReportingEnabled": false,
  "SpellCheckServiceEnabled": false,
  "SafeBrowsingEnabled": true,
  "SafeBrowsingProtectionLevel": 1,
  "SearchSuggestEnabled": false,
  "BackgroundModeEnabled": false,
  "DnsOverHttpsMode": "automatic",
  "WebRtcIPHandlingPolicy": "disable_non_proxied_udp",
  "HardwareAccelerationModeEnabled": true,
  "HttpsOnlyMode": "force_enabled",
  "BlockThirdPartyCookies": true,
  "SitePerProcess": true,
  "RemoteDebuggingAllowed": false,
  "BrowserSignin": 0,
  "SyncDisabled": true,
  "DefaultBrowserSettingEnabled": false,
  "DefaultGeolocationSetting": 2,
  "DefaultNotificationsSetting": 2,
  "DefaultSensorsSetting": 2,
  "BraveRewardsDisabled": true,
  "BraveWalletDisabled": true,
  "BraveVPNDisabled": true,
  "BraveAIChatEnabled": false,
  "ExtensionInstallForcelist": [
    "ddkjiahefjhfhefomlbhegpnlnlpeicp;https://clients2.google.com/service/update2/crx"
  ]
}
EOP
)"
    printf '%s\n' "$policy_json" | sudo_run install -m 0644 -o root -g root /dev/stdin "$pol_dir/10-awesome-hardening.json"

    # External extension registration for Brave
    local ext_dir="/usr/share/brave/extensions"
    sudo_run install -d -m 0755 -o root -g root /usr/share/brave "$ext_dir"
    local ext_json
    ext_json="$(cat <<'EOP'
{
  "external_update_url": "https://clients2.google.com/service/update2/crx"
}
EOP
)"
    printf '%s\n' "$ext_json" | sudo_run install -m 0644 -o root -g root /dev/stdin "$ext_dir/ddkjiahefjhfhefomlbhegpnlnlpeicp.json"
    msg "Enterprise policy and uBlock Origin Lite installed for Brave (mode 0644)"
}

# Review-gated AUR builder shared with the installer (base stages a copy as
# /root/aur-review.sh on installed systems).
find_aur_review_lib() {
    local script_dir candidate
    script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
    for candidate in "$script_dir/../hardening/lib/aur-review.sh" "$script_dir/aur-review.sh" /root/aur-review.sh; do
        if [[ -r "$candidate" ]]; then
            printf '%s' "$candidate"
            return 0
        fi
    done
    return 1
}

install_brave() {
    if pacman -Qi brave-bin &>/dev/null || pacman -Qi brave &>/dev/null; then
        msg "Brave is already installed ($(pacman -Q brave-bin 2>/dev/null || pacman -Q brave))."
        return 0
    fi

    sanitize_aur_cache_acls
    install_pacman_hook

    # AUR recipes are mutable, user-submitted build instructions. Instead of
    # `yay/paru --noconfirm` or a bare makepkg, the reviewed builder shows the
    # exact recipe commit, waits for a typed confirmation on the terminal and
    # builds as a disposable unprivileged user.
    local aur_lib
    aur_lib="$(find_aur_review_lib)" \
        || err "hardening/lib/aur-review.sh not found. Run utils/brave.sh from a full checkout of the repository."

    info "Installing brave-bin from the AUR (the recipe is shown for review first)..."
    sudo_run pacman -S --needed --noconfirm base-devel git
    # shellcheck disable=SC2016
    sudo_run bash -c 'set -euo pipefail; source "$1"; aal_aur_install_reviewed "$2"' _ "$aur_lib" brave-bin \
        || err "brave-bin was not installed (review declined, no terminal, or the build failed)."

    msg "brave-bin installation finished."
}

# --- Main execution ---
if [[ "$DO_STATUS" == true ]]; then
    check_status
    exit 0
fi

if [[ "$DO_HOOK_ONLY" == true ]]; then
    install_pacman_hook
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
