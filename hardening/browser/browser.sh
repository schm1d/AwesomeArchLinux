#!/usr/bin/env bash

# =============================================================================
# Script:      browser.sh
# Description: Hardens Firefox, Chromium/Chrome, and Brave with enterprise
#              policies and an optional Firejail wrapper. Does not vendor a
#              rotting arkenfox user.js; --arkenfox clones the upstream updater
#              into a user profile instead.
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
# =============================================================================

set -euo pipefail
umask 022

readonly C_BLUE='\033[1;34m'
readonly C_RED='\033[1;31m'
readonly C_GREEN='\033[1;32m'
readonly C_YELLOW='\033[1;33m'
readonly C_NC='\033[0m'

msg()  { printf "%b[+]%b %s\n" "$C_GREEN" "$C_NC" "$1"; }
info() { printf "%b[*]%b %s\n" "$C_BLUE"  "$C_NC" "$1"; }
warn() { printf "%b[!]%b %s\n" "$C_YELLOW" "$C_NC" "$1"; }
err()  { printf "%b[!]%b %s\n" "$C_RED"   "$C_NC" "$1" >&2; exit 1; }

DO_FIREFOX=false
DO_CHROMIUM=false
DO_BRAVE=false
DO_FIREJAIL=false
DO_ARKENFOX=false
DO_PACKAGES=true
ANY_EXPLICIT=false
INSTALL_CHROMIUM_PKG=false
STAGE_ONLY=false

usage() {
    cat <<EOF
Usage: sudo $0 [options]

With no flags: detect installed browsers and apply enterprise policies.
If none is installed, Firefox and Chromium policies are staged and no browser
package is installed; pass --firefox / --chromium to install one.

  --firefox --chromium --brave --firejail --arkenfox --no-packages -h
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --firefox)     DO_FIREFOX=true; ANY_EXPLICIT=true; shift ;;
        --chromium)    DO_CHROMIUM=true; INSTALL_CHROMIUM_PKG=true; ANY_EXPLICIT=true; shift ;;
        --brave)       DO_BRAVE=true; ANY_EXPLICIT=true; shift ;;
        --firejail)    DO_FIREJAIL=true; ANY_EXPLICIT=true; shift ;;
        --arkenfox)    DO_ARKENFOX=true; ANY_EXPLICIT=true; shift ;;
        --no-packages) DO_PACKAGES=false; shift ;;
        -h|--help)     usage ;;
        *)             err "Unknown option: $1" ;;
    esac
done

[[ $(id -u) -eq 0 ]] || err "Must be run as root"

TARGET_USER="${SUDO_USER:-}"
if [[ -z "$TARGET_USER" || "$TARGET_USER" == "root" ]]; then
    TARGET_USER=$(awk -F: '$3 >= 1000 && $3 < 65534 && $7 !~ /(nologin|false)/ { print $1; exit }' /etc/passwd)
fi
TARGET_HOME=""
if [[ -n "$TARGET_USER" ]]; then
    TARGET_HOME=$(getent passwd "$TARGET_USER" | cut -d: -f6)
fi

if [[ "$ANY_EXPLICIT" == false ]]; then
    [[ -x /usr/bin/firefox ]] && DO_FIREFOX=true
    [[ -x /usr/bin/chromium || -x /usr/bin/google-chrome-stable ]] && DO_CHROMIUM=true
    [[ -x /usr/bin/brave || -x /usr/bin/brave-browser ]] && DO_BRAVE=true
    if [[ "$DO_FIREFOX" == false && "$DO_CHROMIUM" == false && "$DO_BRAVE" == false ]]; then
        # Auto-detection must not pull two browsers onto a host that has none:
        # stage the policy files so they apply to whatever is installed later.
        DO_FIREFOX=true
        DO_CHROMIUM=true
        STAGE_ONLY=true
        warn "No supported browser found in /usr/bin; staging Firefox and Chromium policies only."
        info "Pass --firefox and/or --chromium to install a browser as well."
    fi
fi

check_userns() {
    local v
    v=$(sysctl -n kernel.unprivileged_userns_clone 2>/dev/null || echo 1)
    if [[ "$v" == "0" ]]; then
        warn "kernel.unprivileged_userns_clone=0 (sysctl strict profile)."
        warn "Chromium's layer-1 sandbox and many Firejail features will fail."
    fi
}

write_firefox_policies() {
    local dir="/etc/firefox/policies" tmp backup
    install -d -m 0755 /etc/firefox "$dir"
    tmp=$(mktemp "$dir/.policies.json.XXXXXX")
    cat > "$tmp" <<'EOF'
{
  "policies": {
    "DisableTelemetry": true,
    "DisableFirefoxStudies": true,
    "DisablePocket": true,
    "DisableFeedbackCommands": true,
    "DontCheckDefaultBrowser": true,
    "HTTPSOnlyMode": "enabled",
    "EnableTrackingProtection": {
      "Value": true,
      "Locked": false,
      "Cryptomining": true,
      "Fingerprinting": true
    },
    "FirefoxHome": {
      "SponsoredTopSites": false,
      "SponsoredPocket": false,
      "Pocket": false
    },
    "UserMessaging": {
      "WhatsNew": false,
      "ExtensionRecommendations": false,
      "FeatureRecommendations": false,
      "UrlbarInterventions": false,
      "SkipOnboarding": true,
      "MoreFromMozilla": false
    },
    "SearchSuggestEnabled": false,
    "Certificates": { "ImportEnterpriseRoots": false },
    "Preferences": {
      "media.ffmpeg.vaapi.enabled": { "Value": true, "Status": "default" },
      "media.hardware-video-decoding.enabled": { "Value": true, "Status": "default" },
      "dom.security.https_only_mode": { "Value": true, "Status": "default" },
      "network.dns.echconfig.enabled": { "Value": true, "Status": "default" },
      "browser.safebrowsing.malware.enabled": { "Value": true, "Status": "default" },
      "browser.safebrowsing.phishing.enabled": { "Value": true, "Status": "default" }
    }
  }
}
EOF
    chmod 644 "$tmp"
    # Firefox reads exactly one policies.json. Keep the previous file (other
    # names in this directory are ignored) instead of silently discarding an
    # administrator's own policies.
    if [[ -f "$dir/policies.json" ]] && ! cmp -s "$tmp" "$dir/policies.json"; then
        backup="$dir/policies.json.bak.$(date +%Y%m%d-%H%M%S)"
        cp -p -- "$dir/policies.json" "$backup"
        warn "Replaced existing $dir/policies.json; previous version saved as $backup"
    fi
    mv -f -- "$tmp" "$dir/policies.json"
    msg "Wrote $dir/policies.json"
}

write_chromium_policies() {
    install -d -m 0755 \
        /etc/chromium /etc/chromium/policies /etc/chromium/policies/managed \
        /etc/opt /etc/opt/chrome /etc/opt/chrome/policies /etc/opt/chrome/policies/managed
    local roots=(
        "/etc/chromium/policies/managed"
        "/etc/opt/chrome/policies/managed"
    )
    local dir
    for dir in "${roots[@]}"; do
        cat > "$dir/awesome-hardening.json" <<'EOF'
{
  "CloudReportingEnabled": false,
  "MetricsReportingEnabled": false,
  "SpellCheckServiceEnabled": false,
  "SafeBrowsingEnabled": true,
  "SafeBrowsingProtectionLevel": 1,
  "AutofillAddressEnabled": false,
  "AutofillCreditCardEnabled": false,
  "BlockThirdPartyCookies": true,
  "DnsOverHttpsMode": "automatic",
  "HttpsOnlyMode": "force_enabled",
  "SitePerProcess": true,
  "RemoteDebuggingAllowed": false,
  "BackgroundModeEnabled": false,
  "HardwareAccelerationModeEnabled": true,
  "PasswordManagerEnabled": true,
  "BrowserSignin": 0,
  "SyncDisabled": true,
  "DefaultBrowserSettingEnabled": false,
  "ExtensionInstallForcelist": [
    "ddkjiahefjhfhefomlbhegpnlnlpeicp;https://clients2.google.com/service/update2/crx"
  ]
}
EOF
        chmod 0644 "$dir/awesome-hardening.json"
        msg "Wrote $dir/awesome-hardening.json"
    done

    # External extension registration for Chromium
    local ext_dir="/usr/share/chromium/extensions"
    install -d -m 0755 /usr/share/chromium "$ext_dir"
    cat > "$ext_dir/ddkjiahefjhfhefomlbhegpnlnlpeicp.json" <<'EOF'
{
  "external_update_url": "https://clients2.google.com/service/update2/crx"
}
EOF
    chmod 0644 "$ext_dir/ddkjiahefjhfhefomlbhegpnlnlpeicp.json"
    msg "Registered uBlock Origin Lite in $ext_dir"
}

write_brave_policies() {
    local dir="/etc/brave/policies/managed"
    install -d -m 0755 /etc/brave /etc/brave/policies "$dir"
    rm -f "$dir/10-security.json" "$dir/awesome-hardening.json"

    cat > "$dir/10-awesome-hardening.json" <<'EOF'
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
EOF
    chmod 0644 "$dir/10-awesome-hardening.json"
    msg "Wrote $dir/10-awesome-hardening.json"

    local ext_dir="/usr/share/brave/extensions"
    install -d -m 0755 /usr/share/brave "$ext_dir"
    cat > "$ext_dir/ddkjiahefjhfhefomlbhegpnlnlpeicp.json" <<'EOF'
{
  "external_update_url": "https://clients2.google.com/service/update2/crx"
}
EOF
    chmod 0644 "$ext_dir/ddkjiahefjhfhefomlbhegpnlnlpeicp.json"
    msg "Registered uBlock Origin Lite in $ext_dir"
}

install_firejail() {
    if [[ "$DO_PACKAGES" == true ]]; then
        pacman -Syu --noconfirm --needed firejail
    fi
    command -v firejail >/dev/null || err "firejail is not installed"
    install -d -m 0755 /usr/local /usr/local/bin
    local app dest
    for app in firefox chromium google-chrome-stable brave brave-browser; do
        if [[ "$DO_FIREFOX" == true || "$DO_CHROMIUM" == true || "$DO_BRAVE" == true ]]; then
            case "$app" in
                firefox)                       [[ "$DO_FIREFOX" == true ]] || continue ;;
                chromium|google-chrome-stable) [[ "$DO_CHROMIUM" == true ]] || continue ;;
                brave|brave-browser)           [[ "$DO_BRAVE" == true ]] || continue ;;
            esac
        fi
        dest="/usr/local/bin/${app}"
        if [[ -x "/usr/bin/${app}" ]] || [[ "$app" == "brave" && "$DO_BRAVE" == true ]]; then
            [[ -x "/usr/bin/${app}" ]] || warn "/usr/bin/${app} is not installed yet; staging wrapper anyway"
            cat > "$dest" <<EOF
#!/usr/bin/env bash
exec /usr/bin/firejail --quiet /usr/bin/${app} "\$@"
EOF
            chmod 0755 "$dest"
            msg "Installed $dest wrapper"
        fi
    done
    warn "Wrappers in /usr/local/bin shadow /usr/bin. Undo: rm -f /usr/local/bin/{firefox,chromium,google-chrome-stable,brave,brave-browser}"
}

install_arkenfox() {
    [[ -n "$TARGET_HOME" && -d "$TARGET_HOME" ]] || err "Cannot resolve a non-root home for arkenfox"
    local missing_pkgs=()
    command -v git >/dev/null 2>&1 || missing_pkgs+=(git)
    command -v curl >/dev/null 2>&1 || missing_pkgs+=(curl)
    if (( ${#missing_pkgs[@]} > 0 )); then
        if [[ "$DO_PACKAGES" == true ]]; then
            pacman -Syu --noconfirm --needed "${missing_pkgs[@]}"
        else
            err "Missing required tool(s) for --arkenfox (${missing_pkgs[*]}) and --no-packages is set"
        fi
    fi

    local profile
    profile=$(find "$TARGET_HOME/.mozilla/firefox" -maxdepth 1 -type d -name '*.default-release' 2>/dev/null | head -1 || true)
    if [[ -z "$profile" ]]; then
        profile=$(find "$TARGET_HOME/.mozilla/firefox" -maxdepth 1 -type d -name '*.default*' 2>/dev/null | head -1 || true)
    fi
    [[ -n "$profile" ]] || err "No Firefox profile under $TARGET_HOME/.mozilla/firefox — start Firefox once, then re-run --arkenfox"

    local src="$TARGET_HOME/.local/src/arkenfox-user.js"
    ( cd "$TARGET_HOME" && runuser -u "$TARGET_USER" -- mkdir -p "$(dirname "$src")" )
    if [[ -d "$src/.git" ]]; then
        ( cd "$TARGET_HOME" && runuser -u "$TARGET_USER" -- git -C "$src" pull --ff-only )
    else
        ( cd "$TARGET_HOME" && runuser -u "$TARGET_USER" -- git clone --depth 1 https://github.com/arkenfox/user.js.git "$src" )
    fi
    warn "Close Firefox first. The updater overlays user.js; user-overrides.js is preserved if present."
    ( cd "$TARGET_HOME" && runuser -u "$TARGET_USER" -- bash "$src/updater.sh" -p "$profile" -s -d )
    if [[ -f "$profile/prefs.js" ]]; then
        ( cd "$TARGET_HOME" && runuser -u "$TARGET_USER" -- install -m 0700 "$src/prefsCleaner.sh" "$profile/prefsCleaner.sh" )
        ( cd "$profile" && runuser -u "$TARGET_USER" -- bash "./prefsCleaner.sh" -s -d ) || true
    fi
    msg "arkenfox applied to $profile"
}

check_userns

if [[ "$DO_FIREFOX" == true ]]; then
    if [[ "$DO_PACKAGES" == true && "$STAGE_ONLY" == false ]]; then
        pacman -Syu --noconfirm --needed firefox
    fi
    write_firefox_policies
fi

if [[ "$DO_CHROMIUM" == true ]]; then
    if [[ "$DO_PACKAGES" == true && "$INSTALL_CHROMIUM_PKG" == true ]]; then
        pacman -Syu --noconfirm --needed chromium
    fi
    write_chromium_policies
fi

if [[ "$DO_BRAVE" == true ]]; then
    if [[ "$DO_PACKAGES" == true && ! -x /usr/bin/brave && ! -x /usr/bin/brave-browser ]]; then
        if pacman -Si brave &>/dev/null; then
            pacman -Syu --noconfirm --needed brave
        else
            info "Brave is not in official Arch repositories; writing enterprise policies to /etc/brave/policies/managed"
        fi
    fi
    write_brave_policies
fi

if [[ "$DO_FIREJAIL" == true ]]; then
    install_firejail
fi

if [[ "$DO_ARKENFOX" == true ]]; then
    install_arkenfox
fi

echo
msg "Browser policy hardening complete. Restart Firefox/Chromium/Brave."
info "AppArmor browser profiles are not shipped: they rot faster than policies."
