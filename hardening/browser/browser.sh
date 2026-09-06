#!/usr/bin/env bash

# =============================================================================
# Script:      browser.sh
# Description: Hardens Firefox and Chromium with enterprise policies and an
#              optional Firejail wrapper. Does not vendor a rotting arkenfox
#              user.js; --arkenfox clones the upstream updater into a user
#              profile instead.
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
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

DO_FIREFOX=false
DO_CHROMIUM=false
DO_FIREJAIL=false
DO_ARKENFOX=false
DO_PACKAGES=true
ANY_EXPLICIT=false

usage() {
    cat <<EOF
Usage: sudo $0 [options]

With no flags: detect installed browsers and apply enterprise policies.

  --firefox --chromium --firejail --arkenfox --no-packages -h
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --firefox)     DO_FIREFOX=true; ANY_EXPLICIT=true; shift ;;
        --chromium)    DO_CHROMIUM=true; ANY_EXPLICIT=true; shift ;;
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
    command -v firefox >/dev/null && DO_FIREFOX=true
    command -v chromium >/dev/null && DO_CHROMIUM=true
    if [[ "$DO_FIREFOX" == false && "$DO_CHROMIUM" == false ]]; then
        DO_FIREFOX=true
        DO_CHROMIUM=true
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
    local dir="/etc/firefox/policies"
    mkdir -p "$dir"
    cat > "$dir/policies.json" <<'EOF'
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
    chmod 644 "$dir/policies.json"
    msg "Wrote $dir/policies.json"
}

write_chromium_policies() {
    local roots=("/etc/chromium/policies/managed" "/etc/opt/chrome/policies/managed")
    local dir
    for dir in "${roots[@]}"; do
        mkdir -p "$dir"
        cat > "$dir/awesome-hardening.json" <<'EOF'
{
  "CloudReportingEnabled": false,
  "MetricsReportingEnabled": false,
  "SpellCheckServiceEnabled": false,
  "SafeBrowsingEnabled": true,
  "SafeBrowsingProtectionLevel": 2,
  "AutofillAddressEnabled": false,
  "AutofillCreditCardEnabled": false,
  "BlockThirdPartyCookies": true,
  "DefaultCookiesSetting": 4,
  "DnsOverHttpsMode": "automatic",
  "HttpsOnlyMode": "force_enabled",
  "SitePerProcess": true,
  "RemoteDebuggingAllowed": false,
  "BackgroundModeEnabled": false,
  "HardwareAccelerationModeEnabled": true,
  "PasswordManagerEnabled": true,
  "BrowserSignin": 0,
  "SyncDisabled": true,
  "DefaultBrowserSettingEnabled": false
}
EOF
        chmod 644 "$dir/awesome-hardening.json"
        msg "Wrote $dir/awesome-hardening.json"
    done
}

install_firejail() {
    if [[ "$DO_PACKAGES" == true ]]; then
        pacman -Syu --noconfirm --needed firejail
    fi
    command -v firejail >/dev/null || err "firejail is not installed"
    mkdir -p /usr/local/bin
    local app dest
    for app in firefox chromium; do
        dest="/usr/local/bin/${app}"
        if [[ -x "/usr/bin/${app}" ]]; then
            cat > "$dest" <<EOF
#!/bin/sh
exec /usr/bin/firejail --quiet /usr/bin/${app} "\$@"
EOF
            chmod 755 "$dest"
            msg "Installed $dest wrapper"
        fi
    done
    warn "Wrappers in /usr/local/bin shadow /usr/bin. Undo: rm -f /usr/local/bin/firefox /usr/local/bin/chromium"
}

install_arkenfox() {
    [[ -n "$TARGET_HOME" && -d "$TARGET_HOME" ]] || err "Cannot resolve a non-root home for arkenfox"
    command -v git >/dev/null || pacman -Syu --noconfirm --needed git

    local profile
    profile=$(find "$TARGET_HOME/.mozilla/firefox" -maxdepth 1 -type d -name '*.default-release' 2>/dev/null | head -1)
    if [[ -z "$profile" ]]; then
        profile=$(find "$TARGET_HOME/.mozilla/firefox" -maxdepth 1 -type d -name '*.default*' 2>/dev/null | head -1)
    fi
    [[ -n "$profile" ]] || err "No Firefox profile under $TARGET_HOME/.mozilla/firefox — start Firefox once, then re-run --arkenfox"

    local src="$TARGET_HOME/.local/src/arkenfox-user.js"
    mkdir -p "$(dirname "$src")"
    if [[ -d "$src/.git" ]]; then
        git -C "$src" pull --ff-only
    else
        git clone --depth 1 https://github.com/arkenfox/user.js.git "$src"
    fi
    chown -R "$TARGET_USER:$TARGET_USER" "$(dirname "$src")"
    warn "Close Firefox first. The updater overlays user.js; user-overrides.js is preserved if present."
    sudo -u "$TARGET_USER" bash "$src/updater.sh" -p "$profile" -s
    sudo -u "$TARGET_USER" bash "$src/prefsCleaner.sh" -p "$profile" -s || true
    msg "arkenfox applied to $profile"
}

check_userns

if [[ "$DO_FIREFOX" == true ]]; then
    if [[ "$DO_PACKAGES" == true ]]; then
        pacman -Syu --noconfirm --needed firefox
    fi
    write_firefox_policies
fi

if [[ "$DO_CHROMIUM" == true ]]; then
    if [[ "$DO_PACKAGES" == true ]]; then
        pacman -Syu --noconfirm --needed chromium
    fi
    write_chromium_policies
fi

if [[ "$DO_FIREJAIL" == true ]]; then
    install_firejail
fi

if [[ "$DO_ARKENFOX" == true ]]; then
    install_arkenfox
fi

echo
msg "Browser policy hardening complete. Restart Firefox/Chromium."
info "AppArmor browser profiles are not shipped: they rot faster than policies."
