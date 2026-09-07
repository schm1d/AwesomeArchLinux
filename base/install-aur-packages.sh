#!/usr/bin/env bash
# Post-install security packages: root orchestrates, AUR builds are unprivileged.
set -euo pipefail

[[ "$(id -u)" == 0 ]] || {
    echo "Run as root: sudo /root/install-aur-packages.sh" >&2
    exit 1
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for component in aur-review.sh aide-config.sh; do
    [[ -r "$SCRIPT_DIR/$component" ]] || {
        echo "Missing staged post-install component: $SCRIPT_DIR/$component" >&2
        exit 1
    }
done
# shellcheck source=../hardening/lib/aur-review.sh
source "$SCRIPT_DIR/aur-review.sh"

pacman -S --needed --noconfirm base-devel git
for package in aide acct; do
    if pacman -Qq "$package" &>/dev/null; then
        printf '%s is already installed.\n' "$package"
    elif pacman -Si "$package" &>/dev/null; then
        pacman -S --needed --noconfirm "$package"
    else
        aal_aur_install_reviewed "$package"
    fi
done

systemctl enable --now psacct.service

# Use the shared configurator so the config, database paths and timer agree.
# Rerunning package setup must not silently replace an integrity baseline.
if [[ -s /var/lib/aide/aide.db || -s /var/lib/aide/aide.db.gz ]]; then
    echo "Existing AIDE baseline preserved. Use aide-config.sh --check or --update as appropriate."
else
    bash "$SCRIPT_DIR/aide-config.sh" --init
fi

echo "Security packages configured successfully."
