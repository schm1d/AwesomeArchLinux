#!/usr/bin/env bash
#
# Script: install_firehol_blocklist.sh
# Description: Installs and configures Firehol with IP sets from Firehol's blocklist-ipsets repository.
# Author: @brulliant
# Usage: sudo ./install_firehol_blocklist.sh

BBlue='\033[1;34m'
NC='\033[0m'

# ==============================
# 1. Prerequisites: Check Root
# ==============================
if [ $(id -u) -ne 0 ]; then
    echo "[!] This script must be run as root or with sudo privileges."
    exit 1
fi

# ==============================
# 2. Install Required Packages
# ==============================

echo -e "${BBlue}[+] Installing dependencies...${NC}"
pacman -Syu --noconfirm wget git cronie

echo -e "${BBlue}[+] Installing Firehol from AUR...${NC}"
if ! command -v yay &> /dev/null; then
    echo -e "${BBlue}[+] Installing yay AUR helper...${NC}"
    su - $USER -c "git clone https://aur.archlinux.org/yay.git $HOME/yay"
    cd $HOME/yay || exit 1
    su - $USER -c "makepkg -si --noconfirm"
    cd - || exit 1
    rm -rf $HOME/yay
fi

mount -o remount,exec /tmp
systemctl daemon-reload

su - $USER -c "yay -S --noconfirm firehol"

mount -o remount,noexec /tmp
systemctl daemon-reload

exit 

# ==============================
# 3. Configure Firehol Rules
# ==============================
FIREHOL_CONF="/etc/firehol/firehol.conf"
BACKUP_CONF="/etc/firehol/firehol.conf.backup.$(date +%F_%T)"

if [ -f "$FIREHOL_CONF" ]; then
    echo -e "${BBlue}[+] Backing up existing Firehol configuration...${NC}"
    cp "$FIREHOL_CONF" "$BACKUP_CONF"
fi

# Generate a basic configuration
cat <<EOF > "$FIREHOL_CONF"
version 6

# Trusted network example
interface any world
    policy drop

    server ssh accept
    server http accept
    server https accept

    # Allow DNS and NTP outbound traffic
    client all accept

# Block traffic based on IP sets
iptables -I INPUT -m set --match-set blacklist src -j DROP
iptables -I INPUT -m set --match-set bogons src -j DROP
EOF

chmod 600 "$FIREHOL_CONF"


# ==============================
# 5. Automate Blocklist Updates
# ==============================
echo -e "${BBlue}[+] Scheduling automatic updates via cron, every 10 minutes...${NC}"
CRON_JOB="*/10 * * * * root /sbin/update-ipsets && firehol restart"
CRON_FILE="/etc/cron.d/firehol-ipsets"

cat <<EOF > "$CRON_FILE"
$CRON_JOB
EOF
chmod 644 "$CRON_FILE"
systemctl enable cronie --now

# ==============================
# 6. Start Firehol Service
# ==============================
echo -e "${BBlue}[+] Enabling and starting Firehol...${NC}"
systemctl enable firehol --now

# ==============================
# 7. Status and Final Steps
# ==============================
echo -e "${BBlue}[+] Firehol and IP sets setup complete!${NC}"
firehol status
systemctl status firehol --no-pager

# ==============================
# 8. Adding and updating ipsets 
# ==============================
echo -e "${BBlue}[+] Using update-ipsets to add ipsets blocklists...${NC}"

update-ipsets enable firehol_level1
update-ipsets enable iblocklist_ads
update-ipsets enable iblocklist_badpeers
update-ipsets enable iblocklist_spamhaus_drop
update-ipsets enable esentire_emptyarray_ru
update-ipsets enable esentire_auth_update_ru
update-ipsets enable coinbl_hosts
update-ipsets enable alienvault_reputation
update-ipsets enable iblocklist_pedophiles
update-ipsets enable iblocklist_spyware
update-ipsets enable firehol_webserver

# ==============================
# 9. Verify IP Sets (Optional)
# ==============================
echo -e "${BBlue}[+] Testing IP sets (after download).${NC}"
cd "$BLOCKLIST_DIR" || exit 1
ipset list
exit 0
