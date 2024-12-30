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
    git clone https://aur.archlinux.org/yay.git /tmp/yay
    cd /tmp/yay || exit 1
    makepkg -si --noconfirm
    cd - || exit 1
fi
yay -S --noconfirm firehol

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
# 4. Download Firehol Blocklists
# ==============================
BLOCKLIST_DIR="/etc/firehol/ipsets"
BLOCKLIST_FETCHER="https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/update-ipsets.sh"

echo -e "${BBlue}[+] Setting up Firehol IP sets...${NC}"

mkdir -p "$BLOCKLIST_DIR"
cd "$BLOCKLIST_DIR" || exit 1

# Download the blocklist update script
wget -O update-ipsets.sh "$BLOCKLIST_FETCHER"
chmod +x update-ipsets.sh

# ==============================
# 5. Automate Blocklist Updates
# ==============================
echo -e "${BBlue}[+] Scheduling automatic updates via cron...${NC}"
CRON_JOB="0 2 * * * root /etc/firehol/ipsets/update-ipsets.sh && firehol restart"
CRON_FILE="/etc/cron.d/firehol-ipsets"

if [ -f "$CRON_FILE" ]; then
    mv "$CRON_FILE" "$CRON_FILE.bak"
fi

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
# 8. Verify IP Sets (Optional)
# ==============================
echo -e "${BBlue}[+] Testing IP sets (after download).${NC}"
cd "$BLOCKLIST_DIR" || exit 1
./update-ipsets.sh
ipset list

exit 0
