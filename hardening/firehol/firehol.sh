#!/usr/bin/env bash
#
# Script: firehol.sh
# Description: Installs and configures Firehol with IP sets from Firehol's blocklist-ipsets repository.
# Author: @brulliant
# LinkedIn: https://www.linkedin.com/in/schmidbruno/
# Usage: ./firehol.sh

# Define color codes for output
BBlue='\033[1;34m'
NC='\033[0m'

# Log all output to a file for later review
exec > >(tee -a /var/log/firehol_install.log) 2>&1

# ==============================
# Helper Functions
# ==============================

# Function to run commands with sudo if needed
run_sudo() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    else
        sudo "$@"
    fi
}

# Function to run commands as regular user, even if script is run with sudo
run_user() {
    if [ "$(id -u)" -eq 0 ] && [ -n "$SUDO_USER" ]; then
        sudo -u "$SUDO_USER" "$@"
    else
        "$@"
    fi
}

# ==============================
# 1. Install Required Packages
# ==============================
echo -e "${BBlue}[+] Installing dependencies...${NC}"
run_sudo pacman -S --noconfirm wget git cronie iputils iproute2 jq less || { 
    echo "[!] Failed to install dependencies."; 
    exit 1; 
}

# ==============================
# 2. Install Firehol from AUR
# ==============================
echo -e "${BBlue}[+] Installing Firehol from AUR...${NC}"
if ! command -v yay &> /dev/null; then
    echo -e "${BBlue}[+] Installing yay AUR helper...${NC}"
    YAY_TEMP_DIR=$(mktemp -d)
    run_user git clone https://aur.archlinux.org/yay.git "$YAY_TEMP_DIR" || { 
        echo "[!] Failed to clone yay."; 
        exit 1; 
    }
    cd "$YAY_TEMP_DIR" || exit 1
    run_user makepkg -si --noconfirm || { 
        echo "[!] Failed to install yay."; 
        exit 1; 
    }
    cd - || exit 1
    rm -rf "$YAY_TEMP_DIR"
fi

# Install FireHOL as regular user
echo -e "${BBlue}[+] Installing FireHOL from AUR...${NC}"
run_user yay -S --noconfirm firehol || { 
    echo "[!] Failed to install FireHOL. Ensure yay is correctly installed and try again."
    echo "    You may need to manually install yay or check for AUR helper issues."
    exit 1; 
}

# Verify installation
for pkg in firehol update-ipsets; do
    if ! command -v "$pkg" &> /dev/null; then
        echo "[!] $pkg is not installed. Please check the installation process."
        exit 1
    fi
done

# ==============================
# 3. Configure Firehol Rules
# ==============================
FIREHOL_CONF="/etc/firehol/firehol.conf"
BACKUP_CONF="/etc/firehol/firehol.conf.backup.$(date +%F_%T)"

if [ -f "$FIREHOL_CONF" ]; then
    echo -e "${BBlue}[+] Backing up existing Firehol configuration...${NC}"
    run_sudo cp "$FIREHOL_CONF" "$BACKUP_CONF" || { echo "[!] Failed to backup configuration."; exit 1; }
fi

# Generate a hardened configuration with drop policy and logging
echo -e "${BBlue}[+] Creating hardened Firehol configuration...${NC}"
cat <<EOF > /tmp/firehol.conf
version 6

# Default interface for all traffic
interface any world
    policy drop
    protection strong  # Enable logging for dropped packets
    # Accept specific incoming services
    server ssh accept
    server http accept
    server https accept
    # Allow all outbound traffic
    client all accept
EOF

run_sudo mkdir -p "/etc/firehol"
run_sudo cp /tmp/firehol.conf "$FIREHOL_CONF"
run_sudo chown root:root "$FIREHOL_CONF"
run_sudo chmod 600 "$FIREHOL_CONF" || { echo "[!] Failed to set permissions on Firehol configuration."; exit 1; }

# ==============================
# 4. Automate Blocklist Updates
# ==============================
echo -e "${BBlue}[+] Scheduling automatic updates via cron, daily...${NC}"
CRON_JOB="0 0 * * * root /sbin/update-ipsets && /usr/bin/firehol try"
CRON_FILE="/etc/cron.d/firehol-ipsets"

echo "$CRON_JOB" > /tmp/firehol-ipsets
run_sudo cp /tmp/firehol-ipsets "$CRON_FILE"
run_sudo chmod 644 "$CRON_FILE" || { echo "[!] Failed to set permissions on cron file."; exit 1; }
run_sudo systemctl enable cronie --now || { echo "[!] Failed to enable cronie."; exit 1; }

# ==============================
# 5. Enable and Start Firehol Service
# ==============================
echo -e "${BBlue}[+] Enabling and starting Firehol service...${NC}"
run_sudo systemctl enable firehol || { 
    echo "[!] Failed to enable Firehol service. Check systemctl status."; 
    exit 1; 
}
run_sudo systemctl start firehol || { 
    echo "[!] Failed to start Firehol service. Check logs with: journalctl -xeu firehol.service"; 
    exit 1; 
}

# Verify service status
if ! run_sudo systemctl is-active --quiet firehol; then
    echo "[!] FireHOL service is not running. Check logs with: journalctl -xeu firehol.service"
    exit 1
fi

# ==============================
# 6. Optional: Enable IP Sets
# ==============================
read -p "Do you want to enable the firehol_level1 IP set now? (y/N): " enable_ipset
if [[ "$enable_ipset" =~ ^[Yy]$ ]]; then
    echo -e "${BBlue}[+] Enabling firehol_level1 IP set...${NC}"
    run_sudo update-ipsets enable firehol_level1 || { 
        echo "[!] Failed to enable IP set."; 
        exit 1; 
    }
    echo "blacklist fullbogons ipset:firehol_level1" >> "$FIREHOL_CONF"
    run_sudo firehol try || { 
        echo "[!] Failed to apply IP set configuration."; 
        exit 1; 
    }
fi

# ==============================
# 7. Final Steps and Recommendations
# ==============================
echo -e "${BBlue}[+] FireHOL installation and configuration complete!${NC}"
echo -e ""
echo -e "=========== NEXT STEPS ==========="
echo -e "1. Check FireHOL status with: systemctl status firehol"
echo -e "2. View logs with: journalctl -xeu firehol.service"
echo -e "3. To add more IP sets, edit /etc/firehol/firehol.conf and use 'update-ipsets enable <set_name>'"
echo -e "4. Test configuration changes with: sudo firehol try"
echo -e "=================================="
exit 0
