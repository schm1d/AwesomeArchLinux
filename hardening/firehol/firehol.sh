#!/usr/bin/env bash
#
# Script: firehol.sh
# Description: Installs and configures Firehol with IP sets from Firehol's blocklist-ipsets repository.
# Author: @brulliant
#Linkedin: https://www.linkedin.com/in/schmidbruno/
# Usage: ./firehol.sh

BBlue='\033[1;34m'
NC='\033[0m'

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

for pkg in firehol update-ipsets; do
    if ! command -v "$pkg" &> /dev/null; then
        echo "[!] $pkg is not installed. Please check the installation process."
        exit 1
    fi
done

# ==============================
# 2. Install Firehol from AUR
# ==============================
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

# Install FireHOL as a regular user
# Check if ping is available
if ! command -v ping &> /dev/null; then
    echo -e "${BBlue}[!] The ping command is not available. Installing iputils package...${NC}"
    run_sudo pacman -S --noconfirm iputils || { echo "[!] Failed to install iputils."; exit 1; }
fi

# Install additional dependencies that might be required by FireHOL
run_sudo pacman -S --noconfirm jq less || { echo "[!] Failed to install additional dependencies."; exit 1; }

echo -e "${BBlue}[+] Installing FireHOL from AUR...${NC}"
run_user yay -S --noconfirm firehol || { 
    echo "[!] Failed to install FireHOL. Ensure yay is correctly installed and try again."
    echo "    You may need to install yay or check for AUR helper issues manually."
    exit 1; 
}

# ==============================
# 3. Configure Firehol Rules
# ==============================
FIREHOL_CONF="/etc/firehol/firehol.conf"
BACKUP_CONF="/etc/firehol/firehol.conf.backup.$(date +%F_%T)"

if [ -f "$FIREHOL_CONF" ]; then
    echo -e "${BBlue}[+] Backing up existing Firehol configuration...${NC}"
    run_sudo cp "$FIREHOL_CONF" "$BACKUP_CONF" || { echo "[!] Failed to backup configuration."; exit 1; }
fi

# Generate a simpler configuration to ensure FireHOL starts correctly
echo -e "${BBlue}[+] Creating basic Firehol configuration...${NC}"
cat <<EOF > /tmp/firehol.conf
version 6

# Default interface for all traffic
interface any world
    policy drop
    # Accept specific incoming services
    server ssh accept
    server http accept
    server https accept
    # Allow all outbound traffic
    client all accept
EOF
run_sudo mkdir -p "/etc/firehol"
run_sudo cp /tmp/firehol.conf "$FIREHOL_CONF"
run_sudo chmod 600 "$FIREHOL_CONF" || { echo "[!] Failed to set permissions."; exit 1; }

# ==============================
# 4. Automate Blocklist Updates
# ==============================
echo -e "${BBlue}[+] Scheduling automatic updates via cron, daily...${NC}"
CRON_JOB="*/30 * * * * root /sbin/update-ipsets && /usr/bin/firehol try"
CRON_FILE="/etc/cron.d/firehol-ipsets"

echo "$CRON_JOB" > /tmp/firehol-ipsets
run_sudo cp /tmp/firehol-ipsets "$CRON_FILE"
run_sudo chmod 644 "$CRON_FILE" || { echo "[!] Failed to set permissions on cron file."; exit 1; }
run_sudo systemctl enable cronie --now || { echo "[!] Failed to enable cronie."; exit 1; }

# ==============================
# 5. Enable Firehol Service (but don't start yet)
# ==============================
echo -e "${BBlue}[+] Enabling Firehol service...${NC}"
run_sudo systemctl enable firehol || { echo "[!] Failed to enable Firehol."; exit 1; }

# ==============================
# 6. Test configuration before starting
# ==============================
echo -e "${BBlue}[+] Testing FireHOL configuration...${NC}"
run_sudo firehol try || {
    echo "[!] FireHOL configuration test failed.";
    echo "    Using fallback minimal configuration...";
    
    # Create a minimal fallback configuration
    cat <<EOF > /tmp/firehol-minimal.conf
version 6
interface any world
    policy accept
EOF
    run_sudo cp /tmp/firehol-minimal.conf "$FIREHOL_CONF"
    echo "[+] Created minimal configuration to ensure FireHOL can start."
}

# ==============================
# 7. Starting Firehol with Diagnostic Information
# ==============================
echo -e "${BBlue}[+] Checking FireHOL configuration...${NC}"
run_sudo firehol helpme || { echo "[!] Failed to get FireHOL diagnostic information."; }

echo -e "${BBlue}[+] Running FireHOL debug to check configuration...${NC}"
run_sudo firehol debug || { echo "[!] Failed to debug FireHOL configuration."; }

# Start FireHOL with the basic configuration
echo -e "${BBlue}[+] Trying to start FireHOL with basic configuration...${NC}"
run_sudo systemctl restart firehol || { 
    echo "[!] Failed to start FireHOL service.";
    echo "    Please check the logs with: journalctl -xeu firehol.service";
}

# ==============================
# 8. Add IP Sets After Basic Configuration Works
# ==============================
echo -e "${BBlue}[+] Once FireHOL starts correctly, you can enable IP sets with:${NC}"
echo -e "    sudo update-ipsets enable firehol_level1"
echo -e "    sudo firehol restart"
echo -e ""
echo -e "${BBlue}[+] Then gradually add more IP sets to your configuration as needed${NC}"

echo -e "${BBlue}[+] FireHOL installation complete!${NC}"
echo -e ""
echo -e "=========== NEXT STEPS ==========="
echo -e "1. Check if FireHOL is running with: systemctl status firehol"
echo -e "2. If not running, view logs with: journalctl -xeu firehol.service"
echo -e "3. Once basic configuration works, update with blocklists:"
echo -e "   a. Run: sudo update-ipsets download"
echo -e "   b. Enable specific IP sets: sudo update-ipsets enable firehol_level1"
echo -e "   c. Edit /etc/firehol/firehol.conf to add: blacklist fullbogons ipset:firehol_level1"
echo -e "   d. Test and reload: sudo firehol try"
echo -e "=================================="
exit 0
