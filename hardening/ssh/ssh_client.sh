#!/bin/bash

# Description: This script configures a client machine to connect to a hardened SSH server.
# It generates an SSH key pair, configures SSH client settings, and assists in copying
# the public key to the server.
# Author: Bruno Schmid @brulliant
# LinkedIn: https://www.linkedin.com/in/schmidbruno/


set -euo pipefail

# Set up the variables
BBlue='\033[1;34m'
NC='\033[0m'

# Variables (adjust as needed)
SSH_PORT=22                  # Replace with the SSH port of the server if different
SERVER_IP="your_server_ip"   # Replace with your server's IP address or hostname
USERNAME="$USER"             # Replace with your username on the server if different
CONFIG_FILE="$HOME/.ssh/config"
KEY_TYPE="ed25519"
KEY_FILE="$HOME/.ssh/id_$KEY_TYPE"

# Functions
check_ssh_version() {
    echo -e "${BBlue}Checking SSH client version...${NC}"
    SSH_VERSION=$(ssh -V 2>&1)
    echo "SSH Client Version: $SSH_VERSION"

    # Parse the version number
    if [[ $SSH_VERSION =~ OpenSSH_([0-9]+)\.([0-9]+) ]]; then
        MAJOR=${BASH_REMATCH[1]}
        MINOR=${BASH_REMATCH[2]}
        if (( MAJOR < 7 )) || (( MAJOR == 7 && MINOR < 6 )); then
            echo -e "${BBlue}Your SSH client version is outdated. Please update to OpenSSH 7.6 or higher.${NC}"
            exit 1
        fi
    else
        echo "Unable to determine SSH client version."
        exit 1
    fi
}

generate_ssh_key() {
    if [ ! -f "$KEY_FILE" ]; then
        echo -e "${BBlue}Generating a new SSH key pair ($KEY_TYPE)...${NC}"
        ssh-keygen -t $KEY_TYPE -C "$USERNAME" -f "$KEY_FILE"
    else
        echo -e "${BBlue}SSH key ($KEY_FILE) already exists.${NC}"
    fi
}

copy_public_key() {
    echo -e "${BBlue}Attempting to copy public key to the server...${NC}"

    read -p "Do you have existing SSH access to the server? (y/n): " HAS_ACCESS
    if [ "$HAS_ACCESS" == "y" ]; then
        # Use ssh-copy-id
        ssh-copy-id -i "$KEY_FILE.pub" -p "$SSH_PORT" "$USERNAME@$SERVER_IP"
    else
        echo "Cannot copy public key automatically without existing access."
        echo "Please copy your public key manually to the server's ~/.ssh/authorized_keys."
        echo "Your public key is located at $KEY_FILE.pub"
    fi
}

configure_ssh_client() {
    echo -e "${BBlue}Configuring SSH client settings in $CONFIG_FILE...${NC}"

    # Create the config file if it doesn't exist
    mkdir -p "$HOME/.ssh"
    touch "$CONFIG_FILE"

    # Backup existing config if not already backed up
    if [ ! -f "${CONFIG_FILE}.bak" ]; then
        cp "$CONFIG_FILE" "${CONFIG_FILE}.bak"
    fi

    # Remove any existing configuration for the server
    sed -i.bak '/^Host myserver$/,/^Host /d' "$CONFIG_FILE" || true

    # Append new configuration
    cat >> "$CONFIG_FILE" <<EOF

Host myserver
    HostName $SERVER_IP
    Port $SSH_PORT
    User $USERNAME
    HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
    KexAlgorithms curve25519-sha256@libssh.org,curve25519-sha256,diffie-hellman-group18-sha512,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256,diffie-hellman-group-exchange-sha256
    Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr
    MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
    PubkeyAuthentication yes
    PasswordAuthentication yes
    IdentitiesOnly yes
    IdentityFile $KEY_FILE
    ServerAliveInterval 10
    ServerAliveCountMax 2
EOF

    echo "SSH client configuration updated."
}

hash_known_hosts() {
    echo -e "${BBlue}Hashing known_hosts file...${NC}"
    ssh-keygen -H -f "$HOME/.ssh/known_hosts" 2>/dev/null || true
    rm -f "$HOME/.ssh/known_hosts.old"
}

test_connection() {
    echo -e "${BBlue}Attempting to connect to the server...${NC}"
    ssh myserver
}

# Main script execution

# Prompt to adjust variables
echo -e "${BBlue}Before proceeding, ensure you've updated the script variables with your server's information.${NC}"
echo "Current settings:"
echo "SSH_PORT = $SSH_PORT"
echo "SERVER_IP = $SERVER_IP"
echo "USERNAME = $USERNAME"
read -p "Have you updated the variables accordingly? (y/n): " VAR_CONFIRM
if [ "$VAR_CONFIRM" != "y" ]; then
    echo -e "${BBlue}Please edit the script to set the correct SERVER_IP, USERNAME, and SSH_PORT.${NC}"
    exit 1
fi

check_ssh_version
generate_ssh_key
copy_public_key
configure_ssh_client
hash_known_hosts

echo -e "${BBlue}Client configuration complete.${NC}"

read -p "Do you want to test the SSH connection now? (y/n): " TEST_CONN
if [ "$TEST_CONN" == "y" ]; then
    test_connection
else
    echo -e "${BBlue}You can connect to the server using 'ssh <TARGET_SERVER>'${NC}"
fi

chmod 700 /home/$USER/.ssh
chmod 600 /home/$USER/.ssh/authorized_keys
chown -R $USER:$USER /home/$USER/.ssh
