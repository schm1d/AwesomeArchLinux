#!/bin/bash

# Description: This script configures Nano with hardening settings
# Author: @brulliant
# LinkedIn: https://www.linkedin.com/in/schmidbruno/

# Function to handle errors
handle_error() {
    echo "Error: $1" >&2
    exit 1
}

# Install Nano if not already installed
if ! command -v nano &> /dev/null; then
    echo "Installing Nano..."
    sudo pacman -S nano --noconfirm || handle_error "Failed to install Nano."
else
    echo "Nano is already installed."
fi

# Download the latest Nano configuration from GitHub
echo "Downloading the latest nanorc configuration file from GitHub..."
curl -sL https://raw.githubusercontent.com/scopatz/nanorc/master/install.sh | sh -s -- -y || handle_error "Failed to download Nano configuration."

# Create backup directory
echo "Creating backup directory..."
mkdir -p ~/.cache/nano/backups/ || handle_error "Failed to create backup directory."

# Append hardening settings to ~/.nanorc if not already present
NANORC=~/.nanorc
echo "Applying hardening settings to Nano configuration..."
declare -A settings=(
    ["set constantshow"]="Show cursor position constantly"
    ["set locking"]="Prevent multiple instances editing the same file"
    ["set nohelp"]="Disable help text"
    ["set nonewlines"]="Avoid adding newlines at file end"
    ["set nowrap"]="Disable line wrapping"
    ["set minibar"]="Show minimal status bar"
    ["set zap"]="Delete selection when typing"
    ["set linenumbers"]="Display line numbers"
    ["set tabsize 4"]="Set tab width to 4 spaces"
    ["set tabstospaces"]="Convert tabs to spaces"
    ["set wordbounds punct,alnum"]="Define word boundaries"
    ["set regexp ^[A-Za-z_][A-Za-z0-9_]*$"]="Set regex for search/highlighting"
    ["set backup"]="Enable backups"
    ["set backupdir \"~/.cache/nano/backups/\""]="Set backup directory"
)

for setting in "${!settings[@]}"; do
    if ! grep -q "^$setting" "$NANORC" 2>/dev/null; then
        echo "$setting" >> "$NANORC"
        echo "Added: ${settings[$setting]}"
    fi
done

# Set secure permissions on the configuration file
echo "Setting secure permissions on Nano configuration..."
sudo chown "$USER:$USER" "$NANORC" || handle_error "Failed to set ownership."
sudo chmod 600 "$NANORC" || handle_error "Failed to set permissions."

echo "Nano configuration completed successfully!"
