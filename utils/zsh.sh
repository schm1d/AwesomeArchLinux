#!/usr/bin/env bash

# =============================================================================
# Script:      zsh.sh
# Description: Installs and configures Zsh with Oh My Zsh, syntax highlighting,
#              autosuggestions, and Powerlevel10k theme on Arch Linux.
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
#
# Usage:       ./zsh.sh
# =============================================================================

set -euo pipefail

BBlue='\033[1;34m'
BRed='\033[1;31m'
BGreen='\033[1;32m'
NC='\033[0m'

# Must NOT run as root — Oh My Zsh installs into user home
if [ "$(id -u)" -eq 0 ]; then
    echo -e "${BRed}Do not run this script as root. Run as your normal user.${NC}" >&2
    exit 1
fi

# Check dependencies
for cmd in git curl; do
    if ! command -v "$cmd" &>/dev/null; then
        echo -e "${BRed}Required command '$cmd' not found. Install it first.${NC}" >&2
        exit 1
    fi
done

# Install Zsh if not already installed
if ! command -v zsh &>/dev/null; then
    echo -e "${BBlue}Installing Zsh...${NC}"
    sudo pacman -S --noconfirm zsh
fi

# Set Zsh as the default shell
ZSH_PATH="$(command -v zsh)"
if [ "$(basename "$SHELL")" != "zsh" ]; then
    echo -e "${BBlue}Setting Zsh as the default shell...${NC}"
    chsh -s "$ZSH_PATH" || {
        echo -e "${BRed}chsh failed. You can set it manually: chsh -s $ZSH_PATH${NC}" >&2
    }
fi

# Install Oh My Zsh if not already installed
if [ ! -d "$HOME/.oh-my-zsh" ]; then
    echo -e "${BBlue}Installing Oh My Zsh...${NC}"
    sh -c "$(curl -fsSL https://raw.githubusercontent.com/robbyrussell/oh-my-zsh/master/tools/install.sh)" "" --unattended
fi

ZSH_CUSTOM="${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}"

# Install zsh-syntax-highlighting plugin
if [ ! -d "$ZSH_CUSTOM/plugins/zsh-syntax-highlighting" ]; then
    echo -e "${BBlue}Installing zsh-syntax-highlighting...${NC}"
    git clone https://github.com/zsh-users/zsh-syntax-highlighting.git \
        "$ZSH_CUSTOM/plugins/zsh-syntax-highlighting"
fi

# Install zsh-autosuggestions plugin
if [ ! -d "$ZSH_CUSTOM/plugins/zsh-autosuggestions" ]; then
    echo -e "${BBlue}Installing zsh-autosuggestions...${NC}"
    git clone https://github.com/zsh-users/zsh-autosuggestions.git \
        "$ZSH_CUSTOM/plugins/zsh-autosuggestions"
fi

# Enable plugins in .zshrc
ZSHRC="$HOME/.zshrc"
if [ -f "$ZSHRC" ]; then
    if ! grep -q "zsh-syntax-highlighting" "$ZSHRC"; then
        echo -e "${BBlue}Enabling plugins in .zshrc...${NC}"
        sed -i 's/plugins=(git)/plugins=(git zsh-syntax-highlighting zsh-autosuggestions)/' "$ZSHRC"
    fi

    # Add source lines if not present
    if ! grep -q "source.*zsh-syntax-highlighting.zsh" "$ZSHRC"; then
        echo "source $ZSH_CUSTOM/plugins/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh" >> "$ZSHRC"
    fi
    if ! grep -q "source.*zsh-autosuggestions.zsh" "$ZSHRC"; then
        echo "source $ZSH_CUSTOM/plugins/zsh-autosuggestions/zsh-autosuggestions.zsh" >> "$ZSHRC"
    fi

    # Set highlight styles (only once)
    if ! grep -q "ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE" "$ZSHRC"; then
        echo "ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE='fg=8'" >> "$ZSHRC"
    fi
fi

# Install Powerlevel10k via yay (requires yay — install with utils/yay.sh first)
if command -v yay &>/dev/null; then
    echo -e "${BBlue}Installing Powerlevel10k font and theme...${NC}"
    yay -S --noconfirm --needed ttf-meslo-nerd-font-powerlevel10k zsh-theme-powerlevel10k-git
else
    echo -e "${BRed}yay not found — skipping Powerlevel10k installation.${NC}" >&2
    echo "Install yay first (utils/yay.sh), then re-run this script." >&2
fi

# Add Powerlevel10k theme to .zshrc if not already present
if [ -f "$ZSHRC" ] && ! grep -q "powerlevel10k.zsh-theme" "$ZSHRC"; then
    echo 'source /usr/share/zsh-theme-powerlevel10k/powerlevel10k.zsh-theme' >> "$ZSHRC"
fi

# Set secure permissions (no sudo needed — user files)
if [ -f "$ZSHRC" ]; then
    chmod 600 "$ZSHRC"
fi

echo -e "${BGreen}Zsh configuration completed. Log out and back in to use Zsh.${NC}"
