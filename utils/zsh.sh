#!/usr/bin/env bash

# =============================================================================
# Script:      zsh.sh
# Description: Installs and configures Zsh with Oh My Zsh, syntax highlighting,
#              autosuggestions, Powerlevel10k theme, and umask/history hardening.
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
BYellow='\033[1;33m'
NC='\033[0m'

# Must NOT run as root — Oh My Zsh installs into user home
if [ "$(id -u)" -eq 0 ]; then
    echo -e "${BRed}Do not run this script as root. Run as your normal user.${NC}" >&2
    exit 1
fi

for cmd in git curl; do
    if ! command -v "$cmd" &>/dev/null; then
        echo -e "${BRed}Required command '$cmd' not found. Install it first.${NC}" >&2
        exit 1
    fi
done

if ! command -v zsh &>/dev/null; then
    echo -e "${BBlue}Installing Zsh...${NC}"
    sudo pacman -S --needed --noconfirm zsh
fi

ZSH_PATH="$(command -v zsh)"
CURRENT_LOGIN_SHELL="$(getent passwd "$(id -un)" | cut -d: -f7)"
if [ "$(basename "${CURRENT_LOGIN_SHELL:-}")" != "zsh" ]; then
    echo -e "${BBlue}Setting Zsh as the default shell...${NC}"
    chsh -s "$ZSH_PATH" || {
        echo -e "${BYellow}chsh failed. You can set it manually: chsh -s $ZSH_PATH${NC}" >&2
    }
fi

if [ ! -d "$HOME/.oh-my-zsh" ]; then
    echo -e "${BBlue}Installing Oh My Zsh...${NC}"
    git clone --depth=1 https://github.com/ohmyzsh/ohmyzsh.git "$HOME/.oh-my-zsh"
fi
chmod 700 "$HOME/.oh-my-zsh"

ZSH_CUSTOM="${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}"
ZSHRC="$HOME/.zshrc"

if [ ! -f "$ZSHRC" ] && [ -f "$HOME/.oh-my-zsh/templates/zshrc.zsh-template" ]; then
    cp "$HOME/.oh-my-zsh/templates/zshrc.zsh-template" "$ZSHRC"
fi

if [ ! -d "$ZSH_CUSTOM/plugins/zsh-autosuggestions" ]; then
    echo -e "${BBlue}Installing zsh-autosuggestions...${NC}"
    git clone --depth=1 https://github.com/zsh-users/zsh-autosuggestions.git \
        "$ZSH_CUSTOM/plugins/zsh-autosuggestions"
fi

if [ ! -d "$ZSH_CUSTOM/plugins/zsh-syntax-highlighting" ]; then
    echo -e "${BBlue}Installing zsh-syntax-highlighting...${NC}"
    git clone --depth=1 https://github.com/zsh-users/zsh-syntax-highlighting.git \
        "$ZSH_CUSTOM/plugins/zsh-syntax-highlighting"
fi

# Install Powerlevel10k via yay if available (with ACL-clean cache dir)
if command -v yay &>/dev/null; then
    echo -e "${BBlue}Installing Powerlevel10k font and theme...${NC}"
    mkdir -p -m 0700 "$HOME/.cache" "$HOME/.cache/yay" "$HOME/.cache/yay-tmp"
    if command -v setfacl &>/dev/null; then
        setfacl -b -k "$HOME/.cache/yay" "$HOME/.cache/yay-tmp" 2>/dev/null || true
    fi
    TMPDIR="$HOME/.cache/yay-tmp" yay -S --noconfirm --needed ttf-meslo-nerd-font-powerlevel10k zsh-theme-powerlevel10k-git
    rm -rf -- "$HOME/.cache/yay-tmp" 2>/dev/null || true
else
    echo -e "${BYellow}yay not found — skipping Powerlevel10k installation.${NC}" >&2
    echo "Install yay first (utils/yay.sh), then re-run this script if Powerlevel10k is desired." >&2
fi

if [ -f "$ZSHRC" ]; then
    # Keep plugins loaded once in the proper order (autosuggestions before syntax-highlighting)
    if grep -q '^plugins=(git)$' "$ZSHRC"; then
        echo -e "${BBlue}Enabling plugins in .zshrc...${NC}"
        sed -i 's/^plugins=(git)$/plugins=(git zsh-autosuggestions zsh-syntax-highlighting)/' "$ZSHRC"
    fi

    if ! grep -q "ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE" "$ZSHRC"; then
        echo "ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE='fg=8'" >> "$ZSHRC"
    fi

    if ! grep -qxF 'umask 027' "$ZSHRC"; then
        echo 'umask 027' >> "$ZSHRC"
    fi

    if ! grep -q 'HIST_IGNORE_SPACE' "$ZSHRC"; then
        echo 'setopt HIST_IGNORE_SPACE HIST_IGNORE_ALL_DUPS' >> "$ZSHRC"
    fi

    if [ -r /usr/share/zsh-theme-powerlevel10k/powerlevel10k.zsh-theme ] && ! grep -q "powerlevel10k.zsh-theme" "$ZSHRC"; then
        echo 'source /usr/share/zsh-theme-powerlevel10k/powerlevel10k.zsh-theme' >> "$ZSHRC"
    fi

    chmod 600 "$ZSHRC"
fi

echo -e "${BGreen}Zsh configuration completed. Log out and back in to use Zsh.${NC}"
