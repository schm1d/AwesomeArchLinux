#!/usr/bin/env bash

# =============================================================================
# Script:      neovim.sh
# Description: Installs NeoVim with vim-plug and nvim-treesitter for enhanced
#              syntax highlighting. Applies secure permissions on config files.
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
#
# Usage:       ./neovim.sh
# =============================================================================

set -euo pipefail

BBlue='\033[1;34m'
BRed='\033[1;31m'
BGreen='\033[1;32m'
NC='\033[0m'

# Must NOT run as root — config goes into user home
if [ "$(id -u)" -eq 0 ]; then
    echo -e "${BRed}Do not run this script as root. Run as your normal user.${NC}" >&2
    exit 1
fi

# Install Neovim if not already installed
if ! command -v nvim &>/dev/null; then
    echo -e "${BBlue}Installing Neovim...${NC}"
    sudo pacman -S --noconfirm neovim
fi

# Create Neovim config directory
mkdir -p "$HOME/.config/nvim"

# Create init.vim with basic configurations if it doesn't exist
INITVIM="$HOME/.config/nvim/init.vim"
if [ ! -f "$INITVIM" ]; then
    echo -e "${BBlue}Creating init.vim...${NC}"
    cat > "$INITVIM" <<'EOL'
set encoding=utf-8
filetype on
syntax on
filetype plugin on
EOL
fi

# Install vim-plug if not already installed
PLUG_VIM="$HOME/.local/share/nvim/site/autoload/plug.vim"
if [ ! -f "$PLUG_VIM" ]; then
    echo -e "${BBlue}Installing vim-plug...${NC}"
    curl -fLo "$PLUG_VIM" --create-dirs \
        https://raw.githubusercontent.com/junegunn/vim-plug/master/plug.vim
fi

# Create plugins.vim with nvim-treesitter if it doesn't exist
PLUGINS_FILE="$HOME/.config/nvim/plugins.vim"
if [ ! -f "$PLUGINS_FILE" ]; then
    echo -e "${BBlue}Creating plugins.vim with nvim-treesitter...${NC}"
    cat > "$PLUGINS_FILE" <<'EOL'
call plug#begin()
Plug 'nvim-treesitter/nvim-treesitter', {'do': ':TSUpdate'}
call plug#end()

lua << EOF
local status, configs = pcall(require, 'nvim-treesitter.configs')
if status then
    configs.setup {
        ensure_installed = { "c", "lua", "vim", "vimdoc", "query" },
        highlight = { enable = true },
    }
end
EOF
EOL
else
    if ! grep -q "nvim-treesitter/nvim-treesitter" "$PLUGINS_FILE"; then
        echo -e "${BBlue}Adding nvim-treesitter to existing plugins.vim...${NC}"
        sed -i "/call plug#begin()/a Plug 'nvim-treesitter/nvim-treesitter', {'do': ':TSUpdate'}" "$PLUGINS_FILE"
    fi
fi

# Ensure plugins.vim is sourced in init.vim
if ! grep -q "source.*plugins.vim" "$INITVIM"; then
    echo "source $PLUGINS_FILE" >> "$INITVIM"
fi

# Install plugins in headless mode
echo -e "${BBlue}Installing plugins...${NC}"
nvim --headless +PlugInstall +qall 2>/dev/null || true

# Set secure permissions (no sudo needed — user files)
chmod 600 "$INITVIM" "$PLUGINS_FILE"
chmod 700 "$HOME/.config/nvim"

echo -e "${BGreen}NeoVim configured with nvim-treesitter.${NC}"
