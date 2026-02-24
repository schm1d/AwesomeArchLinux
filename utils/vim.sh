#!/usr/bin/env bash

# =============================================================================
# Script:      vim.sh
# Description: Installs Vim with vim-plug and a curated set of plugins,
#              then applies secure permissions on configuration files.
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
#
# Usage:       ./vim.sh
# =============================================================================

set -euo pipefail

BBlue='\033[1;34m'
BRed='\033[1;31m'
BGreen='\033[1;32m'
NC='\033[0m'

# Must NOT run as root — vim-plug installs into the user's home
if [ "$(id -u)" -eq 0 ]; then
    echo -e "${BRed}Do not run this script as root. Run as your normal user.${NC}" >&2
    exit 1
fi

# Install Vim if not already installed
if ! command -v vim &>/dev/null; then
    echo -e "${BBlue}Installing Vim...${NC}"
    sudo pacman -S --noconfirm vim
fi

# Install vim-plug if not already installed
PLUG_VIM="$HOME/.vim/autoload/plug.vim"
if [ ! -f "$PLUG_VIM" ]; then
    echo -e "${BBlue}Installing vim-plug...${NC}"
    curl -fLo "$PLUG_VIM" --create-dirs \
        https://raw.githubusercontent.com/junegunn/vim-plug/master/plug.vim
fi

# Create .vimrc if it doesn't exist
VIMRC="$HOME/.vimrc"
if [ ! -f "$VIMRC" ]; then
    touch "$VIMRC"
fi

# Add vim-plug configuration to .vimrc if not already present
if ! grep -q "call plug#begin" "$VIMRC"; then
    echo -e "${BBlue}Adding vim-plug configuration to .vimrc...${NC}"
    cat >> "$VIMRC" <<'EOL'

" vim-plug configuration
call plug#begin('~/.vim/plugged')
Plug 'sheerun/vimrc'
Plug 'sheerun/vim-polyglot'
Plug 'scrooloose/nerdtree'
Plug 'tpope/vim-fugitive'
Plug 'airblade/vim-gitgutter'
Plug 'tomlion/vim-solidity'
Plug 'antenore/vim-safe'
call plug#end()
EOL
fi

# Install plugins using vim-plug
echo -e "${BBlue}Installing Vim plugins...${NC}"
vim +PlugInstall +qall

# Set secure permissions (no sudo needed — these are user files)
chmod 600 "$VIMRC"
chmod 700 "$HOME/.vim"

echo -e "${BGreen}Vim configuration completed successfully.${NC}"
