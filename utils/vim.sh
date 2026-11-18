#!/usr/bin/env bash

# =============================================================================
# Script:      vim.sh
# Description: Installs Vim with vim-plug and a curated set of plugins,
#              then applies editor hardening and secure permissions.
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

for cmd in git curl; do
    if ! command -v "$cmd" &>/dev/null; then
        echo -e "${BRed}Required command '$cmd' not found. Install it first.${NC}" >&2
        exit 1
    fi
done

if ! command -v vim &>/dev/null; then
    echo -e "${BBlue}Installing Vim...${NC}"
    sudo pacman -S --needed --noconfirm vim
fi

mkdir -p -m 0700 "$HOME/.vim" "$HOME/.vim/swap" "$HOME/.vim/backup" "$HOME/.vim/undo"

# Install vim-plug if not already installed
PLUG_VIM="$HOME/.vim/autoload/plug.vim"
if [ ! -f "$PLUG_VIM" ]; then
    echo -e "${BBlue}Installing vim-plug...${NC}"
    curl -fLo "$PLUG_VIM" --create-dirs \
        https://raw.githubusercontent.com/junegunn/vim-plug/master/plug.vim
fi

VIMRC="$HOME/.vimrc"
if [ ! -f "$VIMRC" ]; then
    touch "$VIMRC"
fi

if ! grep -q "set nomodeline" "$VIMRC"; then
    cat >> "$VIMRC" <<'EOL'

" Editor security hardening (prevent modeline code execution & world-readable swap)
set nomodeline
set modelines=0
set directory^=~/.vim/swap//
set backupdir^=~/.vim/backup//
set undodir^=~/.vim/undo//
set undofile
EOL
fi

if ! grep -q "call plug#begin" "$VIMRC"; then
    echo -e "${BBlue}Adding vim-plug configuration to .vimrc...${NC}"
    cat >> "$VIMRC" <<'EOL'

" vim-plug configuration
call plug#begin('~/.vim/plugged')
Plug 'sheerun/vimrc'
Plug 'sheerun/vim-polyglot'
Plug 'preservim/nerdtree'
Plug 'tpope/vim-fugitive'
Plug 'airblade/vim-gitgutter'
Plug 'tomlion/vim-solidity'
Plug 'antenore/vim-safe'
call plug#end()
EOL
fi

echo -e "${BBlue}Installing Vim plugins...${NC}"
GIT_TERMINAL_PROMPT=0 vim --not-a-term +PlugInstall +qall < /dev/null || true

chmod 600 "$VIMRC"
chmod 700 "$HOME/.vim"

echo -e "${BGreen}Vim configuration completed successfully.${NC}"
