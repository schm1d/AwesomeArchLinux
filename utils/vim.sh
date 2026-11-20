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

for cmd in git curl sha256sum; do
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

# vim-plug release 0.15.0. The URL names the commit, so its content cannot
# change, and the download is checked against that file's SHA-256 before it
# is installed where the editor loads it.
PLUG_VIM_COMMIT="4c4e56b5f7384369927a075804b6a17de7644edd"
PLUG_VIM_SHA256="f2e856512c982063d0f4353744a29208e98fc622a474209e3a022969c974654a"

install_plug_vim() {
    local dest="$1" tmp
    mkdir -p "$(dirname "$dest")"
    tmp="$(mktemp "${dest}.XXXXXX")"
    if ! curl -fLo "$tmp" "https://raw.githubusercontent.com/junegunn/vim-plug/${PLUG_VIM_COMMIT}/plug.vim"; then
        rm -f -- "$tmp"
        echo -e "${BRed}Could not download vim-plug.${NC}" >&2
        exit 1
    fi
    if ! printf '%s  %s\n' "$PLUG_VIM_SHA256" "$tmp" | sha256sum --check --status; then
        rm -f -- "$tmp"
        echo -e "${BRed}vim-plug download does not match the pinned SHA-256. Not installed.${NC}" >&2
        exit 1
    fi
    mv -f -- "$tmp" "$dest"
}

# Install vim-plug if not already installed
PLUG_VIM="$HOME/.vim/autoload/plug.vim"
if [ ! -f "$PLUG_VIM" ]; then
    echo -e "${BBlue}Installing vim-plug...${NC}"
    install_plug_vim "$PLUG_VIM"
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
" Each plugin is pinned to a fixed commit (the tip of its default branch on
" 2026-11-20), so :PlugInstall and :PlugUpdate never pull whatever upstream
" holds that day. To update a plugin, read its changes and edit the hash.
call plug#begin('~/.vim/plugged')
Plug 'sheerun/vimrc', { 'commit': '73e4c4606bf54f0f22534afcb2320471566fbd4a' }
Plug 'sheerun/vim-polyglot', { 'commit': 'f061eddb7cdcc614c8406847b2bfb53099832a4e' }
Plug 'preservim/nerdtree', { 'commit': '690d061b591525890f1471c6675bcb5bdc8cdff9' }
Plug 'tpope/vim-fugitive', { 'commit': '3b753cf8c6a4dcde6edee8827d464ba9b8c4a6f0' }
Plug 'airblade/vim-gitgutter', { 'commit': '90b75207bd9b55d8ac4af15f72b4e935462014d0' }
Plug 'tomlion/vim-solidity', { 'commit': '569bbbedc3898236d5912fed0caf114936112ae4' }
Plug 'antenore/vim-safe', { 'commit': '8283021414032b857e950ba89768a42c0c190c14' }
call plug#end()
EOL
fi

echo -e "${BBlue}Installing Vim plugins...${NC}"
GIT_TERMINAL_PROMPT=0 vim --not-a-term +PlugInstall +qall < /dev/null || true

chmod 600 "$VIMRC"
chmod 700 "$HOME/.vim"

echo -e "${BGreen}Vim configuration completed successfully.${NC}"
