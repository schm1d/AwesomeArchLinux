#!/usr/bin/env bash

# =============================================================================
# Script:      neovim.sh
# Description: Installs NeoVim with vim-plug and nvim-treesitter for enhanced
#              syntax highlighting. Applies editor hardening and secure
#              permissions while avoiding /tmp noexec failures.
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
BYellow='\033[1;33m'
NC='\033[0m'

# Must NOT run as root — config goes into user home
if [ "$(id -u)" -eq 0 ]; then
    echo -e "${BRed}Do not run this script as root. Run as your normal user.${NC}" >&2
    exit 1
fi

for cmd in git curl tar; do
    if ! command -v "$cmd" &>/dev/null; then
        echo -e "${BRed}Required command '$cmd' not found. Install it first.${NC}" >&2
        exit 1
    fi
done

if ! command -v nvim &>/dev/null; then
    echo -e "${BBlue}Installing Neovim...${NC}"
    sudo pacman -S --needed --noconfirm neovim
fi

mkdir -p -m 0700 "$HOME/.config" "$HOME/.config/nvim" "$HOME/.cache" "$HOME/.cache/nvim/tmp"
if command -v setfacl &>/dev/null; then
    setfacl -b -k "$HOME/.cache/nvim/tmp" 2>/dev/null || true
fi

INITVIM="$HOME/.config/nvim/init.vim"
if [ ! -f "$INITVIM" ]; then
    echo -e "${BBlue}Creating init.vim...${NC}"
    cat > "$INITVIM" <<'EOL'
set encoding=utf-8
set nomodeline
set modelines=0
filetype on
syntax on
filetype plugin on
EOL
elif ! grep -q "set nomodeline" "$INITVIM"; then
    printf '\nset nomodeline\nset modelines=0\n' >> "$INITVIM"
fi

PLUG_VIM="$HOME/.local/share/nvim/site/autoload/plug.vim"
if [ ! -f "$PLUG_VIM" ]; then
    echo -e "${BBlue}Installing vim-plug...${NC}"
    curl -fLo "$PLUG_VIM" --create-dirs \
        https://raw.githubusercontent.com/junegunn/vim-plug/master/plug.vim
fi

PLUGINS_FILE="$HOME/.config/nvim/plugins.vim"
if [ ! -f "$PLUGINS_FILE" ]; then
    echo -e "${BBlue}Creating plugins.vim with nvim-treesitter...${NC}"
    cat > "$PLUGINS_FILE" <<'EOL'
call plug#begin()
Plug 'nvim-treesitter/nvim-treesitter', {'branch': 'master', 'do': ':TSUpdate'}
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
        sed -i "/call plug#begin()/a Plug 'nvim-treesitter/nvim-treesitter', {'branch': 'master', 'do': ':TSUpdate'}" "$PLUGINS_FILE"
    fi
fi

if ! grep -q "source.*plugins.vim" "$INITVIM"; then
    echo "source $PLUGINS_FILE" >> "$INITVIM"
fi

echo -e "${BBlue}Installing plugins...${NC}"
TMPDIR="$HOME/.cache/nvim/tmp" GIT_TERMINAL_PROMPT=0 nvim --headless +PlugInstall +qall 2>/dev/null || true

if command -v cc &>/dev/null && [[ -x "$(command -v cc)" ]]; then
    TMPDIR="$HOME/.cache/nvim/tmp" nvim --headless "+TSUpdateSync" +qall 2>/dev/null || true
else
    echo -e "${BYellow}Note: C compiler not accessible in current session (check 'compilers' group membership); treesitter parsers will compile once compiler access is active.${NC}"
fi

chmod 600 "$INITVIM" "$PLUGINS_FILE"
chmod 700 "$HOME/.config/nvim"

echo -e "${BGreen}NeoVim configured with nvim-treesitter.${NC}"
