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

for cmd in git curl tar sha256sum; do
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
INITLUA="$HOME/.config/nvim/init.lua"

# Neovim reads init.lua or init.vim, never both: with an init.lua in place, an
# added init.vim makes every start fail with E5422 "Conflicting configs" and
# neither the hardening nor the plugin setup below would be loaded. Keep the
# Lua configuration and add the hardening as a plugin file instead, which
# Neovim sources after init.lua.
if [ -f "$INITLUA" ]; then
    HARDENING_LUA="$HOME/.config/nvim/plugin/00-awesome-hardening.lua"
    echo -e "${BBlue}init.lua found — writing modeline hardening to ${HARDENING_LUA}...${NC}"
    mkdir -p -m 0700 "$HOME/.config/nvim/plugin"
    cat > "$HARDENING_LUA" <<'EOL'
-- Written by utils/neovim.sh. Modelines let a file that is merely opened set
-- editor options; keep them off.
vim.o.modeline = false
vim.o.modelines = 0
EOL
    chmod 600 "$HARDENING_LUA"
    chmod 700 "$HOME/.config/nvim"
    echo -e "${BYellow}vim-plug and nvim-treesitter were not set up: plugins are managed by your init.lua.${NC}"
    echo -e "${BGreen}NeoVim modeline hardening installed.${NC}"
    exit 0
fi

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

PLUG_VIM="$HOME/.local/share/nvim/site/autoload/plug.vim"
if [ ! -f "$PLUG_VIM" ]; then
    echo -e "${BBlue}Installing vim-plug...${NC}"
    install_plug_vim "$PLUG_VIM"
fi

# nvim-treesitter is pinned to a fixed commit of its 'master' branch (the one
# that provides nvim-treesitter.configs; tip on 2026-11-20), so :PlugInstall
# and :PlugUpdate never pull whatever upstream holds that day. To update it,
# read upstream's changes and edit the hash in plugins.vim.
TREESITTER_PLUG="Plug 'nvim-treesitter/nvim-treesitter', {'branch': 'master', 'commit': 'cf12346a3414fa1b06af75c79faebe7f76df080a', 'do': ':TSUpdate'}"

PLUGINS_FILE="$HOME/.config/nvim/plugins.vim"
if [ ! -f "$PLUGINS_FILE" ]; then
    echo -e "${BBlue}Creating plugins.vim with nvim-treesitter...${NC}"
    cat > "$PLUGINS_FILE" <<EOL
call plug#begin()
${TREESITTER_PLUG}
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
        sed -i "/call plug#begin()/a ${TREESITTER_PLUG}" "$PLUGINS_FILE"
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
