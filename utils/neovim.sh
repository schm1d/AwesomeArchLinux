#!/bin/bash

# Description: This script installs and configures NeoVim on Arch Linux.
#              It also installs https://github.com/nvim-treesitter/nvim-treesitter?tab=readme-ov-file
# Author: Bruno Schmid @brulliant
# LinkedIn: https://www.linkedin.com/in/schmidbruno/

set -euo pipefail

BBlue='\033[1;34m'
NC='\033[0m'

# Function to handle errors
handle_error() {
    echo "Error: $1" >&2
    exit 1
}

# Update the system (optional but recommended for security)
echo "Updating system packages..."
sudo pacman -Syu --noconfirm || handle_error "Failed to update system."

# Install Neovim if not already installed
if ! command -v nvim &> /dev/null; then
    echo "Installing Neovim..."
    sudo pacman -S neovim --noconfirm || handle_error "Failed to install Neovim."
fi

# Create Neovim config directory if it doesn't exist
mkdir -p ~/.config/nvim

# Create init.vim with basic configurations if it doesn't exist
if [ ! -f ~/.config/nvim/init.vim ]; then
    echo "Creating basic init.vim..."
    cat > ~/.config/nvim/init.vim <<EOL
set encoding=utf-8
filetype on
syntax on
filetype plugin on
EOL
fi

# Install vim-plug if not already installed
if [ ! -f ~/.local/share/nvim/site/autoload/plug.vim ]; then
    echo "Installing vim-plug..."
    curl -fLo ~/.local/share/nvim/site/autoload/plug.vim --create-dirs \
        https://raw.githubusercontent.com/junegunn/vim-plug/master/plug.vim || handle_error "Failed to install vim-plug."
fi

# Create or append to plugins.vim for nvim-treesitter
PLUGINS_FILE=~/.config/nvim/plugins.vim
if [ ! -f "$PLUGINS_FILE" ]; then
    echo "Creating plugins.vim with nvim-treesitter..."
    cat > "$PLUGINS_FILE" <<EOL
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
    if ! grep -q "Plug 'nvim-treesitter/nvim-treesitter'" "$PLUGINS_FILE"; then
        echo "Adding nvim-treesitter to existing plugins.vim..."
        sed -i "/call plug#begin()/a Plug 'nvim-treesitter/nvim-treesitter', {'do': ':TSUpdate'}" "$PLUGINS_FILE"
        echo -e "\nlua << EOF\nlocal status, configs = pcall(require, 'nvim-treesitter.configs')\nif status then\n    configs.setup {\n        ensure_installed = { \"c\", \"lua\", \"vim\", \"vimdoc\", \"query\" },\n        highlight = { enable = true },\n    }\nend\nEOF" >> "$PLUGINS_FILE"
    fi
fi

# Ensure plugins.vim is sourced in init.vim
if ! grep -q "source ~/.config/nvim/plugins.vim" ~/.config/nvim/init.vim; then
    echo "Sourcing plugins.vim in init.vim..."
    echo "source ~/.config/nvim/plugins.vim" >> ~/.config/nvim/init.vim
fi

# Install plugins using Neovim in headless mode
echo "Installing plugins..."
nvim --headless +PlugInstall +qall || handle_error "Failed to install plugins."

# Create a secure directory for future plugin management (optional)
mkdir -p ~/.config/nvim/secure-plugins
chmod 700 ~/.config/nvim/secure-plugins

# Set secure permissions on config files
echo "Setting secure permissions on config files..."
sudo chown $USER:$USER ~/.config/nvim/init.vim
sudo chown $USER:$USER ~/.config/nvim/plugins.vim
sudo chmod 600 ~/.config/nvim/init.vim
sudo chmod 600 ~/.config/nvim/plugins.vim

echo "Neovim is set up with nvim-treesitter for enhanced syntax highlighting and hardened configurations."
