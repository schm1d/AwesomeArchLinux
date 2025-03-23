#!/bin/bash

# Description: This script configures Vim with plugins and hardening settings
# Author: @brulliant
# LinkedIn: https://www.linkedin.com/in/schmidbruno/

# Function to handle errors
handle_error() {
    echo "Error: $1" >&2
    exit 1
}

# Install Vim if not already installed
if ! command -v vim &> /dev/null; then
    echo "Installing Vim..."
    sudo pacman -S vim --noconfirm || handle_error "Failed to install Vim."
else
    echo "Vim is already installed."
fi

# Install vim-plug if not already installed
PLUG_VIM=~/.vim/autoload/plug.vim
if [ ! -f "$PLUG_VIM" ]; then
    echo "Installing vim-plug..."
    curl -fLo "$PLUG_VIM" --create-dirs \
        https://raw.githubusercontent.com/junegunn/vim-plug/master/plug.vim || handle_error "Failed to install vim-plug."
fi

# Create .vimrc if it doesn't exist
VIMRC=~/.vimrc
if [ ! -f "$VIMRC" ]; then
    echo "Creating .vimrc..."
    touch "$VIMRC" || handle_error "Failed to create .vimrc."
fi

# Add vim-plug configuration to .vimrc if not already present
echo "Adding vim-plug configuration to .vimrc..."
if ! grep -q "call plug#begin('~/.vim/plugged')" "$VIMRC"; then
    cat <<EOL >> "$VIMRC"

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
echo "Installing Vim plugins..."
vim +PlugInstall +qall || handle_error "Failed to install Vim plugins."

# Hardening: Set secure permissions on .vimrc
echo "Setting secure permissions on .vimrc..."
sudo chown "$USER:$USER" "$VIMRC" || handle_error "Failed to set ownership."
sudo chmod 600 "$VIMRC" || handle_error "Failed to set permissions."

echo "Vim configuration completed successfully!"
