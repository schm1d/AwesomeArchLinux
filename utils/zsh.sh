#!/bin/bash

# Description: This script configures and hardens Zsh on Arch Linux.
# Author: @brulliant
# LinkedIn: https://www.linkedin.com/in/schmidbruno/

# Function to handle errors
handle_error() {
    echo "Error: $1" >&2
    exit 1
}

# Update the system (optional but recommended)
echo "Updating system packages..."
sudo pacman -Syu --noconfirm || handle_error "Failed to update system."

# Install Zsh if not already installed
if ! command -v zsh &> /dev/null; then
    echo "Installing Zsh..."
    sudo pacman -S zsh --noconfirm || handle_error "Failed to install Zsh."
fi

# Set Zsh as the default shell for the current user
echo "Setting Zsh as the default shell..."
chsh -s $(which zsh) || handle_error "Failed to set Zsh as default shell."

# Install Oh My Zsh if not already installed
if [ ! -d "$HOME/.oh-my-zsh" ]; then
    echo "Installing Oh My Zsh..."
    sh -c "$(curl -fsSL https://raw.githubusercontent.com/robbyrussell/oh-my-zsh/master/tools/install.sh)" "" --unattended || handle_error "Failed to install Oh My Zsh."
fi

# Install zsh-syntax-highlighting plugin if not already installed
if [ ! -d "${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting" ]; then
    echo "Installing zsh-syntax-highlighting..."
    git clone https://github.com/zsh-users/zsh-syntax-highlighting.git ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting || handle_error "Failed to install zsh-syntax-highlighting."
fi

# Install zsh-autosuggestions plugin if not already installed
if [ ! -d "${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}/plugins/zsh-autosuggestions" ]; then
    echo "Installing zsh-autosuggestions..."
    git clone https://github.com/zsh-users/zsh-autosuggestions ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions || handle_error "Failed to install zsh-autosuggestions."
fi

# Enable plugins in .zshrc if not already enabled
ZSHRC="$HOME/.zshrc"
if ! grep -q "plugins=(.*zsh-syntax-highlighting.*zsh-autosuggestions.*)" "$ZSHRC"; then
    echo "Enabling plugins in .zshrc..."
    sed -i 's/plugins=(git)/plugins=(git zsh-syntax-highlighting zsh-autosuggestions)/' "$ZSHRC" || handle_error "Failed to enable plugins."
fi

# Add syntax highlighting and autosuggestions source lines if not present
if ! grep -q "source.*zsh-syntax-highlighting.zsh" "$ZSHRC"; then
    echo "Adding syntax highlighting to .zshrc..."
    echo "source ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh" >> "$ZSHRC"
fi
if ! grep -q "source.*zsh-autosuggestions.zsh" "$ZSHRC"; then
    echo "Adding autosuggestions to .zshrc..."
    echo "source ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions/zsh-autosuggestions.zsh" >> "$ZSHRC"
fi

# Set highlight styles
echo "Setting highlight styles..."
echo "ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE='fg=8'" >> "$ZSHRC"
echo "ZSH_HIGHLIGHT_STYLES[default]='fg=8'" >> "$ZSHRC"

# Install yay if not already installed (AUR helper)
if ! command -v yay &> /dev/null; then
    echo "Installing yay (AUR helper)..."
    sudo pacman -S --needed git base-devel || handle_error "Failed to install dependencies for yay."
    git clone https://aur.archlinux.org/yay.git || handle_error "Failed to clone yay repository."
    cd yay
    makepkg -si --noconfirm || handle_error "Failed to install yay."
    cd ..
    rm -rf yay
fi

# Install ttf-meslo-nerd-font-powerlevel10k and zsh-theme-powerlevel10k-git using yay
echo "Installing Powerlevel10k font and theme..."
yay -Sy --noconfirm ttf-meslo-nerd-font-powerlevel10k zsh-theme-powerlevel10k-git || handle_error "Failed to install Powerlevel10k packages."

# Add Powerlevel10k theme to .zshrc if not already present
if ! grep -q "source /usr/share/zsh-theme-powerlevel10k/powerlevel10k.zsh-theme" "$ZSHRC"; then
    echo "Adding Powerlevel10k theme to .zshrc..."
    echo 'source /usr/share/zsh-theme-powerlevel10k/powerlevel10k.zsh-theme' >> "$ZSHRC"
fi

# Set secure permissions on .zshrc
echo "Setting secure permissions on .zshrc..."
sudo chown "$USER:$USER" "$ZSHRC" || handle_error "Failed to set ownership."
sudo chmod 600 "$ZSHRC" || handle_error "Failed to set permissions."

echo "Zsh configuration completed successfully! Please log out and log back in to use Zsh."
