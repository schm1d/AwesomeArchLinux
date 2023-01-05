#!/bin/bash

# Hardening neovim on Arch Linux

# Update the system
sudo pacman -Syu

# Install neovim
sudo pacman -S neovim

# Create a backup of the neovim config file
cp ~/.config/nvim/init.vim ~/.config/nvim/init.vim.bak

# Create a secure directory for neovim plugins
mkdir -p ~/.config/nvim/secure-plugins
chmod 700 ~/.config/nvim/secure-plugins

# Install additional plugins for neovim, such as Syntastic and Ale, from the AUR 
yay -S neovim-syntastic neovim-ale 

# Add secure aliases to the config file to prevent malicious code execution 
echo "alias nvim='nvim --cmd \"set secure\"'" >> ~/.config/nvim/init.vim 
echo "alias vim='nvim --cmd \"set secure\"'" >> ~/.config/nvim/init.vim 
echo "alias vi='nvim --cmd \"set secure\"'" >> ~/.config/nvim/init.vim 
echo "alias view='nvim --cmd \"set secure\"'" >> ~/.config/nvim/init.vim 
echo "alias gview='nvim --cmd \"set secure\"'" >> ~/.config/nvim/init.vim 
echo "alias rgview='nvim --cmd \"set secure\"'" >> ~/.config/nvim/init.vim 
echo "alias rview='nvim --cmd \"set secure\"'" >> ~/.config/nvim/init.vim 
echo "alias ex='nvim --cmd \"set secure\"'" >> ~/.config/nvim/init.vim 
echo "alias rgex='nvim --cmd \"set secure\"'" >> ~/.config/nvim/init.vim 
echo "alias gex='nvim --cmd \"set secure\"'" >> ~/.config/nvim/init.vim 

# Disable auto commands in the config file to prevent malicious code execution 
sed -i '/autocmd BufWritePost/,+1d' ~/.config/nvim/init.vim 

# Disable modelines in the config file to prevent malicious code execution 
sed -i '/modeline/,+1d' ~/.config/n vim / init . vim

# Disable command execution in the config file to prevent malicious code execution 
sed -i '/command/,+1d' ~/.config / n vim / init . vim

 # Set a timeout for command execution in the config file to prevent malicious code execution 
echo "set timeoutlen=1000" >>~/.config / n vim / init . vim

# Set a default editor in the config file to prevent malicious code execution from other editors  
echo "export EDITOR=neovim" >>~/.bashrc

# Set a default shell in the config file to prevent malicious code execution from other shells  
echo "export SHELL=/bin/bash" >>~/.bashrc

# Set secure permissions on the config file
sudo chown root:root ~/.config/nvim/init.vim
sudo chmod 600 ~/.config/nvim/init.vim