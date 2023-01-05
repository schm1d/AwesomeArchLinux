#!/bin/zsh

#Description    : This script configures and hardens the .zshrc file on Arch Linux.
#Author         : @brulliant                                                
#Linkedin       : https://www.linkedin.com/in/schmidbruno/


# Update the system
sudo pacman -Syu

# Install zsh
sudo pacman -S zsh

# Set zsh as the default shell
chsh -s $(which zsh)

# Install oh-my-zsh
sh -c "$(curl -fsSL https://raw.githubusercontent.com/robbyrussell/oh-my-zsh/master/tools/install.sh)"

# Install zsh-syntax-highlighting plugin
git clone https://github.com/zsh-users/zsh-syntax-highlighting.git ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting

# Install zsh-autosuggestions plugin
git clone https://github.com/zsh-users/zsh-autosuggestions ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions

# Enable plugins in .zshrc file
sed -i 's/plugins=(git)/plugins=(git zsh-syntax-highlighting zsh-autosuggestions)/' ~/.zshrc 

# Enable syntax highlighting in .zshrc file
echo "source ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh" >> ~/.zshrc 
echo "source ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions/zsh-autosuggestions.zsh" >> ~/.zshrc 
echo "ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE='fg=8'" >> ~/.zshrcl
echo "ZSH_SYNTAX_HIGHLIGHTING_STYLE='fg=8'" >> ~/.zshrcl 


yay -Sy --noconfirm ttf-meslo-nerd-font-powerlevel10k

yay -Sy --noconfirm zsh-theme-powerlevel10k-git

echo 'source /usr/share/zsh-theme-powerlevel10k/powerlevel10k.zsh-theme' >>! ~/.zshrc

# Add a line to the .zshrc file to prevent it from being executed as a shell script.
echo "export ZDOTDIR=$HOME/.zshrc" >> ~/.zshrc

# Reload .zshrcl file 
source ~/.zshrcl

# Set the permissions on the .zshrc file to be read-only for the owner and group.
chmod 600 ~/.zshrc