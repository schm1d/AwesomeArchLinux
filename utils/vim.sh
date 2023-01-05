
#!/bin/bash

#Description    : This script configures vim
#Author         : @brulliant
#Linkedin       : https://www.linkedin.com/in/schmidbruno/

# Install vim-plug package manager
curl -fLo ~/.vim/autoload/plug.vim --create-dirs \
    https://raw.githubusercontent.com/junegunn/vim-plug/master/plug.vim

# Create .vimrc file if it doesn't exist
if [ ! -f ~/.vimrc ]; then
    touch ~/.vimrc
fi

# Add vim-plug configuration to .vimrc file
echo "call plug#begin('~/.vim/plugged')" >> ~/.vimrc
echo "Plug 'sheerun/vimrc'" >> ~/.vimrc
echo "Plug 'sheerun/vim-polyglot'" >> ~/.vimrc
echo "Plug 'scrooloose/nerdtree'" >> ~/.vimrc 
echo "Plug 'tpope/vim-fugitive'" >> ~/.vimrc 
echo "Plug 'airblade/vim-gitgutter'" >> ~/.vimrc
echo "Plug 'tomlion/vim-solidity'" >> ~/.vimrc
echo "call plug#end()" >> ~/.vimrc 

 # Install plugins using vim-plug package manager 
 vim +PlugInstall +qall