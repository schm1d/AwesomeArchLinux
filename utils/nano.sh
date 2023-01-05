#!/bin/bash

#Description    : This script configures nano
#Author         : @brulliant                                                
#Linkedin       : https://www.linkedin.com/in/schmidbruno/


# Install nano
sudo pacman -S nano

echo "Downloading the latest nanorc configuration file from Github..."
curl -sL https://raw.githubusercontent.com/scopatz/nanorc/master/install.sh | sh -s -- -y

# Add the following settings to the nano configuration file to harden it
echo "set const" >> ~/.nanorc
echo "set nohelp" >> ~/.nanorc
echo "set nonewlines" >> ~/.nanorc
echo "set nobackup" >> ~/.nanorc
echo "set nowrap" >> ~/.nanorc
echo "set smooth" >> ~/.nanorc
echo "set tabsize 4" >> ~/.nanorc
echo "set tabstospaces" >> ~/.nanorc
echo "set suspend" >> ~/.nanorc
echo "set viewdirectory" >> ~/.nanorc
echo "set viewoptions all" >> ~/.nanorc
echo "set whitespace newline,space,tab" >> ~/.nanorc
echo "set wordbounds punct,alnum" >> ~/.nanorc
echo "set regexp ^[A-Za-z_][A-Za-z0-9_]*$" >> ~/.nanorc 
 
# Set permissions on the configuration file to prevent unauthorized changes 
chmod 600 ~/.nanorc