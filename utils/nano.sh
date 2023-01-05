#!/bin/bash

#Description    : This script configures nano
#Author         : @brulliant
#Linkedin       : https://www.linkedin.com/in/schmidbruno/


# Install nano
sudo pacman -S nano

echo "Downloading the latest nanorc configuration file from Github..."
curl -sL https://raw.githubusercontent.com/scopatz/nanorc/master/install.sh | sh -s -- -y

# Add the following settings to the nano configuration file to harden it
echo "set constantshow" >> ~/.nanorc
echo "set locking" >> ~/.nanorc
echo "set nohelp" >> ~/.nanorc
echo "set nonewlines" >> ~/.nanorc
echo "set nowrap" >> ~/.nanorc
echo "set minibar" >> ~/.nanorc
echo "set wrap" >> ~/.nanorc
echo "set zap" >> ~/.nanorc
echo "set linenumbers" >> ~/.nanorc
echo "set tabsize 4" >> ~/.nanorc
echo "set tabstospaces" >> ~/.nanorc
echo "set wordbounds punct,alnum" >> ~/.nanorc
echo "set regexp ^[A-Za-z_][A-Za-z0-9_]*$" >> ~/.nanorc

# Enable and set a working backup directory
set backup                              # Creates backups of your current file.
set backupdir "~/.cache/nano/backups/"  # The location of the backups.

# Set permissions on the configuration file to prevent unauthorized changes 
chmod 600 ~/.nanorc
