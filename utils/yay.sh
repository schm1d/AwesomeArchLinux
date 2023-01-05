#!/bin/sh

#Description    : This script will install yay on Arch Linux
#Author         : @brulliant                                                
#Linkedin       : https://www.linkedin.com/in/schmidbruno/


# Update the repository
sudo pacman -Syu

# Clone the yay repo from github
git clone https://aur.archlinux.org/yay.git

# Change directory to yay
cd yay

# Make the package 
makepkg -si

# Clean up the yay directory 
cd .. && rm -rf yay