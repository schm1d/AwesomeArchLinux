
#!/usr/bin/env bash

# Description: This is the chroot script for Arch Linux installation.
# Author: Bruno Schmid @brulliant
# LinkedIn: https://www.linkedin.com/in/schmidbruno/

set -euo pipefail

# Set up the variables
BBlue='\033[1;34m'
NC='\033[0m'


echo -e "${BBlue}installing WhiteSur Theme...${NC}"
git clone https://github.com/vinceliuice/WhiteSur-gtk-theme.git --depth=1

cd ./WhiteSur-gtk-theme

./install.sh --color dark --theme blue --gnomeshell -icon arch --roundedmaxwindow

cd ../

rm -rf ./WhiteSur-gtk-theme

https://github.com/vinceliuice/grub2-themes

cd ./grub2-themes

sudo ./install.sh -t vimix -s ultrawide -i whitesur -b /boot/grub

cd ../

rm -rf ./grub2-themes
