#!/bin/bash

##########################################################################################
#Script Name    : chroot.sh                                   
#Description    : Fully encrypted LVM2 on LUKS with UEFI Arch installation script. 
#               : This is the chroot which should be executed after the 'archinstall.sh'                                                                                        
#Author         : Bruno Schmid                                                
#Email          : schmid.github@gmail.com
#Twitter        : @brulliant
#Linkedin       : https://www.linkedin.com/in/schmidbruno/                     
############################################################################################

# Set up the variables
BBlue='\033[1;34m'
NC='\033[0m'

# change the below values to match with your configuration
DISK='<your_target_disk>' # Should be the same as in the archInstall.sh script
CRYPT_NAME='crypt_lvm' # Should be the same as in the archInstall.sh script
LVM_NAME='lvm_arch' # Should be the same as in the archInstall.sh script
USERNAME='<user_name_goes_here>'
HOSTNAME='<hostname_goes_here>'
LUKS_KEYS='/etc/luksKeys/boot.key' # Where you will store the root partition key
UUID=$(cryptsetup luksDump $DISK"3" | grep UUID | awk '{print $2}')
CPU_VENDOR_ID=$(lscpu | grep Vendor | awk '{print $3}')

pacman-key --init
pacman-key --populate archlinux

# set the timezone
echo -e "${BBlue}Setting the timezone...${NC}" 
ln -sf /usr/share/zoneinfo/Europe/Zurich /etc/localtime &&\
hwclock --systohc --utc &&\

# set up locale
echo -e "${BBlue}Setting up locale...${NC}"
sed -i '/#en_US.UTF-8/s/^#//g' /etc/locale.gen && locale-gen &&\
echo 'LANG=en_US.UTF-8' > /etc/locale.conf &&\
export LANG=en_US.UTF-8 &&\

echo -e "${BBlue}Setting up console keymap and fonts...${NC}"
echo 'KEYMAP=de_CH-latin1' > /etc/vconsole.conf &&\
echo 'FONT=lat9w-16' >> /etc/vconsole.conf &&\
echo 'FONT_MAP=8859-1_to_uni' >> etc/vconsole.conf &&\

# set hostname
echo -e "${BBlue}Setting hostname...${NC}"
echo $HOSTNAME > /etc/hostname &&\
echo "127.0.0.1 localhost localhost.localdomain $HOSTNAME.localdomain $HOSTNAME" > /etc/hosts

echo -e "${BBlue}Enabling NetworkManager...${NC}"
systemctl enable NetworkManager &&\

echo -e "${BBlue}Enabling OpenSSH...${NC}"
systemctl enable sshd &&\

# add a user
echo -e "${BBlue}Adding the user $USERNAME...${NC}"
useradd -g wheel -s /bin/zsh -m $USERNAME &&\
passwd $USERNAME &&\

echo -e "${BBlue}Setting up /home and .ssh/ of the user $USERNAME...${NC}"
mkdir /home/$USERNAME/.ssh
touch /home/$USERNAME/.ssh/authorized_keys &&\
chmod 700 /home/$USERNAME/.ssh
chmod 600 /home/$USERNAME/.ssh/authorized_keys
chown -R $USERNAME:$USERNAME /home/$USERNAME

# GRUB hardening setup and encryption
echo -e "${BBlue}Adjusting /etc/mkinitcpio.conf for encryption...${NC}"
sed -i "s|^HOOKS=.*|HOOKS=(base udev autodetect keyboard keymap modconf block encrypt lvm2 filesystems fsck)|g" /etc/mkinitcpio.conf
sed -i "s|^FILES=.*|FILES=(${LUKS_KEYS})|g" /etc/mkinitcpio.conf
mkinitcpio -p linux &&\

echo -e "${BBlue}Adjusting etc/default/grub for encryption...${NC}"
sed -i '/GRUB_ENABLE_CRYPTODISK/s/^#//g' /etc/default/grub


echo -e "${BBlue}Hardening GRUB and Kernel boot options...${NC}"

# GRUBSEC Hardening explanation:
# slab_nomerge: This disables slab merging, which significantly increases the difficulty of heap exploitation
# init_on_alloc=1 init_on_free=1: enables zeroing of memory during allocation and free time, which can help mitigate use-after-free vulnerabilities and erase sensitive information in memory.
# page_alloc.shuffle=1: randomises page allocator freelists, improving security by making page allocations less predictable. This also improves performance.
# pti=on: enables Kernel Page Table Isolation, which mitigates Meltdown and prevents some KASLR bypasses.
# randomize_kstack_offset=on:  randomises the kernel stack offset on each syscall, which makes attacks that rely on deterministic kernel stack layout significantly more difficult
# vsyscall=none: disables vsyscalls, as they are obsolete and have been replaced with vDSO. vsyscalls are also at fixed addresses in memory, making them a potential target for ROP attacks.
# lockdown=confidentiality: eliminate many methods that user space code could abuse to escalate to kernel privileges and extract sensitive information.
GRUBSEC="\"slab_nomerge init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 pti=on randomize_kstack_offset=on vsyscall=none lockdown=confidentiality quiet loglevel=3\""
GRUBCMD="\"cryptdevice=UUID=$UUID:$LVM_NAME root=/dev/mapper/$LVM_NAME-root cryptkey=rootfs:$LUKS_KEYS\""
sed -i "s|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT=${GRUBSEC}|g" /etc/default/grub
sed -i "s|^GRUB_CMDLINE_LINUX=.*|GRUB_CMDLINE_LINUX=${GRUBCMD}|g" /etc/default/grub

echo -e "${BBlue}Setting up GRUB...${NC}"
grub-install --target=x86_64-efi --efi-directory=/efi --bootloader-id=GRUB --recheck &&\
grub-mkconfig -o /boot/grub/grub.cfg &&\
chmod 600 $LUKS_KEYS


echo -e "${BBlue}Installing CPU ucode...${NC}"
# Use grep to check if the string 'Intel' is present in the CPU info
if [[ $CPU_VENDOR_ID =~ "GenuineIntel" ]]; then
    pacman -S intel-ucode --noconfirm
elif
    # If the string 'Intel' is not present, check if the string 'AMD' is present
    [[ $CPU_VENDOR_ID =~ "AuthenticAMD" ]]; then
    pacman -S amd-ucode --noconfirm
else
    # If neither 'Intel' nor 'AMD' is present, then it is an unknown CPU
    echo "This is an unknown CPU."
fi

echo -e "${BBlue}Setting permission on config files...${NC}"

chmod 0700 /boot

chmod 644 /etc/hosts.allow
chmod 644 /etc/hosts.deny
chmod 644 /etc/passwd
chown root:root /etc/passwd
chmod 644 /etc/group
chown root:root /etc/group
chmod 600 /etc/shadow
chown root:root /etc/shadow
chmod 600 /etc/gshadow
chown root:root /etc/gshadow
chown root:root /etc/ssh/sshd_config
chmod 600 /etc/ssh/sshd_config
chown root:root /etc/fstab
chown root:root /etc/issue
chmod 644 /etc/issue
chown root:root /boot/grub/grub.cfg
chmod og-rwx /boot/grub/grub.cfg
chown root:root /etc/sudoers.d/
chmod 750 /etc/sudoers.d
chmod 0440 /etc/sudoers
chmod 0700 /etc/sysctl.conf
chmod 02750 /bin/ping 
chmod 02750 /usr/bin/w 
chmod 02750 /usr/bin/who
chmod 02750 /usr/bin/whereis
chmod 0600 /etc/login.defs
chown root:root /etc/motd
chmod 644 /etc/motd


echo -e "${BBlue}Setting root password...${NC}"
passwd &&\

echo -e "${BBlue}Installation completed! You can reboot the system now.${NC}"
rm /chroot.sh
exit
