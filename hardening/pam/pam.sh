#!/bin/bash
# This script will harden login on Arch Linux

# Create a backup of the original /etc/pam.d/system-auth file
cp /etc/pam.d/system-auth /etc/pam.d/system-auth.bak

# Set password expiration to 90 days
echo "password    requisite     pam_unix.so md5 shadow nullok try_first_pass use_authtok remember=90" >> /etc/pam.d/system-auth

# Set minimum password length to 8 characters
echo "password    requisite     pam_cracklib.so minlen=8" >> /etc/pam.d/system-auth

# Set password complexity requirements
echo "password    requisite     pam_cracklib.so dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 minclass=4 maxrepeat=3" >> /etc/pam.d/system-auth

# Set password lockout after 5 failed attempts
echo "auth        required      pam_tally2.so deny=5 unlock_time=900" >> /etc/pam.d/system-auth

# Set password reuse limit to 3 passwords
echo "password    required      pam_unix.so md5 shadow nullok try_first_pass use_authtok remember=3" >> /etc/pam.d/system-auth

# Set password warning before expiration to 7 days 
echo "password    required      pam_unix.so md5 shadow nullok try_first_pass use_authtok warn=7" >> /etc/pam.d/system-auth