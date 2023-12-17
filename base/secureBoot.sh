#!/bin/bash

# Ensure the script is run as root
if [ "$(id -u)" -ne 0 ]; then
   echo "This script must be run as root"
   exit 1
fi

# Check for UEFI mode
if [ ! -d /sys/firmware/efi/efivars ]; then
    echo "UEFI not detected. Secure Boot requires UEFI."
    exit 1
fi

# Install necessary packages
echo "Installing necessary packages..."
pacman -Syu --needed efibootmgr sbsigntools openssl

# Create the keys directory
mkdir -p /etc/efi-keys
cd /etc/efi-keys

# Generate the Platform Key (PK)
openssl req -newkey rsa:2048 -nodes -keyout PK.key -new -x509 -sha256 -days 3650 -subj "/CN=Platform Key/" -out PK.crt
openssl x509 -outform DER -in PK.crt -out PK.cer

# Generate the Key Exchange Key (KEK)
openssl req -newkey rsa:2048 -nodes -keyout KEK.key -new -x509 -sha256 -days 3650 -subj "/CN=Key Exchange Key/" -out KEK.crt
openssl x509 -outform DER -in KEK.crt -out KEK.cer

# Generate the Signature Database key (db)
openssl req -newkey rsa:2048 -nodes -keyout db.key -new -x509 -sha256 -days 3650 -subj "/CN=Signature Database Key/" -out db.crt
openssl x509 -outform DER -in db.crt -out db.cer

# Generate the revoked Signature Database key (dbx)
openssl req -newkey rsa:2048 -nodes -keyout dbx.key -new -x509 -sha256 -days 3650 -subj "/CN=Revoked Signature Database Key/" -out dbx.crt
openssl x509 -outform DER -in dbx.crt -out dbx.cer

# Backup the old EFI signatures
efi-readvar -v PK -o old_PK.esl
efi-readvar -v KEK -o old_KEK.esl
efi-readvar -v db -o old_db.esl
efi-readvar -v dbx -o old_dbx.esl

# Create a new EFI signature list with our keys
cert-to-efi-sig-list -g "$(uuidgen)" PK.crt PK.esl
cert-to-efi-sig-list -g "$(uuidgen)" KEK.crt KEK.esl
cert-to-efi-sig-list -g "$(uuidgen)" db.crt db.esl
cert-to-efi-sig-list -g "$(uuidgen)" dbx.crt dbx.esl

# Sign the EFI signature lists
sign-efi-sig-list -k PK.key -c PK.crt PK PK.esl PK.auth
sign-efi-sig-list -k PK.key -c PK.crt KEK KEK.esl KEK.auth
sign-efi-sig-list -k KEK.key -c KEK.crt db db.esl db.auth
sign-efi-sig-list -k KEK.key -c KEK.crt dbx dbx.esl dbx.auth

# Sign the GRUB bootloader
sbsign --key db.key --cert db.crt --output /boot/efi/EFI/arch/grubx64.efi /boot/efi/EFI/arch/grubx64.efi

# Enroll the keys to UEFI
efi-updatevar -e -f PK.esl PK
efi-updatevar -e -f KEK.esl KEK
efi-updatevar -e -f db.esl db
efi-updatevar -f dbx.esl dbx

echo "Secure Boot setup is complete. Please reboot your system."
