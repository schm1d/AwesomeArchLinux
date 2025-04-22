#!/usr/bin/env bash
# ================================================================
# Secure Boot Setup Script
# Description: Generates and enrolls PK/KEK/db/dbx keys, signs EFI binaries,
#              and configures UEFI Secure Boot on an Arch system.
# Author: Bruno Schmid @brulliant
# LinkedIn: https://www.linkedin.com/in/schmidbruno/
# Usage: sudo ./secureboot_setup.sh [-d KEY_DIR] [-p EFI_MOUNT] [-k KEY_SIZE]
#                                     [-v VALID_DAYS] [-o] [-h]
# ================================================================

set -euo pipefail
IFS=$'\n\t'

# Defaults
KEY_DIR="/etc/efi-keys"
EFI_MOUNT="/boot/efi"
KEY_SIZE=2048
VALID_DAYS=3650
UPDATE_ONLY=false
LOGFILE="/var/log/secureboot_setup.log"

# Colors
readonly C_OK="\033[1;32m"
readonly C_INFO="\033[1;34m"
readonly C_ERR="\033[1;31m"
readonly C_NC="\033[0m"

echo_log() { printf "%b %s\n" "${C_INFO}" "${1}" | tee -a "$LOGFILE"; }
echo_err() { printf "%b %s\n" "${C_ERR}" "${1}" | tee -a "$LOGFILE"; exit 1; }

usage() {
  cat <<EOF
Usage: sudo $0 [options]
  -d KEY_DIR     Directory to store keys and lists (default: $KEY_DIR)
  -p EFI_MOUNT   Mounted EFI partition (default: $EFI_MOUNT)
  -k KEY_SIZE    RSA key size in bits (default: $KEY_SIZE)
  -v VALID_DAYS  Certificate validity in days (default: $VALID_DAYS)
  -o             Update-only: enroll existing .esl/.auth files
  -h             Show this help and exit
EOF
  exit 1
}

# Parse arguments
while getopts ":d:p:k:v:oh" opt; do
  case "$opt" in
    d) KEY_DIR="$OPTARG" ;;  
    p) EFI_MOUNT="$OPTARG" ;;  
    k) KEY_SIZE="$OPTARG" ;;  
    v) VALID_DAYS="$OPTARG" ;;  
    o) UPDATE_ONLY=true ;;  
    h) usage ;;              
    :) echo_err "Option -$OPTARG requires an argument." ;;  
    \?) echo_err "Invalid option: -$OPTARG" ;;  
  esac
done

# Ensure root
[[ $(id -u) -eq 0 ]] || echo_err "Must be run as root"

# Check UEFI
[[ -d /sys/firmware/efi/efivars ]] || echo_err "UEFI not detected. Secure Boot requires UEFI."

# Ensure dependencies
for cmd in openssl efibootmgr sbsigntools efi-updatevar cert-to-efi-sig-list sign-efi-sig-list uuidgen; do
  command -v "$cmd" >/dev/null || echo_err "Missing dependency: $cmd"
done

# Prepare environment
mkdir -p "$KEY_DIR"
chmod 700 "$KEY_DIR"
echo_log "Using key directory: $KEY_DIR"
echo_log "EFI partition mount: $EFI_MOUNT"

# File names
declare -A CERT=( [PK]=PK [KEK]=KEK [db]=db [dbx]=dbx )

cd "$KEY_DIR"

if ! \$UPDATE_ONLY; then
  # Generate keys and certificates
echo_log "Generating keys and certificates (size=$KEY_SIZE, validity=$VALID_DAYS days)"
  for name in PK KEK db dbx; do
    openssl req -newkey rsa:"$KEY_SIZE" -nodes \
      -keyout ${name}.key -x509 -sha256 -days "$VALID_DAYS" \
      -subj "/CN=Secure Boot ${name} Certificate/" \
      -out ${name}.crt
    openssl x509 -in ${name}.crt -outform DER -out ${name}.cer
  done

  # Backup existing vars
  echo_log "Backing up existing EFI variables"
  for var in PK KEK db dbx; do
    if efivar --list | grep -qi "^${var}-"; then
      efivars_dir=/sys/firmware/efi/efivars
      cp "$efivars_dir/${var}-*.efi" "${name}_old_${var}.esl" || true
    fi
  done

  # Create .esl and .auth lists
  echo_log "Creating EFI signature lists"
  for var in PK KEK db dbx; do
    uuid="$(uuidgen)"
    cert-to-efi-sig-list -g "$uuid" ${var}.cer ${var}.esl
    sign-efi-sig-list -k PK.key -c PK.crt "$var" ${var}.esl ${var}.auth
    # KEK signs subsequent lists
    if [[ $var == "db" || $var == "dbx" ]]; then
      sign-efi-sig-list -k KEK.key -c KEK.crt "$var" ${var}.esl ${var}.auth
    fi
  done
else
  echo_log "Update-only: skipping key generation"
fi

# Enroll keys
echo_log "Enrolling Secure Boot variables"
for var in PK KEK db dbx; do
  if [[ -f ${var}.auth ]]; then
    efi-updatevar -e -f ${var}.auth "$var"
    echo_log "Enrolled $var"
  else
    echo_err "Missing ${var}.auth – cannot enroll $var"
  fi
done

# Sign GRUB binary
GRUB_EFI="${EFI_MOUNT}/EFI/arch/grubx64.efi"
if [[ -f "$GRUB_EFI" ]]; then
  echo_log "Signing GRUB binary: $GRUB_EFI"
  sbsign --key db.key --cert db.crt --output "$GRUB_EFI" "$GRUB_EFI"
else
  echo_err "GRUB EFI not found at $GRUB_EFI"
fi

# Verify enrollment
echo_log "Verifying Secure Boot variables"
efibootmgr -v || echo_warn "Failed to list EFI boot entries"

echo_log "Secure Boot setup complete. Please reboot to activate."
