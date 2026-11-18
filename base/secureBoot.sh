#!/usr/bin/env bash
# ================================================================
# Secure Boot Setup Script
# Description: Generates and enrolls PK/KEK/db keys, signs EFI binaries,
#              and configures UEFI Secure Boot on an Arch system.
# Author: Bruno Schmid @brulliant
# LinkedIn: https://www.linkedin.com/in/schmidbruno/
# Usage: sudo ./secureBoot.sh [-d KEY_DIR] [-p EFI_MOUNT] [-k KEY_SIZE]
#                             [-v VALID_DAYS] [-o] [-h]
# ================================================================

set -euo pipefail
IFS=$'\n\t'

# Defaults
KEY_DIR="/etc/efi-keys"
if [[ -d "/efi" ]]; then
    EFI_MOUNT="/efi"
elif [[ -d "/boot/efi" ]]; then
    EFI_MOUNT="/boot/efi"
else
    EFI_MOUNT="/boot"
fi
KEY_SIZE=4096
VALID_DAYS=3650
UPDATE_ONLY=false
LOGFILE="/var/log/secureboot_setup.log"

# Colors
readonly C_OK="\033[1;32m" C_INFO="\033[1;34m" C_ERR="\033[1;31m" C_NC="\033[0m"

log_to_file() {
    if [[ $(id -u) -eq 0 && -n "${LOGFILE:-}" ]]; then
        printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" >> "$LOGFILE" 2>/dev/null || true
    fi
}

echo_log() {
    printf '%b[*]%b %s\n' "${C_INFO}" "${C_NC}" "$1"
    log_to_file "INFO: $1"
}

echo_ok() {
    printf '%b[+]%b %s\n' "${C_OK}" "${C_NC}" "$1"
    log_to_file "OK: $1"
}

echo_err() {
    printf '%b[!]%b %s\n' "${C_ERR}" "${C_NC}" "$1" >&2
    log_to_file "ERROR: $1"
    exit 1
}

usage() {
    cat <<EOF
Usage: sudo $0 [options]
  -d KEY_DIR     Directory to store keys and lists (default: $KEY_DIR)
  -p EFI_MOUNT   Mounted EFI partition (default: $EFI_MOUNT)
  -k KEY_SIZE    RSA key size in bits, minimum 2048 (default: $KEY_SIZE)
  -v VALID_DAYS  Certificate validity in days (default: $VALID_DAYS)
  -o             Update-only: sign binaries and enroll existing .auth files
  -h             Show this help and exit
EOF
    exit 0
}

# Parse arguments before root/log setup so -h works unprivileged
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

# Ensure root BEFORE touching /var/log
[[ $(id -u) -eq 0 ]] || echo_err "Must be run as root"

install -d -m 0755 "$(dirname "$LOGFILE")"
if [[ ! -f "$LOGFILE" ]]; then
    install -m 0600 /dev/null "$LOGFILE"
else
    chmod 0600 "$LOGFILE"
fi

if ! [[ "$KEY_SIZE" =~ ^[0-9]+$ ]] || (( 10#$KEY_SIZE < 2048 )); then
    echo_err "Invalid KEY_SIZE '$KEY_SIZE' (must be an integer >= 2048)."
fi
if ! [[ "$VALID_DAYS" =~ ^[1-9][0-9]*$ ]]; then
    echo_err "Invalid VALID_DAYS '$VALID_DAYS' (must be a positive integer)."
fi

# Refuse to clobber sbctl-managed UKI Secure Boot setups
if [[ -f /var/lib/sbctl/GUID || -f /usr/share/secureboot/GUID || -f /etc/awesome-secureboot.conf ]]; then
    echo_err "sbctl already manages Secure Boot keys on this system. Use 'awesome-secureboot' (status / enroll-keys / refresh) or 'sbctl' instead."
fi

# Check UEFI
[[ -d /sys/firmware/efi/efivars ]] || echo_err "UEFI not detected. Secure Boot requires UEFI."

# Ensure dependencies
for cmd in openssl efibootmgr sbsign efivar efi-updatevar cert-to-efi-sig-list sign-efi-sig-list uuidgen; do
    command -v "$cmd" >/dev/null || echo_err "Missing dependency: $cmd"
done

# Prepare private key directory
umask 077
install -d -m 0700 "$KEY_DIR"
echo_log "Using key directory: $KEY_DIR"
echo_log "EFI partition mount: $EFI_MOUNT"

cd "$KEY_DIR"

if [[ "$UPDATE_ONLY" == false ]]; then
    # Generate PK, KEK, and db keys/certificates only.
    # Never generate or enroll a synthetic dbx certificate: dbx is the UEFI
    # revocation list, and overwriting it wipes vendor security revocations.
    echo_log "Generating PK, KEK, and db keys/certificates (size=$KEY_SIZE, validity=$VALID_DAYS days)"
    for name in PK KEK db; do
        openssl req -newkey "rsa:${KEY_SIZE}" -nodes \
            -keyout "${name}.key" -x509 -sha256 -days "$VALID_DAYS" \
            -subj "/CN=AwesomeArchLinux ${name} Certificate/" \
            -out "${name}.crt"
        openssl x509 -in "${name}.crt" -outform DER -out "${name}.cer"
        chmod 0600 "${name}.key"
    done

    # Backup existing EFI Secure Boot variables (efivarfs names have no .efi suffix)
    echo_log "Backing up existing EFI variables"
    efivars_dir="/sys/firmware/efi/efivars"
    shopt -s nullglob
    for var in PK KEK db dbx; do
        matches=("$efivars_dir/${var}-"*)
        for src in "${matches[@]}"; do
            [[ -f "$src" ]] || continue
            cp -- "$src" "${KEY_DIR}/backup-${src##*/}.efivar" || true
        done
    done
    shopt -u nullglob

    # Create .esl and signed .auth lists using a consistent owner GUID
    echo_log "Creating signed EFI signature lists"
    owner_guid="$(uuidgen)"
    printf '%s\n' "$owner_guid" > GUID.txt

    for var in PK KEK db; do
        cert-to-efi-sig-list -g "$owner_guid" "${var}.cer" "${var}.esl"
    done

    # PK signs PK and KEK; KEK signs db
    sign-efi-sig-list -g "$owner_guid" -k PK.key -c PK.crt PK PK.esl PK.auth
    sign-efi-sig-list -g "$owner_guid" -k PK.key -c PK.crt KEK KEK.esl KEK.auth
    sign-efi-sig-list -g "$owner_guid" -k KEK.key -c KEK.crt db db.esl db.auth
else
    echo_log "Update-only: skipping key generation"
fi

# Verify required signing key/cert and .auth files exist BEFORE modifying anything
for var in db KEK PK; do
    [[ -f "${var}.auth" ]] || echo_err "Missing ${var}.auth - cannot enroll $var"
done
[[ -f db.key && -f db.crt ]] || echo_err "Missing db.key or db.crt - cannot sign EFI binaries"

# Collect candidate bootloaders, kernels, and UKIs (deduplicated by realpath)
declare -A seen_candidates=()
declare -a candidates=()
shopt -s nullglob
for raw_candidate in \
    "${EFI_MOUNT}/EFI/Linux/"*.efi \
    "/boot/EFI/Linux/"*.efi \
    "${EFI_MOUNT}/EFI/GRUB/grubx64.efi" \
    "${EFI_MOUNT}/EFI/BOOT/BOOTX64.EFI" \
    "${EFI_MOUNT}/EFI/arch/grubx64.efi" \
    "${EFI_MOUNT}/EFI/systemd/systemd-bootx64.efi" \
    "${EFI_MOUNT}/vmlinuz-linux" \
    "/boot/vmlinuz-linux"; do
    [[ -f "$raw_candidate" ]] || continue
    resolved_candidate=$(realpath -e -- "$raw_candidate" 2>/dev/null) || continue
    [[ -z "${seen_candidates[$resolved_candidate]:-}" ]] || continue
    seen_candidates[$resolved_candidate]=1
    candidates+=("$resolved_candidate")
done
shopt -u nullglob

if (( ${#candidates[@]} == 0 )); then
    echo_err "No candidate EFI binaries found to sign in $EFI_MOUNT or /boot; aborting before enrolling keys."
fi

# Sign EFI binaries atomically via temporary file BEFORE enrolling keys.
# Signing in-place (--output X X) can truncate the binary, and enrolling keys
# before signing would leave the machine unbootable if signing fails.
for efi_candidate in "${candidates[@]}"; do
    if command -v sbverify >/dev/null 2>&1 && sbverify --cert db.crt "$efi_candidate" >/dev/null 2>&1; then
        echo_log "Already signed with db.crt: $efi_candidate"
        continue
    fi
    echo_log "Signing binary: $efi_candidate"
    orig_mode=$(stat -c '%a' "$efi_candidate")
    tmp_signed=$(mktemp "${efi_candidate}.signed.XXXXXX")
    if sbsign --key db.key --cert db.crt --output "$tmp_signed" "$efi_candidate"; then
        chmod "$orig_mode" "$tmp_signed"
        mv -f -- "$tmp_signed" "$efi_candidate"
    else
        rm -f -- "$tmp_signed"
        echo_err "Failed to sign $efi_candidate; Secure Boot keys have NOT been enrolled."
    fi
done

# Enroll keys in strict order: db -> KEK -> PK.
# Enrolling PK transitions UEFI firmware from Setup Mode to User Mode, so PK
# MUST always be enrolled last.
echo_log "Enrolling Secure Boot variables (db -> KEK -> PK)"
for var in db KEK PK; do
    efi-updatevar -e -f "${var}.auth" "$var"
    echo_ok "Enrolled $var"
done

echo_log "Verifying EFI boot entries"
efibootmgr -v || echo_log "Failed to list EFI boot entries"

echo_ok "Secure Boot setup complete. Please reboot and verify Secure Boot enforcement in firmware."
