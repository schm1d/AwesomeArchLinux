#!/usr/bin/env bash
# ================================================================
# Secure Boot Setup Script
# Description: Generates and enrolls PK/KEK/db keys, signs EFI binaries,
#              and configures UEFI Secure Boot on an Arch system.
# Author: Bruno Schmid @brulliant
# LinkedIn: https://www.linkedin.com/in/schmidbruno/
# Usage: sudo ./secureBoot.sh [-d KEY_DIR] [-p EFI_MOUNT] [-k KEY_SIZE]
#                             [-v VALID_DAYS] [-o | -s] [-m] [-G] [-y] [-h]
# ================================================================

set -euo pipefail
IFS=$'\n\t'

# Resolve our own location before any cd: it is installed as the re-sign helper.
SELF_PATH="$(realpath -e -- "${BASH_SOURCE[0]}" 2>/dev/null || true)"

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
# provision: generate keys, sign, enroll   (default)
# update:    existing keys, sign, enroll   (-o)
# sign:      existing keys, sign only      (-s, used by the pacman hook)
MODE="provision"
KEEP_FIRMWARE_CERTS=false
REBUILD_GRUB=true
ASSUME_YES=false
LOGFILE="/var/log/secureboot_setup.log"
RESIGN_HELPER="/usr/local/sbin/awesome-efi-resign"
RESIGN_HOOK="/etc/pacman.d/hooks/zz-awesome-efi-resign.hook"

# Colors
readonly C_OK="\033[1;32m" C_INFO="\033[1;34m" C_WARN="\033[1;33m" C_ERR="\033[1;31m" C_NC="\033[0m"

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

echo_warn() {
    printf '%b[!]%b %s\n' "${C_WARN}" "${C_NC}" "$1" >&2
    log_to_file "WARN: $1"
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
  -o             Update-only: keep the existing keys, sign binaries, and enroll
                 the existing lists if the firmware is in Setup Mode
  -s             Sign-only: keep the existing keys, sign binaries, never touch
                 firmware variables (this is what the pacman hook runs)
  -m             Keep the certificates currently enrolled in the firmware
                 (normally Microsoft's and the hardware vendor's) in db and KEK
                 next to your own. Without it db holds ONLY your certificate
                 and vendor-signed option ROMs are rejected.
  -G             Do not rebuild GRUB (use only if it was already installed with
                 --disable-shim-lock and the tpm module)
  -y             Assume yes for confirmations (non-interactive use)
  -h             Show this help and exit

Enrolling keys requires the firmware to be in Setup Mode (clear the Platform
Key in the firmware setup first).
EOF
    exit 0
}

# Ask for explicit confirmation of a risky step. -y answers yes; without a
# terminal the script refuses rather than guessing.
confirm() {
    local question="$1" reply=""
    if [[ "$ASSUME_YES" == true ]]; then
        return 0
    fi
    if [[ ! -t 0 ]]; then
        echo_err "$question -- refusing to continue non-interactively (re-run with -y to accept)."
    fi
    read -r -p "$question Type YES to continue: " reply || reply=""
    [[ "$reply" == "YES" ]]
}

# setup | user | unknown, from the SetupMode EFI variable (4 attribute bytes,
# then one data byte: 1 = Setup Mode).
firmware_mode() {
    local var="/sys/firmware/efi/efivars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c" value=""
    if [[ -r "$var" ]]; then
        value=$(od -An -t u1 -j 4 -N 1 "$var" 2>/dev/null | tr -d '[:space:]' || true)
    fi
    case "$value" in
        1) printf 'setup\n' ;;
        0) printf 'user\n' ;;
        *) printf 'unknown\n' ;;
    esac
}

# Parse arguments before root/log setup so -h works unprivileged
while getopts ":d:p:k:v:osmGyh" opt; do
    case "$opt" in
        d) KEY_DIR="$OPTARG" ;;
        p) EFI_MOUNT="$OPTARG" ;;
        k) KEY_SIZE="$OPTARG" ;;
        v) VALID_DAYS="$OPTARG" ;;
        o) MODE="update" ;;
        s) MODE="sign" ;;
        m) KEEP_FIRMWARE_CERTS=true ;;
        G) REBUILD_GRUB=false ;;
        y) ASSUME_YES=true ;;
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

# Check UEFI. Signing alone needs no firmware access, and the pacman hook must
# also work from a rescue chroot where efivarfs is not mounted.
if [[ "$MODE" != "sign" ]]; then
    [[ -d /sys/firmware/efi/efivars ]] || echo_err "UEFI not detected. Secure Boot requires UEFI."
fi

# Ensure dependencies
required_cmds=(sbsign)
if [[ "$MODE" != "sign" ]]; then
    required_cmds+=(efibootmgr efivar efi-updatevar)
fi
if [[ "$MODE" == "provision" ]]; then
    required_cmds+=(openssl cert-to-efi-sig-list sign-efi-sig-list uuidgen)
    if [[ "$KEEP_FIRMWARE_CERTS" == true ]]; then
        required_cmds+=(efi-readvar)
    fi
fi
for cmd in "${required_cmds[@]}"; do
    command -v "$cmd" >/dev/null || echo_err "Missing dependency: $cmd"
done

# Keys can only be enrolled without an existing Platform Key. Check before
# anything is generated, rebuilt or signed.
FIRMWARE_MODE=$(firmware_mode)
ENROLL=false
case "$MODE" in
    provision)
        if [[ "$FIRMWARE_MODE" == "user" ]]; then
            echo_err "The firmware is not in Setup Mode (a Platform Key is enrolled). Clear the PK in the firmware setup, boot again and re-run. Nothing was changed."
        fi
        [[ "$FIRMWARE_MODE" == "setup" ]] || echo_warn "Could not read the SetupMode variable; enrollment will fail if the firmware is not in Setup Mode."
        ENROLL=true
        ;;
    update)
        if [[ "$FIRMWARE_MODE" == "user" ]]; then
            echo_log "Firmware is in User Mode: the enrolled keys stay as they are, binaries are re-signed only."
        else
            ENROLL=true
        fi
        ;;
esac

# What the GRUB rebuild further down needs (see prepare_grub_for_secure_boot),
# checked here so a missing prerequisite stops the run before keys are
# generated or anything else is touched.
check_grub_prerequisites() {
    local grub_help
    [[ -f "${EFI_MOUNT}/EFI/GRUB/grubx64.efi" && "$REBUILD_GRUB" == true ]] || return 0
    command -v grub-install >/dev/null || echo_err "GRUB is on the ESP but grub-install is missing; cannot prepare it for Secure Boot (use -G if it is already prepared). Nothing was changed."
    grub_help=$(grub-install --help 2>&1 || true)
    [[ "$grub_help" == *"--disable-shim-lock"* ]] || echo_err "This grub-install has no --disable-shim-lock option; GRUB cannot be used without shim under Secure Boot. Nothing was changed."
    if [[ ! -c /dev/tpmrm0 && ! -c /dev/tpm0 ]]; then
        echo_err "No TPM found. Without shim, GRUB needs its tpm module as the verifier for what it loads under Secure Boot. Use the installer's 'uki' boot profile on machines without a TPM, or -G if your GRUB is prepared differently. Nothing was changed."
    fi
}

if [[ "$MODE" == "provision" ]]; then
    check_grub_prerequisites
fi

# Prepare private key directory
umask 077
install -d -m 0700 "$KEY_DIR"
KEY_DIR="$(realpath -e -- "$KEY_DIR")"
echo_log "Using key directory: $KEY_DIR"
echo_log "EFI partition mount: $EFI_MOUNT"

cd "$KEY_DIR"

# Never overwrite an existing key set: move it aside. Binaries signed with the
# old db key can only be verified against the old certificate.
backup_existing_keys() {
    local backup_dir old_file
    local -a old_files=()
    shopt -s nullglob
    for old_file in PK.* KEK.* db.* GUID.txt db-enroll.esl KEK-enroll.esl firmware-db.esl firmware-KEK.esl; do
        # Literal names survive nullglob even when the file is absent.
        [[ -e "$old_file" ]] && old_files+=("$old_file")
    done
    shopt -u nullglob
    (( ${#old_files[@]} > 0 )) || return 0
    # mktemp keeps two runs within the same second from sharing a directory.
    backup_dir=$(mktemp -d "previous-keys-$(date +%Y%m%d-%H%M%S).XXXXXX")
    chmod 0700 "$backup_dir"
    mv -- "${old_files[@]}" "$backup_dir/"
    echo_warn "Existing key material was moved to $KEY_DIR/$backup_dir instead of being overwritten."
}

# Save what the firmware currently trusts and return 0 if <var> has entries.
read_firmware_list() {
    local var="$1" out="firmware-${1}.esl"
    rm -f -- "$out"
    efi-readvar -v "$var" -o "$out" >/dev/null 2>&1 || true
    [[ -s "$out" ]]
}

FIRMWARE_DB_KEPT=false
if [[ "$MODE" == "provision" ]]; then
    backup_existing_keys

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

    # cert-to-efi-sig-list reads the PEM certificate (.crt), not the DER copy.
    for var in PK KEK db; do
        cert-to-efi-sig-list -g "$owner_guid" "${var}.crt" "${var}.esl"
    done

    # The lists that are actually enrolled. With -m they start with what the
    # firmware trusts today, so vendor/Microsoft-signed option ROMs and
    # firmware updates keep working.
    cp -- db.esl db-enroll.esl
    cp -- KEK.esl KEK-enroll.esl
    if [[ "$KEEP_FIRMWARE_CERTS" == true ]]; then
        if read_firmware_list db; then
            cat firmware-db.esl db.esl > db-enroll.esl
            FIRMWARE_DB_KEPT=true
            echo_log "Keeping the certificates currently in the firmware db"
        else
            echo_warn "The firmware db is empty (keys were cleared), so there is nothing to keep with -m."
        fi
        if read_firmware_list KEK; then
            cat firmware-KEK.esl KEK.esl > KEK-enroll.esl
            echo_log "Keeping the certificates currently in the firmware KEK"
        fi
    fi

    # PK signs PK and KEK; KEK signs db
    sign-efi-sig-list -g "$owner_guid" -k PK.key -c PK.crt PK PK.esl PK.auth
    sign-efi-sig-list -g "$owner_guid" -k PK.key -c PK.crt KEK KEK-enroll.esl KEK.auth
    sign-efi-sig-list -g "$owner_guid" -k KEK.key -c KEK.crt db db-enroll.esl db.auth
else
    echo_log "Using the existing keys in $KEY_DIR (no key generation)"
    # Key sets created by earlier versions have no *-enroll.esl files.
    [[ -f db-enroll.esl || ! -f db.esl ]] || cp -- db.esl db-enroll.esl
    [[ -f KEK-enroll.esl || ! -f KEK.esl ]] || cp -- KEK.esl KEK-enroll.esl
fi

# Verify required signing key/cert and enrollment files exist BEFORE modifying anything
[[ -f db.key && -f db.crt ]] || echo_err "Missing db.key or db.crt - cannot sign EFI binaries"
if [[ "$ENROLL" == true ]]; then
    for required in db-enroll.esl KEK-enroll.esl PK.auth; do
        [[ -s "$required" ]] || echo_err "Missing $required - cannot enroll keys"
    done
fi

# Replacing db with only our own certificate is the step that can cost the
# display: say so and get an explicit go-ahead before anything on the ESP or
# in the firmware is touched.
if [[ "$ENROLL" == true && "$FIRMWARE_DB_KEPT" != true && ! -s firmware-db.esl ]]; then
    echo_warn "db will contain ONLY your own certificate."
    echo_warn "Firmware components signed by Microsoft or the hardware vendor (graphics, network and storage option ROMs, some firmware updates) will then be refused. On machines whose graphics card needs its option ROM this can leave you without any display output, including in the firmware setup."
    echo_warn "Re-run with -m while the vendor certificates are still in the firmware to keep them."
    confirm "Enroll only your own certificate?" || echo_err "Aborted before any change to the ESP or the firmware."
fi

# GRUB built by a plain grub-install registers its shim_lock verifier as soon
# as Secure Boot is on and then refuses to load anything, because this setup
# has no shim. It has to be rebuilt with --disable-shim-lock. In lockdown GRUB
# also wants a verifier for the modules and kernel it reads; the embedded tpm
# module provides one, which is why a TPM is required.
prepare_grub_for_secure_boot() {
    local grub_efi="${EFI_MOUNT}/EFI/GRUB/grubx64.efi"
    local fallback_efi="${EFI_MOUNT}/EFI/BOOT/BOOTX64.EFI"

    [[ -f "$grub_efi" ]] || return 0
    if [[ "$REBUILD_GRUB" != true ]]; then
        echo_warn "Not rebuilding GRUB (-G). It only boots under Secure Boot if it was installed with --disable-shim-lock and --modules=tpm."
        return 0
    fi

    echo_log "Rebuilding GRUB without the shim_lock verifier (tpm module embedded)"
    grub-install --target=x86_64-efi --bootloader-id=GRUB --efi-directory="$EFI_MOUNT" \
        --modules="tpm" --disable-shim-lock --recheck
    # Only refresh the removable-media fallback if it is GRUB's own copy.
    if [[ -f "$fallback_efi" ]] && ! grep -aq 'systemd-boot' "$fallback_efi" && grep -aqi 'grub' "$fallback_efi"; then
        grub-install --target=x86_64-efi --efi-directory="$EFI_MOUNT" --removable \
            --modules="tpm" --disable-shim-lock --recheck ||
            echo_warn "Could not rebuild the fallback loader $fallback_efi; it will be signed as it is."
    fi
}

if [[ "$MODE" == "provision" ]]; then
    prepare_grub_for_secure_boot
fi

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
    "${EFI_MOUNT}/vmlinuz-"* \
    "/boot/vmlinuz-"*; do
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

# Kernel packages replace /boot/vmlinuz-* with an unsigned image on every
# update. Install this script as a sign-only helper plus a pacman hook that
# runs it after the kernel has been copied to /boot (hooks run in file-name
# order; "zz-" sorts after mkinitcpio's 90- hook).
install_resign_hook() {
    if [[ -z "$SELF_PATH" || ! -f "$SELF_PATH" ]]; then
        echo_warn "Could not locate this script on disk; the pacman re-sign hook was not installed."
        return 0
    fi
    if [[ "$SELF_PATH" != "$RESIGN_HELPER" ]]; then
        install -D -o root -g root -m 0755 "$SELF_PATH" "$RESIGN_HELPER"
    fi
    install -D -o root -g root -m 0644 /dev/stdin "$RESIGN_HOOK" <<EOF
[Trigger]
Operation = Install
Operation = Upgrade
Type = Path
Target = usr/lib/modules/*/vmlinuz

[Action]
Description = Re-signing kernels and boot loaders for Secure Boot...
When = PostTransaction
Exec = $RESIGN_HELPER -s -d "$KEY_DIR" -p "$EFI_MOUNT"
EOF
    echo_ok "Installed $RESIGN_HELPER and $RESIGN_HOOK (kernels are re-signed after each update)"
}

if [[ "$ENROLL" != true ]]; then
    if [[ "$MODE" == "update" ]]; then
        install_resign_hook
    fi
    echo_ok "EFI binaries are signed. Firmware variables were not modified."
    exit 0
fi

# Enroll keys in strict order: db -> KEK -> PK.
# Enrolling PK transitions UEFI firmware from Setup Mode to User Mode, so PK
# MUST always be enrolled last.
#
# In Setup Mode db and KEK are written as plain EFI signature lists, which is
# what efi-updatevar's -e means ("use EFI Signature List instead of signed
# update"); passing a signed .auth file together with -e, as this script used
# to, hands the tool the wrong format. PK is written as its self-signed .auth.
echo_log "Enrolling Secure Boot variables (db -> KEK -> PK)"
shopt -s nullglob
for efivar_file in /sys/firmware/efi/efivars/PK-* /sys/firmware/efi/efivars/KEK-* /sys/firmware/efi/efivars/db-*; do
    # efivarfs marks existing variables immutable; a write then fails with EPERM.
    chattr -i "$efivar_file" 2>/dev/null || true
done
shopt -u nullglob

efi-updatevar -e -f db-enroll.esl db
echo_ok "Enrolled db"
efi-updatevar -e -f KEK-enroll.esl KEK
echo_ok "Enrolled KEK"
efi-updatevar -f PK.auth PK
echo_ok "Enrolled PK"

install_resign_hook

echo_log "Verifying EFI boot entries"
efibootmgr -v || echo_log "Failed to list EFI boot entries"

if [[ "$(firmware_mode)" == "setup" ]]; then
    echo_warn "The firmware still reports Setup Mode; check the Platform Key in the firmware setup."
fi
if [[ -f "${EFI_MOUNT}/EFI/GRUB/grubx64.efi" ]]; then
    echo_log "After any later grub-install, pass --modules=tpm --disable-shim-lock again and run: $RESIGN_HELPER -s -d \"$KEY_DIR\" -p \"$EFI_MOUNT\""
fi
echo_ok "Secure Boot setup complete. Please reboot and verify Secure Boot enforcement in firmware."
