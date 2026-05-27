#!/usr/bin/env bash
# base/systemd-boot.sh
#
# Installs systemd-boot, wires the initramfs for TPM 2.0 LUKS unlock, and
# enrolls the TPM keyslot. Called from chroot.sh when the user picked the
# "server" boot profile in archinstall.sh.
#
# End-state when this script returns 0:
#   - systemd-boot installed at /efi/EFI/systemd/systemd-bootx64.efi
#   - Linux Boot Manager UEFI entry created (efibootmgr) and set first
#   - Kernel + initramfs + microcode copied to /efi/EFI/Linux/
#   - /efi/loader/loader.conf set with default=arch.conf, timeout=3
#   - /efi/loader/entries/arch.conf with rd.luks.name + tpm2-device=auto
#   - /etc/crypttab.initramfs contains a single line wiring TPM unlock
#   - LUKS volume has a new keyslot sealed to the TPM (systemd-tpm2 token)
#
# Safety properties:
#   - Refuses to start if TPM 2.0 isn't enumerable, /efi is missing, or the
#     LUKS UUID isn't present on the target disk.
#   - Hard-fails if systemd-cryptenroll claims success but no systemd-tpm2
#     token is found in the LUKS header afterwards (silent enrollment was
#     the failure mode we hit on real hardware once already).
#   - The pre-existing /etc/luksKeys/boot.key keyfile slot is left alone.
#     It's the documented manual fallback if TPM unsealing ever fails and
#     the recovery passphrase has also been lost. The post-install cleanup
#     step (run-once after a confirmed silent boot) removes it.
#
# Inputs (env vars set by chroot.sh):
#   LUKS_UUID       — UUID of the LUKS partition (e.g. /dev/nvme0n1p3)
#   LVM_NAME        — LUKS-opened mapper name (e.g. lvm_arch / crypt_lvm)
#   LUKS_KEYS       — directory containing boot.key (e.g. /etc/luksKeys)
#   INSTALL_TPM_PCRS — PCR string (e.g. "0+7"); defaults to 0+7
#   EFI_MOUNT       — EFI System Partition mount point (defaults /efi)
#   KERNEL_NAME     — kernel base name (defaults "linux")
#   KERNEL_HARDEN   — kernel cmdline hardening flags string

set -euo pipefail

# Color helpers — kept compatible with the parent scripts' palette so log
# output reads consistently across archinstall.sh / chroot.sh / here.
if [[ -t 1 ]]; then
    BRed='\033[1;31m'; BGreen='\033[1;32m'; BYellow='\033[1;33m'
    BBlue='\033[1;34m'; NC='\033[0m'
else
    BRed=''; BGreen=''; BYellow=''; BBlue=''; NC=''
fi

# Resolve config — sensible defaults so the script can also be exercised
# stand-alone post-install for debugging.
LUKS_UUID="${LUKS_UUID:?LUKS_UUID must be set (UUID of the LUKS partition)}"
LVM_NAME="${LVM_NAME:?LVM_NAME must be set (LUKS mapper / VG name)}"
LUKS_KEYS="${LUKS_KEYS:-/etc/luksKeys}"
TPM_PCRS="${INSTALL_TPM_PCRS:-${TPM_PCRS:-0+7}}"
EFI_MOUNT="${EFI_MOUNT:-/efi}"
KERNEL_NAME="${KERNEL_NAME:-linux}"
KERNEL_HARDEN="${KERNEL_HARDEN:-slab_nomerge init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 pti=on randomize_kstack_offset=on vsyscall=none quiet loglevel=3}"

BOOT_KEY="$LUKS_KEYS/boot.key"

banner() {
    echo -e "\n${BBlue}========== $* ==========${NC}"
}

# -------------------------------------------------------------------------
# Pre-flight — refuse to start if any assumption is wrong. Bricking a fresh
# install at this point would mean re-running archinstall.sh, so guard
# everything aggressively before any state change.
# -------------------------------------------------------------------------
banner "pre-flight"

# TPM 2.0 must be present and version 2 (not 1.2).
if [[ ! -e /sys/class/tpm/tpm0 ]]; then
    echo -e "${BRed}FATAL: no TPM device under /sys/class/tpm/${NC}" >&2
    exit 21
fi
TPM_MAJOR=$(cat /sys/class/tpm/tpm0/tpm_version_major 2>/dev/null || echo "")
if [[ "$TPM_MAJOR" != "2" ]]; then
    echo -e "${BRed}FATAL: TPM is not 2.0 (tpm_version_major=$TPM_MAJOR)${NC}" >&2
    exit 22
fi
echo "  TPM 2.0 present"

# systemd-cryptenroll must be available (systemd ≥ 252 ships it).
if ! command -v systemd-cryptenroll >/dev/null 2>&1; then
    echo -e "${BRed}FATAL: systemd-cryptenroll not found in PATH${NC}" >&2
    exit 23
fi

# /efi must be mounted with at least 500 MB free. Kernel (~17 MB) +
# initramfs (~110 MB) + microcode (~10 MB) + headroom for future kernels.
if ! mountpoint -q "$EFI_MOUNT"; then
    echo -e "${BRed}FATAL: $EFI_MOUNT is not a mountpoint${NC}" >&2
    exit 24
fi
AVAIL_KB=$(df --output=avail -k "$EFI_MOUNT" | tail -1)
if (( AVAIL_KB < 512000 )); then
    echo -e "${BRed}FATAL: less than 500 MB free on $EFI_MOUNT ($((AVAIL_KB/1024)) MB)${NC}" >&2
    exit 25
fi
echo "  $EFI_MOUNT mounted, $((AVAIL_KB/1024)) MB free"

# Boot key must exist (archinstall.sh seeded it pre-chroot). It seeds the
# TPM enrollment as the existing unlock key.
if [[ ! -f "$BOOT_KEY" ]]; then
    echo -e "${BRed}FATAL: $BOOT_KEY missing — archinstall.sh should have created it${NC}" >&2
    exit 26
fi

# LUKS UUID resolvable to a real partition?
if ! blkid -U "$LUKS_UUID" >/dev/null 2>&1; then
    echo -e "${BRed}FATAL: no block device with LUKS UUID $LUKS_UUID${NC}" >&2
    exit 27
fi
LUKS_DEV=$(blkid -U "$LUKS_UUID")
echo "  LUKS device: $LUKS_DEV"

# -------------------------------------------------------------------------
# bootctl install — writes systemd-boot binaries to /efi and registers the
# UEFI variable. Without --no-variables (which we used during the live
# migration), the firmware boot entry gets created in one shot.
# -------------------------------------------------------------------------
banner "bootctl install"
bootctl install
echo

# -------------------------------------------------------------------------
# Copy kernel + initramfs + microcode to /efi/EFI/Linux/
# systemd-boot reads them from there at boot time. /boot lives inside the
# encrypted LVM, but /efi is unencrypted FAT32 — that's the whole reason
# systemd-boot can chain-load without prompting.
# -------------------------------------------------------------------------
banner "stage kernel + initramfs + microcode to $EFI_MOUNT/EFI/Linux/"
mkdir -p "$EFI_MOUNT/EFI/Linux"

for f in "/boot/vmlinuz-$KERNEL_NAME" "/boot/initramfs-$KERNEL_NAME.img"; do
    if [[ ! -s "$f" ]]; then
        echo -e "${BRed}FATAL: missing or empty kernel artifact: $f${NC}" >&2
        exit 30
    fi
    cp -v "$f" "$EFI_MOUNT/EFI/Linux/"
done

# Microcode is optional — depends on which ucode package matches the CPU.
# Copy whichever is present; absence is not an error.
for ucode in /boot/intel-ucode.img /boot/amd-ucode.img; do
    [[ -f "$ucode" ]] && cp -v "$ucode" "$EFI_MOUNT/EFI/Linux/"
done

# -------------------------------------------------------------------------
# loader.conf — defaults shown to the user during boot
# -------------------------------------------------------------------------
banner "write $EFI_MOUNT/loader/loader.conf"
cat > "$EFI_MOUNT/loader/loader.conf" <<EOF
default arch.conf
timeout 3
console-mode max
editor no
EOF
cat "$EFI_MOUNT/loader/loader.conf"

# -------------------------------------------------------------------------
# arch.conf — the actual boot entry
# - rd.luks.name pins the LUKS UUID to a mapper name
# - rd.luks.options=tpm2-device=auto tells sd-encrypt to use the TPM token
# - root= mounts the LV that's inside the unlocked LUKS
# - KERNEL_HARDEN are the same flags the desktop GRUB path already sets
# -------------------------------------------------------------------------
banner "write $EFI_MOUNT/loader/entries/arch.conf"
{
    echo "title   Arch Linux"
    echo "linux   /EFI/Linux/vmlinuz-$KERNEL_NAME"
    for ucode in intel-ucode.img amd-ucode.img; do
        [[ -f "$EFI_MOUNT/EFI/Linux/$ucode" ]] && echo "initrd  /EFI/Linux/$ucode"
    done
    echo "initrd  /EFI/Linux/initramfs-$KERNEL_NAME.img"
    echo "options rd.luks.name=$LUKS_UUID=$LVM_NAME rd.luks.options=tpm2-device=auto root=/dev/mapper/${LVM_NAME}-root rw $KERNEL_HARDEN"
} > "$EFI_MOUNT/loader/entries/arch.conf"
cat "$EFI_MOUNT/loader/entries/arch.conf"

# -------------------------------------------------------------------------
# /etc/crypttab.initramfs
# sd-encrypt reads it at boot. The "-" means no password file; tpm2-device=auto
# tells systemd-cryptsetup to ask the TPM to release the sealed key.
# -------------------------------------------------------------------------
banner "write /etc/crypttab.initramfs"
echo "$LVM_NAME UUID=$LUKS_UUID - tpm2-device=auto" > /etc/crypttab.initramfs
cat /etc/crypttab.initramfs

# -------------------------------------------------------------------------
# Regenerate initramfs with the new crypttab embedded, then re-stage to /efi
# -------------------------------------------------------------------------
banner "regenerate initramfs"
mkinitcpio -P
cp -v "/boot/initramfs-$KERNEL_NAME.img" "$EFI_MOUNT/EFI/Linux/"

# -------------------------------------------------------------------------
# Enroll the TPM keyslot
# - --tpm2-pcrs binds the unlock policy to PCRs 0+7 by default (UEFI
#   firmware + Secure Boot state). Survives kernel updates.
# - --unlock-key-file uses the boot.key seeded pre-chroot to authorize the
#   slot creation — no interactive passphrase prompt here.
# -------------------------------------------------------------------------
banner "enroll TPM 2.0 keyslot (PCRs: $TPM_PCRS)"
systemd-cryptenroll \
    --tpm2-device=auto \
    --tpm2-pcrs="$TPM_PCRS" \
    --unlock-key-file="$BOOT_KEY" \
    "$LUKS_DEV"

# Verify the token landed — silent enrollment failure is the precise bug
# that bit us during live migration. Hard-abort if no systemd-tpm2 token
# shows up in the LUKS header.
if ! cryptsetup luksDump "$LUKS_DEV" | grep -q "systemd-tpm2"; then
    echo -e "${BRed}FATAL: enrollment returned 0 but no systemd-tpm2 token in LUKS header${NC}" >&2
    echo "Inspect with: cryptsetup luksDump $LUKS_DEV" >&2
    exit 32
fi
echo -e "${BGreen}[verify] systemd-tpm2 token present${NC}"

# -------------------------------------------------------------------------
# Final sanity: all the boot-critical artifacts must exist with non-zero
# size. /efi entries dated from this run.
# -------------------------------------------------------------------------
banner "final verification"
for f in \
    "$EFI_MOUNT/EFI/systemd/systemd-bootx64.efi" \
    "$EFI_MOUNT/EFI/Linux/vmlinuz-$KERNEL_NAME" \
    "$EFI_MOUNT/EFI/Linux/initramfs-$KERNEL_NAME.img" \
    "$EFI_MOUNT/loader/loader.conf" \
    "$EFI_MOUNT/loader/entries/arch.conf" \
    "/etc/crypttab.initramfs"
do
    if [[ ! -s "$f" ]]; then
        echo -e "${BRed}FATAL: expected artifact missing or empty: $f${NC}" >&2
        exit 33
    fi
    echo "  [ok] $f ($(stat -c%s "$f") bytes)"
done

cat <<EOF

${BGreen}systemd-boot + TPM 2.0 server profile install complete.${NC}

  Boot loader: systemd-boot
  LUKS unlock: TPM 2.0 (PCRs $TPM_PCRS) — silent at boot when PCRs match
  Fallback:    interactive passphrase prompt (uses your install passphrase
               OR the recovery key in $LUKS_KEYS/boot.key)

On first boot, the firmware will pick "Linux Boot Manager", systemd-boot
will load /EFI/Linux/vmlinuz-$KERNEL_NAME, sd-encrypt will read the
embedded /etc/crypttab.initramfs, the kernel will ask the TPM to unseal
the keyslot, and LUKS will open with zero prompts.

If a firmware update changes PCRs 0 or 7, the TPM seal becomes invalid
and the boot falls through to the recovery passphrase prompt. To re-arm
TPM unlock after such an event, run as root inside the booted system:

    systemd-cryptenroll --wipe-slot=tpm2 $LUKS_DEV
    systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=$TPM_PCRS \\
        --unlock-key-file=$BOOT_KEY $LUKS_DEV

EOF
