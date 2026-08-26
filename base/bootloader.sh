#!/usr/bin/env bash

# Bootloader and initramfs configuration shared by the bare-metal installer.
# This file is sourced by chroot.sh; it is not intended to be run directly.

bl_array_contains() {
    local needle="$1"
    shift
    local item

    for item in "$@"; do
        if [[ "$item" == "$needle" ]]; then
            return 0
        fi
    done
    return 1
}

bl_array_remove() {
    local array_name="$1"
    local value="$2"
    local -n remove_ref="$array_name"
    local -a kept=()
    local item

    for item in "${remove_ref[@]}"; do
        if [[ "$item" != "$value" ]]; then
            kept+=("$item")
        fi
    done
    remove_ref=("${kept[@]}")
}

bl_array_append_unique() {
    local array_name="$1"
    shift
    local -n append_ref="$array_name"
    local item

    for item in "$@"; do
        if ! bl_array_contains "$item" "${append_ref[@]}"; then
            append_ref+=("$item")
        fi
    done
}

bl_array_place_after() {
    local array_name="$1"
    local anchor="$2"
    local value="$3"
    local -n after_ref="$array_name"
    local -a updated=()
    local inserted=false
    local item

    bl_array_remove "$array_name" "$value"
    for item in "${after_ref[@]}"; do
        updated+=("$item")
        if [[ "$item" == "$anchor" && "$inserted" == false ]]; then
            updated+=("$value")
            inserted=true
        fi
    done
    if [[ "$inserted" == false ]]; then
        updated+=("$value")
    fi
    after_ref=("${updated[@]}")
}

bl_array_deduplicate() {
    local array_name="$1"
    local -n dedupe_ref="$array_name"
    local -a unique=()
    local item

    for item in "${dedupe_ref[@]}"; do
        if ! bl_array_contains "$item" "${unique[@]}"; then
            unique+=("$item")
        fi
    done
    dedupe_ref=("${unique[@]}")
}

bl_write_array_assignment() {
    local config_file="$1"
    local array_name="$2"
    local -n write_ref="$array_name"
    local rendered quoted item

    rendered="${array_name}=("
    for item in "${write_ref[@]}"; do
        printf -v quoted '%q' "$item"
        rendered+="${quoted} "
    done
    rendered="${rendered% }"
    rendered+=")"

    if grep -qE "^[[:space:]]*${array_name}=" "$config_file"; then
        sed -i -E "s|^[[:space:]]*${array_name}=.*$|${rendered}|" "$config_file"
    else
        printf '\n%s\n' "$rendered" >> "$config_file"
    fi
}

# Merge the required encryption hooks/modules into the existing mkinitcpio
# arrays. Unrelated entries survive, and later callers (notably NVIDIA setup)
# append their requirements instead of replacing TPM modules.
# shellcheck disable=SC2120  # Optional arguments are supplied by chroot.sh.
bl_set_hooks() {
    local config_file="${MKINITCPIO_CONFIG:-/etc/mkinitcpio.conf}"
    local -a extra_hooks=()
    local -a extra_modules=()
    local -a HOOKS=()
    # shellcheck disable=SC2034  # Read/written through nameref helpers.
    local -a MODULES=()
    # shellcheck disable=SC2034  # Read/written through nameref helpers.
    local -a FILES=()
    local hook

    while (( $# > 0 )); do
        case "$1" in
            --hook)
                [[ $# -ge 2 ]] || { echo "bl_set_hooks: --hook requires a value" >&2; return 2; }
                extra_hooks+=("$2")
                shift 2
                ;;
            --module)
                [[ $# -ge 2 ]] || { echo "bl_set_hooks: --module requires a value" >&2; return 2; }
                extra_modules+=("$2")
                shift 2
                ;;
            *)
                echo "bl_set_hooks: unknown argument: $1" >&2
                return 2
                ;;
        esac
    done

    # mkinitcpio.conf is a trusted shell configuration owned by root.
    # shellcheck source=/etc/mkinitcpio.conf
    source "$config_file"

    for hook in "${extra_hooks[@]}"; do
        bl_array_append_unique HOOKS "$hook"
    done

    if [[ "$INSTALL_BOOTLOADER" == "uki" || "$INSTALL_TPM" == "true" ]]; then
        for hook in "${!HOOKS[@]}"; do
            case "${HOOKS[$hook]}" in
                udev) HOOKS[$hook]="systemd" ;;
                keymap|consolefont) HOOKS[$hook]="sd-vconsole" ;;
                encrypt) HOOKS[$hook]="sd-encrypt" ;;
            esac
        done
        bl_array_deduplicate HOOKS
        bl_array_append_unique HOOKS base filesystems fsck
        bl_array_place_after HOOKS base systemd
        if bl_array_contains microcode "${HOOKS[@]}"; then
            bl_array_place_after HOOKS autodetect microcode
            bl_array_place_after HOOKS microcode modconf
        else
            bl_array_place_after HOOKS autodetect modconf
        fi
        if bl_array_contains kms "${HOOKS[@]}"; then
            bl_array_place_after HOOKS modconf kms
            bl_array_place_after HOOKS kms keyboard
        else
            bl_array_place_after HOOKS modconf keyboard
        fi
        bl_array_place_after HOOKS keyboard sd-vconsole
        bl_array_place_after HOOKS sd-vconsole block
        bl_array_place_after HOOKS block sd-encrypt
        bl_array_place_after HOOKS sd-encrypt lvm2
        bl_array_place_after HOOKS lvm2 filesystems
        bl_array_place_after HOOKS filesystems fsck
        bl_array_append_unique MODULES tpm tpm_tis tpm_crb
    else
        for hook in "${!HOOKS[@]}"; do
            case "${HOOKS[$hook]}" in
                systemd) HOOKS[$hook]="udev" ;;
                sd-vconsole) HOOKS[$hook]="keymap" ;;
                sd-encrypt) HOOKS[$hook]="encrypt" ;;
            esac
        done
        bl_array_deduplicate HOOKS
        bl_array_append_unique HOOKS base filesystems fsck
        bl_array_place_after HOOKS base udev
        if bl_array_contains microcode "${HOOKS[@]}"; then
            bl_array_place_after HOOKS autodetect microcode
            bl_array_place_after HOOKS microcode modconf
        else
            bl_array_place_after HOOKS autodetect modconf
        fi
        if bl_array_contains kms "${HOOKS[@]}"; then
            bl_array_place_after HOOKS modconf kms
            bl_array_place_after HOOKS kms keyboard
        else
            bl_array_place_after HOOKS modconf keyboard
        fi
        bl_array_place_after HOOKS keyboard keymap
        if bl_array_contains consolefont "${HOOKS[@]}"; then
            bl_array_place_after HOOKS keymap consolefont
            bl_array_place_after HOOKS consolefont block
        else
            bl_array_place_after HOOKS keymap block
        fi
        bl_array_place_after HOOKS block encrypt
        bl_array_place_after HOOKS encrypt lvm2
        bl_array_place_after HOOKS lvm2 filesystems
        bl_array_place_after HOOKS filesystems fsck
    fi

    bl_array_append_unique MODULES "${extra_modules[@]}"

    if [[ "$INSTALL_BOOTLOADER" == "uki" ]]; then
        # shellcheck disable=SC2034  # Written through bl_write_array_assignment.
        FILES=()
    else
        bl_array_append_unique FILES "$LUKS_KEYS"
    fi

    bl_write_array_assignment "$config_file" MODULES
    bl_write_array_assignment "$config_file" FILES
    bl_write_array_assignment "$config_file" HOOKS
}

bl_kernel_cmdline() {
    local section="${1:-all}"
    local -a hardening=(
        slab_nomerge
        init_on_alloc=1
        init_on_free=1
        page_alloc.shuffle=1
        pti=on
        randomize_kstack_offset=on
        vsyscall=none
        quiet
        loglevel=3
    )
    local -a luks=()
    local -a result=()

    if [[ "$INSTALL_BOOTLOADER" == "grub" && "$INSTALL_TPM" != "true" ]]; then
        luks+=(
            "cryptdevice=UUID=${LUKS_UUID}:${CRYPT_NAME}"
            "root=/dev/mapper/${LVM_NAME}-root"
            "cryptkey=rootfs:${LUKS_KEYS}"
        )
    else
        luks+=(
            "rd.luks.name=${LUKS_UUID}=${CRYPT_NAME}"
            "rd.lvm.lv=${LVM_NAME}/root"
            "root=/dev/mapper/${LVM_NAME}-root"
        )
        if [[ "$INSTALL_TPM" == "true" ]]; then
            luks+=("rd.luks.options=${LUKS_UUID}=tpm2-device=auto")
        fi
    fi

    case "$section" in
        hardening) result=("${hardening[@]}" "${BOOT_EXTRA_CMDLINE[@]}") ;;
        luks) result=("${luks[@]}") ;;
        all) result=("${hardening[@]}" "${luks[@]}" "${BOOT_EXTRA_CMDLINE[@]}") ;;
        *)
            echo "bl_kernel_cmdline: expected hardening, luks, or all" >&2
            return 2
            ;;
    esac

    printf '%s\n' "${result[*]}"
}

bl_set_shell_value() {
    local config_file="$1"
    local key="$2"
    local value="$3"
    local rendered="${key}=\"${value}\""

    if grep -qE "^#?${key}=" "$config_file"; then
        sed -i -E "s|^#?${key}=.*$|${rendered}|" "$config_file"
    else
        printf '%s\n' "$rendered" >> "$config_file"
    fi
}

configure_grub() {
    local grub_security grub_luks

    # shellcheck disable=SC2154  # Color variables are defined by chroot.sh.
    echo -e "${BBlue}Configuring encrypted GRUB boot...${NC}"
    bl_set_hooks
    mkinitcpio -P

    grub_security=$(bl_kernel_cmdline hardening)
    grub_luks=$(bl_kernel_cmdline luks)
    bl_set_shell_value /etc/default/grub GRUB_PRELOAD_MODULES "part_gpt part_msdos lvm"
    bl_set_shell_value /etc/default/grub GRUB_ENABLE_CRYPTODISK "y"
    bl_set_shell_value /etc/default/grub GRUB_CMDLINE_LINUX_DEFAULT "$grub_security"
    bl_set_shell_value /etc/default/grub GRUB_CMDLINE_LINUX "$grub_luks"
    bl_set_shell_value /etc/default/grub GRUB_GFXMODE "1024x768,auto"
    bl_set_shell_value /etc/default/grub GRUB_GFXPAYLOAD_LINUX "keep"

    mkdir -p /boot/grub
    grub-install --target=x86_64-efi --bootloader-id=GRUB --efi-directory=/efi --recheck

    # Removable-media fallback loader at /efi/EFI/BOOT/BOOTX64.EFI.
    # Without it, losing the "GRUB" UEFI NVRAM entry leaves the firmware with
    # nothing to boot even though the ESP and grubx64.efi are intact -- the
    # drive simply reports as unbootable. --removable implies no NVRAM write,
    # so it cannot disturb the entry the first pass just created, and it works
    # inside a chroot. Non-fatal: an otherwise-good install should not abort
    # over a redundancy, but the operator must hear about it.
    # shellcheck disable=SC2154  # Color variables are defined by chroot.sh.
    grub-install --target=x86_64-efi --efi-directory=/efi --removable --recheck \
        || echo -e "${BYellow}Warning: fallback loader install failed; the UEFI NVRAM entry is the only boot path.${NC}"

    # Preserve the existing interactive password flow: the operator must
    # successfully create a GRUB PBKDF2 password before installation proceeds.
    set +e
    while true; do
        local grub_tmpfile grub_pass
        echo -e "${BBlue}Setting GRUB password...${NC}"
        grub_tmpfile=$(mktemp /tmp/grubpass.XXXXXX)
        chmod 600 "$grub_tmpfile"
        grub-mkpasswd-pbkdf2 | tee "$grub_tmpfile"
        grub_pass=$(awk '/grub.pbkdf2/ { print $NF; exit }' "$grub_tmpfile")
        rm -f "$grub_tmpfile"
        if [[ -n "$grub_pass" ]]; then
            cat <<EOF >> /etc/grub.d/40_custom
set superusers="admin"
password_pbkdf2 admin $grub_pass
EOF
            break
        fi
        echo -e "${BBlue}GRUB password generation failed. Please try again.${NC}"
        sleep 1
    done
    set -e

    grub-mkconfig -o /boot/grub/grub.cfg
}

bl_configure_uki_preset() {
    install -d -m 0755 /efi/EFI/Linux
    cat > /etc/mkinitcpio.d/linux.preset <<'EOF'
# mkinitcpio preset file for the linux package -- UKI-only boot
ALL_kver="/boot/vmlinuz-linux"
PRESETS=('default' 'fallback')

default_uki="/efi/EFI/Linux/arch-linux.efi"
default_options=""

fallback_uki="/efi/EFI/Linux/arch-linux-fallback.efi"
fallback_options="-S autodetect"
EOF

    # pacstrap generated these before the profile-specific preset existed.
    # They are not boot artifacts in the UKI profile and must not linger.
    rm -f /boot/initramfs-linux.img /boot/initramfs-linux-fallback.img
}

bl_configure_fwupd_secure_boot() {
    local config_file=/etc/fwupd/fwupd.conf
    local efi_source=/usr/lib/fwupd/efi/fwupdx64.efi
    local efi_signed="${efi_source}.signed"
    local config_tmp

    if [[ ! -f "$config_file" || ! -f "$efi_source" ]]; then
        echo "fwupd Secure Boot files are missing; cannot configure capsule updates." >&2
        return 1
    fi

    # With locally generated Secure Boot keys fwupd must launch its directly
    # signed EFI binary instead of expecting a shim-signed one. Preserve the
    # packaged configuration while setting the option idempotently.
    config_tmp=$(mktemp "${config_file}.XXXXXX")
    if ! awk '
        BEGIN {
            in_section = 0
            found_section = 0
            wrote_key = 0
        }
        function write_key() {
            if (in_section && !wrote_key) {
                print "DisableShimForSecureBoot=true"
                wrote_key = 1
            }
        }
        /^\[uefi_capsule\][[:space:]]*$/ {
            write_key()
            in_section = 1
            found_section = 1
            wrote_key = 0
            print
            next
        }
        /^\[[^]]+\][[:space:]]*$/ {
            write_key()
            in_section = 0
            print
            next
        }
        in_section && /^[[:space:]#;]*DisableShimForSecureBoot[[:space:]]*=/ {
            if (!wrote_key) {
                print "DisableShimForSecureBoot=true"
            }
            wrote_key = 1
            next
        }
        { print }
        END {
            write_key()
            if (!found_section) {
                print ""
                print "[uefi_capsule]"
                print "DisableShimForSecureBoot=true"
            }
        }
    ' "$config_file" > "$config_tmp"; then
        rm -f "$config_tmp"
        return 1
    fi
    install -o root -g root -m 0640 "$config_tmp" "$config_file"
    rm -f "$config_tmp"

    # -s registers the signed output in sbctl's database so its pacman hook
    # re-signs the updater whenever fwupd-efi is upgraded.
    sbctl sign -s -o "$efi_signed" "$efi_source"
}

bl_install_secureboot_helper() {
    cat > /etc/awesome-secureboot.conf <<EOF
LUKS_DEVICE="/dev/disk/by-uuid/${LUKS_UUID}"
LUKS_UUID="${LUKS_UUID}"
TPM2_PCRS="${TPM_PCRS:-7}"
EOF
    chmod 600 /etc/awesome-secureboot.conf

    install -Dm755 /dev/stdin /usr/local/bin/awesome-secureboot <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

CONFIG=/etc/awesome-secureboot.conf
if [[ ! -r "$CONFIG" ]]; then
    echo "Missing $CONFIG" >&2
    exit 1
fi
# shellcheck disable=SC1090
source "$CONFIG"

usage() {
    cat <<USAGE
Usage: awesome-secureboot <command>

Commands:
  status       Show Secure Boot status, registered signatures, and LUKS tokens
  enroll-keys  Enroll sbctl keys while firmware is in Setup Mode
  bind-tpm     Replace any TPM2 token and bind LUKS unlock to configured PCRs
  refresh      Rebuild/sign UKIs and refresh the systemd-boot binaries
USAGE
}

ensure_tpm_cmdline() {
    local option="rd.luks.options=${LUKS_UUID}=tpm2-device=auto"
    local current_cmdline
    if ! grep -qwF "$option" /etc/kernel/cmdline; then
        current_cmdline=$(tr '\n' ' ' < /etc/kernel/cmdline)
        printf '%s %s\n' "${current_cmdline% }" "$option" > /etc/kernel/cmdline
        mkinitcpio -P
        sbctl sign-all
    fi
}

case "${1:-}" in
    status)
        sbctl status
        sbctl verify
        cryptsetup luksDump "$LUKS_DEVICE"
        ;;
    enroll-keys)
        shift
        sbctl enroll-keys "$@"
        echo "Reboot with Secure Boot enabled before binding the configured PCR set."
        ;;
    bind-tpm)
        # PCR 7 measures Secure Boot state. Binding while Secure Boot is off
        # produces a policy that any OS booted on this machine satisfies --
        # including an unsigned replacement UKI or a live USB -- so the TPM
        # would hand over the LUKS key to an attacker. Refuse outright.
        if ! sbctl status 2>/dev/null | grep -qE 'Secure Boot:[[:space:]]*.*[Ee]nabled'; then
            echo "Refusing to bind: Secure Boot is not enabled." >&2
            echo "PCR ${TPM2_PCRS} is meaningless without it -- any OS would satisfy the policy." >&2
            echo "Run 'awesome-secureboot enroll-keys', enable Secure Boot in firmware, reboot, then retry." >&2
            exit 1
        fi
        if sbctl status 2>/dev/null | grep -qE 'Setup Mode:[[:space:]]*.*[Ee]nabled'; then
            echo "Refusing to bind: firmware is still in Setup Mode." >&2
            echo "Secure Boot is not enforcing custom keys yet. Leave Setup Mode, reboot, then retry." >&2
            exit 1
        fi
        ensure_tpm_cmdline
        systemd-cryptenroll \
            --wipe-slot=tpm2 \
            --tpm2-device=auto \
            --tpm2-pcrs="$TPM2_PCRS" \
            "$LUKS_DEVICE"
        echo "TPM2 unlock is bound to PCRs: $TPM2_PCRS"
        ;;
    refresh)
        # Sign the packaged source first so bootctl copies the preferred
        # .efi.signed binary rather than replacing the ESP with an unsigned one.
        sbctl sign-all
        bootctl --esp-path=/efi update
        mkinitcpio -P
        sbctl sign-all
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac
EOF
}

# Locate the "Linux Boot Manager" entry that actually points at THIS system's
# ESP. Matching on the label alone is not safe: a stale entry from another disk
# or a previous install carries the same label, and prioritising it would boot
# the wrong system. efibootmgr -v renders the device path with the ESP's
# partition GUID, so match on that.
bl_find_boot_entry() {
    local esp_guid="$1"
    efibootmgr -v | awk -v guid="${esp_guid^^}" '
        /Linux Boot Manager/ && index(toupper($0), guid) && !found {
            value=$1; sub(/^Boot/, "", value); sub(/\*$/, "", value)
            print value; found=1
        }'
}

bl_prioritize_systemd_boot() {
    local boot_number boot_order new_order entry esp_guid
    local -a entries=()

    esp_guid=$(blkid -s PARTUUID -o value "${DISK}${PART_SUFFIX}2")
    if [[ -z "$esp_guid" ]]; then
        echo "Unable to determine the ESP PARTUUID; refusing to reorder boot entries" >&2
        return 1
    fi

    boot_number=$(bl_find_boot_entry "$esp_guid")
    if [[ -z "$boot_number" ]]; then
        efibootmgr --create \
            --disk "$DISK" \
            --part 2 \
            --label "Linux Boot Manager" \
            --loader '\EFI\systemd\systemd-bootx64.efi'
        boot_number=$(bl_find_boot_entry "$esp_guid")
        if [[ -z "$boot_number" ]]; then
            echo "Unable to create the Linux Boot Manager EFI entry" >&2
            return 1
        fi
    fi

    boot_order=$(efibootmgr | awk -F': ' '/^BootOrder:/ && !found { print $2; found=1 }')
    new_order="$boot_number"
    IFS=',' read -r -a entries <<< "$boot_order"
    for entry in "${entries[@]}"; do
        if [[ "${entry^^}" != "${boot_number^^}" && -n "$entry" ]]; then
            new_order+=",${entry}"
        fi
    done
    efibootmgr --bootorder "$new_order"
}

configure_systemd_boot_uki() {
    local kernel_cmdline efi_binary
    local systemd_boot_source=/usr/lib/systemd/boot/efi/systemd-bootx64.efi
    local systemd_boot_signed=/usr/lib/systemd/boot/efi/systemd-bootx64.efi.signed
    local -a signed_binaries=(
        /efi/EFI/Linux/arch-linux.efi
        /efi/EFI/Linux/arch-linux-fallback.efi
        /efi/EFI/systemd/systemd-bootx64.efi
        /efi/EFI/BOOT/BOOTX64.EFI
    )

    # shellcheck disable=SC2154  # Color variables are defined by chroot.sh.
    echo -e "${BBlue}Configuring systemd-boot with signed UKIs...${NC}"

    bootctl install --esp-path=/efi

    kernel_cmdline=$(bl_kernel_cmdline all)
    install -d -m 0755 /etc/kernel
    printf '%s\n' "$kernel_cmdline" > /etc/kernel/cmdline
    chmod 600 /etc/kernel/cmdline

    bl_set_hooks
    bl_configure_uki_preset

    install -d -m 0755 /efi/loader
    cat > /efi/loader/loader.conf <<'EOF'
default arch-linux.efi
timeout 3
editor no
EOF

    mkinitcpio -P

    if [[ ! -f /var/lib/sbctl/GUID ]]; then
        sbctl create-keys
    fi
    bl_configure_fwupd_secure_boot
    sbctl sign -s -o "$systemd_boot_signed" "$systemd_boot_source"
    for efi_binary in "${signed_binaries[@]}"; do
        if [[ ! -f "$efi_binary" ]]; then
            echo "Expected EFI binary was not generated: $efi_binary" >&2
            return 1
        fi
        sbctl sign -s "$efi_binary"
    done

    bl_install_secureboot_helper
    bl_prioritize_systemd_boot
}
