#!/usr/bin/env bash
# Pure-Bash unit and integration tests for utils/gpu-unlock.sh and optional
# installer wiring in base/archinstall.sh + base/chroot.sh.

set -euo pipefail

# shellcheck disable=SC1090,SC1091
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

GPU_UNLOCK_SCRIPT="$REPO_ROOT/utils/gpu-unlock.sh"

make_pci_dev() {
    local root="$1" bdf="$2" vendor="$3" device="$4" class="$5" driver="${6:-}"
    local dir="$root/$bdf"
    mkdir -p "$dir"
    printf '%s\n' "$vendor" > "$dir/vendor"
    printf '%s\n' "$device" > "$dir/device"
    printf '%s\n' "$class"  > "$dir/class"
    if [[ -n "$driver" ]]; then
        mkdir -p "$root/_drivers/$driver"
        ln -s "$root/_drivers/$driver" "$dir/driver"
    fi
}

test_pci_device_classification_and_scan() {
    local tmp
    tmp="$(mktemp -d)"
    trap 'trap - RETURN EXIT; [[ -n "${tmp:-}" ]] && rm -rf -- "$tmp"' RETURN EXIT

    local pci="$tmp/pci"
    make_pci_dev "$pci" "0000:01:00.0" "0x10de" "0x2204" "0x030000" "nvidia"
    make_pci_dev "$pci" "0000:01:00.1" "0x10de" "0x1aef" "0x040300" "snd_hda_intel"
    make_pci_dev "$pci" "0000:21:00.0" "0x10de" "0x2684" "0x030200" ""
    make_pci_dev "$pci" "0000:22:00.0" "0x10de" "0x1e04" "0x030000" "nvidia"
    make_pci_dev "$pci" "0000:23:00.0" "0x10de" "0x2b85" "0x030000" "nvidia"
    make_pci_dev "$pci" "0000:00:02.0" "0x8086" "0x4680" "0x030000" "i915"

    local out
    out="$(GPU_UNLOCK_SYSFS_PCI="$pci" bash -c '
        set -euo pipefail
        lspci() { return 1; }
        source "$1"
        scan_nvidia_gpus
    ' _ "$GPU_UNLOCK_SCRIPT")"

    assert_contains "$out" "0000:01:00.0|2204|stable|Ampere GA102 (RTX 30)|nvidia|"
    assert_contains "$out" "0000:21:00.0|2684|experimental|Ada Lovelace AD102 (RTX 40)|unbound|"
    assert_contains "$out" "0000:22:00.0|1e04|experimental|Turing TU102 (RTX 20 / Titan RTX)|nvidia|"
    assert_contains "$out" "0000:23:00.0|2b85|unsupported|Blackwell (RTX 50)"
    assert_not_contains "$out" "0000:01:00.1" "PCI audio function ignored"
    assert_not_contains "$out" "0000:00:02.0" "non-NVIDIA GPU ignored"
}

test_targets_validation_and_cmdline_transform() {
    bash -c '
        set -euo pipefail
        source "$1"
        validate_targets "all"
        validate_targets "0000:01:00.0"
        validate_targets "0000:01:00.0,0000:23:00.0"
        validate_targets "0000:AB:cd.7"

        ! validate_targets ""
        ! validate_targets "01:00.0"
        ! validate_targets "all,0000:01:00.0"
        ! validate_targets "0000:01:00.8"
        ! validate_targets "0000:01:00.0;reboot"
        ! validate_targets "0000:01:00.0 extra=1"
    ' _ "$GPU_UNLOCK_SCRIPT"

    local transformed
    transformed="$(bash -c '
        set -euo pipefail
        source "$1"
        transform_cmdline_string \
            '\''rd.luks.name=123=crypt root=/dev/sd* acpi_osi="!Windows 2020" gpu_unlock.targets=0000:01:00.0 gpu_unlock.resume=0 quiet'\'' \
            "gpu_unlock.targets=all"
    ' _ "$GPU_UNLOCK_SCRIPT")"

    assert_eq "$transformed" 'rd.luks.name=123=crypt root=/dev/sd* acpi_osi="!Windows 2020" quiet gpu_unlock.targets=all' \
        "preserves quotes & globs while replacing old gpu_unlock tokens"

    local cleared
    cleared="$(bash -c '
        set -euo pipefail
        source "$1"
        transform_cmdline_string \
            '\''quiet gpu_unlock.targets=all gpu_unlock.resume=0 loglevel=3'\''
    ' _ "$GPU_UNLOCK_SCRIPT")"

    assert_eq "$cleared" "quiet loglevel=3" "removes all gpu_unlock tokens on disable"
}

test_bootloader_updates_uki_systemd_boot_and_grub() {
    local tmp
    tmp="$(mktemp -d)"
    trap 'trap - RETURN EXIT; [[ -n "${tmp:-}" ]] && rm -rf -- "$tmp"' RETURN EXIT

    # 1. UKI + sbctl re-signing
    mkdir -p "$tmp/uki/etc/kernel" "$tmp/uki/etc/mkinitcpio.d" "$tmp/uki/sbctl"
    printf 'quiet loglevel=3\n' > "$tmp/uki/etc/kernel/cmdline"
    chmod 0600 "$tmp/uki/etc/kernel/cmdline"
    printf 'default_uki="/efi/EFI/Linux/arch-linux.efi"\n' > "$tmp/uki/etc/mkinitcpio.d/linux.preset"
    printf 'guid\n' > "$tmp/uki/sbctl/GUID"

    local uki_calls="$tmp/uki_calls"
    GPU_UNLOCK_KERNEL_CMDLINE="$tmp/uki/etc/kernel/cmdline" \
    GPU_UNLOCK_PRESET_DIR="$tmp/uki/etc/mkinitcpio.d" \
    GPU_UNLOCK_SBCTL_DIR="$tmp/uki/sbctl" \
    GPU_UNLOCK_GRUB_DEFAULT="$tmp/uki/nonexistent-grub" \
    GPU_UNLOCK_LOADER_ENTRIES_DIR="$tmp/uki/nonexistent-entries" \
    bash -c '
        set -euo pipefail
        calls="$1"; shift
        id() { echo 0; }
        find_systemd_boot_entries() { :; }
        mkinitcpio() { printf "mkinitcpio %s\n" "$*" >> "$calls"; }
        sbctl() { printf "sbctl %s\n" "$*" >> "$calls"; }
        command() {
            if [[ "${1:-}" == "-v" && ( "${2:-}" == "sbctl" || "${2:-}" == "mkinitcpio" ) ]]; then
                return 0
            fi
            builtin command "$@"
        }
        source "$1"
        main --set-targets 0000:01:00.0,0000:23:00.0 --no-resume-unlock
    ' _ "$uki_calls" "$GPU_UNLOCK_SCRIPT" >/dev/null

    assert_eq "$(cat "$tmp/uki/etc/kernel/cmdline")" "quiet loglevel=3 gpu_unlock.targets=0000:01:00.0,0000:23:00.0 gpu_unlock.resume=0"
    assert_file_mode "$tmp/uki/etc/kernel/cmdline" "600"
    assert_contains "$(cat "$uki_calls")" "mkinitcpio -P"
    assert_contains "$(cat "$uki_calls")" "sbctl sign-all"

    # 2. Type-1 systemd-boot entry update
    mkdir -p "$tmp/sdboot/entries"
    cat > "$tmp/sdboot/entries/arch.conf" <<'EOF'
title Arch Linux
linux /vmlinuz-linux
initrd /initramfs-linux.img
options root=UUID=1111 rw quiet
EOF
    GPU_UNLOCK_KERNEL_CMDLINE="$tmp/sdboot/no-cmdline" \
    GPU_UNLOCK_PRESET_DIR="$tmp/sdboot/no-presets" \
    GPU_UNLOCK_GRUB_DEFAULT="$tmp/sdboot/no-grub" \
    GPU_UNLOCK_LOADER_ENTRIES_DIR="$tmp/sdboot/entries" \
    bash -c '
        set -euo pipefail
        id() { echo 0; }
        mkinitcpio() { :; }
        source "$1"
        main --set-targets all
    ' _ "$GPU_UNLOCK_SCRIPT" >/dev/null

    assert_contains "$(cat "$tmp/sdboot/entries/arch.conf")" "options root=UUID=1111 rw quiet gpu_unlock.targets=all"

    # 3. GRUB update + disable round-trip
    mkdir -p "$tmp/grub/etc/default" "$tmp/grub/boot/grub"
    cat > "$tmp/grub/etc/default/grub" <<'EOF'
GRUB_TIMEOUT=5
GRUB_CMDLINE_LINUX_DEFAULT="slab_nomerge quiet"
GRUB_CMDLINE_LINUX="cryptdevice=UUID=abc:crypt_lvm"
EOF
    local grub_calls="$tmp/grub_calls"
    GPU_UNLOCK_KERNEL_CMDLINE="$tmp/grub/no-cmdline" \
    GPU_UNLOCK_PRESET_DIR="$tmp/grub/no-presets" \
    GPU_UNLOCK_LOADER_ENTRIES_DIR="$tmp/grub/no-entries" \
    GPU_UNLOCK_GRUB_DEFAULT="$tmp/grub/etc/default/grub" \
    GPU_UNLOCK_GRUB_CFG="$tmp/grub/boot/grub/grub.cfg" \
    bash -c '
        set -euo pipefail
        calls="$1"; shift
        id() { echo 0; }
        mkinitcpio() { printf "mkinitcpio %s\n" "$*" >> "$calls"; }
        grub-mkconfig() { printf "grub-mkconfig %s\n" "$*" >> "$calls"; touch "$2"; }
        command() {
            if [[ "${1:-}" == "-v" && ( "${2:-}" == "grub-mkconfig" || "${2:-}" == "mkinitcpio" ) ]]; then
                return 0
            fi
            builtin command "$@"
        }
        source "$1"
        main --set-targets all
        grep -qF '\''GRUB_CMDLINE_LINUX_DEFAULT="slab_nomerge quiet gpu_unlock.targets=all"'\'' "$GPU_UNLOCK_GRUB_DEFAULT"
        main --disable
    ' _ "$grub_calls" "$GPU_UNLOCK_SCRIPT" >/dev/null

    assert_contains "$(cat "$tmp/grub/etc/default/grub")" 'GRUB_CMDLINE_LINUX_DEFAULT="slab_nomerge quiet"'
    assert_contains "$(cat "$grub_calls")" "grub-mkconfig -o $tmp/grub/boot/grub/grub.cfg"
}

test_installer_optional_default_and_staging() {
    local archinstall="$REPO_ROOT/base/archinstall.sh"
    local chroot_sh="$REPO_ROOT/base/chroot.sh"

    assert_contains "$(cat "$archinstall")" "INSTALL_GPU_UNLOCK=false" "gpu-unlock is disabled/optional by default"
    assert_contains "$(cat "$archinstall")" "/mnt/usr/local/lib/awesomearchlinux/gpu-unlock.sh" "stages gpu-unlock.sh into target"
    assert_contains "$(cat "$archinstall")" "/mnt/usr/local/sbin/awesome-gpu-unlock" "creates awesome-gpu-unlock symlink"
    assert_contains "$(cat "$chroot_sh")" '--no-bootloader' "chroot delegates cmdline/image generation to bootloader.sh"
    assert_contains "$(cat "$chroot_sh")" 'BOOT_EXTRA_CMDLINE+=("gpu_unlock.targets=${GPU_UNLOCK_TARGETS}")' "chroot queues gpu_unlock.targets into BOOT_EXTRA_CMDLINE"
}

run_test "PCI device ID classification and sysfs GPU scan" test_pci_device_classification_and_scan
run_test "gpu_unlock.targets validation and quote-safe cmdline transform" test_targets_validation_and_cmdline_transform
run_test "UKI (sbctl) and GRUB kernel cmdline update and disable round-trip" test_bootloader_updates_uki_systemd_boot_and_grub
run_test "archinstall.sh and chroot.sh optional gpu-unlock wiring" test_installer_optional_default_and_staging

finish_test_file "test_gpu_unlock.sh"
