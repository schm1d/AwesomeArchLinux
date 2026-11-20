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

        # "! cmd" never trips errexit, so each rejection is tested explicitly.
        for bad in "" "01:00.0" "all,0000:01:00.0" "0000:01:00.8" "0000:01:00.0;reboot" "0000:01:00.0 extra=1"; do
            if validate_targets "$bad"; then
                echo "validate_targets accepted: [$bad]" >&2
                exit 1
            fi
        done
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

# Run "main ARGS..." of gpu-unlock.sh as root-by-stub with every bootloader
# location pointed below $1. mkinitcpio, sbctl and grub-mkconfig are functions
# that append to $1/calls; MKINITCPIO_RC / GRUBMK_RC make them fail.
run_gpu_main() {
    local root="$1"
    shift
    GPU_UNLOCK_KERNEL_CMDLINE="$root/etc/kernel/cmdline" \
    GPU_UNLOCK_PRESET_DIR="$root/etc/mkinitcpio.d" \
    GPU_UNLOCK_SBCTL_DIR="$root/sbctl" \
    GPU_UNLOCK_GRUB_DEFAULT="$root/etc/default/grub" \
    GPU_UNLOCK_GRUB_CFG="$root/boot/grub/grub.cfg" \
    GPU_UNLOCK_LOADER_ENTRIES_DIR="$root/loader/entries" \
    GPU_UNLOCK_MODPROBE_PM_CONF="$root/etc/modprobe.d/gpu-unlock-pm.conf" \
    GPU_UNLOCK_TPM_LUKS_CONF="$root/etc/tpm_luks.conf" \
    GPU_UNLOCK_SECUREBOOT_CONF="$root/etc/awesome-secureboot.conf" \
    CALLS="$root/calls" MKINITCPIO_RC="${MKINITCPIO_RC:-0}" GRUBMK_RC="${GRUBMK_RC:-0}" \
    bash -c '
        set -euo pipefail
        id() { echo 0; }
        mkinitcpio() { printf "mkinitcpio %s\n" "$*" >> "$CALLS"; return "$MKINITCPIO_RC"; }
        sbctl() { printf "sbctl %s\n" "$*" >> "$CALLS"; }
        grub-mkconfig() {
            printf "grub-mkconfig %s\n" "$*" >> "$CALLS"
            [[ "$GRUBMK_RC" == 0 ]] || return "$GRUBMK_RC"
            touch "$2"
        }
        command() {
            if [[ "${1:-}" == "-v" && ( "${2:-}" == "grub-mkconfig" || "${2:-}" == "mkinitcpio" ) ]]; then
                return 0
            fi
            builtin command "$@"
        }
        source "$1"; shift
        main "$@"
    ' _ "$GPU_UNLOCK_SCRIPT" "$@"
}

test_uki_cmdline_keeps_comments_and_never_invents_a_cmdline() {
    local tmp out rc
    tmp="$(mktemp -d)"
    trap 'trap - RETURN EXIT; [[ -n "${tmp:-}" ]] && rm -rf -- "$tmp"' RETURN EXIT

    # 1. Comment lines stay comments (mkinitcpio drops them; folded into the
    #    parameter line they would comment out root=).
    local a="$tmp/a"
    mkdir -p "$a/etc/kernel"
    printf '# managed by admin\nroot=/dev/mapper/vg-root rd.luks.name=abc=crypt quiet\n' > "$a/etc/kernel/cmdline"
    cp "$a/etc/kernel/cmdline" "$a/original"
    run_gpu_main "$a" --set-targets all >/dev/null
    assert_eq "$(cat "$a/etc/kernel/cmdline")" \
        $'# managed by admin\nroot=/dev/mapper/vg-root rd.luks.name=abc=crypt quiet gpu_unlock.targets=all' \
        "comment preserved, tokens appended to the parameter line"
    assert_eq "$(find "$a/etc/kernel" -name 'cmdline.bak.*' | wc -l | tr -d ' ')" "1" "previous cmdline backed up"
    cmp -s "$a/original" "$(find "$a/etc/kernel" -name 'cmdline.bak.*')" || fail "backup is not the original cmdline"
    run_gpu_main "$a" --disable >/dev/null
    cmp -s "$a/etc/kernel/cmdline" "$a/original" || fail "--disable did not restore the original cmdline"

    # 2. UKI preset without /etc/kernel/cmdline: a file holding only our token
    #    would replace /etc/cmdline.d and /proc/cmdline as the UKI command line.
    local b="$tmp/b"
    mkdir -p "$b/etc/kernel" "$b/etc/mkinitcpio.d"
    printf 'default_uki="/efi/EFI/Linux/arch-linux.efi"\n' > "$b/etc/mkinitcpio.d/linux.preset"
    rc=0
    out="$(run_gpu_main "$b" --set-targets all 2>&1)" || rc=$?
    assert_eq "$rc" "1" "refuses when there is no parameter line to extend"
    assert_contains "$out" "Nothing was changed"
    [[ ! -e "$b/etc/kernel/cmdline" ]] || fail "created a token-only $b/etc/kernel/cmdline"
    [[ ! -e "$b/calls" ]] || fail "rebuilt the UKI although nothing changed: $(cat "$b/calls")"

    # 3. A comments-only file is the same situation.
    local c="$tmp/c"
    mkdir -p "$c/etc/kernel"
    printf '# only a comment\n' > "$c/etc/kernel/cmdline"
    rc=0
    run_gpu_main "$c" --set-targets all >/dev/null 2>&1 || rc=$?
    assert_eq "$rc" "1"
    assert_eq "$(cat "$c/etc/kernel/cmdline")" "# only a comment" "comments-only cmdline untouched"

    # 4. A failed UKI rebuild puts the previous cmdline back.
    local d="$tmp/d"
    mkdir -p "$d/etc/kernel"
    printf 'root=UUID=1 rw quiet\n' > "$d/etc/kernel/cmdline"
    rc=0
    out="$(MKINITCPIO_RC=1 run_gpu_main "$d" --set-targets all 2>&1)" || rc=$?
    assert_eq "$rc" "1" "mkinitcpio failure is reported"
    assert_contains "$out" "Rebuilding or signing the UKI failed"
    assert_eq "$(cat "$d/etc/kernel/cmdline")" "root=UUID=1 rw quiet" "cmdline rolled back after failed rebuild"
}

test_loader_entries_only_linux_entries_and_reversible() {
    local tmp
    tmp="$(mktemp -d)"
    trap 'trap - RETURN EXIT; [[ -n "${tmp:-}" ]] && rm -rf -- "$tmp"' RETURN EXIT

    local entries="$tmp/loader/entries" f
    mkdir -p "$entries" "$tmp/originals"
    printf 'title Windows\nefi /EFI/Microsoft/Boot/bootmgfw.efi\n' > "$entries/windows.conf"
    printf 'title Arch\nlinux /vmlinuz-linux\ninitrd /initramfs-linux.img\n' > "$entries/arch-noopts.conf"
    printf 'title Arch 2\nlinux /vmlinuz-linux\noptions root=UUID=1 rw\noptions quiet\n' > "$entries/arch-two.conf"
    cp "$entries"/*.conf "$tmp/originals/"

    run_gpu_main "$tmp" --set-targets all >/dev/null
    cmp -s "$entries/windows.conf" "$tmp/originals/windows.conf" || fail "non-Linux entry was edited"
    assert_eq "$(grep -c '^options' "$entries/arch-noopts.conf")" "1"
    assert_contains "$(cat "$entries/arch-noopts.conf")" "options gpu_unlock.targets=all"
    assert_eq "$(grep -c 'gpu_unlock.targets=all' "$entries/arch-two.conf")" "1" "tokens added once, not per options line"
    assert_contains "$(cat "$entries/arch-two.conf")" "options quiet gpu_unlock.targets=all"

    run_gpu_main "$tmp" --disable >/dev/null
    for f in windows.conf arch-noopts.conf arch-two.conf; do
        cmp -s "$entries/$f" "$tmp/originals/$f" || fail "--disable did not restore $f: $(cat "$entries/$f")"
    done
    # Backups must not look like loader entries (*.conf).
    assert_eq "$(find "$entries" -name '*.conf' | wc -l | tr -d ' ')" "3" "no stray *.conf files in loader/entries"
}

test_grub_default_is_edited_in_place_and_reversible() {
    local tmp
    tmp="$(mktemp -d)"
    trap 'trap - RETURN EXIT; [[ -n "${tmp:-}" ]] && rm -rf -- "$tmp"' RETURN EXIT

    # name|expected value of GRUB_CMDLINE_LINUX_DEFAULT as grub-mkconfig (a shell) reads it
    local -a cases=(
        'escaped|acpi_osi="Windows 2020" quiet gpu_unlock.targets=all gpu_unlock.resume=0'
        'single|loglevel=3 quiet gpu_unlock.targets=all gpu_unlock.resume=0'
        'two|quiet nvme_core.default_ps_max_latency_us=0 gpu_unlock.targets=all gpu_unlock.resume=0'
        'comment|quiet splash gpu_unlock.targets=all gpu_unlock.resume=0'
        'unquoted|quiet gpu_unlock.targets=all gpu_unlock.resume=0'
        'concatenated|quiet x=1 gpu_unlock.targets=all gpu_unlock.resume=0'
    )
    local spec name expected root grub evaluated
    for spec in "${cases[@]}"; do
        name="${spec%%|*}"
        expected="${spec#*|}"
        root="$tmp/$name"
        grub="$root/etc/default/grub"
        mkdir -p "$root/etc/default" "$root/boot/grub"
        case "$name" in
            escaped)      printf '%s\n' 'GRUB_TIMEOUT=5' 'GRUB_CMDLINE_LINUX_DEFAULT="acpi_osi=\"Windows 2020\" quiet"' ;;
            single)       printf '%s\n' "GRUB_CMDLINE_LINUX_DEFAULT='loglevel=3 quiet'" ;;
            two)          printf '%s\n' '#GRUB_CMDLINE_LINUX_DEFAULT="old"' 'GRUB_CMDLINE_LINUX_DEFAULT="quiet"' \
                              'GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT nvme_core.default_ps_max_latency_us=0"' ;;
            comment)      printf '%s\n' 'GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"   # keep me' ;;
            unquoted)     printf '%s\n' 'GRUB_CMDLINE_LINUX_DEFAULT=quiet' ;;
            concatenated) printf '%s\n' "GRUB_CMDLINE_LINUX_DEFAULT=\"quiet \"'x=1'" ;;
        esac > "$grub"
        cp "$grub" "$root/original"

        run_gpu_main "$root" --set-targets all --no-resume-unlock >/dev/null
        evaluated="$(bash -c 'source "$1"; printf %s "$GRUB_CMDLINE_LINUX_DEFAULT"' _ "$grub")"
        assert_eq "$evaluated" "$expected" "GRUB value after --set-targets ($name)"
        if [[ "$name" == two ]]; then
            assert_contains "$(cat "$grub")" '#GRUB_CMDLINE_LINUX_DEFAULT="old"' "commented assignment left alone"
        fi
        if [[ "$name" == comment ]]; then
            assert_contains "$(cat "$grub")" '   # keep me' "trailing comment kept"
        fi

        # Applying the same targets again changes nothing (no second backup).
        run_gpu_main "$root" --set-targets all --no-resume-unlock >/dev/null
        assert_eq "$(find "$root/etc/default" -name 'grub.bak.*' | wc -l | tr -d ' ')" "1" "idempotent ($name)"

        run_gpu_main "$root" --disable >/dev/null
        cmp -s "$grub" "$root/original" || fail "--disable did not restore /etc/default/grub ($name): $(cat "$grub")"
    done

    # grub-mkconfig failure: the edited file is rolled back and the run fails.
    local f="$tmp/fail" rc=0
    mkdir -p "$f/etc/default" "$f/boot/grub"
    printf 'GRUB_CMDLINE_LINUX_DEFAULT="quiet"\n' > "$f/etc/default/grub"
    GRUBMK_RC=1 run_gpu_main "$f" --set-targets all >/dev/null 2>&1 || rc=$?
    assert_eq "$rc" "1" "grub-mkconfig failure is reported"
    assert_eq "$(cat "$f/etc/default/grub")" 'GRUB_CMDLINE_LINUX_DEFAULT="quiet"' "grub default rolled back"
}

test_tpm_warning_reads_only_tpm2_pcrs_and_pm_override_is_reversible() {
    local tmp
    tmp="$(mktemp -d)"
    trap 'trap - RETURN EXIT; [[ -n "${tmp:-}" ]] && rm -rf -- "$tmp"' RETURN EXIT

    mkdir -p "$tmp/etc/kernel"
    local pcrs out
    for pcrs in '7' '7+11' '"0,4"' '0+7'; do
        printf 'root=UUID=1 rw quiet\n' > "$tmp/etc/kernel/cmdline"
        # The UUID is full of 4s and 9s: only the TPM2_PCRS value may count.
        printf 'CRYPTDEVICE=UUID=0f3e9c1a-77b2-4a6d-9412-49aa11c4e912:crypt\nTPM2_PCRS=%s\n' "$pcrs" > "$tmp/etc/tpm_luks.conf"
        out="$(run_gpu_main "$tmp" --set-targets all 2>&1)"
        case "$pcrs" in
            '7+11')  assert_contains "$out" "bound to PCR 11" ;;
            '"0,4"') assert_contains "$out" "bound to PCR 4" ;;
            *)       assert_not_contains "$out" "TPM2 LUKS policy" "no PCR warning for TPM2_PCRS=$pcrs" ;;
        esac
    done

    # --disable-dynamic-pm is honoured by --set-targets and undone by --disable.
    local pm="$tmp/etc/modprobe.d/gpu-unlock-pm.conf"
    run_gpu_main "$tmp" --set-targets all --disable-dynamic-pm >/dev/null 2>&1
    assert_contains "$(cat "$pm")" "options nvidia NVreg_DynamicPowerManagement=0x00"
    run_gpu_main "$tmp" --disable >/dev/null 2>&1
    [[ ! -e "$pm" ]] || fail "--disable left $pm behind"
}

# Run build_and_install_packages with every privileged or network step
# replaced by a function that records it in $1/calls.
run_gpu_build() {
    local root="$1" repo_url="$2" git_ref="$3"
    GPU_UNLOCK_CACHE_ROOT="$root/cache" CALLS="$root/calls" FAKE_HEAD="${FAKE_HEAD:-}" SUDO_USER="alice" \
    bash -c '
        set -euo pipefail
        source "$1"
        pacman() { printf "pacman %s\n" "$*" >> "$CALLS"; }
        ensure_kernel_headers() { :; }
        id() {
            case "$*" in
                "-u alice") echo 1000 ;;
                "-gn alice") echo alice ;;
                "-nG alice") echo "alice wheel" ;;
                *) echo 0 ;;
            esac
        }
        getent() { [[ "$1" == group && "$2" == compilers ]]; }
        usermod() { printf "usermod %s\n" "$*" >> "$CALLS"; }
        useradd() { printf "useradd %s\n" "$*" >> "$CALLS"; }
        userdel() { :; }
        chown() { :; }
        setfacl() { :; }
        install() { mkdir -p "${@: -2}"; }
        modinfo() { return 0; }
        runuser() {
            printf "runuser %s\n" "$*" >> "$CALLS"
            local last="${*: -1}"
            case " $* " in
                *" git clone "*)
                    mkdir -p "$last/packaging/arch"
                    : > "$last/packaging/arch/PKGBUILD"
                    : > "$last/VERSION"
                    ;;
                *" rev-parse HEAD "*) printf "%s\n" "${FAKE_HEAD:-$DEFAULT_REPO_REF}" ;;
                *"makepkg -f --noconfirm"*)
                    : > "${*: -2:1}/pkg/gpu-unlock-firmware-1-1-any.pkg.tar.zst"
                    : > "${*: -2:1}/pkg/gpu-unlock-dkms-1-1-any.pkg.tar.zst"
                    ;;
            esac
        }
        build_and_install_packages "$2" "$3" "" "false"
    ' _ "$GPU_UNLOCK_SCRIPT" "$repo_url" "$git_ref"
}

test_build_is_pinned_and_compiler_group_is_per_invocation() {
    local tmp pin default_url out rc calls
    tmp="$(mktemp -d)"
    trap 'trap - RETURN EXIT; [[ -n "${tmp:-}" ]] && rm -rf -- "$tmp"' RETURN EXIT

    pin="$(bash -c 'source "$1"; printf %s "$DEFAULT_REPO_REF"' _ "$GPU_UNLOCK_SCRIPT")"
    default_url="$(bash -c 'source "$1"; printf %s "$DEFAULT_REPO_URL"' _ "$GPU_UNLOCK_SCRIPT")"
    [[ "$pin" =~ ^[0-9a-f]{40}$ ]] || fail "DEFAULT_REPO_REF is not a full commit hash: $pin"

    # 1. Default repository without --ref builds the pinned commit.
    mkdir -p "$tmp/a"
    run_gpu_build "$tmp/a" "$default_url" "" >/dev/null 2>&1
    calls="$(cat "$tmp/a/calls")"
    assert_contains "$calls" "checkout --detach $pin" "default repository is built at the pinned commit"
    assert_not_contains "$calls" "clone --depth 1" "pinned build does not take the branch tip"
    assert_contains "$calls" "pacman -U --noconfirm"
    # compilers membership is granted to the build processes only.
    assert_contains "$calls" "runuser -u alice -g alice -G compilers -- "
    assert_not_contains "$calls" "usermod" "the invoking user is not added to a group permanently"

    # 2. A checkout that is not the requested commit is never built.
    mkdir -p "$tmp/b"
    rc=0
    out="$(FAKE_HEAD="1111111111111111111111111111111111111111" run_gpu_build "$tmp/b" "$default_url" "" 2>&1)" || rc=$?
    assert_eq "$rc" "1" "commit mismatch aborts the build"
    assert_contains "$out" "does not match the requested commit"
    assert_not_contains "$(cat "$tmp/b/calls")" "makepkg" "nothing is built from an unexpected commit"
    assert_not_contains "$(cat "$tmp/b/calls")" "pacman -U" "nothing is installed from an unexpected commit"

    # 3. Another repository without --ref is allowed but called out as unpinned.
    mkdir -p "$tmp/c"
    out="$(run_gpu_build "$tmp/c" "https://example.invalid/fork.git" "" 2>&1)"
    assert_contains "$out" "not pinned"
    assert_contains "$(cat "$tmp/c/calls")" "clone --depth 1 -- https://example.invalid/fork.git"
}

test_installer_optional_default_and_staging() {
    local archinstall="$REPO_ROOT/base/archinstall.sh"
    local chroot_sh="$REPO_ROOT/base/chroot.sh"

    # Code lines only: a mention in a comment is not wiring.
    local archinstall_code chroot_code
    archinstall_code="$(script_code "$archinstall")"
    chroot_code="$(script_code "$chroot_sh")"
    assert_contains "$archinstall_code" "INSTALL_GPU_UNLOCK=false" "gpu-unlock is disabled/optional by default"
    assert_contains "$archinstall_code" "/mnt/usr/local/lib/awesomearchlinux/gpu-unlock.sh" "stages gpu-unlock.sh into target"
    assert_contains "$archinstall_code" "/mnt/usr/local/sbin/awesome-gpu-unlock" "creates awesome-gpu-unlock symlink"
    assert_contains "$chroot_code" '--no-bootloader' "chroot delegates cmdline/image generation to bootloader.sh"
    assert_contains "$chroot_code" 'BOOT_EXTRA_CMDLINE+=("gpu_unlock.targets=${GPU_UNLOCK_TARGETS}")' "chroot queues gpu_unlock.targets into BOOT_EXTRA_CMDLINE"
}

run_test "PCI device ID classification and sysfs GPU scan" test_pci_device_classification_and_scan
run_test "gpu_unlock.targets validation and quote-safe cmdline transform" test_targets_validation_and_cmdline_transform
run_test "UKI (sbctl) and GRUB kernel cmdline update and disable round-trip" test_bootloader_updates_uki_systemd_boot_and_grub
run_test "UKI cmdline keeps comment lines, refuses a token-only cmdline, rolls back" test_uki_cmdline_keeps_comments_and_never_invents_a_cmdline
run_test "loader entries: only Linux entries are edited and --disable restores them" test_loader_entries_only_linux_entries_and_reversible
run_test "GRUB default: quoting preserved, edits reversible, failed grub-mkconfig rolled back" test_grub_default_is_edited_in_place_and_reversible
run_test "TPM PCR warning parses TPM2_PCRS only; dynamic-PM override is reversible" test_tpm_warning_reads_only_tpm2_pcrs_and_pm_override_is_reversible
run_test "build uses the pinned commit, refuses a mismatch, scopes compilers group to the build" test_build_is_pinned_and_compiler_group_is_per_invocation
run_test "archinstall.sh and chroot.sh optional gpu-unlock wiring" test_installer_optional_default_and_staging

finish_test_file "test_gpu_unlock.sh"
