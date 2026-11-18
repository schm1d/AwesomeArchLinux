#!/usr/bin/env bash
# ==============================================================================
# Script: gpu-unlock.sh
# Description: Optional installer and manager for Zagitta/gpu-unlock on Arch
#              Linux (unlocks full-rate FP16/BF16/TF32 tensor cores on supported
#              GeForce RTX 20 / 30 / 40 GPUs at boot before nvidia binds).
# Upstream:    https://github.com/Zagitta/gpu-unlock
# ==============================================================================

set -euo pipefail
umask 022

DEFAULT_REPO_URL="https://github.com/Zagitta/gpu-unlock.git"
SYSFS_PCI_DEVICES="${GPU_UNLOCK_SYSFS_PCI:-/sys/bus/pci/devices}"
SYSFS_DMI_DIR="${GPU_UNLOCK_SYSFS_DMI:-/sys/class/dmi/id}"
KERNEL_CMDLINE_FILE="${GPU_UNLOCK_KERNEL_CMDLINE:-/etc/kernel/cmdline}"
PROC_CMDLINE_FILE="${GPU_UNLOCK_PROC_CMDLINE:-/proc/cmdline}"
GRUB_DEFAULT_FILE="${GPU_UNLOCK_GRUB_DEFAULT:-/etc/default/grub}"
GRUB_CFG_FILE="${GPU_UNLOCK_GRUB_CFG:-/boot/grub/grub.cfg}"
MKINITCPIO_PRESET_DIR="${GPU_UNLOCK_PRESET_DIR:-/etc/mkinitcpio.d}"
MKINITCPIO_DROPIN="${GPU_UNLOCK_MKINITCPIO_DROPIN:-/etc/mkinitcpio.conf.d/zz-gpu-unlock.conf}"
SBCTL_DIR="${GPU_UNLOCK_SBCTL_DIR:-/var/lib/sbctl}"
MODPROBE_PM_CONF="${GPU_UNLOCK_MODPROBE_PM_CONF:-/etc/modprobe.d/gpu-unlock-pm.conf}"
INSTALLED_HELPER="${GPU_UNLOCK_INSTALLED_HELPER:-/usr/local/lib/awesomearchlinux/gpu-unlock.sh}"
INSTALLED_SYMLINK="${GPU_UNLOCK_INSTALLED_SYMLINK:-/usr/local/sbin/awesome-gpu-unlock}"
CACHE_ROOT="${GPU_UNLOCK_CACHE_ROOT:-/var/cache/awesomearchlinux/gpu-unlock}"

C_BLUE='\033[1;34m'
C_GREEN='\033[1;32m'
C_YELLOW='\033[1;33m'
C_RED='\033[1;31m'
C_NC='\033[0m'

info() { printf "${C_BLUE}[INFO]${C_NC} %s\n" "$*"; }
ok()   { printf "${C_GREEN}[OK]${C_NC} %s\n" "$*"; }
warn() { printf "${C_YELLOW}[WARN]${C_NC} %s\n" "$*" >&2; }
err()  { printf "${C_RED}[ERROR]${C_NC} %s\n" "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
Usage: gpu-unlock.sh [MODE] [OPTIONS]

Build, install, configure, inspect, or remove Zagitta/gpu-unlock on Arch Linux.

Modes:
  --status                  Show GPU compatibility, DKMS/firmware, and cmdline status (default)
  --install                 Build & install gpu-unlock-firmware + gpu-unlock-dkms and enable cmdline
  --set-targets TARGETS     Update gpu_unlock.targets= on an installed system and refresh boot images
  --disable                 Remove gpu_unlock.* parameters from kernel cmdline (keep packages installed)
  --uninstall               Remove kernel cmdline parameters, uninstall packages, and refresh boot images
  -h, --help                Show this help

Options:
  --targets TARGETS         'all' (default) or comma-separated PCI BDFs (e.g. 0000:01:00.0,0000:21:00.0)
  --no-resume-unlock        Also set gpu_unlock.resume=0 on the kernel command line
  --disable-dynamic-pm      Write NVreg_DynamicPowerManagement=0x00 for laptop dGPUs
  --repo-url URL            Upstream Git repository URL (default: https://github.com/Zagitta/gpu-unlock.git)
  --ref REF                 Optional Git tag, branch, or commit SHA to check out before building
  --build-user USER         Unprivileged user account to run makepkg (default: SUDO_USER or ephemeral builder)
  --no-bootloader           Install packages/DKMS only; caller updates bootloader/UKI (used by chroot.sh)
  --keep-cache              Keep downloaded NVIDIA source/installer cache under /var/cache/awesomearchlinux
  -y, --yes                 Non-interactive mode (skip confirmation prompts)
EOF
}

in_chroot() {
    local root_id init_id
    root_id="$(stat -c '%d:%i' / 2>/dev/null || true)"
    init_id="$(stat -c '%d:%i' /proc/1/root/. 2>/dev/null || true)"
    [[ -n "$root_id" && -n "$init_id" && "$root_id" != "$init_id" ]]
}

require_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        err "This operation requires root privileges (run with sudo)."
    fi
}

# Validate gpu_unlock.targets= value: either literal 'all' or comma-separated
# full PCI addresses (DDDD:BB:DD.F in hex, matching lspci -D).
validate_targets() {
    local targets="$1"
    [[ -n "$targets" ]] || return 1
    if [[ "$targets" == "all" ]]; then
        return 0
    fi
    local bdf_re='^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7](,[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7])*$'
    [[ "$targets" =~ $bdf_re ]]
}

# Classify an NVIDIA 4-hex-digit PCI device ID (lowercase, without 0x) against
# Zagitta/gpu-unlock's kernel/gpu_unlock/recipes.c support table.
# Prints: "stable|<family>" | "experimental|<family>" | "unsupported|<reason>"
classify_nvidia_device_id() {
    local dev_id="${1,,}"
    dev_id="${dev_id#0x}"
    case "$dev_id" in
        # Ampere GA102 / GA103 / GA104 / GA106 (RTX 30 series) — Stable
        2200|2203|2204|2205|2206|2207|2208|220a|220d|2216|222b|222f)
            printf 'stable|Ampere GA102 (RTX 30)\n' ;;
        2414)
            printf 'stable|Ampere GA103 (RTX 30)\n' ;;
        2480|2482|2483|2484|2486|2487|2488|2489|248a|248c|248d|248e|\
        249c|249d|249f|24a0|24a4|24ac|24ad|24af|24bf|24c0|24c7|24c8|\
        24c9|24dc|24dd|24df|24e0)
            printf 'stable|Ampere GA104 (RTX 30)\n' ;;
        2501|2503|2504|2505|2507|2508|2509|252f|2544)
            printf 'stable|Ampere GA106 (RTX 30)\n' ;;

        # Ada Lovelace AD102 / AD103 / AD104 / AD106 / AD107 (RTX 40 series) — Experimental
        2684|2685|2689)
            printf 'experimental|Ada Lovelace AD102 (RTX 40)\n' ;;
        2702|2704|2705|2709|2757)
            printf 'experimental|Ada Lovelace AD103 (RTX 40)\n' ;;
        2782|2783|2786)
            printf 'experimental|Ada Lovelace AD104 (RTX 40)\n' ;;
        2803|2805)
            printf 'experimental|Ada Lovelace AD106 (RTX 40)\n' ;;
        2882|28a0|28e0|28e1)
            printf 'experimental|Ada Lovelace AD107 (RTX 40)\n' ;;

        # Turing TU102 / TU104 / TU106 (RTX 20 / Titan RTX) — Experimental
        1e03|1e04|1e07|1e2d|1e2e)
            printf 'experimental|Turing TU102 (RTX 20 / Titan RTX)\n' ;;
        1e81|1e82|1e84|1e87|1e89|1ec2|1ec7)
            printf 'experimental|Turing TU104 (RTX 20)\n' ;;
        1f02|1f03|1f06|1f07|1f08|1f42|1f47)
            printf 'experimental|Turing TU106 (RTX 20)\n' ;;

        # Blackwell (RTX 50) — Explicitly unsupported
        2b*|2c*|2d*|2f*)
            printf 'unsupported|Blackwell (RTX 50) is not supported by gpu-unlock\n' ;;
        *)
            printf 'unsupported|Device ID 0x%s is not in gpu-unlock recipes.c\n' "$dev_id" ;;
    esac
}

# Enumerate NVIDIA PCI display/3D controllers from sysfs.
# Output lines: BDF|DEV_ID|TIER|FAMILY|DRIVER|MODEL
scan_nvidia_gpus() {
    [[ -d "$SYSFS_PCI_DEVICES" ]] || return 0
    local dev_path bdf vendor class device driver="" driver_link model="" classification tier family
    for dev_path in "$SYSFS_PCI_DEVICES"/*; do
        [[ -d "$dev_path" ]] || continue
        [[ -r "$dev_path/vendor" && -r "$dev_path/device" && -r "$dev_path/class" ]] || continue
        vendor="$(<"$dev_path/vendor")"
        [[ "${vendor,,}" == "0x10de" ]] || continue
        class="$(<"$dev_path/class")"
        # PCI class 0x0300xx (VGA) or 0x0302xx (3D controller)
        [[ "${class,,}" == 0x0300* || "${class,,}" == 0x0302* ]] || continue
        bdf="$(basename "$dev_path")"
        device="$(<"$dev_path/device")"
        device="${device#0x}"
        device="${device,,}"
        driver="unbound"
        if [[ -L "$dev_path/driver" ]]; then
            driver_link="$(readlink "$dev_path/driver" 2>/dev/null || true)"
            [[ -n "$driver_link" ]] && driver="$(basename "$driver_link")"
        fi
        model="NVIDIA PCI 10de:${device}"
        if command -v lspci >/dev/null 2>&1; then
            local lspci_line
            lspci_line="$(lspci -D -s "$bdf" 2>/dev/null | cut -d':' -f4- | sed 's/^[[:space:]]*//' || true)"
            [[ -n "$lspci_line" ]] && model="$lspci_line"
        fi
        classification="$(classify_nvidia_device_id "$device")"
        tier="${classification%%|*}"
        family="${classification#*|}"
        printf '%s|%s|%s|%s|%s|%s\n' "$bdf" "$device" "$tier" "$family" "$driver" "$model"
    done
}

is_laptop_chassis() {
    [[ -r "$SYSFS_DMI_DIR/chassis_type" ]] || return 1
    local ct
    ct="$(<"$SYSFS_DMI_DIR/chassis_type")"
    case "$ct" in
        8|9|10|14|30|31|32) return 0 ;;
        *) return 1 ;;
    esac
}

# Pure-Bash quote-preserving kernel cmdline transformer: removes any existing
# gpu_unlock.targets=* and gpu_unlock.resume=* tokens, preserves quoted tokens
# (e.g. acpi_osi="!Windows 2020"), never glob-expands, and appends new tokens.
transform_cmdline_string() {
    local current="$1"
    shift
    local -a new_tokens=("$@")
    local -a parsed=() kept=()
    local cur="" in_quote="" esc=0 i ch len=${#current}

    for (( i = 0; i < len; i++ )); do
        ch="${current:i:1}"
        if (( esc )); then
            cur+="$ch"
            esc=0
            continue
        fi
        if [[ "$ch" == '\' && "$in_quote" != "'" ]]; then
            cur+="$ch"
            esc=1
            continue
        fi
        if [[ -n "$in_quote" ]]; then
            cur+="$ch"
            [[ "$ch" == "$in_quote" ]] && in_quote=""
            continue
        fi
        if [[ "$ch" == '"' || "$ch" == "'" ]]; then
            cur+="$ch"
            in_quote="$ch"
            continue
        fi
        if [[ "$ch" == [[:space:]] ]]; then
            if [[ -n "$cur" ]]; then
                parsed+=("$cur")
                cur=""
            fi
            continue
        fi
        cur+="$ch"
    done
    [[ -n "$cur" ]] && parsed+=("$cur")

    local tok
    for tok in "${parsed[@]}"; do
        case "$tok" in
            gpu_unlock.targets=*|gpu_unlock.resume=*) continue ;;
            *) kept+=("$tok") ;;
        esac
    done
    for tok in "${new_tokens[@]}"; do
        [[ -n "$tok" ]] && kept+=("$tok")
    done
    printf '%s' "${kept[*]}"
}

has_uki_preset() {
    [[ -d "$MKINITCPIO_PRESET_DIR" ]] || return 1
    local preset
    for preset in "$MKINITCPIO_PRESET_DIR"/*.preset; do
        [[ -f "$preset" ]] || continue
        if grep -qE '^[[:space:]]*(default|fallback)_uki=' "$preset" 2>/dev/null; then
            return 0
        fi
    done
    return 1
}

find_systemd_boot_entries() {
    local -a dirs=()
    if [[ -n "${GPU_UNLOCK_LOADER_ENTRIES_DIR:-}" ]]; then
        dirs=("$GPU_UNLOCK_LOADER_ENTRIES_DIR")
    else
        dirs=(
            /efi/loader/entries
            /boot/loader/entries
            /boot/efi/loader/entries
        )
    fi
    local d f
    declare -A seen=()
    for d in "${dirs[@]}"; do
        [[ -n "$d" && -d "$d" ]] || continue
        for f in "$d"/*.conf; do
            [[ -f "$f" ]] || continue
            local real_f
            real_f="$(realpath "$f" 2>/dev/null || printf '%s' "$f")"
            [[ -v seen[$real_f] ]] && continue
            seen[$real_f]=1
            printf '%s\n' "$f"
        done
    done
}

# Update kernel command line across UKI (/etc/kernel/cmdline), Type-1
# systemd-boot loader entries, or GRUB (/etc/default/grub), then rebuild and
# re-sign boot artifacts as needed.
apply_bootloader_cmdline() {
    local -a desired_tokens=("$@")
    local updated_any=false

    # 1. UKI profile (/etc/kernel/cmdline + mkinitcpio UKI preset)
    if [[ -f "$KERNEL_CMDLINE_FILE" ]] || has_uki_preset; then
        local existing="" updated_line tmp_cmd
        if [[ -f "$KERNEL_CMDLINE_FILE" ]]; then
            existing="$(tr '\n' ' ' < "$KERNEL_CMDLINE_FILE")"
        fi
        updated_line="$(transform_cmdline_string "$existing" "${desired_tokens[@]}")"
        install -d -m 0755 "$(dirname "$KERNEL_CMDLINE_FILE")"
        tmp_cmd="$(mktemp "${KERNEL_CMDLINE_FILE}.XXXXXX")"
        chmod 0600 "$tmp_cmd"
        printf '%s\n' "$updated_line" > "$tmp_cmd"
        mv -f "$tmp_cmd" "$KERNEL_CMDLINE_FILE"
        info "Updated UKI kernel command line in $KERNEL_CMDLINE_FILE"
        mkinitcpio -P
        if [[ -f "$SBCTL_DIR/GUID" || -d "$SBCTL_DIR/keys" ]] && command -v sbctl >/dev/null 2>&1; then
            info "Re-signing EFI binaries with sbctl..."
            sbctl sign-all
        fi
        warn_if_tpm_pcr_needs_rebind
        updated_any=true
    fi

    # 2. Type-1 systemd-boot loader entries (if present)
    local -a boot_entries=()
    local entry_file
    while IFS= read -r entry_file; do
        [[ -n "$entry_file" ]] && boot_entries+=("$entry_file")
    done < <(find_systemd_boot_entries)

    if (( ${#boot_entries[@]} > 0 )); then
        for entry_file in "${boot_entries[@]}"; do
            local tmp_entry
            tmp_entry="$(mktemp "${entry_file}.XXXXXX")"
            chmod 0644 "$tmp_entry"
            local had_options=false line
            while IFS= read -r line || [[ -n "$line" ]]; do
                if [[ "$line" =~ ^options([[:space:]]+(.*))?$ ]]; then
                    had_options=true
                    local new_opts
                    new_opts="$(transform_cmdline_string "${BASH_REMATCH[2]:-}" "${desired_tokens[@]}")"
                    if [[ -n "$new_opts" ]]; then
                        printf 'options %s\n' "$new_opts" >> "$tmp_entry"
                    else
                        printf 'options\n' >> "$tmp_entry"
                    fi
                else
                    printf '%s\n' "$line" >> "$tmp_entry"
                fi
            done < "$entry_file"
            if [[ "$had_options" == false && ${#desired_tokens[@]} -gt 0 ]]; then
                printf 'options %s\n' "${desired_tokens[*]}" >> "$tmp_entry"
            fi
            mv -f "$tmp_entry" "$entry_file"
            info "Updated systemd-boot entry: $entry_file"
        done
        if [[ "$updated_any" == false ]] && command -v mkinitcpio >/dev/null 2>&1; then
            mkinitcpio -P
        fi
        updated_any=true
    fi

    # 3. GRUB (/etc/default/grub)
    if [[ -f "$GRUB_DEFAULT_FILE" ]]; then
        local current_grub="" new_grub escaped_grub tmp_grub
        current_grub="$(awk '
            /^[[:space:]]*GRUB_CMDLINE_LINUX_DEFAULT=/ {
                line = $0
                sub(/^[[:space:]]*GRUB_CMDLINE_LINUX_DEFAULT=[[:space:]]*"?/, "", line)
                sub(/"?[[:space:]]*$/, "", line)
                print line
                exit
            }
        ' "$GRUB_DEFAULT_FILE")"
        new_grub="$(transform_cmdline_string "$current_grub" "${desired_tokens[@]}")"
        escaped_grub="${new_grub//\\/\\\\}"
        escaped_grub="${escaped_grub//\"/\\\"}"
        tmp_grub="$(mktemp "${GRUB_DEFAULT_FILE}.XXXXXX")"
        chmod 0644 "$tmp_grub"
        RENDERED="GRUB_CMDLINE_LINUX_DEFAULT=\"${escaped_grub}\"" awk '
            BEGIN { repl = ENVIRON["RENDERED"]; done_line = 0 }
            /^[[:space:]]*#?[[:space:]]*GRUB_CMDLINE_LINUX_DEFAULT=/ {
                if (!done_line) { print repl; done_line = 1 }
                next
            }
            { print }
            END { if (!done_line) print repl }
        ' "$GRUB_DEFAULT_FILE" > "$tmp_grub"
        mv -f "$tmp_grub" "$GRUB_DEFAULT_FILE"
        info "Updated GRUB_CMDLINE_LINUX_DEFAULT in $GRUB_DEFAULT_FILE"
        if [[ "$updated_any" == false ]] && command -v mkinitcpio >/dev/null 2>&1; then
            mkinitcpio -P
        fi
        if command -v grub-mkconfig >/dev/null 2>&1 && [[ -d "$(dirname "$GRUB_CFG_FILE")" ]]; then
            grub-mkconfig -o "$GRUB_CFG_FILE"
            chmod og-rwx "$GRUB_CFG_FILE" 2>/dev/null || true
        fi
        updated_any=true
    fi

    if [[ "$updated_any" == false ]]; then
        err "Could not detect UKI ($KERNEL_CMDLINE_FILE), systemd-boot entries, or GRUB ($GRUB_DEFAULT_FILE)."
    fi
}

warn_if_tpm_pcr_needs_rebind() {
    if [[ -r /etc/tpm_luks.conf ]] && grep -qE '(^|[^0-9])(4|9)([^0-9]|$)' /etc/tpm_luks.conf 2>/dev/null; then
        warn "TPM2 LUKS policy appears to include PCR 4 or 9; if UKI measurements are bound, re-run 'sudo awesome-secureboot bind-tpm' after verifying boot."
    fi
}

warn_if_module_sig_enforced() {
    local cmd=""
    [[ -r "$PROC_CMDLINE_FILE" ]] && cmd+=" $(<"$PROC_CMDLINE_FILE")"
    [[ -r "$KERNEL_CMDLINE_FILE" ]] && cmd+=" $(<"$KERNEL_CMDLINE_FILE")"
    if [[ "$cmd" == *"module.sig_enforce=1"* || "$cmd" == *"lockdown=integrity"* || "$cmd" == *"lockdown=confidentiality"* ]]; then
        warn "Kernel module signature enforcement or lockdown detected on cmdline; unsigned DKMS modules (gpu_unlock) will be rejected unless signed by a trusted kernel module key."
    fi
}

ensure_kernel_headers() {
    local -a header_pkgs=()
    local kpkg
    for kpkg in linux linux-lts linux-zen linux-hardened; do
        if pacman -Qq "$kpkg" >/dev/null 2>&1; then
            header_pkgs+=("${kpkg}-headers")
        fi
    done
    if (( ${#header_pkgs[@]} > 0 )); then
        info "Ensuring matching kernel headers are installed: ${header_pkgs[*]}"
        pacman -S --needed --noconfirm "${header_pkgs[@]}"
    fi
}

install_self_helper() {
    local self_path
    self_path="$(realpath "${BASH_SOURCE[0]}" 2>/dev/null || printf '%s' "${BASH_SOURCE[0]}")"
    if [[ -f "$self_path" && "$self_path" != "$INSTALLED_HELPER" ]]; then
        install -Dm0755 "$self_path" "$INSTALLED_HELPER"
    fi
    if [[ -x "$INSTALLED_HELPER" ]]; then
        install -d -m 0755 "$(dirname "$INSTALLED_SYMLINK")"
        ln -sfn "$INSTALLED_HELPER" "$INSTALLED_SYMLINK"
    fi
}

_GU_BUILD_WORKDIR=""
_GU_KEEP_CACHE="false"
_GU_TEMP_USER=""

cleanup_build() {
    trap - RETURN EXIT
    if [[ -n "${_GU_BUILD_WORKDIR:-}" && -d "${_GU_BUILD_WORKDIR}" ]]; then
        rm -rf -- "$_GU_BUILD_WORKDIR"
    fi
    if [[ "${_GU_KEEP_CACHE:-false}" != "true" && -n "${CACHE_ROOT:-}" && -d "${CACHE_ROOT}" ]]; then
        rm -rf -- "$CACHE_ROOT"
    fi
    if [[ -n "${_GU_TEMP_USER:-}" ]]; then
        userdel "$_GU_TEMP_USER" 2>/dev/null || true
    fi
    _GU_BUILD_WORKDIR=""
    _GU_TEMP_USER=""
}

build_and_install_packages() {
    local repo_url="$1"
    local git_ref="$2"
    local requested_user="$3"
    local keep_cache="$4"

    info "Installing build and DKMS dependencies..."
    pacman -S --needed --noconfirm base-devel dkms git python zstd openssl
    ensure_kernel_headers

    local build_user="$requested_user"
    _GU_KEEP_CACHE="$keep_cache"
    _GU_TEMP_USER=""

    if [[ -z "$build_user" && -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
        build_user="$SUDO_USER"
    fi

    if [[ -n "$build_user" ]]; then
        id -u "$build_user" >/dev/null 2>&1 || err "Specified build user '$build_user' does not exist."
        if getent group compilers >/dev/null 2>&1; then
            usermod -aG compilers "$build_user" 2>/dev/null || true
        fi
    else
        build_user="_awesome_gpubuild"
        if ! id -u "$build_user" >/dev/null 2>&1; then
            local -a extra_groups=()
            if getent group compilers >/dev/null 2>&1; then
                extra_groups=(-G compilers)
            fi
            useradd -r -M -d /nonexistent -s /usr/bin/nologin "${extra_groups[@]}" "$build_user"
            _GU_TEMP_USER="$build_user"
        fi
    fi

    install -d -m 0755 "$CACHE_ROOT"
    local src_cache="$CACHE_ROOT/sources"
    install -d -m 0755 "$src_cache"
    if command -v setfacl >/dev/null 2>&1; then
        setfacl -b -k "$CACHE_ROOT" "$src_cache" 2>/dev/null || true
    fi

    local workdir
    workdir="$(mktemp -d "$CACHE_ROOT/build.XXXXXX")"
    _GU_BUILD_WORKDIR="$workdir"
    trap cleanup_build RETURN EXIT

    if command -v setfacl >/dev/null 2>&1; then
        setfacl -b -k "$workdir" 2>/dev/null || true
    fi
    install -d -m 0700 -o "$build_user" -g "$(id -gn "$build_user")" \
        "$workdir/home" "$workdir/pkg"
    chown -hR "$build_user:$(id -gn "$build_user")" "$workdir" "$src_cache"

    info "Cloning gpu-unlock from $repo_url..."
    if [[ -n "$git_ref" ]]; then
        runuser -u "$build_user" -- env \
            HOME="$workdir/home" \
            GIT_TERMINAL_PROMPT=0 \
            GIT_CONFIG_COUNT=1 \
            GIT_CONFIG_KEY_0=protocol.file.allow \
            GIT_CONFIG_VALUE_0=always \
            git clone -- "$repo_url" "$workdir/repo"
        runuser -u "$build_user" -- env \
            HOME="$workdir/home" \
            git -C "$workdir/repo" checkout --detach "$git_ref"
    else
        runuser -u "$build_user" -- env \
            HOME="$workdir/home" \
            GIT_TERMINAL_PROMPT=0 \
            GIT_CONFIG_COUNT=1 \
            GIT_CONFIG_KEY_0=protocol.file.allow \
            GIT_CONFIG_VALUE_0=always \
            git clone --depth 1 -- "$repo_url" "$workdir/repo"
    fi

    [[ -f "$workdir/repo/packaging/arch/PKGBUILD" ]] || err "Cloned repository is missing packaging/arch/PKGBUILD"
    [[ -f "$workdir/repo/VERSION" ]] || err "Cloned repository is missing VERSION"

    info "Building gpu-unlock-firmware and gpu-unlock-dkms via makepkg (downloads & verifies pinned NVIDIA 610.43.03 assets)..."
    runuser -u "$build_user" -- bash -c '
        set -euo pipefail
        umask 022
        cd "$1/repo/packaging/arch"
        HOME="$1/home" \
        PKGDEST="$1/pkg" \
        SRCDEST="$2" \
        GIT_TERMINAL_PROMPT=0 \
        GIT_CONFIG_COUNT=1 \
        GIT_CONFIG_KEY_0=protocol.file.allow \
        GIT_CONFIG_VALUE_0=always \
        makepkg -f --noconfirm
    ' _ "$workdir" "$src_cache"

    local -a built_pkgs=()
    local pkg_file
    for pkg_file in "$workdir/pkg"/gpu-unlock-firmware-*.pkg.tar.* "$workdir/pkg"/gpu-unlock-dkms-*.pkg.tar.*; do
        [[ -f "$pkg_file" && "$pkg_file" != *.sig ]] || continue
        built_pkgs+=("$pkg_file")
    done
    (( ${#built_pkgs[@]} >= 2 )) || err "makepkg did not produce both gpu-unlock-firmware and gpu-unlock-dkms packages"

    info "Installing built packages with pacman -U..."
    pacman -U --noconfirm "${built_pkgs[@]}"

    # Verify DKMS built gpu_unlock for every installed kernel that has headers
    local kbuild kver built_count=0
    for kbuild in /usr/lib/modules/*/build; do
        [[ -d "$kbuild" ]] || continue
        kver="$(basename "$(dirname "$kbuild")")"
        if ! modinfo -k "$kver" gpu_unlock >/dev/null 2>&1; then
            info "Triggering dkms autoinstall for kernel $kver..."
            dkms autoinstall -k "$kver"
            depmod "$kver"
        fi
        modinfo -k "$kver" gpu_unlock >/dev/null 2>&1 || err "DKMS module gpu_unlock failed to build for kernel $kver"
        (( ++built_count ))
    done
    if (( built_count == 0 )); then
        warn "No /usr/lib/modules/*/build headers directory found; install matching linux-headers so DKMS can build gpu_unlock."
    else
        ok "Verified gpu_unlock DKMS module across $built_count installed kernel(s)."
    fi

    cleanup_build
}

show_status() {
    printf '=== Zagitta/gpu-unlock Status ===\n'

    local -a gpu_lines=()
    local line
    while IFS= read -r line; do
        [[ -n "$line" ]] && gpu_lines+=("$line")
    done < <(scan_nvidia_gpus)

    if (( ${#gpu_lines[@]} == 0 )); then
        printf 'Detected NVIDIA GPUs: none\n'
    else
        printf 'Detected NVIDIA GPUs:\n'
        local bdf dev_id tier family driver model
        for line in "${gpu_lines[@]}"; do
            IFS='|' read -r bdf dev_id tier family driver model <<< "$line"
            printf '  - %s [10de:%s] %s\n    Support: %s (%s) | Bound driver: %s\n' \
                "$bdf" "$dev_id" "$model" "$tier" "$family" "$driver"
        done
    fi

    printf '\nPackages:\n'
    local pkg ver
    for pkg in gpu-unlock-dkms gpu-unlock-firmware; do
        if command -v pacman >/dev/null 2>&1 && ver="$(pacman -Q "$pkg" 2>/dev/null)"; then
            printf '  - %s: installed (%s)\n' "$pkg" "$ver"
        else
            printf '  - %s: not installed\n' "$pkg"
        fi
    done

    printf '\nInitramfs & DKMS:\n'
    if [[ -f "$MKINITCPIO_DROPIN" ]]; then
        printf '  - mkinitcpio drop-in: present (%s)\n' "$MKINITCPIO_DROPIN"
    else
        printf '  - mkinitcpio drop-in: absent\n'
    fi
    local kbuild kver any_k=false
    for kbuild in /usr/lib/modules/*/build; do
        [[ -d "$kbuild" ]] || continue
        any_k=true
        kver="$(basename "$(dirname "$kbuild")")"
        if modinfo -k "$kver" gpu_unlock >/dev/null 2>&1; then
            printf '  - kernel %s: gpu_unlock module built\n' "$kver"
        else
            printf '  - kernel %s: gpu_unlock module NOT built\n' "$kver"
        fi
    done
    [[ "$any_k" == false ]] && printf '  - kernel headers: none found under /usr/lib/modules/*/build\n'

    printf '\nKernel Command Line:\n'
    if [[ -r "$PROC_CMDLINE_FILE" ]]; then
        local active_tok="" tok
        for tok in $(<"$PROC_CMDLINE_FILE"); do
            [[ "$tok" == gpu_unlock.* ]] && active_tok+="${active_tok:+ }$tok"
        done
        printf '  - Active (/proc/cmdline): %s\n' "${active_tok:-none (module inactive until reboot with gpu_unlock.targets=...)}"
    fi
    if [[ -r "$KERNEL_CMDLINE_FILE" ]]; then
        local uki_tok="" tok
        for tok in $(<"$KERNEL_CMDLINE_FILE"); do
            [[ "$tok" == gpu_unlock.* ]] && uki_tok+="${uki_tok:+ }$tok"
        done
        printf '  - Configured UKI (%s): %s\n' "$KERNEL_CMDLINE_FILE" "${uki_tok:-none}"
    elif [[ -e "$KERNEL_CMDLINE_FILE" ]]; then
        printf '  - Configured UKI (%s): present (run with sudo to read mode 0600 file)\n' "$KERNEL_CMDLINE_FILE"
    fi
    if [[ -r "$GRUB_DEFAULT_FILE" ]]; then
        local grub_line=""
        grub_line="$(grep -E '^[[:space:]]*GRUB_CMDLINE_LINUX_DEFAULT=' "$GRUB_DEFAULT_FILE" 2>/dev/null || true)"
        if [[ -n "$grub_line" ]]; then
            printf '  - Configured GRUB (%s): %s\n' "$GRUB_DEFAULT_FILE" "$grub_line"
        fi
    fi

    if ! in_chroot && command -v journalctl >/dev/null 2>&1; then
        local klog=""
        klog="$(journalctl -k -b --no-pager 2>/dev/null | grep -i 'gpu_unlock' | tail -n 5 || true)"
        if [[ -n "$klog" ]]; then
            printf '\nRecent kernel log (gpu_unlock):\n%s\n' "$klog"
        fi
    fi
}

main() {
    local mode="status"
    local targets="all"
    local no_resume_unlock=false
    local disable_dynamic_pm=false
    local repo_url="$DEFAULT_REPO_URL"
    local git_ref=""
    local build_user=""
    local no_bootloader=false
    local keep_cache=false
    local assume_yes=false

    while (( $# > 0 )); do
        case "$1" in
            --status)
                mode="status"
                shift
                ;;
            --install)
                mode="install"
                shift
                ;;
            --set-targets)
                [[ $# -ge 2 && -n "${2:-}" ]] || err "--set-targets requires a value ('all' or PCI BDF list)"
                mode="set-targets"
                targets="$2"
                shift 2
                ;;
            --disable)
                mode="disable"
                shift
                ;;
            --uninstall)
                mode="uninstall"
                shift
                ;;
            --targets)
                [[ $# -ge 2 && -n "${2:-}" ]] || err "--targets requires a value ('all' or PCI BDF list)"
                targets="$2"
                shift 2
                ;;
            --no-resume-unlock)
                no_resume_unlock=true
                shift
                ;;
            --disable-dynamic-pm)
                disable_dynamic_pm=true
                shift
                ;;
            --repo-url)
                [[ $# -ge 2 && -n "${2:-}" ]] || err "--repo-url requires a URL"
                repo_url="$2"
                shift 2
                ;;
            --ref)
                [[ $# -ge 2 && -n "${2:-}" ]] || err "--ref requires a Git tag, branch, or commit"
                git_ref="$2"
                shift 2
                ;;
            --build-user)
                [[ $# -ge 2 && -n "${2:-}" ]] || err "--build-user requires a username"
                build_user="$2"
                shift 2
                ;;
            --no-bootloader)
                no_bootloader=true
                shift
                ;;
            --keep-cache)
                keep_cache=true
                shift
                ;;
            -y|--yes)
                assume_yes=true
                shift
                ;;
            -h|--help)
                usage
                return 0
                ;;
            *)
                err "Unknown argument: $1 (see --help)"
                ;;
        esac
    done

    case "$mode" in
        status)
            show_status
            ;;
        install)
            require_root
            validate_targets "$targets" || err "Invalid --targets '$targets'. Expected 'all' or comma-separated PCI BDFs (e.g. 0000:01:00.0)."
            warn_if_module_sig_enforced

            if [[ "$assume_yes" != "true" && "$no_bootloader" != "true" && -t 0 ]]; then
                local reply=""
                read -r -p "Build and install Zagitta/gpu-unlock with gpu_unlock.targets=${targets}? [y/N]: " reply
                [[ "$reply" =~ ^[Yy]$ ]] || { info "Cancelled."; return 0; }
            fi

            build_and_install_packages "$repo_url" "$git_ref" "$build_user" "$keep_cache"
            install_self_helper

            if [[ "$disable_dynamic_pm" == "true" ]]; then
                install -d -m 0755 "$(dirname "$MODPROBE_PM_CONF")"
                printf '# Prevent laptop dGPU runtime D3cold from resetting gpu_unlock tensor selectors\noptions nvidia NVreg_DynamicPowerManagement=0x00\n' > "$MODPROBE_PM_CONF"
                chmod 0644 "$MODPROBE_PM_CONF"
                info "Wrote $MODPROBE_PM_CONF"
            elif is_laptop_chassis; then
                warn "Laptop/portable chassis detected: if your dGPU powers off when idle, re-run with --disable-dynamic-pm to keep tensor-core unlock persistent."
            fi

            if [[ "$no_bootloader" == "true" ]]; then
                ok "Installed gpu-unlock packages and DKMS module (--no-bootloader; caller owns cmdline & boot image generation)."
            else
                local -a tokens=("gpu_unlock.targets=${targets}")
                [[ "$no_resume_unlock" == "true" ]] && tokens+=("gpu_unlock.resume=0")
                apply_bootloader_cmdline "${tokens[@]}"
                ok "gpu-unlock installed and configured (${tokens[*]}). Reboot to activate."
            fi
            ;;
        set-targets)
            require_root
            validate_targets "$targets" || err "Invalid targets '$targets'. Expected 'all' or comma-separated PCI BDFs (e.g. 0000:01:00.0)."
            local -a tokens=("gpu_unlock.targets=${targets}")
            [[ "$no_resume_unlock" == "true" ]] && tokens+=("gpu_unlock.resume=0")
            apply_bootloader_cmdline "${tokens[@]}"
            ok "Updated kernel command line (${tokens[*]}). Reboot to apply."
            ;;
        disable)
            require_root
            apply_bootloader_cmdline
            ok "Removed gpu_unlock.* from kernel command line (packages remain installed). Reboot to apply."
            ;;
        uninstall)
            require_root
            local -a remove_pkgs=()
            local pkg
            for pkg in gpu-unlock-dkms gpu-unlock-firmware; do
                if pacman -Qq "$pkg" >/dev/null 2>&1; then
                    remove_pkgs+=("$pkg")
                fi
            done
            if (( ${#remove_pkgs[@]} > 0 )); then
                info "Removing packages: ${remove_pkgs[*]}"
                pacman -Rns --noconfirm "${remove_pkgs[@]}"
            fi
            rm -f -- "$MODPROBE_PM_CONF"
            if [[ "$no_bootloader" != "true" ]]; then
                apply_bootloader_cmdline
            fi
            ok "Uninstalled gpu-unlock and cleaned kernel command line."
            ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
