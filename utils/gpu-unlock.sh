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
# Commit of DEFAULT_REPO_URL that is built when --ref is not given, so an
# unattended install never builds whatever upstream's default branch holds at
# that moment. Review upstream's diff before moving this pin.
DEFAULT_REPO_REF="7eb51bccae0a0b7e599e084d971170e9a1e82d0c"
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
TPM_LUKS_CONF="${GPU_UNLOCK_TPM_LUKS_CONF:-/etc/tpm_luks.conf}"
SECUREBOOT_CONF="${GPU_UNLOCK_SECUREBOOT_CONF:-/etc/awesome-secureboot.conf}"
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
  --disable                 Remove gpu_unlock.* parameters from kernel cmdline and the
                            dynamic-PM override (keep packages installed)
  --uninstall               Remove kernel cmdline parameters, uninstall packages, and refresh boot images
  -h, --help                Show this help

Options:
  --targets TARGETS         'all' (default) or comma-separated PCI BDFs (e.g. 0000:01:00.0,0000:21:00.0)
  --no-resume-unlock        Also set gpu_unlock.resume=0 on the kernel command line
  --disable-dynamic-pm      Write NVreg_DynamicPowerManagement=0x00 for laptop dGPUs
                            (with --install or --set-targets)
  --repo-url URL            Upstream Git repository URL (default: https://github.com/Zagitta/gpu-unlock.git)
  --ref REF                 Git tag, branch, or commit SHA to build (default: the commit
                            pinned in this script for the default repository)
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

# Kernel parameters in /etc/kernel/cmdline: everything except comment lines,
# which mkinitcpio also leaves out of the UKI.
kernel_cmdline_content() {
    [[ -r "$KERNEL_CMDLINE_FILE" ]] || return 0
    grep -v '^[[:space:]]*#' "$KERNEL_CMDLINE_FILE" || true
}

_GU_LAST_BACKUP=""
_GU_CMDLINE_STATUS=""

# Move TMP over FILE unless both are identical. A changed FILE is first copied
# to FILE.bak.<timestamp>; _GU_LAST_BACKUP names that copy (empty: no change).
replace_if_changed() {
    local tmp="$1" file="$2"
    _GU_LAST_BACKUP=""
    if cmp -s -- "$tmp" "$file"; then
        rm -f -- "$tmp"
        return 0
    fi
    _GU_LAST_BACKUP="${file}.bak.$(date +%Y%m%d%H%M%S)"
    cp -p -- "$file" "$_GU_LAST_BACKUP"
    mv -f -- "$tmp" "$file"
}

restore_backup() {
    local backup="$1" file="$2"
    [[ -n "$backup" && -f "$backup" ]] || return 0
    cp -p -- "$backup" "$file"
    warn "Restored $file from $backup"
}

# Add or remove gpu_unlock.* tokens in /etc/kernel/cmdline and report the
# outcome in _GU_CMDLINE_STATUS (updated | unchanged | refused).
#  - Comment lines stay untouched. Folding them into the parameter line would
#    turn the whole command line into a comment and mkinitcpio would build a
#    UKI without root=.
#  - New tokens are appended to the last parameter line. Without such a line
#    (file missing, empty or comments only) nothing is written: a file holding
#    only our tokens would replace mkinitcpio's other command line sources
#    (/etc/cmdline.d/*.conf, /proc/cmdline) and likewise drop root=.
update_kernel_cmdline_file() {
    local -a desired_tokens=("$@")
    local -a lines=() out=()
    local line last_content=-1 tmp_cmd

    _GU_LAST_BACKUP=""
    _GU_CMDLINE_STATUS="unchanged"
    if [[ -f "$KERNEL_CMDLINE_FILE" ]]; then
        mapfile -t lines < "$KERNEL_CMDLINE_FILE"
    fi
    for line in "${lines[@]}"; do
        if [[ ! "$line" =~ ^[[:space:]]*(#|$) ]]; then
            if [[ "$line" == *gpu_unlock.* ]]; then
                line="$(transform_cmdline_string "$line")"
                # A line that only held our tokens disappears again.
                [[ -n "$line" ]] || continue
            fi
            last_content=${#out[@]}
        fi
        out+=("$line")
    done

    if (( ${#desired_tokens[@]} > 0 )); then
        if (( last_content < 0 )); then
            _GU_CMDLINE_STATUS="refused"
            return 0
        fi
        out[last_content]="$(transform_cmdline_string "${out[last_content]}" "${desired_tokens[@]}")"
    fi
    [[ -f "$KERNEL_CMDLINE_FILE" ]] || return 0

    tmp_cmd="$(mktemp "${KERNEL_CMDLINE_FILE}.XXXXXX")"
    chmod 0600 "$tmp_cmd"
    if (( ${#out[@]} > 0 )); then
        printf '%s\n' "${out[@]}" > "$tmp_cmd"
    fi
    replace_if_changed "$tmp_cmd" "$KERNEL_CMDLINE_FILE"
    [[ -z "$_GU_LAST_BACKUP" ]] || _GU_CMDLINE_STATUS="updated"
}

# Write SRC (/etc/default/grub) to DST with the gpu_unlock.* tokens of
# GRUB_CMDLINE_LINUX_DEFAULT replaced by the given ones, without re-quoting
# what the admin wrote: old tokens are removed textually from every active
# assignment, and the new ones go in front of the closing quote of the last
# assignment. A value that is not one plain "..." or '...' string (optionally
# followed by a comment) is left alone and extended by a single managed line,
# which grub-mkconfig evaluates like any other shell assignment.
render_grub_default() {
    local src="$1" dst="$2"
    shift 2
    local tokens="$*"
    local marker="# awesome-gpu-unlock"
    local token_re='gpu_unlock\.(targets|resume)=[0-9A-Za-z:.,]*'
    local -a lines=()
    local line last=-1

    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ "$line" =~ ^[[:space:]]*GRUB_CMDLINE_LINUX_DEFAULT= ]]; then
            [[ "$line" != *"$marker" ]] || continue
            if [[ "$line" == *gpu_unlock.* ]]; then
                line="$(sed -E "s/[[:space:]]+${token_re}//g; s/([\"'=])${token_re}[[:space:]]*/\\1/g" <<<"$line")"
            fi
            last=${#lines[@]}
        fi
        lines+=("$line")
    done < "$src"

    local managed=""
    if [[ -n "$tokens" ]]; then
        managed="GRUB_CMDLINE_LINUX_DEFAULT=\"\${GRUB_CMDLINE_LINUX_DEFAULT} ${tokens}\" ${marker}"
        if (( last >= 0 )); then
            local prefix value quote body rest ch
            local i esc=0 close=-1
            line="${lines[last]}"
            prefix="${line%%=*}="
            value="${line#*=}"
            quote="${value:0:1}"
            if [[ "$quote" == '"' || "$quote" == "'" ]]; then
                for (( i = 1; i < ${#value}; i++ )); do
                    ch="${value:i:1}"
                    if (( esc )); then
                        esc=0
                    elif [[ "$quote" == '"' && "$ch" == '\' ]]; then
                        esc=1
                    elif [[ "$ch" == "$quote" ]]; then
                        close=$i
                        break
                    fi
                done
            fi
            if (( close > 0 )); then
                body="${value:1:close-1}"
                rest="${value:close+1}"
                if [[ "$rest" =~ ^[[:space:]]*(#.*)?$ ]]; then
                    [[ -z "$body" || "$body" == *[[:space:]] ]] || body+=" "
                    lines[last]="${prefix}${quote}${body}${tokens}${quote}${rest}"
                    managed=""
                fi
            fi
        fi
    fi

    : > "$dst"
    if (( ${#lines[@]} > 0 )); then
        printf '%s\n' "${lines[@]}" >> "$dst"
    fi
    if [[ -n "$managed" ]]; then
        printf '%s\n' "$managed" >> "$dst"
    fi
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
    local uki_refused=false

    # 1. UKI profile (/etc/kernel/cmdline + mkinitcpio UKI preset)
    if [[ -f "$KERNEL_CMDLINE_FILE" ]] || has_uki_preset; then
        update_kernel_cmdline_file "${desired_tokens[@]}"
        if [[ "$_GU_CMDLINE_STATUS" == "refused" ]]; then
            uki_refused=true
            warn "$KERNEL_CMDLINE_FILE has no kernel parameter line to extend; it was left untouched and no UKI was rebuilt."
        else
            local cmdline_backup="$_GU_LAST_BACKUP" rebuild_ok=true
            if [[ -n "$cmdline_backup" ]]; then
                info "Updated UKI kernel command line in $KERNEL_CMDLINE_FILE (previous version: $cmdline_backup)"
            fi
            mkinitcpio -P || rebuild_ok=false
            if [[ "$rebuild_ok" == true ]] && [[ -f "$SBCTL_DIR/GUID" || -d "$SBCTL_DIR/keys" ]] && command -v sbctl >/dev/null 2>&1; then
                info "Re-signing EFI binaries with sbctl..."
                sbctl sign-all || rebuild_ok=false
            fi
            if [[ "$rebuild_ok" != true ]]; then
                restore_backup "$cmdline_backup" "$KERNEL_CMDLINE_FILE"
                err "Rebuilding or signing the UKI failed. Boot images may be partly rebuilt: fix the error above and run 'mkinitcpio -P' before rebooting."
            fi
            warn_if_tpm_pcr_needs_rebind
            updated_any=true
        fi
    fi

    # 2. Type-1 systemd-boot loader entries (if present)
    local -a boot_entries=()
    local entry_file
    while IFS= read -r entry_file; do
        [[ -n "$entry_file" ]] && boot_entries+=("$entry_file")
    done < <(find_systemd_boot_entries)

    local linux_entries=0
    for entry_file in "${boot_entries[@]}"; do
        # Only Linux entries take kernel parameters. Windows, EFI shell and
        # other "efi" entries are not ours to edit.
        grep -qE '^[[:space:]]*(linux|uki)[[:space:]]' "$entry_file" || continue
        (( ++linux_entries ))

        local -a entry_lines=() entry_out=()
        local line new_opts tmp_entry last_options=-1
        mapfile -t entry_lines < "$entry_file"
        for line in "${entry_lines[@]}"; do
            if [[ "$line" =~ ^options([[:space:]]+(.*))?$ ]]; then
                new_opts="$(transform_cmdline_string "${BASH_REMATCH[2]:-}")"
                # An options line that only held our tokens disappears again,
                # so --disable restores the entry instead of leaving "options".
                [[ -n "$new_opts" ]] || continue
                last_options=${#entry_out[@]}
                entry_out+=("options $new_opts")
            else
                entry_out+=("$line")
            fi
        done
        # systemd-boot concatenates all options lines: add the tokens once.
        if (( ${#desired_tokens[@]} > 0 )); then
            if (( last_options >= 0 )); then
                entry_out[last_options]+=" ${desired_tokens[*]}"
            else
                entry_out+=("options ${desired_tokens[*]}")
            fi
        fi

        tmp_entry="$(mktemp "${entry_file}.XXXXXX")"
        chmod 0644 "$tmp_entry"
        printf '%s\n' "${entry_out[@]}" > "$tmp_entry"
        replace_if_changed "$tmp_entry" "$entry_file"
        if [[ -n "$_GU_LAST_BACKUP" ]]; then
            info "Updated systemd-boot entry: $entry_file (previous version: $_GU_LAST_BACKUP)"
        fi
    done
    if (( linux_entries > 0 )); then
        if [[ "$updated_any" == false ]] && command -v mkinitcpio >/dev/null 2>&1; then
            mkinitcpio -P
        fi
        updated_any=true
    fi

    # 3. GRUB (/etc/default/grub)
    if [[ -f "$GRUB_DEFAULT_FILE" ]]; then
        local tmp_grub grub_backup
        tmp_grub="$(mktemp "${GRUB_DEFAULT_FILE}.XXXXXX")"
        chmod --reference="$GRUB_DEFAULT_FILE" "$tmp_grub"
        render_grub_default "$GRUB_DEFAULT_FILE" "$tmp_grub" "${desired_tokens[@]}"
        replace_if_changed "$tmp_grub" "$GRUB_DEFAULT_FILE"
        grub_backup="$_GU_LAST_BACKUP"
        if [[ -n "$grub_backup" ]]; then
            info "Updated GRUB_CMDLINE_LINUX_DEFAULT in $GRUB_DEFAULT_FILE (previous version: $grub_backup)"
        fi
        if [[ "$updated_any" == false ]] && command -v mkinitcpio >/dev/null 2>&1; then
            mkinitcpio -P
        fi
        if command -v grub-mkconfig >/dev/null 2>&1 && [[ -d "$(dirname "$GRUB_CFG_FILE")" ]]; then
            if ! grub-mkconfig -o "$GRUB_CFG_FILE"; then
                restore_backup "$grub_backup" "$GRUB_DEFAULT_FILE"
                err "grub-mkconfig failed; $GRUB_CFG_FILE was not regenerated."
            fi
            chmod og-rwx "$GRUB_CFG_FILE" 2>/dev/null || true
        fi
        updated_any=true
    fi

    if [[ "$updated_any" == false ]]; then
        if [[ "$uki_refused" == true ]]; then
            err "Nothing was changed. Add '${desired_tokens[*]}' to your kernel command line yourself (next to root=... in $KERNEL_CMDLINE_FILE or /etc/cmdline.d/) and run 'mkinitcpio -P'."
        fi
        err "Could not detect UKI ($KERNEL_CMDLINE_FILE), systemd-boot entries, or GRUB ($GRUB_DEFAULT_FILE)."
    fi
}

# Print the PCR indexes named by TPM2_PCRS= in the installer's TPM settings,
# one per line (only that key: other lines hold UUIDs full of digits).
configured_tpm_pcrs() {
    local file line value
    for file in "$TPM_LUKS_CONF" "$SECUREBOOT_CONF"; do
        [[ -r "$file" ]] || continue
        while IFS= read -r line || [[ -n "$line" ]]; do
            [[ "$line" =~ ^[[:space:]]*(export[[:space:]]+)?TPM2_PCRS=(.*)$ ]] || continue
            value="${BASH_REMATCH[2]}"
            value="${value//[\"\']/}"
            tr -s '+, \t' '\n' <<<"$value"
        done < "$file"
    done
}

# PCR 4 (boot loader / UKI image), 9 (kernel and initrd) and 11/12 (UKI
# sections, kernel command line) change when the UKI is rebuilt.
warn_if_tpm_pcr_needs_rebind() {
    local pcr
    while IFS= read -r pcr; do
        case "$pcr" in
            4|9|11|12)
                warn "TPM2 LUKS policy is bound to PCR ${pcr}, which the rebuilt UKI changes: expect a passphrase prompt on next boot, then re-run 'sudo awesome-secureboot bind-tpm'."
                return 0
                ;;
        esac
    done < <(configured_tpm_pcrs)
}

warn_if_module_sig_enforced() {
    local cmd=""
    [[ -r "$PROC_CMDLINE_FILE" ]] && cmd+=" $(<"$PROC_CMDLINE_FILE")"
    cmd+=" $(kernel_cmdline_content)"
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

    # Compiler access is restricted to the 'compilers' group on hardened
    # installs. Grant it to this build only (runuser --supp-group) instead of
    # permanently adding an existing account to the group.
    local -a run_as=(runuser -u "$build_user")
    if getent group compilers >/dev/null 2>&1 && [[ " $(id -nG "$build_user") " != *" compilers "* ]]; then
        run_as+=(-g "$(id -gn "$build_user")" -G compilers)
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

    if [[ -z "$git_ref" && "$repo_url" == "$DEFAULT_REPO_URL" ]]; then
        git_ref="$DEFAULT_REPO_REF"
    fi

    info "Cloning gpu-unlock from $repo_url..."
    if [[ -n "$git_ref" ]]; then
        "${run_as[@]}" -- env \
            HOME="$workdir/home" \
            GIT_TERMINAL_PROMPT=0 \
            GIT_CONFIG_COUNT=1 \
            GIT_CONFIG_KEY_0=protocol.file.allow \
            GIT_CONFIG_VALUE_0=always \
            git clone -- "$repo_url" "$workdir/repo"
        "${run_as[@]}" -- env \
            HOME="$workdir/home" \
            git -C "$workdir/repo" checkout --detach "$git_ref"
    else
        warn "No --ref given for $repo_url: building the current tip of its default branch (not pinned)."
        "${run_as[@]}" -- env \
            HOME="$workdir/home" \
            GIT_TERMINAL_PROMPT=0 \
            GIT_CONFIG_COUNT=1 \
            GIT_CONFIG_KEY_0=protocol.file.allow \
            GIT_CONFIG_VALUE_0=always \
            git clone --depth 1 -- "$repo_url" "$workdir/repo"
    fi

    local head_commit
    head_commit="$("${run_as[@]}" -- env HOME="$workdir/home" git -C "$workdir/repo" rev-parse HEAD)"
    if [[ "$git_ref" =~ ^[0-9a-fA-F]{40}$ && "${head_commit,,}" != "${git_ref,,}" ]]; then
        err "Checked-out commit $head_commit does not match the requested commit $git_ref"
    fi
    info "Building gpu-unlock at commit $head_commit"

    [[ -f "$workdir/repo/packaging/arch/PKGBUILD" ]] || err "Cloned repository is missing packaging/arch/PKGBUILD"
    [[ -f "$workdir/repo/VERSION" ]] || err "Cloned repository is missing VERSION"

    info "Building gpu-unlock-firmware and gpu-unlock-dkms via makepkg (downloads & verifies pinned NVIDIA 610.43.03 assets)..."
    "${run_as[@]}" -- bash -c '
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
        for tok in $(kernel_cmdline_content); do
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

write_dynamic_pm_conf() {
    install -d -m 0755 "$(dirname "$MODPROBE_PM_CONF")"
    printf '# Prevent laptop dGPU runtime D3cold from resetting gpu_unlock tensor selectors\noptions nvidia NVreg_DynamicPowerManagement=0x00\n' > "$MODPROBE_PM_CONF"
    chmod 0644 "$MODPROBE_PM_CONF"
    info "Wrote $MODPROBE_PM_CONF"
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
                write_dynamic_pm_conf
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
            if [[ "$disable_dynamic_pm" == "true" ]]; then
                write_dynamic_pm_conf
            fi
            apply_bootloader_cmdline "${tokens[@]}"
            ok "Updated kernel command line (${tokens[*]}). Reboot to apply."
            ;;
        disable)
            require_root
            if [[ -f "$MODPROBE_PM_CONF" ]]; then
                rm -f -- "$MODPROBE_PM_CONF"
                info "Removed $MODPROBE_PM_CONF (NVIDIA dynamic power management is back to its default)"
            fi
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
