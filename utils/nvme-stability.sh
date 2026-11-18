#!/usr/bin/env bash
# =============================================================================
# Script:      nvme-stability.sh
# Description: Opt-in NVMe dropout workaround for this project's signed linux
#              UKIs. Builds staged UKIs with APST/ASPM power-management
#              workarounds, signs and verifies them under sbctl's Landlock
#              sandbox, and atomically updates /efi with automatic rollback.
#
# Usage:       ./nvme-stability.sh [--status | --apply | --restore BACKUP]
# =============================================================================

set -euo pipefail

CMDLINE_FILE="${NVME_STABILITY_CMDLINE:-/etc/kernel/cmdline}"
PRESET_FILE="${NVME_STABILITY_PRESET:-/etc/mkinitcpio.d/linux.preset}"
ESP_DIR="${NVME_STABILITY_ESP:-/efi}"
STATE_DIR="${NVME_STABILITY_STATE:-/var/lib/awesomearchlinux/nvme-stability}"
LEGACY_STATE_DIR="/var/lib/awesomearch/nvme-stability"
LOCK_FILE="${NVME_STABILITY_LOCK:-/run/awesome-nvme-stability.lock}"
PROC_CMDLINE="${NVME_STABILITY_PROC_CMDLINE:-/proc/cmdline}"
HWMON_DIR="${NVME_STABILITY_HWMON_DIR:-/sys/class/hwmon}"

if [[ -n "${NVME_STABILITY_IMAGES:-}" ]]; then
    IFS=':' read -r -a UKI_IMAGES <<< "$NVME_STABILITY_IMAGES"
else
    UKI_IMAGES=(
        "${ESP_DIR}/EFI/Linux/arch-linux.efi"
        "${ESP_DIR}/EFI/Linux/arch-linux-fallback.efi"
    )
fi

readonly -a WORKAROUND_PARAMS=(
    "nvme_core.default_ps_max_latency_us=0"
    "pcie_aspm=off"
    "pcie_port_pm=off"
)

die() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
Usage: nvme-stability.sh [--status | --apply | --restore BACKUP] [-h|--help]

Opt-in NVMe dropout workaround for this project's signed linux UKIs.

Options:
  --status          Read-only status (default)
  --apply           Build, sign, verify, and install the workaround UKIs
  --restore BACKUP  Restore a saved command line from a backup directory
  -h, --help        Show this help message
EOF
}

run_cmd() {
    "$@"
}

# Parse kernel command line text intoCMDLINE_TOKENS array, preserving "..."
# spans and backslashes without shell evaluation. Returns non-zero on invalid
# syntax (unclosed quotes or NUL bytes).
declare -a CMDLINE_TOKENS=()

tokenize_cmdline() {
    local text="$1"
    CMDLINE_TOKENS=()

    local line trimmed joined=""
    while IFS= read -r line || [[ -n "$line" ]]; do
        trimmed="${line#"${line%%[![:space:]]*}"}"
        [[ "$trimmed" == \#* ]] && continue
        if [[ -n "$joined" ]]; then
            joined+=" $line"
        else
            joined="$line"
        fi
    done <<< "$text"

    local quotes_only="${joined//[^\"]/}"
    if (( ${#quotes_only} % 2 != 0 )); then
        printf 'Error: Invalid kernel command line (unclosed quote)\n' >&2
        return 1
    fi

    local len=${#joined} i=0 ch in_quote=0 cur="" has_tok=0
    while (( i < len )); do
        ch="${joined:i:1}"
        if (( in_quote )); then
            cur+="$ch"
            if [[ "$ch" == '"' ]]; then
                in_quote=0
            fi
        else
            case "$ch" in
                '"')
                    cur+="$ch"
                    in_quote=1
                    has_tok=1
                    ;;
                [[:space:]])
                    if (( has_tok )); then
                        CMDLINE_TOKENS+=("$cur")
                        cur=""
                        has_tok=0
                    fi
                    ;;
                *)
                    cur+="$ch"
                    has_tok=1
                    ;;
            esac
        fi
        (( i += 1 ))
    done
    if (( has_tok )); then
        CMDLINE_TOKENS+=("$cur")
    fi
    return 0
}

read_text_no_nul() {
    local file="$1"
    [[ -f "$file" ]] || { printf 'Error: Missing file: %s\n' "$file" >&2; return 1; }
    local byte_count char_content
    byte_count="$(wc -c < "$file")"
    byte_count="${byte_count//[[:space:]]/}"
    char_content="$(cat -- "$file"; printf 'x')"
    char_content="${char_content%x}"
    local actual_bytes
    actual_bytes="$(printf '%s' "$char_content" | wc -c)"
    actual_bytes="${actual_bytes//[[:space:]]/}"
    if [[ "$byte_count" != "$actual_bytes" ]]; then
        printf 'Error: Invalid kernel command line (NUL byte)\n' >&2
        return 1
    fi
    printf '%s' "$char_content"
}

with_workaround() {
    local text="$1"
    tokenize_cmdline "$text" || return 1

    local tok has_root=false key norm_key
    local -a kept=()
    for tok in "${CMDLINE_TOKENS[@]}"; do
        if [[ "$tok" == "--" ]]; then
            printf 'Error: Command lines containing an init argument separator are unsupported\n' >&2
            return 1
        fi
        if [[ "$tok" == root=* ]]; then
            has_root=true
        fi
        key="${tok%%=*}"
        norm_key="${key//-/_}"
        case "$norm_key" in
            nvme_core.default_ps_max_latency_us|pcie_aspm|pcie_port_pm)
                continue
                ;;
            *)
                kept+=("$tok")
                ;;
        esac
    done

    if [[ "$has_root" == false ]]; then
        printf 'Error: Refusing to change a command line without root=\n' >&2
        return 1
    fi

    kept+=("${WORKAROUND_PARAMS[@]}")
    printf '%s\n' "${kept[*]}"
}

tokens_equal() {
    local a="$1" b="$2"
    tokenize_cmdline "$a" || return 1
    local -a tok_a=("${CMDLINE_TOKENS[@]}")
    tokenize_cmdline "$b" || return 1
    local -a tok_b=("${CMDLINE_TOKENS[@]}")

    (( ${#tok_a[@]} == ${#tok_b[@]} )) || return 1
    local idx
    for idx in "${!tok_a[@]}"; do
        [[ "${tok_a[idx]}" == "${tok_b[idx]}" ]] || return 1
    done
    return 0
}

# Read only the PE section table and .cmdline section via coreutils od + dd.
embedded_cmdline() {
    local path="$1"
    [[ -f "$path" ]] || { printf '%s: missing file\n' "$path" >&2; return 1; }

    local file_size
    file_size="$(stat -c '%s' -- "$path")" || return 1
    if (( file_size < 64 )); then
        printf '%s: not a PE image\n' "$path" >&2
        return 1
    fi

    local mz
    mz="$(od -An -tx1 -j 0 -N 2 -- "$path" | tr -d ' \n')"
    if [[ "$mz" != "4d5a" ]]; then
        printf '%s: not a PE image\n' "$path" >&2
        return 1
    fi

    local pe_off
    pe_off="$(od -An -tu4 --endian=little -j 60 -N 4 -- "$path" | tr -d ' \n')"
    [[ "$pe_off" =~ ^[0-9]+$ ]] || { printf '%s: invalid PE offset\n' "$path" >&2; return 1; }
    if (( pe_off + 24 > file_size )); then
        printf '%s: invalid PE signature\n' "$path" >&2
        return 1
    fi

    local pe_sig
    pe_sig="$(od -An -tx1 -j "$pe_off" -N 4 -- "$path" | tr -d ' \n')"
    if [[ "$pe_sig" != "50450000" ]]; then
        printf '%s: invalid PE signature\n' "$path" >&2
        return 1
    fi

    local count opt_size
    count="$(od -An -tu2 --endian=little -j $(( pe_off + 6 )) -N 2 -- "$path" | tr -d ' \n')"
    opt_size="$(od -An -tu2 --endian=little -j $(( pe_off + 20 )) -N 2 -- "$path" | tr -d ' \n')"

    local sec_table=$(( pe_off + 24 + opt_size ))
    if (( sec_table + count * 40 > file_size )); then
        printf '%s: truncated PE section table\n' "$path" >&2
        return 1
    fi

    local idx sec_off sec_name vsize vaddr rsize rptr size extracted
    for (( idx = 0; idx < count; idx++ )); do
        sec_off=$(( sec_table + idx * 40 ))
        sec_name="$(od -An -tx1 -j "$sec_off" -N 8 -- "$path" | tr -d ' \n')"
        # ".cmdline" in ASCII hex is 2e 63 6d 64 6c 69 6e 65
        if [[ "$sec_name" == "2e636d646c696e65" ]]; then
            read -r vsize vaddr rsize rptr < <(
                od -An -tu4 --endian=little -j $(( sec_off + 8 )) -N 16 -- "$path"
            )
            : "$vaddr"
            size=$vsize
            (( rsize < size )) && size=$rsize
            if (( size <= 0 || size > 1048576 || rptr + size > file_size )); then
                printf '%s: invalid .cmdline size\n' "$path" >&2
                return 1
            fi
            extracted="$(dd if="$path" bs=1 skip="$rptr" count="$size" status=none | tr -d '\0')"
            extracted="${extracted#"${extracted%%[![:space:]]*}"}"
            extracted="${extracted%"${extracted##*[![:space:]]}"}"
            printf '%s' "$extracted"
            return 0
        fi
    done

    printf '%s: no embedded .cmdline\n' "$path" >&2
    return 1
}

# sbctl verify can exit 0 for an unsigned file; parse its --json output to
# confirm is_signed == 1 for the exact path.
verify_signature() {
    local path="$1"
    local json_out
    json_out="$(run_cmd sbctl --json verify "$path")" || {
        printf '%s: signature verification failed\n' "$path" >&2
        return 1
    }

    if ! awk -v target="$path" '
        BEGIN {
            in_str = 0; esc = 0; depth = 0
            expect_val = 0; cur_str = ""; cur_key = ""; num_buf = ""
            file_name = ""; is_signed = ""; matched = 0
        }
        {
            line = $0 "\n"
            n = length(line)
            for (i = 1; i <= n; i++) {
                c = substr(line, i, 1)
                if (in_str) {
                    if (esc) {
                        if (c == "\"" || c == "\\" || c == "/") cur_str = cur_str c
                        else if (c == "n") cur_str = cur_str "\n"
                        else if (c == "t") cur_str = cur_str "\t"
                        else cur_str = cur_str c
                        esc = 0
                    } else if (c == "\\") {
                        esc = 1
                    } else if (c == "\"") {
                        in_str = 0
                        if (depth == 2) {
                            if (!expect_val) {
                                cur_key = cur_str
                            } else {
                                if (cur_key == "file_name") file_name = cur_str
                                expect_val = 0
                                cur_key = ""
                            }
                        }
                        cur_str = ""
                    } else {
                        cur_str = cur_str c
                    }
                    continue
                }
                if (num_buf != "" && c !~ /[0-9]/) {
                    if (depth == 2 && expect_val && cur_key == "is_signed") {
                        is_signed = num_buf
                    }
                    num_buf = ""
                    if (c !~ /[[:space:]]/) {
                        expect_val = 0
                        cur_key = ""
                    }
                }
                if (c == "\"") {
                    in_str = 1
                    cur_str = ""
                } else if (c == "[" || c == "{") {
                    depth++
                    if (depth == 2 && c == "{") {
                        file_name = ""; is_signed = ""; cur_key = ""; expect_val = 0
                    }
                } else if (c == "}" || c == "]") {
                    if (depth == 2 && c == "}") {
                        if (file_name == target && is_signed == "1") matched = 1
                    }
                    depth--
                } else if (c == ":" && depth == 2) {
                    expect_val = 1
                } else if (c == "," && depth == 2) {
                    expect_val = 0
                    cur_key = ""
                } else if (depth == 2 && expect_val && c ~ /[0-9]/) {
                    num_buf = num_buf c
                }
            }
        }
        END { exit(matched ? 0 : 1) }
    ' <<< "$json_out"; then
        printf '%s: signature verification failed\n' "$path" >&2
        return 1
    fi
}

free_bytes() {
    local target="$1"
    df -B1 --output=avail -- "$target" | awk 'NR == 2 { print $1 }'
}

verify_staged_signature() {
    local staged="$1"
    local img_size avail verify_dir rc=0

    img_size="$(stat -c '%s' -- "$staged")"
    avail="$(free_bytes "$ESP_DIR")"
    if (( avail < img_size + 16 * 1048576 )); then
        die "Insufficient ESP space to verify a staged UKI"
    fi

    verify_dir="$(mktemp -d "${ESP_DIR}/.nvme-verify-XXXXXX")"
    cp -- "$staged" "${verify_dir}/${staged##*/}" || rc=$?
    if (( rc == 0 )); then
        verify_signature "${verify_dir}/${staged##*/}" || rc=$?
    fi
    rm -rf -- "$verify_dir"
    return "$rc"
}

atomic_copy() {
    local source="$1"
    local target="$2"
    local parent tmp

    parent="$(dirname -- "$target")"
    tmp="$(mktemp "${parent}/.${target##*/}.XXXXXX")"
    if ! {
        cp -- "$source" "$tmp" &&
        chmod 0600 -- "$tmp" &&
        { sync -f -- "$tmp" 2>/dev/null || sync; } &&
        mv -f -- "$tmp" "$target"
    }; then
        rm -f -- "$tmp"
        return 1
    fi
    sync -f -- "$parent" 2>/dev/null || sync
}

preflight() {
    [[ "$(id -u)" -eq 0 ]] || die "Administrator access required: run this command with sudo"

    local cmd
    for cmd in bash mkinitcpio sbctl findmnt od dd df stat flock; do
        command -v "$cmd" >/dev/null 2>&1 || die "Missing command: $cmd"
    done

    local fstype="" opts=""
    read -r fstype opts < <(run_cmd findmnt -n -r -M "$ESP_DIR" -o FSTYPE,OPTIONS 2>/dev/null || true)
    if [[ "$fstype" != "vfat" || ",${opts}," != *,rw,* ]]; then
        die "${ESP_DIR} must be a mounted, writable FAT EFI system partition"
    fi

    if [[ ! -f "$PRESET_FILE" ]]; then
        die "Missing ${PRESET_FILE}: this utility supports signed UKI installations only (for GRUB, edit /etc/default/grub instead)"
    fi

    local -a settings=()
    mapfile -t settings < <(
        bash -c '
            source "$1" || exit 1
            printf "%s\n" "${PRESETS[*]}" "${default_uki:-}" "${fallback_uki:-}" "${default_options[*]:-}" "${fallback_options[*]:-}"
            printf "%s\n" "${default_image:-}${fallback_image:-}${ALL_kerneldest:-}${default_kerneldest:-}${fallback_kerneldest:-}"
        ' nvme-stability "$PRESET_FILE"
    ) || die "Failed to parse ${PRESET_FILE}"

    if (( ${#settings[@]} != 6 )) ||
       [[ "${settings[0]}" != "default fallback" ]] ||
       [[ "${settings[1]}" != "${UKI_IMAGES[0]}" ]] ||
       [[ "${settings[2]}" != "${UKI_IMAGES[1]}" ]] ||
       [[ "${settings[3]}" != "" ]] ||
       [[ "${settings[4]}" != "-S autodetect" ]] ||
       [[ "${settings[5]}" != "" ]]; then
        die "Unsupported linux.preset: expected this project's two UKI outputs only"
    fi

    local img
    for img in "${UKI_IMAGES[@]}"; do
        if [[ ! -f "$img" || -L "$img" ]]; then
            die "Missing or unsupported UKI: $img"
        fi
        embedded_cmdline "$img" >/dev/null || exit 1
        verify_signature "$img" || exit 1
    done
}

deploy_files() {
    local cmdline_src="$1"
    shift
    local -a sources=("$@")
    local idx
    for idx in "${!UKI_IMAGES[@]}"; do
        atomic_copy "${sources[idx]}" "${UKI_IMAGES[idx]}" || return 1
    done
    atomic_copy "$cmdline_src" "$CMDLINE_FILE" || return 1
}

install_command_line() {
    local desired="$1"
    local original
    original="$(read_text_no_nul "$CMDLINE_FILE")" || exit 1

    local all_match=true img emb
    if ! tokens_equal "$original" "$desired"; then
        all_match=false
    else
        for img in "${UKI_IMAGES[@]}"; do
            emb="$(embedded_cmdline "$img")" || { all_match=false; break; }
            if ! tokens_equal "$emb" "$desired"; then
                all_match=false
                break
            fi
        done
    fi

    if [[ "$all_match" == true ]]; then
        printf 'Both signed UKIs already contain the requested command line. Check --status after boot.\n'
        return 0
    fi

    install -d -m 0700 -- "$STATE_DIR"

    local sum_sizes=0 sz avail
    for img in "${UKI_IMAGES[@]}"; do
        sz="$(stat -c '%s' -- "$img")"
        sum_sizes=$(( sum_sizes + sz ))
    done
    avail="$(free_bytes "$STATE_DIR")"
    if (( avail < 2 * sum_sizes + 1073741824 )); then
        die "Insufficient space for UKI staging and backups"
    fi

    local backup
    backup="$(mktemp -d "${STATE_DIR}/backup-XXXXXX")"
    chmod 0700 -- "$backup"
    printf 'Backup and build directory: %s\n' "$backup"

    cp -p -- "$CMDLINE_FILE" "${backup}/cmdline.before"
    cp -p -- "$PRESET_FILE" "${backup}/linux.preset.before"
    local -a before_imgs=() staged_imgs=()
    for img in "${UKI_IMAGES[@]}"; do
        cp -- "$img" "${backup}/${img##*/}.before"
        before_imgs+=("${backup}/${img##*/}.before")
        staged_imgs+=("${backup}/${img##*/}")
    done

    printf '%s' "$desired" > "${backup}/cmdline.after"

    local build_preset="${backup}/linux.preset"
    {
        printf 'source %q\n' "$PRESET_FILE"
        printf 'default_uki=%q\n' "${staged_imgs[0]}"
        printf 'fallback_uki=%q\n' "${staged_imgs[1]}"
    } > "$build_preset"

    run_cmd mkinitcpio -p "$build_preset" -- --cmdline "${backup}/cmdline.after" --nopost

    local staged
    for staged in "${staged_imgs[@]}"; do
        emb="$(embedded_cmdline "$staged")" || die "${staged}: failed to read rebuilt .cmdline; boot files unchanged"
        if ! tokens_equal "$emb" "$desired"; then
            die "${staged}: rebuilt command line differs; boot files unchanged"
        fi
        run_cmd sbctl sign "$staged"
        verify_staged_signature "$staged" || die "${staged}: staged signature verification failed; boot files unchanged"
    done

    local growth=0 max_staged=0 new_sz old_sz idx
    for idx in "${!UKI_IMAGES[@]}"; do
        new_sz="$(stat -c '%s' -- "${staged_imgs[idx]}")"
        old_sz="$(stat -c '%s' -- "${UKI_IMAGES[idx]}")"
        (( new_sz > max_staged )) && max_staged=$new_sz
        if (( new_sz > old_sz )); then
            growth=$(( growth + new_sz - old_sz ))
        fi
    done

    avail="$(free_bytes "$ESP_DIR")"
    if (( avail < max_staged + growth + 16 * 1048576 )); then
        die "Insufficient ESP space for atomic UKI replacement; boot files unchanged"
    fi

    local deploy_ok=true
    if ! deploy_files "${backup}/cmdline.after" "${staged_imgs[@]}"; then
        deploy_ok=false
    else
        for img in "${UKI_IMAGES[@]}"; do
            if ! verify_signature "$img"; then
                deploy_ok=false
                break
            fi
            emb="$(embedded_cmdline "$img" 2>/dev/null || true)"
            if ! tokens_equal "$emb" "$desired"; then
                printf 'Error: %s: installed command line differs\n' "$img" >&2
                deploy_ok=false
                break
            fi
        done
    fi

    if [[ "$deploy_ok" == false ]]; then
        printf 'Installation failed; restoring original cmdline and signed UKIs.\n' >&2
        deploy_files "${backup}/cmdline.before" "${before_imgs[@]}" || true
        exit 1
    fi

    local self_quoted backup_quoted
    printf -v self_quoted '%q' "$(readlink -f -- "${BASH_SOURCE[0]}")"
    printf -v backup_quoted '%q' "$backup"
    printf 'Installed and verified both signed UKIs. The running kernel is unchanged.\n'
    printf 'Reboot when ready, then run this utility with --status.\n'
    printf 'Rollback: sudo %s --restore %s\n' "$self_quoted" "$backup_quoted"
}

cmd_restore() {
    local backup_arg="$1"
    preflight

    local resolved_backup resolved_parent resolved_state resolved_legacy uid
    resolved_backup="$(readlink -f -- "$backup_arg")" || die "Backup directory does not exist: $backup_arg"
    [[ -d "$resolved_backup" ]] || die "Backup directory does not exist: $backup_arg"
    resolved_parent="$(dirname -- "$resolved_backup")"
    resolved_state="$(readlink -m -- "$STATE_DIR")"
    resolved_legacy="$(readlink -m -- "$LEGACY_STATE_DIR")"
    uid="$(stat -c '%u' -- "$resolved_backup")"

    if [[ ( "$resolved_parent" != "$resolved_state" && "$resolved_parent" != "$resolved_legacy" ) || "$uid" != "0" ]]; then
        die "Expected a root-owned backup directory directly inside ${STATE_DIR}"
    fi

    local before
    before="$(read_text_no_nul "${resolved_backup}/cmdline.before")" || exit 1
    # Validate saved command line without keeping workaround alterations
    with_workaround "$before" >/dev/null || exit 1
    install_command_line "$before"
}

cmd_status() {
    local current=""
    if [[ -r "$PROC_CMDLINE" ]]; then
        current="$(<"$PROC_CMDLINE")"
    fi
    tokenize_cmdline "$current" 2>/dev/null || CMDLINE_TOKENS=()
    local -a running_tokens=("${CMDLINE_TOKENS[@]}")

    printf 'Running kernel parameters:\n'
    local param tok found
    for param in "${WORKAROUND_PARAMS[@]}"; do
        found="ABSENT"
        for tok in "${running_tokens[@]}"; do
            if [[ "$tok" == "$param" ]]; then
                found="ACTIVE"
                break
            fi
        done
        printf '  %s: %s\n' "$param" "$found"
    done

    local latency_file="/sys/module/nvme_core/parameters/default_ps_max_latency_us"
    if [[ -r "$latency_file" ]]; then
        local lat=""
        IFS= read -r lat < "$latency_file" 2>/dev/null || true
        printf 'NVMe APST default latency: %s\n' "$lat"
    fi

    local img emb err_msg all_present p t matched_p
    for img in "${UKI_IMAGES[@]}"; do
        if emb="$(embedded_cmdline "$img" 2>&1)"; then
            if tokenize_cmdline "$emb" 2>/dev/null; then
                all_present=true
                for p in "${WORKAROUND_PARAMS[@]}"; do
                    matched_p=false
                    for t in "${CMDLINE_TOKENS[@]}"; do
                        if [[ "$t" == "$p" ]]; then
                            matched_p=true
                            break
                        fi
                    done
                    if [[ "$matched_p" == false ]]; then
                        all_present=false
                        break
                    fi
                done
                if [[ "$all_present" == true ]]; then
                    printf '%s: workaround embedded (signature not checked)\n' "$img"
                else
                    printf '%s: workaround absent (signature not checked)\n' "$img"
                fi
            else
                printf '%s: invalid embedded .cmdline\n' "$img"
            fi
        else
            err_msg="$emb"
            printf '%s\n' "$err_msg"
        fi
    done

    if [[ -d "$HWMON_DIR" ]]; then
        local -a hwmon_dirs=()
        shopt -s nullglob
        hwmon_dirs=("$HWMON_DIR"/hwmon*)
        shopt -u nullglob
        if (( ${#hwmon_dirs[@]} > 0 )); then
            IFS=$'\n' read -r -d '' -a hwmon_dirs < <(printf '%s\n' "${hwmon_dirs[@]}" | LC_ALL=C sort && printf '\0') || true
        fi
        local hw name raw_temp dev_path whole tenth
        for hw in "${hwmon_dirs[@]}"; do
            [[ -r "$hw/name" ]] || continue
            IFS= read -r name < "$hw/name" 2>/dev/null || continue
            [[ "$name" == "nvme" ]] || continue
            if [[ -r "$hw/temp1_input" ]] && IFS= read -r raw_temp < "$hw/temp1_input" 2>/dev/null && [[ "$raw_temp" =~ ^-?[0-9]+$ ]]; then
                dev_path="$(readlink -f -- "$hw/device" 2>/dev/null || printf '%s' "$hw")"
                whole=$(( (raw_temp + 50) / 1000 ))
                tenth=$(( ((raw_temp + 50) % 1000) / 100 ))
                (( tenth < 0 )) && tenth=$(( -tenth ))
                printf '%s: %d.%d C\n' "${dev_path##*/}" "$whole" "$tenth"
            else
                dev_path="$(readlink -f -- "$hw/device" 2>/dev/null || printf '%s' "$hw")"
                printf '%s: unavailable\n' "${dev_path##*/}"
            fi
        done
    fi
}

main() {
    local action=""
    local restore_path=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --status|--apply)
                if [[ -n "$action" ]]; then
                    die "Options --status, --apply, and --restore are mutually exclusive"
                fi
                action="${1#--}"
                shift
                ;;
            --restore)
                if [[ -n "$action" ]]; then
                    die "Options --status, --apply, and --restore are mutually exclusive"
                fi
                [[ $# -ge 2 ]] || die "--restore requires a BACKUP path"
                action="restore"
                restore_path="$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                die "Unknown option: $1"
                ;;
        esac
    done

    case "${action:-status}" in
        apply|restore)
            [[ "$(id -u)" -eq 0 ]] || die "Administrator access required: run this command with sudo"
            umask 077
            local lock_fd
            exec {lock_fd}>"$LOCK_FILE" || die "Cannot open lock file $LOCK_FILE"
            flock -n "$lock_fd" || die "Another nvme-stability operation is already running"
            if [[ "$action" == "apply" ]]; then
                preflight
                printf 'Proposed kernel parameters: %s\n' "${WORKAROUND_PARAMS[*]}"
                local raw_cmdline desired_cmdline
                raw_cmdline="$(read_text_no_nul "$CMDLINE_FILE")" || exit 1
                desired_cmdline="$(with_workaround "$raw_cmdline")" || exit 1
                install_command_line "$desired_cmdline"
            else
                cmd_restore "$restore_path"
            fi
            ;;
        status)
            cmd_status
            ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
