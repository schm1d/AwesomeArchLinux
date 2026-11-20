#!/usr/bin/env bash
# Regression tests for the bare-metal installer path in pure Bash: prompt EOF
# handling, input validation, partition layout, X11 keyboard mapping, the base
# firewall ruleset, generated systemd/.network files, kernel command-line
# editing, the recovery menu, and Secure Boot key enrollment order.

set -euo pipefail

# shellcheck disable=SC1090,SC1091
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

# Print the body of the first here-document in $1 whose opening line matches
# the extended regex $2 (the delimiter is taken from that line).
extract_heredoc() {
    local rel_path="$1" opener_re="$2"
    awk -v re="$opener_re" '
        !capture && $0 ~ re {
            delim = $0
            sub(/.*<<-?[[:space:]]*/, "", delim)
            sub(/[[:space:]].*$/, "", delim)
            gsub(/["\047]/, "", delim)
            capture = 1
            next
        }
        capture && $0 == delim { found = 1; exit }
        capture { print }
        END { if (!found) exit 1 }
    ' "$REPO_ROOT/$rel_path"
}

load_installer_prompt_helpers() {
    # shellcheck disable=SC2034  # Colours are referenced by the extracted functions.
    BRed='' BBlue='' BGreen='' BYellow='' NC=''
    local fn
    for fn in "$@"; do
        eval "$(extract_shell_function "base/archinstall.sh" "$fn")"
    done
}

test_prompts_abort_at_eof_instead_of_looping() {
    load_installer_prompt_helpers prompt_read ask_yes_no ask_for_numeric confirm_disk_erase
    local out rc

    # A closed stdin used to spin forever inside "while true; read".
    rc=0
    out="$(timeout 10 bash -c "$(declare -f prompt_read ask_yes_no); BRed='' NC=''; ask_yes_no question" </dev/null 2>/dev/null)" || rc=$?
    assert_ne "$rc" "0" "ask_yes_no must fail at EOF"
    assert_ne "$rc" "124" "ask_yes_no must not loop until the timeout at EOF"
    assert_eq "$out" "" "ask_yes_no must not print an answer at EOF"

    rc=0
    timeout 10 bash -c "$(declare -f prompt_read ask_for_numeric); BRed='' NC=''; ask_for_numeric size" </dev/null >/dev/null 2>&1 || rc=$?
    assert_ne "$rc" "0" "ask_for_numeric must fail at EOF"
    assert_ne "$rc" "124" "ask_for_numeric must not loop at EOF"

    # Invalid answers are still re-asked, valid ones returned.
    out="$(printf 'maybe\ny\n' | ask_yes_no question 2>/dev/null)"
    assert_eq "$out" "y" "ask_yes_no returns the first valid answer"
    out="$(printf 'abc\n0\n42\n' | ask_for_numeric size 2>/dev/null)"
    assert_eq "$out" "42" "ask_for_numeric returns the first positive integer"

    # The erase confirmation needs the exact disk name; "abort" and EOF decline.
    printf 'sda\nsdz\n' | confirm_disk_erase /dev/sdz >/dev/null 2>&1 || fail "typing the disk name must confirm"
    if printf 'abort\n' | confirm_disk_erase /dev/sdz >/dev/null 2>&1; then
        fail "'abort' must decline the erase"
    fi
    if ( confirm_disk_erase /dev/sdz </dev/null >/dev/null 2>&1 ); then
        fail "EOF must decline the erase"
    fi

    # No ask_* helper may be called inside [[ $(...) ]]: that swallows the
    # failure the EOF handling relies on.
    if grep -nE '\[\[[[:space:]]*\$\(ask_' "$REPO_ROOT/base/archinstall.sh"; then
        fail "ask_* helper used inside [[ \$(...) ]] in base/archinstall.sh"
    fi
}

test_timezone_keymap_and_ssh_key_validation() {
    load_installer_prompt_helpers valid_timezone console_keymap_exists validate_ssh_pubkey
    local tz key_dir preset presets

    if [[ ! -f /usr/share/zoneinfo/UTC ]]; then
        echo "tzdata unavailable"
        return 77
    fi
    for tz in UTC Europe/Zurich America/Port-au-Prince; do
        [[ -f "/usr/share/zoneinfo/$tz" ]] || continue
        valid_timezone "$tz" || fail "valid timezone rejected: $tz"
    done
    for tz in ../../etc/passwd /etc/passwd zone.tab tzdata.zi Europe/ Europe/Nowhere ""; do
        if valid_timezone "$tz"; then
            fail "invalid timezone accepted: '$tz'"
        fi
    done

    # Every preset offered by the installer must be a real console keymap
    # ("kr" was offered and does not exist).
    presets="$(awk '/local -a keymaps=\(/ { capture = 1; next } capture && /^[[:space:]]*\)/ { exit } capture { gsub(/[" ]/, ""); print }' "$REPO_ROOT/base/archinstall.sh")"
    [[ -n "$presets" ]] || fail "keymap preset list not found in archinstall.sh"
    assert_not_contains $'\n'"$presets"$'\n' $'\nkr\n' "nonexistent keymap preset 'kr'"
    if console_keymap_exists us; then
        while IFS= read -r preset; do
            console_keymap_exists "$preset" || fail "keymap preset does not exist on this system: $preset"
        done <<< "$presets"
        if console_keymap_exists "u."; then
            fail "keymap name must be matched literally, not as a regex"
        fi
    fi

    validate_ssh_pubkey "" || fail "an empty key means 'none' and must be accepted"
    if validate_ssh_pubkey 'ssh-ed25519 AAAA$(id)' 2>/dev/null; then
        fail "shell metacharacters in a key must be rejected"
    fi
    if validate_ssh_pubkey 'ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY= x' 2>/dev/null; then
        fail "plain ECDSA keys are refused by the hardened sshd and must be rejected"
    fi
    if command -v ssh-keygen >/dev/null 2>&1; then
        key_dir="$(mktemp -d)"
        ssh-keygen -q -t ed25519 -N '' -f "$key_dir/ed" >/dev/null
        ssh-keygen -q -t ecdsa -N '' -f "$key_dir/ec" >/dev/null
        validate_ssh_pubkey "$(< "$key_dir/ed.pub")" || fail "a real ed25519 key must be accepted"
        if validate_ssh_pubkey "$(< "$key_dir/ec.pub")" 2>/dev/null; then
            fail "a real ECDSA key must be rejected"
        fi
        if validate_ssh_pubkey "ssh-ed25519 AAAAC3Nza truncated" 2>/dev/null; then
            fail "a truncated key must be rejected"
        fi
    fi

    # The accepted types must be a subset of what hardening/ssh/ssh.sh lets sshd accept.
    local accepted
    accepted="$(grep -m1 '^PubkeyAcceptedAlgorithms ' "$REPO_ROOT/hardening/ssh/ssh.sh")"
    assert_contains "$accepted" "ssh-ed25519"
    assert_not_contains "$accepted" ",ecdsa-sha2-" "sshd accepts plain ECDSA now: update the installer validators"
}

test_partition_layout_uses_sizes_not_sector_numbers() {
    if ! command -v sgdisk >/dev/null 2>&1; then
        echo "sgdisk unavailable"
        return 77
    fi
    local tmp disk commands line layout
    tmp="$(mktemp -d)"
    disk="$tmp/disk.img"
    truncate -s 4G "$disk"
    sgdisk -o "$disk" >/dev/null

    commands="$(grep -E '^sgdisk -n [123]:' "$REPO_ROOT/base/archinstall.sh")"
    assert_eq "$(wc -l <<< "$commands")" "3" "expected three partition-creation commands"
    # Absolute sector ranges assume 512-byte sectors (8 GiB ESP on 4Kn drives).
    if grep -Eq -- '-n [0-9]+:[0-9]{3,}:' <<< "$commands"; then
        fail "partition commands use absolute sector numbers"
    fi
    while IFS= read -r line; do
        DISK="$disk" bash -c "set -euo pipefail; $line" >/dev/null
    done <<< "$commands"

    layout="$(sgdisk -p "$disk" | awk '/^ +[0-9]/ { print $1, $2, $3, $6 }')"
    assert_eq "$layout" $'1 2048 4095 EF02\n2 4096 2101247 EF00\n3 2101248 8388574 8309' "512-byte layout: 1 MiB BIOS boot, 1 GiB ESP, LUKS on the rest"
}

test_vps_installer_shares_the_disk_safety_steps() {
    local fn commands
    # The VPS installer erases a disk too: same in-use refusal, same typed
    # confirmation, kept identical to the bare-metal helpers.
    for fn in assert_disk_not_in_use confirm_disk_erase; do
        assert_eq "$(extract_shell_function "base/vps-install.sh" "$fn")" \
            "$(extract_shell_function "base/archinstall.sh" "$fn")" "$fn differs between the two installers"
    done
    # Both checks must come before the first write to the disk.
    awk '
        /^assert_disk_not_in_use "\$DISK"$/ { asserted = NR }
        /^if ! confirm_disk_erase "\$DISK"; then$/ { confirmed = NR }
        /^(sgdisk|wipefs|mkfs)/ && !first_write { first_write = NR }
        END { exit !(asserted && confirmed && first_write && asserted < first_write && confirmed < first_write) }
    ' "$REPO_ROOT/base/vps-install.sh" || fail "vps-install.sh writes to the disk before the in-use check and the erase confirmation"

    commands="$(grep -E '^[[:space:]]*sgdisk -n [12]:' "$REPO_ROOT/base/vps-install.sh")"
    assert_eq "$(wc -l <<< "$commands")" "4" "expected four partition-creation commands (UEFI and BIOS)"
    if grep -Eq -- '-n [0-9]+:[0-9]{3,}:' <<< "$commands"; then
        fail "vps-install.sh partition commands use absolute sector numbers"
    fi

    if ! command -v sgdisk >/dev/null 2>&1; then
        return 0
    fi
    local tmp disk line layout
    tmp="$(mktemp -d)"
    disk="$tmp/disk.img"
    truncate -s 3G "$disk"
    sgdisk -o "$disk" >/dev/null
    # UEFI branch: the first two commands.
    while IFS= read -r line; do
        DISK="$disk" bash -c "set -euo pipefail; $line" >/dev/null
    done < <(head -n 2 <<< "$commands")
    layout="$(sgdisk -p "$disk" | awk '/^ +[0-9]/ { print $1, $2, $3, $6 }')"
    assert_eq "$layout" $'1 2048 2101247 EF00\n2 2101248 6291422 8300' "512-byte VPS UEFI layout must be unchanged"
}

test_x11_layout_comes_from_the_right_map_columns() {
    local tmp fn
    tmp="$(mktemp -d)"
    cat > "$tmp/kbd-model-map" <<'EOF'
# consolelayout		xlayout	xmodel		xvariant	xoptions
sg			ch	pc105		de_nodeadkeys	terminate:ctrl_alt_bksp
us			us	pc105+inet	-		terminate:ctrl_alt_bksp
uk			gb	pc105		-		terminate:ctrl_alt_bksp
br-abnt2		br	abnt2		-		terminate:ctrl_alt_bksp
EOF
    fn="$(extract_shell_function "base/chroot.sh" "vconsole_to_x11")"
    fn="${fn//\/usr\/share\/systemd\/kbd-model-map/$tmp/kbd-model-map}"
    eval "$fn"

    # layout model variant -- the model column used to be taken for the layout.
    assert_eq "$(vconsole_to_x11 sg)" "ch pc105 de_nodeadkeys"
    assert_eq "$(vconsole_to_x11 us)" "us pc105+inet "
    assert_eq "$(vconsole_to_x11 uk)" "gb pc105 "
    assert_eq "$(vconsole_to_x11 br-abnt2)" "br abnt2 "
    # Not in the map: heuristic fallback.
    assert_eq "$(vconsole_to_x11 de_CH-latin1)" "ch pc105 de"
    assert_eq "$(vconsole_to_x11 de-latin1)" "de pc105 "
}

test_base_firewall_ruleset_is_per_source_and_valid() {
    local ruleset tmp
    ruleset="$(extract_heredoc "base/chroot.sh" '^cat <<EOF > /etc/nftables\.conf$')"
    ruleset="${ruleset//\$\{SSH_PORT\}/22}"

    assert_contains "$ruleset" "flush ruleset" "hardening/lib/nftables.sh requires the base ruleset to own the table"
    assert_contains "$ruleset" "add @ssh_ratelimit4 { ip saddr limit rate over" "SSH limit must be tracked per IPv4 source"
    assert_contains "$ruleset" "add @ssh_ratelimit6 { ip6 saddr limit rate over" "SSH limit must be tracked per IPv6 source"
    # One shared token bucket lets scan noise lock every legitimate client out.
    if grep -Eq 'ct state new limit rate [^}]*accept' <<< "$ruleset"; then
        fail "global (shared-bucket) SSH rate limit is back"
    fi
    assert_contains "$ruleset" "udp sport 547 udp dport 546 accept" "DHCPv6 client replies must be accepted"
    assert_not_contains "$ruleset" "ip6 nexthdr icmpv6" "ICMPv6 must be matched with meta l4proto"

    if command -v nft >/dev/null 2>&1 && unshare -rn true 2>/dev/null; then
        tmp="$(mktemp -d)"
        printf '%s\n' "$ruleset" > "$tmp/nftables.conf"
        unshare -rn nft -c -f "$tmp/nftables.conf" || fail "base nftables ruleset does not load"
    fi
}

test_generated_unit_files_have_no_trailing_comments() {
    # systemd rejects "Key=value  # comment": the whole string becomes the
    # value, the setting is ignored, and the default silently applies.
    local offenders
    offenders="$(awk '
        /<<-?[[:space:]]*["\047]?[A-Z_]+["\047]?/ && /\/etc\/systemd\// {
            delim = $0
            sub(/.*<<-?[[:space:]]*/, "", delim); sub(/[[:space:]].*$/, "", delim); gsub(/["\047]/, "", delim)
            capture = 1; next
        }
        capture && $0 == delim { capture = 0; next }
        capture && /^[[:space:]]*[A-Z][A-Za-z0-9]*=[^#]*[[:space:]]#/ { print FILENAME ":" FNR ": " $0 }
    ' "$REPO_ROOT/base/chroot.sh")"
    assert_eq "$offenders" "" "setting lines with trailing comments in generated systemd files"

    local sshd_dropin bluetooth_dropin update_unit
    sshd_dropin="$(extract_heredoc "base/chroot.sh" 'sshd\.service\.d/hardening\.conf')"
    # seccomp-based directives are inherited by every SSH login session.
    if grep -Eq '^(RestrictAddressFamilies|LockPersonality|RestrictRealtime)=' <<< "$sshd_dropin"; then
        fail "sshd drop-in sets a seccomp filter that leaks into login sessions"
    fi
    bluetooth_dropin="$(extract_heredoc "base/chroot.sh" 'bluetooth\.service\.d/override\.conf')"
    assert_contains "$bluetooth_dropin" "AF_ALG" "bluetoothd needs AF_ALG for its crypto (Privacy=device)"
    assert_contains "$bluetooth_dropin" "AF_NETLINK"
    update_unit="$(extract_heredoc "base/chroot.sh" 'pacman-autoupdate\.service$')"
    assert_contains "$update_unit" "StandardOutput=truncate:" "update report must be overwritten, not patched in place"
}

test_clamd_option_helper_matches_whole_option_names() {
    local tmp
    tmp="$(mktemp -d)"
    CLAMD_CONF="$tmp/clamd.conf"
    printf '%s\n' '#Bytecode yes' '#BytecodeSecurity TrustSigned' '#BytecodeTimeout 60000' \
        '#AlertEncrypted no' '#AlertEncryptedArchive no' 'User nobody' > "$CLAMD_CONF"
    eval "$(extract_shell_function "base/chroot.sh" "ensure_clamd_option")"

    ensure_clamd_option Bytecode yes
    ensure_clamd_option AlertEncrypted yes
    ensure_clamd_option User clamav
    ensure_clamd_option LogTime yes
    assert_eq "$(< "$CLAMD_CONF")" $'Bytecode yes\n#BytecodeSecurity TrustSigned\n#BytecodeTimeout 60000\nAlertEncrypted yes\n#AlertEncryptedArchive no\nUser clamav\nLogTime yes'
}

test_tpm_cmdline_edit_keeps_comments_and_parameters() {
    local tmp fn calls
    tmp="$(mktemp -d)"
    fn="$(extract_shell_function "base/bootloader.sh" "ensure_tpm_cmdline")"
    fn="${fn//cmdline_file=\/etc\/kernel\/cmdline/cmdline_file=$tmp/cmdline}"
    eval "$fn"
    calls="$tmp/calls"
    : > "$calls"
    mkinitcpio() { echo "mkinitcpio $*" >> "$calls"; }
    sbctl() { echo "sbctl $*" >> "$calls"; }
    # shellcheck disable=SC2034  # Read by the extracted function.
    LUKS_UUID="1234-abcd"
    # What mkinitcpio builds the UKI command line from.
    effective_cmdline() { grep -ha -- '^[^#]' "$tmp/cmdline" | tr -s '\n' ' '; }

    printf '# root on LUKS\ncryptdevice=UUID=x:crypt root=/dev/mapper/vg-root rw\n' > "$tmp/cmdline"
    chmod 600 "$tmp/cmdline"
    ensure_tpm_cmdline
    assert_eq "$(effective_cmdline)" "cryptdevice=UUID=x:crypt root=/dev/mapper/vg-root rw rd.luks.options=1234-abcd=tpm2-device=auto "
    assert_eq "$(head -n1 "$tmp/cmdline")" "# root on LUKS" "comment lines must be preserved"
    assert_file_mode "$tmp/cmdline" "600"
    assert_eq "$(< "$calls")" $'mkinitcpio -P\nsbctl sign-all'

    # Idempotent: no second append, no second rebuild.
    ensure_tpm_cmdline
    assert_eq "$(grep -o 'tpm2-device=auto' "$tmp/cmdline" | wc -l)" "1"
    assert_eq "$(wc -l < "$calls")" "2"

    # A file without parameters must never produce a UKI.
    printf '# only a comment\n' > "$tmp/cmdline"
    : > "$calls"
    if ensure_tpm_cmdline 2>/dev/null; then
        fail "a cmdline without parameters must be refused"
    fi
    assert_eq "$(< "$tmp/cmdline")" "# only a comment"
    assert_eq "$(< "$calls")" "" "no UKI rebuild from an empty command line"

    # refresh must survive "bootctl update" reporting an up-to-date loader.
    assert_contains "$(extract_heredoc "base/bootloader.sh" 'awesome-secureboot <<')" "bootctl --esp-path=/efi --graceful update"
}

test_grub_unrestricted_patch_is_reapplied_by_a_hook() {
    local tmp helper hook
    tmp="$(mktemp -d)"
    helper="$(extract_heredoc "base/bootloader.sh" 'awesome-grub-unrestricted <<')"
    helper="${helper//target=\/etc\/grub.d\/10_linux/target=$tmp/10_linux}"
    printf '%s\n' "$helper" > "$tmp/helper.sh"

    printf '%s\n' '#! /bin/sh' 'CLASS="--class gnu-linux --class gnu --class os"' > "$tmp/10_linux"
    bash "$tmp/helper.sh"
    assert_contains "$(< "$tmp/10_linux")" 'CLASS="--class gnu-linux --class gnu --class os --unrestricted"'
    bash "$tmp/helper.sh"
    assert_eq "$(grep -c -- '--unrestricted' "$tmp/10_linux")" "1" "patch must be idempotent"

    # Upstream changed the line: say so instead of pretending.
    printf '%s\n' 'CLASS="--class something-else"' > "$tmp/10_linux"
    if bash "$tmp/helper.sh" 2>/dev/null; then
        fail "helper must fail when it cannot apply the patch"
    fi

    hook="$(extract_heredoc "base/bootloader.sh" '90-awesome-grub-unrestricted\.hook <<')"
    assert_contains "$hook" "Target = grub"
    assert_contains "$hook" "Exec = /usr/local/sbin/awesome-grub-unrestricted"
}

test_recovery_menu_survives_a_failing_action() {
    # shellcheck disable=SC2034
    BRed='' NC=''
    eval "$(extract_shell_function "base/recovery-mount.sh" "run_menu_action")"
    local out
    failing_action() { echo "step-1"; false; echo "step-2-must-not-run"; }
    working_action() { echo "worked"; }

    out="$(set -euo pipefail; run_menu_action failing_action 2>&1; echo "menu-alive"; run_menu_action working_action; echo "end")"
    assert_contains "$out" "step-1"
    assert_not_contains "$out" "step-2-must-not-run" "a failing action must stop at its first error"
    assert_contains "$out" "did not complete"
    assert_contains "$out" "menu-alive" "the menu must survive a failing action"
    assert_contains "$out" "worked"

    # Every menu entry goes through the wrapper.
    if grep -Eq '^[[:space:]]+[1-5]\) (show_status|unmount_all|remount_all|continue_install|enter_chroot) ;;' "$REPO_ROOT/base/recovery-mount.sh"; then
        fail "menu action called without run_menu_action"
    fi
}

test_resumed_install_cleans_up_and_keeps_the_boot_profile() {
    local root src out profile
    root="$(mktemp -d)"
    mkdir -p "$root/root" "$root/sysctl-profile"
    # shellcheck disable=SC2034  # Read by the extracted functions.
    BBlue='' BRed='' BGreen='' BYellow='' NC='' LUKS_NAME=crypt_lvm
    src="$(extract_shell_function "base/recovery-mount.sh" "finish_resumed_install")"$'\n'"$(extract_shell_function "base/recovery-mount.sh" "continue_install")"
    src="${src//\/mnt/$root}"
    eval "$src"
    findmnt() { return 0; }
    cryptsetup() { printf '  device:  /dev/sdz3\n'; }
    shred() { command rm -f -- "${@: -1}"; }
    # Like the real chroot.sh, a successful run removes its environment file.
    arch-chroot() { command rm -f -- "$root/root/.install-env"; }

    for profile in uki grub; do
        printf 'export INSTALL_BOOTLOADER=%s\nexport _INSTALL_BOOTLOADER=%s\n' "$profile" "$profile" > "$root/root/.install-env"
        : > "$root/chroot.sh"
        : > "$root/bootloader.sh"
        mkdir -p "$root/sysctl-profile"
        : > "$root/sysctl-profile/90-test.conf"
        out="$(continue_install 2>&1)"
        if [[ "$profile" == uki ]]; then
            assert_contains "$out" "cryptsetup luksKillSlot /dev/sdz3 1" "the UKI install-session key slot must be pointed out after a resumed run"
        else
            assert_not_contains "$out" "luksKillSlot" "the GRUB profile keeps its key slot"
        fi
        [[ ! -e "$root/chroot.sh" && ! -e "$root/bootloader.sh" && ! -e "$root/sysctl-profile" ]] ||
            fail "staged installer files were left behind after a resumed $profile run"
    done

    # Nothing to resume: report it as a failure instead of "completed".
    if out="$(continue_install 2>&1)"; then
        fail "continue_install must fail when no staged installer is present"
    fi
    assert_not_contains "$out" "Installation steps completed"

    # The profile marker audit-check.sh reads must be written before the
    # environment file is removed, by both chroot scripts.
    local script
    for script in base/chroot.sh base/vps-chroot.sh; do
        awk '
            /> \/etc\/awesome-install-profile$/ { marker = NR }
            /^shred -u \/root\/\.install-env/ { removed = NR }
            END { exit !(marker && removed && marker < removed) }
        ' "$REPO_ROOT/$script" || fail "$script does not record /etc/awesome-install-profile before removing /root/.install-env"
    done
}

# Run a patched copy of secureBoot.sh with every firmware-facing tool replaced
# by a recording stub. $1 = firmware mode (setup|user), rest = script options.
run_secureboot_sim() {
    local fw_mode="$1"
    shift
    (
        export SIM_CALLS="$SB_TMP/calls" SIM_FW_MODE="$fw_mode" SIM_FW_DB="${SIM_FW_DB:-full}"
        id() { echo 0; }
        install() {
            local -a args=()
            while (( $# )); do
                case "$1" in
                    -o|-g) shift ;;
                    *) args+=("$1") ;;
                esac
                shift
            done
            command install "${args[@]}"
        }
        # The script runs with a newline-first IFS, so join arguments explicitly.
        efi-updatevar() { local IFS=' '; echo "efi-updatevar $*" >> "$SIM_CALLS"; }
        efi-readvar() {
            local out=""
            while (( $# )); do [[ "$1" == "-o" ]] && out="$2"; shift; done
            if [[ "$SIM_FW_DB" == full ]]; then printf 'VENDOR\n' > "$out"; else : > "$out"; fi
        }
        cert-to-efi-sig-list() {
            # The real tool only reads PEM.
            grep -q 'BEGIN CERTIFICATE' "${@: -2:1}" || { echo "not a PEM certificate: ${*: -2:1}" >&2; return 1; }
            printf 'ESL(%s)\n' "${@: -2:1}" > "${@: -1}"
        }
        sign-efi-sig-list() { printf 'AUTH\n' > "${@: -1}"; }
        sbsign() {
            local out="" in=""
            while (( $# )); do
                case "$1" in
                    --output) out="$2"; shift ;;
                    --key|--cert) shift ;;
                    *) in="$1" ;;
                esac
                shift
            done
            { cat "$in"; echo SIGNED; } > "$out"
        }
        sbverify() { grep -q SIGNED "${@: -1}"; }
        efibootmgr() { :; }
        efivar() { :; }
        chattr() { :; }
        grub-install() {
            local IFS=' '
            if [[ "${1:-}" == "--help" ]]; then echo "--disable-shim-lock"; else echo "grub-install $*" >> "$SIM_CALLS"; fi
        }
        export -f id install efi-updatevar efi-readvar cert-to-efi-sig-list sign-efi-sig-list \
            sbsign sbverify efibootmgr efivar chattr grub-install
        bash "$SB_TMP/secureBoot.sim.sh" -d "$SB_TMP/keys" -p "$SB_TMP/esp" -k 2048 "$@" </dev/null
    )
}

test_secureboot_enrollment_order_and_safety_rails() {
    local dep out rc first_db_key
    for dep in openssl uuidgen od; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            echo "$dep unavailable"
            return 77
        fi
    done
    SB_TMP="$(mktemp -d)"
    mkdir -p "$SB_TMP/esp/EFI/systemd" "$SB_TMP/boot" "$SB_TMP/out"
    printf 'loader\n' > "$SB_TMP/esp/EFI/systemd/systemd-bootx64.efi"
    printf 'kernel\n' > "$SB_TMP/boot/vmlinuz-linux"
    # Redirect the fixed system paths into the fixture and make the firmware
    # mode controllable; everything else is the real script.
    sed -e "s#/var/lib/sbctl/GUID#$SB_TMP/absent1#; s#/usr/share/secureboot/GUID#$SB_TMP/absent2#; s#/etc/awesome-secureboot.conf#$SB_TMP/absent3#" \
        -e "s#^LOGFILE=.*#LOGFILE=\"$SB_TMP/out/log\"#" \
        -e "s#^RESIGN_HELPER=.*#RESIGN_HELPER=\"$SB_TMP/out/awesome-efi-resign\"#" \
        -e "s#^RESIGN_HOOK=.*#RESIGN_HOOK=\"$SB_TMP/out/hooks/resign.hook\"#" \
        -e 's#^firmware_mode() {#firmware_mode() {\n    printf "%s\\n" "$SIM_FW_MODE"; return 0#' \
        -e "s#\"/boot/vmlinuz-\"\\*#\"$SB_TMP/boot/vmlinuz-\"*#; s#\"/boot/EFI/Linux/\"\\*\\.efi#\"$SB_TMP/absent/\"*.efi#" \
        "$REPO_ROOT/base/secureBoot.sh" > "$SB_TMP/secureBoot.sim.sh"
    grep -q 'SIM_FW_MODE' "$SB_TMP/secureBoot.sim.sh" || fail "could not make firmware_mode controllable"
    : > "$SB_TMP/calls"

    # 1. A Platform Key is enrolled (User Mode): refuse before creating anything.
    rc=0
    out="$(run_secureboot_sim user 2>&1)" || rc=$?
    assert_ne "$rc" "0" "provisioning must be refused outside Setup Mode"
    assert_contains "$out" "not in Setup Mode"
    [[ ! -e "$SB_TMP/keys/PK.key" ]] || fail "keys were generated although the firmware is not in Setup Mode"

    # 2. Own certificate only, no -y, no terminal: refuse before signing or enrolling.
    rc=0
    out="$(run_secureboot_sim setup 2>&1)" || rc=$?
    assert_ne "$rc" "0" "replacing db with only the own certificate needs confirmation"
    assert_contains "$out" "ONLY your own certificate"
    assert_eq "$(< "$SB_TMP/calls")" "" "nothing may be enrolled without confirmation"
    assert_eq "$(< "$SB_TMP/boot/vmlinuz-linux")" "kernel" "nothing may be signed without confirmation"
    first_db_key="$(< "$SB_TMP/keys/db.key")"

    # 3. -m keeps the firmware's certificates; db -> KEK as signature lists, PK last as .auth.
    out="$(run_secureboot_sim setup -m 2>&1)" || fail "provisioning with -m failed: $out"
    assert_eq "$(< "$SB_TMP/calls")" $'efi-updatevar -e -f db-enroll.esl db\nefi-updatevar -e -f KEK-enroll.esl KEK\nefi-updatevar -f PK.auth PK'
    assert_eq "$(< "$SB_TMP/keys/db-enroll.esl")" $'VENDOR\nESL(db.crt)' "db must keep the firmware's certificates and add ours"
    assert_contains "$(< "$SB_TMP/boot/vmlinuz-linux")" "SIGNED"
    assert_contains "$(< "$SB_TMP/esp/EFI/systemd/systemd-bootx64.efi")" "SIGNED"
    # The key set from run 2 was moved aside, not overwritten.
    assert_eq "$(cat "$SB_TMP"/keys/previous-keys-*/db.key)" "$first_db_key" "the previous key set must be preserved"
    assert_ne "$(< "$SB_TMP/keys/db.key")" "$first_db_key"
    assert_contains "$(< "$SB_TMP/out/hooks/resign.hook")" "awesome-efi-resign -s -d"
    assert_contains "$(< "$SB_TMP/out/hooks/resign.hook")" "Target = usr/lib/modules/*/vmlinuz"

    # 4. Kernel update: sign-only mode re-signs and never touches the firmware.
    : > "$SB_TMP/calls"
    printf 'new kernel\n' > "$SB_TMP/boot/vmlinuz-linux"
    out="$(run_secureboot_sim user -s 2>&1)" || fail "sign-only run failed: $out"
    assert_contains "$(< "$SB_TMP/boot/vmlinuz-linux")" "SIGNED"
    assert_eq "$(< "$SB_TMP/calls")" "" "sign-only mode must not write firmware variables"

    # 5. -o in User Mode re-signs without attempting enrollment.
    out="$(run_secureboot_sim user -o 2>&1)" || fail "update-only run failed in User Mode: $out"
    assert_eq "$(< "$SB_TMP/calls")" "" "update-only must not enroll in User Mode"
}

run_test "prompts abort at EOF; disk erase needs the typed disk name" test_prompts_abort_at_eof_instead_of_looping
run_test "timezone, keymap preset, and SSH key type validation" test_timezone_keymap_and_ssh_key_validation
run_test "partition layout uses sizes (512-byte result unchanged)" test_partition_layout_uses_sizes_not_sector_numbers
run_test "VPS installer: in-use refusal, typed confirmation, size-based layout" test_vps_installer_shares_the_disk_safety_steps
run_test "X11 layout/model/variant come from the right kbd-model-map columns" test_x11_layout_comes_from_the_right_map_columns
run_test "base nftables ruleset: per-source SSH limit, DHCPv6, loads cleanly" test_base_firewall_ruleset_is_per_source_and_valid
run_test "generated systemd files: no trailing comments, no session-leaking sshd filters" test_generated_unit_files_have_no_trailing_comments
run_test "clamd option helper matches whole option names" test_clamd_option_helper_matches_whole_option_names
run_test "TPM cmdline edit keeps comments; refresh tolerates current loader" test_tpm_cmdline_edit_keeps_comments_and_parameters
run_test "GRUB --unrestricted patch helper and pacman hook" test_grub_unrestricted_patch_is_reapplied_by_a_hook
run_test "recovery menu survives a failing action" test_recovery_menu_survives_a_failing_action
run_test "resumed install: cleanup, UKI key-slot hint, install-profile marker" test_resumed_install_cleans_up_and_keeps_the_boot_profile
run_test "Secure Boot: Setup Mode gate, confirmation, enrollment order, key preservation" test_secureboot_enrollment_order_and_safety_rails

finish_test_file "test_base_installer.sh"
