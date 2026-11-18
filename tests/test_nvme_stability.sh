#!/usr/bin/env bash
# Boot-file preservation, PE .cmdline parsing, and atomic rollback tests in pure Bash.

set -euo pipefail

# shellcheck disable=SC1090,SC1091
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

NVME_SCRIPT="$REPO_ROOT/utils/nvme-stability.sh"

# Write a minimal synthetic 1024-byte PE/UKI image with a .cmdline section at offset 512.
write_fake_uki() {
    local path="$1"
    local cmdline="$2"
    local encoded_len=$(( ${#cmdline} + 1 ))
    local hex_len
    printf -v hex_len '%02x\\%02x\\%02x\\%02x' \
        $(( encoded_len & 0xff )) \
        $(( (encoded_len >> 8) & 0xff )) \
        $(( (encoded_len >> 16) & 0xff )) \
        $(( (encoded_len >> 24) & 0xff ))

    dd if=/dev/zero of="$path" bs=1024 count=1 status=none
    # MZ at 0, PE offset 128 (0x80) at 60
    printf 'MZ' | dd of="$path" bs=1 seek=0 conv=notrunc status=none
    printf '\x80\x00\x00\x00' | dd of="$path" bs=1 seek=60 conv=notrunc status=none
    # PE\0\0 at 128, 1 section at 134, optional_size=0 at 148
    printf 'PE\x00\x00\x64\x86\x01\x00' | dd of="$path" bs=1 seek=128 conv=notrunc status=none
    # Section header at 152: ".cmdline" + vsize + vaddr(4096) + rsize + rptr(512)
    printf '.cmdline' | dd of="$path" bs=1 seek=152 conv=notrunc status=none
    printf "\\x${hex_len}\\x00\\x10\\x00\\x00\\x${hex_len}\\x00\\x02\\x00\\x00" \
        | dd of="$path" bs=1 seek=160 conv=notrunc status=none
    printf '%s\x00' "$cmdline" | dd of="$path" bs=1 seek=512 conv=notrunc status=none
}

test_cmdline_rewriting_and_validation() {
    # shellcheck disable=SC1090,SC1091
    source "$NVME_SCRIPT"

    local original='# comment
root=/dev/mapper/lvm_arch-root rd.luks.name=uuid=crypt_lvm
rd.luks.options=uuid=tpm2-device=auto example="two words" nvme-core.default-ps-max-latency-us=5500 pcie_aspm=force pcie_aspm=off pcie_port_pm=force'

    local result
    result="$(with_workaround "$original")"$'\n'
    # Strip extra newline added by command substitution capture restoration
    result="${result%$'\n'}"$'\n'

    assert_contains "$result" 'rd.luks.options=uuid=tpm2-device=auto example="two words"'
    assert_not_contains "$result" "5500"
    assert_eq "$(grep -o 'pcie_aspm=' <<<"$result" | wc -l | tr -d ' ')" "1" "deduplicated pcie_aspm"
    assert_eq "$(with_workaround "$result")" "${result%$'\n'}" "idempotent rewrite"

    local bad rc
    for bad in "quiet" 'root=x x="broken' 'root=x -- initarg'; do
        rc=0
        with_workaround "$bad" >/dev/null 2>&1 || rc=$?
        assert_ne "$rc" "0" "rejected bad cmdline: $bad"
    done
}

test_unsigned_sbctl_json_is_rejected() {
    local rc=0
    bash -c '
        set -euo pipefail
        source "$1"
        run_cmd() { printf '\''[{"file_name": "/test.efi", "is_signed": 0}]\n'\''; }
        verify_signature "/test.efi"
    ' _ "$NVME_SCRIPT" >/dev/null 2>&1 || rc=$?
    assert_ne "$rc" "0" "unsigned sbctl JSON rejected"

    bash -c '
        set -euo pipefail
        source "$1"
        run_cmd() { printf '\''[\n  {\n    "file_name": "/test.efi",\n    "is_signed": 1\n  }\n]\n'\''; }
        verify_signature "/test.efi"
    ' _ "$NVME_SCRIPT" >/dev/null
}

setup_tx_fixture() {
    local root="$1"
    mkdir -p "$root/esp/EFI/Linux" "$root/state"
    local orig='root=/dev/mapper/root rd.luks.name=uuid=crypt_lvm'
    printf '%s\n' "$orig" > "$root/cmdline"
    cat > "$root/linux.preset" <<EOF
PRESETS=('default' 'fallback')
default_uki="$root/esp/EFI/Linux/arch-linux.efi"
default_options=""
fallback_uki="$root/esp/EFI/Linux/arch-linux-fallback.efi"
fallback_options="-S autodetect"
EOF
    write_fake_uki "$root/esp/EFI/Linux/arch-linux.efi" "$orig"
    write_fake_uki "$root/esp/EFI/Linux/arch-linux-fallback.efi" "$orig"
    cp "$root/esp/EFI/Linux/arch-linux.efi" "$root/orig-default.efi"
    cp "$root/esp/EFI/Linux/arch-linux-fallback.efi" "$root/orig-fallback.efi"
}

assert_tx_unchanged() {
    local root="$1"
    assert_eq "$(cat "$root/cmdline")" "root=/dev/mapper/root rd.luks.name=uuid=crypt_lvm" "cmdline unchanged"
    cmp -s "$root/esp/EFI/Linux/arch-linux.efi" "$root/orig-default.efi" || fail "default UKI mutated"
    cmp -s "$root/esp/EFI/Linux/arch-linux-fallback.efi" "$root/orig-fallback.efi" || fail "fallback UKI mutated"
}

test_staged_transactions_and_rollback() {
    local tmp
    tmp="$(mktemp -d)"
    trap 'trap - RETURN EXIT; [[ -n "${tmp:-}" ]] && rm -rf -- "$tmp"' RETURN EXIT
    setup_tx_fixture "$tmp"

    # 1. Build failure leaves boot files untouched
    local rc=0
    NVME_STABILITY_CMDLINE="$tmp/cmdline" \
    NVME_STABILITY_PRESET="$tmp/linux.preset" \
    NVME_STABILITY_ESP="$tmp/esp" \
    NVME_STABILITY_STATE="$tmp/state" \
    bash -c '
        set -euo pipefail
        source "$1"
        run_cmd() { return 1; }
        install_command_line "$(with_workaround "$(cat "$CMDLINE_FILE")")"$'\''\n'\''
    ' _ "$NVME_SCRIPT" >/dev/null 2>&1 || rc=$?
    assert_ne "$rc" "0" "build failure returns non-zero"
    assert_tx_unchanged "$tmp"

    # 2. Staged signature failure uses temporary ESP dir, cleans up, and keeps boot files untouched
    rc=0
    NVME_STABILITY_ESP="$tmp/esp" bash -c '
        set -euo pipefail
        source "$1"
        verify_signature() {
            [[ "$1" == "$ESP_DIR/.nvme-verify-"* ]] || exit 99
            return 1
        }
        verify_staged_signature "$ESP_DIR/EFI/Linux/arch-linux.efi"
    ' _ "$NVME_SCRIPT" >/dev/null 2>&1 || rc=$?
    assert_ne "$rc" "0" "staged signature failure returns non-zero"
    assert_eq "$(find "$tmp/esp" -maxdepth 1 -name '.nvme-verify-*' | wc -l | tr -d ' ')" "0" "temp ESP verify dir cleaned"
    assert_tx_unchanged "$tmp"
}

test_full_apply_idempotence_and_mid_deploy_rollback() {
    local tmp
    tmp="$(mktemp -d)"
    trap 'trap - RETURN EXIT; [[ -n "${tmp:-}" ]] && rm -rf -- "$tmp"' RETURN EXIT
    setup_tx_fixture "$tmp"

    local helper_fn
    helper_fn="$(declare -f write_fake_uki)"

    # Mid-deploy second-image failure restores first image & cmdline
    local rc=0
    NVME_STABILITY_CMDLINE="$tmp/cmdline" \
    NVME_STABILITY_PRESET="$tmp/linux.preset" \
    NVME_STABILITY_ESP="$tmp/esp" \
    NVME_STABILITY_STATE="$tmp/state" \
    HELPER_FN="$helper_fn" \
    bash -c '
        set -euo pipefail
        eval "$HELPER_FN"
        source "$1"
        eval "orig_$(declare -f atomic_copy)"
        run_cmd() {
            if [[ "$1" == "mkinitcpio" ]]; then
                stage_dir="$(dirname "$3")"
                write_fake_uki "$stage_dir/arch-linux.efi" "$(tr -d "\n" < "$stage_dir/cmdline.after")"
                write_fake_uki "$stage_dir/arch-linux-fallback.efi" "$(tr -d "\n" < "$stage_dir/cmdline.after")"
            fi
        }
        verify_signature() { return 0; }
        atomic_copy() {
            if [[ "$2" == *"arch-linux-fallback.efi" && "$1" != *".before" ]]; then
                return 1
            fi
            orig_atomic_copy "$@"
        }
        install_command_line "$(with_workaround "$(cat "$CMDLINE_FILE")")"$'\''\n'\''
    ' _ "$NVME_SCRIPT" >/dev/null 2>&1 || rc=$?
    assert_ne "$rc" "0" "second image copy failure exits non-zero"
    assert_tx_unchanged "$tmp"

    rm -rf "$tmp/state"/*

    # Successful apply + idempotent repeat
    local out
    out="$(
        NVME_STABILITY_CMDLINE="$tmp/cmdline" \
        NVME_STABILITY_PRESET="$tmp/linux.preset" \
        NVME_STABILITY_ESP="$tmp/esp" \
        NVME_STABILITY_STATE="$tmp/state" \
        HELPER_FN="$helper_fn" \
        bash -c '
            set -euo pipefail
            eval "$HELPER_FN"
            source "$1"
            run_cmd() {
                echo "RUN $1" >> "$STATE_DIR/../events"
                if [[ "$1" == "mkinitcpio" ]]; then
                    stage_dir="$(dirname "$3")"
                    write_fake_uki "$stage_dir/arch-linux.efi" "$(tr -d "\n" < "$stage_dir/cmdline.after")"
                    write_fake_uki "$stage_dir/arch-linux-fallback.efi" "$(tr -d "\n" < "$stage_dir/cmdline.after")"
                fi
            }
            verify_signature() { return 0; }
            desired="$(with_workaround "$(cat "$CMDLINE_FILE")")"$'\''\n'\''
            install_command_line "$desired"
            install_command_line "$desired"
        ' _ "$NVME_SCRIPT"
    )"
    assert_contains "$out" "Installed and verified both signed UKIs."
    assert_contains "$out" "Both signed UKIs already contain the requested command line."
    assert_not_contains "$out" "python" "rollback command uses bash script directly"
    assert_contains "$(cat "$tmp/cmdline")" "nvme_core.default_ps_max_latency_us=0 pcie_aspm=off pcie_port_pm=off"
    assert_eq "$(grep -c '^RUN mkinitcpio$' "$tmp/events")" "1" "second run is a no-op"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    run_test "cmdline quoting, deduplication, and validation" test_cmdline_rewriting_and_validation
    run_test "sbctl JSON signature parser rejects unsigned entries" test_unsigned_sbctl_json_is_rejected
    run_test "staged verification and failure cleanup" test_staged_transactions_and_rollback
    run_test "full apply, mid-deploy rollback, and idempotent repeat" test_full_apply_idempotence_and_mid_deploy_rollback
    finish_test_file "test_nvme_stability.sh"
fi
