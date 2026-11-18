#!/usr/bin/env bash
# High-severity regression tests in pure Bash: GPT partition gap handling,
# offline /var migration & rollback guard, SSH staging, and Borg backup safety.

set -euo pipefail

# shellcheck disable=SC1090,SC1091
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

check_partition_layout() {
    local expected="$1"
    shift
    local -a numbers=("$@")
    local tmp
    tmp="$(mktemp -d)"
    trap 'trap - RETURN EXIT; [[ -n "${tmp:-}" ]] && rm -rf -- "$tmp"' RETURN EXIT

    local disk="$tmp/disk.img"
    truncate -s 2G "$disk"
    sgdisk -o "$disk" >/dev/null
    local n
    for n in "${numbers[@]}"; do
        sgdisk -n "${n}:0:+16M" -c "${n}:existing-${n}" "$disk" >/dev/null
    done

    local fn_def rc=0 err_out
    fn_def="$(extract_shell_function "base/vps-harden.sh" "create_var_filesystem")"
    err_out="$(PARENT_DISK="$disk" bash -c '
        set -euo pipefail
        info() { :; }; msg() { :; }
        err() { echo "$*" >&2; exit 1; }
        partprobe() { :; }; udevadm() { :; }
        mkfs.ext4() { echo "UNEXPECTED FORMAT" >&2; exit 99; }
        VAR_STRATEGY=partition
        VAR_LOOP_SIZE=1
        DRY_RUN=false
        '"$fn_def"'
        create_var_filesystem
    ' 2>&1 >/dev/null)" || rc=$?

    assert_ne "$rc" "0" "refuses to format missing udev block node"
    assert_contains "$err_out" "New partition has not appeared"
    assert_not_contains "$err_out" "UNEXPECTED FORMAT"
    assert_contains "$(sgdisk -i "$expected" "$disk")" "Partition name: 'var'"
}

test_gpt_partition_allocation() {
    if ! command -v sgdisk >/dev/null 2>&1 || ! command -v uuidgen >/dev/null 2>&1; then
        echo "sgdisk/uuidgen unavailable"
        return 77
    fi
    check_partition_layout 2 1 3
    check_partition_layout 3 1 2
    check_partition_layout 1 2 3
}

test_var_migration_and_rollback_guard() {
    local tmp
    tmp="$(mktemp -d)"
    trap 'trap - RETURN EXIT; [[ -n "${tmp:-}" ]] && rm -rf -- "$tmp"' RETURN EXIT

    local rollback="$tmp/rollback.sh"
    mkdir -p "$tmp/var.old"
    local fn_rb
    fn_rb="$(extract_shell_function "base/vps-harden.sh" "create_rollback_script")"
    ROLLBACK_SCRIPT="$rollback" FSTAB_BACKUP="$tmp/fstab.backup" bash -c '
        set -euo pipefail
        info() { :; }; msg() { :; }
        '"$fn_rb"'
        create_rollback_script
    ' >/dev/null

    sed -i "s|/var.old|$tmp/var.old|g" "$rollback"
    local rc=0 err_out
    err_out="$(bash -c 'id() { echo 0; }; source "$1"' _ "$rollback" 2>&1 </dev/null)" || rc=$?
    assert_eq "$rc" "1" "rollback refuses completed /var migration"
    assert_contains "$err_out" "Refusing live rollback"

    local fn_prep strategy
    fn_prep="$(extract_shell_function "base/vps-harden.sh" "prepare_var_migration")"
    for strategy in partition volume loop; do
        local guide="$tmp/migration-${strategy}.txt"
        VAR_STRATEGY="$strategy" DRY_RUN=false VAR_MIGRATION_GUIDE="$guide" \
        ROOT_DEVICE="/dev/source" VAR_DEVICE="/dev/destination" bash -c '
            set -euo pipefail
            info() { :; }; msg() { :; }; warn() { :; }; log_action() { :; }
            err() { echo "$*" >&2; exit 1; }
            blkid() {
                if [[ "${!#}" == /dev/source ]]; then
                    echo aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
                else
                    echo bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb
                fi
            }
            rsync() { exit 99; }; mv() { exit 99; }; mount() { exit 99; }; umount() { exit 99; }
            '"$fn_prep"'
            prepare_var_migration
        '
        local notes
        notes="$(cat "$guide")"
        assert_contains "$notes" "boot a rescue ISO"
        assert_contains "$notes" "rsync -aHAXxnc"
        assert_file_mode "$guide" "600"
    done
}

test_ssh_component_staging() {
    local fn_stage
    fn_stage="$(extract_shell_function "base/vps-harden.sh" "stage_ssh_components")"

    local mode
    for mode in local download; do
        local tmp
        tmp="$(mktemp -d)"
        local src_dir="$REPO_ROOT/base"
        [[ "$mode" == "download" ]] && src_dir="$tmp/download-only"
        SCRIPT_DIR="$src_dir" STAGE_ROOT="$tmp" REPO_ROOT="$REPO_ROOT" FAIL_COMPONENT="" bash -c '
            set -euo pipefail
            err() { echo "$*" >&2; exit 1; }
            curl() {
                local comp="${2##*/hardening/}"
                [[ "$comp" != "$FAIL_COMPONENT" ]] || return 22
                cp "$REPO_ROOT/hardening/$comp" "$4"
            }
            '"$fn_stage"'
            stage_ssh_components "$STAGE_ROOT"
        '
        local help_out
        help_out="$(bash "$tmp/ssh.sh" -h)"
        assert_contains "$help_out" "Usage:"
        rm -rf -- "$tmp"
    done

    # Missing helper beside standalone ssh.sh fails before root check
    local tmp2 rc=0 err_out
    tmp2="$(mktemp -d)"
    cp "$REPO_ROOT/hardening/ssh/ssh.sh" "$tmp2/ssh.sh"
    err_out="$(bash "$tmp2/ssh.sh" -h 2>&1 >/dev/null)" || rc=$?
    assert_eq "$rc" "1"
    assert_contains "$err_out" "nftables.sh"
    rm -rf -- "$tmp2"
}

run_backup_fixture() {
    local tmp="$1"
    local missing_borg="$2"
    shift 2

    local script="$tmp/backup.sh"
    sed \
        -e "s|/var/log/borg-backup.log|$tmp/backup.log|g" \
        -e "s|/etc/systemd/system|$tmp/units|g" \
        -e "s|/etc/logrotate.d|$tmp/logrotate|g" \
        -e "s|/root/.borg-key-backup|$tmp/key-backup|g" \
        -e "s|/tmp/borg-restore|$tmp/restore|g" \
        "$REPO_ROOT/utils/backup.sh" > "$script"
    printf 'test-only-passphrase' > "$tmp/passphrase"
    mkdir -p "$tmp/units" "$tmp/logrotate"

    TEST_DIR="$tmp" MISSING_BORG="$missing_borg" bash -c '
        id() { echo 0; }
        chown() { :; }
        pacman() { echo "UNEXPECTED PACKAGE OPERATION" >> "$TEST_DIR/events"; return 99; }
        systemctl() { echo "systemctl $*" >> "$TEST_DIR/events"; }
        borg() {
            echo "borg $*" >> "$TEST_DIR/events"
            if [[ "$1" == --version ]]; then echo "borg 1.4"; fi
            if [[ "$1" == key && "$2" == export ]]; then echo "test key" > "$4"; fi
            return 0
        }
        command() {
            if [[ "$MISSING_BORG" == true && "$1" == -v && "$2" == borg ]]; then return 1; fi
            builtin command "$@"
        }
        source "$1" "${@:2}"
    ' _ "$script" -r "$tmp/repo" -p "$tmp/passphrase" "$@"
}

test_backup_operations_and_init() {
    local spec expected
    local -a args=()
    for spec in "--backup --prune|borg create" "--prune|borg prune" "--list|borg list" "--restore snapshot|borg extract"; do
        expected="${spec#*|}"
        read -r -a args <<<"${spec%%|*}"
        local tmp
        tmp="$(mktemp -d)"
        run_backup_fixture "$tmp" "false" "${args[@]}" >/dev/null 2>&1
        local events
        events="$(cat "$tmp/events")"
        assert_contains "$events" "$expected"
        assert_not_contains "$events" "PACKAGE OPERATION"
        assert_not_contains "$events" "systemctl"
        assert_eq "$(find "$tmp/units" -mindepth 1 | wc -l | tr -d ' ')" "0" "no units created in routine ops"
        rm -rf -- "$tmp"
    done

    # Missing borg fails without installing packages
    local tmp_miss rc=0 out
    tmp_miss="$(mktemp -d)"
    out="$(run_backup_fixture "$tmp_miss" "true" --backup 2>&1)" || rc=$?
    assert_eq "$rc" "1"
    assert_contains "$out" "BorgBackup is not installed"
    [[ ! -e "$tmp_miss/events" ]] || fail "unexpected commands executed when borg missing"
    rm -rf -- "$tmp_miss"

    # Explicit --init configures timer and logrotate
    local tmp_init
    tmp_init="$(mktemp -d)"
    run_backup_fixture "$tmp_init" "false" --init >/dev/null 2>&1
    local init_events
    init_events="$(cat "$tmp_init/events")"
    assert_contains "$init_events" "borg init"
    assert_contains "$init_events" "systemctl enable borg-backup.timer"
    [[ -f "$tmp_init/units/borg-backup.service" ]] || fail "borg-backup.service missing"
    [[ -f "$tmp_init/logrotate/borg-backup" ]]     || fail "logrotate config missing"
    rm -rf -- "$tmp_init"
}

run_test "GPT partition gap, contiguous, and missing-first allocation" test_gpt_partition_allocation
run_test "VPS offline /var migration instructions and live rollback refusal" test_var_migration_and_rollback_guard
run_test "SSH component staging local, download, and missing-helper checks" test_ssh_component_staging
run_test "Borg routine operations never touch packages/units; --init sets timer" test_backup_operations_and_init

finish_test_file "test_high_severity.sh"
