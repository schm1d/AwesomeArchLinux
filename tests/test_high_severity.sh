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

# Run stage_ssh_components from base/vps-harden.sh into $1/stage.
#   $2  directory the script believes it lives in (SCRIPT_DIR)
#   $3  USE_LOCAL_COMPONENTS, as verify_local_components would have set it
#   $4  component whose download fails (optional)
# Every URL the curl stub is asked for is recorded in $1/curl-calls.
run_stage_ssh_components() {
    local tmp="$1" script_dir="$2" use_local="$3" fail_component="${4:-}" fn_stage
    fn_stage="$(extract_shell_function "base/vps-harden.sh" "stage_ssh_components")"
    mkdir -p "$tmp/stage"
    SCRIPT_DIR="$script_dir" STAGE_ROOT="$tmp/stage" REPO_ROOT="$REPO_ROOT" FAIL_COMPONENT="$fail_component" \
    USE_LOCAL_COMPONENTS="$use_local" RAW_BASE_URL="https://example.invalid/some-ref" CURL_CALLS="$tmp/curl-calls" bash -c '
        set -euo pipefail
        err() { echo "$*" >&2; exit 1; }
        curl() {
            printf "%s\n" "$2" >> "$CURL_CALLS"
            local comp="${2##*/hardening/}"
            [[ "$comp" != "$FAIL_COMPONENT" ]] || return 22
            cp "$REPO_ROOT/hardening/$comp" "$4"
        }
        '"$fn_stage"'
        stage_ssh_components "$STAGE_ROOT"
    '
}

test_ssh_component_staging() {
    # local:     a checkout next to the script that verify_local_components
    #            accepted (USE_LOCAL_COMPONENTS=true): staged from disk.
    # untrusted: the same files are there but were not accepted: they must not
    #            be used, both components are downloaded.
    # download:  single-file download, nothing next to the script.
    local mode
    for mode in local untrusted download; do
        local tmp src_dir="$REPO_ROOT/base" use_local=false calls
        tmp="$(mktemp -d)"
        [[ "$mode" != "local" ]] || use_local=true
        [[ "$mode" != "download" ]] || src_dir="$tmp/download-only"
        run_stage_ssh_components "$tmp" "$src_dir" "$use_local"

        calls="$(cat "$tmp/curl-calls" 2>/dev/null || true)"
        if [[ "$mode" == "local" ]]; then
            assert_eq "$calls" "" "local: an accepted checkout is staged from disk, nothing is downloaded"
        else
            assert_eq "$calls" \
                $'https://example.invalid/some-ref/hardening/lib/nftables.sh\nhttps://example.invalid/some-ref/hardening/ssh/ssh.sh' \
                "$mode: both components are downloaded from the selected ref"
        fi
        cmp -s "$tmp/stage/ssh.sh" "$REPO_ROOT/hardening/ssh/ssh.sh" || fail "$mode: staged ssh.sh differs from the source"
        cmp -s "$tmp/stage/nftables.sh" "$REPO_ROOT/hardening/lib/nftables.sh" || fail "$mode: staged nftables.sh differs from the source"
        assert_file_mode "$tmp/stage/ssh.sh" "755"
        assert_file_mode "$tmp/stage/nftables.sh" "644"
        local help_out
        help_out="$(bash "$tmp/stage/ssh.sh" -h)"
        assert_contains "$help_out" "Usage:"
        rm -rf -- "$tmp"
    done

    # A failed download stops the run before vps-chroot.sh changes authentication.
    local tmp_fail rc_fail=0 err_fail
    tmp_fail="$(mktemp -d)"
    err_fail="$(run_stage_ssh_components "$tmp_fail" "$tmp_fail/download-only" false "ssh/ssh.sh" 2>&1)" || rc_fail=$?
    assert_eq "$rc_fail" "1" "failed download is fatal"
    assert_contains "$err_fail" "Could not fetch required SSH component: ssh/ssh.sh"
    rm -rf -- "$tmp_fail"

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
        -e "s|/usr/local/sbin/awesome-borg-backup|$tmp/sbin/awesome-borg-backup|g" \
        "$REPO_ROOT/utils/backup.sh" > "$script"
    printf 'test-only-passphrase' > "$tmp/passphrase"
    mkdir -p "$tmp/units" "$tmp/logrotate"

    # The borg stub is strict where the real borg is: "borg list" rejects
    # --format placeholders that do not exist for archive listings (borg 1.x
    # ArchiveFormatter keys), and "borg extract" records where it would unpack.
    TEST_DIR="$tmp" MISSING_BORG="$missing_borg" bash -c '
        id() { echo 0; }
        chown() { :; }
        pacman() { echo "UNEXPECTED PACKAGE OPERATION" >> "$TEST_DIR/events"; return 99; }
        systemctl() { echo "systemctl $*" >> "$TEST_DIR/events"; }
        borg() {
            echo "borg $*" >> "$TEST_DIR/events"
            if [[ "$1" == --version ]]; then echo "borg 1.4"; fi
            if [[ "$1" == key && "$2" == export ]]; then echo "test key" > "$4"; fi
            if [[ "$1" == extract ]]; then echo "extract-cwd $PWD" >> "$TEST_DIR/events"; fi
            if [[ "$1" == list ]]; then
                local fmt="" prev="" arg key
                for arg in "$@"; do
                    [[ "$prev" != --format ]] || fmt="$arg"
                    prev="$arg"
                done
                while [[ "$fmt" =~ \{([A-Za-z_]+)[^}]*\}(.*) ]]; do
                    key="${BASH_REMATCH[1]}"
                    fmt="${BASH_REMATCH[2]}"
                    case "$key" in
                        archive|name|barchive|comment|bcomment|id|tam|start|time|end|command_line|hostname|username) ;;
                        NEWLINE|NL|NUL|SPACE|TAB|CR|LF) ;;
                        *)
                            echo "borg: Invalid placeholder \"$key\" in --format" >&2
                            echo "borg-list-rejected $key" >> "$TEST_DIR/events"
                            return 2
                            ;;
                    esac
                done
            fi
            return 0
        }
        command() {
            if [[ "$MISSING_BORG" == true && "$1" == -v && "$2" == borg ]]; then return 1; fi
            builtin command "$@"
        }
        source "$1" "${@:2}"
    ' _ "$script" -r "${BACKUP_FIXTURE_REPO:-$tmp/repo}" -p "$tmp/passphrase" "$@"
}

# Run verify_local_components and then stage_ssh_components from
# base/vps-harden.sh against the checkout in $1/checkout. The functions are
# sourced from a file inside that checkout, so "the owner of this script" is
# the owner of the fixture, as it is for a real clone.
run_local_component_check() {
    local tmp="$1" fn
    mkdir -p "$tmp/checkout/base" "$tmp/stage"
    {
        for fn in untrusted_path_reason verify_local_components stage_ssh_components; do
            extract_shell_function "base/vps-harden.sh" "$fn"
        done
    } > "$tmp/checkout/base/functions.sh"
    chmod go-w "$tmp/checkout/base" "$tmp/checkout/base/functions.sh"
    CURL_CALLS="$tmp/curl-calls" REPO_ROOT="$REPO_ROOT" bash -c '
        set -euo pipefail
        info() { echo "INFO $*"; }
        warn() { echo "WARN $*"; }
        err() { echo "ERR $*" >&2; exit 1; }
        curl() {
            printf "%s\n" "$2" >> "$CURL_CALLS"
            cp "$REPO_ROOT/hardening/${2##*/hardening/}" "$4"
        }
        COMPONENT_REF="main"
        USE_LOCAL_COMPONENTS=false
        SCRIPT_DIR="$(cd "$1/checkout/base" && pwd -P)"
        source "$SCRIPT_DIR/functions.sh"
        verify_local_components
        echo "USE_LOCAL_COMPONENTS=$USE_LOCAL_COMPONENTS"
        stage_ssh_components "$1/stage"
    ' _ "$tmp" 2>&1
}

# vps-harden.sh runs the files next to it as root. It may only do that when
# nobody but root or the owner of the script could have written them.
test_local_components_need_a_private_checkout() {
    local tmp out rc

    # A private checkout fixture: mktemp -d is 0700, and the copies are made
    # non-writable for group and others whatever the umask of the test run is.
    new_checkout() {
        mkdir -p "$1/checkout/base" "$1/checkout/hardening/lib" "$1/checkout/hardening/ssh"
        printf '#!/usr/bin/env bash\n' > "$1/checkout/base/vps-chroot.sh"
        cp "$REPO_ROOT/hardening/lib/nftables.sh" "$1/checkout/hardening/lib/"
        # The staged copy is recognisable: it can only have come from here.
        { cat "$REPO_ROOT/hardening/ssh/ssh.sh"; printf '# local checkout copy\n'; } > "$1/checkout/hardening/ssh/ssh.sh"
        chmod -R go-w "$1/checkout"
    }

    # 1. Private checkout: accepted, staged from disk, nothing downloaded.
    tmp="$(mktemp -d)"
    new_checkout "$tmp"
    rc=0
    out="$(run_local_component_check "$tmp")" || rc=$?
    assert_eq "$rc" "0" "private checkout is accepted: $out"
    assert_contains "$out" "USE_LOCAL_COMPONENTS=true"
    [[ ! -e "$tmp/curl-calls" ]] || fail "trusted checkout: components were downloaded: $(cat "$tmp/curl-calls")"
    assert_eq "$(tail -n1 "$tmp/stage/ssh.sh")" "# local checkout copy" "ssh.sh was staged from the checkout"
    rm -rf -- "$tmp"

    # 2. One component writable by its group: refused, nothing staged.
    tmp="$(mktemp -d)"
    new_checkout "$tmp"
    chmod g+w "$tmp/checkout/hardening/ssh/ssh.sh"
    rc=0
    out="$(run_local_component_check "$tmp")" || rc=$?
    assert_eq "$rc" "1" "group-writable component is refused"
    assert_contains "$out" "hardening/ssh/ssh.sh is writable by its group or by others"
    assert_contains "$out" "Refusing to use repository files that other users could have written"
    [[ ! -e "$tmp/stage/ssh.sh" ]] || fail "a component was staged from an untrusted checkout"
    rm -rf -- "$tmp"

    # 3. A directory others can write to (they could swap the file): refused.
    tmp="$(mktemp -d)"
    new_checkout "$tmp"
    chmod o+w "$tmp/checkout/hardening/lib"
    rc=0
    out="$(run_local_component_check "$tmp")" || rc=$?
    assert_eq "$rc" "1" "world-writable component directory is refused"
    assert_contains "$out" "hardening/lib is writable by its group or by others"
    [[ ! -e "$tmp/stage/ssh.sh" ]] || fail "a component was staged from an untrusted checkout"
    rm -rf -- "$tmp"

    # 4. A directory above the checkout that others can write to: refused.
    tmp="$(mktemp -d)"
    mkdir -p "$tmp/shared"
    new_checkout "$tmp/shared"
    chmod 0777 "$tmp/shared"
    rc=0
    out="$(run_local_component_check "$tmp/shared")" || rc=$?
    assert_eq "$rc" "1" "checkout below a world-writable directory is refused"
    assert_contains "$out" "/shared is writable by its group or by others"
    rm -rf -- "$tmp"

    # 5. vps-harden.sh alone in a directory: no error, components are downloaded.
    tmp="$(mktemp -d)"
    rc=0
    out="$(run_local_component_check "$tmp")" || rc=$?
    assert_eq "$rc" "0" "single-file download is not an error: $out"
    assert_contains "$out" "USE_LOCAL_COMPONENTS=false"
    assert_eq "$(wc -l < "$tmp/curl-calls" | tr -d ' ')" "2" "both SSH components are downloaded"
    rm -rf -- "$tmp"
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
        if [[ "$spec" == --list* ]]; then
            assert_not_contains "$events" "borg-list-rejected" "--list uses placeholders borg knows"
        fi
        if [[ "$spec" == --restore* ]]; then
            # Default restore target: a new private directory, not a fixed
            # name below world-writable /tmp that someone else could pre-create.
            local restore_dir
            restore_dir="$(sed -n 's/^extract-cwd //p' <<<"$events")"
            [[ "$restore_dir" == "$tmp"/restore.?* && -d "$restore_dir" ]] || fail "restore did not use a fresh mktemp directory: ${restore_dir:-none}"
            assert_file_mode "$restore_dir" "700"
        fi
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

    # The timer must run a root-owned installed copy, never the checkout the
    # script happened to be started from (that would be root running a file
    # the invoking user can edit).
    local exec_start
    exec_start="$(grep '^ExecStart=' "$tmp_init/units/borg-backup.service")"
    assert_eq "$exec_start" \
        "ExecStart=$tmp_init/sbin/awesome-borg-backup -r \"$tmp_init/repo\" -p \"$tmp_init/passphrase\" -k 7 -K 4 -M 6 --backup --prune" \
        "unit runs the installed copy with quoted arguments"
    cmp -s "$tmp_init/sbin/awesome-borg-backup" "$tmp_init/backup.sh" || fail "installed copy differs from the script that ran --init"
    assert_file_mode "$tmp_init/sbin/awesome-borg-backup" "755"
    rm -rf -- "$tmp_init"

    # Paths are quoted for systemd, not for a shell: spaces stay inside one
    # argument, and % / $ are doubled so they are not expanded by systemd.
    local tmp_quote
    tmp_quote="$(mktemp -d)"
    BACKUP_FIXTURE_REPO="$tmp_quote/my repo/50%/\$x" run_backup_fixture "$tmp_quote" "false" --init >/dev/null 2>&1
    exec_start="$(grep '^ExecStart=' "$tmp_quote/units/borg-backup.service")"
    assert_contains "$exec_start" " -r \"$tmp_quote/my repo/50%%/\$\$x\" -p " "repository path quoted and escaped for systemd"
    rm -rf -- "$tmp_quote"
}

run_test "GPT partition gap, contiguous, and missing-first allocation" test_gpt_partition_allocation
run_test "VPS offline /var migration instructions and live rollback refusal" test_var_migration_and_rollback_guard
run_test "SSH component staging local, download, and missing-helper checks" test_ssh_component_staging
run_test "vps-harden.sh uses local components only from a checkout nobody else can write" test_local_components_need_a_private_checkout
run_test "Borg routine operations never touch packages/units; --init sets timer" test_backup_operations_and_init

finish_test_file "test_high_severity.sh"
