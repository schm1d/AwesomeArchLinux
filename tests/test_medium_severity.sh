#!/usr/bin/env bash
# Medium-severity regression tests in pure Bash: reviewed AUR staging,
# fscrypt home migration, per-app Node.js audits, and bounded disk wipes.

set -euo pipefail

# shellcheck disable=SC1090,SC1091
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

stage_aur_bundle() {
    local root="$1"
    local installer="$2"
    local section
    section="$(awk '
        /^# Stage reviewed AUR installation/ { capture = 1; next }
        capture && /^# End post-install package staging\./ { capture = 0; exit }
        capture { print }
    ' "$REPO_ROOT/$installer")"
    section="${section//\/mnt\/root/$root}"
    SCRIPT_DIR="$REPO_ROOT/base" bash -c "set -euo pipefail"$'\n'"$section"
}

test_aur_bundle_staging_and_rerun_baseline() {
    local installer
    for installer in "base/archinstall.sh" "base/vps-install.sh"; do
        local tmp
        tmp="$(mktemp -d)"
        stage_aur_bundle "$tmp" "$installer"
        cmp -s "$tmp/install-aur-packages.sh" "$REPO_ROOT/base/install-aur-packages.sh" || fail "$installer staged wrong install-aur-packages.sh"
        cmp -s "$tmp/aur-review.sh" "$REPO_ROOT/hardening/lib/aur-review.sh" || fail "$installer staged wrong aur-review.sh"
        cmp -s "$tmp/aide-config.sh" "$REPO_ROOT/utils/aide-config.sh" || fail "$installer staged wrong aide-config.sh"
        assert_file_mode "$tmp/install-aur-packages.sh" "700"
        assert_file_mode "$tmp/aur-review.sh" "600"
        assert_file_mode "$tmp/aide-config.sh" "700"
        rm -rf -- "$tmp"
    done

    local tmp
    tmp="$(mktemp -d)"
    trap 'trap - RETURN EXIT; [[ -n "${tmp:-}" ]] && rm -rf -- "$tmp"' RETURN EXIT
    stage_aur_bundle "$tmp" "base/archinstall.sh"
    sed -i "s|/var/lib/aide|$tmp|g" "$tmp/install-aur-packages.sh"
    cat > "$tmp/aur-review.sh" <<'EOF'
aal_aur_install_reviewed() {
    echo "REVIEW $1" >> "$EVENTS"
    [[ "$REJECT_REVIEW" != true ]] || return 1
    touch "$FIXTURE/$1.installed"
}
EOF
    # Every stub run writes a different baseline, so a second initialization
    # is visible in the database content as well as in the event log.
    cat > "$tmp/aide-config.sh" <<'EOF'
echo "AIDE $*" >> "$EVENTS"
echo "init" >> "$FIXTURE/aide-runs"
printf 'reference baseline %s' "$(wc -l < "$FIXTURE/aide-runs" | tr -d ' ')" > "$FIXTURE/aide.db"
EOF

    local reject rc out events run=0
    for reject in true false false; do
        (( ++run ))
        : > "$tmp/events"
        rc=0
        out="$(FIXTURE="$tmp" EVENTS="$tmp/events" REJECT_REVIEW="$reject" bash -c '
            set -euo pipefail
            id() { echo 0; }
            pacman() {
                case "$1" in
                    -Qq) [[ -f "$FIXTURE/$2.installed" ]] ;;
                    -Si) [[ "$2" == acct ]] ;;
                    -S) if [[ "${!#}" == acct ]]; then touch "$FIXTURE/acct.installed"; fi ;;
                    *) exit 99 ;;
                esac
            }
            systemctl() { echo "systemctl $*" >> "$EVENTS"; return 0; }
            makepkg() { exit 99; }
            source "$1"
        ' _ "$tmp/install-aur-packages.sh" 2>&1)" || rc=$?
        events="$(cat "$tmp/events")"
        if [[ "$reject" == true ]]; then
            assert_ne "$rc" "0" "review rejection stops setup"
            assert_not_contains "$events" "AIDE"
        else
            assert_eq "$rc" "0" "accepted review completes setup"
            assert_eq "$(cat "$tmp/aide.db")" "reference baseline 1" "baseline is the one from the first initialization"
            if (( run == 2 )); then
                assert_contains "$events" "AIDE --init" "first accepted run initializes AIDE"
            else
                assert_not_contains "$events" "AIDE" "re-run must not initialize AIDE again"
            fi
        fi
    done
    assert_contains "$out" "Existing AIDE baseline preserved"
}

run_fscrypt_fixture() {
    local root="$1"
    local failure="$2"
    local shared="$3"
    local action="$4"
    local active="$5"

    local home="$root/homes/alice"
    mkdir -p "$home" "$root/rootfs"
    printf 'original data' > "$home/original.txt"
    touch "$root/config" "$root/pam.so"
    : > "$root/events"

    local fns="" fn
    for fn in is_ext4 validate_encryption_filesystem prepare_encryption_filesystem do_setup do_encrypt_user; do
        fns+="$(extract_shell_function "hardening/fscrypt/fscrypt.sh" "$fn")"$'\n'
    done
    fns="${fns//\/root\/fscrypt-recovery-/$root/recovery-}"

    local call_cmd="do_encrypt_user"
    [[ "$action" == "setup" ]] && call_cmd="do_setup"

    FIXTURE="$root" USER_HOME="$home" TARGET_USER="alice" \
    FSCRYPT_CONF="$root/config" PAM_FSCRYPT_SO="$root/pam.so" \
    PAM_SYSTEM_LOGIN="$root/config" PAM_PASSWD="$root/config" \
    PAM_AUTH_LINE="auth" PAM_SESSION_LINE="session" PAM_PASSWORD_LINE="password" \
    MARK="# test" EVENTS="$root/events" FAILURE="$failure" \
    SHARED="$shared" ACTIVE="$active" \
    bash -c '
        set -euo pipefail
        info() { :; }; ok() { :; }; warn() { echo "$*" >&2; }
        err() { echo "$*" >&2; exit 1; }
        id() { echo 1000; }
        getent() { printf "alice:x:1000:1000::%s:/bin/bash\n" "$USER_HOME"; }
        mountpoint() { return 1; }
        chown() { :; }; sleep() { :; }; require_cmd() { :; }
        pacman() { exit 99; }
        append_pam_line() { echo PAM >> "$EVENTS"; }
        insert_pam_session_before_systemd() { echo PAM >> "$EVENTS"; }
        findmnt() {
            local path="${!#}" kind="$3" mount="$FIXTURE/rootfs" dev=/dev/root
            if [[ "$path" != / && "$SHARED" != true ]]; then
                mount="$FIXTURE/homes"; dev=/dev/home
            fi
            case "$kind" in
                FSTYPE) if [[ "$path" != / && "$FAILURE" == type ]]; then echo xfs; else echo ext4; fi ;;
                SOURCE) echo "$dev" ;;
                TARGET) echo "$mount" ;;
            esac
        }
        has_encrypt_feature() { [[ "$1" != /dev/home || "$FAILURE" != feature ]]; }
        fscrypt() {
            printf "fscrypt %s\n" "$*" >> "$EVENTS"
            case "$1" in
                status)
                    if [[ "$2" == "$USER_HOME" ]]; then
                        [[ "$FAILURE" == encrypted ]]; return
                    fi
                    [[ -d "$2/.fscrypt/policies" ]] ;;
                setup)
                    [[ "$2" != "$FIXTURE/homes" || "$FAILURE" != setup ]] || return 1
                    mkdir -p "$2/.fscrypt/policies" "$2/.fscrypt/protectors" ;;
                encrypt)
                    [[ "$FAILURE" != encrypt ]] || return 1
                    [[ "$3" == --user=alice && "$4" == --source=pam_passphrase ]] || return 99
                    touch "$2/encrypted-marker" ;;
            esac
        }
        loginctl() {
            printf "loginctl %s\n" "$*" >> "$EVENTS"
            if [[ "$1" == list-users && "$ACTIVE" == true ]]; then echo "1000 alice"; fi
        }
        mv() {
            printf "mv %s\n" "$*" >> "$EVENTS"
            if [[ "$FAILURE" == activate && "${@: -2:1}" == *.encrypt.* ]]; then return 1; fi
            command mv "$@"
        }
        '"$fns"'
        '"$call_cmd"'
    ' <<< "YES"
}

test_fscrypt_migration_safety() {
    local failure
    for failure in type feature setup encrypt; do
        local tmp rc=0
        tmp="$(mktemp -d)"
        run_fscrypt_fixture "$tmp" "$failure" "false" "encrypt" "false" >/dev/null 2>&1 || rc=$?
        assert_ne "$rc" "0" "fscrypt failure $failure aborts"
        assert_eq "$(cat "$tmp/homes/alice/original.txt")" "original data"
        [[ ! -e "$tmp/homes/alice.pre-encrypt" ]] || fail "pre-encrypt backup should not exist on preflight failure"
        rm -rf -- "$tmp"
    done

    # Successful separate & shared home migrations
    local shared
    for shared in false true; do
        local tmp
        tmp="$(mktemp -d)"
        run_fscrypt_fixture "$tmp" "" "$shared" "encrypt" "true" >/dev/null 2>&1
        [[ -f "$tmp/homes/alice/encrypted-marker" ]] || fail "encrypted marker missing"
        assert_eq "$(cat "$tmp/homes/alice.pre-encrypt/original.txt")" "original data"
        assert_contains "$(cat "$tmp/events")" "loginctl terminate-user alice"
        rm -rf -- "$tmp"
    done

    # Failed activation restores original home
    local tmp_act rc=0
    tmp_act="$(mktemp -d)"
    run_fscrypt_fixture "$tmp_act" "activate" "false" "encrypt" "false" >/dev/null 2>&1 || rc=$?
    assert_ne "$rc" "0" "activation failure exits non-zero"
    assert_eq "$(cat "$tmp_act/homes/alice/original.txt")" "original data"
    rm -rf -- "$tmp_act"
}

test_nodejs_independent_audits() {
    local tmp
    tmp="$(mktemp -d)"
    trap 'trap - RETURN EXIT; [[ -n "${tmp:-}" ]] && rm -rf -- "$tmp"' RETURN EXIT
    mkdir -p "$tmp/bin" "$tmp/units" "$tmp/logs"

    local section
    section="$(awk '
        /msg "Setting up automated npm security audit\.\.\."/ { capture = 1; next }
        capture && /^# 10\. FILE PERMISSIONS/ { capture = 0; exit }
        capture { print }
    ' "$REPO_ROOT/hardening/nodejs/nodejs.sh")"
    section="${section//\/usr\/local\/bin/$tmp/bin}"
    section="${section//\/etc\/systemd\/system/$tmp/units}"
    section="${section//\/var\/log/$tmp/logs}"

    local spec name dir
    for spec in "first|first app" "second|second" 'first|updated $literal "app"'; do
        name="${spec%%|*}"
        dir="$tmp/${spec#*|}"
        mkdir -p "$dir"
        APP_NAME="$name" APP_PATH="$dir" APP_USER="$(id -un)" bash -c '
            set -euo pipefail
            msg() { :; }; info() { :; }; warn() { :; }
            chown() { :; }; systemctl() { :; }
            '"$section"'
        '
    done

    local cmd
    cmd="$(awk -F= '/^ExecStart=/ { sub(/^ExecStart=/, ""); print; exit }' "$tmp/units/first-audit.service")"
    AUDITED_PATH="$tmp/audited" bash -c '
        set -euo pipefail
        npm() { printf "%s\n" "$PWD" > "$AUDITED_PATH"; }
        source "$1"
    ' _ "$cmd"
    assert_eq "$(cat "$tmp/audited")" "$tmp/updated \$literal \"app\"" "quoted path preserved across audit scripts"
}

test_bounded_disk_wipe() {
    local fn_wipe
    fn_wipe="$(extract_shell_function "base/archinstall.sh" "wipe_disk")"

    local source
    for source in /dev/zero /dev/urandom; do
        local tmp
        tmp="$(mktemp -d)"
        local disk="$tmp/disk.img"
        local size=$(( 1048576 + 512 ))
        head -c "$size" /dev/urandom > "$disk"

        local out
        out="$(DISK="$disk" DEVICE_SIZE="$size" SOURCE="$source" bash -c '
            set -euo pipefail
            blockdev() { printf "%s\n" "$DEVICE_SIZE"; }
            '"$fn_wipe"'
            wipe_disk "$DISK" "$SOURCE"
            echo NEXT_INSTALL_STEP
        ')"
        assert_contains "$out" "NEXT_INSTALL_STEP"
        assert_eq "$(stat -c '%s' "$disk")" "$size" "exact device size preserved"
        rm -rf -- "$tmp"
    done

    # Write failure on /dev/full stops installation
    local rc=0
    DISK="/dev/full" DEVICE_SIZE="512" SOURCE="/dev/zero" bash -c '
        set -euo pipefail
        blockdev() { printf "%s\n" "$DEVICE_SIZE"; }
        '"$fn_wipe"'
        wipe_disk "$DISK" "$SOURCE"
    ' >/dev/null 2>&1 || rc=$?
    assert_ne "$rc" "0" "/dev/full write error fails wipe_disk"

    # Invalid sizes leave disk untouched
    local tmp_bad bad_sz
    tmp_bad="$(mktemp -d)"
    printf 'preserve this' > "$tmp_bad/disk.img"
    for bad_sz in "" "0" "unknown" "-1"; do
        rc=0
        DISK="$tmp_bad/disk.img" DEVICE_SIZE="$bad_sz" SOURCE="/dev/zero" bash -c '
            set -euo pipefail
            blockdev() { printf "%s\n" "$DEVICE_SIZE"; }
            '"$fn_wipe"'
            wipe_disk "$DISK" "$SOURCE"
        ' >/dev/null 2>&1 || rc=$?
        assert_ne "$rc" "0" "invalid size '$bad_sz' rejected"
        assert_eq "$(cat "$tmp_bad/disk.img")" "preserve this"
    done
    rm -rf -- "$tmp_bad"
}

run_test "post-install AUR bundle staging and AIDE baseline preservation" test_aur_bundle_staging_and_rerun_baseline
run_test "fscrypt preflight, separate/shared home migration, and activation rollback" test_fscrypt_migration_safety
run_test "Node.js per-app independent npm audit scripts" test_nodejs_independent_audits
run_test "bounded disk wipe exact partial block and write-error propagation" test_bounded_disk_wipe

finish_test_file "test_medium_severity.sh"
