#!/usr/bin/env bash
set -euo pipefail

readonly PERSIST_FILE="/etc/sysctl.d/90-awesome-modules-lockdown.conf"
MODE=""
CONFIRMATION=""

usage() {
    cat <<EOF
Usage: sudo $0 (--runtime|--persist) --confirm LOCK-MODULES

Set kernel.modules_disabled=1 after every required module is already loaded.
This cannot be undone until reboot and can break hotplug, VPN, filesystem,
storage, GPU, and peripheral workflows.

  --runtime  Lock the running kernel only; reboot restores module loading
  --persist  Lock now and install $PERSIST_FILE for future boots
EOF
}

die() {
    printf 'Error: %s\n' "$1" >&2
    exit 1
}

while (($# > 0)); do
    case "$1" in
        --runtime|--persist)
            [[ -z "$MODE" ]] || die "select exactly one mode"
            MODE="$1"
            shift
            ;;
        --confirm)
            (($# >= 2)) || die "--confirm requires LOCK-MODULES"
            CONFIRMATION="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown option '$1'"
            ;;
    esac
done

[[ $EUID -eq 0 ]] || die "run as root"
[[ -n "$MODE" ]] || die "select --runtime or --persist"
[[ "$CONFIRMATION" == "LOCK-MODULES" ]] || \
    die "refusing irreversible change without --confirm LOCK-MODULES"

current="$(sysctl -n kernel.modules_disabled)"
if [[ "$current" == "1" ]]; then
    printf 'Kernel module loading is already disabled.\n'
    exit 0
fi
[[ "$current" == "0" ]] || die "unexpected kernel.modules_disabled value: $current"

printf '%s\n' \
    'WARNING: no script can prove every future hotplug or workload module is loaded.' \
    'After the next write, modules cannot be loaded or unloaded until reboot.' >&2

if [[ "$MODE" == "--persist" ]]; then
    install -d -m 0755 -- /etc/sysctl.d
    [[ ! -d "$PERSIST_FILE" ]] || die "refusing to replace directory: $PERSIST_FILE"
    temporary_file="$(mktemp /etc/sysctl.d/.90-awesome-modules-lockdown.XXXXXX)"
    cleanup() {
        if [[ -n "${temporary_file:-}" && -e "$temporary_file" ]]; then
            rm -- "$temporary_file"
        fi
    }
    trap cleanup EXIT
    printf '%s\n' \
        '# Managed by AwesomeArchLinux lock-modules-now.sh.' \
        '# Remove this file from recovery media to restore module loading next boot.' \
        'kernel.modules_disabled = 1' > "$temporary_file"
    chmod 0644 "$temporary_file"
fi

# Prepare the persistent artifact before crossing the irreversible runtime
# boundary. The final rename remains atomic within /etc/sysctl.d.
sysctl -w kernel.modules_disabled=1

if [[ "$MODE" == "--persist" ]]; then
    mv -- "$temporary_file" "$PERSIST_FILE"
    temporary_file=""
    trap - EXIT
    printf 'Persistent module lockdown installed at %s\n' "$PERSIST_FILE"
else
    printf 'Module loading is disabled for this boot only.\n'
fi
