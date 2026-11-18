#!/usr/bin/env bash
set -euo pipefail
umask 022

# kernel.modules_disabled semantics:
# https://docs.kernel.org/admin-guide/sysctl/kernel.html#modules-disabled

readonly PERSIST_UNIT="/etc/systemd/system/awesome-lock-modules.service"
readonly LEGACY_PERSIST_SYSCTL="/etc/sysctl.d/90-awesome-modules-lockdown.conf"
MODE=""
CONFIRMATION=""

usage() {
    cat <<EOF
Usage: sudo $0 (--runtime|--persist) --confirm LOCK-MODULES

Set kernel.modules_disabled=1 after every required module is already loaded.
This cannot be undone until reboot and can break hotplug, VPN, filesystem,
storage, GPU, and peripheral workflows.

  --runtime  Lock the running kernel only; reboot restores module loading
  --persist  Lock now and install late-boot $PERSIST_UNIT for future boots
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
            [[ $# -ge 2 && -n "${2:-}" ]] || die "--confirm requires LOCK-MODULES"
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
if [[ "$current" != "0" && "$current" != "1" ]]; then
    die "unexpected kernel.modules_disabled value: $current"
fi
if [[ "$current" == "1" && "$MODE" == "--runtime" ]]; then
    printf 'Kernel module loading is already disabled.\n'
    exit 0
fi

if [[ "$MODE" == "--persist" ]]; then
    install -d -m 0755 -- /etc/systemd/system
    [[ ! -d "$PERSIST_UNIT" ]] || die "refusing to replace directory: $PERSIST_UNIT"

    # Remove any legacy early-boot sysctl drop-in that would lock module loading
    # before vfat (/boot) or nf_tables (nftables.service) finish loading.
    if [[ -f "$LEGACY_PERSIST_SYSCTL" || -L "$LEGACY_PERSIST_SYSCTL" ]]; then
        rm -f -- "$LEGACY_PERSIST_SYSCTL"
        printf 'Removed legacy early-boot sysctl lockdown (%s).\n' "$LEGACY_PERSIST_SYSCTL"
    fi

    temporary_file="$(mktemp /etc/systemd/system/.awesome-lock-modules.service.XXXXXX)"
    cleanup() {
        if [[ -n "${temporary_file:-}" && -e "$temporary_file" ]]; then
            rm -f -- "$temporary_file"
        fi
    }
    trap cleanup EXIT
    cat > "$temporary_file" <<'EOF'
# Managed by AwesomeArchLinux lock-modules-now.sh.
# Disable or remove this unit from recovery media to restore module loading next boot.

[Unit]
Description=Lock Linux kernel module loading after boot initialization
Documentation=https://docs.kernel.org/admin-guide/sysctl/kernel.html#modules-disabled
DefaultDependencies=yes
After=multi-user.target graphical.target display-manager.service network-online.target nftables.service docker.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/sysctl -w kernel.modules_disabled=1
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    chmod 0644 "$temporary_file"
    mv -- "$temporary_file" "$PERSIST_UNIT"
    temporary_file=""
    trap - EXIT
    systemctl daemon-reload
    systemctl enable awesome-lock-modules.service
fi

if [[ "$current" == "0" ]]; then
    printf '%s\n' \
        'WARNING: no script can prove every future hotplug or workload module is loaded.' \
        'After the next write, modules cannot be loaded or unloaded until reboot.' >&2
    sysctl -w kernel.modules_disabled=1
fi

if [[ "$MODE" == "--persist" ]]; then
    printf 'Persistent late-boot module lockdown installed and enabled at %s\n' "$PERSIST_UNIT"
else
    printf 'Module loading is disabled for this boot only.\n'
fi
