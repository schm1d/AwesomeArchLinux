#!/usr/bin/env bash

# =============================================================================
# Script:      iosched.sh
# Description: udev rule — bfq for HDDs, mq-deadline for SATA/virtio SSD,
#              none for NVMe.
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
# =============================================================================

set -euo pipefail

readonly C_BLUE='\033[1;34m'
readonly C_RED='\033[1;31m'
readonly C_GREEN='\033[1;32m'
readonly C_YELLOW='\033[1;33m'
readonly C_NC='\033[0m'

msg()  { printf "%b[+]%b %s\n" "$C_GREEN" "$C_NC" "$1"; }
info() { printf "%b[*]%b %s\n" "$C_BLUE"  "$C_NC" "$1"; }
warn() { printf "%b[!]%b %s\n" "$C_YELLOW" "$C_NC" "$1"; }
err()  { printf "%b[!]%b %s\n" "$C_RED"   "$C_NC" "$1" >&2; exit 1; }

RULE="/etc/udev/rules.d/60-awesome-ioschedulers.rules"
DO_STATUS=false
DO_REMOVE=false

usage() { echo "Usage: sudo $0 [--status] [--remove] [-h]"; exit 0; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --status)  DO_STATUS=true; shift ;;
        --remove)  DO_REMOVE=true; shift ;;
        -h|--help) usage ;;
        *)         err "Unknown option: $1" ;;
    esac
done

[[ $(id -u) -eq 0 ]] || err "Must be run as root"

show_status() {
    echo
    info "I/O schedulers:"
    local dev sched rot
    for dev in /sys/block/*/queue/scheduler; do
        [[ -r "$dev" ]] || continue
        sched=$(tr -d '\n' <"$dev")
        rot="?"
        [[ -r "$(dirname "$dev")/rotational" ]] && rot=$(cat "$(dirname "$dev")/rotational")
        printf "  %-16s rotational=%s  %s\n" "$(basename "$(dirname "$(dirname "$dev")")")" "$rot" "$sched"
    done
    echo
    [[ -f "$RULE" ]] && info "Rule installed at $RULE" || info "No $RULE"
}

if [[ "$DO_STATUS" == true ]]; then show_status; exit 0; fi
if [[ "$DO_REMOVE" == true ]]; then rm -f "$RULE"; msg "Removed $RULE"; show_status; exit 0; fi

mkdir -p /etc/udev/rules.d
cat > "$RULE" <<'EOF'
# AwesomeArchLinux I/O scheduler policy (whole devices only).
ACTION=="add|change", SUBSYSTEM=="block", KERNEL=="sd[a-z]|vd[a-z]|xvd[a-z]|hd[a-z]", ATTR{queue/rotational}=="1", ATTR{queue/scheduler}="bfq"
ACTION=="add|change", SUBSYSTEM=="block", KERNEL=="sd[a-z]|vd[a-z]|xvd[a-z]", ATTR{queue/rotational}=="0", ATTR{queue/scheduler}="mq-deadline"
ACTION=="add|change", SUBSYSTEM=="block", KERNEL=="nvme[0-9]*n[0-9]*", ATTR{queue/scheduler}="none"
ACTION=="add|change", SUBSYSTEM=="block", KERNEL=="mmcblk[0-9]", ATTR{queue/scheduler}="bfq"
EOF
chmod 644 "$RULE"
msg "Wrote $RULE"
udevadm control --reload
udevadm trigger --subsystem-match=block --action=change
msg "Reloaded udev and triggered block devices"
show_status
