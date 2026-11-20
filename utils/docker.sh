#!/usr/bin/env bash

# =============================================================================
# Script:      docker.sh
# Description: Docker/Podman hardening script for Arch Linux.
#              Supports rootless Podman (default, recommended) and hardened
#              Docker daemon configurations.
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
#
# Usage:       sudo ./docker.sh [--docker|--podman] [-u USERNAME] [-h]
# =============================================================================

set -euo pipefail

umask 022

readonly C_BLUE='\033[1;34m'
readonly C_RED='\033[1;31m'
readonly C_GREEN='\033[1;32m'
readonly C_YELLOW='\033[1;33m'
readonly C_NC='\033[0m'

msg()  { printf "%b[+]%b %s\n" "$C_GREEN"  "$C_NC" "$1"; }
info() { printf "%b[*]%b %s\n" "$C_BLUE"   "$C_NC" "$1"; }
warn() { printf "%b[!]%b %s\n" "$C_YELLOW" "$C_NC" "$1"; }
err()  { printf "%b[!]%b %s\n" "$C_RED"    "$C_NC" "$1" >&2; exit 1; }

MODE="podman"
TARGET_USER="${SUDO_USER:-}"

# Replace root-owned FILE with the content on stdin. A previous version with
# different content is kept as FILE.bak.<timestamp>.
install_config() {
    local mode="$1" file="$2" tmp backup
    tmp="$(mktemp "${file}.XXXXXX")"
    cat > "$tmp"
    chmod "$mode" "$tmp"
    if [[ -f "$file" ]] && ! cmp -s -- "$file" "$tmp"; then
        backup="${file}.bak.$(date +%Y%m%d%H%M%S)"
        cp -a -- "$file" "$backup"
        info "Existing $file saved as $backup"
    fi
    mv -f -- "$tmp" "$file"
}

usage() {
    cat <<EOF
Usage: sudo $0 [--docker|--podman] [-u USERNAME] [-h]

Modes:
  --podman    (default) Install and configure rootless Podman
  --docker    Install and configure hardened Docker

Options:
  -u USER     Target user for group membership / rootless setup
              (default: \$SUDO_USER, must not be root)
  -h, --help  Show this help
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --docker)   MODE="docker";  shift ;;
        --podman)   MODE="podman";  shift ;;
        -u)
            [[ $# -ge 2 && -n "${2:-}" ]] || err "-u requires a username"
            TARGET_USER="$2"
            shift 2
            ;;
        -h|--help)  usage ;;
        *)          err "Unknown option: $1. See -h for help." ;;
    esac
done

[[ $(id -u) -eq 0 ]] || err "Must be run as root (use sudo)"

if [[ -z "$TARGET_USER" || "$TARGET_USER" == "root" ]]; then
    err "Target user must be a non-root account. Pass -u USERNAME or run via sudo."
fi

if ! id "$TARGET_USER" &>/dev/null; then
    err "User '$TARGET_USER' does not exist."
fi

TARGET_HOME="$(getent passwd "$TARGET_USER" | cut -d: -f6)"
[[ -n "$TARGET_HOME" && -d "$TARGET_HOME" ]] || err "Home directory '$TARGET_HOME' does not exist."

info "Mode: $MODE"
info "Target user: $TARGET_USER (home: $TARGET_HOME)"

# =============================================================================
# 1. COMMON: Container-specific sysctl settings
# =============================================================================

msg "Configuring container sysctl settings..."
modprobe br_netfilter 2>/dev/null || true

install -d -m 0755 /etc/sysctl.d /etc/modules-load.d
cat > /etc/sysctl.d/90-container.conf <<'SYSCTL'
# Container networking: allow netfilter to process bridged traffic
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
SYSCTL
chmod 0644 /etc/sysctl.d/90-container.conf

if [[ ! -f /etc/modules-load.d/br_netfilter.conf ]]; then
    echo "br_netfilter" > /etc/modules-load.d/br_netfilter.conf
    chmod 0644 /etc/modules-load.d/br_netfilter.conf
fi

sysctl --system >/dev/null 2>&1 || true
msg "sysctl settings applied (bridge-nf-call-iptables/ip6tables)"

# =============================================================================
# DOCKER MODE
# =============================================================================

if [[ "$MODE" == "docker" ]]; then

    msg "Installing Docker..."
    pacman -Syu --noconfirm --needed docker docker-compose

    DOCKER_VER=$(docker --version)
    info "$DOCKER_VER"

    msg "Writing hardened /etc/docker/daemon.json..."
    install -d -m 0755 /etc/docker

    # Keep Docker's maintained built-in seccomp profile rather than fetching an
    # unpinned static JSON file from GitHub master that goes stale across upgrades.
    # default-ulimits entries need "Name": dockerd passes it on as RLIMIT_<NAME>,
    # and an entry without it makes every container start fail.
    install_config 0600 /etc/docker/daemon.json <<'EOF'
{
    "icc": false,
    "no-new-privileges": true,
    "userland-proxy": false,
    "live-restore": true,
    "log-driver": "json-file",
    "log-opts": {
        "max-size": "10m",
        "max-file": "3"
    },
    "storage-driver": "overlay2",
    "default-ulimits": {
        "nofile": { "Name": "nofile", "Hard": 64000, "Soft": 64000 },
        "nproc":  { "Name": "nproc",  "Hard": 4096,  "Soft": 4096  }
    },
    "default-address-pools": [
        { "base": "172.17.0.0/16", "size": 24 }
    ],
    "iptables": true,
    "ip-forward": true,
    "ip-masq": true
}
EOF
    if daemon_validate_out="$(dockerd --validate --config-file /etc/docker/daemon.json 2>&1)"; then
        msg "daemon.json written with hardened defaults (validated by dockerd)"
    else
        printf '%s\n' "$daemon_validate_out" >&2
        err "dockerd rejected /etc/docker/daemon.json; docker.service was left untouched."
    fi

    if ! getent group docker &>/dev/null; then
        groupadd docker
    fi

    if id -nG "$TARGET_USER" | grep -qw docker; then
        info "User '$TARGET_USER' is already in the docker group"
    else
        usermod -aG docker "$TARGET_USER"
        msg "User '$TARGET_USER' added to docker group"
    fi

    echo
    echo -e "${C_YELLOW}========================================================================${C_NC}"
    echo -e "${C_YELLOW} SECURITY WARNING: docker group membership${C_NC}"
    echo -e "${C_YELLOW}========================================================================${C_NC}"
    echo -e "${C_YELLOW} Members of the 'docker' group have effective root access on the host.${C_NC}"
    echo -e "${C_YELLOW} Only add trusted users. Consider rootless Podman as an alternative.${C_NC}"
    echo -e "${C_YELLOW}========================================================================${C_NC}"
    echo

    msg "Creating systemd override for docker.service..."
    install -d -m 0755 /etc/systemd/system/docker.service.d

    # The packaged unit runs "dockerd -H fd:// --containerd=/run/containerd/containerd.sock"
    # and is intentionally not sandboxed: dockerd mounts container root filesystems
    # and network namespaces that containerd/runc (other units) must see, writes
    # /run/docker.pid and /run/docker, and unpacks image layers that contain
    # setuid files. ProtectSystem=, ProtectHome=, ReadWritePaths=, ProtectKernelLogs=
    # (private mount namespace) and RestrictSUIDSGID= break container start or
    # image pulls, so containment comes from daemon.json above instead.
    cat > /etc/systemd/system/docker.service.d/hardened.conf <<'EOF'
[Service]
LockPersonality=true

LimitNOFILE=1048576
LimitNPROC=infinity
LimitCORE=0
EOF
    chmod 0644 /etc/systemd/system/docker.service.d/hardened.conf

    systemctl daemon-reload
    msg "systemd override created (resource limits, no core dumps)"

    msg "Enabling and starting Docker..."
    systemctl enable docker.service
    systemctl restart docker.service
    msg "Docker service enabled and started"

    msg "Verifying Docker installation..."
    echo
    docker_info_out="$(docker info 2>&1 || true)"
    sed -n '1,30p' <<<"$docker_info_out"
    echo "..."
    msg "Docker info output shown above (truncated)"

fi

# =============================================================================
# PODMAN MODE
# =============================================================================

if [[ "$MODE" == "podman" ]]; then

    userns_val="$(sysctl -n kernel.unprivileged_userns_clone 2>/dev/null || echo 1)"
    if [[ "$userns_val" == "0" ]]; then
        warn "kernel.unprivileged_userns_clone=0 (strict sysctl profile): rootless Podman requires user namespaces!"
        warn "Switch to workstation profile: sudo ./hardening/sysctl/sysctl.sh workstation"
    fi

    msg "Installing Podman ecosystem packages..."
    pacman -Syu --noconfirm --needed \
        podman \
        podman-compose \
        buildah \
        skopeo \
        slirp4netns \
        fuse-overlayfs \
        crun

    PODMAN_VER=$(podman --version)
    info "$PODMAN_VER"

    msg "Configuring rootless Podman for user '$TARGET_USER'..."

    if getent group proc >/dev/null 2>&1; then
        gpasswd -a "$TARGET_USER" proc >/dev/null 2>&1 || true
    fi

    SUBID_COUNT=65536
    for MAP_FILE in /etc/subuid /etc/subgid; do
        touch "$MAP_FILE"
        chmod 0644 "$MAP_FILE"
        if ! grep -q "^${TARGET_USER}:" "$MAP_FILE" 2>/dev/null; then
            next_start=$(awk -F: '
                BEGIN { max_end = 100000 }
                $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ {
                    end = $2 + $3
                    if (end > max_end) max_end = end
                }
                END { print max_end }
            ' "$MAP_FILE")
            echo "${TARGET_USER}:${next_start}:${SUBID_COUNT}" >> "$MAP_FILE"
            msg "Added $TARGET_USER to $MAP_FILE (${next_start}:${SUBID_COUNT})"
        else
            info "$TARGET_USER already has entry in $MAP_FILE"
        fi
    done

    USER_CONTAINERS_DIR="${TARGET_HOME}/.config/containers"
    runuser -u "$TARGET_USER" -- mkdir -p -m 0700 "${TARGET_HOME}/.config" "$USER_CONTAINERS_DIR"

    # Written as the target user: root must never write through a path (or
    # symlink) that the user controls. A differing storage.conf is backed up.
    runuser -u "$TARGET_USER" -- bash -c '
        set -euo pipefail
        umask 077
        tmp="$(mktemp "$1.XXXXXX")"
        cat > "$tmp"
        if [[ -e "$1" || -L "$1" ]] && ! cmp -s -- "$1" "$tmp"; then
            cp -a -- "$1" "$1.bak.$(date +%Y%m%d%H%M%S)"
        fi
        mv -f -- "$tmp" "$1"
    ' _ "${USER_CONTAINERS_DIR}/storage.conf" <<'EOF'
[storage]
driver = "overlay"

[storage.options.overlay]
mount_program = "/usr/bin/fuse-overlayfs"
EOF
    msg "User storage.conf configured (overlay + fuse-overlayfs)"

    msg "Writing hardened /etc/containers/containers.conf..."
    install -d -m 0755 /etc/containers

    install_config 0644 /etc/containers/containers.conf <<'EOF'
[containers]
no_new_privileges = true
default_ulimits = [
    "nofile=64000:64000",
]
pids_limit = 2048
log_driver = "journald"

[engine]
runtime = "crun"
events_logger = "journald"
EOF
    msg "containers.conf written with hardened defaults"

    msg "Writing hardened /etc/containers/registries.conf..."
    # v2 format only: a v1 table such as [registries.insecure] next to these keys
    # makes Podman reject the whole file. Registries are TLS-verified unless a
    # [[registry]] entry sets insecure = true, so nothing has to be listed here.
    install_config 0644 /etc/containers/registries.conf <<'EOF'
unqualified-search-registries = ["docker.io"]
short-name-mode = "enforcing"
EOF
    msg "registries.conf written (short-name-mode=enforcing, no insecure registries)"

    msg "Enabling podman.socket and podman-auto-update.timer for user '$TARGET_USER'..."
    systemctl --user -M "${TARGET_USER}@" enable podman.socket 2>/dev/null || \
        warn "Could not enable podman.socket live — run after login: systemctl --user enable podman.socket"
    systemctl --user -M "${TARGET_USER}@" enable podman-auto-update.timer 2>/dev/null || \
        warn "Could not enable podman-auto-update.timer live — run after login: systemctl --user enable podman-auto-update.timer"

    msg "Verifying Podman installation..."
    echo
    if podman_info_out="$(runuser -u "$TARGET_USER" -- env HOME="$TARGET_HOME" podman info 2>&1)"; then
        sed -n '1,30p' <<<"$podman_info_out"
        echo "..."
        msg "Podman info output shown above (truncated)"
    else
        sed -n '1,10p' <<<"$podman_info_out" >&2
        warn "podman info failed (output above) — a new subuid/subgid range needs a fresh login session"
    fi

fi

# =============================================================================
# SECURITY BEST PRACTICES REMINDER
# =============================================================================

echo
echo -e "${C_BLUE}========================================================================${C_NC}"
echo -e "${C_BLUE} Container Security Best Practices${C_NC}"
echo -e "${C_BLUE}========================================================================${C_NC}"
echo
echo -e "${C_GREEN} 1.${C_NC} Use read-only root filesystem where possible: --read-only"
echo -e "${C_GREEN} 2.${C_NC} Drop all capabilities and add only what is needed: --cap-drop=ALL"
echo -e "${C_GREEN} 3.${C_NC} Run as non-root inside containers: --user 1000:1000"
echo -e "${C_GREEN} 4.${C_NC} Scan images for vulnerabilities before deploying: trivy image <img:tag>"
echo -e "${C_GREEN} 5.${C_NC} Pin immutable image tags/digests, never :latest in production"
echo -e "${C_GREEN} 6.${C_NC} Limit container resources: --memory=512m --cpus=1.0 --pids-limit=256"
echo -e "${C_GREEN} 7.${C_NC} Use tmpfs for sensitive ephemeral data: --tmpfs /tmp:rw,noexec,nosuid,size=64m"
echo -e "${C_GREEN} 8.${C_NC} Keep Docker/Podman default seccomp and AppArmor profiles enabled"
echo -e "${C_GREEN} 9.${C_NC} Never store secrets in images — use runtime secrets management"
echo -e "${C_GREEN}10.${C_NC} Keep images minimal — use distroless or minimal base images"
echo
echo -e "${C_GREEN}Done.${C_NC}"
