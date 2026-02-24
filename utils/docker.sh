#!/usr/bin/env bash

# =============================================================================
# Script:      docker.sh
# Description: Docker/Podman hardening script for Arch Linux.
#
#              Supports two container runtimes:
#
#              PODMAN (default, recommended):
#                - Daemonless, rootless by default — no privileged daemon
#                - Fork/exec model: each container is a child process
#                - Uses crun (faster, lower memory than runc)
#                - Compatible with Docker CLI commands and Compose files
#                - OCI-compliant images work with Docker and Podman alike
#                - Trade-off: some Docker ecosystem tools assume dockerd
#
#              DOCKER:
#                - Client/server model with a privileged root daemon (dockerd)
#                - Larger ecosystem: Docker Hub, Docker Desktop, Compose v2
#                - Broader third-party tool support (CI/CD, monitoring, etc.)
#                - Trade-off: the daemon runs as root — a container escape
#                  means root on the host unless mitigated
#
#              Both modes apply sysctl hardening, restricted ulimits, logging
#              configuration, and seccomp/capability best practices.
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
#
# Usage:       sudo ./docker.sh [--docker|--podman] [-u USERNAME] [-h]
#
#              --podman   (default) Install and configure rootless Podman
#              --docker   Install and configure hardened Docker
#              -u USER    Target user (default: $SUDO_USER)
#              -h         Show help
#
# Requirements:
#   - Arch Linux with pacman
#   - Root privileges (sudo)
# =============================================================================

set -euo pipefail

# --- Colors ---
readonly C_BLUE='\033[1;34m'
readonly C_RED='\033[1;31m'
readonly C_GREEN='\033[1;32m'
readonly C_YELLOW='\033[1;33m'
readonly C_NC='\033[0m'

msg()  { printf "%b[+]%b %s\n" "$C_GREEN"  "$C_NC" "$1"; }
info() { printf "%b[*]%b %s\n" "$C_BLUE"   "$C_NC" "$1"; }
warn() { printf "%b[!]%b %s\n" "$C_YELLOW" "$C_NC" "$1"; }
err()  { printf "%b[!]%b %s\n" "$C_RED"    "$C_NC" "$1" >&2; exit 1; }

# --- Defaults ---
MODE="podman"
TARGET_USER="${SUDO_USER:-}"

# --- Usage ---
usage() {
    cat <<EOF
Usage: sudo $0 [--docker|--podman] [-u USERNAME] [-h]

Modes:
  --podman    (default) Install and configure rootless Podman
  --docker    Install and configure hardened Docker

Options:
  -u USER     Target user for group membership / rootless setup
              (default: \$SUDO_USER)
  -h, --help  Show this help

Examples:
  sudo $0                        # Podman (default) for current sudo user
  sudo $0 --podman -u alice      # Podman for user alice
  sudo $0 --docker               # Docker for current sudo user
  sudo $0 --docker -u bob        # Docker for user bob
EOF
    exit 0
}

# --- Parse Arguments ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --docker)   MODE="docker";  shift ;;
        --podman)   MODE="podman";  shift ;;
        -u)         TARGET_USER="$2"; shift 2 ;;
        -h|--help)  usage ;;
        *)          err "Unknown option: $1. See -h for help." ;;
    esac
done

# --- Validate ---
[[ $(id -u) -eq 0 ]] || err "Must be run as root (use sudo)"

if [[ -z "$TARGET_USER" ]]; then
    err "Cannot determine target user. Pass -u USERNAME or run via sudo."
fi

if ! id "$TARGET_USER" &>/dev/null; then
    err "User '$TARGET_USER' does not exist."
fi

TARGET_HOME="$(eval echo "~${TARGET_USER}")"

info "Mode: $MODE"
info "Target user: $TARGET_USER (home: $TARGET_HOME)"

# =============================================================================
# 1. COMMON: Container-specific sysctl settings
# =============================================================================

msg "Configuring container sysctl settings..."

# Ensure the bridge module is loaded so the sysctl keys exist
modprobe br_netfilter 2>/dev/null || true

cat > /etc/sysctl.d/90-container.conf <<'SYSCTL'
# Container networking: allow iptables to process bridged traffic
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
SYSCTL

# Ensure br_netfilter loads at boot
if [[ ! -f /etc/modules-load.d/br_netfilter.conf ]]; then
    echo "br_netfilter" > /etc/modules-load.d/br_netfilter.conf
fi

sysctl --system >/dev/null 2>&1
msg "sysctl settings applied (bridge-nf-call-iptables/ip6tables)"

# =============================================================================
# DOCKER MODE
# =============================================================================

if [[ "$MODE" == "docker" ]]; then

    # -----------------------------------------------------------------
    # 2. Install Docker
    # -----------------------------------------------------------------
    msg "Installing Docker..."
    pacman -Syu --noconfirm --needed docker docker-compose

    DOCKER_VER=$(docker --version)
    info "$DOCKER_VER"

    # -----------------------------------------------------------------
    # 3. Hardened daemon.json
    # -----------------------------------------------------------------
    msg "Writing hardened /etc/docker/daemon.json..."
    mkdir -p /etc/docker

    # Build the JSON — conditionally include seccomp-profile if available
    SECCOMP_LINE=""
    if [[ -f /etc/docker/seccomp-default.json ]]; then
        SECCOMP_LINE='"seccomp-profile": "/etc/docker/seccomp-default.json",'
    fi

    cat > /etc/docker/daemon.json <<EOF
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
        "nofile": { "Hard": 64000, "Soft": 64000 },
        "nproc":  { "Hard": 4096,  "Soft": 4096  }
    },
    ${SECCOMP_LINE}
    "default-address-pools": [
        { "base": "172.17.0.0/16", "size": 24 }
    ],
    "iptables": true,
    "ip-forward": true,
    "ip-masq": true
}
EOF

    chmod 600 /etc/docker/daemon.json
    msg "daemon.json written with hardened defaults"

    # -----------------------------------------------------------------
    # 4. Add user to docker group (with security warning)
    # -----------------------------------------------------------------
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

    # -----------------------------------------------------------------
    # 5. Enable Docker Content Trust
    # -----------------------------------------------------------------
    msg "Enabling Docker Content Trust (DOCKER_CONTENT_TRUST=1)..."

    if grep -q "DOCKER_CONTENT_TRUST" /etc/environment 2>/dev/null; then
        sed -i 's/^DOCKER_CONTENT_TRUST=.*/DOCKER_CONTENT_TRUST=1/' /etc/environment
    else
        echo "DOCKER_CONTENT_TRUST=1" >> /etc/environment
    fi

    msg "DOCKER_CONTENT_TRUST=1 set in /etc/environment"

    # -----------------------------------------------------------------
    # 6. Seccomp default profile
    # -----------------------------------------------------------------
    msg "Setting up default seccomp profile..."

    if [[ ! -f /etc/docker/seccomp-default.json ]]; then
        # Fetch the official Docker default seccomp profile
        SECCOMP_URL="https://raw.githubusercontent.com/moby/moby/master/profiles/seccomp/default.json"
        if curl -fsSL "$SECCOMP_URL" -o /etc/docker/seccomp-default.json 2>/dev/null; then
            chmod 644 /etc/docker/seccomp-default.json
            msg "Default seccomp profile downloaded to /etc/docker/seccomp-default.json"

            # Now update daemon.json to include the seccomp profile
            # Re-write with the seccomp line included
            cat > /etc/docker/daemon.json <<'EOF'
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
        "nofile": { "Hard": 64000, "Soft": 64000 },
        "nproc":  { "Hard": 4096,  "Soft": 4096  }
    },
    "seccomp-profile": "/etc/docker/seccomp-default.json",
    "default-address-pools": [
        { "base": "172.17.0.0/16", "size": 24 }
    ],
    "iptables": true,
    "ip-forward": true,
    "ip-masq": true
}
EOF
            chmod 600 /etc/docker/daemon.json
            msg "daemon.json updated with seccomp-profile path"
        else
            warn "Could not download seccomp profile — continuing without it"
            warn "You can manually place a profile at /etc/docker/seccomp-default.json"
        fi
    else
        info "Seccomp profile already exists at /etc/docker/seccomp-default.json"
    fi

    # -----------------------------------------------------------------
    # 7. Harden Docker systemd service with override
    # -----------------------------------------------------------------
    msg "Creating hardened systemd override for docker.service..."

    mkdir -p /etc/systemd/system/docker.service.d

    cat > /etc/systemd/system/docker.service.d/hardened.conf <<'EOF'
[Service]
# Restrict filesystem access
ProtectHome=read-only
ProtectSystem=strict
ReadWritePaths=/var/lib/docker /etc/docker /run/docker /run/docker.sock

# Restrict kernel and hardware access
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true

# Restrict misc capabilities
NoNewPrivileges=false
RestrictSUIDSGID=true
MemoryDenyWriteExecute=false

# Limit resources
LimitNOFILE=1048576
LimitNPROC=infinity
LimitCORE=infinity

# Restrict network namespaces — Docker needs them, but restrict others
RestrictNamespaces=~user
EOF

    systemctl daemon-reload
    msg "systemd hardened override created"

    # -----------------------------------------------------------------
    # 8. Enable and start Docker
    # -----------------------------------------------------------------
    msg "Enabling and starting Docker..."
    systemctl enable docker.service
    systemctl restart docker.service
    msg "Docker service enabled and started"

    # -----------------------------------------------------------------
    # 9. Verify with docker info
    # -----------------------------------------------------------------
    msg "Verifying Docker installation..."
    echo
    docker info 2>&1 | head -30
    echo "..."
    msg "Docker info output shown above (truncated)"

fi  # end Docker mode

# =============================================================================
# PODMAN MODE
# =============================================================================

if [[ "$MODE" == "podman" ]]; then

    # -----------------------------------------------------------------
    # 2. Install Podman and friends
    # -----------------------------------------------------------------
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

    # -----------------------------------------------------------------
    # 3. Configure rootless Podman for user
    # -----------------------------------------------------------------
    msg "Configuring rootless Podman for user '$TARGET_USER'..."

    # Ensure subuid/subgid entries exist
    TARGET_UID=$(id -u "$TARGET_USER")
    SUBID_START=$(( TARGET_UID * 65536 ))
    SUBID_COUNT=65536

    for MAP_FILE in /etc/subuid /etc/subgid; do
        if ! grep -q "^${TARGET_USER}:" "$MAP_FILE" 2>/dev/null; then
            echo "${TARGET_USER}:${SUBID_START}:${SUBID_COUNT}" >> "$MAP_FILE"
            msg "Added $TARGET_USER to $MAP_FILE (${SUBID_START}:${SUBID_COUNT})"
        else
            info "$TARGET_USER already has entry in $MAP_FILE"
        fi
    done

    # Create user storage config for rootless overlay with fuse-overlayfs
    USER_CONTAINERS_DIR="${TARGET_HOME}/.config/containers"
    mkdir -p "$USER_CONTAINERS_DIR"

    cat > "${USER_CONTAINERS_DIR}/storage.conf" <<'EOF'
[storage]
driver = "overlay"

[storage.options.overlay]
mount_program = "/usr/bin/fuse-overlayfs"
EOF

    chown -R "${TARGET_USER}:${TARGET_USER}" "${USER_CONTAINERS_DIR}"
    msg "User storage.conf configured (overlay + fuse-overlayfs)"

    # -----------------------------------------------------------------
    # 4. Configure /etc/containers/containers.conf
    # -----------------------------------------------------------------
    msg "Writing hardened /etc/containers/containers.conf..."
    mkdir -p /etc/containers

    cat > /etc/containers/containers.conf <<'EOF'
[containers]
# Security: prevent privilege escalation inside containers
no_new_privileges = true

# Resource limits
default_ulimits = [
    "nofile=64000:64000",
]
pids_limit = 2048

# Logging
log_driver = "journald"

[engine]
# Use crun: faster startup, lower memory footprint than runc
runtime = "crun"

# Use journald for engine events
events_logger = "journald"
EOF

    chmod 644 /etc/containers/containers.conf
    msg "containers.conf written with hardened defaults"

    # -----------------------------------------------------------------
    # 5. Configure /etc/containers/registries.conf
    # -----------------------------------------------------------------
    msg "Writing hardened /etc/containers/registries.conf..."

    cat > /etc/containers/registries.conf <<'EOF'
# Search only Docker Hub by default
unqualified-search-registries = ["docker.io"]

# Require fully qualified image names (e.g., docker.io/library/nginx:latest)
short-name-mode = "enforcing"

# Block insecure (HTTP) registries globally
[registries.insecure]
registries = []
EOF

    chmod 644 /etc/containers/registries.conf
    msg "registries.conf written (short-name-mode=enforcing, no insecure registries)"

    # -----------------------------------------------------------------
    # 6. Enable podman socket for user
    # -----------------------------------------------------------------
    msg "Enabling podman.socket for user '$TARGET_USER'..."

    # Run systemctl --user as the target user via machinectl / su
    if command -v machinectl &>/dev/null; then
        machinectl shell "${TARGET_USER}@.host" /usr/bin/systemctl --user enable podman.socket 2>/dev/null || \
            su - "$TARGET_USER" -c "systemctl --user enable podman.socket" 2>/dev/null || \
            warn "Could not enable podman.socket — user may need to run: systemctl --user enable podman.socket"
    else
        su - "$TARGET_USER" -c "systemctl --user enable podman.socket" 2>/dev/null || \
            warn "Could not enable podman.socket — user may need to run: systemctl --user enable podman.socket"
    fi

    msg "podman.socket enabled (provides Docker-compatible API)"

    # -----------------------------------------------------------------
    # 7. Enable podman auto-update timer for user
    # -----------------------------------------------------------------
    msg "Enabling podman-auto-update.timer for user '$TARGET_USER'..."

    if command -v machinectl &>/dev/null; then
        machinectl shell "${TARGET_USER}@.host" /usr/bin/systemctl --user enable podman-auto-update.timer 2>/dev/null || \
            su - "$TARGET_USER" -c "systemctl --user enable podman-auto-update.timer" 2>/dev/null || \
            warn "Could not enable podman-auto-update.timer — user may need to run: systemctl --user enable podman-auto-update.timer"
    else
        su - "$TARGET_USER" -c "systemctl --user enable podman-auto-update.timer" 2>/dev/null || \
            warn "Could not enable podman-auto-update.timer — user may need to run: systemctl --user enable podman-auto-update.timer"
    fi

    msg "podman-auto-update.timer enabled"

    # -----------------------------------------------------------------
    # 8. Verify with podman info
    # -----------------------------------------------------------------
    msg "Verifying Podman installation..."
    echo

    # Run podman info as the target user to verify rootless setup
    su - "$TARGET_USER" -c "podman info" 2>&1 | head -30 || \
        warn "podman info failed — user may need to log out and back in"
    echo "..."
    msg "Podman info output shown above (truncated)"

fi  # end Podman mode

# =============================================================================
# SECURITY BEST PRACTICES REMINDER
# =============================================================================

echo
echo -e "${C_BLUE}========================================================================${C_NC}"
echo -e "${C_BLUE} Container Security Best Practices${C_NC}"
echo -e "${C_BLUE}========================================================================${C_NC}"
echo
echo -e "${C_GREEN} 1.${C_NC} Use read-only root filesystem where possible:"
echo "      docker run --read-only ..."
echo "      podman run --read-only ..."
echo
echo -e "${C_GREEN} 2.${C_NC} Drop all capabilities and add only what is needed:"
echo "      --cap-drop=ALL --cap-add=NET_BIND_SERVICE"
echo
echo -e "${C_GREEN} 3.${C_NC} Run as non-root inside containers:"
echo "      USER nonroot   (in Dockerfile)"
echo "      --user 1000:1000"
echo
echo -e "${C_GREEN} 4.${C_NC} Scan images for vulnerabilities before deploying:"
echo "      trivy image myimage:latest"
echo "      grype myimage:latest"
echo
echo -e "${C_GREEN} 5.${C_NC} Use specific image tags, never :latest in production"
echo
echo -e "${C_GREEN} 6.${C_NC} Limit container resources:"
echo "      --memory=512m --cpus=1.0 --pids-limit=256"
echo
echo -e "${C_GREEN} 7.${C_NC} Use tmpfs for sensitive ephemeral data:"
echo "      --tmpfs /tmp:rw,noexec,nosuid,size=64m"
echo
echo -e "${C_GREEN} 8.${C_NC} Enable seccomp, AppArmor, or SELinux profiles"
echo
echo -e "${C_GREEN} 9.${C_NC} Never store secrets in images — use secrets management:"
echo "      docker secret, podman secret, or external vault"
echo
echo -e "${C_GREEN}10.${C_NC} Keep images minimal — use distroless or Alpine base images"
echo

# =============================================================================
# SUMMARY
# =============================================================================

echo -e "${C_GREEN}========================================================================${C_NC}"
echo -e "${C_GREEN} Setup Complete!${C_NC}"
echo -e "${C_GREEN}========================================================================${C_NC}"
echo

if [[ "$MODE" == "docker" ]]; then
    echo -e "${C_BLUE}Runtime:${C_NC}           Docker"
    echo -e "${C_BLUE}User:${C_NC}              $TARGET_USER"
    echo -e "${C_BLUE}Daemon config:${C_NC}     /etc/docker/daemon.json"
    echo -e "${C_BLUE}Seccomp profile:${C_NC}   /etc/docker/seccomp-default.json"
    echo -e "${C_BLUE}Content trust:${C_NC}     DOCKER_CONTENT_TRUST=1 (in /etc/environment)"
    echo -e "${C_BLUE}Service:${C_NC}           docker.service (enabled, hardened override)"
    echo -e "${C_BLUE}ICC:${C_NC}               Disabled (containers isolated by default)"
    echo -e "${C_BLUE}Storage driver:${C_NC}    overlay2"
    echo -e "${C_BLUE}Log driver:${C_NC}        json-file (10m max, 3 files)"
    echo
    echo -e "${C_YELLOW}NOTE: User '$TARGET_USER' must log out and back in for${C_NC}"
    echo -e "${C_YELLOW}docker group membership to take effect.${C_NC}"
else
    echo -e "${C_BLUE}Runtime:${C_NC}           Podman (rootless)"
    echo -e "${C_BLUE}OCI runtime:${C_NC}       crun"
    echo -e "${C_BLUE}User:${C_NC}              $TARGET_USER"
    echo -e "${C_BLUE}Storage driver:${C_NC}    overlay (fuse-overlayfs)"
    echo -e "${C_BLUE}System config:${C_NC}     /etc/containers/containers.conf"
    echo -e "${C_BLUE}Registry config:${C_NC}   /etc/containers/registries.conf"
    echo -e "${C_BLUE}User config:${C_NC}       ${TARGET_HOME}/.config/containers/storage.conf"
    echo -e "${C_BLUE}Log driver:${C_NC}        journald"
    echo -e "${C_BLUE}Pids limit:${C_NC}        2048 per container"
    echo -e "${C_BLUE}Socket:${C_NC}            podman.socket (user, Docker-compatible API)"
    echo -e "${C_BLUE}Auto-update:${C_NC}       podman-auto-update.timer (user)"
    echo
    echo -e "${C_YELLOW}NOTE: User '$TARGET_USER' must log out and back in for${C_NC}"
    echo -e "${C_YELLOW}subuid/subgid changes and user services to take full effect.${C_NC}"
fi

echo
echo -e "${C_GREEN}Done.${C_NC}"
