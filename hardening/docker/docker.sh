#!/usr/bin/env bash

# =============================================================================
# Script:      docker.sh
# Description: Docker container runtime security hardening for Arch Linux.
#
#              This script focuses on runtime container security, image
#              scanning, and compose hardening. It complements the installation
#              and daemon configuration script at utils/docker.sh.
#
#              Features:
#                - CIS Docker Benchmark audit (daemon + running containers)
#                - Image vulnerability scanning via Trivy
#                - Docker Compose security auditing
#                - Docker network hardening with nftables
#                - Hardened AppArmor profile for containers
#                - Tightened seccomp profile blocking dangerous syscalls
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
#
# Usage:       sudo ./docker.sh [--scan] [--bench] [--compose PATH]
#                                [--network] [-h]
#
#              --bench          Run CIS Docker Benchmark security audit
#              --scan           Scan all local images with Trivy
#              --compose PATH   Audit a docker-compose.yml for security issues
#              --network        Generate Docker network hardening rules
#              -h, --help       Show this help
#
#              With no flags the script generates AppArmor and seccomp
#              profiles and prints a security summary.
#
# Requirements:
#   - Arch Linux with pacman
#   - Root privileges (sudo)
#   - Docker or Podman installed (utils/docker.sh)
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
DO_BENCH=false
DO_SCAN=false
DO_COMPOSE=false
DO_NETWORK=false
COMPOSE_PATH=""
LOGFILE="/var/log/docker-security-$(date +%Y%m%d-%H%M%S).log"

# CIS Bench scoring
BENCH_PASS=0
BENCH_WARN=0
BENCH_FAIL=0

# Track generated files
declare -a GENERATED_FILES=()

# --- Usage ---
usage() {
    cat <<EOF
Usage: sudo $0 [options]

Modes:
  --bench          Run CIS Docker Benchmark security audit
  --scan           Scan all local images with Trivy
  --compose PATH   Audit a docker-compose.yml for security issues
  --network        Generate Docker network hardening rules

Options:
  -h, --help       Show this help

With no flags the script generates hardened AppArmor and seccomp
profiles and prints a security summary.

Examples:
  sudo $0 --bench                         # CIS benchmark audit
  sudo $0 --scan                          # Scan all images
  sudo $0 --compose /opt/app/docker-compose.yml
  sudo $0 --network                       # Generate nftables rules
  sudo $0 --bench --scan --network        # All checks
EOF
    exit 0
}

# --- Parse Arguments ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --bench)     DO_BENCH=true;   shift ;;
        --scan)      DO_SCAN=true;    shift ;;
        --compose)   DO_COMPOSE=true; COMPOSE_PATH="$2"; shift 2 ;;
        --network)   DO_NETWORK=true; shift ;;
        -h|--help)   usage ;;
        *)           err "Unknown option: $1. See -h for help." ;;
    esac
done

# --- Validate ---
[[ $(id -u) -eq 0 ]] || err "Must be run as root (use sudo)"

# --- Detect container runtime ---
RUNTIME=""
if command -v docker &>/dev/null; then
    RUNTIME="docker"
elif command -v podman &>/dev/null; then
    RUNTIME="podman"
else
    err "Neither docker nor podman found. Install one first (see utils/docker.sh)."
fi

info "Detected container runtime: $RUNTIME"
info "Log: $LOGFILE"

# Redirect output to logfile as well
exec > >(tee -a "$LOGFILE") 2>&1

# =============================================================================
# HELPER: CIS Bench result functions
# =============================================================================

bench_pass() {
    printf "  %b[PASS]%b %s\n" "$C_GREEN" "$C_NC" "$1"
    ((BENCH_PASS++))
}

bench_warn() {
    printf "  %b[WARN]%b %s\n" "$C_YELLOW" "$C_NC" "$1"
    ((BENCH_WARN++))
}

bench_fail() {
    printf "  %b[FAIL]%b %s\n" "$C_RED" "$C_NC" "$1"
    ((BENCH_FAIL++))
}

# =============================================================================
# 1. VERIFY RUNTIME IS INSTALLED
# =============================================================================

msg "Verifying container runtime..."

if [[ "$RUNTIME" == "docker" ]]; then
    DOCKER_VER=$(docker --version 2>/dev/null || echo "unknown")
    info "$DOCKER_VER"
    if ! systemctl is-active --quiet docker.service 2>/dev/null; then
        warn "Docker daemon is not running. Some checks may fail."
    fi
elif [[ "$RUNTIME" == "podman" ]]; then
    PODMAN_VER=$(podman --version 2>/dev/null || echo "unknown")
    info "$PODMAN_VER"
fi

# =============================================================================
# 2. --bench: CIS Docker Benchmark Security Audit
# =============================================================================

if [[ "$DO_BENCH" == true ]]; then

    echo
    echo -e "${C_BLUE}========================================================================${C_NC}"
    echo -e "${C_BLUE} CIS Docker Benchmark Security Audit${C_NC}"
    echo -e "${C_BLUE}========================================================================${C_NC}"
    echo

    # -----------------------------------------------------------------
    # 2.1 Daemon Configuration Checks
    # -----------------------------------------------------------------
    msg "Section 1: Daemon Configuration"

    # 1.1 Audit rules for Docker files
    info "1.1 - Checking audit rules for Docker files..."

    AUDIT_PATHS=(
        "/usr/bin/docker"
        "/usr/bin/dockerd"
        "/var/lib/docker"
        "/etc/docker"
        "/usr/lib/systemd/system/docker.service"
        "/usr/lib/systemd/system/docker.socket"
    )

    for audit_path in "${AUDIT_PATHS[@]}"; do
        if [[ -e "$audit_path" ]]; then
            if command -v auditctl &>/dev/null; then
                if auditctl -l 2>/dev/null | grep -q "$audit_path"; then
                    bench_pass "1.1 - Audit rule exists for $audit_path"
                else
                    bench_warn "1.1 - No audit rule for $audit_path"
                fi
            else
                bench_warn "1.1 - auditctl not found; cannot verify audit rules for $audit_path"
            fi
        fi
    done

    # 1.2 Daemon.json hardening checks
    info "1.2 - Checking daemon.json settings..."

    DAEMON_JSON="/etc/docker/daemon.json"
    if [[ -f "$DAEMON_JSON" ]]; then
        # Check icc
        if grep -q '"icc"[[:space:]]*:[[:space:]]*false' "$DAEMON_JSON"; then
            bench_pass "1.2 - Inter-container communication disabled (icc: false)"
        else
            bench_fail "1.2 - Inter-container communication NOT disabled (icc should be false)"
        fi

        # Check no-new-privileges
        if grep -q '"no-new-privileges"[[:space:]]*:[[:space:]]*true' "$DAEMON_JSON"; then
            bench_pass "1.2 - no-new-privileges enabled"
        else
            bench_fail "1.2 - no-new-privileges NOT enabled"
        fi

        # Check userland-proxy
        if grep -q '"userland-proxy"[[:space:]]*:[[:space:]]*false' "$DAEMON_JSON"; then
            bench_pass "1.2 - Userland proxy disabled"
        else
            bench_warn "1.2 - Userland proxy NOT disabled (userland-proxy should be false)"
        fi

        # Check live-restore
        if grep -q '"live-restore"[[:space:]]*:[[:space:]]*true' "$DAEMON_JSON"; then
            bench_pass "1.2 - Live restore enabled"
        else
            bench_warn "1.2 - Live restore NOT enabled"
        fi
    else
        bench_fail "1.2 - $DAEMON_JSON not found"
    fi

    # 1.3 Content trust
    info "1.3 - Checking Docker Content Trust..."

    if [[ "${DOCKER_CONTENT_TRUST:-}" == "1" ]]; then
        bench_pass "1.3 - DOCKER_CONTENT_TRUST is enabled in current environment"
    elif grep -q "DOCKER_CONTENT_TRUST=1" /etc/environment 2>/dev/null; then
        bench_pass "1.3 - DOCKER_CONTENT_TRUST=1 set in /etc/environment (active after re-login)"
    else
        bench_warn "1.3 - DOCKER_CONTENT_TRUST not enabled"
    fi

    # -----------------------------------------------------------------
    # 2.2 Running Container Checks
    # -----------------------------------------------------------------
    msg "Section 2: Container Runtime"

    if [[ "$RUNTIME" == "docker" ]]; then
        CONTAINERS=$(docker ps -q 2>/dev/null || true)
    else
        CONTAINERS=$(podman ps -q 2>/dev/null || true)
    fi

    if [[ -z "$CONTAINERS" ]]; then
        info "No running containers found. Skipping container runtime checks."
    else
        for CONTAINER_ID in $CONTAINERS; do
            if [[ "$RUNTIME" == "docker" ]]; then
                INSPECT=$(docker inspect "$CONTAINER_ID" 2>/dev/null)
                CNAME=$(echo "$INSPECT" | grep -oP '"Name":\s*"/\K[^"]+' | head -1)
            else
                INSPECT=$(podman inspect "$CONTAINER_ID" 2>/dev/null)
                CNAME=$(echo "$INSPECT" | grep -oP '"Name":\s*"\K[^"]+' | head -1)
            fi
            CNAME="${CNAME:-$CONTAINER_ID}"

            info "Checking container: $CNAME ($CONTAINER_ID)"

            # 2.1 Running as root
            CONTAINER_USER=$(echo "$INSPECT" | grep -oP '"User":\s*"\K[^"]*' | head -1)
            if [[ -z "$CONTAINER_USER" || "$CONTAINER_USER" == "root" || "$CONTAINER_USER" == "0" ]]; then
                bench_warn "2.1 - Container '$CNAME' is running as root"
            else
                bench_pass "2.1 - Container '$CNAME' runs as non-root user ($CONTAINER_USER)"
            fi

            # 2.2 Privileged mode
            if echo "$INSPECT" | grep -q '"Privileged":\s*true'; then
                bench_fail "2.2 - Container '$CNAME' is running in PRIVILEGED mode"
            else
                bench_pass "2.2 - Container '$CNAME' is not privileged"
            fi

            # 2.3 Host network namespace
            NETMODE=$(echo "$INSPECT" | grep -oP '"NetworkMode":\s*"\K[^"]*' | head -1)
            if [[ "$NETMODE" == "host" ]]; then
                bench_warn "2.3 - Container '$CNAME' uses host network namespace"
            else
                bench_pass "2.3 - Container '$CNAME' does not use host network"
            fi

            # 2.4 Host PID namespace
            PIDMODE=$(echo "$INSPECT" | grep -oP '"PidMode":\s*"\K[^"]*' | head -1)
            if [[ "$PIDMODE" == "host" ]]; then
                bench_fail "2.4 - Container '$CNAME' uses host PID namespace"
            else
                bench_pass "2.4 - Container '$CNAME' does not use host PID namespace"
            fi

            # 2.5 Read-only root filesystem
            if echo "$INSPECT" | grep -q '"ReadonlyRootfs":\s*true'; then
                bench_pass "2.5 - Container '$CNAME' has read-only root filesystem"
            else
                bench_warn "2.5 - Container '$CNAME' does NOT have read-only root filesystem"
            fi

            # 2.6 Excessive capabilities
            CAPS_ADD=$(echo "$INSPECT" | grep -oP '"CapAdd":\s*\[\K[^\]]*' | head -1)
            if [[ -n "$CAPS_ADD" && "$CAPS_ADD" != "null" ]]; then
                bench_warn "2.6 - Container '$CNAME' has added capabilities: $CAPS_ADD"
            else
                bench_pass "2.6 - Container '$CNAME' has no extra capabilities added"
            fi

            # 2.7 Health check
            HEALTHCHECK=$(echo "$INSPECT" | grep -oP '"Healthcheck":\s*\{' | head -1)
            if [[ -z "$HEALTHCHECK" ]]; then
                bench_warn "2.7 - Container '$CNAME' has no health check configured"
            else
                bench_pass "2.7 - Container '$CNAME' has a health check"
            fi

            # 2.8 Memory limits
            MEMORY=$(echo "$INSPECT" | grep -oP '"Memory":\s*\K[0-9]+' | head -1)
            if [[ -z "$MEMORY" || "$MEMORY" == "0" ]]; then
                bench_warn "2.8 - Container '$CNAME' has no memory limit set"
            else
                bench_pass "2.8 - Container '$CNAME' has memory limit: $((MEMORY / 1048576))MB"
            fi

            # 2.9 CPU limits
            NANOC=$(echo "$INSPECT" | grep -oP '"NanoCpus":\s*\K[0-9]+' | head -1)
            CPUSHARES=$(echo "$INSPECT" | grep -oP '"CpuShares":\s*\K[0-9]+' | head -1)
            if [[ (-z "$NANOC" || "$NANOC" == "0") && (-z "$CPUSHARES" || "$CPUSHARES" == "0") ]]; then
                bench_warn "2.9 - Container '$CNAME' has no CPU limit set"
            else
                bench_pass "2.9 - Container '$CNAME' has CPU limits configured"
            fi

            # 2.10 Bind-mounted sensitive paths
            SENSITIVE_PATHS=("/etc" "/proc" "/sys" "/dev" "/var/run/docker.sock")
            MOUNTS=$(echo "$INSPECT" | grep -oP '"Source":\s*"\K[^"]*' || true)
            for SPATH in "${SENSITIVE_PATHS[@]}"; do
                if echo "$MOUNTS" | grep -q "^${SPATH}$\|^${SPATH}/"; then
                    bench_fail "2.10 - Container '$CNAME' has bind mount to sensitive path: $SPATH"
                fi
            done
        done
    fi

    echo
    echo -e "${C_BLUE}--- CIS Bench Summary ---${C_NC}"
    echo -e "  ${C_GREEN}PASS: $BENCH_PASS${C_NC}  ${C_YELLOW}WARN: $BENCH_WARN${C_NC}  ${C_RED}FAIL: $BENCH_FAIL${C_NC}"
    BENCH_TOTAL=$((BENCH_PASS + BENCH_WARN + BENCH_FAIL))
    if [[ "$BENCH_TOTAL" -gt 0 ]]; then
        BENCH_SCORE=$(( (BENCH_PASS * 100) / BENCH_TOTAL ))
        echo -e "  Score: ${BENCH_SCORE}% (${BENCH_PASS}/${BENCH_TOTAL} checks passed)"
    fi
    echo

fi  # end --bench

# =============================================================================
# 3. --scan: Image Security Scanning with Trivy
# =============================================================================

if [[ "$DO_SCAN" == true ]]; then

    echo
    echo -e "${C_BLUE}========================================================================${C_NC}"
    echo -e "${C_BLUE} Image Security Scanning (Trivy)${C_NC}"
    echo -e "${C_BLUE}========================================================================${C_NC}"
    echo

    # -----------------------------------------------------------------
    # 3.1 Install Trivy if not present
    # -----------------------------------------------------------------
    if ! command -v trivy &>/dev/null; then
        msg "Installing Trivy..."

        TRIVY_INSTALLED=false

        # Try AUR helpers first
        if command -v paru &>/dev/null; then
            info "Attempting install via paru (AUR)..."
            if sudo -u "${SUDO_USER:-nobody}" paru -S --noconfirm trivy-bin 2>/dev/null; then
                TRIVY_INSTALLED=true
            fi
        elif command -v yay &>/dev/null; then
            info "Attempting install via yay (AUR)..."
            if sudo -u "${SUDO_USER:-nobody}" yay -S --noconfirm trivy-bin 2>/dev/null; then
                TRIVY_INSTALLED=true
            fi
        fi

        # Fall back to direct binary download
        if [[ "$TRIVY_INSTALLED" == false ]]; then
            info "Downloading Trivy binary from GitHub releases..."
            TRIVY_VERSION=$(curl -fsSL "https://api.github.com/repos/aquasecurity/trivy/releases/latest" \
                | grep -oP '"tag_name":\s*"v\K[^"]+' | head -1)

            if [[ -z "$TRIVY_VERSION" ]]; then
                err "Could not determine latest Trivy version. Check your internet connection."
            fi

            ARCH=$(uname -m)
            case "$ARCH" in
                x86_64)  TRIVY_ARCH="Linux-64bit" ;;
                aarch64) TRIVY_ARCH="Linux-ARM64" ;;
                *)       err "Unsupported architecture: $ARCH" ;;
            esac

            TRIVY_URL="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${TRIVY_ARCH}.tar.gz"
            TMP_DIR=$(mktemp -d)
            curl -fsSL "$TRIVY_URL" -o "$TMP_DIR/trivy.tar.gz"
            tar -xzf "$TMP_DIR/trivy.tar.gz" -C "$TMP_DIR"
            install -m 755 "$TMP_DIR/trivy" /usr/local/bin/trivy
            rm -rf "$TMP_DIR"
            msg "Trivy v${TRIVY_VERSION} installed to /usr/local/bin/trivy"
        fi
    else
        TRIVY_VER=$(trivy --version 2>/dev/null | head -1)
        info "Trivy already installed: $TRIVY_VER"
    fi

    # -----------------------------------------------------------------
    # 3.2 Scan all local images
    # -----------------------------------------------------------------
    msg "Scanning local images for HIGH and CRITICAL vulnerabilities..."

    SCAN_DIR="/var/log/docker-security"
    mkdir -p "$SCAN_DIR"
    SCAN_DATE=$(date +%Y%m%d-%H%M%S)
    SCAN_REPORT="$SCAN_DIR/image-scan-${SCAN_DATE}.json"

    # Initialize JSON report array
    echo "[" > "$SCAN_REPORT"
    FIRST_ENTRY=true

    if [[ "$RUNTIME" == "docker" ]]; then
        IMAGES=$(docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -v '<none>' || true)
    else
        IMAGES=$(podman images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -v '<none>' || true)
    fi

    if [[ -z "$IMAGES" ]]; then
        info "No local images found to scan."
    else
        TOTAL_IMAGES=0
        VULN_IMAGES=0

        while IFS= read -r IMAGE; do
            [[ -z "$IMAGE" ]] && continue
            ((TOTAL_IMAGES++))

            info "Scanning: $IMAGE"

            # Append comma separator for JSON array
            if [[ "$FIRST_ENTRY" == true ]]; then
                FIRST_ENTRY=false
            else
                echo "," >> "$SCAN_REPORT"
            fi

            # Run Trivy scan
            SCAN_OUTPUT=$(trivy image --severity HIGH,CRITICAL --format json "$IMAGE" 2>/dev/null || echo "{}")
            echo "$SCAN_OUTPUT" >> "$SCAN_REPORT"

            # Check for vulnerabilities in output
            VULN_COUNT=$(echo "$SCAN_OUTPUT" | grep -c '"VulnerabilityID"' 2>/dev/null || echo "0")
            if [[ "$VULN_COUNT" -gt 0 ]]; then
                warn "  Found $VULN_COUNT HIGH/CRITICAL vulnerabilities in $IMAGE"
                ((VULN_IMAGES++))
            else
                msg "  No HIGH/CRITICAL vulnerabilities in $IMAGE"
            fi

        done <<< "$IMAGES"

        echo "]" >> "$SCAN_REPORT"
        GENERATED_FILES+=("$SCAN_REPORT")

        echo
        echo -e "${C_BLUE}--- Scan Summary ---${C_NC}"
        echo "  Total images scanned: $TOTAL_IMAGES"
        echo "  Images with vulnerabilities: $VULN_IMAGES"
        echo "  Report: $SCAN_REPORT"
        echo
    fi

    # -----------------------------------------------------------------
    # 3.3 Create systemd timer for weekly image scans
    # -----------------------------------------------------------------
    msg "Creating weekly image scan timer..."

    cat > /usr/local/bin/docker-image-scan.sh <<'SCANSCRIPT'
#!/usr/bin/env bash
# =============================================================================
# Automated Docker image vulnerability scan
# Generated by AwesomeArchLinux/hardening/docker/docker.sh
# =============================================================================

set -euo pipefail

SCAN_DIR="/var/log/docker-security"
mkdir -p "$SCAN_DIR"
SCAN_DATE=$(date +%Y%m%d-%H%M%S)
REPORT="$SCAN_DIR/image-scan-${SCAN_DATE}.json"

# Detect runtime
if command -v docker &>/dev/null; then
    IMAGES=$(docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -v '<none>' || true)
elif command -v podman &>/dev/null; then
    IMAGES=$(podman images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -v '<none>' || true)
else
    echo "No container runtime found" >&2
    exit 1
fi

echo "[" > "$REPORT"
FIRST=true

while IFS= read -r IMAGE; do
    [[ -z "$IMAGE" ]] && continue
    if [[ "$FIRST" == true ]]; then
        FIRST=false
    else
        echo "," >> "$REPORT"
    fi
    trivy image --severity HIGH,CRITICAL --format json "$IMAGE" >> "$REPORT" 2>/dev/null || echo "{}" >> "$REPORT"
done <<< "$IMAGES"

echo "]" >> "$REPORT"

# Clean up old reports (keep last 12)
ls -1t "$SCAN_DIR"/image-scan-*.json 2>/dev/null | tail -n +13 | xargs -r rm -f

echo "Scan complete: $REPORT"
SCANSCRIPT

    chmod 755 /usr/local/bin/docker-image-scan.sh
    GENERATED_FILES+=("/usr/local/bin/docker-image-scan.sh")

    cat > /etc/systemd/system/docker-image-scan.service <<'EOF'
[Unit]
Description=Docker image vulnerability scan (Trivy)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/docker-image-scan.sh
PrivateTmp=true
EOF

    cat > /etc/systemd/system/docker-image-scan.timer <<'EOF'
[Unit]
Description=Weekly Docker image vulnerability scan

[Timer]
OnCalendar=weekly
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable docker-image-scan.timer
    systemctl start docker-image-scan.timer
    GENERATED_FILES+=("/etc/systemd/system/docker-image-scan.service")
    GENERATED_FILES+=("/etc/systemd/system/docker-image-scan.timer")
    msg "Weekly image scan timer enabled: docker-image-scan.timer"

fi  # end --scan

# =============================================================================
# 4. --compose: Harden a docker-compose.yml
# =============================================================================

if [[ "$DO_COMPOSE" == true ]]; then

    echo
    echo -e "${C_BLUE}========================================================================${C_NC}"
    echo -e "${C_BLUE} Docker Compose Security Audit${C_NC}"
    echo -e "${C_BLUE}========================================================================${C_NC}"
    echo

    [[ -f "$COMPOSE_PATH" ]] || err "Compose file not found: $COMPOSE_PATH"

    info "Auditing: $COMPOSE_PATH"
    echo

    COMPOSE_CONTENT=$(cat "$COMPOSE_PATH")
    COMPOSE_ISSUES=0

    # 4.1 Missing read_only: true
    if ! echo "$COMPOSE_CONTENT" | grep -q "read_only:\s*true"; then
        bench_warn "4.1 - Missing 'read_only: true' on one or more services"
        ((COMPOSE_ISSUES++))
    else
        bench_pass "4.1 - 'read_only: true' found"
    fi

    # 4.2 Missing security_opt: [no-new-privileges:true]
    if ! echo "$COMPOSE_CONTENT" | grep -q "no-new-privileges"; then
        bench_warn "4.2 - Missing 'security_opt: [no-new-privileges:true]'"
        ((COMPOSE_ISSUES++))
    else
        bench_pass "4.2 - 'no-new-privileges' security option found"
    fi

    # 4.3 Missing cap_drop: [ALL]
    if ! echo "$COMPOSE_CONTENT" | grep -q "cap_drop"; then
        bench_warn "4.3 - Missing 'cap_drop: [ALL]' — capabilities not dropped"
        ((COMPOSE_ISSUES++))
    else
        bench_pass "4.3 - 'cap_drop' found"
    fi

    # 4.4 Using privileged: true
    if echo "$COMPOSE_CONTENT" | grep -q "privileged:\s*true"; then
        bench_fail "4.4 - Service uses 'privileged: true' — CRITICAL security risk"
        ((COMPOSE_ISSUES++))
    else
        bench_pass "4.4 - No 'privileged: true' found"
    fi

    # 4.5 Using network_mode: host
    if echo "$COMPOSE_CONTENT" | grep -q "network_mode:\s*[\"']*host"; then
        bench_warn "4.5 - Service uses 'network_mode: host' — breaks network isolation"
        ((COMPOSE_ISSUES++))
    else
        bench_pass "4.5 - No 'network_mode: host' found"
    fi

    # 4.6 Binding to 0.0.0.0 instead of 127.0.0.1
    if echo "$COMPOSE_CONTENT" | grep -qE '(0\.0\.0\.0:|"0\.0\.0\.0:|-\s*"?[0-9]+:[0-9])' 2>/dev/null; then
        # Check if any port binding does NOT start with 127.0.0.1
        if echo "$COMPOSE_CONTENT" | grep -E 'ports:' -A 20 | grep -qE '^\s*-\s*"?[0-9]+:' 2>/dev/null; then
            bench_warn "4.6 - Ports may be bound to 0.0.0.0 — prefer 127.0.0.1:PORT:PORT"
            ((COMPOSE_ISSUES++))
        fi
    else
        bench_pass "4.6 - No 0.0.0.0 port bindings detected"
    fi

    # 4.7 Missing mem_limit and cpus
    if ! echo "$COMPOSE_CONTENT" | grep -qE "(mem_limit|memory:)" 2>/dev/null; then
        bench_warn "4.7 - Missing memory limits (mem_limit or deploy.resources.limits.memory)"
        ((COMPOSE_ISSUES++))
    else
        bench_pass "4.7 - Memory limits found"
    fi

    if ! echo "$COMPOSE_CONTENT" | grep -qE "(cpus:|cpu_count:)" 2>/dev/null; then
        bench_warn "4.7 - Missing CPU limits (cpus or deploy.resources.limits.cpus)"
        ((COMPOSE_ISSUES++))
    else
        bench_pass "4.7 - CPU limits found"
    fi

    # 4.8 Missing healthcheck
    if ! echo "$COMPOSE_CONTENT" | grep -q "healthcheck:"; then
        bench_warn "4.8 - Missing 'healthcheck' definition"
        ((COMPOSE_ISSUES++))
    else
        bench_pass "4.8 - 'healthcheck' found"
    fi

    # 4.9 Using :latest tag
    if echo "$COMPOSE_CONTENT" | grep -qE "image:.*:latest"; then
        bench_warn "4.9 - Using ':latest' tag — pin to a specific version"
        ((COMPOSE_ISSUES++))
    else
        bench_pass "4.9 - No ':latest' tag detected"
    fi

    # 4.10 Mounting docker.sock
    if echo "$COMPOSE_CONTENT" | grep -q "docker.sock"; then
        bench_fail "4.10 - Docker socket mounted in container — CRITICAL security risk"
        ((COMPOSE_ISSUES++))
    else
        bench_pass "4.10 - Docker socket not mounted"
    fi

    # 4.11 Missing tmpfs for /tmp
    if ! echo "$COMPOSE_CONTENT" | grep -q "tmpfs:"; then
        bench_warn "4.11 - Missing 'tmpfs' mount for /tmp"
        ((COMPOSE_ISSUES++))
    else
        bench_pass "4.11 - 'tmpfs' mount found"
    fi

    echo
    echo -e "${C_BLUE}--- Compose Audit: $COMPOSE_ISSUES issue(s) found ---${C_NC}"
    echo

    # -----------------------------------------------------------------
    # Generate hardened example compose snippet
    # -----------------------------------------------------------------
    msg "Hardened docker-compose.yml example:"
    echo
    cat <<'EXAMPLE'
# =============================================================================
# Hardened docker-compose.yml — Security Best Practices
# =============================================================================

services:
  app:
    image: myapp:1.2.3                       # Pin specific version, never :latest
    read_only: true                           # Read-only root filesystem
    user: "1000:1000"                         # Run as non-root user

    security_opt:
      - no-new-privileges:true               # Prevent privilege escalation

    cap_drop:
      - ALL                                  # Drop all capabilities
    cap_add:
      - NET_BIND_SERVICE                     # Add only what is needed

    ports:
      - "127.0.0.1:8080:8080"               # Bind to localhost only

    mem_limit: 512m                          # Memory limit
    cpus: 1.0                                # CPU limit
    pids_limit: 256                          # Limit number of processes

    tmpfs:
      - /tmp:rw,noexec,nosuid,size=64m       # tmpfs for /tmp

    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 15s

    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"

    networks:
      - internal                             # Use isolated network

    volumes:
      - app-data:/app/data:rw                # Named volumes, not bind mounts

    # Never mount:
    #   - /var/run/docker.sock
    #   - /etc, /proc, /sys, /dev

networks:
  internal:
    driver: bridge
    internal: true                           # No external access

volumes:
  app-data:
    driver: local
EXAMPLE
    echo

fi  # end --compose

# =============================================================================
# 5. --network: Docker Network Hardening
# =============================================================================

if [[ "$DO_NETWORK" == true ]]; then

    echo
    echo -e "${C_BLUE}========================================================================${C_NC}"
    echo -e "${C_BLUE} Docker Network Hardening${C_NC}"
    echo -e "${C_BLUE}========================================================================${C_NC}"
    echo

    # -----------------------------------------------------------------
    # 5.1 Create isolated Docker network
    # -----------------------------------------------------------------
    if [[ "$RUNTIME" == "docker" ]]; then
        msg "Creating isolated Docker network..."

        ISOLATED_NET="docker-isolated"
        if docker network ls --format '{{.Name}}' | grep -q "^${ISOLATED_NET}$"; then
            info "Network '$ISOLATED_NET' already exists"
        else
            docker network create \
                --driver bridge \
                --internal \
                --subnet 172.28.0.0/16 \
                --opt com.docker.network.bridge.enable_icc=false \
                "$ISOLATED_NET" 2>/dev/null && \
                msg "Created isolated network: $ISOLATED_NET (internal, no ICC)" || \
                warn "Failed to create isolated network (Docker daemon may not be running)"
        fi
    else
        msg "Creating isolated Podman network..."
        ISOLATED_NET="podman-isolated"
        if podman network ls --format '{{.Name}}' | grep -q "^${ISOLATED_NET}$"; then
            info "Network '$ISOLATED_NET' already exists"
        else
            podman network create \
                --internal \
                --subnet 172.28.0.0/16 \
                "$ISOLATED_NET" 2>/dev/null && \
                msg "Created isolated network: $ISOLATED_NET (internal)" || \
                warn "Failed to create isolated network"
        fi
    fi

    # -----------------------------------------------------------------
    # 5.2 Generate nftables rules for Docker
    # -----------------------------------------------------------------
    msg "Generating nftables rules for Docker network hardening..."

    NFTABLES_RULES="/etc/nftables.d/docker-hardening.nft"
    mkdir -p /etc/nftables.d

    cat > "$NFTABLES_RULES" <<'NFTRULES'
#!/usr/sbin/nft -f
# =============================================================================
# nftables rules for Docker container network hardening
# Generated by AwesomeArchLinux/hardening/docker/docker.sh
#
# Apply with:  nft -f /etc/nftables.d/docker-hardening.nft
# Verify with: nft list ruleset
# =============================================================================

table inet docker_hardening {

    # --- Chain: restrict container-to-host communication ---
    chain docker_input {
        type filter hook input priority filter; policy accept;

        # Allow established/related connections
        ct state established,related accept

        # Allow containers to reach host DNS (port 53)
        iifname "docker0" tcp dport 53 accept
        iifname "docker0" udp dport 53 accept

        # Allow DHCP from containers
        iifname "docker0" udp dport { 67, 68 } accept

        # Log and drop other container-to-host traffic
        iifname "docker0" log prefix "[DOCKER-DROP] " drop
    }

    # --- Chain: restrict container outbound traffic ---
    chain docker_forward {
        type filter hook forward priority filter; policy accept;

        # Allow established/related connections
        ct state established,related accept

        # Allow specific outbound ports from containers
        # HTTP, HTTPS, DNS, NTP — adjust as needed
        iifname "docker0" oifname != "docker0" tcp dport { 80, 443 } accept
        iifname "docker0" oifname != "docker0" udp dport { 53, 123 } accept

        # Log and drop other container-to-external traffic
        iifname "docker0" oifname != "docker0" log prefix "[DOCKER-FWD-DROP] " drop
    }
}
NFTRULES

    chmod 644 "$NFTABLES_RULES"
    GENERATED_FILES+=("$NFTABLES_RULES")
    msg "nftables rules written to $NFTABLES_RULES"

    echo
    echo -e "${C_YELLOW}To apply the nftables rules:${C_NC}"
    echo "  nft -f $NFTABLES_RULES"
    echo
    echo -e "${C_YELLOW}To persist across reboots, include in /etc/nftables.conf:${C_NC}"
    echo "  include \"$NFTABLES_RULES\""
    echo
    echo -e "${C_YELLOW}To verify the ruleset:${C_NC}"
    echo "  nft list ruleset"
    echo

    info "Allowed outbound ports from containers: 80 (HTTP), 443 (HTTPS), 53 (DNS), 123 (NTP)"
    info "All other container-to-host and container-to-external traffic is logged and dropped."
    info "Edit $NFTABLES_RULES to allow additional ports as needed."

fi  # end --network

# =============================================================================
# 6. CREATE APPARMOR PROFILE FOR DOCKER CONTAINERS
# =============================================================================

echo
msg "Creating hardened AppArmor profile for Docker containers..."

APPARMOR_DIR="/etc/apparmor.d"
APPARMOR_PROFILE="$APPARMOR_DIR/docker-default-hardened"

mkdir -p "$APPARMOR_DIR"

cat > "$APPARMOR_PROFILE" <<'PROFILE'
# =============================================================================
# Hardened AppArmor profile for Docker containers
# Generated by AwesomeArchLinux/hardening/docker/docker.sh
#
# This profile extends the default Docker AppArmor profile with additional
# restrictions. Apply to containers with:
#
#   docker run --security-opt apparmor=docker-default-hardened ...
#
# =============================================================================

abi <abi/3.0>,

#include <tunables/global>

profile docker-default-hardened flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>

  # --- Network ---
  network,

  # --- Capabilities ---
  # Allow only the minimal default Docker capabilities
  capability chown,
  capability dac_override,
  capability fowner,
  capability fsetid,
  capability kill,
  capability setgid,
  capability setuid,
  capability setpcap,
  capability net_bind_service,
  capability net_raw,
  capability sys_chroot,
  capability mknod,
  capability audit_write,
  capability setfcap,

  # --- Deny dangerous operations ---
  # Deny all mount operations inside containers
  deny mount,

  # Deny ptrace — prevents container escape via process tracing
  deny ptrace (read, readby, trace, tracedby),

  # --- Filesystem ---
  # General file access (containers need broad read/write)
  file,

  # Restrict /proc access
  deny /proc/*/mem rwklx,
  deny /proc/kcore rwklx,
  deny /proc/sysrq-trigger rwklx,
  deny /proc/acpi/** rwklx,
  deny /proc/timer_list r,
  deny /proc/timer_stats r,

  # Restrict /sys access
  deny /sys/firmware/** rwklx,
  deny /sys/kernel/security/** rwklx,
  deny /sys/kernel/debug/** rwklx,
  deny /sys/fs/** rwklx,

  # Deny write access to critical kernel interfaces
  deny /sys/devices/virtual/dmi/** r,

  # --- Signal handling ---
  signal (receive) peer=unconfined,
  signal (send,receive) peer=docker-default-hardened,
}
PROFILE

chmod 644 "$APPARMOR_PROFILE"
GENERATED_FILES+=("$APPARMOR_PROFILE")

# Load the profile if AppArmor is available
if command -v apparmor_parser &>/dev/null; then
    if apparmor_parser -r -W "$APPARMOR_PROFILE" 2>/dev/null; then
        msg "AppArmor profile loaded: docker-default-hardened"
    else
        warn "Failed to parse AppArmor profile (AppArmor may not be active)"
        info "Reboot with apparmor=1 security=apparmor kernel parameters"
    fi
else
    info "apparmor_parser not found; profile written but not loaded"
    info "Install apparmor (see hardening/apparmor/apparmor.sh) and reboot"
fi

msg "AppArmor profile: $APPARMOR_PROFILE"
info "Usage: docker run --security-opt apparmor=docker-default-hardened <image>"

# =============================================================================
# 7. CREATE HARDENED SECCOMP PROFILE
# =============================================================================

echo
msg "Creating hardened seccomp profile..."

SECCOMP_DIR="/etc/docker"
SECCOMP_PROFILE="$SECCOMP_DIR/seccomp-hardened.json"
mkdir -p "$SECCOMP_DIR"

cat > "$SECCOMP_PROFILE" <<'SECCOMP'
{
    "_comment": "Hardened seccomp profile for Docker containers. Generated by AwesomeArchLinux/hardening/docker/docker.sh. Blocks dangerous syscalls beyond the Docker default.",
    "defaultAction": "SCMP_ACT_ERRNO",
    "defaultErrnoRet": 1,
    "archMap": [
        {
            "architecture": "SCMP_ARCH_X86_64",
            "subArchitectures": [
                "SCMP_ARCH_X86",
                "SCMP_ARCH_X32"
            ]
        },
        {
            "architecture": "SCMP_ARCH_AARCH64",
            "subArchitectures": [
                "SCMP_ARCH_ARM"
            ]
        }
    ],
    "syscalls": [
        {
            "names": [
                "accept",
                "accept4",
                "access",
                "adjtimex",
                "alarm",
                "bind",
                "brk",
                "capget",
                "capset",
                "chdir",
                "chmod",
                "chown",
                "chown32",
                "chroot",
                "clock_adjtime",
                "clock_adjtime64",
                "clock_getres",
                "clock_getres_time64",
                "clock_gettime",
                "clock_gettime64",
                "clock_nanosleep",
                "clock_nanosleep_time64",
                "clone",
                "clone3",
                "close",
                "close_range",
                "connect",
                "copy_file_range",
                "creat",
                "dup",
                "dup2",
                "dup3",
                "epoll_create",
                "epoll_create1",
                "epoll_ctl",
                "epoll_ctl_old",
                "epoll_pwait",
                "epoll_pwait2",
                "epoll_wait",
                "epoll_wait_old",
                "eventfd",
                "eventfd2",
                "execve",
                "execveat",
                "exit",
                "exit_group",
                "faccessat",
                "faccessat2",
                "fadvise64",
                "fadvise64_64",
                "fallocate",
                "fanotify_mark",
                "fchdir",
                "fchmod",
                "fchmodat",
                "fchmodat2",
                "fchown",
                "fchown32",
                "fchownat",
                "fcntl",
                "fcntl64",
                "fdatasync",
                "fgetxattr",
                "flistxattr",
                "flock",
                "fork",
                "fremovexattr",
                "fsetxattr",
                "fstat",
                "fstat64",
                "fstatat64",
                "fstatfs",
                "fstatfs64",
                "fsync",
                "ftruncate",
                "ftruncate64",
                "futex",
                "futex_time64",
                "futex_waitv",
                "futimesat",
                "get_robust_list",
                "get_thread_area",
                "getcpu",
                "getcwd",
                "getdents",
                "getdents64",
                "getegid",
                "getegid32",
                "geteuid",
                "geteuid32",
                "getgid",
                "getgid32",
                "getgroups",
                "getgroups32",
                "getitimer",
                "getpeername",
                "getpgid",
                "getpgrp",
                "getpid",
                "getppid",
                "getpriority",
                "getrandom",
                "getresgid",
                "getresgid32",
                "getresuid",
                "getresuid32",
                "getrlimit",
                "getrusage",
                "getsid",
                "getsockname",
                "getsockopt",
                "gettid",
                "gettimeofday",
                "getuid",
                "getuid32",
                "getxattr",
                "inotify_add_watch",
                "inotify_init",
                "inotify_init1",
                "inotify_rm_watch",
                "io_cancel",
                "io_destroy",
                "io_getevents",
                "io_pgetevents",
                "io_pgetevents_time64",
                "io_setup",
                "io_submit",
                "io_uring_enter",
                "io_uring_register",
                "io_uring_setup",
                "ioctl",
                "ioprio_get",
                "ioprio_set",
                "ipc",
                "kill",
                "landlock_add_rule",
                "landlock_create_ruleset",
                "landlock_restrict_self",
                "lchown",
                "lchown32",
                "lgetxattr",
                "link",
                "linkat",
                "listen",
                "listxattr",
                "llistxattr",
                "lremovexattr",
                "lseek",
                "lsetxattr",
                "lstat",
                "lstat64",
                "madvise",
                "membarrier",
                "memfd_create",
                "memfd_secret",
                "mincore",
                "mkdir",
                "mkdirat",
                "mknod",
                "mknodat",
                "mlock",
                "mlock2",
                "mlockall",
                "mmap",
                "mmap2",
                "mount",
                "mprotect",
                "mq_getsetattr",
                "mq_notify",
                "mq_open",
                "mq_timedreceive",
                "mq_timedreceive_time64",
                "mq_timedsend",
                "mq_timedsend_time64",
                "mq_unlink",
                "mremap",
                "msgctl",
                "msgget",
                "msgrcv",
                "msgsnd",
                "msync",
                "munlock",
                "munlockall",
                "munmap",
                "name_to_handle_at",
                "nanosleep",
                "newfstatat",
                "open",
                "openat",
                "openat2",
                "pause",
                "pidfd_open",
                "pidfd_send_signal",
                "pipe",
                "pipe2",
                "pivot_root",
                "pkey_alloc",
                "pkey_free",
                "pkey_mprotect",
                "poll",
                "ppoll",
                "ppoll_time64",
                "prctl",
                "pread64",
                "preadv",
                "preadv2",
                "prlimit64",
                "pselect6",
                "pselect6_time64",
                "pwrite64",
                "pwritev",
                "pwritev2",
                "read",
                "readahead",
                "readlink",
                "readlinkat",
                "readv",
                "recv",
                "recvfrom",
                "recvmmsg",
                "recvmmsg_time64",
                "recvmsg",
                "remap_file_pages",
                "removexattr",
                "rename",
                "renameat",
                "renameat2",
                "restart_syscall",
                "rmdir",
                "rseq",
                "rt_sigaction",
                "rt_sigpending",
                "rt_sigprocmask",
                "rt_sigqueueinfo",
                "rt_sigreturn",
                "rt_sigsuspend",
                "rt_sigtimedwait",
                "rt_sigtimedwait_time64",
                "rt_tgsigqueueinfo",
                "sched_get_priority_max",
                "sched_get_priority_min",
                "sched_getaffinity",
                "sched_getattr",
                "sched_getparam",
                "sched_getscheduler",
                "sched_setaffinity",
                "sched_setattr",
                "sched_setparam",
                "sched_setscheduler",
                "sched_yield",
                "seccomp",
                "select",
                "semctl",
                "semget",
                "semop",
                "semtimedop",
                "semtimedop_time64",
                "send",
                "sendfile",
                "sendfile64",
                "sendmmsg",
                "sendmsg",
                "sendto",
                "set_robust_list",
                "set_thread_area",
                "set_tid_address",
                "setfsgid",
                "setfsgid32",
                "setfsuid",
                "setfsuid32",
                "setgid",
                "setgid32",
                "setgroups",
                "setgroups32",
                "setitimer",
                "setpgid",
                "setpriority",
                "setregid",
                "setregid32",
                "setresgid",
                "setresgid32",
                "setresuid",
                "setresuid32",
                "setreuid",
                "setreuid32",
                "setrlimit",
                "setsid",
                "setsockopt",
                "setuid",
                "setuid32",
                "setxattr",
                "shmat",
                "shmctl",
                "shmdt",
                "shmget",
                "shutdown",
                "sigaltstack",
                "signalfd",
                "signalfd4",
                "sigprocmask",
                "sigreturn",
                "socket",
                "socketcall",
                "socketpair",
                "splice",
                "stat",
                "stat64",
                "statfs",
                "statfs64",
                "statx",
                "symlink",
                "symlinkat",
                "sync",
                "sync_file_range",
                "syncfs",
                "sysinfo",
                "tee",
                "tgkill",
                "time",
                "timer_create",
                "timer_delete",
                "timer_getoverrun",
                "timer_gettime",
                "timer_gettime64",
                "timer_settime",
                "timer_settime64",
                "timerfd_create",
                "timerfd_gettime",
                "timerfd_gettime64",
                "timerfd_settime",
                "timerfd_settime64",
                "times",
                "tkill",
                "truncate",
                "truncate64",
                "ugetrlimit",
                "umask",
                "umount2",
                "uname",
                "unlink",
                "unlinkat",
                "unshare",
                "utime",
                "utimensat",
                "utimensat_time64",
                "utimes",
                "vfork",
                "vmsplice",
                "wait4",
                "waitid",
                "waitpid",
                "write",
                "writev"
            ],
            "action": "SCMP_ACT_ALLOW"
        },
        {
            "_comment": "Explicitly blocked dangerous syscalls (beyond Docker default)",
            "names": [
                "keyctl",
                "add_key",
                "request_key",
                "ptrace",
                "userfaultfd",
                "personality",
                "bpf"
            ],
            "action": "SCMP_ACT_ERRNO",
            "errnoRet": 1
        },
        {
            "_comment": "Also blocked: kernel module and kexec operations",
            "names": [
                "init_module",
                "finit_module",
                "delete_module",
                "kexec_file_load",
                "kexec_load",
                "reboot",
                "acct",
                "lookup_dcookie",
                "open_by_handle_at",
                "setns",
                "swapon",
                "swapoff",
                "mount_setattr",
                "move_mount",
                "open_tree",
                "fsopen",
                "fsmount",
                "fsconfig",
                "fspick"
            ],
            "action": "SCMP_ACT_ERRNO",
            "errnoRet": 1
        }
    ]
}
SECCOMP

chmod 644 "$SECCOMP_PROFILE"
GENERATED_FILES+=("$SECCOMP_PROFILE")
msg "Seccomp profile created: $SECCOMP_PROFILE"

echo
info "Usage: docker run --security-opt seccomp=$SECCOMP_PROFILE <image>"
info "Or set as default in /etc/docker/daemon.json:"
info "  \"seccomp-profile\": \"$SECCOMP_PROFILE\""
echo

echo -e "${C_YELLOW}Blocked syscalls in hardened profile:${C_NC}"
echo "  keyctl, add_key, request_key  — Kernel keyring manipulation"
echo "  ptrace                        — Process tracing / debugging"
echo "  userfaultfd                   — Use-after-free attack surface"
echo "  personality                   — Change execution domain"
echo "  bpf                           — eBPF program loading"
echo "  init_module, finit_module     — Kernel module loading"
echo "  delete_module                 — Kernel module removal"
echo "  kexec_file_load, kexec_load   — Load new kernel for execution"
echo "  reboot                        — System reboot"
echo "  acct                          — Process accounting"
echo "  setns                         — Join namespaces (container escape)"
echo "  swapon, swapoff               — Swap management"
echo

# =============================================================================
# 8. COMPREHENSIVE SUMMARY
# =============================================================================

echo
echo -e "${C_GREEN}========================================================================${C_NC}"
echo -e "${C_GREEN} Docker Container Security Hardening Complete!${C_NC}"
echo -e "${C_GREEN}========================================================================${C_NC}"
echo

# --- Bench results ---
if [[ "$DO_BENCH" == true ]]; then
    echo -e "${C_BLUE}CIS Benchmark Results:${C_NC}"
    echo -e "  ${C_GREEN}PASS: $BENCH_PASS${C_NC}  ${C_YELLOW}WARN: $BENCH_WARN${C_NC}  ${C_RED}FAIL: $BENCH_FAIL${C_NC}"
    BENCH_TOTAL=$((BENCH_PASS + BENCH_WARN + BENCH_FAIL))
    if [[ "$BENCH_TOTAL" -gt 0 ]]; then
        BENCH_SCORE=$(( (BENCH_PASS * 100) / BENCH_TOTAL ))
        echo "  Score: ${BENCH_SCORE}%"
    fi
    echo
fi

# --- Scan results ---
if [[ "$DO_SCAN" == true ]]; then
    echo -e "${C_BLUE}Image Scan Results:${C_NC}"
    if [[ -f "${SCAN_REPORT:-}" ]]; then
        echo "  Report: $SCAN_REPORT"
    fi
    echo "  Timer:  docker-image-scan.timer (weekly)"
    echo
fi

# --- Compose audit ---
if [[ "$DO_COMPOSE" == true ]]; then
    echo -e "${C_BLUE}Compose Audit:${C_NC}"
    echo "  File:   $COMPOSE_PATH"
    echo "  Issues: ${COMPOSE_ISSUES:-0}"
    echo
fi

# --- Network rules ---
if [[ "$DO_NETWORK" == true ]]; then
    echo -e "${C_BLUE}Network Hardening:${C_NC}"
    echo "  Isolated network: ${ISOLATED_NET:-N/A}"
    echo "  nftables rules:   ${NFTABLES_RULES:-N/A}"
    echo
fi

# --- Generated files ---
echo -e "${C_BLUE}Generated Files:${C_NC}"
echo "  AppArmor profile:  $APPARMOR_PROFILE"
echo "  Seccomp profile:   $SECCOMP_PROFILE"
for f in "${GENERATED_FILES[@]}"; do
    # Skip the two already printed above
    if [[ "$f" != "$APPARMOR_PROFILE" && "$f" != "$SECCOMP_PROFILE" ]]; then
        echo "  $(basename "$f"):  $f"
    fi
done
echo "  Log:               $LOGFILE"
echo

# --- Security Best Practices Checklist ---
echo -e "${C_BLUE}Container Security Best Practices Checklist:${C_NC}"
echo
echo -e "  ${C_GREEN} 1.${C_NC} Use read-only root filesystem (--read-only)"
echo -e "  ${C_GREEN} 2.${C_NC} Drop all capabilities and add only what is needed"
echo "       --cap-drop=ALL --cap-add=NET_BIND_SERVICE"
echo -e "  ${C_GREEN} 3.${C_NC} Run as non-root user inside containers"
echo "       USER nonroot (Dockerfile) or --user 1000:1000"
echo -e "  ${C_GREEN} 4.${C_NC} Pin image versions — never use :latest in production"
echo -e "  ${C_GREEN} 5.${C_NC} Scan images regularly with Trivy"
echo "       trivy image myimage:1.2.3"
echo -e "  ${C_GREEN} 6.${C_NC} Set resource limits on every container"
echo "       --memory=512m --cpus=1.0 --pids-limit=256"
echo -e "  ${C_GREEN} 7.${C_NC} Never mount the Docker socket in containers"
echo -e "  ${C_GREEN} 8.${C_NC} Use tmpfs for sensitive ephemeral data"
echo "       --tmpfs /tmp:rw,noexec,nosuid,size=64m"
echo -e "  ${C_GREEN} 9.${C_NC} Apply seccomp and AppArmor profiles"
echo "       --security-opt seccomp=$SECCOMP_PROFILE"
echo "       --security-opt apparmor=docker-default-hardened"
echo -e "  ${C_GREEN}10.${C_NC} Use Docker secrets or external vault for secrets"
echo "       Never store secrets in images or environment variables"
echo -e "  ${C_GREEN}11.${C_NC} Use multi-stage builds and minimal base images"
echo "       distroless, Alpine, or scratch"
echo -e "  ${C_GREEN}12.${C_NC} Enable Docker Content Trust (DOCKER_CONTENT_TRUST=1)"
echo -e "  ${C_GREEN}13.${C_NC} Use isolated networks with --internal flag"
echo -e "  ${C_GREEN}14.${C_NC} Configure health checks for all containers"
echo -e "  ${C_GREEN}15.${C_NC} Enable centralized logging and monitoring"
echo

echo -e "${C_GREEN}Done.${C_NC}"
