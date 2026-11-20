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
#                - Isolated container network with persistent nftables policy
#                - Docker's maintained built-in AppArmor and seccomp defaults
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
#              --network        Create and firewall an isolated network
#              -h, --help       Show this help
#
#              With no flags the script preserves the runtime security defaults
#              and prints a security summary.
#
# Requirements:
#   - Arch Linux with pacman
#   - Root privileges (sudo)
#   - Docker or Podman installed (utils/docker.sh)
# =============================================================================

set -euo pipefail
umask 022

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck disable=SC1090,SC1091
source "$SCRIPT_DIR/../lib/nftables.sh"

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
  --network        Create and firewall an isolated container network

Options:
  -h, --help       Show this help

With no flags the script preserves Docker's built-in AppArmor and seccomp
defaults and prints a security summary.

Examples:
  sudo $0 --bench                         # CIS benchmark audit
  sudo $0 --scan                          # Scan all images
  sudo $0 --compose /opt/app/docker-compose.yml
  sudo $0 --network                       # Create isolated network and rules
  sudo $0 --bench --scan --network        # All checks
EOF
    exit 0
}

# --- Parse Arguments ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --bench)     DO_BENCH=true;   shift ;;
        --scan)      DO_SCAN=true;    shift ;;
        --compose)
            [[ $# -ge 2 && -n "$2" && "$2" != -* ]] || err "--compose requires a path"
            DO_COMPOSE=true; COMPOSE_PATH="$2"; shift 2
            ;;
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
install -o root -g root -m 0600 /dev/null "$LOGFILE"
exec > >(tee -a "$LOGFILE") 2>&1

# =============================================================================
# HELPER: CIS Bench result functions
# =============================================================================

bench_pass() {
    printf "  %b[PASS]%b %s\n" "$C_GREEN" "$C_NC" "$1"
    (( ++BENCH_PASS ))
}

bench_warn() {
    printf "  %b[WARN]%b %s\n" "$C_YELLOW" "$C_NC" "$1"
    (( ++BENCH_WARN ))
}

bench_fail() {
    printf "  %b[FAIL]%b %s\n" "$C_RED" "$C_NC" "$1"
    (( ++BENCH_FAIL ))
}

warn_if_rootless_podman() {
    local kind="$1"
    [[ "$RUNTIME" == "podman" ]] || return 0
    if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
        local sudo_home
        sudo_home=$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6 || true)
        if [[ -n "$sudo_home" && -d "$sudo_home/.local/share/containers" ]]; then
            warn "Root Podman store has no $kind, while '$SUDO_USER' has rootless Podman storage at $sudo_home/.local/share/containers (sudo inspects rootful Podman only)."
        else
            warn "Root Podman store has no $kind; note that sudo inspects rootful Podman, not '$SUDO_USER''s rootless Podman store."
        fi
    fi
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
                # Exact match on a rule's path operand (-w PATH, -F path=PATH,
                # -F dir=PATH): a substring match would let the /usr/bin/dockerd
                # rule satisfy /usr/bin/docker, or /etc/docker/daemon.json
                # satisfy /etc/docker.
                if auditctl -l 2>/dev/null | awk -v p="$audit_path" '
                        {
                            for (i = 1; i <= NF; i++) {
                                f = $i
                                sub(/^(path|dir)=/, "", f)
                                if (f != "/") sub(/\/$/, "", f)
                                if (f == p) found = 1
                            }
                        }
                        END { exit !found }
                    '; then
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

    CONTAINERS=$($RUNTIME ps -q 2>/dev/null || true)

    if [[ -z "$CONTAINERS" ]]; then
        info "No running containers found. Skipping container runtime checks."
        warn_if_rootless_podman "running containers"
    else
        while IFS= read -r CONTAINER_ID; do
            [[ -z "$CONTAINER_ID" ]] && continue
            CNAME=$($RUNTIME inspect --format '{{.Name}}' "$CONTAINER_ID" 2>/dev/null || true)
            CNAME="${CNAME#/}"
            CNAME="${CNAME:-$CONTAINER_ID}"

            info "Checking container: $CNAME ($CONTAINER_ID)"

            # 2.1 Running as root
            CONTAINER_USER=$($RUNTIME inspect --format '{{.Config.User}}' "$CONTAINER_ID" 2>/dev/null || true)
            case "$CONTAINER_USER" in
                ""|0|root|0:*|root:*)
                    bench_warn "2.1 - Container '$CNAME' is running as root"
                    ;;
                *)
                    bench_pass "2.1 - Container '$CNAME' runs as non-root user ($CONTAINER_USER)"
                    ;;
            esac

            # 2.2 Privileged mode
            PRIVILEGED=$($RUNTIME inspect --format '{{.HostConfig.Privileged}}' "$CONTAINER_ID" 2>/dev/null || true)
            if [[ "$PRIVILEGED" == "true" ]]; then
                bench_fail "2.2 - Container '$CNAME' is running in PRIVILEGED mode"
            else
                bench_pass "2.2 - Container '$CNAME' is not privileged"
            fi

            # 2.3 Host network namespace
            NETMODE=$($RUNTIME inspect --format '{{.HostConfig.NetworkMode}}' "$CONTAINER_ID" 2>/dev/null || true)
            if [[ "$NETMODE" == "host" ]]; then
                bench_warn "2.3 - Container '$CNAME' uses host network namespace"
            else
                bench_pass "2.3 - Container '$CNAME' does not use host network"
            fi

            # 2.4 Host PID namespace
            PIDMODE=$($RUNTIME inspect --format '{{.HostConfig.PidMode}}' "$CONTAINER_ID" 2>/dev/null || true)
            if [[ "$PIDMODE" == "host" ]]; then
                bench_fail "2.4 - Container '$CNAME' uses host PID namespace"
            else
                bench_pass "2.4 - Container '$CNAME' does not use host PID namespace"
            fi

            # 2.5 Read-only root filesystem
            READONLY_ROOTFS=$($RUNTIME inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$CONTAINER_ID" 2>/dev/null || true)
            if [[ "$READONLY_ROOTFS" == "true" ]]; then
                bench_pass "2.5 - Container '$CNAME' has read-only root filesystem"
            else
                bench_warn "2.5 - Container '$CNAME' does NOT have read-only root filesystem"
            fi

            # 2.6 Excessive capabilities
            CAPS_ADD=$($RUNTIME inspect --format '{{json .HostConfig.CapAdd}}' "$CONTAINER_ID" 2>/dev/null || true)
            if [[ -n "$CAPS_ADD" && "$CAPS_ADD" != "null" && "$CAPS_ADD" != "[]" ]]; then
                bench_warn "2.6 - Container '$CNAME' has added capabilities: $CAPS_ADD"
            else
                bench_pass "2.6 - Container '$CNAME' has no extra capabilities added"
            fi

            # 2.7 Health check (treat null, {}, empty Test, and Podman/Docker ["NONE"] as missing)
            HEALTHCHECK=$($RUNTIME inspect --format '{{json .Config.Healthcheck}}' "$CONTAINER_ID" 2>/dev/null || true)
            if [[ -z "$HEALTHCHECK" || "$HEALTHCHECK" == "null" || "$HEALTHCHECK" == "{}" ]] || \
                [[ "$HEALTHCHECK" == *'["NONE"]'* ]] || \
                ! [[ "$HEALTHCHECK" == *'"Test":['*'"'* ]]; then
                bench_warn "2.7 - Container '$CNAME' has no health check configured"
            else
                bench_pass "2.7 - Container '$CNAME' has a health check"
            fi

            # 2.8 Memory limits
            MEMORY=$($RUNTIME inspect --format '{{.HostConfig.Memory}}' "$CONTAINER_ID" 2>/dev/null || true)
            if [[ -z "$MEMORY" || "$MEMORY" == "0" || ! "$MEMORY" =~ ^[0-9]+$ ]]; then
                bench_warn "2.8 - Container '$CNAME' has no memory limit set"
            else
                bench_pass "2.8 - Container '$CNAME' has memory limit: $((MEMORY / 1048576))MB"
            fi

            # 2.9 CPU limits
            NANOC=$($RUNTIME inspect --format '{{.HostConfig.NanoCpus}}' "$CONTAINER_ID" 2>/dev/null || true)
            CPUSHARES=$($RUNTIME inspect --format '{{.HostConfig.CpuShares}}' "$CONTAINER_ID" 2>/dev/null || true)
            if [[ (-z "$NANOC" || "$NANOC" == "0") && (-z "$CPUSHARES" || "$CPUSHARES" == "0") ]]; then
                bench_warn "2.9 - Container '$CNAME' has no CPU limit set"
            else
                bench_pass "2.9 - Container '$CNAME' has CPU limits configured"
            fi

            # 2.10 Bind-mounted sensitive paths
            SENSITIVE_PATHS=("/etc" "/proc" "/sys" "/dev" "/var/run/docker.sock" "/run/docker.sock")
            MOUNTS=$($RUNTIME inspect --format '{{range .Mounts}}{{println .Source}}{{end}}' "$CONTAINER_ID" 2>/dev/null || true)
            for SPATH in "${SENSITIVE_PATHS[@]}"; do
                if grep -Eq "^${SPATH}(/|$)" <<< "$MOUNTS"; then
                    bench_fail "2.10 - Container '$CNAME' has bind mount to sensitive path: $SPATH"
                fi
            done
        done <<< "$CONTAINERS"
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

        # Trivy is in Arch's signed official repositories. Do not fall back to
        # an AUR package or an unauthenticated release archive.
        pacman -Syu --noconfirm --needed trivy
        command -v trivy &>/dev/null || err "Trivy installation completed but no executable was found"
        TRIVY_VER=$(trivy --version 2>/dev/null | head -1 || true)
        info "Installed from the signed Arch repository: $TRIVY_VER"
    else
        TRIVY_VER=$(trivy --version 2>/dev/null | head -1 || true)
        info "Trivy already installed: $TRIVY_VER"
    fi

    # -----------------------------------------------------------------
    # 3.2 Scan all local images
    # -----------------------------------------------------------------
    msg "Scanning local images for HIGH and CRITICAL vulnerabilities..."

    SCAN_DIR="/var/log/docker-security"
    install -d -m 0750 "$SCAN_DIR"
    SCAN_DATE=$(date +%Y%m%d-%H%M%S)
    SCAN_REPORT="$SCAN_DIR/image-scan-${SCAN_DATE}.json"

    IMAGES=$($RUNTIME images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -v '<none>' || true)

    if [[ -z "$IMAGES" ]]; then
        printf '[]\n' > "$SCAN_REPORT"
        chmod 0640 "$SCAN_REPORT"
        GENERATED_FILES+=("$SCAN_REPORT")
        info "No local images found to scan. Wrote empty report: $SCAN_REPORT"
        warn_if_rootless_podman "images"
    else
        printf '[\n' > "$SCAN_REPORT"
        chmod 0640 "$SCAN_REPORT"
        FIRST_ENTRY=true
        TOTAL_IMAGES=0
        VULN_IMAGES=0
        FAILED_IMAGES=0

        while IFS= read -r IMAGE; do
            [[ -z "$IMAGE" ]] && continue
            (( ++TOTAL_IMAGES ))

            info "Scanning: $IMAGE"

            # Append comma separator for JSON array
            if [[ "$FIRST_ENTRY" == true ]]; then
                FIRST_ENTRY=false
            else
                printf ',\n' >> "$SCAN_REPORT"
            fi

            # Run Trivy scan into a variable first so partial output on failure
            # never corrupts the JSON report array. A scan that failed (no
            # vulnerability database, no network, unreadable image) is recorded
            # as an explicit error entry: it must never read as "clean".
            if ! SCAN_OUTPUT=$(trivy image --severity HIGH,CRITICAL --format json "$IMAGE" 2>/dev/null) || [[ -z "$SCAN_OUTPUT" ]]; then
                IMAGE_JSON="${IMAGE//\\/\\\\}"
                IMAGE_JSON="${IMAGE_JSON//\"/\\\"}"
                printf '{"ArtifactName": "%s", "ScanError": true}\n' "$IMAGE_JSON" >> "$SCAN_REPORT"
                warn "  Scan FAILED for $IMAGE (not counted as clean). Re-run: trivy image $IMAGE"
                (( ++FAILED_IMAGES ))
                continue
            fi
            printf '%s\n' "$SCAN_OUTPUT" >> "$SCAN_REPORT"

            # Check for vulnerabilities in output
            VULN_COUNT=$(grep -c '"VulnerabilityID"' <<< "$SCAN_OUTPUT" || true)
            VULN_COUNT="${VULN_COUNT:-0}"
            if [[ "$VULN_COUNT" -gt 0 ]]; then
                warn "  Found $VULN_COUNT HIGH/CRITICAL vulnerabilities in $IMAGE"
                (( ++VULN_IMAGES ))
            else
                msg "  No HIGH/CRITICAL vulnerabilities in $IMAGE"
            fi

        done <<< "$IMAGES"

        printf ']\n' >> "$SCAN_REPORT"
        GENERATED_FILES+=("$SCAN_REPORT")

        echo
        echo -e "${C_BLUE}--- Scan Summary ---${C_NC}"
        echo "  Total images: $TOTAL_IMAGES"
        echo "  Images scanned: $(( TOTAL_IMAGES - FAILED_IMAGES ))"
        echo "  Images with vulnerabilities: $VULN_IMAGES"
        echo "  Images that could not be scanned: $FAILED_IMAGES"
        echo "  Report: $SCAN_REPORT"
        echo
        if (( FAILED_IMAGES > 0 )); then
            warn "$FAILED_IMAGES image(s) could not be scanned and are NOT known to be clean (\"ScanError\" entries in the report)."
        fi
    fi

    # -----------------------------------------------------------------
    # 3.3 Create systemd timer for weekly image scans
    # -----------------------------------------------------------------
    msg "Creating weekly image scan timer..."

    install -d -m 0755 /usr/local/bin /etc/systemd/system

    cat > /usr/local/bin/docker-image-scan.sh <<'SCANSCRIPT'
#!/usr/bin/env bash
# =============================================================================
# Automated Docker image vulnerability scan
# Generated by AwesomeArchLinux/hardening/docker/docker.sh
# =============================================================================

set -euo pipefail
umask 022

SCAN_DIR="/var/log/docker-security"
install -d -m 0750 "$SCAN_DIR"
SCAN_DATE=$(date +%Y%m%d-%H%M%S)
REPORT="$SCAN_DIR/image-scan-${SCAN_DATE}.json"
FAILED=0

# Detect runtime
if command -v docker &>/dev/null; then
    IMAGES=$(docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -v '<none>' || true)
elif command -v podman &>/dev/null; then
    IMAGES=$(podman images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -v '<none>' || true)
else
    echo "No container runtime found" >&2
    exit 1
fi

if [[ -z "$IMAGES" ]]; then
    printf '[]\n' > "$REPORT"
    chmod 0640 "$REPORT"
else
    printf '[\n' > "$REPORT"
    chmod 0640 "$REPORT"
    FIRST=true

    while IFS= read -r IMAGE; do
        [[ -z "$IMAGE" ]] && continue
        if [[ "$FIRST" == true ]]; then
            FIRST=false
        else
            printf ',\n' >> "$REPORT"
        fi
        # A failed scan is recorded as an explicit error entry and makes the
        # unit fail: an empty result must never read as "no vulnerabilities".
        if ! SCAN_OUTPUT=$(trivy image --severity HIGH,CRITICAL --format json "$IMAGE" 2>/dev/null) || [[ -z "$SCAN_OUTPUT" ]]; then
            IMAGE_JSON="${IMAGE//\\/\\\\}"
            IMAGE_JSON="${IMAGE_JSON//\"/\\\"}"
            SCAN_OUTPUT=$(printf '{"ArtifactName": "%s", "ScanError": true}' "$IMAGE_JSON")
            echo "Scan failed for $IMAGE" >&2
            FAILED=$((FAILED + 1))
        fi
        printf '%s\n' "$SCAN_OUTPUT" >> "$REPORT"
    done <<< "$IMAGES"

    printf ']\n' >> "$REPORT"
fi

# Clean up old reports (keep newest 12)
shopt -s nullglob
REPORTS=( "$SCAN_DIR"/image-scan-*.json )
shopt -u nullglob
if (( ${#REPORTS[@]} > 12 )); then
    rm -f -- "${REPORTS[@]:0:${#REPORTS[@]}-12}"
fi

echo "Scan complete: $REPORT"
if (( FAILED > 0 )); then
    echo "$FAILED image(s) could not be scanned; see the ScanError entries in $REPORT" >&2
    exit 1
fi
SCANSCRIPT

    rmdir /etc/systemd/system/docker-image-scan.service.d 2>/dev/null || true
    chmod 0755 /usr/local/bin/docker-image-scan.sh
    GENERATED_FILES+=("/usr/local/bin/docker-image-scan.sh")

    TMP_SCAN_UNIT=$(mktemp /etc/systemd/system/.docker-image-scan.service.XXXXXX)
    cat > "$TMP_SCAN_UNIT" <<'EOF'
[Unit]
Description=Docker image vulnerability scan (Trivy)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/docker-image-scan.sh
PrivateTmp=true
EOF
    install -o root -g root -m 0644 "$TMP_SCAN_UNIT" /etc/systemd/system/docker-image-scan.service
    rm -f -- "$TMP_SCAN_UNIT"

    TMP_SCAN_TIMER=$(mktemp /etc/systemd/system/.docker-image-scan.timer.XXXXXX)
    cat > "$TMP_SCAN_TIMER" <<'EOF'
[Unit]
Description=Weekly Docker image vulnerability scan

[Timer]
OnCalendar=weekly
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
EOF
    install -o root -g root -m 0644 "$TMP_SCAN_TIMER" /etc/systemd/system/docker-image-scan.timer
    rm -f -- "$TMP_SCAN_TIMER"

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
    if ! grep -q "read_only:\s*true" <<< "$COMPOSE_CONTENT"; then
        bench_warn "4.1 - Missing 'read_only: true' on one or more services"
        (( ++COMPOSE_ISSUES ))
    else
        bench_pass "4.1 - 'read_only: true' found"
    fi

    # 4.2 Missing security_opt: [no-new-privileges:true]
    if ! grep -q "no-new-privileges" <<< "$COMPOSE_CONTENT"; then
        bench_warn "4.2 - Missing 'security_opt: [no-new-privileges:true]'"
        (( ++COMPOSE_ISSUES ))
    else
        bench_pass "4.2 - 'no-new-privileges' security option found"
    fi

    # 4.3 Missing cap_drop: [ALL]
    if ! grep -q "cap_drop" <<< "$COMPOSE_CONTENT"; then
        bench_warn "4.3 - Missing 'cap_drop: [ALL]' — capabilities not dropped"
        (( ++COMPOSE_ISSUES ))
    else
        bench_pass "4.3 - 'cap_drop' found"
    fi

    # 4.4 Using privileged: true
    if grep -q "privileged:\s*true" <<< "$COMPOSE_CONTENT"; then
        bench_fail "4.4 - Service uses 'privileged: true' — CRITICAL security risk"
        (( ++COMPOSE_ISSUES ))
    else
        bench_pass "4.4 - No 'privileged: true' found"
    fi

    # 4.5 Using network_mode: host
    if grep -q "network_mode:\s*[\"']*host" <<< "$COMPOSE_CONTENT"; then
        bench_warn "4.5 - Service uses 'network_mode: host' — breaks network isolation"
        (( ++COMPOSE_ISSUES ))
    else
        bench_pass "4.5 - No 'network_mode: host' found"
    fi

    # 4.6 Binding to 0.0.0.0 / [::] / unspecified host interface instead of 127.0.0.1
    if awk '
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*ports:[[:space:]]*(#.*)?$/ { in_ports = 1; ports_indent = match($0, /[^[:space:]]/) - 1; next }
        in_ports {
            cur_indent = match($0, /[^[:space:]]/) - 1
            if (cur_indent >= 0 && cur_indent <= ports_indent && $0 !~ /^[[:space:]]*-/) {
                in_ports = 0
            }
        }
        /(^|[^0-9.])0\.0\.0\.0:[0-9]/ || /\[::\]:[0-9]/ || /(^|[[:space:]"'\'']):::[0-9]/ || /host_ip:[[:space:]]*["'\'']?(0\.0\.0\.0|::)["'\'']?([[:space:]]|$)/ {
            found = 1; exit
        }
        in_ports && /^[[:space:]]*-[[:space:]]*["'\'']?[0-9]+(-[0-9]+)?:[0-9]+/ {
            found = 1; exit
        }
        END { exit !found }
    ' <<< "$COMPOSE_CONTENT"; then
        bench_warn "4.6 - Ports bound to 0.0.0.0, [::], or unspecified interface — prefer 127.0.0.1:PORT:PORT"
        (( ++COMPOSE_ISSUES ))
    else
        bench_pass "4.6 - No wildcard (0.0.0.0 / [::] / unspecified) port bindings detected"
    fi

    # 4.7 Missing mem_limit and cpus
    if ! grep -qE "(mem_limit|memory:)" <<< "$COMPOSE_CONTENT" 2>/dev/null; then
        bench_warn "4.7 - Missing memory limits (mem_limit or deploy.resources.limits.memory)"
        (( ++COMPOSE_ISSUES ))
    else
        bench_pass "4.7 - Memory limits found"
    fi

    if ! grep -qE "(cpus:|cpu_count:)" <<< "$COMPOSE_CONTENT" 2>/dev/null; then
        bench_warn "4.7 - Missing CPU limits (cpus or deploy.resources.limits.cpus)"
        (( ++COMPOSE_ISSUES ))
    else
        bench_pass "4.7 - CPU limits found"
    fi

    # 4.8 Missing healthcheck
    if ! grep -q "healthcheck:" <<< "$COMPOSE_CONTENT"; then
        bench_warn "4.8 - Missing 'healthcheck' definition"
        (( ++COMPOSE_ISSUES ))
    else
        bench_pass "4.8 - 'healthcheck' found"
    fi

    # 4.9 Using :latest tag
    if grep -qE "image:.*:latest" <<< "$COMPOSE_CONTENT"; then
        bench_warn "4.9 - Using ':latest' tag — pin to a specific version"
        (( ++COMPOSE_ISSUES ))
    else
        bench_pass "4.9 - No ':latest' tag detected"
    fi

    # 4.10 Mounting docker.sock
    if grep -q "docker.sock" <<< "$COMPOSE_CONTENT"; then
        bench_fail "4.10 - Docker socket mounted in container — CRITICAL security risk"
        (( ++COMPOSE_ISSUES ))
    else
        bench_pass "4.10 - Docker socket not mounted"
    fi

    # 4.11 Missing tmpfs for /tmp
    if ! grep -q "tmpfs:" <<< "$COMPOSE_CONTENT"; then
        bench_warn "4.11 - Missing 'tmpfs' mount for /tmp"
        (( ++COMPOSE_ISSUES ))
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

    command -v nft &>/dev/null || err "--network requires nftables"
    nft list chain inet filter input &>/dev/null || \
        err "--network requires the installer-owned inet filter input chain"
    nft list chain inet filter forward &>/dev/null || \
        err "--network requires the installer-owned inet filter forward chain"

    # -----------------------------------------------------------------
    # 5.1 Create isolated Docker network
    # -----------------------------------------------------------------
    if [[ "$RUNTIME" == "docker" ]]; then
        msg "Creating isolated Docker network..."

        ISOLATED_NET="docker-isolated"
        if docker network ls --format '{{.Name}}' | grep -q "^${ISOLATED_NET}$"; then
            DOCKER_INTERNAL=$(docker network inspect --format '{{.Internal}}' "$ISOLATED_NET")
            DOCKER_SUBNETS=$(docker network inspect --format \
                '{{range .IPAM.Config}}{{println .Subnet}}{{end}}' "$ISOLATED_NET")
            DOCKER_ICC=$(docker network inspect --format \
                '{{index .Options "com.docker.network.bridge.enable_icc"}}' "$ISOLATED_NET")
            [[ "$DOCKER_INTERNAL" == true ]] || \
                err "Existing network '$ISOLATED_NET' is not internal; refusing to trust it"
            grep -Fxq '172.28.0.0/16' <<< "$DOCKER_SUBNETS" || \
                err "Existing network '$ISOLATED_NET' does not use 172.28.0.0/16"
            [[ "$DOCKER_ICC" == false ]] || \
                err "Existing network '$ISOLATED_NET' does not disable inter-container communication"
            info "Verified existing isolated network '$ISOLATED_NET'"
        else
            if ! docker network create \
                --driver bridge \
                --internal \
                --subnet 172.28.0.0/16 \
                --opt com.docker.network.bridge.enable_icc=false \
                "$ISOLATED_NET"; then
                err "Failed to create isolated Docker network"
            fi
            msg "Created isolated network: $ISOLATED_NET (internal, no ICC)"
        fi
    else
        msg "Creating isolated Podman network..."
        ISOLATED_NET="podman-isolated"
        if podman network ls --format '{{.Name}}' | grep -q "^${ISOLATED_NET}$"; then
            PODMAN_INTERNAL=$(podman network inspect --format '{{.Internal}}' "$ISOLATED_NET")
            PODMAN_SUBNETS=$(podman network inspect --format \
                '{{range .Subnets}}{{println .Subnet}}{{end}}' "$ISOLATED_NET")
            [[ "$PODMAN_INTERNAL" == true ]] || \
                err "Existing network '$ISOLATED_NET' is not internal; refusing to trust it"
            grep -Fxq '172.28.0.0/16' <<< "$PODMAN_SUBNETS" || \
                err "Existing network '$ISOLATED_NET' does not use 172.28.0.0/16"
            info "Verified existing isolated network '$ISOLATED_NET'"
        else
            if ! podman network create \
                --internal \
                --subnet 172.28.0.0/16 \
                "$ISOLATED_NET"; then
                err "Failed to create isolated Podman network"
            fi
            msg "Created isolated network: $ISOLATED_NET (internal)"
        fi
    fi

    # -----------------------------------------------------------------
    # 5.2 Persist and apply host isolation rules
    # -----------------------------------------------------------------
    msg "Installing persistent nftables isolation for 172.28.0.0/16..."
    aal_nft_persist_block container-isolated-network <<'EOF'
insert rule inet filter input ip saddr 172.28.0.0/16 drop comment "awesome-container-host-drop"
insert rule inet filter forward ip saddr 172.28.0.0/16 drop comment "awesome-container-egress-drop"
insert rule inet filter forward ip daddr 172.28.0.0/16 drop comment "awesome-container-ingress-drop"
EOF
    aal_nft_remove_live_rules inet filter input awesome-container-host-drop
    aal_nft_remove_live_rules inet filter forward awesome-container-egress-drop
    aal_nft_remove_live_rules inet filter forward awesome-container-ingress-drop
    nft insert rule inet filter input ip saddr 172.28.0.0/16 \
        drop comment "awesome-container-host-drop"
    nft insert rule inet filter forward ip saddr 172.28.0.0/16 \
        drop comment "awesome-container-egress-drop"
    nft insert rule inet filter forward ip daddr 172.28.0.0/16 \
        drop comment "awesome-container-ingress-drop"

    msg "Isolated network policy applied and persisted in ${AAL_NFT_CONFIG:-/etc/nftables.conf}"
    info "Containers on '$ISOLATED_NET' cannot reach the host or external networks."

fi  # end --network

# Docker's built-in docker-default AppArmor profile and default seccomp profile
# are versioned with the runtime and are safer than the static profiles this
# script previously generated. In particular, the old seccomp allowlist opened
# clone3, mount, unshare, and io_uring. Static profile generation is therefore
# intentionally removed rather than left as an easy-to-enable fallback.
msg "Using Docker's built-in AppArmor and seccomp profiles"
for legacy_profile in /etc/apparmor.d/docker-default-hardened /etc/docker/seccomp-hardened.json; do
    if [[ -e "$legacy_profile" ]]; then
        warn "Legacy profile remains at $legacy_profile; remove any explicit container/daemon references to it"
    fi
done

# =============================================================================
# 6. COMPREHENSIVE SUMMARY
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
    echo "  Isolated subnet:  172.28.0.0/16 (managed in ${AAL_NFT_CONFIG:-/etc/nftables.conf})"
    echo
fi

# --- Runtime profiles and generated files ---
echo -e "${C_BLUE}Runtime security profiles:${C_NC}"
echo "  AppArmor:          Docker built-in docker-default"
echo "  Seccomp:           Docker built-in default profile"
echo -e "${C_BLUE}Generated Files:${C_NC}"
for f in "${GENERATED_FILES[@]}"; do
    echo "  $(basename "$f"):  $f"
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
echo -e "  ${C_GREEN} 9.${C_NC} Keep Docker's built-in seccomp and docker-default AppArmor profiles"
echo "       Do not pass seccomp=unconfined or apparmor=unconfined"
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
