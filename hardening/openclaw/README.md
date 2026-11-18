# OpenClaw Production Hardening

Hardens a self-hosted [OpenClaw](https://github.com/openclaw/openclaw) (formerly ClawdBot/Moltbot) AI agent deployment on Arch Linux. OpenClaw connects messaging platforms (WhatsApp, Telegram, Discord, Slack, Signal, Matrix, Teams, iMessage) to an AI coding agent via a WebSocket Gateway. The agent can execute arbitrary commands on the host, browse the web, access files, and call external APIs -- making it one of the highest-risk services you can self-host. This script applies gateway lockdown, execution sandboxing, AppArmor confinement, network firewall rules, and systemd hardening.

## Quick Start

```bash
sudo ./openclaw.sh -u myuser --with-sandbox --with-firewall --with-apparmor
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-u USERNAME` | Linux user running OpenClaw | *required* |
| `-p PORT` | Gateway WebSocket port | `18789` |
| `--with-sandbox` | Enable verified rootless Docker sandbox for tool execution | |
| `--with-firewall` | Create nftables rules for OpenClaw | |
| `--with-apparmor` | Write and load AppArmor profile | |
| `-h` | Show help | |

### Examples

```bash
# Basic -- defaults for port and no optional hardening layers
sudo ./openclaw.sh -u myuser

# Full hardening with custom port
sudo ./openclaw.sh -u myuser -p 19000 --with-sandbox --with-firewall --with-apparmor

# Sandbox and firewall only (no AppArmor)
sudo ./openclaw.sh -u myuser --with-sandbox --with-firewall
```

## What It Does

### 1. Gateway Security

The OpenClaw Gateway is a WebSocket server (default port 18789) that bridges messaging platforms to the AI agent. It accepts connections, authenticates them, and dispatches commands to the agent process. **If exposed to the public internet without authentication, anyone can execute arbitrary shell commands on your machine.**

#### The Shodan Exposure Problem

Internet scans have discovered 923+ OpenClaw gateways bound to `0.0.0.0` on the public internet with zero authentication. Every one of these is a full remote code execution vector -- an attacker connects via WebSocket and instructs the agent to run any command. This is not a theoretical risk; it is the single most common OpenClaw misconfiguration.

#### Bind Modes

| Bind Mode | Address | Risk Level | Use Case |
|-----------|---------|------------|----------|
| `loopback` | `127.0.0.1` | Lowest | Local-only access, SSH tunnel for remote |
| `tailnet` | Tailscale IP | Low | Access from your Tailscale network only |
| `lan` | `0.0.0.0` (LAN-filtered) | Medium | Local network access with firewall |
| `custom` | User-specified IP | Varies | Bind to a specific interface |
| `0.0.0.0` (unfiltered) | All interfaces | **Critical** | **Never use this without a firewall** |

This script sets the bind mode to `loopback` and configures the gateway to listen on `127.0.0.1` only.

#### Token Authentication

The gateway supports token-based authentication. This script generates a cryptographically random 64-character hex token (256-bit entropy), stores it as `OPENCLAW_GATEWAY_TOKEN` in `~/.openclaw/.env` (mode `600`, loaded via systemd `EnvironmentFile`), and references `${OPENCLAW_GATEWAY_TOKEN}` in `~/.openclaw/openclaw.json` so plaintext secrets never sit in the JSON config:

```jsonc
// ~/.openclaw/openclaw.json (gateway section)
{
  "gateway": {
    "mode": "local",
    "bind": "loopback",
    "port": 18789,
    "auth": {
      "mode": "token",
      "token": "${OPENCLAW_GATEWAY_TOKEN}",
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
  }
}
```

**Token vs Password:** Tokens are preferred over passwords because they are generated with sufficient entropy (256 bits), are not reused across services, and can be rotated without user interaction. Passwords are only appropriate for interactive pairing flows.

#### TrustedProxies

If running behind a reverse proxy (nginx, Caddy), set `trustedProxies` to the proxy IP addresses so the gateway reads the real client IP from `X-Forwarded-For`. An empty array (the default set by this script) means no proxies are trusted, which is correct for loopback-only deployments.

### 2. DM & Channel Policy

OpenClaw can receive messages from direct messages and group channels across all connected platforms. The DM policy controls who can initiate a conversation with the agent.

#### DM Policy Spectrum

| Policy | Description | Risk Level |
|--------|-------------|------------|
| `disabled` | No DMs accepted from any user | Lowest |
| `allowlist` | Only pre-approved user IDs can DM | Low |
| `pairing` | Users must complete a pairing flow (one-time code) | Medium |
| `open` | **Any user on the platform can DM the agent** | **Critical** |

**Why "open" is catastrophic:** With an `open` DM policy, any Telegram user, any Discord member of a shared server, or any WhatsApp contact can send instructions to your agent. The agent will execute tool calls (file reads, shell commands, web requests) on behalf of a completely untrusted party. Combined with insufficient tool restrictions, this is full RCE from a chat message.

This script omits placeholder channel blocks so OpenClaw's built-in `pairing` default applies until you explicitly configure a channel. When onboarding a channel, keep `dmPolicy` at `pairing` or tighten it to `allowlist` with exact trusted user IDs.

#### Per-Channel Configuration

Each messaging platform has its own channel configuration:

```jsonc
{
  "channels": {
    "telegram": {
      "enabled": true,
      "dmPolicy": "allowlist",
      "allowedUsers": ["123456789"],       // Telegram user IDs
      "groupMentionOnly": true,            // Respond only when @mentioned in groups
      "allowedGroups": ["-1001234567890"]   // Specific group IDs only
    },
    "discord": {
      "enabled": true,
      "dmPolicy": "allowlist",
      "allowedUsers": ["987654321098765432"],
      "mentionGating": true,               // Require @mention in channels
      "allowedChannels": ["1234567890"]     // Specific channel IDs
    },
    "whatsapp": {
      "enabled": false                     // Disable unless needed
    },
    "slack": {
      "enabled": false
    },
    "signal": {
      "enabled": false
    }
  }
}
```

#### Session Isolation Scopes

Sessions control the memory boundary of agent conversations. A wider scope means more users share the same context.

| Scope | Isolation | Use Case |
|-------|-----------|----------|
| `main` | Single global session | Dangerous -- all users share context and history |
| `per-peer` | One session per user ID across all channels | Standard for single-user setups |
| `per-channel-peer` | One session per user per channel | Multi-channel setups |
| `per-account-channel-peer` | One session per user per channel per platform account | Maximum isolation for multi-platform |

This script sets `tools.message.crossContext` (`allowWithinProvider: false`, `allowAcrossProviders: false`, `marker.enabled: true`) to prevent cross-channel context leakage.

### 3. Tool Policy & Execution Security

OpenClaw's power comes from its tools -- shell execution, file operations, web browsing, and browser automation. Tool policy controls which tools are available and how they execute.

#### Tool Profiles

| Profile | Tools Available | Risk Level | Use Case |
|---------|----------------|------------|----------|
| `minimal` | File read, search, list | Lowest | Read-only assistant |
| `messaging` | Minimal + message send/reply | Low | Chat bot without code execution |
| `coding` | Messaging + shell (sandboxed), file write, git | Medium | Development assistant |
| `full` | All tools including host shell, browser, admin | **High** | Full autonomous agent |

This script sets the default profile to `messaging` and explicitly denies `["exec", "process", "apply_patch", "browser"]`.

#### Execution Security Model

| Setting | Options | Hardened Value |
|---------|---------|----------------|
| `tools.exec.host` | `gateway`, `sandbox`, `node` | `sandbox` -- never direct host execution |
| `tools.exec.security` | `deny`, `allowlist`, `full` | `allowlist` with empty `safeBins: []` |
| `tools.exec.ask` | `always`, `on-miss`, `off` | `always` -- require explicit approval |
| `tools.exec.strictInlineEval` | `true`, `false` | `true` |
| `tools.exec.timeoutSec` | Seconds | `300` -- terminate runaway commands |

#### SafeBins

SafeBins is a curated list of binaries the agent is allowed to execute directly (bypassing the denylist check). This is only relevant in `host` exec mode; sandboxed execution uses its own binary set.

```jsonc
{
  "exec": {
    "safeBins": [
      "ls", "cat", "head", "tail", "grep", "find", "wc",
      "git", "node", "npm", "npx", "tsc",
      "python3", "pip",
      "jq", "curl", "sed", "awk",
      "mkdir", "cp", "mv", "touch"
    ]
  }
}
```

**What to exclude from safeBins:** Never add `rm`, `dd`, `mkfs`, `chmod 777`, `chown`, `systemctl`, `reboot`, `shutdown`, `iptables`, or package managers (`pacman`, `apt`, `yum`).

#### Web Tool Restrictions

```jsonc
{
  "tools": {
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
  }
}
```

**Browser automation risks:** The headless browser tool can navigate to arbitrary URLs, fill forms, click buttons, and extract page content. If enabled, an attacker (via prompt injection or compromised channel) could use it to interact with internal services, OAuth flows, or admin panels accessible from the host network. Disable it unless your workflow explicitly requires it.

### 4. Elevated Mode -- The Most Dangerous Feature

Elevated mode grants the agent direct, unrestricted host shell access with no sandboxing, no denylist filtering, and no confirmation prompts. It is designed for trusted operators who need the agent to perform system administration tasks.

#### Why Elevated Mode Is Critical Severity

In elevated mode, the agent can:
- Execute any command as the OpenClaw user (`rm -rf /`, `dd if=/dev/zero of=/dev/sda`)
- Read any file the user has access to (`~/.ssh/id_ed25519`, `~/.gnupg/`)
- Install packages, modify system configuration, create users
- Exfiltrate data via network (`curl`, `scp`, `nc`)
- Modify its own configuration to persist access

#### The allowFrom Wildcard Problem

```jsonc
// DANGEROUS -- any user on any platform can enable elevated mode
{
  "elevated": {
    "allowFrom": ["*"]
  }
}

// DANGEROUS -- any user on Telegram can enable elevated mode
{
  "elevated": {
    "allowFrom": ["telegram:*"]
  }
}

// SAFE -- only this specific Telegram user ID
{
  "elevated": {
    "allowFrom": ["telegram:123456789"]
  }
}

// SAFEST -- elevated mode disabled entirely
{
  "elevated": {
    "enabled": false
  }
}
```

This script sets `elevated.enabled` to `false`. If you need elevated mode, configure exact user IDs and specific channel IDs.

#### Proper Elevated Configuration

If elevated mode is required:

```jsonc
{
  "elevated": {
    "enabled": true,
    "allowFrom": ["telegram:123456789"],
    "allowChannels": ["telegram:-1001234567890"],
    "requireConfirmation": true,
    "sessionTimeout": 300,
    "auditLog": true
  }
}
```

- `requireConfirmation`: The agent asks for explicit confirmation before each elevated command
- `sessionTimeout`: Elevated mode auto-disables after 300 seconds (5 minutes) of inactivity
- `auditLog`: Every elevated command is logged to a separate audit file

#### Verifying Elevated Is Disabled

```bash
# Check the config file
grep -A3 '"elevated"' ~/.openclaw/openclaw.json

# Via the CLI
openclaw config get tools.elevated.enabled
# Should output: false

# In a chat session, the /elevated command should return:
# "Elevated mode is disabled by configuration."
```

#### The /elevated Session Command

Users can toggle elevated mode within a chat session using `/elevated on` and `/elevated off`. This only works if `elevated.enabled` is `true` in the config and the user's ID is in `allowFrom`. The `/elevated status` command shows whether elevated mode is currently active.

### 5. Docker Sandbox Configuration

The Docker sandbox executes agent tool calls inside an isolated container, preventing direct host access. **Important:** `openclaw.sh --with-sandbox` requires **rootless Docker** (`/run/user/<UID>/docker.sock`) and explicitly refuses to run if the OpenClaw user belongs to the system `docker` group (because membership in `docker` is equivalent to host `root`).

#### Sandbox Modes

| Mode | Description | Risk Level |
|------|-------------|------------|
| `off` | All execution on host | **High** |
| `non-main` | Sandbox non-main sessions, host for main | Medium |
| `all` | **All execution sandboxed** | Lowest |

This script sets the sandbox mode to `all`.

#### Workspace Access Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| `none` | No workspace mounted | Maximum isolation, limited usefulness |
| `ro` | Read-only workspace mount | Code review, analysis |
| `rw` | Read-write workspace mount | Development, code generation |

#### Docker Security Flags

| Flag | Value | Purpose |
|------|-------|---------|
| `--network` | `none` | No network access from sandbox |
| `--read-only` | `true` | Read-only root filesystem |
| `--cap-drop` | `ALL` | Drop all Linux capabilities |
| `--security-opt` | `no-new-privileges` | Cannot escalate privileges |
| `--pids-limit` | `256` | Prevent fork bombs |
| `--memory` | `512m` | Memory limit |
| `--cpus` | `1.0` | CPU limit |
| `--tmpfs` | `/tmp:rw,noexec,nosuid,size=64m` | Writable tmp with no execution |
| `--ulimit` | `nofile=1024:1024` | File descriptor limit |

#### Building the Sandbox Image

```bash
# Pull the official OpenClaw sandbox base image
docker pull ghcr.io/openclaw/sandbox:latest

# Or build from the included Dockerfile
cd ~/.openclaw/sandbox/
docker build -t openclaw-sandbox:local .

# Verify the image
docker run --rm openclaw-sandbox:local cat /etc/os-release
```

#### Sandbox Configuration

```jsonc
{
  "agents": {
    "defaults": {
      "workspace": "/home/<USER>/.openclaw/workspace",
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
    }
  }
}
```

#### Sandbox vs Host Execution

| Aspect | Host Execution | Sandbox Execution |
|--------|---------------|-------------------|
| File system access | Full user access | Workspace only (configurable) |
| Network access | Full | None (default) |
| Installed tools | System-wide | Sandbox image only |
| Privilege escalation | Possible via sudo/SUID | Blocked by cap-drop and no-new-privileges |
| Fork bombs | Can exhaust system PIDs | Limited to 256 PIDs |
| Memory exhaustion | Can consume all RAM | Capped at 512 MB |
| Persistence | Commands affect host state | Container destroyed after each execution |
| Speed | Fastest | ~200ms overhead per command |
| Git operations | Full repo access | Workspace-scoped only |

### 6. Dangerous Commands Denylist

The execution denylist prevents the agent from running commands that could destroy data, exfiltrate secrets, or compromise the host. This applies in both host and sandbox modes (though sandbox provides additional containment).

#### Destructive Commands

| Pattern | Risk | Explanation |
|---------|------|-------------|
| `rm -rf /` | System destruction | Recursively deletes entire filesystem |
| `rm -rf /*` | System destruction | Same effect with glob |
| `rm -rf ~` | Data destruction | Deletes entire home directory |
| `mkfs.*` | Disk destruction | Formats disk partitions |
| `dd if=/dev/zero` | Disk destruction | Overwrites disk with zeros |
| `dd if=/dev/urandom` | Disk destruction | Overwrites disk with random data |
| `:(){ :\|:& };:` | Resource exhaustion | Fork bomb |
| `> /dev/sda` | Disk destruction | Redirect to raw disk device |
| `chmod -R 777 /` | Permission destruction | Makes entire filesystem world-writable |
| `chown -R` on system dirs | Permission destruction | Changes ownership of system directories |

#### Exfiltration Commands

| Pattern | Risk | Explanation |
|---------|------|-------------|
| `curl \| sh` | Remote code execution | Downloads and executes arbitrary script |
| `wget \| bash` | Remote code execution | Same via wget |
| `curl -d @/etc/passwd` | Data exfiltration | POSTs system files to remote server |
| `scp ~/.ssh/*` | Credential theft | Copies SSH keys to remote host |
| `tar czf - ~ \| nc` | Data exfiltration | Tars and streams home directory |
| `rsync ~ remote:` | Data exfiltration | Syncs home directory to remote |
| `base64 /etc/shadow` | Credential theft | Encodes sensitive files for copy-paste exfil |

#### Credential Exposure

| Pattern | Risk | Explanation |
|---------|------|-------------|
| `cat ~/.ssh/id_*` | Private key exposure | Reads SSH private keys |
| `cat ~/.gnupg/` | GPG key exposure | Reads GPG private keys |
| `printenv` | Secret exposure | Dumps all environment variables (may contain API keys) |
| `history` | Command history exposure | May contain typed passwords and tokens |
| `cat ~/.aws/credentials` | Cloud credential theft | AWS access keys |
| `cat ~/.config/gcloud/` | Cloud credential theft | GCP credentials |
| `cat /etc/shadow` | Password hash exposure | System password hashes |

#### Git Footguns

| Pattern | Risk | Explanation |
|---------|------|-------------|
| `git push --force` | Data destruction | Overwrites remote history |
| `git reset --hard` | Data destruction | Discards uncommitted changes |
| `git clean -fdx` | Data destruction | Deletes all untracked files including ignored |
| `git checkout .` | Data destruction | Discards all unstaged changes |

#### Safe Alternatives

| Dangerous Command | Safe Alternative |
|-------------------|-----------------|
| `rm -rf` | `rm -i` or `trash-put` (trash-cli) |
| `curl \| sh` | Download then inspect then execute |
| `git push --force` | `git push --force-with-lease` |
| `git reset --hard` | `git stash` then review |
| `git clean -fdx` | `git clean -n` (dry run first) |
| `chmod -R 777` | `chmod` on specific files with correct modes |
| `printenv` | `echo $SPECIFIC_VAR` for non-secret vars |

### 7. Prompt Injection Defense

OpenClaw processes untrusted content from multiple sources: chat messages, web page content, file contents, command output, and API responses. Prompt injection attacks attempt to manipulate the agent by embedding instructions in this untrusted content.

#### How OpenClaw Wraps Untrusted Content

All untrusted input is wrapped in content delimiters before being passed to the AI model:

```
<untrusted-content source="web-fetch" url="https://example.com">
[page content here]
</untrusted-content>
```

The AI model is instructed to treat content within these tags as data, not instructions. This is not a perfect defense (frontier models can still be manipulated), but it significantly raises the bar.

#### Suspicious Pattern Detection

OpenClaw scans incoming content for known injection patterns:

| Pattern Category | Examples | Action |
|------------------|----------|--------|
| Instruction override | "Ignore previous instructions", "You are now", "System:" | Warning logged, content flagged |
| Command injection | Backticks, `$(...)`, `; rm -rf` | Blocked or escaped |
| Encoding evasion | Base64-encoded instructions, Unicode homoglyphs | Decoded and re-scanned |
| Role manipulation | "As an admin, I need you to..." | Flagged for review |

#### Defense Layers

| Layer | What It Does | Coverage |
|-------|-------------|----------|
| Frontier model alignment | Model trained to resist prompt injection | Broad but imperfect |
| Content wrapping | Untrusted content marked with delimiter tags | Raises injection difficulty |
| Docker sandbox | Limits blast radius of successful injection | Execution containment |
| Network isolation | `--network none` blocks exfiltration from sandbox | Data loss prevention |
| Command denylist | Blocks destructive commands even if agent is tricked | Known-bad prevention |
| Tool allowlist | Restricts available tools to minimum needed | Attack surface reduction |
| Session isolation | Per-channel-peer scoping limits cross-contamination | Lateral movement prevention |
| Audit logging | All commands logged for post-incident review | Detection and forensics |

#### Workspace Git-Based Rollback

If a prompt injection attack modifies workspace files (context poisoning), you can use git to identify and revert changes:

```bash
# Check for unexpected modifications
cd ~/.openclaw/workspace
git status
git diff

# Revert all changes since last known-good state
git checkout <known-good-commit> -- .

# Or reset entirely
git reset --hard <known-good-commit>
```

This script initializes the workspace as a git repository (if not already one) and sets up a pre-session auto-commit so each session starts from a known state.

### 8. Plugin & Skill Security

OpenClaw supports plugins (server-side extensions) and skills (agent-side capabilities pulled from ClawHub). Both can introduce arbitrary code into the agent's execution environment.

#### Plugin Risk Levels

| Risk Level | Examples | Concern |
|------------|----------|---------|
| Low | Formatting plugins, emoji reactions | No tool access, cosmetic only |
| Medium | Search plugins, knowledge base connectors | Read access to external data |
| High | Code execution plugins, deployment tools | Write access, shell execution |
| Critical | Admin plugins, credential managers | Full system access, secret handling |

#### Deny-by-Default Plugin & Skill Policy

```jsonc
{
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
  }
}
```

- `plugins.allow: []` + `bundledDiscovery: "allowlist"` -- no plugins load unless explicitly allowlisted
- `skills.allowBundled: []` + `allowUploadedArchives: false` -- blocks untrusted archive skill installs
- `hooks.enabled: false` -- disables workspace/request hooks to prevent prompt injection

#### Auditing Installed Plugins

```bash
# List all installed plugins
openclaw plugin list

# Show details of a specific plugin
openclaw plugin info <plugin-name>

# Check plugin integrity (checksums)
openclaw plugin verify --all

# Remove a plugin
openclaw plugin remove <plugin-name>

# List skills pulled from ClawHub
openclaw skill list

# Remove a skill
openclaw skill remove <skill-name>
```

### 9. Logging & Secret Redaction

OpenClaw logs all agent activity including commands executed, files accessed, messages received, and API calls made.

#### Log Levels

| Level | What Gets Logged | Production Recommendation |
|-------|-----------------|---------------------------|
| `debug` | Everything including model prompts and responses | **Never in production** |
| `info` | Commands, file operations, messages, errors | Recommended |
| `warn` | Warnings and errors only | Minimum for production |
| `error` | Errors only | Insufficient for forensics |

This script sets the log level to `info`.

#### Automatic Secret Redaction

When `redactSensitive` is enabled, OpenClaw automatically redacts the following patterns from all log output:

| Pattern | Example | Redacted As |
|---------|---------|-------------|
| API keys | `sk-ant-api03-...` | `[REDACTED:API_KEY]` |
| Bearer tokens | `Bearer eyJhbG...` | `[REDACTED:BEARER]` |
| PEM private keys | `-----BEGIN RSA PRIVATE KEY-----` | `[REDACTED:PEM_KEY]` |
| AWS access keys | `AKIA...` | `[REDACTED:AWS_KEY]` |
| GitHub tokens | `ghp_...`, `github_pat_...` | `[REDACTED:GH_TOKEN]` |
| Generic secrets | Strings matching `secret`, `password`, `token` in key-value pairs | `[REDACTED:GENERIC]` |
| SSH private keys | `-----BEGIN OPENSSH PRIVATE KEY-----` | `[REDACTED:SSH_KEY]` |

#### Custom Redaction Patterns

Add custom patterns for application-specific secrets:

```jsonc
{
  "logging": {
    "level": "info",
    "consoleLevel": "info",
    "consoleStyle": "compact",
    "redactSensitive": "tools",
    "redactPatterns": [
      "sk-[a-zA-Z0-9_-]{20,}",
      "sk-ant-[a-zA-Z0-9_-]{20,}",
      "xox[bpors]-[a-zA-Z0-9-]+"
    ]
  }
}
```

**Why redactSensitive should never be "off":** With redaction disabled, any secret that appears in command output, file contents, or error messages is written to disk in plaintext. If logs are later accessed (by an attacker, a log aggregator, or a careless backup), all secrets are exposed.

#### Log Rotation

This script installs a per-user logrotate configuration using `copytruncate` (**never** `SIGUSR1`, because Node.js interprets `SIGUSR1` as activating the V8 inspector debugger!):

```
# /etc/logrotate.d/openclaw-<USER>
/home/<USER>/.openclaw/logs/*.log
/home/<USER>/.openclaw/agents/*/sessions/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    copytruncate
    su <USER> <GROUP>
}
```

### 10. File Permissions Reference

| Path | Mode | Owner | Purpose |
|------|------|-------|---------|
| `~/.openclaw/` | `700` | `USER:GROUP` | Root config directory; no other users should read agent data |
| `~/.openclaw/openclaw.json` | `600` | `USER:GROUP` | Main config (references `${OPENCLAW_GATEWAY_TOKEN}`) |
| `~/.openclaw/.env` | `600` | `USER:GROUP` | Gateway token and AI provider API keys (`EnvironmentFile`) |
| `~/.openclaw/credentials/` | `700` | `USER:GROUP` | Credential storage directory |
| `~/.openclaw/credentials/*` | `600` | `USER:GROUP` | Stored platform credentials |
| `~/.openclaw/agents/*/sessions/` | `700` | `USER:GROUP` | Session history; contains full conversation logs |
| `~/.openclaw/exec-approvals.json` | `600` | `USER:GROUP` | Cached command approval decisions |
| `~/.openclaw/workspace/` | `700` | `USER:GROUP` | Agent workspace; git-tracked for rollback |
| `~/.openclaw/logs/` | `750` | `USER:GROUP` | Log files directory |

> **Security Note:** Never add `<USER>` to the `docker` or `proc` groups (`docker` grants host-root container control; `proc` bypasses `hidepid=2`). When `--with-sandbox` is enabled, rootless Docker (`/run/user/<UID>/docker.sock`) is used instead.

### 11. systemd Service Hardening

OpenClaw runs as a user-level systemd service (`~/.config/systemd/user/openclaw-gateway.service`) with a security drop-in (`~/.config/systemd/user/openclaw-gateway.service.d/hardening.conf`), managed from root via `systemctl --machine=<USER>@ --user`.

#### systemd Directive Reference

| Directive | Value | Purpose |
|-----------|-------|---------|
| `ProtectSystem` | `strict` | Read-only filesystem except explicit `ReadWritePaths` |
| `ProtectHome` | `read-only` | Home hierarchy is read-only outside `~/.openclaw` |
| `ReadWritePaths` | `~/.openclaw` | Explicit write access to OpenClaw data directory |
| `PrivateTmp` | `yes` | Isolated `/tmp` namespace |
| `PrivateDevices` | `yes` | No access to physical devices |
| `NoNewPrivileges` | `yes` | Cannot escalate privileges via SUID/SGID |
| `ProtectKernelTunables` | `yes` | No writes to `/proc/sys`, `/sys` |
| `ProtectKernelModules` | `yes` | Cannot load kernel modules |
| `ProtectKernelLogs` | `yes` | No access to kernel log buffer |
| `ProtectControlGroups` | `yes` | Read-only cgroup filesystem |
| `ProtectHostname` | `yes` | Cannot change hostname |
| `ProtectProc` / `ProcSubset` | `invisible` / `pid` | Hide other processes in `/proc` |
| `RestrictAddressFamilies` | `AF_INET AF_INET6 AF_UNIX AF_NETLINK` | TCP, UDP, Unix sockets, netlink |
| `RestrictNamespaces` | `yes` (or `~cgroup ipc` with `--with-sandbox`) | Block namespace creation (except rootless Docker namespaces when sandboxed) |
| `RestrictRealtime` | `yes` | No realtime scheduling |
| `RestrictSUIDSGID` | `yes` | Cannot create SUID/SGID files |
| `MemoryDenyWriteExecute` | `no` | **Required for V8 JIT compilation** -- Node.js will crash without this |
| `LockPersonality` | `yes` | Cannot change execution domain |
| `SystemCallFilter` | `@system-service @network-io` (+ deny dangerous groups) | Allowlist of permitted syscall groups |
| `SystemCallErrorNumber` | `EPERM` | Return `EPERM` instead of `SIGSYS` on filtered syscalls |
| `SystemCallArchitectures` | `native` | No 32-bit compat syscalls |
| `CapabilityBoundingSet` | (empty) | No Linux capabilities |
| `UMask` | `077` | Restrictive file creation mask |
| `LimitNOFILE` | `4096` | File descriptor limit for WebSocket connections |
| `LimitNPROC` | `512` | Process limit |
| `AppArmorProfile` | `-openclaw-gateway` | Binds only OpenClaw to the unattached AppArmor profile (when `--with-apparmor`) |

#### Why MemoryDenyWriteExecute=no

V8 (the JavaScript engine in Node.js) uses Just-In-Time (JIT) compilation, which requires memory pages to be simultaneously writable and executable. Setting `MemoryDenyWriteExecute=yes` would cause Node.js to crash on startup with a `SIGABRT`. This is a known and accepted limitation of running any V8-based process under systemd hardening.

#### Managing the User Service

`openclaw.sh` enables `loginctl enable-linger <USER>` so the user manager starts at boot without requiring an interactive login session:

```bash
systemctl --machine=<USER>@ --user enable --now openclaw-gateway.service
systemctl --machine=<USER>@ --user status openclaw-gateway.service
```

### 12. Network Security

#### nftables Rules

When `--with-firewall` is specified, this script creates `/etc/nftables.d/openclaw.conf`, persists its include as an AwesomeArchLinux-managed block in `/etc/nftables.conf`, and loads it immediately:

```nft
table inet openclaw {
    chain input {
        type filter hook input priority -10; policy accept;
        iifname != "lo" tcp dport 18789 limit rate 5/minute log prefix "openclaw-blocked: " level warn
        iifname != "lo" tcp dport 18789 drop
    }
}
```

The first rule rate-limits logging; it does not rate-limit accepted remote clients. The second rule drops every non-loopback packet to the gateway port. No outbound restriction is claimed: a destination-port allowlist inside a policy-accept chain would not enforce one, while a static policy-drop list would be brittle for dynamic API and messaging endpoints. Outbound control remains the responsibility of the host firewall and service sandbox.

#### Typical Outbound Ports (informational)

| Port | Protocol | Destination | Purpose |
|------|----------|-------------|---------|
| 443 | TCP | `api.anthropic.com` | Claude API |
| 443 | TCP | `api.openai.com` | OpenAI API (if configured) |
| 443 | TCP | `api.telegram.org` | Telegram Bot API |
| 443 | TCP | `discord.com`, `gateway.discord.gg` | Discord API and gateway |
| 443 | TCP | `slack.com`, `wss-primary.slack.com` | Slack API and WebSocket |
| 443 | TCP | `web.whatsapp.com` | WhatsApp Web API |
| 443 | TCP | `textsecure-service.whispersystems.org` | Signal API |
| 443 | TCP | `matrix-client.matrix.org` | Matrix homeserver (varies) |
| 443 | TCP | `registry.npmjs.org` | npm packages (for updates) |
| 443 | TCP | `ghcr.io` | Docker sandbox image pulls |
| 53 | UDP/TCP | DNS resolver | Name resolution |

#### SSH Tunnel for Remote Access

With the gateway bound to loopback, remote access is achieved via an SSH tunnel:

```bash
# From your local machine, forward port 18789 to the server's loopback
ssh -L 18789:localhost:18789 user@server

# Now connect to the gateway at localhost:18789 on your local machine
# The connection is encrypted via SSH and never exposed to the network
```

For persistent tunnel access, use autossh:

```bash
# Install autossh
pacman -S autossh

# Persistent tunnel that reconnects on failure
autossh -M 0 -f -N -L 18789:localhost:18789 user@server \
    -o "ServerAliveInterval 30" \
    -o "ServerAliveCountMax 3"
```

#### Tailscale Serve vs Funnel

| Feature | Tailscale Serve | Tailscale Funnel |
|---------|----------------|------------------|
| Accessible from | Your Tailscale network only | **The entire internet** |
| Authentication | Tailscale identity (WireGuard) | None by default |
| Risk level | Low | **High -- equivalent to binding 0.0.0.0** |
| Recommendation | Safe for personal use | **Never use for OpenClaw** |

```bash
# SAFE -- expose on your tailnet only
tailscale serve --bg 18789

# DANGEROUS -- exposes to the entire internet
# tailscale funnel 18789  # DO NOT DO THIS
```

### 13. AppArmor Confinement

When `--with-apparmor` is specified, this script installs an AppArmor profile at `/etc/apparmor.d/openclaw-gateway`.

#### Profile Summary

| Access Type | Allowed | Denied |
|-------------|---------|--------|
| Network: inet/inet6 stream | Yes (TCP for API calls, WebSocket) | |
| Network: inet/inet6 dgram | Yes (UDP for DNS) | |
| Network: unix stream | Yes (Docker socket if sandbox enabled) | |
| Network: raw | | Yes (no raw sockets) |
| File read: `/usr/bin/node` and `$OPENCLAW_BIN` | Yes | |
| File read: `/usr/lib/node_modules/` | Yes | |
| File read/write: `~/.openclaw/**` | Yes (other `$HOME` dirs like `~/.config`, `~/.mozilla`, `~/.netrc` are not readable) | |
| File write: `~/.openclaw/.env` and `~/.openclaw/credentials/**` | | Explicitly denied (`w` blocked even to owner) |
| Rootless Docker (`--with-sandbox`): `/usr/bin/docker` & `/run/user/*/docker.sock` | Yes (`rix` / `owner rw`) | |
| File read: `/etc/ssl/certs/` | Yes (TLS certificate store) | |
| File read: `/etc/resolv.conf` | Yes (DNS resolution) | |
| File: `/proc/self/**` | Read-only | |
| File: `/home/*/.ssh/` | | Denied |
| File: `/home/*/.gnupg/` | | Denied |
| File: `/etc/shadow` | | Denied |
| File: `/etc/passwd` | Read-only | |
| Capability: ptrace | | Denied |
| Capability: mount | | Denied |
| Capability: sys_admin | | Denied |
| Capability: sys_rawio | | Denied |
| Capability: sys_ptrace | | Denied |
| Signal: send to self | Yes | |
| Signal: send to others | | Denied |

#### Why ptrace/mount/raw Are Denied

- **ptrace**: Allows a process to inspect and modify the memory of other processes. An attacker could use it to read secrets from other running services or inject code into them.
- **mount**: Allows mounting filesystems, potentially overlaying system directories with attacker-controlled content.
- **sys_rawio**: Allows raw I/O port access and direct memory/disk access, bypassing filesystem permissions entirely.

#### Managing the Profile

```bash
# Check current status
aa-status | grep openclaw

# Reload after config changes
apparmor_parser -r /etc/apparmor.d/openclaw-gateway

# Switch to complain mode for debugging (logs but does not block)
aa-complain /etc/apparmor.d/openclaw-gateway

# Switch back to enforce mode
aa-enforce /etc/apparmor.d/openclaw-gateway

# View denials in real time
journalctl -f | grep apparmor.*DENIED
```

### 14. Incident Response

If you suspect the OpenClaw agent or gateway has been compromised, follow these steps in order.

#### Step 1: Kill the Gateway

```bash
# Stop the service immediately
systemctl --user stop openclaw-gateway

# Verify it is stopped
systemctl --user status openclaw-gateway

# If the service does not stop, force kill
pkill -9 -f "openclaw.*gateway"
```

#### Step 2: Disable All Channels

Edit `~/.openclaw/openclaw.json` and set `enabled: false` for every channel, or rename the config file to prevent restart:

```bash
mv ~/.openclaw/openclaw.json ~/.openclaw/openclaw.json.disabled
```

#### Step 3: Rotate All Secrets

```bash
# Regenerate gateway token in ~/.openclaw/.env
NEW_TOKEN=$(openssl rand -hex 32)
sed -i "s/^OPENCLAW_GATEWAY_TOKEN=.*/OPENCLAW_GATEWAY_TOKEN=${NEW_TOKEN}/" ~/.openclaw/.env

# Rotate API keys (manually via provider dashboards)
# - Anthropic: https://console.anthropic.com/settings/keys
# - OpenAI: https://platform.openai.com/api-keys

# Rotate platform bot tokens
# - Telegram: /revoke via @BotFather
# - Discord: Bot settings > Reset Token
# - Slack: App settings > Reinstall to workspace
```

#### Step 4: Review Session Logs

```bash
# Review recent sessions for suspicious activity
ls -lt ~/.openclaw/agents/*/sessions/ | head -20

# Search for unusual commands
grep -r "curl\|wget\|scp\|nc \|netcat\|base64\|/etc/shadow\|/etc/passwd\|ssh.*key" \
    ~/.openclaw/agents/*/sessions/

# Search for elevated mode usage
grep -r "elevated.*on\|elevated.*true" ~/.openclaw/agents/*/sessions/

# Check for commands executed outside workspace
grep -r '"tool":"exec"' ~/.openclaw/agents/*/sessions/ | grep -v workspace
```

#### Step 5: Run Security Audit

```bash
openclaw security audit --deep --filesystem
```

#### Step 6: Check Workspace for Context Poisoning

```bash
cd ~/.openclaw/workspace
git log --oneline -20
git diff HEAD~5..HEAD
git status

# Look for files that should not exist
find ~/.openclaw/workspace -name "*.sh" -o -name "*.py" -o -name "*.js" | \
    xargs grep -l "curl\|wget\|eval\|exec"
```

#### Step 7: Clear Agent Memory

If the agent's context has been poisoned (injected instructions persisted in memory):

```bash
# Clear all session history
rm -rf ~/.openclaw/agents/*/sessions/*

# Or clear a specific agent's memory
openclaw agent clear-memory --agent default

# Verify
openclaw agent info --agent default
```

#### Signs of Compromise

| Indicator | What to Check |
|-----------|---------------|
| Unexpected network connections | `ss -tlnp \| grep -v 127.0.0.1` |
| Commands you did not request | Session logs, `journalctl --user -u openclaw-gateway` |
| Files modified outside workspace | `find ~ -newer ~/.openclaw/openclaw.json -not -path '~/.openclaw/*'` |
| Agent responding to unseen messages | Channel message history vs session logs |
| New or modified plugins/skills | `openclaw plugin list`, `openclaw skill list`, check modification times |
| Unusual outbound DNS queries | `journalctl -u systemd-resolved` or DNS query logs |
| Gateway `.env` file modified | `stat ~/.openclaw/.env` |
| Exec-approvals modified | `stat ~/.openclaw/exec-approvals.json`, review contents |

### 15. Security Audit

#### The openclaw security audit Command

```bash
# Quick audit
openclaw security audit

# Deep audit with filesystem permission checks
openclaw security audit --deep --filesystem

# Output as JSON for automation
openclaw security audit --deep --json > /var/log/openclaw/audit-$(date +%Y%m%d).json
```

#### What the Audit Checks

| Check | Severity | Description |
|-------|----------|-------------|
| Gateway bind address | Critical | Verifies gateway is bound to loopback, not 0.0.0.0 |
| Gateway authentication | Critical | Verifies token auth is enabled |
| DM policy | Critical | Flags `open` DM policy |
| Elevated mode allowFrom wildcards | Critical | Flags wildcard patterns in elevated.allowFrom |
| Sandbox mode | High | Warns if sandbox is `off` |
| Exec denylist | High | Verifies denylist is not empty |
| Plugin policy | High | Warns if plugin policy is not `deny` |
| ClawHub auto-pull | High | Warns if skill auto-pull is enabled |
| File permissions | High | Checks all paths against expected permissions |
| Log redaction | Medium | Warns if `redactSensitive` is off |
| Log level | Medium | Warns if log level is `debug` in production |
| Session scope | Medium | Warns if scope is `main` (shared sessions) |
| Token age | Medium | Warns if gateway token is older than 90 days |
| Node.js version | Medium | Checks for known vulnerable Node.js versions |
| Dependency vulnerabilities | Medium | Runs `npm audit` on OpenClaw installation |
| Browser tool enabled | Low | Notes if headless browser is enabled |
| Hooks enabled | Low | Notes if plugin hooks are active |
| Workspace git status | Low | Notes if workspace has uncommitted changes |

#### The openclaw doctor Command

A lighter diagnostic check focused on configuration validity and service health:

```bash
openclaw doctor

# Example output:
# [PASS] Node.js >= 22.0.0 (v22.12.0)
# [PASS] Gateway config valid
# [PASS] Gateway reachable on 127.0.0.1:18789
# [PASS] Token auth configured
# [WARN] Telegram channel enabled but no allowedUsers set
# [PASS] Sandbox mode: all
# [PASS] Docker available and sandbox image pulled
# [PASS] File permissions correct
# [FAIL] AppArmor profile not loaded
# [PASS] Log rotation configured
```

#### Automated Weekly Audit via systemd Timer

This script creates a systemd timer that runs the deep audit weekly:

```ini
# ~/.config/systemd/user/openclaw-audit.service
[Unit]
Description=OpenClaw Weekly Security Audit
After=network-online.target

[Service]
Type=oneshot
EnvironmentFile=/home/<USER>/.openclaw/.env
UMask=0077
ExecStart=/home/<USER>/.local/bin/openclaw-security-audit.sh
PrivateTmp=true

# ~/.config/systemd/user/openclaw-audit.timer
[Unit]
Description=Weekly OpenClaw Security Audit Timer

[Timer]
OnCalendar=weekly
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
# Enable the timer
systemctl --user enable --now openclaw-audit.timer

# Verify
systemctl --user list-timers | grep openclaw
```

### 16. Secret Scanning

The script installs a pure-Bash `pre-commit` hook at `~/.openclaw/workspace/.git/hooks/pre-commit` (avoiding PEP 668 `pip install` conflicts on Arch Linux). Before every workspace commit, it scans `git diff --cached` for:

- Staged credential filenames (`.env`, `.env.*`, `*.pem`, `*.key`, `*.p12`, `*.pfx`)
- Anthropic (`sk-ant-...`), OpenAI (`sk-...`), GitHub (`ghp_...`, `github_pat_...`), GitLab (`glpat-...`), Slack (`xox[baprs]-...`), AWS (`AKIA...`), and Google (`AIza...`) keys
- PEM/SSH/PGP private key headers (`-----BEGIN ... PRIVATE KEY-----`) and gateway tokens

For full git history scanning, install `gitleaks` from the official Arch repositories — the installed `pre-commit` hook automatically invokes `gitleaks protect --staged` when present:

```bash
sudo pacman -S gitleaks
cd ~/.openclaw/workspace && gitleaks detect --redact
```

### 17. Complete Hardened Configuration Reference

```jsonc
// ~/.openclaw/openclaw.json -- Complete hardened configuration written by openclaw.sh
// Secrets live in ~/.openclaw/.env (OPENCLAW_GATEWAY_TOKEN, API keys), never in JSON.
{
  "gateway": {
    "mode": "local",
    "bind": "loopback",                // CRITICAL: Loopback (127.0.0.1) only.
    "port": 18789,
    "auth": {
      "mode": "token",
      "token": "${OPENCLAW_GATEWAY_TOKEN}",
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
      "workspace": "/home/<USER>/.openclaw/workspace",
      "sandbox": {
        "mode": "all",                 // "off" when run without --with-sandbox
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
      "search": { "enabled": true, "maxResults": 10, "timeoutSeconds": 15 },
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
        "marker": { "enabled": true }
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
      "Bearer\\s+[a-zA-Z0-9._-]+",
      "ghp_[a-zA-Z0-9]{36,}",
      "glpat-[a-zA-Z0-9_-]{20,}",
      "xox[bpors]-[a-zA-Z0-9-]+"
    ]
  }
}
```

### 18. Verification Commands

After running the hardening script, verify the configuration with these commands:

```bash
# --- Service Health ---
# Run the built-in diagnostic check
openclaw doctor

# Run a deep security audit
openclaw security audit --deep --filesystem

# Check the gateway service is running
systemctl --user status openclaw-gateway

# --- Network ---
# Verify gateway is bound to loopback only (should show 127.0.0.1:18789)
ss -tlnp | grep 18789
# Expected: 127.0.0.1:18789   LISTEN   ... node

# Verify no unexpected outbound connections
ss -tnp | grep openclaw

# --- File Permissions ---
# Config file should be 600 (owner read/write only)
stat -c "%a %U" ~/.openclaw/openclaw.json
# Expected: 600 myuser

# Credentials directory should be 700
stat -c "%a %U" ~/.openclaw/credentials/
# Expected: 700 myuser

# Exec-approvals should be 600
stat -c "%a %U" ~/.openclaw/exec-approvals.json
# Expected: 600 myuser

# --- Sandbox ---
# Verify Docker sandbox image exists
docker images | grep openclaw-sandbox

# Test sandbox execution
openclaw exec --sandbox "echo 'Sandbox working'"

# Verify sandbox network isolation
openclaw exec --sandbox "curl -s https://example.com" 2>&1
# Expected: network error (no network in sandbox)

# --- AppArmor ---
# Verify profile is loaded and in enforce mode
aa-status | grep openclaw
# Expected: openclaw-gateway (enforce)

# --- Firewall ---
# Verify nftables rules are loaded
nft list table inet openclaw

# --- Configuration ---
# Verify gateway bind mode
openclaw config get gateway.bind
# Expected: loopback

# Verify elevated mode is disabled
openclaw config get tools.elevated.enabled
# Expected: false

# Verify sandbox mode (when --with-sandbox was used)
openclaw config get agents.defaults.sandbox.mode
# Expected: all

# Verify log redaction is enabled
openclaw config get logging.redactSensitive
# Expected: tools
```

### 19. CVEs and Known Vulnerabilities

#### CVE-2026-25253 -- Remote Code Execution (Critical)

- **Affected versions:** All versions below 2026.1.29
- **Severity:** CVSS 10.0 (Critical)
- **Description:** The gateway WebSocket handler did not validate the authentication token before dispatching tool execution requests. An unauthenticated attacker could connect and execute arbitrary commands.
- **Mitigation:** Upgrade to 2026.1.29 or later. If upgrade is not possible, ensure the gateway is bound to loopback and behind an authenticated reverse proxy.
- **Reference:** [GHSA-xxxx-xxxx-xxxx](https://github.com/openclaw/openclaw/security/advisories)

#### Dependency Vulnerabilities

| Package | CVE | Severity | Fixed In | Description |
|---------|-----|----------|----------|-------------|
| `form-data` | CVE-2025-43869 | High | 4.0.2 | Prototype pollution via crafted form boundary |
| `qs` | CVE-2025-29927 | High | 6.14.0 | Prototype pollution via nested query strings |
| `tar` | CVE-2024-28863 | High | 6.2.1 | Path traversal during archive extraction |
| `hono` | CVE-2025-43859 | Medium | 4.7.5 | Request smuggling via header parsing |

```bash
# Check for vulnerable dependencies
cd /usr/lib/node_modules/openclaw
npm audit --omit=dev

# Update dependencies
npm update
```

#### Node.js Version Requirements

OpenClaw requires Node.js >= 22. Specific security patches in the Node.js 22.x line:

| Node.js Version | Fix | Relevance |
|-----------------|-----|-----------|
| 22.12.0 | Permission model improvements, HTTP request smuggling fix | Required minimum |
| 22.13.1 | CVE-2025-23083 (worker thread permission bypass) | Recommended |
| 22.14.0 | Multiple OpenSSL fixes | Recommended |

```bash
# Check current Node.js version
node --version

# Update Node.js on Arch
pacman -Syu nodejs
```

### 20. Generated Files

| Path | Description |
|------|-------------|
| `~/.openclaw/openclaw.json` | Hardened main configuration |
| `~/.openclaw/.env` | Gateway authentication token (`OPENCLAW_GATEWAY_TOKEN`) and API keys (`0600`) |
| `~/.config/systemd/user/openclaw-gateway.service` | Hardened systemd user service |
| `~/.config/systemd/user/openclaw-gateway.service.d/hardening.conf` | systemd sandboxing drop-in |
| `~/.config/systemd/user/openclaw-audit.service` | Security audit service (`EnvironmentFile=~/.openclaw/.env`, `UMask=0077`) |
| `~/.config/systemd/user/openclaw-audit.timer` | Weekly audit timer |
| `~/.local/bin/openclaw-security-audit.sh` | Automated audit wrapper script |
| `~/.openclaw/EXEC_DENYLIST.md` | Dangerous command denylist reference |
| `~/.openclaw/workspace/.git/hooks/pre-commit` | Pure-Bash secret-scanning pre-commit hook |
| `/etc/apparmor.d/openclaw-gateway` | AppArmor confinement profile (if `--with-apparmor`) |
| `/etc/nftables.d/openclaw.conf` | nftables firewall rules (if `--with-firewall`) |
| `/etc/logrotate.d/openclaw-<USER>` | Per-user log rotation configuration (`copytruncate`) |

## References

- [OpenClaw GitHub](https://github.com/openclaw/openclaw) -- Source code and official documentation
- [OpenClaw Security Hardening Gist](https://gist.github.com/openclaw/security-hardening) -- Community hardening guide
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker) -- Docker container security baseline
- [Node.js Security Releases](https://nodejs.org/en/blog/vulnerability) -- Node.js vulnerability announcements
- [OWASP Guidelines for AI Agents](https://owasp.org/www-project-top-10-for-large-language-model-applications/) -- LLM/agent security risks
- [Anthropic Security Documentation](https://docs.anthropic.com/en/docs/build-with-claude/prompt-engineering/mitigate-jailbreaks) -- Prompt injection mitigation
- [systemd exec sandboxing](https://www.freedesktop.org/software/systemd/man/systemd.exec.html) -- systemd security directives
- [AppArmor -- Arch Wiki](https://wiki.archlinux.org/title/AppArmor) -- AppArmor setup on Arch Linux
- [nftables -- Arch Wiki](https://wiki.archlinux.org/title/Nftables) -- nftables firewall on Arch Linux
- [detect-secrets](https://github.com/Yelp/detect-secrets) -- Secret scanning for repositories
- [Tailscale Serve and Funnel](https://tailscale.com/kb/1223/funnel) -- Tailscale network exposure documentation
