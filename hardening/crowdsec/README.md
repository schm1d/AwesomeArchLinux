# CrowdSec IDS Hardening

Installs and configures [CrowdSec](https://www.crowdsec.net/) on Arch Linux -- a modern, open-source intrusion detection system with collaborative threat intelligence.

CrowdSec works by analyzing logs (SSH, nginx, system auth) to detect malicious behavior (brute force, port scanning, credential stuffing). When an attack is detected, it creates a **decision** (ban, captcha, throttle) that is enforced by a **bouncer** (nftables, nginx, etc.). Threat signals are shared across the CrowdSec network, so all participants benefit from collective detection.

## Quick Start

```bash
# Base install: SSH + system log monitoring
sudo ./crowdsec.sh

# With nftables IP blocking
sudo ./crowdsec.sh --with-nftables

# Full stack: SSH + nginx + nftables
sudo ./crowdsec.sh --with-nginx --with-nftables
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `--with-nginx` | Add nginx log acquisition and nginx bouncer | off |
| `--with-nftables` | Install nftables firewall bouncer for IP blocking | off |
| `-h` | Show help | |

### Prerequisites

- Arch Linux with `pacman`
- Root privileges (`sudo`)
- An AUR helper (`yay` or `paru`) for installing CrowdSec packages

## What It Does

### 1. Package Installation

CrowdSec packages are installed from the AUR:

| Package | Description |
|---------|-------------|
| `crowdsec` | CrowdSec engine (agent + LAPI) |
| `crowdsec-firewall-bouncer-nftables` | nftables bouncer (with `--with-nftables`) |
| `crowdsec-nginx-bouncer` | nginx bouncer (with `--with-nginx`) |

### 2. Log Acquisition

The script configures CrowdSec to monitor these log sources:

| Source | Method | Detection |
|--------|--------|-----------|
| SSH (sshd) | journalctl | Brute force, password spray, invalid users |
| systemd-logind | journalctl | Authentication anomalies |
| /var/log/auth.log | File (if exists) | PAM authentication events |
| Kernel messages | journalctl | Firewall drops, audit events |
| nginx access log | File (`--with-nginx`) | Web attacks, scanners, bots |
| nginx error log | File (`--with-nginx`) | Application errors, exploit attempts |

### 3. Detection Collections

Collections are bundles of parsers and detection scenarios:

| Collection | What It Detects |
|------------|-----------------|
| `crowdsecurity/linux` | System-level attacks, su/sudo brute force |
| `crowdsecurity/sshd` | SSH brute force, dictionary attacks, invalid users |
| `crowdsecurity/nginx` | HTTP flood, path traversal, scanner detection, CVE exploits |

### 4. nftables Firewall Bouncer

When `--with-nftables` is used, the bouncer creates nftables sets and chains to block banned IPs at the kernel level:

- **Table**: `crowdsec` (IPv4) / `crowdsec6` (IPv6)
- **Chain**: `crowdsec-chain` / `crowdsec6-chain`
- **Action**: DROP (banned IPs are silently dropped)
- **Update frequency**: Every 10 seconds

### 5. systemd Service Hardening

The CrowdSec unit gets a security override with:

- `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`
- Kernel module/tunable/log/clock protection
- Capability bounding to `CAP_NET_BIND_SERVICE`
- Native-only syscall filtering
- `NoNewPrivileges`, namespace restrictions, `PrivateDevices`

## Generated Files

| Path | Description |
|------|-------------|
| `/etc/crowdsec/acquis.yaml` | Log acquisition configuration |
| `/etc/crowdsec/config.yaml` | Main CrowdSec config (default) |
| `/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml` | nftables bouncer config |
| `/etc/systemd/system/crowdsec.service.d/hardening.conf` | systemd security override |

## Common Operations

### Checking Alerts

```bash
# List recent alerts
cscli alerts list

# List alerts for a specific IP
cscli alerts list --ip 1.2.3.4

# Detailed alert info
cscli alerts inspect <alert_id>
```

### Viewing Active Decisions (Bans)

```bash
# List all active bans
cscli decisions list

# Check if a specific IP is banned
cscli decisions list --ip 1.2.3.4
```

### Manually Banning / Unbanning IPs

```bash
# Ban an IP for 24 hours
cscli decisions add --ip 1.2.3.4 --duration 24h --reason "manual ban"

# Ban an entire subnet
cscli decisions add --range 1.2.3.0/24 --duration 48h --reason "subnet ban"

# Unban a specific IP
cscli decisions delete --ip 1.2.3.4

# Remove all decisions
cscli decisions delete --all
```

### Whitelisting IPs

To prevent CrowdSec from ever banning trusted IPs, edit the whitelist parser:

```bash
# Edit the whitelist configuration
sudo nano /etc/crowdsec/parsers/s02-enrich/whitelist.yaml
```

Add your trusted IPs:

```yaml
name: crowdsecurity/whitelists
description: "Whitelist trusted IPs"
whitelist:
  reason: "trusted network"
  ip:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
    - "YOUR.TRUSTED.IP.HERE"
```

Then reload CrowdSec:

```bash
sudo systemctl reload crowdsec
```

### Viewing Metrics

```bash
# Overall metrics (parsing, scenarios, decisions)
cscli metrics

# Show what CrowdSec is currently processing
cscli metrics show acquisition
```

### Updating Hub Content

```bash
# Update the hub index
cscli hub update

# Upgrade all installed collections, parsers, and scenarios
cscli hub upgrade
```

## CrowdSec Console Enrollment

The [CrowdSec Console](https://app.crowdsec.net/) is a free web dashboard that provides:

- Real-time alert visualization
- IP reputation lookup
- Community blocklist subscription
- Multi-instance management

### Enrollment Steps

1. Create an account at [app.crowdsec.net](https://app.crowdsec.net/)
2. Copy your enrollment key from the console dashboard
3. Enroll your instance:

```bash
sudo cscli console enroll <YOUR_ENROLLMENT_KEY>
```

4. Approve the enrollment in the web console
5. Enable the community blocklist (recommended):

```bash
sudo cscli console enable blocklist:community
sudo systemctl reload crowdsec
```

## Integration with nftables

If you are using the AwesomeArchLinux nftables firewall configuration, the CrowdSec bouncer creates its own table (`crowdsec`) and chain. It operates independently and does not conflict with your existing nftables rules.

To verify the CrowdSec nftables rules are active:

```bash
# List CrowdSec nftables table
sudo nft list table ip crowdsec

# List the banned IP set
sudo nft list set ip crowdsec crowdsec-blacklists
```

If you prefer CrowdSec to use your existing nftables table instead of creating its own, edit `/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml` and set `set-only: true` along with your table and chain names.

## Integration with nginx

When using `--with-nginx`, CrowdSec monitors nginx logs for web-based attacks. The nginx bouncer can block malicious requests at the application level before they reach your backend.

The detected attack types include:

- HTTP brute force (login pages)
- Path traversal / directory enumeration
- Vulnerability scanner detection (Nikto, sqlmap, etc.)
- Known CVE exploit attempts
- Bad user agents and bot detection

## Troubleshooting

### CrowdSec service not starting

```bash
# Check service status and logs
systemctl status crowdsec
journalctl -u crowdsec -e --no-pager

# Validate configuration
cscli config show
```

### Bouncer not blocking IPs

```bash
# Verify the bouncer is registered and running
cscli bouncers list
systemctl status crowdsec-firewall-bouncer

# Check bouncer logs
journalctl -u crowdsec-firewall-bouncer -e --no-pager

# Verify nftables rules exist
sudo nft list table ip crowdsec
```

### Too many false positives

```bash
# Check which scenario triggered the ban
cscli alerts list
cscli alerts inspect <alert_id>

# Whitelist the IP (see Whitelisting section above)
# Or remove the offending scenario:
cscli scenarios remove crowdsecurity/<scenario_name>
```

### Acquisition not parsing logs

```bash
# Verify acquisition sources
cscli machines list
cscli metrics show acquisition

# Test a parser manually
echo '<log_line>' | cscli explain --type syslog
```

## Architecture Overview

```
                    ┌─────────────────┐
                    │  CrowdSec       │
                    │  Console (SaaS) │
                    └────────┬────────┘
                             │ enrollment + blocklists
                             │
┌──────────────┐    ┌────────┴────────┐    ┌──────────────────┐
│  Log Sources │───>│  CrowdSec       │───>│  Bouncers        │
│  - journalctl│    │  Engine (LAPI)  │    │  - nftables      │
│  - nginx logs│    │  - Parser       │    │  - nginx          │
│  - auth.log  │    │  - Scenarios    │    │  - custom         │
└──────────────┘    │  - Decisions    │    └──────────────────┘
                    └─────────────────┘
                             │
                    Shared threat
                    intelligence network
```

## References

- [CrowdSec Documentation](https://docs.crowdsec.net/)
- [CrowdSec Hub (Collections, Parsers, Scenarios)](https://hub.crowdsec.net/)
- [CrowdSec Console](https://app.crowdsec.net/)
- [CrowdSec GitHub](https://github.com/crowdsecurity/crowdsec)
- [Arch Wiki -- CrowdSec](https://wiki.archlinux.org/title/CrowdSec)
- [nftables Bouncer Documentation](https://docs.crowdsec.net/docs/bouncers/firewall/)
- [CrowdSec Community Blocklist](https://www.crowdsec.net/community-blocklist)
