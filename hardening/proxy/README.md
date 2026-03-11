# Hardened Transparent Proxy

Installs and configures a hardened [Squid](http://www.squid-cache.org/) transparent proxy on Arch Linux with domain blocklists, optional SSL bump (HTTPS inspection), and optional DNS filtering.

## Quick Start

```bash
# Basic transparent HTTP proxy
sudo ./proxy.sh -n 192.168.1.0/24

# Full setup: SSL bump + DNS filtering + larger cache
sudo ./proxy.sh -n 10.0.0.0/8 -c 20000 --ssl-bump --dns-filter

# Preview configs without starting
sudo ./proxy.sh -n 192.168.1.0/24 --dry-run
```

### Prerequisites

1. **Arch Linux** with root access
2. **Gateway position** — clients must route through this host
3. **nftables** for transparent interception

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-n CIDR` | LAN network CIDR | *required* |
| `-p PORT` | HTTP intercept port | `3128` |
| `-P PORT` | HTTPS intercept port | `3129` |
| `-c SIZE_MB` | Disk cache size in MB | `10000` |
| `-e EMAIL` | Admin email | `admin@hostname` |
| `--ssl-bump` | Enable HTTPS interception (peek-and-splice) | |
| `--dns-filter` | Enable DNS-level ad/malware blocking via dnsmasq | |
| `--dry-run` | Write configs, validate, don't start services | |
| `-h` | Show help | |

## Architecture

```
     Clients (192.168.1.0/24)
              │
     ┌────────┴────────┐
     │  nftables NAT   │──── REDIRECT port 80 → 3128
     │  (prerouting)   │     REDIRECT port 443 → 3129 (if --ssl-bump)
     └────────┬────────┘
              │
     ┌────────┴────────┐         ┌──────────────┐
     │  Squid Proxy    │────────►│  Blocklists   │
     │  (intercept)    │         │  ads/malware  │
     └────────┬────────┘         └──────────────┘
              │
     ┌────────┴────────┐         ┌──────────────┐
     │  SSL Bump       │         │  DNS Filter   │
     │  peek-and-      │         │  (dnsmasq)    │
     │  splice         │         └──────────────┘
     └────────┬────────┘
              │
         Origin Servers

     Anti-loop: nftables skuid exempts proxy user traffic
```

## What It Does

### Transparent Interception

Traffic from the configured network is transparently redirected to Squid via nftables REDIRECT rules. No client-side proxy configuration is needed — clients just need to route through this host.

| Component | Detail |
|-----------|--------|
| **nftables table** | `ip squid-proxy` with prerouting REDIRECT |
| **Anti-loop** | `skuid proxy` exempts Squid's own traffic |
| **HTTP** | Port 80 → `$HTTP_PORT` (intercept mode) |
| **HTTPS** | Port 443 → `$HTTPS_PORT` (if `--ssl-bump`) |
| **sysctl** | `ip_forward=1` via `/etc/sysctl.d/99-z-squid-proxy.conf` |

### Security Hardening

| Feature | Setting | Purpose |
|---------|---------|---------|
| **Via header** | `off` | Hide proxy presence |
| **X-Forwarded-For** | `delete` | Don't expose client IPs |
| **Server header** | Stripped | Don't reveal origin server |
| **X-Cache headers** | Stripped | Don't leak cache internals |
| **Version string** | Suppressed | Don't reveal Squid version |
| **CONNECT** | SSL ports only | Block tunneling to arbitrary ports |
| **Unsafe ports** | Denied | Only allow standard ports |
| **Conn limit** | 64/IP | Prevent resource exhaustion |
| **Delay pools** | 10 MB/s per client | Rate limiting |
| **Query strings** | Stripped from logs | Log privacy |

### Domain Blocklists

- **Ads + tracking**: StevenBlack unified hosts (100K+ domains)
- **Malware + fakenews**: StevenBlack extended list
- **Whitelist**: Custom whitelist for overrides
- **Auto-update**: systemd timer runs daily at 03:00

### SSL Bump (Optional)

When `--ssl-bump` is enabled:

- **Peek-and-splice mode**: Reads the SNI (server name) from the TLS ClientHello, then splices (passes through) by default — no decryption
- **Selective bumping**: Can be configured to decrypt specific domains for inspection
- **Dynamic certs**: Generates certificates on-the-fly signed by the proxy CA
- **TLS 1.2+**: Outbound connections use ECDHE/AEAD ciphers only
- **CA cert**: Must be deployed to client trust stores

### DNS Filtering (Optional)

When `--dns-filter` is enabled:

- **dnsmasq** provides DNS-level blocking using the same blocklists
- Blocks domains at the DNS layer before HTTP requests are made
- Upstream resolvers: Quad9 (9.9.9.9) and Cloudflare (149.112.112.112)
- Handles systemd-resolved conflict automatically
- systemd hardening applied to dnsmasq

### Cache

| Setting | Value | Purpose |
|---------|-------|---------|
| **Store type** | `rock` | SSD-friendly (no directory churn) |
| **Disk cache** | Configurable (default 10 GB) | Main object store |
| **Memory cache** | 256 MB | Hot objects |
| **Max object** | 256 MB | Large file caching |
| **Collapsed forwarding** | On | Deduplicates concurrent requests |
| **Refresh patterns** | Standard | FTP, dynamic, static content |

### systemd Hardening

- `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`
- `ProtectKernel{Tunables,Modules,Logs}=yes`
- `LockPersonality=yes`, `RestrictRealtime=yes`
- `CapabilityBoundingSet` limited to `CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_NET_ADMIN CAP_IPC_LOCK`
- `LimitNOFILE=65536`
- `NoNewPrivileges=no` (required — Squid internally drops privileges)

## Post-Installation

### Client Setup

Clients need to use this host as their default gateway:

```bash
# On client (or configure via DHCP)
ip route add default via <proxy-host-ip>
```

Or configure your DHCP server to hand out this host's IP as the default gateway.

### Customize Blocklists

```bash
# Add domains to whitelist
echo ".example.com" >> /etc/squid/blocklists/whitelist.txt
squid -k reconfigure

# Add custom blocked domains
echo ".badsite.com" >> /etc/squid/blocklists/ads.txt
squid -k reconfigure
```

### Deploy SSL CA Certificate (if --ssl-bump)

Clients must trust the proxy CA to avoid certificate warnings:

```bash
# Linux clients
cp /etc/squid/ssl/squid-ca.pem /usr/local/share/ca-certificates/squid-proxy.crt
update-ca-trust

# Export for other platforms
# The CA cert is at: /etc/squid/ssl/squid-ca.pem
```

### Selective SSL Bumping

To decrypt specific domains, edit `squid.conf`:

```
# Before the "ssl_bump splice all" line, add:
acl bump_domains dstdomain .suspicious-site.org .inspect-this.com
ssl_bump bump bump_domains
```

Then `squid -k reconfigure`.

## Testing

### Verify Proxy is Working

```bash
# Direct test
curl -x http://127.0.0.1:3128 http://example.com

# Verify transparent interception (from a client on the LAN)
curl http://example.com   # Should work without proxy config

# Check a blocked domain
curl -x http://127.0.0.1:3128 http://ads.example.com
# Should return 403 Forbidden
```

### Monitor Traffic

```bash
# Watch access log
tail -f /var/log/squid/access.log

# Cache statistics
squidclient -h 127.0.0.1 -p 3128 mgr:info
squidclient -h 127.0.0.1 -p 3128 mgr:5min
squidclient -h 127.0.0.1 -p 3128 mgr:utilization

# Cache hit ratio
squidclient mgr:info | grep "Hit Ratios"
```

### Verify nftables Rules

```bash
# View interception rules
nft list table ip squid-proxy

# Verify anti-loop rule
nft list chain ip squid-proxy output
```

### Validate Configuration

```bash
squid -k parse      # Validate config syntax
squid -k check      # Full validation
```

## Troubleshooting

### Squid won't start

```bash
systemctl status squid
journalctl -u squid -e
squid -k parse    # Check for config errors

# If systemd hardening is too restrictive
systemctl revert squid
systemctl restart squid
```

### Routing loop (client can't access anything)

```bash
# Verify anti-loop rule exists
nft list chain ip squid-proxy output | grep skuid

# If missing, re-add
nft add rule ip squid-proxy output skuid proxy tcp dport 80 accept
```

### DNS not resolving (with --dns-filter)

```bash
# Check dnsmasq
systemctl status dnsmasq
journalctl -u dnsmasq -e

# Check if port 53 is bound
ss -tlnp | grep ':53 '

# Test DNS directly
dig @127.0.0.1 example.com
```

### SSL bump certificate warnings

Ensure the CA cert is deployed to client trust stores. The CA cert is at `/etc/squid/ssl/squid-ca.pem`.

### Cache not working (all misses)

```bash
# Check cache directory permissions
ls -la /var/cache/squid/

# Re-initialize cache
systemctl stop squid
squid -z --foreground
chown -R proxy:proxy /var/cache/squid
systemctl start squid
```

## TPROXY Alternative

TPROXY preserves the original client source IP (the origin server sees the real client IP instead of the proxy's IP). See `/etc/squid/conf.d/tproxy-alternative.txt` for setup instructions.

## Generated Files

| Path | Description |
|------|-------------|
| `/etc/squid/squid.conf` | Main Squid configuration |
| `/etc/squid/blocklists/ads.txt` | Ads/tracking blocklist |
| `/etc/squid/blocklists/malware.txt` | Malware blocklist |
| `/etc/squid/blocklists/whitelist.txt` | Custom whitelist |
| `/etc/squid/ssl/squid-ca.{pem,key}` | SSL bump CA (if enabled) |
| `/etc/squid/ssl/dhparam.pem` | DH parameters (if SSL bump) |
| `/etc/squid/conf.d/tproxy-alternative.txt` | TPROXY setup guide |
| `/etc/sysctl.d/99-z-squid-proxy.conf` | ip_forward override |
| `/etc/systemd/system/squid.service.d/hardening.conf` | systemd hardening |
| `/etc/systemd/system/squid-blocklist-update.{service,timer}` | Auto-update |
| `/etc/logrotate.d/squid` | Log rotation (14 days) |
| `/etc/dnsmasq.d/proxy-{blocklist,dns}.conf` | DNS filtering (if enabled) |
| `/etc/systemd/system/dnsmasq.service.d/hardening.conf` | dnsmasq hardening (if enabled) |

## References

- [Squid Documentation](http://www.squid-cache.org/Doc/)
- [Squid Transparent Proxy](https://wiki.squid-cache.org/SquidFaq/InterceptionProxy)
- [Squid SSL Bump](https://wiki.squid-cache.org/Features/SslPeekAndSplice)
- [StevenBlack Hosts](https://github.com/StevenBlack/hosts)
- [nftables Wiki](https://wiki.nftables.org/)
- [Arch Wiki — Squid](https://wiki.archlinux.org/title/Squid)
- [Arch Wiki — dnsmasq](https://wiki.archlinux.org/title/Dnsmasq)
