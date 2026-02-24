# Chrony NTS — Authenticated Time Synchronization

## What is NTS?

**NTS (Network Time Security)** is the authenticated extension of NTP, defined in [RFC 8915](https://datatracker.ietf.org/doc/html/rfc8915). Standard NTP packets are unauthenticated and transmitted in plaintext, making them vulnerable to man-in-the-middle attacks. An attacker who can manipulate NTP traffic can shift a system's clock forward or backward, which breaks:

- **TLS certificate validation** (expired or not-yet-valid certificates accepted)
- **DNSSEC signature verification** (time-bound signatures fail)
- **Kerberos authentication** (relies on clock synchronization within 5 minutes)
- **TOTP two-factor authentication** (time-based codes drift out of window)
- **Log correlation and forensics** (timestamps become unreliable)
- **Certificate Transparency** (log inclusion timestamps become meaningless)

NTS solves this with a two-phase protocol:

1. **NTS-KE (Key Establishment)** — A TLS 1.3 handshake over TCP port 4460 authenticates the server and derives session keys. The server provides AEAD-encrypted cookies.
2. **NTS-protected NTP** — Each NTP request/response carries an NTS authenticator extension field, using the cookies from phase 1. The AEAD construction (typically AES-SIV) ensures integrity and authenticity of every time packet.

Chrony has had native NTS client support since version 4.0 (2020).

## NTS Servers

All servers configured by this script support NTS:

| Server | Operator | Location | Notes |
|--------|----------|----------|-------|
| `time.cloudflare.com` | Cloudflare | Anycast (global) | Largest NTS deployment, lowest latency worldwide |
| `nts.netnod.se` | Netnod | Sweden | Swedish Internet infrastructure operator, runs `i.root-servers.net` |
| `ptbtime1.ptb.de` | PTB | Braunschweig, Germany | National metrology institute, operates cesium fountain clocks |
| `ptbtime2.ptb.de` | PTB | Braunschweig, Germany | Redundant PTB server |
| `nts.sth1.ntp.se` | Netnod | Stockholm, Sweden | Netnod datacenter 1 |
| `nts.sth2.ntp.se` | Netnod | Stockholm, Sweden | Netnod datacenter 2 |

The configuration requires `minsources 3`, meaning chrony will not adjust the clock unless at least 3 of these servers are reachable and in agreement. This protects against a compromised or malfunctioning individual server.

## What the Script Does

1. **Installs chrony** via pacman
2. **Disables systemd-timesyncd** (conflicts with chrony on NTP port)
3. **Backs up** the existing `/etc/chrony.conf`
4. **Writes a hardened** `/etc/chrony.conf` with all 6 NTS servers
5. **Creates** `/etc/chrony.keys` with permissions `640 root:chrony`
6. **Creates** `/var/log/chrony/` with permissions `750 root:chrony`
7. **Hardens the chronyd systemd service** with a drop-in override:
   - `ProtectSystem=strict` (read-only filesystem except explicit paths)
   - `ProtectHome=yes` (no access to /home)
   - `NoNewPrivileges=yes` (no privilege escalation)
   - `CapabilityBoundingSet=CAP_SYS_TIME CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID`
   - `SystemCallFilter=@system-service @clock` (restrict syscalls)
   - `ProtectKernelTunables=yes`, `ProtectKernelModules=yes`
   - `MemoryDenyWriteExecute=yes`
8. **Enables and starts** chronyd
9. **Verifies** NTS authentication is working

## Verification Commands

After running the script, verify NTS is working:

```bash
# Show NTS cookie status for each server
# Look for "NTS" in the "AuthData" column with cookie counts > 0
chronyc -N authdata

# Show all time sources, their stratum, poll interval, and offset
chronyc sources -v

# Show detailed NTP data including NTS authentication status
chronyc -N ntpdata

# Show current clock tracking information (offset, frequency, etc.)
chronyc tracking

# Check the systemd service status
systemctl status chronyd
```

### Expected Output

When NTS is working correctly, `chronyc -N authdata` should show something like:

```
Name/IP address             Mode KeyID Type KLen Last Atmp  NAK Cook CLen
=========================================================================
time.cloudflare.com          NTS     1   15  256  33m    0    0    8  100
nts.netnod.se                NTS     1   15  256  33m    0    0    8  100
ptbtime1.ptb.de              NTS     1   15  256  33m    0    0    8  100
ptbtime2.ptb.de              NTS     1   15  256  33m    0    0    8  100
nts.sth1.ntp.se              NTS     1   15  256  33m    0    0    8  100
nts.sth2.ntp.se              NTS     1   15  256  33m    0    0    8  100
```

Key indicators:
- **Mode = NTS** — NTS is active for this server
- **Cook > 0** — NTS cookies have been obtained (typically 8)
- **NAK = 0** — No authentication failures
- **Atmp = 0** — No retry attempts needed

## Troubleshooting

### NTS-KE Handshake Failures

If `chronyc -N authdata` shows `Mode = NTS` but `Cook = 0` and `Atmp > 0`:

```bash
# Check chrony logs for TLS errors
journalctl -u chronyd | grep -i nts

# Check if NTS-KE port is reachable
openssl s_client -connect time.cloudflare.com:4460 -brief

# Force chrony to retry NTS-KE
chronyc reload sources
```

Common causes:
- **Firewall blocking TCP 4460 outbound** (NTS-KE port)
- **TLS certificate issues** (system CA bundle outdated)
- **DNS resolution failure** (server hostname cannot be resolved)

### Firewall Rules

NTS requires two outbound connections:

| Protocol | Port | Direction | Purpose |
|----------|------|-----------|---------|
| TCP | 4460 | Outbound | NTS-KE (TLS 1.3 key establishment) |
| UDP | 123 | Outbound | NTP time queries |

**nftables example:**

```bash
# Allow outbound NTS-KE and NTP
nft add rule inet filter output tcp dport 4460 accept
nft add rule inet filter output udp dport 123 accept
```

**iptables example:**

```bash
iptables -A OUTPUT -p tcp --dport 4460 -j ACCEPT
iptables -A OUTPUT -p udp --dport 123 -j ACCEPT
```

### Clock Not Synchronizing

If `chronyc sources` shows all sources as `?` (unreachable):

```bash
# Check if chronyd is running
systemctl status chronyd

# Check DNS resolution
host time.cloudflare.com

# Check if UDP 123 outbound is allowed
chronyc activity

# Force an immediate sync attempt
chronyc makestep
```

### systemd-timesyncd Conflict

If both chronyd and systemd-timesyncd are running, they will fight over the system clock:

```bash
# Verify timesyncd is disabled
systemctl is-enabled systemd-timesyncd
systemctl is-active systemd-timesyncd

# If still active, disable it
sudo systemctl disable --now systemd-timesyncd
```

### Checking NTS vs Plain NTP

To confirm packets are actually NTS-authenticated (not falling back to plain NTP):

```bash
# The "Authenticated" field should show "yes" for NTS servers
chronyc -N ntpdata | grep -A2 "Name\|Authenticated"
```

If a server shows `Authenticated: no`, chrony has fallen back to unauthenticated NTP for that server. Check the NTS-KE handshake status with `chronyc -N authdata`.

## Configuration File Reference

| File | Purpose |
|------|---------|
| `/etc/chrony.conf` | Main chrony configuration |
| `/etc/chrony.keys` | Authentication keys (640 root:chrony) |
| `/var/lib/chrony/chrony.drift` | Clock drift rate data |
| `/var/lib/chrony/*.nts` | Cached NTS cookies (survives restart) |
| `/var/log/chrony/` | Tracking, measurement, and statistics logs |
| `/etc/systemd/system/chronyd.service.d/hardening.conf` | systemd hardening |

## Further Reading

- [RFC 8915 — Network Time Security for NTP](https://datatracker.ietf.org/doc/html/rfc8915)
- [Chrony NTS documentation](https://chrony-project.org/doc/4.5/chrony.conf.html#nts)
- [Cloudflare NTS announcement](https://blog.cloudflare.com/secure-time/)
- [Netnod NTS service](https://www.netnod.se/nts/)
- [PTB NTS time servers](https://www.ptb.de/cms/en/ptb/fachabteilungen/abt4/fb-44/ag-442/dissemination-of-legal-time/network-time-protocol-ntp-servers-of-ptb.html)
