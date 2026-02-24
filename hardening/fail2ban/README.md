# fail2ban Hardening for Arch Linux

Extended fail2ban jail configuration with nftables integration, targeting SSH brute-force protection, nginx HTTP abuse mitigation, and automatic escalation for repeat offenders.

## Usage

```bash
sudo ./fail2ban.sh              # Default SSH port 22
sudo ./fail2ban.sh -p 2222      # Custom SSH port
sudo ./fail2ban.sh -h           # Show help
```

## Jail Descriptions

### SSH Jails

| Jail | Trigger | Ban Duration | Description |
|------|---------|-------------|-------------|
| `sshd` | 3 failed logins in 1h | 24 hours | Standard SSH brute-force protection. Matches failed password and publickey attempts. Uses the built-in `sshd` filter. |
| `sshd-aggressive` | 1 attempt | 7 days | Zero-tolerance jail with a custom filter. Catches invalid usernames, connections closed without authenticating, disconnections before auth, and bad protocol version strings. Designed for clearly malicious probing. |

### nginx Jails

| Jail | Trigger | Ban Duration | Description |
|------|---------|-------------|-------------|
| `nginx-http-auth` | 3 failures in 10m | 1 hour | Protects HTTP basic auth endpoints from credential stuffing. Reads from nginx error log. |
| `nginx-botsearch` | 2 attempts in 10m | 7 days | Catches vulnerability scanners probing for common exploit paths (e.g., `/wp-admin`, `/phpmyadmin`, `/.env`). Reads from nginx access log. |
| `nginx-limit-req` | 5 violations in 10m | 1 hour | Enforces nginx rate limiting. Requires `limit_req_zone` and `limit_req` directives in your nginx config. Reads from nginx error log. |

### Recidive Jail

| Jail | Trigger | Ban Duration | Description |
|------|---------|-------------|-------------|
| `recidive` | 3 bans in 1 day | 4 weeks | Monitors fail2ban's own log. If any IP gets banned 3 times across any jail within 24 hours, it is banned from **all ports** for 4 weeks. Uses `nftables-allports` action. |

## Files Created

```
/etc/fail2ban/jail.local                          # Jail configuration (overrides jail.conf)
/etc/fail2ban/filter.d/sshd-aggressive.conf       # Custom aggressive SSH filter
/etc/fail2ban/action.d/nftables-common.local      # nftables action override for Arch
```

## Customization

### Adding Your IP to the Whitelist

Edit `/etc/fail2ban/jail.local` and add your IP to the `ignoreip` line in the `[DEFAULT]` section:

```ini
ignoreip = 127.0.0.1/8 ::1 203.0.113.50 2001:db8::1
```

### Adjusting Ban Times

All time values support these suffixes: `s` (seconds), `m` (minutes), `h` (hours), `d` (days), `w` (weeks).

```ini
bantime  = 1h       # 1 hour
bantime  = 7d       # 7 days
bantime  = 4w       # 4 weeks
bantime  = -1       # permanent ban (until manual unban)
```

### Disabling a Jail

Set `enabled = false` in the jail section within `/etc/fail2ban/jail.local`:

```ini
[nginx-botsearch]
enabled = false
```

Then reload: `sudo fail2ban-client reload`

### Adding Email Notifications

Install a mail transfer agent and add to `[DEFAULT]` in `jail.local`:

```ini
destemail  = admin@example.com
sender     = fail2ban@example.com
mta        = sendmail
action     = %(action_mwl)s
```

## Checking Ban Status

```bash
# List all active jails
sudo fail2ban-client status

# Show status of a specific jail (banned IPs, total bans, etc.)
sudo fail2ban-client status sshd
sudo fail2ban-client status sshd-aggressive
sudo fail2ban-client status recidive

# View fail2ban log in real time
sudo journalctl -u fail2ban -f

# View active nftables rules (see fail2ban chains)
sudo nft list ruleset

# Check how many IPs are currently banned across all jails
sudo fail2ban-client status | grep "Jail list" | sed 's/.*://;s/,/\n/g' | \
    xargs -I{} sh -c 'echo "--- {} ---"; sudo fail2ban-client status {}'
```

## Unbanning IPs

```bash
# Unban a specific IP from a specific jail
sudo fail2ban-client set sshd unbanip 203.0.113.50

# Unban from the aggressive jail
sudo fail2ban-client set sshd-aggressive unbanip 203.0.113.50

# Unban from the recidive jail (important — this jail blocks all ports)
sudo fail2ban-client set recidive unbanip 203.0.113.50

# Unban an IP from ALL jails at once
sudo fail2ban-client unban 203.0.113.50

# Unban all IPs from all jails
sudo fail2ban-client unban --all
```

## Troubleshooting

### fail2ban fails to start

Check the configuration for syntax errors:

```bash
sudo fail2ban-client -t
sudo journalctl -u fail2ban --no-pager -n 50
```

### nginx jails show 0 bans despite attacks

Ensure nginx log files exist and are readable by fail2ban:

```bash
ls -la /var/log/nginx/error.log /var/log/nginx/access.log
```

If nginx is not installed or logs do not exist yet, the nginx jails will be inactive but will not prevent fail2ban from starting.

### sshd-aggressive catches legitimate users

If a legitimate user triggers the aggressive filter (e.g., typos in username), either:

1. Add their IP to `ignoreip` in `jail.local`
2. Increase `maxretry` in the `[sshd-aggressive]` section
3. Unban them: `sudo fail2ban-client set sshd-aggressive unbanip <IP>`

### nftables rules not appearing

Verify nftables is running:

```bash
sudo systemctl status nftables
sudo nft list ruleset
```

fail2ban creates its own table (`f2b-table`) and chains dynamically. They appear only when at least one IP is banned.
