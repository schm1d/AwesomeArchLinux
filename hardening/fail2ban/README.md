# fail2ban Hardening for Arch Linux

Extended fail2ban jail configuration with nftables integration, targeting SSH brute-force protection, nginx HTTP abuse mitigation, Postfix/Dovecot login protection, and automatic escalation for repeat offenders.

## Usage

```bash
sudo ./fail2ban.sh              # Default SSH port 22
sudo ./fail2ban.sh -p 2222      # Custom SSH port
sudo ./fail2ban.sh -p 2222 -i 203.0.113.50 -i 2001:db8:1234::/48   # Never ban these
sudo ./fail2ban.sh -h           # Show help
```

| Option | Meaning |
|---|---|
| `-p PORT` | SSH port (default 22; decimal, a leading zero is ignored) |
| `-i ADDRESS` | IPv4/IPv6 address or CIDR network that is never banned (repeatable). A `/0` network is rejected |
| `-h` | Show help |

`jail.local` is regenerated on every run (the previous file is kept as
`jail.local.bak.<timestamp>`). Pass the same `-p` and `-i` options again when
you re-run the script, otherwise the SSH port returns to 22 and the whitelist
to loopback only.

Give `-i` the address you administer the host from. Without it, three mistyped
SSH logins ban your own address for 24 hours, and three bans within a day
escalate to four weeks on all ports.

## Jail Descriptions

### SSH Jails

| Jail | Trigger | Ban Duration | Description |
|------|---------|-------------|-------------|
| `sshd` | 3 failed logins in 1h | 24 hours | Standard SSH brute-force protection. Matches failed password and publickey attempts via the built-in `sshd` filter plus `filter.d/sshd.local` (which matches OpenSSH 10.x `sshd-auth` / `sshd-session` journal entries). |
| `sshd-aggressive` | 3 attempts in 24h | 7 days | Custom filter catching invalid usernames, pre-auth closures/disconnections involving `(?:invalid\|authenticating) user`, and clients that do not send an SSH banner (`banner exchange: Connection from ... invalid format`), while ignoring benign bare TCP probes and Happy Eyeballs races. |

### nginx Jails

| Jail | Trigger | Ban Duration | Description |
|------|---------|-------------|-------------|
| `nginx-http-auth` | 3 failures in 10m | 1 hour | Protects HTTP basic auth endpoints from credential stuffing. Reads from nginx error log. |
| `nginx-botsearch` | 2 attempts in 10m | 7 days | Catches vulnerability scanners probing for common exploit paths (e.g., `/wp-admin`, `/phpmyadmin`, `/.env`). Reads from nginx access log. |
| `nginx-limit-req` | 5 violations in 10m | 1 hour | Enforces nginx rate limiting. Requires `limit_req_zone` and `limit_req` directives in your nginx config. Reads from nginx error log. |

### Mail Jails

| Jail | Trigger | Ban Duration | Description |
|------|---------|-------------|-------------|
| `postfix-sasl` | 5 failures in 1h | 24 hours | SMTP AUTH failures on the submission ports (`SASL ... authentication failed`), using the built-in `postfix[mode=auth]` filter on the systemd journal. Enabled when the `postfix` package is installed. |
| `dovecot` | 5 failures in 1h | 24 hours | IMAP/POP3/ManageSieve login failures, using the built-in `dovecot` filter on the systemd journal. Enabled when the `dovecot` package is installed. |

Both are written with `enabled = false` when the package is missing. Re-run
`fail2ban.sh` after `hardening/postfix/postfix.sh` to switch them on.

### Recidive Jail

| Jail | Trigger | Ban Duration | Description |
|------|---------|-------------|-------------|
| `recidive` | 3 bans in 1 day | 4 weeks | Monitors fail2ban's own log. If any IP gets banned 3 times across any jail within 24 hours, it is banned from **all ports** for 4 weeks. Uses `nftables-allports` action. |

## Files Created

```
/etc/fail2ban/jail.local                          # Jail configuration (overrides jail.conf)
/etc/fail2ban/filter.d/sshd.local                 # OpenSSH 10.x _daemon & journalmatch override for [sshd]
/etc/fail2ban/filter.d/sshd-aggressive.conf       # Custom aggressive SSH filter (OpenSSH 10.x aware)
/etc/fail2ban/action.d/nftables.local             # Dual-stack nftables action override
```

## Customization

### Adding Your IP to the Whitelist

Preferably pass the addresses with `-i` when running the script, so they survive a re-run:

```bash
sudo ./fail2ban.sh -p 2222 -i 203.0.113.50 -i 2001:db8::1
```

A manual edit of the `ignoreip` line in the `[DEFAULT]` section of
`/etc/fail2ban/jail.local` works as well, but is overwritten by the next run:

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
for jail in $(sudo fail2ban-client status | awk -F: '/Jail list:/ { gsub(/,/, " ", $2); print $2 }'); do
    printf -- '--- %s ---\n' "$jail"
    sudo fail2ban-client status "$jail"
done
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

If nginx is not installed or `/var/log/nginx/{access,error}.log` do not exist when `fail2ban.sh` runs, `[nginx-*]` jails are written with `enabled = false` so fail2ban always starts cleanly. Re-run `sudo ./fail2ban.sh` (or set `enabled = true` and `sudo fail2ban-client reload`) after configuring nginx.

### sshd-aggressive catches legitimate users

If a legitimate user triggers the aggressive filter (e.g., typos in username), either:

1. Add their IP with `-i` (or to `ignoreip` in `jail.local`)
2. Increase `maxretry` in the `[sshd-aggressive]` section
3. Unban them: `sudo fail2ban-client set sshd-aggressive unbanip <IP>`

### nftables rules not appearing

Verify nftables is running:

```bash
sudo systemctl status nftables
sudo nft list ruleset
```

fail2ban creates its own table (`f2b-table`) and chains dynamically. They appear only when at least one IP is banned.

## References

- [Fail2ban upstream repository and documentation](https://github.com/fail2ban/fail2ban)
- [`jail.conf(5)` upstream manual](https://github.com/fail2ban/fail2ban/blob/master/man/jail.conf.5)
- [Fail2ban upstream nftables action](https://github.com/fail2ban/fail2ban/blob/master/config/action.d/nftables.conf)
- [Fail2ban — ArchWiki](https://wiki.archlinux.org/title/Fail2ban)
- [systemd service sandboxing](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)
- [nftables documentation](https://wiki.nftables.org/wiki-nftables/index.php/Main_Page)
