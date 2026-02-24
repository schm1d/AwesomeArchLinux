# Postfix Send-Only Mail Relay

Installs and configures [Postfix](https://www.postfix.org/) as a **send-only mail relay** for system notifications on Arch Linux. The host does not accept inbound mail -- it only relays outbound messages (cron alerts, fail2ban notifications, SMART warnings, etc.) through an external SMTP provider.

## Quick Start

```bash
sudo ./postfix.sh -r smtp.gmail.com -u user@gmail.com -p 'your-app-password'
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-r HOST` | SMTP relay hostname | *required* |
| `-P PORT` | SMTP relay port | `587` |
| `-u USER` | SMTP relay username | |
| `-p PASS` | SMTP relay password | |
| `-f EMAIL` | Envelope From address | `root@$(hostname -f)` |
| `-a EMAIL` | Forward root mail to this address | |
| `-h` | Show help | |

## What It Does

### 1. Package Installation

- `postfix` (Arch official repos)
- `s-nail` (BSD mailx replacement for the `mail` command)

### 2. Sendmail Removal

Stops and masks `sendmail` if present to prevent conflicts.

### 3. Send-Only Relay Configuration (`main.cf`)

| Setting | Value | Purpose |
|---------|-------|---------|
| `inet_interfaces` | `loopback-only` | Listen only on localhost |
| `mydestination` | *(empty)* | No local delivery -- send-only |
| `relayhost` | `[HOST]:PORT` | All mail goes through the relay |
| `smtp_tls_security_level` | `encrypt` | Require TLS for all outbound |
| `smtp_tls_protocols` | `!SSLv2, !SSLv3, !TLSv1, !TLSv1.1` | TLS 1.2+ only |
| `smtp_sasl_auth_enable` | `yes` | Authenticate to the relay |
| `smtp_header_checks` | `regexp:/etc/postfix/header_checks` | Strip internal headers |
| `smtpd_relay_restrictions` | `permit_mynetworks, reject` | Reject all inbound relay |

### 4. Hardening

| Setting | Value | Purpose |
|---------|-------|---------|
| `disable_vrfy_command` | `yes` | Prevent user enumeration |
| `smtpd_helo_required` | `yes` | Require proper EHLO |
| `smtpd_client_restrictions` | `permit_mynetworks, reject` | Block external connections |
| `header_size_limit` | `51200` | Limit header size |
| `message_size_limit` | `10240000` (~10 MB) | Limit message size |
| `smtp_tls_loglevel` | `1` | Log TLS handshake summary |

### 5. Header Stripping

Internal `Received:` headers are stripped via `/etc/postfix/header_checks` to prevent leaking internal hostnames and IP addresses.

### 6. systemd Service Hardening

The postfix unit gets a security override (`/etc/systemd/system/postfix.service.d/hardening.conf`):

- `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`
- `NoNewPrivileges=yes`
- Capability bounding to `CAP_NET_BIND_SERVICE` only
- Write access limited to `/var/spool/postfix`, `/var/lib/postfix`, `/var/log/mail`

## Relay Setup Examples

### Gmail (App Password)

Requires a [Google App Password](https://support.google.com/accounts/answer/185833) (2FA must be enabled on the account).

```bash
sudo ./postfix.sh \
    -r smtp.gmail.com \
    -P 587 \
    -u your-address@gmail.com \
    -p 'your-16-char-app-password' \
    -a your-address@gmail.com
```

### SendGrid

Create an API key at [app.sendgrid.com/settings/api_keys](https://app.sendgrid.com/settings/api_keys) with "Mail Send" permission.

```bash
sudo ./postfix.sh \
    -r smtp.sendgrid.net \
    -P 587 \
    -u apikey \
    -p 'SG.xxxxxxxxxxxxxxxxxxxxxxxx' \
    -f noreply@yourdomain.com \
    -a admin@yourdomain.com
```

### Mailgun

Retrieve SMTP credentials from your Mailgun domain settings.

```bash
sudo ./postfix.sh \
    -r smtp.mailgun.org \
    -P 587 \
    -u postmaster@mg.yourdomain.com \
    -p 'your-mailgun-smtp-password' \
    -f noreply@yourdomain.com \
    -a admin@yourdomain.com
```

### Amazon SES

Create SMTP credentials in the [SES console](https://console.aws.amazon.com/ses/).

```bash
sudo ./postfix.sh \
    -r email-smtp.us-east-1.amazonaws.com \
    -P 587 \
    -u 'AKIAIOSFODNN7EXAMPLE' \
    -p 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' \
    -f noreply@yourdomain.com \
    -a admin@yourdomain.com
```

## Testing

### Send a test email

```bash
echo "Hello from $(hostname)" | mail -s "Test" your-address@example.com
```

### Check the mail queue

```bash
mailq
```

### Flush queued mail (retry delivery)

```bash
postqueue -f
```

### Watch postfix logs

```bash
journalctl -u postfix -f
```

### Verify TLS is used

```bash
# Send a test email, then check logs for TLS confirmation:
journalctl -u postfix --since "5 minutes ago" | grep "TLS connection established"
```

### Validate configuration

```bash
postfix check
postconf -n    # Show all non-default settings
```

## Troubleshooting

### Mail stuck in queue

```bash
# View the queue
mailq

# View a specific queued message
postcat -q <QUEUE_ID>

# Check why delivery failed
journalctl -u postfix -e | grep "status=deferred"

# Flush and retry
postqueue -f
```

### Authentication failure

```bash
# Verify SASL credentials file exists and has correct format
cat /etc/postfix/sasl_passwd
# Expected: [smtp.example.com]:587 user:password

# Regenerate the hash map
postmap /etc/postfix/sasl_passwd

# Check logs for auth errors
journalctl -u postfix -e | grep -i "sasl\|auth"
```

### TLS handshake failure

```bash
# Test TLS connectivity manually
openssl s_client -starttls smtp -connect smtp.gmail.com:587

# Check if CA certificates are present
ls -la /etc/ssl/certs/ca-certificates.crt

# If missing, install ca-certificates
pacman -S ca-certificates
```

### "Relay access denied"

This usually means the relay host rejected the message. Verify:

1. Credentials are correct in `/etc/postfix/sasl_passwd`
2. The sending domain/address is authorized at the relay provider
3. For Gmail: App Password is used (not the account password)
4. For SendGrid/Mailgun: the sender domain is verified

### Postfix fails to start after hardening

```bash
# Check what systemd is complaining about
systemctl status postfix
journalctl -u postfix -e

# If ReadWritePaths is too restrictive, temporarily disable hardening:
systemctl revert postfix
systemctl restart postfix
```

## Integration with System Services

### fail2ban Notifications

Add to `/etc/fail2ban/jail.local`:

```ini
[DEFAULT]
destemail = admin@yourdomain.com
sender    = fail2ban@yourhostname
mta       = mail
action    = %(action_mwl)s
```

### Cron Job Notifications

Cron automatically mails output to the `MAILTO` address. Add to your crontab:

```bash
MAILTO=admin@yourdomain.com

# Example: daily disk usage report
0 8 * * * df -h | mail -s "Disk report - $(hostname)" admin@yourdomain.com
```

### SMART Disk Monitoring

Configure `smartd` to send email alerts in `/etc/smartd.conf`:

```
DEVICESCAN -a -o on -S on -n standby,q -s (S/../.././02|L/../../6/03) -W 4,35,45 -m admin@yourdomain.com
```

### Logwatch

Install `logwatch` and configure email delivery:

```bash
pacman -S logwatch
# Edit /etc/logwatch/conf/logwatch.conf:
# MailTo = admin@yourdomain.com
# MailFrom = logwatch@yourhostname
```

### Unattended Upgrades (pacman hooks)

Create a pacman hook to notify on updates:

```bash
# /etc/pacman.d/hooks/notify-updates.hook
[Trigger]
Operation = Upgrade
Type = Package
Target = *

[Action]
When = PostTransaction
Exec = /bin/sh -c 'pacman -Qqu 2>/dev/null | mail -s "Packages upgraded on $(hostname)" root'
```

## Generated Files

| Path | Description |
|------|-------------|
| `/etc/postfix/main.cf` | Main postfix configuration (send-only relay) |
| `/etc/postfix/sasl_passwd` | SASL credentials (mode 600) |
| `/etc/postfix/sasl_passwd.db` | SASL credentials hash map (mode 600) |
| `/etc/postfix/header_checks` | Regexp rules to strip internal headers |
| `/etc/postfix/aliases` | System mail aliases |
| `/etc/postfix/aliases.db` | Aliases hash map |
| `/etc/systemd/system/postfix.service.d/hardening.conf` | systemd security override |

## References

- [Postfix Documentation](https://www.postfix.org/documentation.html)
- [Postfix SASL Authentication](https://www.postfix.org/SASL_README.html)
- [Postfix TLS Support](https://www.postfix.org/TLS_README.html)
- [Arch Wiki -- Postfix](https://wiki.archlinux.org/title/Postfix)
- [Gmail SMTP -- App Passwords](https://support.google.com/accounts/answer/185833)
- [SendGrid SMTP Integration](https://docs.sendgrid.com/for-developers/sending-email/integrating-with-the-smtp-api)
- [Mailgun SMTP Documentation](https://documentation.mailgun.com/en/latest/quickstart-sending.html)
