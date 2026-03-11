# ProtonMail-Grade Hardened Mail Server

Installs and configures a full **ProtonMail-grade hardened mail server** on Arch Linux with [Postfix](https://www.postfix.org/), [Dovecot](https://www.dovecot.org/), [OpenDKIM](http://www.opendkim.org/), [rspamd](https://rspamd.com/), and [ClamAV](https://www.clamav.net/).

## Quick Start

```bash
# Full mail server (requires TLS cert at /etc/letsencrypt/live/mail.example.com/)
sudo ./postfix.sh -d example.com

# Preview configs without starting services
sudo ./postfix.sh -d example.com --dry-run

# With custom hostname and outbound relay
sudo ./postfix.sh -d example.com -H mx1.example.com -r smtp.sendgrid.net -u apikey -p 'SG.xxxx'
```

### Prerequisites

1. **Arch Linux** with root access
2. **TLS certificate** for the mail hostname (e.g., via certbot/nginx.sh)
3. **AUR helper** (yay or paru) for `opendkim`
4. **DNS control** over your domain
5. **DNSSEC** on your domain (required for DANE)

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-d DOMAIN` | Mail domain | *required* |
| `-H HOSTNAME` | Mail server hostname | `mail.$DOMAIN` |
| `-s SELECTOR` | DKIM selector name | `default` |
| `-r HOST` | SMTP relay for outbound (hybrid) | |
| `-R PORT` | SMTP relay port | `587` |
| `-u USER` | SMTP relay username | |
| `-p PASS` | SMTP relay password | |
| `-e EMAIL` | Admin email address | `postmaster@$DOMAIN` |
| `--dry-run` | Write configs, validate, don't start services | |
| `-h` | Show help | |

## Architecture

```
                    Internet
                       │
              ┌────────┴────────┐
              │   Port 25 (MX)  │
              │   Postscreen    │──── DNSBL screening
              └────────┬────────┘
                       │
              ┌────────┴────────┐
              │     Postfix     │
              │    (smtpd)      │──── SMTP smuggling protection
              └──┬──────────┬───┘
                 │          │
        ┌────────┴──┐  ┌───┴────────┐
        │ OpenDKIM  │  │  rspamd    │
        │ (milter)  │  │  (milter)  │──── SPF/DKIM/DMARC/ARC
        │ Sign+Vrfy │  │  Spam+AV   │     Phishing, Rate limit
        └────────┬──┘  └───┬────────┘     ClamAV integration
                 │          │
              ┌──┴──────────┴───┐
              │  Dovecot LMTP   │──── Delivery to Maildir
              │  mail_crypt     │     Encryption at rest
              └────────┬────────┘
                       │
              ┌────────┴────────┐
              │  Dovecot IMAP   │──── Port 993 (TLS-only)
              │  + Sieve        │     Server-side filtering
              └─────────────────┘

     Submission: Port 587 (STARTTLS) / Port 465 (implicit TLS)
     → Authenticated users only → Header privacy stripping
```

## What It Does

### 1. Package Installation

- `postfix` — MTA (Mail Transfer Agent)
- `dovecot` + `pigeonhole` — IMAP server with Sieve filtering
- `opendkim` — DKIM signing and verification (AUR)
- `rspamd` — Spam filtering, SPF/DKIM/DMARC/ARC, phishing, rate limiting
- `redis` — Backend for rspamd Bayes classifier and rate limiting
- `clamav` — Antivirus scanning via rspamd
- `s-nail` — CLI mail client for testing

### 2. Postfix Configuration

| Feature | Setting | Purpose |
|---------|---------|---------|
| **Full MX** | `inet_interfaces = all` | Accept inbound + outbound |
| **TLS 1.2+** | ECDHE/AEAD-only cipher suite | ProtonMail-grade encryption |
| **DANE** | `smtp_tls_security_level = dane` | DNSSEC-verified outbound TLS |
| **Postscreen** | DNSBL + protocol tests | Block bots before smtpd |
| **SMTP smuggling** | `smtpd_forbid_bare_newline` | CVE-2023-51764 protection |
| **Virtual mailbox** | LMTP to Dovecot | No system user per mailbox |
| **Rate limiting** | 10 conn/min, 30 msg/min | Dual-layer with rspamd |
| **Milters** | OpenDKIM + rspamd | DKIM signing + spam filtering |
| **Submission** | Port 587 (STARTTLS) | Authenticated user submission |
| **SMTPS** | Port 465 (implicit TLS) | RFC 8314 submission |
| **Header privacy** | Strip on submission only | Hide sender IP/client |
| **VRFY disabled** | `disable_vrfy_command = yes` | Prevent user enumeration |

### 3. Dovecot (IMAP)

| Feature | Detail |
|---------|--------|
| **IMAP only** | POP3 disabled, port 143 disabled |
| **TLS required** | Same ECDHE/AEAD cipher suite as Postfix |
| **Encryption at rest** | `mail_crypt` plugin with secp521r1 |
| **LMTP delivery** | Socket inside Postfix chroot |
| **SASL auth** | Dovecot provides auth to Postfix |
| **Sieve** | Server-side filtering, auto Junk folder |
| **Virtual users** | passwd-file backend (no system accounts) |

### 4. OpenDKIM

- RSA 2048-bit key generation
- Sign and verify mode
- `OversignHeaders From` — prevents header injection
- Milter socket shared with Postfix

### 5. rspamd

- **SPF** checking with caching
- **DKIM** verification
- **DMARC** policy enforcement with reporting
- **ARC** signing and sealing
- **Bayes** spam classifier (Redis backend, autolearn)
- **Phishing** detection (OpenPhish + PhishTank)
- **Rate limiting** (per-recipient and per-sender)
- **ClamAV** integration (reject on virus)

### 6. systemd Hardening

All services (Postfix, Dovecot, OpenDKIM, rspamd) get hardening overrides:

- `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`
- `ProtectKernel{Tunables,Modules,Logs}=yes`
- `NoNewPrivileges=yes`, `LockPersonality=yes`
- `RestrictNamespaces=yes`, `PrivateDevices=yes`
- `SystemCallArchitectures=native`
- Service-specific `CapabilityBoundingSet` and `ReadWritePaths`

### 7. DNS Record Generation

The script outputs all required DNS records:

| Record | Purpose |
|--------|---------|
| **MX** | Points domain to mail server |
| **SPF** | Authorizes sending IPs |
| **DKIM** | Public key for signature verification |
| **DMARC** | Policy for failed SPF/DKIM (starts at quarantine) |
| **DANE/TLSA** | Certificate pinning via DNSSEC |
| **MTA-STS** | Strict Transport Security for SMTP |
| **TLS-RPT** | TLS failure reporting |
| **PTR** | Reverse DNS (set at hosting provider) |

## Post-Installation

### Add Virtual Users

```bash
# Generate password hash
doveadm pw -s BLF-CRYPT

# Add to Dovecot users file
echo 'user@example.com:{BLF-CRYPT}$2y$05$...' >> /etc/dovecot/users

# Add mailbox mapping
echo 'user@example.com example.com/user/Maildir/' >> /etc/postfix/vmailbox
postmap /etc/postfix/vmailbox

# Restart Dovecot to pick up new user
systemctl restart dovecot
```

### Add DNS Records

Add all records output by the script to your DNS provider. Wait for propagation before sending production mail.

### Upgrade DMARC Policy

After 2-4 weeks of monitoring reports:

```
# Change from:
_dmarc.example.com. IN TXT "v=DMARC1; p=quarantine; ..."

# To:
_dmarc.example.com. IN TXT "v=DMARC1; p=reject; ..."
```

### Set Up MTA-STS

Create `https://mta-sts.example.com/.well-known/mta-sts.txt`:

```
version: STSv1
mode: enforce
mx: mail.example.com
max_age: 604800
```

## Testing

### Inbound/Outbound

```bash
# Send a test email
echo "Hello from $(hostname)" | mail -s "Test" user@example.com

# Check mail queue
mailq

# Watch logs
journalctl -u postfix -f
```

### TLS Verification

```bash
# Test STARTTLS on port 25
openssl s_client -connect mail.example.com:25 -starttls smtp

# Test SMTPS on port 465
openssl s_client -connect mail.example.com:465

# Test IMAPS on port 993
openssl s_client -connect mail.example.com:993
```

### DKIM Verification

```bash
opendkim-testkey -d example.com -s default -vvv
```

### rspamd

```bash
rspamc stat           # Statistics
rspamc learn_spam     # Train spam
rspamc learn_ham      # Train ham
```

### External Tests

- [CheckTLS](https://www.checktls.com/TestReceiver) — Inbound TLS test
- [MXToolbox](https://mxtoolbox.com/SuperTool.aspx) — MX/SPF/DKIM/DMARC
- [internet.nl](https://internet.nl/mail/example.com/) — Comprehensive test
- [Mail Tester](https://www.mail-tester.com/) — Deliverability score

## Troubleshooting

### Service won't start

```bash
# Check status and logs
systemctl status postfix dovecot opendkim rspamd
journalctl -u postfix -e
journalctl -u dovecot -e

# Validate configs
postfix check
dovecot -n

# If systemd hardening is too restrictive
systemctl revert postfix    # removes hardening override
systemctl restart postfix
```

### Mail stuck in queue

```bash
mailq                          # View queue
postcat -q <QUEUE_ID>         # View specific message
postqueue -f                   # Flush (retry)
journalctl -u postfix -e | grep "status=deferred"
```

### DKIM failures

```bash
# Verify key is published in DNS
dig +short default._domainkey.example.com TXT

# Test signing
opendkim-testkey -d example.com -s default -vvv

# Check OpenDKIM logs
journalctl -u opendkim -e
```

### rspamd issues

```bash
# Check rspamd is listening
ss -tlnp | grep 11332

# View rspamd web UI (if enabled)
# Default: http://localhost:11334

# Check Redis
redis-cli ping
```

### ClamAV memory usage

ClamAV uses ~1GB RAM for virus definitions. If memory is limited:

```bash
# Check usage
systemctl status clamav-daemon

# Disable if needed
systemctl disable --now clamav-daemon
# Remove antivirus.conf from rspamd
rm /etc/rspamd/local.d/antivirus.conf
systemctl restart rspamd
```

## Generated Files

| Path | Description |
|------|-------------|
| `/etc/postfix/main.cf` | Main Postfix config (full MX) |
| `/etc/postfix/master.cf` | Service definitions (postscreen, submission, smtps) |
| `/etc/postfix/header_checks_submission` | Header stripping for submission |
| `/etc/postfix/vmailbox` | Virtual mailbox mapping |
| `/etc/postfix/aliases` | System mail aliases |
| `/etc/postfix/dh2048.pem` | DH parameters for Postfix TLS |
| `/etc/postfix/sasl_passwd` | Relay credentials (if relay configured) |
| `/etc/dovecot/dovecot.conf` | Main Dovecot config |
| `/etc/dovecot/conf.d/10-ssl.conf` | TLS hardening |
| `/etc/dovecot/conf.d/10-mail.conf` | Mail storage + encryption at rest |
| `/etc/dovecot/conf.d/10-auth.conf` | Authentication config |
| `/etc/dovecot/conf.d/10-master.conf` | LMTP + auth sockets |
| `/etc/dovecot/conf.d/20-lmtp.conf` | LMTP protocol config |
| `/etc/dovecot/conf.d/20-imap.conf` | IMAP protocol config |
| `/etc/dovecot/conf.d/90-sieve.conf` | Sieve filtering |
| `/etc/dovecot/users` | Virtual user credentials |
| `/etc/dovecot/dh.pem` | DH parameters for Dovecot TLS |
| `/etc/opendkim/opendkim.conf` | OpenDKIM config |
| `/etc/opendkim/keys/$DOMAIN/` | DKIM keys |
| `/etc/rspamd/local.d/` | rspamd config overrides (12 files) |
| `/etc/systemd/system/*.service.d/hardening.conf` | systemd hardening (4 services) |
| `/etc/tmpfiles.d/opendkim.conf` | Runtime directory for OpenDKIM |

## Security Comparison

| Feature | This Setup | ProtonMail |
|---------|-----------|------------|
| TLS 1.2+ only | Yes | Yes |
| ECDHE/AEAD ciphers | Yes | Yes |
| DANE/TLSA | Yes | Yes |
| MTA-STS | Guided setup | Yes |
| SPF | Yes | Yes |
| DKIM | RSA 2048 | RSA 2048 |
| DMARC | Yes (quarantine→reject) | Yes (reject) |
| ARC | Yes | Yes |
| Header privacy | Submission ports | All outbound |
| Encryption at rest | Dovecot mail_crypt | Custom PGP |
| Postscreen | Yes | Custom |
| Anti-spam | rspamd | Custom |
| Antivirus | ClamAV | Custom |
| Rate limiting | Dual-layer | Yes |
| SMTP smuggling protection | Yes | Yes |
| systemd hardening | Yes | N/A (custom) |

## References

- [Postfix Documentation](https://www.postfix.org/documentation.html)
- [Postfix TLS Support](https://www.postfix.org/TLS_README.html)
- [Postfix Postscreen](https://www.postfix.org/POSTSCREEN_README.html)
- [Dovecot Documentation](https://doc.dovecot.org/)
- [Dovecot mail_crypt Plugin](https://doc.dovecot.org/configuration_manual/mail_crypt_plugin/)
- [OpenDKIM Documentation](http://www.opendkim.org/docs.html)
- [rspamd Documentation](https://rspamd.com/doc/)
- [DANE/TLSA (RFC 7672)](https://tools.ietf.org/html/rfc7672)
- [MTA-STS (RFC 8461)](https://tools.ietf.org/html/rfc8461)
- [SMTP Smuggling (CVE-2023-51764)](https://www.postfix.org/smtp-smuggling.html)
- [Arch Wiki — Postfix](https://wiki.archlinux.org/title/Postfix)
- [Arch Wiki — Dovecot](https://wiki.archlinux.org/title/Dovecot)
