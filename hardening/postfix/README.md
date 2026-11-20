# Hardened Mail Server

Installs and configures a full hardened mail server on Arch Linux with [Postfix](https://www.postfix.org/), [Dovecot](https://www.dovecot.org/), [OpenDKIM](http://www.opendkim.org/), [rspamd](https://rspamd.com/), [Valkey](https://valkey.io/), and [ClamAV](https://www.clamav.net/).

## Quick Start

```bash
# Full mail server (requires TLS cert at /etc/letsencrypt/live/mail.example.com/)
sudo ./postfix.sh -d example.com

# Preview planned configuration and DNS records without modifying the system
sudo ./postfix.sh -d example.com --dry-run

# With custom hostname and outbound relay
install -m 600 /dev/null /root/.smtp-relay-password
printf '%s\n' 'SG.xxxx' > /root/.smtp-relay-password
sudo ./postfix.sh -d example.com -H mx1.example.com \
  -r smtp.sendgrid.net -u apikey \
  --relay-password-file /root/.smtp-relay-password \
  --relay-spf-include sendgrid.net
```

### Prerequisites

1. **Arch Linux** with root access
2. **TLS certificate** for the mail hostname (e.g., via certbot/nginx.sh)
3. **DNS control** over your domain
4. **DNSSEC** on your domain (required for DANE)
5. A **local recursive resolver** (for example unbound) if the Spamhaus DNSBL
   is to be effective; see [Postscreen DNSBLs and the resolver](#postscreen-dnsbls-and-the-resolver)

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-d DOMAIN` | Mail domain | *required* |
| `-H HOSTNAME` | Mail server hostname | `mail.$DOMAIN` |
| `-s SELECTOR` | DKIM selector name | `default` |
| `-r HOST` | SMTP relay for outbound (hybrid). Use the provider's hostname, not an IP address, so its certificate can be verified | |
| `-R PORT` | SMTP relay port (`465` selects implicit TLS) | `587` |
| `-u USER` | SMTP relay username | |
| `--relay-password-file FILE` | Read the SMTP relay password from a private, non-symlink file | |
| `--relay-spf-include DOMAIN` | Provider-published SPF include domain | |
| `-e EMAIL` | Admin email address | `postmaster@$DOMAIN` |
| `--dry-run` | Preview planned configuration and DNS records without modifying the system | |
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
- `opendkim` — DKIM signing and verification (signed official repository package)
- `rspamd` — Spam filtering, SPF/DKIM/DMARC/ARC, phishing, rate limiting
- `valkey` — Redis-compatible backend for rspamd Bayes classification and rate limiting
- `clamav` — Antivirus scanning via rspamd
- `s-nail` — CLI mail client for testing

### 2. Postfix Configuration

| Feature | Setting | Purpose |
|---------|---------|---------|
| **Full MX** | `inet_interfaces = all` | Accept inbound + outbound |
| **TLS 1.2+** | ECDHE/AEAD-only cipher suite | Removes legacy protocols and ciphers |
| **DANE** | `smtp_tls_security_level = dane` | DNSSEC-verified TLS when usable TLSA records exist; opportunistic otherwise |
| **Relay TLS** | `smtp_tls_security_level = secure` | With relay credentials or relay port 465: mandatory TLS and a verified relay certificate (see below) |
| **Postscreen** | DNSBL (reply-filtered) + protocol tests | Block bots before smtpd |
| **Role addresses** | `virtual_alias_maps` | `root@`, `abuse@`, `dmarc-reports@`, `tls-reports@` reach the administrator |
| **SMTP smuggling** | `smtpd_forbid_bare_newline` | CVE-2023-51764 protection |
| **Virtual mailbox** | LMTP to Dovecot | No system user per mailbox |
| **Rate limiting** | 10 conn/min, 30 msg/min | Dual-layer with rspamd |
| **Milters** | OpenDKIM + rspamd | DKIM signing + spam filtering |
| **SMTP AUTH** | `smtpd_sasl_auth_enable = no` globally | AUTH is offered on 587 and 465 only, never on the MX port 25 |
| **Submission** | Port 587 (STARTTLS) | Authenticated user submission |
| **SMTPS** | Port 465 (implicit TLS) | RFC 8314 submission |
| **Header privacy** | Strip on submission only | Hide sender IP/client |
| **VRFY disabled** | `disable_vrfy_command = yes` | Prevent user enumeration |

#### Outbound relay TLS

Without a relay, outbound mail uses `dane`. With `-r HOST` the level depends
on what is sent to the relay:

| Relay options | `smtp_tls_security_level` | Reason |
|---|---|---|
| `-r HOST` only (IP-authorized relay) on a STARTTLS port | `dane` | Unchanged: opportunistic unless the relay publishes TLSA records |
| `-u USER --relay-password-file FILE`, or `-R 465` | `secure` | TLS is mandatory and the certificate must match the relay hostname. `dane` would fall back to opportunistic TLS for a relay without TLSA records, so a man-in-the-middle could strip STARTTLS or present any certificate and collect the password |
| the same, with `-r` given as an IP address | `encrypt` | TLS is mandatory, but a certificate name cannot be matched against an IP address. The script warns; use the hostname |

With credentials, `smtp_sasl_security_options = noanonymous, noplaintext`
keeps the password from ever being offered on an unencrypted session, and
`-R 465` adds `smtp_tls_wrappermode = yes` (implicit TLS). Earlier versions
of the script used `dane` for every relay; if mail to the relay is deferred
with a certificate verification error after re-running, check that `-r` is the
name on the provider's certificate.

#### Postscreen DNSBLs and the resolver

```
postscreen_dnsbl_sites = zen.spamhaus.org=127.0.0.[2..11]*3, bl.spamcop.net=127.0.0.2*2, b.barracudacentral.org=127.0.0.2*2
```

The `=reply` filters are required. Spamhaus refuses queries that arrive
through public or ISP resolvers (Cloudflare, Google, Quad9 and similar) and
answers them with an error code in `127.255.255.0/24`. Without a filter
postscreen treats any answer as a listing, so every remote server scores 3 and
all inbound mail is rejected. With the filter such a resolver is harmless, but
the Spamhaus list then never matches. The script probes the Spamhaus test
entry (`2.0.0.127.zen.spamhaus.org`) at the end and warns when the list is not
usable from this host. To make it effective, run a local recursive resolver
(for example unbound) or use a Spamhaus DQS key. The base installer of this
repository points systemd-resolved at Cloudflare, so expect that warning on a
freshly installed host.

#### Role addresses

`myorigin` is the mail domain, so local mail to `root` (cron, systemd, smartd)
is addressed to `root@DOMAIN`. That domain is a virtual mailbox domain: the
local `aliases` file is not consulted for it, and an address without a mailbox
bounces. The script therefore maintains `/etc/postfix/valiases`
(`virtual_alias_maps`) and maps `root@`, `abuse@`, `dmarc-reports@` and
`tls-reports@DOMAIN` (the last two are published in the generated DMARC and
TLS-RPT records) to the admin address. An address that already has a mailbox
in `vmailbox` or an entry in `valiases` is left alone, so the file can be
edited by hand; run `postmap lmdb:/etc/postfix/valiases` afterwards.

### 3. Dovecot (IMAP)

| Feature | Detail |
|---------|--------|
| **IMAP only** | POP3 disabled, port 143 disabled |
| **TLS required** | Same ECDHE/AEAD cipher suite as Postfix |
| **Encryption at rest** | `mail_crypt` with a managed global EC P-384 keypair |
| **LMTP delivery** | Socket inside Postfix chroot |
| **SASL auth** | Dovecot provides auth to Postfix |
| **Sieve** | Server-side filtering, auto Junk folder |
| **Virtual users** | passwd-file backend (no system accounts) |

### 4. OpenDKIM

- RSA 2048-bit key generation
- Sign and verify mode
- `OversignHeaders From` — prevents header injection
- Milter socket at `/run/opendkim/opendkim.sock` (`UMask 007`, `UserID opendkim:postfix`, leaving Postfix's `0700` `/var/spool/postfix/private` directory untouched)

### 5. rspamd

- **SPF** checking with caching
- **DKIM** verification
- **DMARC** policy enforcement with reporting
- **ARC** signing and sealing
- **Bayes** spam classifier (Valkey backend, autolearn)
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
- Explicit `CapabilityBoundingSet=` reset followed by minimal per-daemon capabilities (`CAP_KILL` included for Postfix and Dovecot master processes) and scoped `ReadWritePaths`

### 7. DNS Record Generation

The script outputs all required DNS records:

| Record | Purpose |
|--------|---------|
| **MX** | Points domain to mail server |
| **SPF** | Authorizes sending IPs |
| **DKIM** | Public key for signature verification |
| **DMARC** | Policy for failed SPF/DKIM (starts at quarantine) |
| **DANE/TLSA** | Certificate pinning via DNSSEC. `TLSA 3 1 1` (leaf SPKI) is the record to rely on; it requires `certbot --reuse-key` / `reuse_key = True`. `TLSA 2 1 1` (SPKI of the CA that issued the current certificate, from `chain.pem`) is printed as an optional extra: Let's Encrypt issues from several intermediates and may switch at any renewal, so that record alone stops matching. Publish it only in addition to `3 1 1`, or publish one for every active intermediate |
| **MTA-STS** | Strict Transport Security for SMTP |
| **TLS-RPT** | TLS failure reporting |
| **PTR** | Reverse DNS (set at hosting provider) |

## Post-Installation

### Add Virtual Users

```bash
# Generate password hash and append passwd-file entry
HASH=$(doveadm pw -s BLF-CRYPT)
printf '%s:%s::::::\n' "user@example.com" "$HASH" >> /etc/dovecot/users

# Add mailbox mapping
echo 'user@example.com example.com/user/Maildir/' >> /etc/postfix/vmailbox
postmap lmdb:/etc/postfix/vmailbox

# Restart Dovecot to pick up new user
systemctl restart dovecot
```

Back up `/etc/dovecot/mail-crypt.key` separately and securely. It is the global private key used to decrypt stored mail; losing it makes encrypted messages unrecoverable. The installer refuses to generate a new key over an existing Maildir.

### Re-running the Script

The script can be run again after a change (new certificate path, selector,
relay). It rewrites the configuration and then restarts ClamAV, OpenDKIM,
rspamd, Dovecot and Postfix so that the running daemons use the new files and
systemd sandboxes; IMAP sessions are disconnected briefly and ClamAV reloads
its signature database. Existing mailboxes (`vmailbox`), aliases (`valiases`),
Dovecot users, DKIM keys and the mail-encryption key are preserved.

### Add DNS Records

Add all records output by the script to your DNS provider. Wait for propagation before sending production mail.
When using an outbound relay, pass the SPF include domain published by that provider with `--relay-spf-include`; it is not necessarily the same as the relay server hostname.

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
echo "Hello from $(uname -n)" | mail -s "Test" user@example.com

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
doveconf -n
rspamadm configtest

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

# Check Valkey
valkey-cli ping
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
| `/etc/postfix/vmailbox{,.lmdb}` | Virtual mailbox source and compiled LMDB map |
| `/etc/postfix/valiases{,.lmdb}` | Virtual alias source and compiled LMDB map (role addresses) |
| `/etc/postfix/aliases{,.lmdb}` | System alias source and compiled LMDB map |
| `/etc/postfix/sasl_passwd{,.lmdb}` | Relay credential source and compiled LMDB map (if configured) |
| `/etc/dovecot/dovecot.conf` | Complete Dovecot 2.4 config: TLS, auth, LMTP, Sieve, and encrypted Maildir |
| `/etc/dovecot/users` | Virtual user credentials |
| `/etc/dovecot/mail-crypt.{key,pub}` | Global EC mail-encryption keypair; the private key must be backed up |
| `/etc/opendkim/opendkim.conf` | OpenDKIM config |
| `/etc/opendkim/keys/$DOMAIN/` | DKIM keys |
| `/etc/rspamd/local.d/` | rspamd config overrides (12 files) |
| `/etc/systemd/system/*.service.d/hardening.conf` | systemd hardening (4 services) |
| `/etc/tmpfiles.d/opendkim.conf` | Runtime directory for OpenDKIM |

## References

- [Postfix Documentation](https://www.postfix.org/documentation.html)
- [Postfix TLS Support](https://www.postfix.org/TLS_README.html)
- [Postfix Postscreen](https://www.postfix.org/POSTSCREEN_README.html)
- [Dovecot Documentation](https://doc.dovecot.org/)
- [Dovecot 2.4 mail_crypt Plugin](https://doc.dovecot.org/2.4.4/core/plugins/mail_crypt.html)
- [OpenDKIM Documentation](http://www.opendkim.org/docs.html)
- [rspamd Documentation](https://rspamd.com/doc/)
- [DANE/TLSA (RFC 7672)](https://tools.ietf.org/html/rfc7672)
- [MTA-STS (RFC 8461)](https://tools.ietf.org/html/rfc8461)
- [SMTP Smuggling (CVE-2023-51764)](https://www.postfix.org/smtp-smuggling.html)
- [Arch Wiki — Postfix](https://wiki.archlinux.org/title/Postfix)
- [Arch Wiki — Dovecot](https://wiki.archlinux.org/title/Dovecot)
