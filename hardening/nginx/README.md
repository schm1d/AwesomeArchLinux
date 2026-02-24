# nginx-mainline Hardening

Installs and hardens [nginx-mainline](https://archlinux.org/packages/extra/x86_64/nginx-mainline/) on Arch Linux with Let's Encrypt certificates, targeting:

- **SSL Labs A+** rating
- **securityheaders.com A+** (all green headers)

## Quick Start

```bash
sudo ./nginx.sh -d example.com -d www.example.com -e admin@example.com
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-d DOMAIN` | Domain name (repeat for multiple) | *required* |
| `-e EMAIL` | Let's Encrypt notification email | `webmaster@DOMAIN` |
| `-w PATH` | Web root directory | `/var/www/html` |
| `-p PORT` | HTTPS port | `443` |
| `--dry-run` | Use Let's Encrypt staging server | off |
| `--skip-certbot` | Skip certificate issuance | off |
| `-h` | Show help | |

### Test before production

```bash
sudo ./nginx.sh -d example.com --dry-run
```

## What It Does

### 1. Package Installation
- `nginx-mainline` (official Arch repos)
- `certbot` + `certbot-nginx`
- `openssl`

### 2. TLS Configuration (SSL Labs A+)

| Setting | Value |
|---------|-------|
| Protocols | TLS 1.2 + TLS 1.3 only |
| TLS 1.2 Ciphers | ECDHE + AEAD only (AES-128/256-GCM, ChaCha20-Poly1305) |
| TLS 1.3 Ciphers | Managed by OpenSSL (TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, TLS_AES_128_GCM_SHA256) |
| ECDH Curves | X25519, secp384r1, secp256r1 |
| DH Parameters | 4096-bit (generated at install time) |
| Certificate | ECDSA P-384 via Let's Encrypt |
| Session Tickets | Disabled (forward secrecy for TLS 1.2) |
| Session Cache | 50MB shared, 1-day timeout |
| OCSP Stapling | Disabled (Let's Encrypt [ended OCSP support in 2025](https://letsencrypt.org/2024/12/05/ending-ocsp)) |
| HTTP/2 | Enabled |
| Compression | Disabled (prevents BREACH attack) |
| Server Tokens | Hidden |

### 3. Security Headers (securityheaders.com A+)

All six graded headers are set, plus OWASP-recommended Cross-Origin headers:

| Header | Value | Purpose |
|--------|-------|---------|
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` | Force HTTPS for 2 years, preload-ready |
| `Content-Security-Policy` | Strict `self`-only baseline | Prevent XSS, code injection |
| `Permissions-Policy` | All browser APIs denied by default | Block camera, mic, geolocation, etc. |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Limit referrer leakage |
| `X-Content-Type-Options` | `nosniff` | Prevent MIME-type sniffing |
| `X-Frame-Options` | `DENY` | Prevent clickjacking |
| `Cross-Origin-Embedder-Policy` | `require-corp` | Require cross-origin opt-in |
| `Cross-Origin-Opener-Policy` | `same-origin` | Isolate browsing context (XS-Leak defense) |
| `Cross-Origin-Resource-Policy` | `same-origin` | Prevent cross-origin resource loading |
| `X-Permitted-Cross-Domain-Policies` | `none` | Block Flash/Acrobat cross-domain |

### 4. nginx Hardening

- **Buffer limits** to mitigate overflow attacks
- **Timeouts** to mitigate Slowloris
- **Gzip disabled** to prevent BREACH
- **Dotfile blocking** (except `.well-known`)
- **Sensitive file blocking** (`.sql`, `.bak`, `.log`, `.sh`, etc.)
- **Unprivileged worker** process (`http` user)

### 5. systemd Service Hardening

The nginx unit gets a security override with:
- `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`
- Kernel module/tunable/log protection
- Capability bounding to `CAP_NET_BIND_SERVICE` only
- Native-only syscall filtering
- `MemoryDenyWriteExecute`, `NoNewPrivileges`, namespace restrictions

### 6. Certificate Auto-Renewal

A systemd timer runs `certbot renew` twice daily with a randomized delay and automatically reloads nginx on success.

```bash
# Check renewal timer
systemctl list-timers certbot-renew.timer

# Manual renewal test
certbot renew --dry-run
```

## Generated Files

| Path | Description |
|------|-------------|
| `/etc/nginx/nginx.conf` | Main nginx config (core, buffers, timeouts) |
| `/etc/nginx/conf.d/ssl-hardening.conf` | TLS protocols, ciphers, DH params, session config |
| `/etc/nginx/conf.d/security-headers.conf` | All security response headers |
| `/etc/nginx/sites-enabled/default.conf` | HTTP redirect + HTTPS server block |
| `/etc/nginx/ssl/dhparam.pem` | 4096-bit DH parameters |
| `/etc/letsencrypt/live/<domain>/` | Let's Encrypt certificates |
| `/etc/systemd/system/certbot-renew.timer` | Auto-renewal timer |
| `/etc/systemd/system/nginx.service.d/hardening.conf` | systemd security override |

## Customization

### Content-Security-Policy

The default CSP is strict (`self`-only). You will likely need to adjust it for your application:

```nginx
# Example: allow scripts from a CDN and inline styles
add_header Content-Security-Policy "default-src 'self'; script-src 'self' https://cdn.example.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https://fonts.gstatic.com; connect-src 'self' https://api.example.com; frame-ancestors 'none'; form-action 'self'; base-uri 'self'; upgrade-insecure-requests;" always;
```

### Cross-Origin Headers

If your site loads third-party resources (images, scripts, fonts from CDNs):

```nginx
# Relax COEP to allow credentialless cross-origin loads
add_header Cross-Origin-Embedder-Policy "credentialless" always;

# Or disable COEP entirely if third-party resources don't support CORS/CORP
add_header Cross-Origin-Embedder-Policy "unsafe-none" always;
```

### Adding Application Ports to the Firewall

If using the AwesomeArchLinux nftables firewall, add HTTP/HTTPS:

```bash
# Edit /etc/nftables.conf, add inside the input chain:
tcp dport { 80, 443 } ct state new accept
```

### Reverse Proxy

To use nginx as a reverse proxy (e.g., for Node.js, Python, Go apps), add to the server block:

```nginx
location /api/ {
    proxy_pass http://127.0.0.1:3000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

## Verification

After running the script:

1. **SSL Labs**: `https://www.ssllabs.com/ssltest/analyze.html?d=<your-domain>`
2. **Security Headers**: `https://securityheaders.com/?q=https://<your-domain>`
3. **HSTS Preload** (after confirming everything works): `https://hstspreload.org/`

## References

- [SSL Labs Server Test](https://www.ssllabs.com/ssltest/)
- [securityheaders.com](https://securityheaders.com/)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
- [Let's Encrypt — Ending OCSP Support (2025)](https://letsencrypt.org/2024/12/05/ending-ocsp)
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- [Certbot — Arch Wiki](https://wiki.archlinux.org/title/Certbot)
