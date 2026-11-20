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
| `-w PATH` | Web root directory (below `/var/www/` or `/srv/http/`). An existing directory keeps its ownership and permissions | `/var/www/html` |
| `-p PORT` | HTTPS port (must not be `80`) | `443` |
| `--dry-run` | Use Let's Encrypt staging server | off |
| `--skip-certbot` | Skip certificate issuance | off |
| `-h` | Show help | |

### Test before production

```bash
sudo ./nginx.sh -d example.com --dry-run
```

### Re-running on a configured server

The script can be run again at any time (new domain, changed options, updated defaults):

- **Backups.** Every run first copies the files it is about to replace (`nginx.conf`, `sites-enabled/default.conf`, `conf.d/ssl-hardening.conf`, `snippets/security-headers.conf`, the systemd drop-in and the certbot units) to `/var/backups/nginx-hardening/<timestamp>/` (root-only, outside `/etc/nginx` and any web root). Changes you made to those files are replaced by the generated versions, so re-apply them from the backup.
- **Rollback.** If `nginx -t`, the nginx start/reload or the first certificate issuance fails, the saved files are restored, nginx is put back on them and the script exits with an error. A broken configuration is never left in place.
- **No TLS downtime.** When a certificate for the primary domain already exists, the running HTTPS configuration stays in service for the whole run: the refreshed vhost is validated and reloaded first, and certbot renews or extends the certificate afterwards. The temporary HTTP-only ACME vhost is only used for the very first issuance.
- **Names served by another vhost.** A domain that another file in `/etc/nginx/sites-enabled/` already declares on port 80 or the HTTPS port (for example a site set up by `../wordpress/wordpress.sh` or `../react/react.sh`) stays with that vhost and is not declared again in `default.conf`; nginx would otherwise ignore one of the two blocks. The certificate still covers the name. Its ACME challenge is validated through the web root that vhost announces in its `# ACME-Webroot:` header line, or through `-w PATH` when there is none.
- **Web content.** A web root that already exists is not re-owned or re-moded; only the `.well-known/acme-challenge` path is opened for the `http` user if needed. A web root created by the script is owned by `root` and world-readable: the workers only read it.

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
| Certificate | ECDSA P-384 via Let's Encrypt |
| Session Tickets | Disabled (forward secrecy for TLS 1.2) |
| Session Cache | 50MB shared, 1-day timeout |
| OCSP Stapling | Disabled (Let's Encrypt [ended OCSP support in 2025](https://letsencrypt.org/2024/12/05/ending-ocsp)) |
| HTTP/2 | Enabled |
| Compression | Disabled (prevents BREACH attack) |
| Server Tokens | Hidden |

### 3. Security Headers (securityheaders.com A+)

All six graded headers are set, plus OWASP-recommended Cross-Origin headers (included via `/etc/nginx/snippets/security-headers.conf` inside the HTTPS `server {}` block so HSTS is never sent over plain HTTP port 80):

| Header | Value | Purpose |
|--------|-------|---------|
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` | Force HTTPS for 2 years, preload-ready |
| `Content-Security-Policy` | Practical baseline (`'self'`, Google Fonts/Analytics, `frame-ancestors 'none'`) | Mitigate XSS and framing |
| `Permissions-Policy` | Powerful browser APIs denied by default (`fullscreen=(self)`) | Block camera, mic, geolocation, etc. |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Limit referrer leakage |
| `X-Content-Type-Options` | `nosniff` | Prevent MIME-type sniffing |
| `X-Frame-Options` | `SAMEORIGIN` | Prevent cross-origin clickjacking |
| `Cross-Origin-Embedder-Policy` | `unsafe-none` | Compatible with cross-origin fonts/CDNs out of the box |
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
- **Root-owned log directory**: `/var/log/nginx` is `root:root 0755` as packaged by Arch, and only the log files belong to `http` (`0640`). The master process opens and chowns logs as root, so a log directory writable by the worker user would let a compromised worker redirect that through a symlink (the CVE-2016-1247 pattern). The script warns about symlinks it finds there.
- **Explicit temp paths**: request bodies larger than `client_body_buffer_size` and buffered upstream responses are spooled to `/var/cache/nginx/{client,proxy,fastcgi,uwsgi,scgi}_temp` (`http`-owned, `0700`), which stay writable under the systemd sandbox. Large uploads up to `client_max_body_size` work without further changes.

### 5. systemd Service Hardening

The nginx unit gets a security override with:
- `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`
- Write access limited to `/var/log/nginx`, `/var/cache/nginx`, `/var/lib/nginx` and the single file `/run/nginx.pid`. The rest of `/run` is read-only for nginx (the PID file is created before each start by an `ExecStartPre=+` step so it can be bound read-write on its own). Side effects: systemd may log one informational `Failed to create reference to PID` line per start (the file is still empty for a moment), nginx cannot unlink a bind-mounted file, so each stop logs one harmless `unlink() "/run/nginx.pid" failed` alert, and the in-place binary upgrade via `USR2` (which renames the PID file) is not available; use `systemctl restart nginx` after package updates
- `UMask=0027`: files nginx creates (new logs, temp files) are never world-readable
- Kernel module/tunable/log protection
- Capability bounding reset (`CapabilityBoundingSet=`) then restricted to `CAP_NET_BIND_SERVICE`, `CAP_DAC_OVERRIDE`, `CAP_DAC_READ_SEARCH`, `CAP_CHOWN`, `CAP_SETUID`, `CAP_SETGID`, and `CAP_KILL` (so the root master process can signal `http` workers on `systemctl reload nginx`, with no `AmbientCapabilities` inherited by workers)
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
| `/etc/nginx/conf.d/ssl-hardening.conf` | TLS protocols, ECDHE ciphers, curves, and session config |
| `/etc/nginx/snippets/security-headers.conf` | All security response headers (included in HTTPS `server {}` block) |
| `/etc/nginx/sites-enabled/default.conf` | HTTP redirect + HTTPS server block |
| `/etc/letsencrypt/live/<domain>/` | Let's Encrypt certificates |
| `/etc/systemd/system/certbot-renew.timer` | Auto-renewal timer |
| `/etc/systemd/system/nginx.service.d/hardening.conf` | systemd security override |
| `/var/backups/nginx-hardening/<timestamp>/` | The configuration each run replaced (`0700`, root) |
| `/var/cache/nginx/*_temp/` | Request body and upstream buffer spool directories |
| `/etc/systemd/system/awesome-nginx-firewall.service` | Idempotent iptables fallback, when nftables is unavailable |

## Customization

### Content-Security-Policy

The default CSP provides a practical baseline (allowing `'self'`, inline styles/scripts, and Google Fonts/Analytics) so common sites render cleanly out of the box. Tighten it to strict `'self'`-only or tailor it to your specific CDNs:

```nginx
# Example: tighten CSP to strict same-origin + explicit CDN without 'unsafe-inline' scripts
add_header Content-Security-Policy "default-src 'self'; script-src 'self' https://cdn.example.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https://fonts.gstatic.com; connect-src 'self' https://api.example.com; frame-ancestors 'none'; form-action 'self'; base-uri 'self'; upgrade-insecure-requests" always;
```

### Cross-Origin Headers

`Cross-Origin-Embedder-Policy` defaults to `"unsafe-none"` for compatibility with third-party fonts/CDNs. If your site serves only same-origin or CORP/CORS-enabled assets and needs `SharedArrayBuffer` / cross-origin isolation:

```nginx
# Enable full cross-origin isolation when all subresources opt in via CORP/CORS
add_header Cross-Origin-Embedder-Policy "require-corp" always;

# Or allow credentialless cross-origin loads
add_header Cross-Origin-Embedder-Policy "credentialless" always;
```

### Adding Application Ports to the Firewall

The script inserts HTTP and the configured HTTPS port into the existing `inet filter input` chain and persists them in an `AwesomeArchLinux: nginx` block in `/etc/nftables.conf`. It replaces only rules bearing its own comments and never snapshots or reloads transient Docker, Fail2Ban, or CrowdSec state.

For an additional application port, add a separate rule before the final drop:

```bash
nft insert rule inet filter input ct state new tcp dport 8443 accept
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

- [nginx HTTPS configuration](https://nginx.org/en/docs/http/configuring_https_servers.html)
- [nginx HTTP headers module](https://nginx.org/en/docs/http/ngx_http_headers_module.html)
- [nginx request limiting module](https://nginx.org/en/docs/http/ngx_http_limit_req_module.html)
- [nginx reverse-proxy module](https://nginx.org/en/docs/http/ngx_http_proxy_module.html)
- [SSL Labs Server Test](https://www.ssllabs.com/ssltest/)
- [securityheaders.com](https://securityheaders.com/)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
- [Let's Encrypt — Ending OCSP Support (2025)](https://letsencrypt.org/2024/12/05/ending-ocsp)
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- [Certbot — Arch Wiki](https://wiki.archlinux.org/title/Certbot)
- [systemd service sandboxing](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)
