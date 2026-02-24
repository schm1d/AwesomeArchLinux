![Arch Linux Secure AF](./archLinux.png)
Wallpaper: [https://www.reddit.com/user/alienpirate5/](https://www.reddit.com/user/alienpirate5/)

## Awesome Arch Linux

A collection of shell scripts for hardened Arch Linux installation, configuration, and security enhancements. The aim is to make this repository a reliable and curated reference for Arch Linux hardened installation setups and configurations.

Two installation paths are provided:

- **Bare-metal / Desktop** (`archinstall.sh`) &mdash; Full disk encryption with [LVM on LUKS with encrypted boot partition](https://wiki.archlinux.org/title/Dm-crypt/Encrypting_an_entire_system#Encrypted_boot_partition_(GRUB)) (GRUB, UEFI), optional TPM2 binding.
- **VPS / Cloud** (`vps-install.sh`) &mdash; Simplified partitioning (no LUKS, no TPM, no GRUB encryption), swap file instead of LVM, serial console support for VPS provider access. All software hardening is preserved.

Both paths share the same hardening philosophy: the scripts will prepare everything for you. No need to worry about partitioning or encryption. All you have to do is provide a few inputs (disk, username, hostname, passwords) and the installer handles the rest.

You will get a very clean, solid, and secure base installation.

---

### Repository Structure

```
AwesomeArchLinux/
+-- base/
|   +-- archinstall.sh       # Bare-metal installer (LUKS + LVM + UEFI + TPM2)
|   +-- chroot.sh            # Bare-metal chroot configuration & hardening
|   +-- vps-install.sh       # VPS/cloud installer (no encryption, swap file)
|   +-- vps-chroot.sh        # VPS chroot configuration & hardening
|   +-- recovery-mount.sh    # Recovery menu: unmount/remount encrypted install
|   +-- secureBoot.sh        # UEFI Secure Boot key generation & enrollment
+-- hardening/
|   +-- apparmor/
|   |   +-- apparmor.sh      # AppArmor profiles for 7 services (enforce mode)
|   |   +-- README.md
|   +-- chrony/
|   |   +-- chrony.sh        # Chrony NTS (authenticated time synchronization)
|   |   +-- README.md
|   +-- docker/
|   |   +-- docker.sh        # Docker runtime security (CIS benchmark, Trivy, seccomp)
|   |   +-- README.md
|   +-- crowdsec/
|   |   +-- crowdsec.sh      # CrowdSec IDS with nftables & nginx bouncers
|   |   +-- README.md
|   +-- fail2ban/
|   |   +-- fail2ban.sh      # Extended fail2ban jails (SSH, nginx, recidive)
|   |   +-- README.md
|   +-- firehol/
|   |   +-- firehol.sh       # FireHOL firewall with IP blocklist integration
|   +-- mariadb/
|   |   +-- mariadb.sh       # MariaDB/MySQL server hardening
|   |   +-- README.md
|   +-- nginx/
|   |   +-- nginx.sh         # nginx-mainline hardening + Let's Encrypt (SSL Labs A+)
|   |   +-- README.md
|   +-- nodejs/
|   |   +-- nodejs.sh        # Node.js/Express production hardening
|   |   +-- README.md
|   +-- php/
|   |   +-- php.sh           # PHP production hardening (php.ini, FPM, nginx)
|   |   +-- README.md
|   +-- postgresql/
|   |   +-- postgresql.sh    # PostgreSQL server hardening
|   |   +-- README.md
|   +-- postfix/
|   |   +-- postfix.sh       # Send-only Postfix mail relay for system notifications
|   |   +-- README.md
|   +-- react/
|   |   +-- react.sh         # React/SPA production deployment hardening (nginx)
|   |   +-- README.md
|   +-- ssh/
|   |   +-- ssh.sh           # SSH server hardening (sshd_config, host keys)
|   |   +-- ssh_client.sh    # SSH client configuration & key generation
|   +-- sysctl/
|   |   +-- sysctl.sh        # Kernel parameter hardening (100+ sysctl settings)
|   +-- totp/
|   |   +-- totp.sh          # TOTP two-factor authentication for SSH
|   |   +-- README.md
|   +-- wireguard/
|   |   +-- wireguard.sh     # WireGuard VPN server with client config generation
|   |   +-- README.md
|   +-- wordpress/
|       +-- wordpress.sh     # WordPress security hardening
|       +-- README.md
+-- utils/
|   +-- aide-config.sh       # AIDE file integrity monitoring automation
|   +-- audit-check.sh       # Hardening compliance checker (pass/fail/warn report)
|   +-- auditd-attack.rules  # Auditd rules mapped to MITRE ATT&CK Framework
|   +-- backup.sh            # Encrypted borg backups with systemd timer
|   +-- docker.sh            # Docker/Podman hardening (rootless, seccomp, AppArmor)
|   +-- monitoring.sh        # Prometheus node_exporter + optional Grafana
|   +-- gnome.sh             # Minimal GNOME desktop (no bloat)
|   +-- openbox.sh           # Openbox + Tint2 panel setup
|   +-- neovim.sh            # NeoVim + Treesitter configuration
|   +-- vim.sh               # Vim plugins & hardening
|   +-- nano.sh              # Nano configuration & hardening
|   +-- zsh.sh               # Zsh configuration & hardening
|   +-- yay.sh               # yay AUR helper installation
|   +-- theme.sh             # Desktop theming
```

---

### Features

#### Installation

- **Automated Arch Linux Installation** &mdash; Automates disk partitioning, formatting, mounting, base system installation, and chroot configuration.
- **Full Disk Encryption (bare-metal)** &mdash; LVM on LUKS1 with encrypted boot partition, `aes-xts-plain64` cipher, 512-bit key, `sha512` hash, 3000ms iteration time.
- **TPM2 Support (bare-metal)** &mdash; Optional TPM 2.0 auto-detection and LUKS key enrollment with configurable PCR binding (0+7, 0+1+7, or 0+1+4+7+9).
- **VPS/Cloud Mode** &mdash; Simplified single-partition + swap file setup, BIOS/UEFI auto-detection, serial console support (`ttyS0` + GRUB serial), no encryption overhead.
- **Recovery Tool** &mdash; Interactive menu to unmount/remount encrypted installations and resume interrupted installs.
- **UEFI Secure Boot** &mdash; Generates PK/KEK/db/dbx keys, enrolls them in firmware, and signs GRUB EFI binaries.
- **NVIDIA & AMD GPU Detection** &mdash; Automatically detects GPU hardware and installs the correct driver packages (bare-metal only).
- **Dual Kernel** &mdash; Installs both `linux` and `linux-hardened` kernels.
- **CPU Microcode** &mdash; Auto-detects Intel/AMD and installs the appropriate microcode package.

#### Encryption & Key Management (bare-metal)

- LUKS1 container with passphrase, boot key file, and recovery key (3 key slots)
- LUKS header backup with secure external storage prompt
- Secure cleanup: `shred` of all key material after installation
- Encrypted swap via `/etc/crypttab`

#### Firewall

- **nftables** &mdash; Default deny policy, SSH rate limiting (2/min), stateful connection tracking, drop invalid packets. Configured automatically during installation.
- **FireHOL** &mdash; Optional advanced firewall with IP blocklist integration from FireHOL's blocklist-ipsets repository. Configurable blocklist levels, automated daily updates via cron.
- **iptables rate limiting** &mdash; SSH brute-force protection via the SSH hardening script.

#### Mandatory Access Control (AppArmor)

- **AppArmor profiles** for 7 services in enforce mode: nginx, sshd, fail2ban, ClamAV (freshclam + clamd), Stubby DNS, and chronyd.
- Each profile uses `abi <abi/3.0>`, precise path rules, minimal network access, and least-privilege capabilities.
- GRUB kernel parameters (`apparmor=1 security=apparmor`) configured automatically.
- See [`hardening/apparmor/README.md`](hardening/apparmor/README.md) for profile details and customization.

#### VPN (WireGuard)

- **WireGuard server** &mdash; One-command VPN setup with automatic key generation, pre-shared keys (quantum resistance), and client config files.
- **nftables integration** &mdash; NAT masquerade, port forwarding, and wg0 interface rules.
- **Client provisioning** &mdash; QR codes generated for each client config (mobile-friendly via `qrencode`).
- **Multi-client support** &mdash; Generate any number of clients with unique IPs.
- See [`hardening/wireguard/README.md`](hardening/wireguard/README.md) for usage and client management.

#### Intrusion Detection (CrowdSec)

- **CrowdSec IDS** &mdash; Behavior-based intrusion detection with community-powered threat intelligence.
- **nftables bouncer** &mdash; Automatic IP banning via nftables sets.
- **nginx bouncer** &mdash; Layer-7 blocking for web attacks (SQLi, XSS, path traversal).
- **Collections** &mdash; Pre-installed detection scenarios for Linux, SSH, and nginx.
- See [`hardening/crowdsec/README.md`](hardening/crowdsec/README.md) for setup and console enrollment.

#### Web Server Hardening (nginx)

- **nginx-mainline** with Let's Encrypt (certbot) &mdash; One-command setup targeting SSL Labs A+ and securityheaders.com A+.
- **TLS** &mdash; TLS 1.2 + 1.3 only, ECDHE + AEAD ciphers, X25519/P-384 curves, 4096-bit DH params, ECDSA P-384 certificates, session tickets disabled (forward secrecy), HTTP/2.
- **Security headers** &mdash; All six securityheaders.com graded headers (HSTS with 2-year preload, CSP, Permissions-Policy, Referrer-Policy, X-Content-Type-Options, X-Frame-Options) plus OWASP Cross-Origin headers (COEP, COOP, CORP).
- **Hardening** &mdash; Buffer limits, Slowloris timeouts, gzip disabled (BREACH prevention), dotfile/sensitive-file blocking, server tokens hidden.
- **Auto-renewal** &mdash; systemd timer runs certbot twice daily with nginx reload hook.
- **OCSP** &mdash; Intentionally disabled (Let's Encrypt ended OCSP support in 2025; browsers use CRLs).
- See [`hardening/nginx/README.md`](hardening/nginx/README.md) for full details.

#### Application Hardening (React & Node.js)

- **React/SPA** (`react.sh`) &mdash; Production deployment hardening via nginx: SPA routing, React-tuned CSP (`script-src 'self'` without `unsafe-eval`), aggressive static asset caching (1yr immutable for hashed files, no-cache for `index.html`), source map blocking, dotfile protection, file permissions (root:http 750/640), `.env.production.example` template with security guidelines.
- **Node.js/Express** (`nodejs.sh`) &mdash; Dedicated system user, hardened systemd service (ProtectSystem=strict, 14+ security directives, V8 JIT-aware), nginx reverse proxy with rate limiting, WebSocket support, `X-Powered-By` stripping, AppArmor profile, automated weekly `npm audit` via systemd timer, log rotation, secure environment file.
- See [`hardening/react/README.md`](hardening/react/README.md) and [`hardening/nodejs/README.md`](hardening/nodejs/README.md) for security best practices.

#### PHP Production Hardening

- **php.ini lockdown** &mdash; 30+ hardened directives: `expose_php=Off`, `display_errors=Off`, `allow_url_include=Off`, `open_basedir` restriction, session hardening (`strict` mode, `httponly`, `samesite=Strict`), `disable_functions` (30+ dangerous functions blocked), `upload_max_filesize` limited.
- **PHP-FPM pool** &mdash; Dedicated pool per application with `chroot`, `chdir`, `pm.max_children` tuning, `security.limit_extensions=.php`, status page on localhost only.
- **nginx FastCGI** &mdash; Snippet with `fastcgi_param PHP_VALUE` overrides, `PATH_INFO` stripping, buffer limits.
- **systemd hardening** &mdash; `ProtectSystem=strict`, `NoNewPrivileges`, private tmp/devices, restricted capabilities.
- See [`hardening/php/README.md`](hardening/php/README.md) for framework-specific configurations (Laravel, WordPress, Symfony).

#### Database Hardening (PostgreSQL & MariaDB)

- **PostgreSQL** (`postgresql.sh`) &mdash; `initdb` with `--data-checksums --auth-host=scram-sha-256`, hardened `postgresql.conf` (SSL required, `password_encryption=scram-sha-256`, `log_connections=on`, `log_disconnections=on`), locked-down `pg_hba.conf` (no `trust` anywhere), `pg_stat_statements` extension, systemd sandboxing.
- **MariaDB** (`mariadb.sh`) &mdash; Automated `mysql_secure_installation` equivalent (removes anonymous users, test database, remote root), random root password saved to `/root/.mariadb-root-pass` (600 permissions), `local-infile=0`, `skip-name-resolve`, `secure-file-priv`, `STRICT_TRANS_TABLES` SQL mode, self-signed SSL certificate generation, systemd hardening, logrotate.
- See [`hardening/postgresql/README.md`](hardening/postgresql/README.md) and [`hardening/mariadb/README.md`](hardening/mariadb/README.md) for backup strategies and common security mistakes.

#### WordPress Hardening

- **wp-config.php** &mdash; 11 security constants (`DISALLOW_FILE_EDIT`, `DISALLOW_FILE_MODS`, `FORCE_SSL_ADMIN`, `WP_AUTO_UPDATE_CORE`), fresh salts from WordPress API, randomized table prefix.
- **File permissions** &mdash; `root:http` ownership, directories 750, files 640, `wp-content/uploads` writable by `http` only.
- **nginx server block** &mdash; `xmlrpc.php` blocked, PHP execution denied in `wp-content/uploads`, hidden files blocked, rate limiting on `wp-login.php` and `wp-admin`.
- **fail2ban jails** &mdash; `wordpress-auth` (login brute-force) and `wordpress-xmlrpc` (XML-RPC abuse).
- **wp-cron** &mdash; Replaces WP's unreliable pseudo-cron with a systemd timer (every 15 minutes).
- See [`hardening/wordpress/README.md`](hardening/wordpress/README.md) for plugin security and update strategies.

#### Docker Runtime Security

- **CIS Docker Benchmark** (`--bench`) &mdash; Automated audit against the CIS Docker Benchmark, checks daemon configuration, container runtime, images, and host security.
- **Trivy image scanning** (`--scan`) &mdash; Vulnerability scanning for container images with weekly systemd timer for automated re-scans.
- **Compose hardening** (`--compose PATH`) &mdash; Audits Docker Compose files for 11 security issues (privileged mode, host networking, writable root filesystem, missing resource limits, etc.).
- **Network hardening** (`--network`) &mdash; nftables rules for container traffic, inter-container communication restrictions.
- **Security profiles** &mdash; Hardened AppArmor profile (`docker-default-hardened`) and seccomp profile (`seccomp-hardened.json`) with blocked syscalls.
- See [`hardening/docker/README.md`](hardening/docker/README.md) for container security best practices.

#### SSH Hardening

- **Server** (`ssh.sh`) &mdash; Regenerates host keys (Ed25519 + RSA 4096), enforces modern algorithms only (ChaCha20-Poly1305, AES-256-GCM, Curve25519), disables root login, X11 forwarding, agent forwarding, TCP forwarding, tunneling, and compression. Configures revoked keys file, VERBOSE logging, key-based + password multi-factor auth, strict session limits (MaxSessions 2, MaxStartups 2, MaxAuthTries 3), client alive timeout (300s), and a legal warning banner.
- **Client** (`ssh_client.sh`) &mdash; Generates Ed25519 key pair, configures SSH client with matching modern algorithms, hashes `known_hosts`, assists with public key deployment to servers.
- **Key Rotation** &mdash; Automated quarterly SSH key rotation via cron.

#### Two-Factor Authentication (TOTP)

- **SSH 2FA** (`totp.sh`) &mdash; Google Authenticator/TOTP for SSH with `pam_google_authenticator`.
- **Multi-factor enforcement** &mdash; Configures `AuthenticationMethods publickey,keyboard-interactive` (SSH key + TOTP required).
- **Gradual rollout** &mdash; `nullok` option allows users without TOTP to still log in during setup phase; remove for mandatory 2FA.
- **Emergency scratch codes** &mdash; Backup codes generated for account recovery.
- See [`hardening/totp/README.md`](hardening/totp/README.md) for compatible apps and setup guide.

#### Extended Intrusion Prevention (fail2ban)

- **7 jails** &mdash; SSH (24h ban, 3 retries), SSH-aggressive (7d ban, 1 retry for invalid users), nginx-http-auth, nginx-botsearch (7d ban), nginx-limit-req, and recidive (4-week ban for repeat offenders).
- **nftables integration** &mdash; Uses `nftables-multiport` and `nftables-allports` ban actions (no iptables dependency).
- **Custom filters** &mdash; Aggressive SSH filter catches invalid users, unauthenticated disconnects, and bad protocol versions.
- See [`hardening/fail2ban/README.md`](hardening/fail2ban/README.md) for jail descriptions and ban management.

#### Time Security (Chrony NTS)

- **Network Time Security** &mdash; Authenticated NTP via TLS 1.3 (RFC 8915), preventing MITM attacks on time synchronization.
- **6 NTS servers** &mdash; Cloudflare, Netnod (Sweden), PTB (Germany), Netnod Stockholm.
- **Client-only mode** &mdash; `port 0` disables NTP server functionality; `cmdallow` restricted to localhost.
- **Hardened systemd service** &mdash; `CAP_SYS_TIME` only, strict filesystem protection, clock syscall filter.
- See [`hardening/chrony/README.md`](hardening/chrony/README.md) for NTS verification and troubleshooting.

#### Send-Only Mail Relay (Postfix)

- **System notifications** &mdash; Send-only Postfix relay through any SMTP provider (Gmail, SendGrid, Mailgun, SES).
- **Security** &mdash; `loopback-only` (no external listening), TLS 1.2+ with STARTTLS, SASL authentication, VRFY disabled, internal header stripping.
- **Integration** &mdash; fail2ban notifications, cron job alerts, SMART monitoring, logwatch reports.
- See [`hardening/postfix/README.md`](hardening/postfix/README.md) for relay provider setup examples.

#### Kernel Hardening (sysctl)

Over 100 kernel parameters configured via `/etc/sysctl.d/99-sysctl.conf`:

- **Memory** &mdash; ASLR maximized (`vm.mmap_rnd_bits=32`), protected symlinks/hardlinks/FIFOs, restricted core dumps, `mmap_min_addr=65536`, strict overcommit.
- **Network** &mdash; SYN flood protection (syncookies), source validation (reverse path filtering), disabled IP forwarding, disabled ICMP redirects, martian packet logging, TCP Fast Open, BBR congestion control, `challenge_ack_limit` CVE mitigation, keepalive tuning, large buffer sizes for performance.
- **IPv6** &mdash; Disabled by default with all RA/redirect/source-route acceptance blocked.
- **Kernel** &mdash; Restricted `dmesg`, `kptr`, `ptrace` (scope 2), BPF JIT hardened, `perf_event_paranoid=3`, panic on oops, kexec disabled, SysRq disabled.

#### Kernel Boot Parameters

Passed via GRUB for defense-in-depth: `slab_nomerge`, `init_on_alloc=1`, `init_on_free=1`, `page_alloc.shuffle=1`, `pti=on`, `randomize_kstack_offset=on`, `vsyscall=none`.

#### DNS Security

- **DNS-over-TLS** via Stubby with privacy-focused upstream resolvers (Quad9 primary, Cloudflare secondary, Google fallback).
- **systemd-resolved** configured to use Stubby as upstream, with DNSSEC, no multicast DNS, no LLMNR.
- **DHCP DNS rejected** &mdash; Network configuration ignores DNS from DHCP to prevent DNS hijacking.

#### Authentication Hardening

- **PAM faillock** &mdash; Account lockout after 5 failed attempts, 15-minute unlock time.
- **Password quality** (`pam_pwquality`) &mdash; Minimum 12 characters, requires uppercase, lowercase, digit, and symbol. Enforced for root.
- **login.defs** &mdash; YESCRYPT encryption (cost factor 7), HMAC SHA512, UMASK 027, fail delay 5s, login timeout 30s, max retries 3, password max age 730 days.

#### Sudo Hardening

Custom `/etc/sudoers` with: secure path, env reset with curated keep list, `requiretty`, `umask=077`, 30-minute timestamp timeout, 3 password attempts, full I/O logging to `/var/log/sudo.log`, no `rootpw`.

#### Systemd Service Hardening

Granular per-service hardening overrides for 15+ services:

| Service | Key Restrictions |
|---------|-----------------|
| **sshd** | `ProtectHome=read-only`, strict syscall filter, device isolation |
| **NetworkManager** | Minimal capabilities (`CAP_NET_ADMIN/RAW`), kernel protection |
| **auditd** | Audit-specific capabilities, netlink-only networking |
| **ClamAV** | Read-only system, task limit (4), file I/O syscalls only |
| **fail2ban** | Net admin capabilities for nftables/iptables, log access |
| **Stubby** | Runs as dedicated `stubby` user, network I/O only |
| **systemd-resolved** | Netlink + inet networking, private temp/devices |
| **chronyd** | `CAP_SYS_TIME`, clock syscalls allowed, no home access |
| **rngd** | Full isolation (generic hardening template) |
| **systemd-journald** | Full isolation (generic hardening template) |
| **nginx** | `CAP_NET_BIND_SERVICE` only, strict filesystem, syscall filter, private devices |
| **Bluetooth** | Strict protection, AF_UNIX + AF_BLUETOOTH only (bare-metal) |
| **CrowdSec** | `ProtectSystem=strict`, limited read-write paths |
| **Postfix** | `CAP_NET_BIND_SERVICE`, strict filesystem, private temp |
| **Node.js apps** | Per-app sandboxing, `MemoryDenyWriteExecute=no` (V8 JIT), capability bounding |
| **PHP-FPM** | `ProtectSystem=strict`, `NoNewPrivileges`, restricted capabilities, private temp/devices |
| **PostgreSQL** | `ProtectSystem=strict`, `CAP_DAC_OVERRIDE` for data directory, syscall filter |
| **MariaDB** | `ProtectSystem=strict`, `CAP_DAC_OVERRIDE`, `CAP_IPC_LOCK`, private network |
| **WordPress (nginx+FPM)** | Combined nginx + PHP-FPM hardening, `wp-cron.timer` replacement |

Each override applies: `ProtectSystem=strict`, `NoNewPrivileges`, kernel module/tunable/log protection, syscall filtering, namespace/realtime/SUID restrictions, `MemoryDenyWriteExecute`, and private temp/devices.

#### Anti-Malware & Intrusion Detection

- **ClamAV** &mdash; Full configuration with PUA detection, heuristic alerts, encrypted archive alerts, all file type scanning enabled. Auto-updating signatures via `clamav-freshclam.service`.
- **rkhunter** &mdash; Rootkit detection with daily automated checks via systemd timer.
- **AIDE** &mdash; File integrity monitoring with custom rules (NORMAL, DIR, PERMS, LOG, DATAONLY), monitors `/boot`, `/etc`, `/usr/bin`, `/usr/sbin`, sensitive config files. Daily checks via systemd timer. See `utils/aide-config.sh`.
- **auditd** &mdash; MITRE ATT&CK-mapped audit rules (~500 rules covering initial access, execution, persistence, privilege escalation, defense evasion, credential access, discovery, lateral movement, collection, exfiltration, and C2).
- **fail2ban** &mdash; 7 jails covering SSH, nginx, and recidive (repeat offenders).
- **CrowdSec** &mdash; Behavior-based IDS with community threat intelligence, nftables and nginx bouncers.
- **arch-audit** &mdash; Daily vulnerability scanning for installed packages via systemd timer.
- **lynis** &mdash; Security auditing framework for compliance checking.
- **arpwatch** &mdash; ARP spoofing detection and monitoring.

#### Encrypted Backups (borg)

- **borg** &mdash; Encrypted, deduplicated backups with `repokey-blake2` encryption and `zstd` compression.
- **Automatic backup** &mdash; Daily at 2:00 AM via systemd timer with 30-minute random delay.
- **Configurable retention** &mdash; Default: 7 daily, 4 weekly, 6 monthly archives.
- **Managed operations** &mdash; `--init`, `--backup`, `--prune`, `--list`, `--restore` modes.
- Includes: `/etc`, `/home`, `/root`, `/var/lib`, `/var/log`, `/var/spool/cron`, `/opt`.

#### Monitoring (Prometheus & Grafana)

- **node_exporter** &mdash; Prometheus metrics exporter with systemd, filesystem, CPU, memory, network, disk, and process collectors. Listens on localhost only.
- **Custom security textfile collector** &mdash; Exports pending updates count, failed SSH logins, fail2ban bans, and failed systemd units (runs every 5 minutes).
- **Prometheus server** (optional) &mdash; 15-second scrape interval, 30-day retention, localhost-only.
- **Grafana** (optional) &mdash; Hardened configuration with security cookies, CSP headers, Prometheus auto-provisioned as datasource.

#### Container Hardening (Docker & Podman)

- **Podman** (default, recommended) &mdash; Rootless containers with `crun` runtime, `fuse-overlayfs` storage, `short-name-mode=enforcing`, journald logging, auto-update timer, subuid/subgid configuration.
- **Docker** (optional) &mdash; Hardened `daemon.json` (ICC disabled, no-new-privileges, userland-proxy off, json-file log rotation, overlay2, seccomp profile, `DOCKER_CONTENT_TRUST=1`), systemd service hardening.
- Both modes include container-specific sysctl settings and a 10-point security best practices checklist.

#### Hardening Compliance Checker

- **audit-check.sh** &mdash; Validates that all AwesomeArchLinux hardening has been correctly applied.
- **47 checks** across 8 categories: kernel hardening (sysctl), filesystem security, authentication, SSH, network, services, boot security, and disabled modules.
- **Output modes** &mdash; Color-coded terminal output (`[PASS]`/`[FAIL]`/`[WARN]`), `--verbose` for actual values, `--json` for machine-readable output.
- **Scoring** &mdash; Final pass/fail score with percentage.

#### Physical Security (bare-metal only)

- **USBGuard** &mdash; Default-block policy for USB devices, auto-generated allow policy for currently connected devices.
- **Bluetooth** &mdash; Hardware detection, secure connections only, LE mode, minimum 16-byte encryption key, privacy mode, systemd service hardened.

#### File System Security

- **Mount hardening** &mdash; `/tmp` and `/dev/shm` mounted with `nosuid,nodev,noexec`. `/proc` mounted with `hidepid=2`.
- **Permissions** &mdash; `/boot` (700), `/etc/shadow` (600), `/etc/gshadow` (600), `sshd_config` (600), `grub.cfg` (no world access), `sudoers` (440), `login.defs` (600).
- **UMASK 027** &mdash; Set globally in `/etc/profile`, `/etc/bash.bashrc`, and `/etc/login.defs`.
- **Home directory ACLs** &mdash; Default ACLs restrict group and other access.
- **Compiler restrictions** &mdash; `gcc`, `g++`, `clang`, `make`, `as`, `ld` restricted to `compilers` group (750).

#### Protocol Hardening

- Disabled kernel modules: `dccp`, `sctp`, `rds`, `tipc`.
- Core dumps disabled via `/etc/security/limits.conf`.
- Hardened compiler flags in `makepkg.conf`: `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, `-Wl,-z,relro,-z,now`, PIE.

#### Monitoring & Maintenance

- **Prometheus + Grafana** &mdash; Full monitoring stack with security-focused textfile collector.
- **sysstat** &mdash; System performance accounting.
- **logrotate** &mdash; Daily rotation, 7-day retention, compressed.
- **journald** &mdash; Persistent storage, compressed, sealed, 200MB max.
- **Automatic updates** &mdash; Daily `pacman -Syu` via systemd timer.

#### GRUB Security

- **Password protection** &mdash; PBKDF2-hashed GRUB password required to edit boot entries.
- **Encrypted boot** (bare-metal) &mdash; GRUB unlocks LUKS with embedded key file.
- **Serial console** (VPS) &mdash; GRUB configured for serial output for VPS provider console access.

#### Utilities

| Script | Description |
|--------|-------------|
| `utils/aide-config.sh` | AIDE file integrity monitoring with custom rules and daily systemd timer |
| `utils/audit-check.sh` | Hardening compliance checker (47 tests, 8 categories, JSON output) |
| `utils/backup.sh` | Encrypted borg backups with configurable retention and systemd timer |
| `utils/docker.sh` | Docker/Podman hardening (rootless Podman default, hardened Docker option) |
| `utils/monitoring.sh` | Prometheus node_exporter + optional Prometheus server + Grafana |
| `utils/gnome.sh` | Minimal GNOME desktop installation (no games/bloat) with security settings |
| `utils/openbox.sh` | Openbox window manager + Tint2 panel |
| `utils/neovim.sh` | NeoVim with Treesitter syntax highlighting |
| `utils/vim.sh` | Vim with plugins and hardening |
| `utils/nano.sh` | Nano with backups, locking, and syntax highlighting |
| `utils/zsh.sh` | Zsh shell configuration and hardening |
| `utils/yay.sh` | yay AUR helper installation |
| `utils/theme.sh` | Desktop theming |

---

### Installation

First, download the Arch Linux ISO [here](https://archlinux.org/download/).

#### Bare-metal (Full Disk Encryption)

Boot the media on the target device.

```bash
pacman -Sy git
git clone https://github.com/schm1d/AwesomeArchLinux.git
cd AwesomeArchLinux/base
chmod +x *.sh
./archinstall.sh
```

The installer will prompt you for:
- Target disk
- Swap, root, and optional `/var` partition sizes
- Username and hostname
- LUKS encryption passphrase
- Optional TPM2 binding
- GRUB password
- User and root passwords

#### VPS / Cloud Server

Boot the Arch Linux ISO on your VPS (most providers support custom ISOs).

```bash
pacman -Sy git
git clone https://github.com/schm1d/AwesomeArchLinux.git
cd AwesomeArchLinux/base
chmod +x *.sh
./vps-install.sh
```

The VPS installer will prompt you for:
- Target disk (typically `vda` or `sda`)
- Swap size
- Username, hostname, and SSH port
- GRUB password
- User and root passwords

#### Offline Installation

Download the scripts on another machine and copy them to a removable media.

1. Copy `archinstall.sh` + `chroot.sh` (or `vps-install.sh` + `vps-chroot.sh`) to the same directory on the live system.
2. Make them executable: `chmod +x *.sh`
3. Run the installer: `./archinstall.sh` or `./vps-install.sh`

---

### Post-Installation

After rebooting:

1. **Run AUR packages script** (as the created user):
   ```bash
   /root/install-aur-packages.sh
   ```

2. **Enable security services**:
   ```bash
   systemctl enable --now apparmor
   systemctl enable --now auditd
   systemctl enable --now rkhunter.timer
   systemctl enable --now arch-audit.timer
   ```

3. **Secure Boot enrollment** (bare-metal, if desired):
   ```bash
   sbctl status
   sbctl sign -s /efi/EFI/GRUB/grubx64.efi
   sbctl sign -s /boot/vmlinuz-linux
   sbctl sign -s /boot/vmlinuz-linux-hardened
   ```

4. **TPM2 enrollment** (bare-metal, if TPM was selected):
   ```bash
   systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=0+7 /dev/<partition>
   ```

5. **Add SSH authorized keys** (VPS):
   ```bash
   # From your local machine:
   ssh-copy-id -p <SSH_PORT> <username>@<server-ip>
   ```

6. **Review**: `/root/POST_INSTALL_README.txt`

---

### Standalone Hardening Scripts

The scripts in `hardening/` and `utils/` can be used independently on any Arch Linux system:

```bash
# --- Mandatory Access Control ---
sudo ./hardening/apparmor/apparmor.sh          # AppArmor profiles for 7 services

# --- Network ---
sudo ./hardening/ssh/ssh.sh                    # Harden SSH server
sudo ./hardening/totp/totp.sh -u myuser        # Add TOTP 2FA to SSH
sudo ./hardening/wireguard/wireguard.sh        # WireGuard VPN server
sudo ./hardening/fail2ban/fail2ban.sh          # Extended fail2ban jails

# --- Web ---
sudo ./hardening/nginx/nginx.sh -d example.com -e admin@example.com   # nginx + Let's Encrypt
sudo ./hardening/react/react.sh -a /var/www/myapp -d app.example.com  # React SPA hardening
sudo ./hardening/nodejs/nodejs.sh -a /opt/api -n api-server           # Node.js hardening
sudo ./hardening/php/php.sh -a /var/www/myapp                         # PHP production hardening
sudo ./hardening/wordpress/wordpress.sh -a /var/www/wordpress -d wp.example.com  # WordPress hardening

# --- Database ---
sudo ./hardening/postgresql/postgresql.sh                             # PostgreSQL hardening
sudo ./hardening/mariadb/mariadb.sh                                   # MariaDB hardening

# --- Container Security ---
sudo ./hardening/docker/docker.sh --bench                             # CIS Docker Benchmark audit
sudo ./hardening/docker/docker.sh --scan myimage:latest               # Trivy image scan
sudo ./hardening/docker/docker.sh --compose docker-compose.yml        # Compose security audit
sudo ./hardening/docker/docker.sh --network                           # Container network hardening

# --- System ---
sudo ./hardening/sysctl/sysctl.sh              # Kernel parameter hardening
sudo ./hardening/chrony/chrony.sh              # Chrony NTS (authenticated NTP)
sudo ./hardening/postfix/postfix.sh -r smtp.gmail.com -u user@gmail.com -p 'pass'  # Mail relay

# --- Detection ---
sudo ./hardening/crowdsec/crowdsec.sh --with-nginx --with-nftables    # CrowdSec IDS
sudo ./hardening/firehol/firehol.sh -l 1       # FireHOL with IP blocklists

# --- Utilities ---
sudo ./utils/backup.sh --init                  # Initialize encrypted backups
sudo ./utils/backup.sh --backup --prune        # Run backup with retention
sudo ./utils/aide-config.sh --init             # Initialize AIDE file integrity DB
sudo ./utils/monitoring.sh --with-prometheus --with-grafana  # Full monitoring stack
sudo ./utils/docker.sh --podman -u myuser      # Rootless Podman containers
sudo ./utils/audit-check.sh                    # Check hardening compliance
sudo ./utils/audit-check.sh --json             # Machine-readable compliance report
```

---

### Customization

- **Variables** &mdash; Modify `TIMEZONE`, `LOCALE`, `SSH_PORT`, and keymap in `chroot.sh` / `vps-chroot.sh`.
- **Package selection** &mdash; Adjust the `pacstrap` package list in the installer scripts.
- **Firewall rules** &mdash; Edit `/etc/nftables.conf` to add application-specific ports.
- **DNS providers** &mdash; Edit `/etc/stubby/stubby.yml` to change upstream DNS resolvers.
- **CSP headers** &mdash; Customize `Content-Security-Policy` in nginx configs for your application needs.
- **Backup paths** &mdash; Edit `backup.sh` include/exclude lists for your environment.
- **Monitoring** &mdash; Add custom Prometheus textfile collectors in `/var/lib/prometheus/node-exporter/`.

### Contributing

Contributions are welcome! Feel free to submit issues or pull requests to improve the scripts, add new features, or enhance the documentation.

### License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

**Note**: Arch Linux is a rolling-release distribution suitable for users who want complete control over their system. These scripts automate the installation and hardening process, but reviewing and understanding the configurations is essential to ensure they meet your security requirements.
