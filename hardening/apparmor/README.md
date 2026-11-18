# AppArmor Hardening for Arch Linux

Mandatory Access Control (MAC) profiles for critical system services on Arch Linux. This script installs AppArmor, configures the detected bootloader (signed UKIs via `/etc/kernel/cmdline`, systemd-boot entries, or GRUB) to enable it at boot, and deploys enforce-mode profiles for seven services.

## Usage

```bash
# Full installation and enforcement
sudo ./apparmor.sh

# Preview profiles without installing (writes to /tmp/apparmor-preview.XXXXXX/)
sudo ./apparmor.sh --dry-run
```

After running the script, **reboot** to activate the AppArmor kernel parameters (`apparmor=1 security=apparmor`).

Verify AppArmor is active after reboot:

```bash
sudo aa-status
```

## Profile Descriptions

| Profile | Binary | Purpose |
|---|---|---|
| `usr.bin.nginx` | `/usr/bin/nginx` | Web server. Allows reading config, web content (`/var/www`, `/srv/http`, `/usr/share/nginx/html`), TLS certs (`abstractions/ssl_certs`, `/etc/letsencrypt`, `/etc/ssl`), and PHP-FPM/Unix upstream sockets (`/run/php-fpm/*.sock`). Grants `net_bind_service` for port 80/443, plus `setuid`/`setgid`/`chown`/`dac_override`/`dac_read_search` for worker and cache management. |
| `usr.bin.sshd` | `/usr/bin/sshd` | SSH daemon. Covers OpenSSH 10.x split helpers (`sshd-session`, `sshd-auth`, `sftp-server`, `ssh-sk-helper`, `ssh-pkcs11-helper`), host and user SSH key access, PAM/systemd-logind/faillock/wtmp (`libpam-systemd`, `wutmp`, `/run/faillock`), systemd notify socket, PTY allocation, and logging. Grants `sys_chroot`, `sys_resource`, `audit_write`, `dac_read_search`, `kill` for privilege separation. Login shells (`bash`, `sh`, `zsh`, `fish`, `git-shell`) execute unconfined (`Ux`) and `nologin` runs confined (`rix`). |
| `usr.bin.fail2ban-server` | `/usr/bin/fail2ban-server` | Intrusion prevention. Reads `/var/log/`, `/run/log/journal/`, and `/etc/machine-id` to detect brute force, locks/writes `/var/lib/fail2ban/`, and uses Unix/Netlink sockets. Executes Python (`mrix`), action shells/utilities (`bash`/`sh`/`dash`, `sed`/`grep`/`gawk`/`awk`), and `nft`/`iptables`/`xtables-*-multi` for ban actions. Grants `net_admin`/`net_raw`/`dac_read_search`. |
| `usr.bin.freshclam` | `/usr/bin/freshclam` | ClamAV signature updater. TCP + TLS (`abstractions/ssl_certs`) network access to download updates and local Unix stream access (`peer=(label=clamd)`) to notify `clamd` after signature reloads. Writes to `/var/lib/clamav/`. Grants `setuid`/`setgid` for privilege drop. |
| `usr.bin.clamd` | `/usr/bin/clamd` | ClamAV scanning daemon. Uses `abstractions/nameservice-strict` (no TCP/UDP network), reads signature database and scan targets, manages temporary unpacked files in `/tmp` and `/var/tmp`, and communicates over local Unix stream sockets only. Grants `dac_override` for scanning files owned by other users. |
| `usr.bin.stubby` | `/usr/bin/stubby` | DNS-over-TLS resolver. Network access for upstream DNS resolution over TLS. Reads its config and TLS trust store (`abstractions/ssl_certs`). Grants `net_bind_service` for port 53 listening. **Only deployed if `/usr/bin/stubby` exists** — if absent, any stale live/on-disk `usr.bin.stubby` profile is unloaded and removed. |
| `usr.bin.chronyd` | `/usr/bin/chronyd` | NTP/NTS daemon. UDP (NTP) and TCP (NTS-KE port 4460) network access plus OpenSSL, `ssl_certs`, and `p11-kit` abstractions (for GnuTLS TLS 1.3 trust verification), `/run/systemd/notify`, and `/etc/chrony.keys`. Grants `sys_time`, `setuid`/`setgid`, `chown`, `dac_override`, and `net_bind_service`. Accesses hardware clock devices (`/dev/rtc*`, `/dev/pps*`, `/dev/ptp*` `rw`). |

## Customization

### Switching a Profile to Complain Mode (Debugging)

If a service breaks after enforcement, switch its profile to **complain** (log-only) mode:

```bash
# Switch to complain mode — violations are logged but not blocked
sudo aa-complain /etc/apparmor.d/usr.bin.nginx

# Check which profiles are in complain vs enforce mode
sudo aa-status
```

Review denial messages:

```bash
# Via audit log (if auditd is running)
sudo grep 'apparmor="DENIED"' /var/log/audit/audit.log

# Via journal (if auditd is not running)
journalctl -k | grep apparmor
```

Once you have identified and fixed the issue, re-enforce:

```bash
sudo aa-enforce /etc/apparmor.d/usr.bin.nginx
```

### Adding Custom Path Rules

To allow a service access to additional paths, edit its profile in `/etc/apparmor.d/`. For example, if nginx needs to serve content from `/srv/www/`:

```
# Add inside the profile block in /etc/apparmor.d/usr.bin.nginx
/srv/www/**    r,
```

Then reload the profile:

```bash
sudo apparmor_parser -r /etc/apparmor.d/usr.bin.nginx
```

### Creating a New Profile

1. Start with a template:

```
abi <abi/3.0>,

#include <tunables/global>

profile myservice /usr/bin/myservice flags=(enforce) {
  #include <abstractions/base>

  /usr/bin/myservice    mr,
  /etc/myservice/**     r,
  /var/log/myservice/** rw,
}
```

2. Save it to `/etc/apparmor.d/usr.bin.myservice`.

3. Load it in complain mode first to discover what access it needs:

```bash
sudo apparmor_parser -r /etc/apparmor.d/usr.bin.myservice
sudo aa-complain /etc/apparmor.d/usr.bin.myservice
```

4. Exercise the service normally. Review denials and add rules.

5. When complete, switch to enforce mode:

```bash
sudo aa-enforce /etc/apparmor.d/usr.bin.myservice
```

### Using aa-logprof to Auto-Generate Rules

After running a profile in complain mode, `aa-logprof` can scan the audit log and suggest rules:

```bash
sudo aa-logprof
```

It presents each denial interactively and lets you approve, deny, or glob the path. The approved rules are written directly into the profile.

### Common Abstractions

AppArmor ships with reusable rule sets in `/etc/apparmor.d/abstractions/`. Include them to avoid duplicating rules:

| Abstraction | Provides |
|---|---|
| `abstractions/base` | Core system access (`/etc/ld.so.cache`, `/lib/**`, `/proc/meminfo`, etc.) |
| `abstractions/nameservice` | DNS resolution, NSS, `/etc/hosts`, `/etc/resolv.conf` |
| `abstractions/nameservice-strict` | Local NSS/DNS config lookup without granting direct TCP/UDP sockets |
| `abstractions/openssl` | OpenSSL config and entropy sources |
| `abstractions/ssl_certs` | System CA trust stores, Let's Encrypt / ACME certificate bundles |
| `abstractions/p11-kit` | PKCS#11 / `p11-kit-trust` modules (used by GnuTLS-linked daemons like `chronyd`) |
| `abstractions/authentication` | PAM, `/etc/passwd`, `/etc/shadow`, `/etc/nsswitch.conf` |
| `abstractions/libpam-systemd` | `systemd-logind` D-Bus session creation/release for PAM logins |
| `abstractions/wutmp` | `utmp`, `wtmp`/`wtmpdb`, `btmp`, and `lastlog`/`lastlog2` login accounting |
| `abstractions/python` | Python interpreter, stdlib, site-packages |

### Useful Commands Reference

```bash
# Show all loaded profiles and their modes
sudo aa-status

# Reload a single profile after editing
sudo apparmor_parser -r /etc/apparmor.d/usr.bin.nginx

# Reload all profiles
sudo systemctl reload apparmor

# Remove a profile (unload and delete)
sudo apparmor_parser -R /etc/apparmor.d/usr.bin.myservice
sudo rm /etc/apparmor.d/usr.bin.myservice

# Disable AppArmor entirely (not recommended)
sudo systemctl disable apparmor.service
# Then remove apparmor=1 security=apparmor from /etc/kernel/cmdline (and rebuild/sign UKIs),
# systemd-boot entry options, or /etc/default/grub (and run grub-mkconfig)
```

## References

- [AppArmor — ArchWiki](https://wiki.archlinux.org/title/AppArmor)
- [AppArmor upstream documentation](https://gitlab.com/apparmor/apparmor/-/wikis/Documentation)
- [`apparmor.d(5)` profile language](https://man.archlinux.org/man/apparmor.d.5.en)
- [`apparmor_parser(8)`](https://man.archlinux.org/man/apparmor_parser.8.en)
- [`aa-logprof(8)`](https://man.archlinux.org/man/aa-logprof.8.en)
- [Linux Security Module documentation](https://docs.kernel.org/admin-guide/LSM/)
