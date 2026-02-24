# AppArmor Hardening for Arch Linux

Mandatory Access Control (MAC) profiles for critical system services on Arch Linux. This script installs AppArmor, configures GRUB to enable it at boot, and deploys enforce-mode profiles for seven services.

## Usage

```bash
# Full installation and enforcement
sudo ./apparmor.sh

# Preview profiles without installing (writes to /tmp/apparmor-preview/)
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
| `usr.bin.nginx` | `/usr/bin/nginx` | Web server. Allows reading config, web content, TLS certs. Grants `net_bind_service` for port 80/443, plus `setuid`/`setgid`/`dac_override` for worker process management. |
| `usr.bin.sshd` | `/usr/bin/sshd` | SSH daemon. Allows host key access, PAM authentication, PTY allocation, and logging. Grants `sys_chroot`, `audit_write`, `kill` for privilege separation. Login shells execute unconfined (`Ux`). |
| `usr.bin.fail2ban-server` | `/usr/bin/fail2ban-server` | Intrusion prevention. Reads all logs to detect brute force, writes its own state/log. Executes `nft`/`iptables` for ban actions. Grants `net_admin`/`net_raw`/`dac_read_search`. |
| `usr.bin.freshclam` | `/usr/bin/freshclam` | ClamAV signature updater. Network access (TCP) to download updates. Writes to `/var/lib/clamav/`. Grants `setuid`/`setgid` for privilege drop. |
| `usr.bin.clamd` | `/usr/bin/clamd` | ClamAV scanning daemon. Reads signature database and files submitted via `/tmp/`. Communicates over Unix sockets only (no network). Grants `dac_override` for scanning files owned by other users. |
| `usr.bin.stubby` | `/usr/bin/stubby` | DNS-over-TLS resolver. Network access for upstream DNS resolution over TLS. Reads its config and TLS trust store. Grants `net_bind_service` for port 53 listening. |
| `usr.bin.chronyd` | `/usr/bin/chronyd` | NTP daemon. UDP network access for time synchronization. Grants `sys_time` to adjust the system clock. Reads hardware clock devices (`/dev/rtc*`, `/dev/pps*`). |

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
| `abstractions/openssl` | OpenSSL config, CA certificates, entropy sources |
| `abstractions/authentication` | PAM, `/etc/passwd`, `/etc/shadow`, `/etc/nsswitch.conf` |
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
# Then remove kernel params from /etc/default/grub and run grub-mkconfig
```
