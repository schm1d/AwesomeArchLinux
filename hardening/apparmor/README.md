# AppArmor Hardening for Arch Linux

Mandatory Access Control (MAC) profiles for critical system services on Arch Linux. This script installs AppArmor, configures the detected bootloader (signed UKIs via `/etc/kernel/cmdline`, systemd-boot entries, or GRUB) to enable it at boot, and deploys profiles for seven services. The profiles are enforced, except that the sshd profile starts in complain mode until you enforce it (see [First boot](#first-boot-sshd-starts-in-complain-mode)).

## Usage

```bash
# Install, configure the bootloader, deploy the profiles
sudo ./apparmor.sh

# Preview profiles without installing (writes to /tmp/apparmor-preview.XXXXXX/)
sudo ./apparmor.sh --dry-run

# Deploy every profile in enforce mode, including sshd
sudo ./apparmor.sh --enforce

# Deploy every profile in complain mode (log only)
sudo ./apparmor.sh --complain
```

| Option | Effect |
|---|---|
| `--dry-run` | Writes the profiles to a private `/tmp/apparmor-preview.XXXXXX/` directory and reports what would change. Installs nothing, edits no bootloader file, loads nothing. The preview profiles carry the mode a real run would use (`flags=(...)` on each `profile` line). |
| `--enforce` | Deploys every profile in enforce mode, including sshd. On a system where the sshd profile has never run, the first enforced login is the one after the reboot: have console (non-SSH) access before you use it there. |
| `--complain` | Deploys every profile in complain mode: nothing is blocked, violations are only logged. |
| neither | Enforce mode for every profile except sshd. The sshd profile is deployed in complain mode unless the running kernel already has it loaded in enforce mode. |

`--enforce` and `--complain` are mutually exclusive. Re-running the script rewrites the generated profiles in the mode selected by these rules.

### Kernel parameters

AppArmor is only active when the kernel boots with `apparmor=1` **and** `apparmor` is named in the `lsm=` list. The script edits the command line accordingly:

- An existing `lsm=` list without `apparmor` gets it inserted, before `bpf` when `bpf` is listed, otherwise at the end.
- A command line without `lsm=` gets a full list: the LSMs active in the running kernel (from `/sys/kernel/security/lsm`, without the always-on `capability`) plus `apparmor`, for example `lsm=landlock,lockdown,yama,apparmor,bpf`. If that file cannot be read, `lsm=landlock,lockdown,yama,integrity,apparmor,bpf` is used.
- `security=apparmor` is not added. The kernel ignores `security=` as soon as the command line carries `lsm=`, so it cannot be relied on. An existing `security=` parameter is left alone.
- An `apparmor=0` is replaced by `apparmor=1`.
- If `selinux` or `smack` is listed ahead of `apparmor`, the script warns: the kernel enables only the first of them, and the list is yours to decide.

How the three supported layouts are edited (a `.bak.<timestamp>` copy is kept next to every file that is changed):

| Layout | Handling |
|---|---|
| UKI (`/etc/kernel/cmdline`) | Comment lines (`#`) are not parameters and stay in the file; all parameter lines are joined into one line. The result is checked with the same filter mkinitcpio uses before it replaces the file, then `mkinitcpio -P` rebuilds the UKIs and `sbctl sign-all` re-signs them when Secure Boot keys are present. |
| systemd-boot entries | All `options` lines of an entry are read as one string (sd-boot joins them) and written back as a single `options` line. |
| GRUB (`/etc/default/grub`) | The last `GRUB_CMDLINE_LINUX_DEFAULT=` assignment is edited (the one that wins when the file is sourced), keeping its quote style; it is appended if missing. A value the script cannot rewrite safely (text after the closing quote, several quoted parts) stops the run with an explanation. `grub-mkconfig` is run afterwards. |

After running the script, **reboot**, then check that the LSM is really on. An enabled `apparmor.service` is not enough:

```bash
cat /sys/kernel/security/lsm   # must list apparmor
sudo aa-status
```

If `apparmor` is missing from that list, the entry you booted does not carry the parameters (for UKIs: `sudo mkinitcpio -P`, then re-sign).

### First boot: sshd starts in complain mode

AppArmor normally becomes active only after the reboot, so a gap in the sshd profile would first show when nobody can log in any more. Unless `--enforce` is given, the sshd profile is therefore deployed in **complain mode**: it blocks nothing and logs everything it would have denied. The other profiles are enforced from the start; a gap there breaks one service, not your access.

The sshd profile stays in complain mode across re-runs. It is enforced only when you ask for it (`--enforce` or `aa-enforce`); once it runs enforced, later runs without options keep it enforced. While it is in complain mode sshd is **not confined**, so do not skip the second half:

1. Reboot and check `/sys/kernel/security/lsm` as shown above. If AppArmor was already active when you ran the script, restart sshd instead (`sudo systemctl restart sshd`) so the profile attaches.
2. Log in over SSH the way you normally do (key, password, TOTP, sftp, port forwarding).
3. List what the profile is missing:

   ```bash
   # auditd running
   sudo grep 'apparmor="ALLOWED"' /var/log/audit/audit.log | grep 'profile="sshd"'

   # no auditd
   sudo journalctl -b | grep 'apparmor="ALLOWED"' | grep 'profile="sshd"'
   ```

   No output means the profile covers your logins. Otherwise add the missing rules to `/etc/apparmor.d/local/usr.bin.sshd` (included by the profile, never touched by this script) and reload with `sudo apparmor_parser -r /etc/apparmor.d/usr.bin.sshd`. These messages need the kernel audit subsystem; with `audit=0` on the command line nothing is logged.
4. Enforce it, keeping one SSH session open until a new login has worked:

   ```bash
   sudo ./apparmor.sh --enforce
   # or only sshd:
   sudo aa-enforce /etc/apparmor.d/usr.bin.sshd
   ```

   If the new login fails, run `sudo aa-complain /etc/apparmor.d/usr.bin.sshd` from the session you kept.

## Profile Descriptions

| Profile | Binary | Purpose |
|---|---|---|
| `usr.bin.nginx` | `/usr/bin/nginx` | Web server. Allows reading config, web content (`/var/www`, `/srv/http`, `/usr/share/nginx/html`), TLS certs (`abstractions/ssl_certs`, `/etc/letsencrypt`, `/etc/ssl`), and PHP-FPM/Unix upstream sockets (`/run/php-fpm/*.sock`). Grants `net_bind_service` for port 80/443, plus `setuid`/`setgid`/`chown`/`dac_override`/`dac_read_search` for worker and cache management. |
| `usr.bin.sshd` | `/usr/bin/sshd` | SSH daemon. **Deployed in complain mode first** (see above). Covers OpenSSH 10.x split helpers (`sshd-session`, `sshd-auth`, `sftp-server`, `ssh-sk-helper`, `ssh-pkcs11-helper`), its own re-exec on `systemctl reload sshd` (`mrix`), host and user SSH key access, PAM/systemd-logind/faillock/wtmp (`libpam-systemd`, `wutmp`, `/run/faillock`), systemd notify socket, PTY allocation, and logging. TOTP logins ([`hardening/totp`](../totp/)): `pam_google_authenticator` may read and rewrite the user's own `~/.google_authenticator` (and its `~` temp file). fscrypt homes ([`hardening/fscrypt`](../fscrypt/)): `pam_fscrypt` may read `/etc/fscrypt.conf`, the mount table, the `.fscrypt` metadata on `/` and `/home`, open `/`, `/home` and the home directories, keep its session count in `/run/fscrypt`, and write `/proc/sys/vm/drop_caches`; these fscrypt rules are best effort and have not been exercised under an enforcing kernel. Grants `sys_chroot`, `sys_resource`, `audit_write`, `dac_read_search`, `kill` for privilege separation. Login shells (`bash`, `sh`, `zsh`, `fish`, `git-shell`) execute unconfined (`Ux`) and `nologin` runs confined (`rix`). Site-specific rules go in `/etc/apparmor.d/local/usr.bin.sshd`, which the profile includes when it exists. |
| `usr.bin.fail2ban-server` | `/usr/bin/fail2ban-server` | Intrusion prevention. Reads `/var/log/`, `/run/log/journal/`, and `/etc/machine-id` to detect brute force, locks/writes `/var/lib/fail2ban/`, and uses Unix/Netlink sockets. Executes Python (`mrix`), action shells/utilities (`bash`/`sh`/`dash`, `sed`/`grep`/`gawk`/`awk`), and `nft`/`iptables`/`xtables-*-multi` for ban actions. Grants `net_admin`/`net_raw`/`dac_read_search`. |
| `usr.bin.freshclam` | `/usr/bin/freshclam` | ClamAV signature updater. TCP + TLS (`abstractions/ssl_certs`) network access to download updates and local Unix stream access (`peer=(label=clamd)`) to notify `clamd` after signature reloads. Writes to `/var/lib/clamav/`. Grants `setuid`/`setgid` for privilege drop and `chown`, because freshclam started as root hands its log file to the `clamav` user (`lchown`) before dropping privileges and exits if that fails. |
| `usr.bin.clamd` | `/usr/bin/clamd` | ClamAV scanning daemon. Uses `abstractions/nameservice-strict` (no TCP/UDP network), reads signature database and scan targets, manages temporary unpacked files in `/tmp` and `/var/tmp`, and communicates over local Unix stream sockets only. Grants `setuid`/`setgid` for privilege drop, `chown` for the same log-file hand-over as freshclam (`LogFile` set and started as root, the Arch default), and `dac_override` for scanning files owned by other users. |
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

Review the messages. An enforced profile logs `apparmor="DENIED"`; a profile in complain mode logs `apparmor="ALLOWED"` for the same events:

```bash
# Via audit log (if auditd is running)
sudo grep -E 'apparmor="(DENIED|ALLOWED)"' /var/log/audit/audit.log

# Via journal (if auditd is not running)
journalctl -k | grep apparmor
```

Once you have identified and fixed the issue, re-enforce:

```bash
sudo aa-enforce /etc/apparmor.d/usr.bin.nginx
```

Running `apparmor.sh` again without options also puts every profile except sshd back into enforce mode; the sshd profile keeps the mode it is running in.

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

Re-running `apparmor.sh` rewrites the generated profiles, so such edits have to be repeated afterwards. For sshd, put site-specific rules in `/etc/apparmor.d/local/usr.bin.sshd` instead: the profile includes that file when it exists and the script never touches it.

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
# Then, in /etc/kernel/cmdline (and rebuild/sign UKIs), the systemd-boot entry
# options, or /etc/default/grub (and run grub-mkconfig):
#   - remove apparmor=1
#   - take "apparmor" out of the lsm= list, or remove the whole lsm= parameter
#     if your command line had none before this script ran
#   - remove security=apparmor if an older version of this script left one
# The .bak.<timestamp> copy next to each file shows what it looked like before.
```

## References

- [AppArmor — ArchWiki](https://wiki.archlinux.org/title/AppArmor)
- [AppArmor upstream documentation](https://gitlab.com/apparmor/apparmor/-/wikis/Documentation)
- [`apparmor.d(5)` profile language](https://man.archlinux.org/man/apparmor.d.5.en)
- [`apparmor_parser(8)`](https://man.archlinux.org/man/apparmor_parser.8.en)
- [`aa-logprof(8)`](https://man.archlinux.org/man/aa-logprof.8.en)
- [Linux Security Module documentation](https://docs.kernel.org/admin-guide/LSM/)
