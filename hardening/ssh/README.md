# SSH Hardening

Hardens OpenSSH server and client configuration on Arch Linux. Regenerates host keys (Ed25519 + RSA 4096) on the first run, enforces modern cryptographic algorithms, restricts access, and applies CIS Benchmark recommendations for SSH.

Author: [Bruno Schmid](https://www.linkedin.com/in/schmidbruno/) X: @brulliant

---

## Scripts

| Script | Purpose |
|--------|---------|
| `ssh.sh` | Server-side hardening (sshd_config, host keys, banner, nftables/iptables rate limiting) |
| `ssh_client.sh` | Client-side setup (key generation, ssh_config, public key deployment) |

---

## Usage

### Server Hardening

```bash
sudo ./ssh.sh -u <username> [-p <port>] [-k] [-r]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-u USER` | User to allow SSH access (required, must not be root) | `$SUDO_USER` if available |
| `-p PORT` | SSH listening port | 22 |
| `-k` | Skip `authorized_keys` lockout check (bare-metal console installs only; never use on VPS) | off |
| `-r` | Regenerate the host keys even though an earlier run already created them | off |
| `-h` | Show help | — |

The script automatically detects `SUDO_USER` when run via `sudo`, so in most cases:

```bash
sudo ./ssh.sh
```

### Client Configuration

```bash
./ssh_client.sh
```

Edit the variables at the top of the script before running:
- `SERVER_IP` — your server's IP or hostname
- `USERNAME` — your username on the server
- `SSH_PORT` — the SSH port (must match the server)

---

## What ssh.sh Does

### 1. Host Key Generation

- First run (the `sshd_config` was not written by this script yet): generates new Ed25519 and RSA 4096-bit host keys and shreds every key the system came with, so keys baked into an image or template are not kept
- Later runs keep the keys the script created, so clients are not confronted with `REMOTE HOST IDENTIFICATION HAS CHANGED` after every re-run. They are only regenerated when one is missing, when the RSA key has fewer than 4096 bits, or when `-r` is passed
- The old keys are kept aside until sshd runs with the new configuration and are restored if the run is rolled back
- Prints the fingerprints at the end of every run; after a regeneration, verify them and run `ssh-keygen -R <host>` on each client
- Sets correct permissions (600 for private keys, 644 for public keys)

If you clone a machine that was already hardened, run `sudo ./ssh.sh -u <user> -r` on the clone to give it its own host keys.

### 2. SSH Daemon Configuration (sshd_config)

Writes a complete hardened `sshd_config` (truncate, not append — avoids first-match-wins issues). Backs up the original before overwriting.

**Network:**
- Configurable port, dual-stack IPv4/IPv6 (`AddressFamily any`), `StrictModes yes`

**Cryptographic Algorithms (OpenSSH 9.x+ modern):**
- Host keys: `ssh-ed25519-cert-v01`, `ssh-ed25519`, `rsa-sha2-512`, `rsa-sha2-256`
- KEX: `sntrup761x25519-sha512` (post-quantum), `curve25519-sha256`, `diffie-hellman-group18-sha512`, `diffie-hellman-group16-sha512`
- Ciphers: `chacha20-poly1305`, `aes256-gcm`, `aes128-gcm` (AEAD only)
- MACs: `hmac-sha2-512-etm`, `hmac-sha2-256-etm`, `umac-128-etm` (ETM only)

**Authentication:**
- Public key only (`AuthenticationMethods publickey`), unless the TOTP drop-in written by `hardening/totp/totp.sh` is present (see "Add TOTP Two-Factor Authentication")
- Password authentication disabled
- Empty passwords, keyboard-interactive, Kerberos, GSSAPI, host-based all disabled

**Access Control:**
- Root login disabled (`PermitRootLogin no`)
- `AllowUsers` restricted to the specified user
- Max 3 auth tries, 2 sessions, 60s login grace time
- `MaxStartups 10:30:60` (rate limiting at the protocol level)

**Session Hardening:**
- All forwarding disabled (`DisableForwarding yes`)
- X11 forwarding disabled
- No compression, no user RC files, no user environment
- `ClientAliveInterval 300`, `ClientAliveCountMax 3` (idle timeout ~15 min)
- `RekeyLimit 512M 1h`
- `VersionAddendum none` (hide software details)

**Logging:**
- `LogLevel VERBOSE`, `SyslogFacility AUTH`

### 3. SSH Client Configuration (ssh_config)

Writes a hardened global client config with:
- `HashKnownHosts yes` (privacy)
- Matching modern algorithms (same as server)
- `StrictHostKeyChecking accept-new`
- Connection multiplexing (`ControlMaster auto`, `ControlPersist 10m`, `ControlPath ~/.ssh/sockets/%C`) in a `Match localuser <allowed user>` block. It applies only to the allowed user, the account whose `~/.ssh/sockets` directory the script creates; root and all other accounts keep plain connections

### 4. Legal Banner

Creates `/etc/issue.net` with an ASCII art banner and legal warning text.

### 5. Validation, Ordering and Rollback

The script is built so that a failure cannot cut off the session it runs in:

1. `sshd -t` validates the new configuration.
2. The firewall is opened for the configured port first: the managed block is written to `/etc/nftables.conf`, then the rules are added to the live ruleset.
3. sshd is reloaded, and the script waits until sshd listens on the configured port.
4. Only then are the rules of the previous port removed (the script's own rules and the SSH rule of the installer's base ruleset, in the file and live).

If any of steps 1-3 fails, or the script is interrupted before sshd has taken over the new configuration, `sshd_config`, `ssh_config`, the host keys and the firewall are restored to their previous state and the script exits non-zero.

### 6. Rate Limiting (nftables / iptables)

Adds per-source rate limiting for SSH: every source address may open 4 new connections per minute (burst 4); excess connections from that address are dropped, other addresses are not affected. Loopback is exempt. Prefers nftables and installs a validated managed block (`ssh-rate-limit`, with the dynamic sets `awesome_ssh_ratelimit4` / `awesome_ssh_ratelimit6`) in the `inet filter` table created by the base installation. On VPS kernels without `nf_tables`, an idempotent oneshot service restores only the script-owned iptables rules at boot instead of snapshotting transient rules from other software; it limits per source with `hashlimit` and covers IPv4 only.

The managed block can only be written to the installer-owned `/etc/nftables.conf` (the one that starts with `flush ruleset`). With any other ruleset that `nftables.service` loads, such as the one shipped by the Arch `nftables` package:

- the firewall is left untouched and no rate limit is installed (a warning says so);
- moving sshd to another port is refused before anything is changed, unless that ruleset already contains a rule naming the new port (`tcp dport <port> ...`). Open the port there, reload it, then re-run.

---

## What ssh_client.sh Does

1. Checks OpenSSH client version (requires 7.6+)
2. Generates an Ed25519 key pair if one doesn't exist
3. Optionally copies the public key to the server via `ssh-copy-id`
4. Writes a hardened `~/.ssh/config` with modern algorithms matching the server
5. Hashes `~/.ssh/known_hosts` for privacy
6. Sets correct permissions on all SSH files (700 for `.ssh/`, 600 for private key, 644 for public key)

---

## Customization

### Change the SSH Port

```bash
sudo ./ssh.sh -u myuser -p 2222
```

The port is applied to sshd_config and the firewall rules, in the order described in "Validation, Ordering and Rollback": the new port is opened before sshd is reloaded and the old one is closed only after sshd answers on the new one. Keep your current session open and test a second connection on the new port before you log out. A leading zero is ignored (`-p 02222` means 2222).

### Allow Multiple Users

Edit the generated `/etc/ssh/sshd_config` after running the script:

```
AllowUsers user1 user2
```

### Add TOTP Two-Factor Authentication

Use the companion `hardening/totp/totp.sh` script to add Google Authenticator (TOTP) as a second factor. Nothing has to be edited by hand: `totp.sh` validates a candidate configuration with `sshd -t` and `sshd -T` and then writes its three settings itself:

```
AuthenticationMethods publickey,keyboard-interactive
KbdInteractiveAuthentication yes
UsePAM yes
```

They go into `/etc/ssh/sshd_config.d/00-awesome-totp.conf` when the main `sshd_config` includes that directory, and into the main file otherwise.

**How `ssh.sh` and `totp.sh` work together.** The `sshd_config` generated by `ssh.sh` starts with

```
Include /etc/ssh/sshd_config.d/00-awesome-totp.conf
```

and sshd keeps the first value it reads for a keyword. The drop-in is therefore authoritative:

- While the drop-in exists, logins need the public key **and** a TOTP code, and re-running `ssh.sh` (for example to change the port) keeps it that way. The public-key-only lines further down in `sshd_config` are the fallback.
- Without the drop-in (it never existed, or it was removed to switch TOTP off for sshd) the public-key-only settings apply. A missing include file is not an error. The PAM side of TOTP belongs to `totp.sh`; see `hardening/totp/README.md`.
- It is the only drop-in that is read. Other files in `/etc/ssh/sshd_config.d/` (including Arch's `99-archlinux.conf`) are ignored once `ssh.sh` has run.
- The order of the two scripts does not matter. Running `totp.sh` after `ssh.sh` finds the `Include` and uses the drop-in.

`ssh.sh` prints a warning, before it rewrites `sshd_config` and again at the end, in the two cases where a run changes whether TOTP is required:

| Situation before the run | What the run does | What to do |
|---|---|---|
| TOTP settings were in the main `sshd_config` (no drop-in; set by hand or by `totp.sh` on a host without the `Include`) | Rewrites `sshd_config` with public key only: **TOTP is off** | Re-run `totp.sh`; it now writes the drop-in, which later `ssh.sh` runs keep |
| The drop-in exists but was not read (`sshd_config` written by an earlier version of `ssh.sh`) | Includes it again: **TOTP is required again** | Test a new login before closing the session; delete the drop-in and re-run `ssh.sh` to stay with public key only |

---

## Testing

After running the script:

1. **Verify sshd status:**
   ```bash
   systemctl status sshd
   ```

2. **Test connection from a remote machine:**
   ```bash
   ssh -p <port> <username>@<server_ip>
   ```

3. **Verify algorithms in use:**
   ```bash
   ssh -vvv -p <port> <username>@<server_ip> 2>&1 | grep "kex:"
   ```

4. **Check firewall rules:**
   ```bash
   sudo nft list ruleset          # nftables
   sudo iptables -L INPUT -n -v   # iptables fallback
   ```

5. **Audit with ssh-audit:**
   ```bash
   pacman -S ssh-audit
   ssh-audit localhost
   ```

---

## Important Notes

- **Backup access:** Ensure you have console or out-of-band access before applying. The script backs up the original config automatically.
- **Authorized keys:** Copy your public key to `~/.ssh/authorized_keys` on the server *before* running the script, as password authentication is disabled. The script refuses to run unless that file holds at least one key of a type the hardened sshd accepts: `ssh-ed25519`, `sk-ssh-ed25519@openssh.com`, `sk-ecdsa-sha2-nistp256@openssh.com` or `ssh-rsa`. Plain ECDSA (`ecdsa-sha2-*`) and DSA keys are not accepted by `PubkeyAcceptedAlgorithms`, so a file containing only those would lock you out. `-k` turns the refusal into a warning.
- **Host keys:** see "Host Key Generation" — keys change on the first run and with `-r` only.
- **Firewall persistence:** nftables rules persist in a marked block in `/etc/nftables.conf` (exempting loopback `lo`). The iptables fallback persists through `awesome-ssh-rate-limit.service` and `/usr/local/lib/awesomearchlinux/ssh-rate-limit.sh`.
- **Banner:** Modify `/etc/issue.net` to match your organization's legal requirements.

---

## References

- [OpenSSH upstream manual index](https://www.openssh.org/manual.html)
- [`sshd_config(5)`](https://man.openbsd.org/sshd_config)
- [`ssh_config(5)`](https://man.openbsd.org/ssh_config)
- [`ssh-keygen(1)`](https://man.openbsd.org/ssh-keygen)
- [OpenSSH security advisories](https://www.openssh.org/security.html)
- [OpenSSH — ArchWiki](https://wiki.archlinux.org/title/OpenSSH)
- [Fail2ban limitations and SSH guidance — ArchWiki](https://wiki.archlinux.org/title/Fail2ban)
