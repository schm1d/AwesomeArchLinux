# SSH Hardening

Hardens OpenSSH server and client configuration on Arch Linux. Regenerates host keys (Ed25519 + RSA 4096), enforces modern cryptographic algorithms, restricts access, and applies CIS Benchmark recommendations for SSH.

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
sudo ./ssh.sh -u <username> [-p <port>]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-u USER` | User to allow SSH access (required, must not be root) | `$SUDO_USER` if available |
| `-p PORT` | SSH listening port | 22 |
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

- Securely shreds all existing host keys
- Generates new Ed25519 and RSA 4096-bit host keys with empty passphrases
- Sets correct permissions (600 for private keys, 644 for public keys)

### 2. SSH Daemon Configuration (sshd_config)

Writes a complete hardened `sshd_config` (truncate, not append — avoids first-match-wins issues). Backs up the original before overwriting.

**Network:**
- Configurable port, IPv4 only (`AddressFamily inet`), `StrictModes yes`

**Cryptographic Algorithms (OpenSSH 9.x+ modern):**
- Host keys: `ssh-ed25519-cert-v01`, `ssh-ed25519`, `rsa-sha2-512`, `rsa-sha2-256`
- KEX: `sntrup761x25519-sha512` (post-quantum), `curve25519-sha256`, `diffie-hellman-group18-sha512`, `diffie-hellman-group16-sha512`
- Ciphers: `chacha20-poly1305`, `aes256-gcm`, `aes128-gcm` (AEAD only)
- MACs: `hmac-sha2-512-etm`, `hmac-sha2-256-etm`, `umac-128-etm` (ETM only)

**Authentication:**
- Public key only (`AuthenticationMethods publickey`)
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
- Connection multiplexing (`ControlMaster auto`, `ControlPersist 10m`)

### 4. Legal Banner

Creates `/etc/issue.net` with an ASCII art banner and legal warning text.

### 5. Configuration Validation

Runs `sshd -t` to validate the configuration before restarting. On failure, automatically rolls back to the backed-up config.

### 6. Rate Limiting (nftables / iptables)

Adds rate limiting for SSH: allows up to 4 new connections per minute, dropping excess. Prefers nftables (integrates with the `inet filter` table created by the base installation). Falls back to iptables automatically on VPS kernels that lack the `nf_tables` module.

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

The port is applied to sshd_config, nftables rules, and the banner.

### Allow Multiple Users

Edit the generated `/etc/ssh/sshd_config` after running the script:

```
AllowUsers user1 user2
```

### Add TOTP Two-Factor Authentication

Use the companion `hardening/totp/totp.sh` script to add Google Authenticator (TOTP) as a second factor. After setup, update `AuthenticationMethods` in sshd_config:

```
AuthenticationMethods publickey,keyboard-interactive
```

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
- **Authorized keys:** Copy your public key to `~/.ssh/authorized_keys` on the server *before* disconnecting, as password authentication is disabled.
- **Firewall persistence:** nftables rules persist via `/etc/nftables.conf` and `nftables.service`. If the iptables fallback is used, rules are saved to `/etc/iptables/iptables.rules` with `iptables.service` enabled.
- **Banner:** Modify `/etc/issue.net` to match your organization's legal requirements.
