# TOTP Two-Factor Authentication for SSH

Hardens SSH access on Arch Linux by requiring both a public key **and** a time-based one-time password (TOTP) for every login.

## Quick Start

```bash
sudo ./totp.sh              # Configure TOTP for current user
sudo ./totp.sh -u alice     # Configure TOTP for a specific user
sudo ./totp.sh -h           # Show help
```

## Prerequisites

- Arch Linux with `pacman`
- Root privileges (run with `sudo`)
- SSH server (`sshd`) installed and running
- Public key authentication already configured for the target user

## What the Script Does

1. Installs `libpam_google_authenticator` and `qrencode` via pacman
2. Configures PAM (`/etc/pam.d/sshd`) to use the Google Authenticator module
3. Configures sshd to require `publickey,keyboard-interactive` authentication
4. Generates a TOTP secret and displays a QR code in the terminal
5. Sets secure permissions (600) on the secret file
6. Restarts sshd
7. Displays emergency scratch codes

## Setting Up TOTP on Your Phone

When the script runs, it displays a QR code in your terminal. Scan it with any TOTP-compatible authenticator app:

| App | Platform | Notes |
|-----|----------|-------|
| **Aegis Authenticator** | Android | Free, open source, encrypted backups. Recommended. |
| **Google Authenticator** | Android, iOS | Simple, widely used. No cloud backup. |
| **Authy** | Android, iOS, Desktop | Cloud-synced, multi-device support. |
| **FreeOTP+** | Android, iOS | Free, open source (Red Hat). |
| **KeePassXC** | Linux, macOS, Windows | Desktop password manager with TOTP support. |
| **Bitwarden** | All platforms | Password manager with TOTP (premium feature). |

### Manual Entry

If you cannot scan the QR code, the script also outputs a secret key (base32 string). In your authenticator app, choose "Enter manually" or "Enter a setup key" and provide:

- **Account name**: your SSH username
- **Secret key**: the base32 string from the script output
- **Type**: Time-based (TOTP)
- **Digits**: 6
- **Period**: 30 seconds

## How Authentication Works After Setup

```
1. Client connects via SSH
2. Server verifies the client's public key
3. Server prompts: "Verification code: "
4. User enters the 6-digit code from their authenticator app
5. Access granted (or denied)
```

The `AuthenticationMethods publickey,keyboard-interactive` directive requires **both** factors to succeed. A valid key alone is not sufficient; a valid TOTP code alone is not sufficient.

## Enabling Mandatory 2FA

By default, the script uses the `nullok` option, which allows users who have **not** yet set up TOTP to still log in with just their public key. This gives you time to onboard all users.

To enforce mandatory 2FA for all users:

```bash
# Edit the PAM configuration
sudo nano /etc/pam.d/sshd

# Find this line:
auth required pam_google_authenticator.so nullok secret=${HOME}/.google_authenticator

# Remove 'nullok':
auth required pam_google_authenticator.so secret=${HOME}/.google_authenticator

# Restart sshd
sudo systemctl restart sshd
```

**WARNING**: Before removing `nullok`, ensure every user who needs SSH access has run `google-authenticator` and configured their app. Otherwise they will be locked out.

## Adding TOTP for Additional Users

Run the script again with the `-u` flag:

```bash
sudo ./totp.sh -u bob
sudo ./totp.sh -u charlie
```

Each user gets their own secret stored at `~/.google_authenticator`.

Alternatively, a user can set up TOTP manually (without the script):

```bash
# As the target user (not root)
google-authenticator -t -d -r 3 -R 30 -w 3 -f -Q UTF8
```

The user must scan the QR code and save the emergency scratch codes. Permissions on `~/.google_authenticator` must be `600`.

## Troubleshooting

### "Permission denied" after entering the correct TOTP code

- Verify `~/.google_authenticator` exists and is owned by the correct user:
  ```bash
  ls -la ~/.google_authenticator
  # Should show: -rw------- 1 username username ...
  ```
- Fix permissions if needed:
  ```bash
  chmod 600 ~/.google_authenticator
  chown username:username ~/.google_authenticator
  ```

### "Permission denied" immediately (no TOTP prompt)

- The public key authentication failed first. Verify your SSH key:
  ```bash
  ssh -vvv user@server
  ```
- Check that `PubkeyAuthentication yes` is set in `/etc/ssh/sshd_config`.
- Ensure your public key is in `~/.ssh/authorized_keys`.

### TOTP code is always rejected (time skew)

- Ensure the server clock is accurate:
  ```bash
  timedatectl status
  # If NTP is not active:
  sudo timedatectl set-ntp true
  ```
- Ensure your phone's time is set to automatic/network time.
- The script uses `-w 3` which allows a window of +/- 1 time step (30 seconds) to account for minor clock drift.

### Locked out completely

- Access the server via physical console, IPMI/iLO, or cloud provider console.
- Restore the backup configs:
  ```bash
  # List backups
  ls /etc/ssh/sshd_config.bak.*
  ls /etc/pam.d/sshd.bak.*

  # Restore
  sudo cp /etc/ssh/sshd_config.bak.YYYYMMDD-HHMMSS /etc/ssh/sshd_config
  sudo cp /etc/pam.d/sshd.bak.YYYYMMDD-HHMMSS /etc/pam.d/sshd
  sudo systemctl restart sshd
  ```
- Alternatively, use an emergency scratch code (each can only be used once).

### sshd fails to start after running the script

- Check the configuration:
  ```bash
  sudo sshd -t
  ```
- Review the log:
  ```bash
  sudo journalctl -u sshd -e
  ```
- Restore from backup as described above.

### Google Authenticator prompts twice

- Check `/etc/pam.d/sshd` for duplicate `pam_google_authenticator` lines:
  ```bash
  grep pam_google_authenticator /etc/pam.d/sshd
  ```
- Remove any duplicates and restart sshd.

### Want to reset TOTP for a user

```bash
# Delete the existing secret
sudo rm /home/username/.google_authenticator

# Re-run the setup
sudo ./totp.sh -u username
```

## Security Notes

- **Secret file**: `~/.google_authenticator` contains the TOTP seed. Protect it like a private key.
- **Scratch codes**: The 5 emergency scratch codes are single-use. Store them offline in a secure location (printed paper, encrypted vault).
- **Rate limiting**: The script configures 3 attempts per 30 seconds to prevent brute-force attacks on the TOTP code.
- **Reuse prevention**: Token reuse is disabled (`-d`). Each 6-digit code can only be used once per 30-second window.
- **Backup**: The script creates timestamped backups of both `/etc/ssh/sshd_config` and `/etc/pam.d/sshd` before making changes.

## Files Modified

| File | Change |
|------|--------|
| `/etc/pam.d/sshd` | Added `pam_google_authenticator.so` auth line |
| `/etc/ssh/sshd_config` | Set `ChallengeResponseAuthentication yes`, `AuthenticationMethods publickey,keyboard-interactive`, `KbdInteractiveAuthentication yes`, `UsePAM yes` |
| `~/.google_authenticator` | Created (TOTP secret, scratch codes, config) |

## References

- [Arch Wiki: Google Authenticator](https://wiki.archlinux.org/title/Google_Authenticator)
- [google-authenticator-libpam (GitHub)](https://github.com/google/google-authenticator-libpam)
- [RFC 6238: TOTP](https://datatracker.ietf.org/doc/html/rfc6238)
- [OpenSSH AuthenticationMethods](https://man.openbsd.org/sshd_config#AuthenticationMethods)
