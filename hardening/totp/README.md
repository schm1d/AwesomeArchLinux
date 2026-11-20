# TOTP Two-Factor Authentication for SSH

Hardens SSH access on Arch Linux by requiring both a public key **and** a time-based one-time password (TOTP) for every login.

## Quick Start

```bash
sudo ./totp.sh              # Configure TOTP for current user (SSH key + TOTP)
sudo ./totp.sh -u alice     # Configure TOTP for a specific user
sudo ./totp.sh -u alice --allow-missing-totp  # Explicit staged rollout
sudo ./totp.sh -u alice --allow-no-ssh-key    # Override missing ~/.ssh/authorized_keys check
sudo ./totp.sh -u alice --require-password    # Require SSH key + Linux password + TOTP
sudo ./totp.sh -u alice --rotate              # Replace alice's existing secret and scratch codes
sudo ./totp.sh -h           # Show help
```

The flags describe the state you want **after this run**. `/etc/pam.d/sshd` is brought to that state on every run, whatever an earlier run left behind: a run without `--allow-missing-totp` makes TOTP mandatory, a run without `--require-password` disables the password prompt again. Repeat the flags you still want on every run.

## Prerequisites

- Arch Linux with `pacman`
- Root privileges (run with `sudo`)
- SSH server (`sshd`) installed (`openssh`)
- Non-empty `~/.ssh/authorized_keys` configured for the target user (enforced before modifying PAM or `sshd` unless `--allow-no-ssh-key` is explicitly passed)
- An `sshd` configuration in which the three required settings can take effect for the target user. Both layouts used in this repository work:
  - **stock Arch** (`/etc/ssh/sshd_config` starts with `Include /etc/ssh/sshd_config.d/*.conf`, and the `openssh` package ships `99-archlinux.conf` with `KbdInteractiveAuthentication no`): the settings are written to a drop-in that is read first
  - **after `hardening/ssh/ssh.sh`**: the generated main file starts with `Include /etc/ssh/sshd_config.d/00-awesome-totp.conf`, so the settings are written to that drop-in and survive later runs of `ssh.sh` (the order in which the two scripts are run does not matter). A main file written by an older `ssh.sh`, which has no `Include`, gets the settings in the main file instead; the next `ssh.sh` run then rewrites that file, warns, and asks you to run `totp.sh` again

  If something else would still override them (for example a `Match` block that sets `AuthenticationMethods` for the user, or a drop-in that sorts before `00-awesome-totp.conf`), the script stops before changing anything and names the file and the overriding line. The check asks `sshd -T` for the settings of the target user connecting from localhost; `Match` blocks that only apply to other users, addresses or ports are not examined.

## What the Script Does

1. Runs lockout preflight checks (`sshd` binary, `/etc/ssh/sshd_config`, `/etc/pam.d/sshd`, non-empty `~/.ssh/authorized_keys`, and `AllowUsers` membership) before installing packages or touching configuration
2. Builds a **candidate** `sshd` configuration in a root-private temporary directory and checks it with `sshd -t` and `sshd -T` (effective `AuthenticationMethods`, `KbdInteractiveAuthentication` and `UsePAM` for the target user). If no candidate gives the required result, it exits with nothing changed
3. Installs `libpam-google-authenticator` and `qrencode` via pacman
4. Generates a TOTP secret as the target user via `runuser` and displays a QR code in the terminal. A user who already has a secret keeps it (pass `--rotate` to replace it). Mode `600` and ownership of `~/.google_authenticator` are checked as the user, **before** modifying PAM or `sshd`
5. Configures PAM (`/etc/pam.d/sshd`) to require the Google Authenticator module and comments out `auth include system-remote-login` (unless `--require-password` is passed) so passwordless SSH-key accounts are prompted only for TOTP
6. Configures `sshd` to require `publickey,keyboard-interactive` authentication: through `/etc/ssh/sshd_config.d/00-awesome-totp.conf` when the main file includes that directory, otherwise in `/etc/ssh/sshd_config` itself (inserting directives safely **before** any `Match` blocks)
7. Validates the live configuration again (`sshd -t`, `sshd -T`) and reloads `sshd` without dropping existing sessions when `sshd.service` is active
8. Displays single-use emergency scratch codes

Steps 5 to 7 are transactional: if anything fails or the script is interrupted (Ctrl-C, a dropped SSH session, a failed `systemctl reload sshd`) before step 7 has completed, `/etc/pam.d/sshd` and the `sshd` files are restored to what they were before the run, a drop-in created by the run is removed, and `sshd` is reloaded with the restored files if it had already been reloaded.

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

## Mandatory 2FA and staged rollouts

Mandatory TOTP is the default. The script creates and verifies the target user's secret before changing PAM, installs a rule without `nullok`, validates sshd, and reloads it without terminating existing sessions. Every SSH user without a secret is then denied.

For a deliberate multi-user rollout, pass `--allow-missing-totp`:

```bash
sudo ./totp.sh -u alice --allow-missing-totp   # start the rollout
sudo ./totp.sh -u bob --allow-missing-totp     # enrol further users, still staged
sudo ./totp.sh -u alice                        # finish: TOTP mandatory for everyone
```

In staged mode the PAM auth stack for `sshd` is:

```
auth required pam_google_authenticator.so nullok secret=${HOME}/.google_authenticator
auth required pam_permit.so # added by totp.sh (staged rollout: ...)
```

- With `nullok` the module returns "ignore" for a user without a secret. A PAM stack in which no module succeeds is denied, so `nullok` alone would lock out exactly the users the rollout is meant to spare. The marked `pam_permit.so` line supplies the success; users without a secret then log in with their key alone.
- A user who **has** a secret must still enter a valid code: the TOTP rule is `required`, so a wrong code fails the stack whatever follows it.
- With `--require-password --allow-missing-totp` no `pam_permit.so` line is added. The password stack (`system-remote-login`) decides for users without a secret.
- Pass `--allow-missing-totp` on **every** run while the rollout lasts. The first run without it removes `nullok` and the marked `pam_permit.so` line again and restores fail-closed enforcement.
- Re-running the script for a user who already has a secret does not generate a new one, so finishing the rollout leaves every authenticator app and scratch code valid.

## Adding TOTP for Additional Users

Run the script again with the `-u` flag (plus the same policy flags as before, see above):

```bash
sudo ./totp.sh -u bob
sudo ./totp.sh -u charlie
```

Each user gets their own secret stored at `~/.google_authenticator`. An existing secret is never replaced unless `--rotate` is passed.

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
- Undo the run. The end of the script output (and `/var/log/totp-setup-*.log`) names the exact files:
  ```bash
  # PAM: always backed up
  ls /etc/pam.d/sshd.bak.*
  sudo cp /etc/pam.d/sshd.bak.YYYYMMDD-HHMMSS /etc/pam.d/sshd

  # sshd, stock Arch layout: the settings live in a drop-in, remove it
  sudo rm /etc/ssh/sshd_config.d/00-awesome-totp.conf

  # sshd, main file edited (no Include): restore the backup
  ls /etc/ssh/sshd_config.bak.*
  sudo cp /etc/ssh/sshd_config.bak.YYYYMMDD-HHMMSS /etc/ssh/sshd_config

  sudo sshd -t && sudo systemctl restart sshd
  ```
- Alternatively, use an emergency scratch code (each can only be used once).

### The script stops with "sshd cannot be made to require publickey + TOTP"

Nothing was changed. The candidate configuration did not give the required effective settings; the message lists the lines that override them. Typical causes:

- a `Match` block that sets `AuthenticationMethods` or `KbdInteractiveAuthentication` for the target user
- a drop-in in `/etc/ssh/sshd_config.d/` that sorts before `00-awesome-totp.conf` and sets one of the three keywords
- an `Include` pattern that does not match `00-awesome-totp.conf` while another included file sets `KbdInteractiveAuthentication no`

Remove or adjust the override and run the script again.

### The script reports "Setup did not complete. Restoring ..."

A step failed after PAM or `sshd` had been changed, and the previous files were put back. Read the error printed just before that message, fix the cause, and re-run. If it says `AUTOMATIC RESTORE FAILED`, do not close your session: the previous files are kept in the directory named in the message and must be copied back by hand.

### sshd fails to start after running the script

- Check the configuration:
  ```bash
  sudo sshd -t
  ```
- Review the log:
  ```bash
  sudo journalctl -u sshd -e
  ```
- Undo the run as described above.

### Google Authenticator prompts twice

- Check `/etc/pam.d/sshd` for duplicate `pam_google_authenticator` lines:
  ```bash
  grep pam_google_authenticator /etc/pam.d/sshd
  ```
- Remove any duplicates and reload `sshd` (`sudo systemctl reload sshd`).

### Want to reset TOTP for a user

```bash
# Generate a new secret and new scratch codes (the old ones stop working)
sudo ./totp.sh -u username --rotate
```

Without `--rotate` the script keeps an existing secret, so a plain re-run never invalidates an enrolled authenticator app. Repeat the policy flags (`--allow-missing-totp`, `--require-password`) you are using.

## Security Notes

- **Secret file**: `~/.google_authenticator` contains the TOTP seed. Protect it like a private key.
- **Scratch codes**: The 5 emergency scratch codes are single-use. Store them offline in a secure location (printed paper, encrypted vault).
- **Rate limiting**: The script configures 3 attempts per 30 seconds to prevent brute-force attacks on the TOTP code.
- **Reuse prevention**: Token reuse is disabled (`-d`). Each 6-digit code can only be used once per 30-second window.
- **Home directory**: the script checks and fixes `~/.google_authenticator` as the target user (`runuser`), never as root, so a symlink placed there cannot redirect a root `chmod`/`chown`.
- **Staged rollout**: with `--allow-missing-totp`, a user without a secret (or who deletes it) logs in with the key alone. End the rollout as soon as every user is enrolled.
- **Backup and rollback**: `/etc/pam.d/sshd` (and `/etc/ssh/sshd_config`, when it is edited) get a timestamped backup before they are replaced. Until the final reload has succeeded, any failure or interruption restores the previous files automatically.

## Files Modified

| File | Change |
|------|--------|
| `/etc/pam.d/sshd` | Added `pam_google_authenticator.so` auth line; commented `auth include system-remote-login` unless `--require-password`; with `--allow-missing-totp` (and no `--require-password`) a marked `auth required pam_permit.so` line after it. Backup: `/etc/pam.d/sshd.bak.YYYYMMDD-HHMMSS` |
| `/etc/ssh/sshd_config.d/00-awesome-totp.conf` | **Stock Arch layout** (main file includes `/etc/ssh/sshd_config.d/*.conf` before any `Match` block) **and the layout written by the current `hardening/ssh/ssh.sh`** (main file includes this one file first): created, mode `600`, with `AuthenticationMethods publickey,keyboard-interactive`, `KbdInteractiveAuthentication yes`, `UsePAM yes`. It sorts before `99-archlinux.conf`, whose `KbdInteractiveAuthentication no` would otherwise win. `/etc/ssh/sshd_config` is not modified |
| `/etc/ssh/sshd_config` | **No such `Include`** (for example a file written by an older `hardening/ssh/ssh.sh`), or when the drop-in could not win: the same three settings are set here, before any `Match` block. Backup: `/etc/ssh/sshd_config.bak.YYYYMMDD-HHMMSS` |
| `~/.google_authenticator` | Created if the user has no secret, or replaced with `--rotate` (TOTP secret, scratch codes, config); otherwise left as it is |
| `/var/log/totp-setup-*.log` | Run log (mode `600`); QR code and scratch codes are not written to it |

All `/etc` changes of a run are applied together or not at all: on a failure before the final `sshd` reload has succeeded, the files above under `/etc` are restored and a drop-in created by the run is removed. Timestamped backups are kept either way.

## References

- [Arch Wiki: Google Authenticator](https://wiki.archlinux.org/title/Google_Authenticator)
- [google-authenticator-libpam (GitHub)](https://github.com/google/google-authenticator-libpam)
- [RFC 6238: TOTP](https://datatracker.ietf.org/doc/html/rfc6238)
- [OpenSSH AuthenticationMethods](https://man.openbsd.org/sshd_config#AuthenticationMethods)
