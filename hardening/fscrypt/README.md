# fscrypt — per-user ext4 home directory encryption

Standalone hardening module that sets up **ext4 native filesystem encryption**
(`fscrypt` + `pam_fscrypt`) to protect individual users' home directories at
rest. After setup, a user's home is encrypted while they are logged out —
even root sees only encrypted filenames and ciphertext. When the user logs
in, PAM transparently unlocks their home using their login password.

This module is **opt-in** and is intentionally **not** run by the base
installer.

---

## What it protects against (threat model)

This complements — it does **not** replace — LUKS full-disk encryption.

| Attacker scenario                                         | LUKS FDE | fscrypt (this module) |
|-----------------------------------------------------------|:--------:|:---------------------:|
| Laptop stolen while powered OFF                           | Yes      | Yes                   |
| Laptop stolen while powered ON / suspended                | No       | Partial (only logged-out users) |
| Malicious local user reading another user's files         | No       | **Yes**               |
| Malicious / compromised **root** reading a logged-out user's files | No | **Yes** (filenames + contents both encrypted) |
| Cold-boot / DMA attack on a running system                | No       | No                    |
| Backup tapes / disk images from a stolen decommissioned disk | Yes   | Yes                   |

The key practical win: on a **multi-user** or **shared-admin** machine,
fscrypt means that when Alice is not logged in, neither Bob nor the admin
can read `/home/alice`. LUKS alone cannot give you this — once the LUKS
container is unlocked (i.e. the system is booted), LUKS is transparent to
any process running as root.

### What it does NOT protect against

- **Anything while the user is logged in.** The key is in the kernel keyring
  and root can trivially extract it. fscrypt is an at-rest protection for
  logged-out users, not a runtime sandbox.
- **Memory / cold-boot attacks** against a running box.
- **Kernel exploits** that bypass the keyring isolation.
- **Swap leaks.** Ensure swap is on LUKS (the base installer does this) or
  encrypted with a random key, otherwise paged-out plaintext ends up on disk.
- **`/tmp`, `/var/tmp`, journald logs, caches outside `$HOME`.** Only the
  home directory itself is encrypted. Applications that store user data
  elsewhere leak plaintext.
- **Filename length / metadata sidechannels.** fscrypt encrypts filenames
  but file sizes, timestamps, and directory layout are still visible.

### Why this is opt-in, not default

- On a single-user laptop with LUKS, fscrypt adds little — both layers
  protect the same scenario (powered-off theft). The complexity is not
  worth it.
- On multi-user or shared-admin systems, the marginal protection (users
  from each other, users from logged-out-root) is real and valuable.
- Home encryption interacts badly with some login managers, with NFS/CIFS
  home mounts, and with backup tools that don't understand unlocked policies.
  You should be deliberate about turning it on.

---

## Prerequisites

- **Arch Linux** (uses pacman, `/etc/pam.d/system-login`, `/usr/lib/security/`).
- **Root privileges.**
- **ext4 root filesystem** with the `encrypt` feature enabled.

Verify current state:

```bash
sudo ./fscrypt.sh --status
```

### Enabling the ext4 `encrypt` feature

This must be done **offline** — the filesystem cannot be mounted:

1. Boot from an Arch ISO / rescue environment.
2. (Optional but recommended) `e2fsck -f /dev/<root-device>`
3. `tune2fs -O encrypt /dev/<root-device>`
4. Reboot.
5. `sudo ./fscrypt.sh --setup`

If your root lives on LUKS + LVM, the device is something like
`/dev/mapper/vg-root`. `findmnt -n -o SOURCE /` prints the right path; the
script shows it in `--status`.

---

## Usage

```
sudo ./fscrypt.sh [--setup] [--encrypt-user USER] [--status] [--uninstall] [-h]
```

### `--setup` (default)

One-time system-wide setup:

1. Verifies root is ext4.
2. Verifies the `encrypt` feature is enabled on the root device; if not,
   prints the exact `tune2fs` command you need to run from rescue and
   exits without half-configuring.
3. Installs `fscrypt` via pacman.
4. Runs `fscrypt setup` to create `/etc/fscrypt.conf` and metadata.
5. Wires `pam_fscrypt.so` into `/etc/pam.d/system-login` (auth + session)
   and `/etc/pam.d/passwd` (password). Each file is backed up first to
   `<file>.bak.<epoch>`; lines are only appended if not already present.

```bash
sudo ./fscrypt.sh --setup
```

### `--encrypt-user USER`

Encrypt an **existing** user's home:

```bash
sudo ./fscrypt.sh --encrypt-user alice
```

What happens:

1. Active sessions for `alice` are terminated (`loginctl terminate-user`).
2. `/home/alice` is **moved aside** to `/home/alice.pre-encrypt` — nothing
   is deleted.
3. A fresh empty `/home/alice` is created (mode 700, owner `alice`).
4. `fscrypt encrypt` is run **as `alice`** with `--source=pam_passphrase`
   so the protector is her login password. She is prompted for that
   password interactively by fscrypt.
5. A recovery notes file is written to
   `/root/fscrypt-recovery-alice.txt` (mode 600). **See the "Recovery
   keys" section below** — this script does NOT generate a fully
   automated recovery passphrase; instructions are provided to add one
   manually.

After the script completes, `alice` must:

```bash
# Log out of any remaining shells. Then log in at the console / DM —
# pam_fscrypt will unlock /home/alice automatically.
cp -a /home/alice.pre-encrypt/. /home/alice/
# Verify everything is there, then:
sudo rm -rf /home/alice.pre-encrypt
```

The old unencrypted copy is **deliberately not deleted** so there is a
rollback path if anything goes wrong.

### `--status`

Prints the current state: root device, FS type, encrypt feature, whether
the `fscrypt` package is installed, `/etc/fscrypt.conf` presence, PAM
wiring status, and `fscrypt status /` output (lists policies and protectors).

```bash
sudo ./fscrypt.sh --status
```

### `--uninstall`

Removes the `pam_fscrypt.so` lines this script added to
`/etc/pam.d/system-login` and `/etc/pam.d/passwd`. Backups are created
first.

```bash
sudo ./fscrypt.sh --uninstall
```

**This does NOT decrypt any user's home directory.** Decryption requires
the user's login passphrase (or their recovery protector) and must be
done interactively as that user. See the uninstall output for the manual
per-user steps and the optional full dismantling (`pacman -R fscrypt`,
removing `/etc/fscrypt.conf` and `/.fscrypt`).

---

## Recovery keys

`fscrypt`'s first-class CLI for creating a secondary "recovery"
passphrase has shifted between releases. Rather than bake a fragile
incantation into the script, we take the conservative approach:

- The script sets up the **login-password protector** via `pam_fscrypt`
  — this is the day-to-day unlock mechanism.
- It writes `/root/fscrypt-recovery-<user>.txt` (mode 600) with a
  placeholder and the exact manual commands needed to add a second
  protector.

### Adding a recovery protector manually

As root, with the user logged in (so the policy is unlocked):

```bash
# 1. Create a new protector backed by a custom passphrase. fscrypt will
#    prompt you for that passphrase — choose a long random one and store
#    it in a password manager.
fscrypt metadata create protector --source=custom_passphrase \
    --name=alice-recovery /

# fscrypt prints a protector descriptor, e.g. a 16-char hex string.
# Note it down as PROTECTOR_ID.

# 2. Find the policy descriptor for /home/alice:
fscrypt status /home/alice
# -> "Policy: 0123456789abcdef ..."

# 3. Attach the new protector to that policy:
fscrypt metadata add-protector-to-policy \
    --protector=/:PROTECTOR_ID \
    --policy=/:POLICY_ID
```

After this, either the login password **or** the recovery passphrase can
unlock the home. If Alice forgets her login password, run
`fscrypt unlock /home/alice` and use the recovery passphrase.

Flag names (`add-protector-to-policy` vs. `--unlock-with`) have moved
between fscrypt releases; check `fscrypt metadata --help` on your system.

---

## Backups

- **The only time you can back up `/home/alice` in plaintext is while
  Alice is logged in** (or while you have explicitly run
  `fscrypt unlock /home/alice` with her passphrase).
- Backups taken while she is logged out contain only ciphertext and
  encrypted filenames. Those backups are safe to store off-box but can
  only be restored to a system that has her protector.
- Running backup tools as root from a cron job will silently back up
  ciphertext if the user isn't logged in at that moment. Consider either:
  - Running backups from a systemd user service, or
  - Explicitly unlocking the policy before the backup and locking it again after.

---

## Rolling back / uninstalling

1. `sudo ./fscrypt.sh --uninstall` — removes PAM wiring.
2. For each encrypted user, **as that user**, back up their data and then
   decrypt:

   ```bash
   # as the user, after logging in so the policy is unlocked:
   cp -a ~ /tmp/alice-backup
   # then, as root, replace the encrypted home with a fresh one:
   sudo loginctl terminate-user alice
   sudo rm -rf /home/alice                # encrypted data gone
   sudo install -d -m 700 -o alice -g alice /home/alice
   sudo cp -a /tmp/alice-backup/. /home/alice/
   sudo chown -R alice:alice /home/alice
   ```

3. Optional full removal:

   ```bash
   sudo pacman -R fscrypt
   sudo rm -rf /etc/fscrypt.conf /.fscrypt
   ```

4. Restart anything still holding PAM in memory:

   ```bash
   sudo systemctl restart sshd
   # reboot for display managers
   ```

The `encrypt` ext4 feature itself stays enabled (there is no in-place
`tune2fs -O ^encrypt` once it has been used). This is harmless.

---

## Known issues and caveats

- **Login managers:** `pam_fscrypt` is well-tested with `login` (console),
  `sshd`, and `lightdm`. `sddm` and `gdm` have historically needed care
  around the session stack. Test your target DM before rolling out
  broadly.
- **NFS / CIFS home directories:** **Not supported.** fscrypt is an ext4
  kernel feature; network-mounted homes cannot be fscrypt-encrypted from
  the client.
- **`/tmp`, `/var/tmp`, `/run/user/<uid>`:** Not encrypted by fscrypt.
  `systemd-tmpfiles` entries for user runtime dirs are not touched by
  this module. Any app that writes sensitive data outside `$HOME` will
  leak plaintext.
- **Root reflinks / snapshots:** If you back up with `cp --reflink` or
  use filesystem-level snapshots that predate the encryption, those older
  copies remain plaintext until explicitly purged.
- **Swap:** Make sure swap is encrypted (LUKS or random-key dm-crypt).
  Otherwise pages from the unlocked home can be written out in plaintext.
- **Hibernation:** Hibernation writes the full RAM image — including the
  fscrypt master keys — to the swap device. Encrypted swap is mandatory
  if you hibernate.
- **Password changes via `passwd`:** Handled — we wire `pam_fscrypt` into
  `/etc/pam.d/passwd` so the protector is re-wrapped when the login
  password changes. If you change the password by other means (e.g.
  editing `/etc/shadow` directly), the user loses access to their home.
- **`useradd` does not auto-encrypt.** New users are created with
  plaintext homes; run `--encrypt-user` for each new account that needs
  it, before they put any data in `$HOME`.

---

## Files this module touches

- Installs: `fscrypt` package (provides `/usr/bin/fscrypt`,
  `/usr/lib/security/pam_fscrypt.so`).
- Creates: `/etc/fscrypt.conf`, `/.fscrypt/` metadata directory.
- Edits (with timestamped `.bak.<epoch>` backups, idempotent line append):
  - `/etc/pam.d/system-login`
  - `/etc/pam.d/passwd`
- Writes (mode 600): `/root/fscrypt-recovery-<user>.txt` per encrypted user.
- Moves aside (per user, never deletes): `/home/<user>` -> `/home/<user>.pre-encrypt`.

Nothing outside `hardening/fscrypt/` in this repo is affected. The base
installer (`base/archinstall.sh`, `base/chroot.sh`) is unchanged — this
module is strictly opt-in.
