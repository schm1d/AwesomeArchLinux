# Hardware Security Keys (FIDO2 / U2F)

Phishing-resistant second factor for **local login** (and optionally sudo) using `pam_u2f`. SSH uses OpenSSH native `ed25519-sk` keys instead of stacking another PAM factor onto the existing TOTP path.

## Quick Start

```bash
sudo ./u2f.sh --enroll                 # Enroll the current sudo user
sudo ./u2f.sh --enroll -u alice        # Enroll a specific user
sudo ./u2f.sh --enroll --sudo          # Also require the key for sudo
sudo ./u2f.sh --status
```

Plug the authenticator in first. Touch it when it blinks. Enroll a **second** key immediately; a single token is not a backup.

## What the Script Does

1. Installs `pam-u2f`, `libfido2`, `pcsclite`, and `ccid`, and starts `pcscd`
2. Enrolls the token with `pamu2fcfg` into `/etc/u2f_mappings`
3. Inserts `pam_u2f` at the top of local login stacks (`system-local-login`, `login`, GDM/SDDM/LightDM when present)
4. Optionally wires `/etc/pam.d/sudo`
5. Refuses to touch `sshd` PAM when TOTP is already configured

## Why not pam_u2f on SSH?

`hardening/totp/totp.sh` already sets `AuthenticationMethods publickey,keyboard-interactive`. Adding `pam_u2f` on that same keyboard-interactive stack means every SSH login needs **key + TOTP + hardware token**. Lose any one factor and you are locked out of a remote box.

OpenSSH FIDO2 keys bind the signature to the origin and stay inside `PubkeyAuthentication`:

```bash
ssh-keygen -t ed25519-sk -O resident -O verify-required -f ~/.ssh/id_ed25519_sk
```

That is the phishing-resistant SSH path. TOTP remains useful as a software backup factor on hosts that cannot require a physical key for every operator.

## Gotchas

- **Lockout.** `--sudo` without a spare key and an open root session will strand you. The script never writes sshd PAM for this reason.
- **`nouserok`.** `--allow-missing` lets unmapped users skip the key. That is a staged rollout, not a hardened end state.
- **Origin.** Mappings are bound to `pam://<short-hostname>`. Renaming the host breaks existing mappings; re-enroll.
- **PIN.** FIDO2 tokens with a PIN will prompt for it. Empty PIN + stolen key is just a second password sitting on a USB stick.
- **NFC / older U2F.** If `fido2-token -L` is empty, the key is not talking to the host (cable, udev, or `pcscd`).
- **USBGuard.** If USBGuard is already enforcing, allow the authenticator before enrollment.

## Files Modified

| File | Change |
|------|--------|
| `/etc/u2f_mappings` | Central user→key mapping (mode 644) |
| `/etc/pam.d/system-local-login` | `auth required pam_u2f.so cue origin=...` |
| `/etc/pam.d/login`, `gdm-password`, `sddm`, `lightdm` | Same line, when the file exists |
| `/etc/pam.d/sudo` | Only with `--sudo` |

Timestamped `*.bak.*` copies are written next to every edited PAM file.

## Recovery

```bash
ls /etc/pam.d/*.bak.*
sudo cp /etc/pam.d/system-local-login.bak.YYYYMMDD-HHMMSS /etc/pam.d/system-local-login
```

## References

- [ArchWiki: Universal 2nd Factor](https://wiki.archlinux.org/title/Universal_2nd_Factor)
- [Yubico pam-u2f](https://developers.yubico.com/pam-u2f/)
- [OpenSSH security keys](https://man.openbsd.org/ssh-keygen#FIDO_AUTHENTICATOR)
