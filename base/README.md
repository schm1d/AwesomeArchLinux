# Base Installation Scripts

Core scripts for installing and configuring a security-hardened Arch Linux system. Two installation paths are provided: **bare-metal** (full disk encryption with `grub` or signed `uki` boot profiles) and **VPS/cloud** (simplified partitioning with BIOS or UEFI GRUB).

---

## Scripts Overview

| Script | Purpose |
|--------|---------|
| `archinstall.sh` | Bare-metal installer — LVM on LUKS2, UEFI, `grub` or `uki` boot profile, optional TPM2 |
| `bootloader.sh` | Shared bootloader, initramfs, `sbctl`, and `awesome-secureboot` helper library sourced by `chroot.sh` |
| `chroot.sh` | Bare-metal post-install — system hardening, GPU drivers, and bootloader setup inside chroot |
| `vps-install.sh` | VPS/cloud installer — EFI or BIOS boot partition + ext4 root, swap file, BIOS/UEFI GRUB |
| `vps-chroot.sh` | VPS post-install — software and service hardening adapted for cloud/VPS environments |
| `vps-harden.sh` | VPS live hardening — filesystem mounts and optional software hardening on a running Arch VPS |
| `lib/chroot-security.sh` | Shared PAM password policy, MITRE ATT&CK audit rule renderer/loader, `arch-audit`, and journal sealing library |
| `install-aur-packages.sh` | Staged post-install security packages (`aide`, `acct`) and AIDE baseline setup |
| `recovery-mount.sh` | Recovery tool — status, clean unmount/remount, chroot continuation, and interactive `arch-chroot` |
| `secureBoot.sh` | Manual UEFI Secure Boot `PK`/`KEK`/`db` key generation, atomic binary signing, and enrollment |

All three workflows (`archinstall.sh`, `vps-install.sh`, and `vps-harden.sh`) stage `install-aur-packages.sh`, `aur-review.sh`, and `aide-config.sh` under `/root`. After reboot, run `sudo /root/install-aur-packages.sh` in a terminal. AUR recipes require operator review before a disposable unprivileged account builds them; root installs the resulting packages, enables `acct.service` (or `psacct.service` if provided), and initializes AIDE. Existing AIDE baselines are preserved on reruns.

Both chroot scripts configure password quality before prompting for the initial user and root passwords. A `requisite` `pam_pwquality` check precedes the password writer, and local `pam_unix` uses the checked token (`use_authtok`). Existing Arch `pam_faillock` authentication control flow is retained, with lockout thresholds managed in `/etc/security/faillock.conf`. Original PAM and policy files are backed up once with a `.before-awesome` suffix.

---

## Bare-Metal Installation (`archinstall.sh`)

### Prerequisites

- Arch Linux live USB ([download](https://archlinux.org/download/))
- UEFI-capable machine
- Internet connection
- Target disk (entire disk will be erased)

### Disk Layout (`archinstall.sh`)

```
+------------+-------------+---------------------------------------------+
| BIOS (1)   | EFI (2)     | LUKS2-encrypted LVM (3)                     |
| 1 MiB ef02 | 1 GiB FAT32 | +------+------+------+--------+-----------+ |
| unmounted  | /efi        | | swap | root | var* | tmp    | home      | |
|            |             | +------+------+------+--------+-----------+ |
|            |             | /tmp: 10 GiB, or 25 GiB on >=1 TB disks     |
+------------+-------------+---------------------------------------------+
```

Note: `/boot` resides inside the encrypted `root` logical volume (there is no separate unencrypted `/boot` partition).

### Steps

1. Boot from the Arch Linux live USB.

2. Connect to the internet:
   ```bash
   iwctl station wlan0 connect <SSID>   # Wi-Fi
   # or plug in Ethernet
   ```

3. Clone the repository and run the installer (`archinstall.sh` requires sibling files from `base/`, `hardening/`, and `utils/` and cannot be run as a standalone single-file download):
   ```bash
   pacman -Sy --needed --noconfirm git
   git clone https://github.com/schm1d/AwesomeArchLinux.git
   cd AwesomeArchLinux/base
   ./archinstall.sh
   ```

4. The script prompts for:
   - **Boot profile** (explicit choice, no default):
     - `grub` — encrypted `/boot`, LUKS2 with PBKDF2, embedded initramfs keyfile (`/etc/luksKeys/boot.key`), GRUB PBKDF2 superuser password (`--unrestricted` normal boot; password required to edit kernel parameters or open the GRUB shell)
     - `uki` — `systemd-boot` + `sbctl`-signed Unified Kernel Images on `/efi/EFI/Linux/`, LUKS2 with Argon2id, no embedded keyfile in the UKI, and the `awesome-secureboot` management CLI
   - Optional TPM2 PCR binding (if TPM 2.0 hardware is detected)
   - Target disk (e.g., `sda`, `nvme0n1`) and optional pre-encryption disk wipe
   - Logical volume sizes (`swap`, `root`, optional `var` — remaining space goes to `home`)
   - Username and hostname
   - Timezone, locale, and console keymap (with live preview via `loadkeys`)
   - SSH public key (password SSH authentication is disabled)
   - Sysctl profile (`workstation`, `strict`, or `performance`) and IPv6 policy
   - Optional NVIDIA tensor-core unlock ([`Zagitta/gpu-unlock`](https://github.com/Zagitta/gpu-unlock), disabled by default; supports `gpu_unlock.targets=all` or specific PCI BDFs on GeForce RTX 20/30/40)
   - LUKS2 passphrase — **copy `recovery.key` and `luks-header-backup.img` to external off-machine storage when prompted** (live-ISO copies are shredded during final cleanup)

5. After partitioning and `pacstrap`, the installer stages `chroot.sh`, `bootloader.sh`, `lib/chroot-security.sh`, `board-health.sh`, `gpu-unlock.sh` (`/usr/local/sbin/awesome-gpu-unlock`), `ssh.sh`, `nftables.sh`, the composable sysctl bundle, and the `/root` post-install bundle, then enters `arch-chroot`.

6. Inside chroot you will be prompted for:
   - User password (enforced by `pam_pwquality`)
   - Root password (enforced by `pam_pwquality`)
   - GRUB superuser password (`grub` boot profile only)

7. Reboot when complete:
   - **`grub` profile**: enter your LUKS passphrase at the GRUB prompt; the initramfs unlocks root automatically via `/etc/luksKeys/boot.key`.
   - **`uki` profile**: enter your LUKS passphrase at the `sd-encrypt` prompt. To enable Secure Boot and optional TPM2 auto-unlock, put firmware in Setup Mode, run `sudo awesome-secureboot enroll-keys`, reboot with Secure Boot enabled, and (if using TPM2) run `sudo awesome-secureboot bind-tpm`.

### What `chroot.sh` Configures

- Timezone, locale, X11 keyboard mapping, hostname, `/etc/hosts`
- DNS-over-TLS via native `systemd-resolved` (with `iwd` + NetworkManager integration)
- `nftables` firewall (default-drop input, ICMPv4/ICMPv6 allowances, SSH rate limiting)
- `rng-tools`, `fwupd` metadata refresh (plus signed `fwupdx64.efi` in the `uki` profile), `smartmontools` + `nvme-cli` alerting, and pure-Bash EC thermal monitoring (`board-health.sh`) on supported boards
- `usbguard` with safe first-boot initial policy generation (`usbguard-initial-policy`)
- ClamAV (`clamd` + `freshclam`), `rkhunter` daily timer (with `--propupd` finalized after all package and permission changes), `arch-audit` daily vulnerability timer, `lynis`, and `arpwatch`
- `auditd` with MITRE ATT&CK rules rendered and locked (`-e 2`) at boot via `audit-rules.service`
- `fail2ban` SSH journal jail
- `journald` persistent compressed logs with Forward Secure Sealing (`awesome-journal-sealing.service`)
- Hardened `/etc/sudoers` validated via `visudo -c` before atomic installation
- User creation with private home (`0700`), default home ACLs (with `~/.cache/{yay,paru}` excluded so AUR `makepkg` `$pkgdir` permissions stay clean), `.nanorc`, and Ed25519 SSH client key/config
- OpenSSH server hardening via `ssh.sh`
- Multi-line-safe `makepkg.conf` compiler flags, `compilers` group restriction (`0750 root:compilers`), and `/etc/pacman.d/hooks/90-awesome-compilers.hook` to preserve compiler permissions across upgrades
- GPU detection supporting standalone and hybrid iGPU + dGPU systems:
  - **NVIDIA**: official `nvidia-open` on Turing+ (`RTX 20/30/40/50`, `GTX 16`, etc.); safe fallback to open-source `mesa` (`nouveau`) on pre-Turing/legacy GPUs with AUR guidance (`nvidia-580xx-dkms` / `nvidia-470xx-dkms`); optional [`Zagitta/gpu-unlock`](https://github.com/Zagitta/gpu-unlock) (`gpu-unlock-dkms` + `gpu-unlock-firmware`) built unprivileged before UKI/GRUB image generation when opted in (or later via `sudo awesome-gpu-unlock --install`)
  - **AMD**: `mesa`, `vulkan-radeon`, `libva-utils` (+ `xf86-video-amdgpu` on discrete Radeon GPUs)
  - **Intel**: `mesa`, `vulkan-intel`, `intel-media-driver`, `libva-intel-driver`, `libva-utils`, `intel-gpu-tools`
- Daily read-only update check (`pacman-autoupdate.timer` using `checkupdates`)
- Systemd service sandboxing drop-ins verified offline via `systemd-analyze verify`
- Composable `sysctl` profile (`workstation`, `strict`, or `performance`) and IPv6 policy

---

## VPS / Cloud Installation (`vps-install.sh`)

### Prerequisites

- VPS booted into an Arch Linux ISO or rescue environment with `arch-chroot`
- Out-of-band console access from your VPS provider

### Steps

1. Boot into the Arch Linux ISO or rescue environment.

2. Clone the repository and run the VPS installer (`vps-install.sh` requires sibling files from the repository):
   ```bash
   pacman -Sy --needed --noconfirm git
   git clone https://github.com/schm1d/AwesomeArchLinux.git
   cd AwesomeArchLinux/base
   ./vps-install.sh
   ```

3. The script auto-detects UEFI vs BIOS, validates your SSH public key (requiring an SSH public key unless you explicitly confirm out-of-band console access), and configures the selected sysctl profile and IPv6 policy inside chroot.

### Differences from Bare-Metal

| Feature | Bare-Metal (`archinstall.sh`) | VPS (`vps-install.sh`) |
|---------|-------------------------------|------------------------|
| Disk encryption | LUKS2 + LVM | None (provider storage layer) |
| TPM2 | Optional PCR binding | Not applicable |
| Bootloader | GRUB (encrypted `/boot`) or signed UKI (`systemd-boot` + `sbctl`) | GRUB (`x86_64-efi` on UEFI, `i386-pc` on BIOS) |
| Partitioning | `BIOS_Boot` (1 MiB) + `EFI` (1 GiB `/efi`) + `LUKS2` (`swap`, `root`, `var*`, `tmp`, `home`) | `EFI` (1 GiB) or `BIOS_Boot` (1 MiB) + `ext4` root + `/swapfile` + `tmpfs` `/tmp` |
| GPU drivers | NVIDIA / AMD / Intel (including hybrid GPUs) | Skipped |
| Serial console | Not enabled by default | Enabled (`ttyS0` in GRUB and `serial-getty@ttyS0`) |
| USBGuard / Bluetooth | Enabled / auto-detected | Skipped |
| Firewall | `nftables` | `nftables` (with automatic legacy `iptables` fallback) |
| Software hardening | Full | Full |

---

## VPS Live Hardening (`vps-harden.sh`)

For VPS providers that pre-install Arch Linux where booting a custom ISO is impractical, `vps-harden.sh` hardens a running Arch Linux system in place. Unlike `archinstall.sh` and `vps-install.sh`, `vps-harden.sh` works either from a full git clone or as a standalone download (fetching required repository components over HTTPS and validating them before execution):

```bash
curl -fsSLO https://raw.githubusercontent.com/schm1d/AwesomeArchLinux/main/base/vps-harden.sh
chmod +x vps-harden.sh
sudo ./vps-harden.sh
```

Preview planned changes without modifying the system:

```bash
sudo ./vps-harden.sh --dry-run
```

Filesystem mount hardening only (skip `/var` storage preparation and software hardening):

```bash
sudo ./vps-harden.sh --skip-var --skip-sw
```

### CLI Options

```
  -t SIZE     tmpfs size for /tmp in GB (minimum: 10; automatic default: 10,
              or 25 when the root disk is at least 1 TB)
  -v SIZE     /var loop image size in GB, if using loop device (default: 10)
  -u USER     Non-root username for vps-chroot.sh (prompted if not given)
  -H HOST     Hostname to set (prompted if not given)
  -p PORT     SSH port for vps-chroot.sh (default: 22)
  --ssh-key KEY
              SSH public key to install for USER
  -k, --allow-no-ssh-key
              Allow disabling SSH password auth without an authorized_keys entry
              (ONLY if you have verified out-of-band VPS console access)
  --skip-var  Skip storage preparation for offline /var migration
  --skip-sw   Skip software hardening (only do filesystem mounts)
  --sysctl-profile PROFILE
              Select workstation, strict, or performance (default: workstation)
  --disable-ipv6
              Install the explicit IPv6-disable sysctl overlay
  --dry-run   Show planned changes without executing
  -h, --help  Show help
```

### Safety Mechanisms

- `--dry-run` previews all planned actions without modifying the system
- `mount -a --fake` validates `/etc/fstab` after every edit and automatically restores the backup on failure
- Auto-generated rollback script at `/root/undo-vps-harden.sh`
- Refuses to disable SSH password authentication unless `authorized_keys` is non-empty, `--ssh-key` / interactive key is supplied, or `-k` / console confirmation is explicitly given
- `/var` is never copied or cut over while the OS is running; device-specific rescue commands are written to `/root/MIGRATE_VAR_OFFLINE.txt`

---

## Recovery Tool (`recovery-mount.sh`)

To inspect, resume, or repair an encrypted bare-metal or VPS Arch installation from a live USB:

```bash
sudo ./recovery-mount.sh
```

Interactive menu options:
1. Show current `/mnt` mounts, active LVM logical volumes, and open `/dev/mapper` containers
2. Safely deactivate swap (`swapoff`), recursively unmount `/mnt` (`umount -R /mnt`), deactivate LVM, and close LUKS
3. Unlock LUKS + activate LVM + mount `root`, `home`, optional `var`, optional `tmp`, and `/efi` (or mount an unencrypted 2-partition VPS root + swapfile)
4. Resume an interrupted `chroot.sh` or `vps-chroot.sh` run
5. Enter an interactive `arch-chroot` shell at `/mnt` for manual repair
6. Exit

---

## UEFI Secure Boot (`awesome-secureboot` vs `secureBoot.sh`)

- **`uki` boot profile (recommended for Secure Boot)**: Secure Boot keys and signing hooks are already provisioned with `sbctl` during installation. Use `sudo awesome-secureboot status`, `sudo awesome-secureboot enroll-keys`, `sudo awesome-secureboot bind-tpm`, and `sudo awesome-secureboot refresh`.
- **Manual `PK`/`KEK`/`db` provisioning (`secureBoot.sh`)**: For custom non-`sbctl` UEFI setups (refuses to run if `sbctl` already manages Secure Boot):
  ```bash
  sudo ./secureBoot.sh [-d KEY_DIR] [-p EFI_MOUNT] [-k KEY_SIZE] [-v VALID_DAYS] [-o] [-h]
  ```
  Generates `PK`, `KEK`, and `db` keys (leaving vendor `dbx` revocations intact), backs up existing efivars, signs candidate bootloaders/kernels/UKIs atomically via temporary files first, and enrolls keys in strict `db` -> `KEK` -> `PK` order.

---

## Post-Installation Checklist

After rebooting into your new system:

1. Run staged security package setup: `sudo /root/install-aur-packages.sh`
2. Verify DNS-over-TLS: `resolvectl status`
3. Check firewall rules: `sudo nft list ruleset`
4. Verify SSH listener: `ss -tlnp | grep ssh`
5. Confirm audit daemon and immutable rules: `systemctl status auditd audit-rules.service` and `sudo auditctl -s` (`enabled 2`)
6. Run vulnerability scan: `sudo systemctl start arch-audit.service` and review `/var/log/arch-audit.log`
7. Check `systemctl status awesome-journal-sealing.service`, move `/root/journal-sealing/verification-<machine-id>.txt` to trusted off-machine storage, verify the copy, and remove the local verification file (never move `/var/log/journal/<machine-id>/fss`)
8. Run a full system audit: `sudo lynis audit system`

---

## References

- [Arch Linux Installation Guide](https://wiki.archlinux.org/title/Installation_guide)
- [dm-crypt: Encrypting an entire system](https://wiki.archlinux.org/title/Dm-crypt/Encrypting_an_entire_system)
- [Unified kernel images — ArchWiki](https://wiki.archlinux.org/title/Unified_kernel_image)
- [UAPI Unified Kernel Image specification](https://uapi-group.org/specifications/specs/unified_kernel_image/)
- [UEFI Secure Boot — ArchWiki](https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot)
- [`systemd-cryptenroll` TPM2 enrollment](https://www.freedesktop.org/software/systemd/man/latest/systemd-cryptenroll.html)
- [`bootctl` and systemd-boot](https://www.freedesktop.org/software/systemd/man/latest/bootctl.html)
- [GRUB security guidance](https://www.gnu.org/software/grub/manual/grub/html_node/Security.html)
- [`sbctl` manual](https://github.com/Foxboron/sbctl/blob/master/docs/sbctl.8.txt)
