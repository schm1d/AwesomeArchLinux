# Base Installation Scripts

Core scripts for installing and configuring a security-hardened Arch Linux system. Two installation paths are provided: **bare-metal** (full disk encryption) and **VPS/cloud** (simplified partitioning).

---

## Scripts Overview

| Script | Purpose |
|--------|---------|
| `archinstall.sh` | Bare-metal installer — LVM on LUKS1, UEFI, optional TPM2 |
| `chroot.sh` | Bare-metal post-install — system hardening inside chroot |
| `vps-install.sh` | VPS/cloud installer — single partition, swap file, BIOS/UEFI |
| `vps-chroot.sh` | VPS post-install — same hardening adapted for VPS |
| `recovery-mount.sh` | Recovery tool — unmount/remount encrypted installations |
| `secureBoot.sh` | UEFI Secure Boot key generation and enrollment |

---

## Bare-Metal Installation

### Prerequisites

- Arch Linux live USB ([download](https://archlinux.org/download/))
- UEFI-capable machine
- Internet connection
- Target disk (entire disk will be erased)

### Disk Layout (archinstall.sh)

```
+----------+----------+------------------------------------------+
| EFI (1)  | Boot (2) | LUKS1-encrypted LVM (3)                  |
| FAT32    | ext4     | +--------+--------+--------+-----------+ |
| 512 MiB  | 1 GiB    | | swap   | root   | var    | home      | |
|          |          | +--------+--------+--------+-----------+ |
| /efi     | /boot    | Sizes chosen interactively               |
+----------+----------+------------------------------------------+
```

### Steps

1. Boot from the Arch Linux live USB.

2. Connect to the internet:
   ```bash
   iwctl station wlan0 connect <SSID>   # Wi-Fi
   # or just plug in ethernet
   ```

3. Download and run the installer:
   ```bash
   curl -fsSLO https://raw.githubusercontent.com/schm1d/AwesomeArchLinux/main/base/archinstall.sh
   chmod +x archinstall.sh
   sudo ./archinstall.sh
   ```

4. The script will prompt for:
   - Target disk (e.g., `sda`, `nvme0n1`)
   - Partition sizes (swap, root, var — remainder goes to home)
   - Username and hostname
   - LUKS encryption passphrase
   - TPM2 binding (if hardware is detected)

5. After partitioning and pacstrap, the script copies `chroot.sh` and `sysctl.sh` into the new system and enters chroot automatically.

6. Inside chroot you will be prompted for:
   - User password
   - Root password
   - GRUB bootloader password

7. Reboot when complete. The system boots encrypted — enter the LUKS passphrase (or TPM unlocks automatically if enrolled).

### What archinstall.sh Does

- Validates UEFI support, network, and disk space
- Detects TPM2 hardware and version
- Creates GPT partition table (EFI + boot + LUKS)
- Encrypts the third partition with LUKS1 (AES-XTS, 512-bit)
- Creates LVM volumes (swap, root, var, home)
- Generates a LUKS keyfile for unattended boot unlocking
- Runs pacstrap with base, linux, linux-hardened, linux-firmware
- Detects CPU vendor and installs microcode (intel-ucode / amd-ucode)
- Copies chroot.sh and sysctl.sh, then enters arch-chroot

### What chroot.sh Does

- Timezone, locale, hostname, /etc/hosts
- DNS-over-TLS via Stubby with systemd-resolved
- nftables firewall (default deny, SSH rate limiting)
- rng-tools for entropy
- ClamAV antivirus with scheduled definition updates
- rkhunter rootkit detection (daily timer)
- auditd with MITRE ATT&CK-mapped rules
- fail2ban with SSH jail
- journald hardening (persistent, compressed, sealed)
- Sudoers hardening (I/O logging, env_reset, secure_path)
- PAM faillock (5 attempts, 15-minute lockout)
- Password quality enforcement (pam_pwquality, 12-char minimum)
- User creation with sudo/wheel group membership
- SSH key generation and client configuration
- SSH server hardening via the standalone `ssh.sh` script
- Nano syntax highlighting and configuration
- GRUB installation with encryption support and PBKDF2 password
- GPU driver detection and installation (NVIDIA/AMD/fallback)
- UEFI Secure Boot preparation
- mkinitcpio with encrypt + lvm2 hooks (or sd-encrypt for TPM)
- Compiler hardening flags (FORTIFY_SOURCE, stack protector, RELRO, PIE)
- Compiler access restricted to `compilers` group
- AppArmor kernel boot parameters
- Disabled protocols (DCCP, SCTP, RDS, TIPC)
- Core dump disabled
- Chrony NTP with network time synchronization
- 15+ systemd service hardening overrides
- 100+ sysctl kernel parameters (via sysctl.sh)
- Secure cleanup of install artifacts on exit

---

## VPS / Cloud Installation

### Prerequisites

- VPS with Arch Linux ISO mounted (or rescue mode with arch-chroot)
- Root/console access from the VPS provider

### Steps

1. Boot into the Arch Linux ISO or rescue environment.

2. Download and run:
   ```bash
   curl -fsSLO https://raw.githubusercontent.com/schm1d/AwesomeArchLinux/main/base/vps-install.sh
   chmod +x vps-install.sh
   sudo ./vps-install.sh
   ```

3. The script auto-detects BIOS vs UEFI and adjusts accordingly.

### Differences from Bare-Metal

| Feature | Bare-metal | VPS |
|---------|-----------|-----|
| Disk encryption | LUKS1 + LVM | None (provider handles it) |
| TPM2 | Optional auto-enrollment | Not available |
| Boot | GRUB + encrypted /boot | GRUB (UEFI) or syslinux (BIOS) |
| Partitioning | EFI + boot + LUKS(LVM) | Single root + swap file |
| GPU drivers | NVIDIA/AMD auto-detect | Skipped |
| Serial console | No | Yes (ttyS0 for provider access) |
| USBGuard | Yes | Skipped |
| Bluetooth | Auto-detected | Skipped |
| Software hardening | Full | Full (identical) |

---

## Recovery Tool

If you need to access your encrypted bare-metal installation from a live USB:

```bash
sudo ./recovery-mount.sh
```

Provides an interactive menu to:
- Open LUKS and activate LVM
- Mount all partitions (root, boot, efi, home, var)
- Enter arch-chroot for repairs
- Cleanly unmount and close LUKS when done

---

## Secure Boot

After installation, optionally enable UEFI Secure Boot:

```bash
sudo ./secureBoot.sh
```

- Generates PK, KEK, db, and dbx keys
- Signs EFI binaries (GRUB, kernel, etc.)
- Enrolls keys into UEFI firmware
- Supports `-d` (key directory), `-p` (EFI mount), `-k` (key size), `-v` (validity days)

---

## Post-Installation Checklist

After rebooting into your new system:

1. Verify DNS-over-TLS is working: `resolvectl status`
2. Check firewall rules: `sudo nft list ruleset`
3. Verify SSH is listening on the correct port: `ss -tlnp | grep ssh`
4. Confirm auditd is running: `systemctl status auditd`
5. Run a security audit: `sudo lynis audit system`
6. Check for vulnerable packages: `arch-audit`
7. Update ClamAV definitions: `sudo freshclam`
8. Review fail2ban status: `sudo fail2ban-client status sshd`
9. Verify AppArmor profiles: `sudo aa-status`
10. Copy your SSH public key to `~/.ssh/authorized_keys` before relying on key-only auth
