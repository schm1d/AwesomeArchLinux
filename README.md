![Arch Linux Secure AF](./archLinux.png)
Wallpaper: [https://www.reddit.com/user/alienpirate5/](https://www.reddit.com/user/alienpirate5/)


## Awesome Arch Linux

A collection of shell scripts for hardened Arch Linux installation, configuration, and security enhancements. The aim is to make this repository a reliable and curated reference for Arch Linux hardened installation setups and configurations.

The encryption method used in the installation script is [LVM on LUKS with encrypted boot partition](https://wiki.archlinux.org/title/Dm-crypt/Encrypting_an_entire_system#Encrypted_boot_partition_(GRUB)) (Full disk encryption (GRUB) for UEFI systems).

The script will prepare everything for you. No need to worry about partitioning or the encryption process. It will also configure GRUB to use the encryption keys. All you have to do is change the variable values according to your system, provide a password to encrypt the disk and specify the username and hostname. If you are using NVIDIA GPUs, the script will also install the appropriate drivers. 🙂

You will get a very clean, solid, and secure base installation.

### Features

- **Automated Arch Linux Installation**: Automates the entire installation process, including disk partitioning, formatting, mounting, and package installation.
- **Full Disk Encryption**: Implements LVM on LUKS with an encrypted boot partition for full disk encryption on UEFI systems.
- **Comprehensive Hardening**: Applies extensive security hardening measures across the system, covering authentication, services, kernel parameters, and more.
- **NVIDIA GPU Support**: Automatically detects and installs the appropriate NVIDIA drivers if an NVIDIA GPU is present.
- **Customizable**: Variables and configurations can be adjusted to suit your specific needs.

### Installation

First, download the Arch Linux ISO [here](https://archlinux.org/download/).

#### Method 1

Boot the media on the target device where you want to install Arch Linux.

If Git is not installed, you can install it with:

```bash
pacman -Sy git
```

Then, on the live system, do the following:

```bash
git clone https://github.com/schm1d/AwesomeArchLinux.git
cd AwesomeArchLinux/base
chmod +x *.sh
./archinstall.sh
```

#### Method 2

Boot the media on the target device where you want to install Arch Linux.

Download the scripts on another machine and copy them to a removable media (e.g., USB drive).

To run the base scripts on your target machine, all you need to do is:

1. Copy both **archinstall.sh** and **chroot.sh** to the same directory on the live system.
2. Make them executable:

   ```bash
   chmod +x archinstall.sh chroot.sh
   ```

3. Run **archinstall.sh**:

   ```bash
   ./archinstall.sh
   ```

### Hardening Techniques Implemented

#### Full Disk Encryption

- **LVM on LUKS with Encrypted Boot Partition**: Provides full disk encryption using LUKS, including the `/boot` partition.
- **Strong Encryption Algorithms**: Utilizes `aes-xts-plain64` cipher with a 512-bit key and `sha512` hash for secure encryption.
- **Randomized Encryption Keys**: Generates a random key file for unlocking the LUKS container, enhancing security.

#### Secure Boot Configuration

- **GRUB Hardening**: Enables GRUB password protection and encrypts GRUB with the LUKS key.
- **Secure Kernel Parameters**: Configures GRUB to pass security-focused parameters to the kernel.

#### PAM Configuration

- **Updated PAM Modules**: Replaces deprecated `pam_tally2.so` with `pam_faillock.so` for account lockout policies.
- **Correct PAM File Modifications**: Ensures changes are made to the correct PAM configuration files (`/etc/pam.d/system-auth`).

#### Password Policies

- **Password Complexity Enforcement**: Sets minimum password length to 12 characters and requires the use of uppercase, lowercase, digits, and symbols.
- **Password Quality Module**: Configures `pam_pwquality.so` with strict settings in `/etc/security/pwquality.conf`.
- **Password Aging Policies**: Sets maximum and minimum password age in `/etc/login.defs`.

#### Account Lockout Policies

- **Failed Login Attempt Limits**: Locks accounts after 5 failed login attempts for 15 minutes using `pam_faillock.so`.
- **Login Retry Limits**: Reduces login retries and timeouts in `/etc/login.defs`.

#### Firewall Configuration

- **iptables Setup**: Configures `iptables` to set default policies, allowing only necessary traffic.
- **SSH Rate Limiting**: Implements rate limiting on SSH connections to mitigate brute-force attacks.
- **Loopback and Established Connections**: Allows loopback traffic and established connections.

#### Service Hardening

- **Disabled Unnecessary Services**: Disables or removes services and protocols that are not needed (e.g., `dccp`, `sctp`, `rds`, `tipc`).
- **Secured System Services**: Configures services like `NetworkManager`, `ssh`, `dhcpcd`, and ensures they are enabled securely.
- **Time Synchronization**: Installs and enables `chrony` and `ntpd` for reliable timekeeping.

#### System Auditing and Monitoring

- **Auditd Installation**: Installs `auditd` and downloads comprehensive audit rules to monitor system activities.
- **Fail2Ban Configuration**: Installs and configures `fail2ban` to protect against unauthorized access attempts.
- **System Accounting**: Enables `sysstat` for system performance monitoring.

#### Kernel Hardening

- **Kernel Parameters**: Sets parameters like `slab_nomerge`, `init_on_alloc=1`, `pti=on`, and others to harden the kernel against attacks.
- **Module Blacklisting**: Blacklists unneeded kernel modules like `nouveau` when installing NVIDIA drivers.
- **CPU Microcode Updates**: Installs CPU microcode updates for Intel and AMD processors.

#### File System Permissions

- **Securing Key Directories and Files**: Sets appropriate permissions on sensitive files like `/etc/shadow`, `/boot/grub/grub.cfg`, and others.
- **UMASK Settings**: Changes default `UMASK` to `027` for more restrictive default file permissions.
- **Home Directory ACLs**: Sets default ACLs on home directories to restrict access.

#### SSH and Network Security

- **SSH Configuration**: Hardened `sshd_config` settings and restricted access via `hosts.allow` and `hosts.deny`.
- **DNS Configuration**: Prevents DNS leaks by configuring `systemd-resolved` with secure DNS servers and enabling DNSSEC.
- **ARPWatch Installation**: Installs `arpwatch` to monitor for ARP spoofing attacks.

#### Disabling Unnecessary Protocols and Services

- **Kernel Module Blacklisting**: Disables unneeded protocols by adding entries in `/etc/modprobe.d/disable-protocols.conf`.
- **Core Dump Disabling**: Prevents core dumps to avoid potential information leakage.

#### Additional Security Enhancements

- **ClamAV Installation**: Provides antivirus scanning capabilities.
- **Rootkit Hunter**: Installs `rkhunter` to detect rootkits and malware.
- **USBGuard Configuration**: Controls USB device access to prevent unauthorized devices.
- **Logrotate Configuration**: Ensures log files are rotated and managed correctly.
- **Sudo Hardening**: Configures `/etc/sudoers` with secure defaults, logging, and environment restrictions.
- **Bootloader Security**: Sets a GRUB password and restricts boot options to prevent unauthorized changes.
- **Banner Creation**: Adds a security banner in `/etc/issue` to warn unauthorized users.

### Customization

- **Variable Configuration**: Modify variables like `DISK`, `USERNAME`, `HOSTNAME`, `TIMEZONE`, and `LOCALE` in the `archinstall.sh` and `chroot.sh` scripts to suit your setup.
- **Package Selection**: Adjust the list of packages installed during the base system installation in `archinstall.sh`.
- **SSH Port**: Change the `SSH_PORT` variable in `chroot.sh` to use a custom SSH port.

### Contributing

Contributions are welcome! Feel free to submit issues or pull requests to improve the scripts, add new features, or enhance the documentation.

### License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

**Note**: Arch Linux is a highly customizable, lightweight, and rolling-release distribution suitable for experienced users who want complete control over their system. These scripts aim to automate the installation and hardening process, but reviewing and understanding the configurations is essential to ensure they meet your security requirements.
