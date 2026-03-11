# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

AwesomeArchLinux is a collection of shell scripts for hardened Arch Linux installation, configuration, and security. It provides two installation paths:
- **Bare-metal**: Full disk encryption (LVM on LUKS), TPM2, UEFI/Secure Boot (`base/archinstall.sh` → `base/chroot.sh`)
- **VPS/Cloud**: Simplified partitioning, serial console support (`base/vps-install.sh` → `base/vps-chroot.sh`)

Post-install, `base/vps-harden.sh` can harden a running system. The `hardening/` directory contains 19 independent application-specific hardening modules (nginx, SSH, Docker, PostgreSQL, etc.), and `utils/` has system administration utilities.

## Lint Command

```bash
shellcheck --severity=warning --shell=bash <script.sh>
```

CI runs ShellCheck on all `*.sh` files via `.github/workflows/shellcheck.yml` on push/PR to main.

## Architecture

**Installation flow:** Installer script (partitioning/pacstrap) → chroot script (system hardening) → optional application hardening modules.

**Three layers:**
- `base/` — Installation and core system hardening (disk encryption, firewall, auditd, PAM, kernel sysctl, systemd overrides, SSH, DNS-over-TLS)
- `hardening/` — Independent per-application modules (each has its own setup script, config files, systemd overrides, AppArmor profiles, and README)
- `utils/` — Optional tools (AIDE, backup, monitoring, Docker setup, desktop configs, MITRE ATT&CK audit rules)

**Key patterns across all scripts:**
- All use `set -euo pipefail` with bash
- Scripts validate prerequisites (root, UEFI, network) before proceeding
- `--dry-run` flag available on newer scripts (e.g., `vps-harden.sh`, `nginx.sh`)
- nftables for firewall, AppArmor for MAC, auditd for logging
- Hardening modules are idempotent and independently deployable

**Chroot scripts are the largest components** (~1300-1580 lines) handling: timezone/locale, DNS-over-TLS (Stubby), nftables firewall, ClamAV, rkhunter, auditd, fail2ban, SSH hardening, PAM, GRUB, compiler flags, 100+ sysctl parameters, and 15+ systemd service overrides.

## Conventions

- Target platform is Arch Linux only (pacman-based, systemd)
- Security decisions should follow defense-in-depth principles
- Every hardening parameter should have a justifiable security rationale
- Firewall rules use nftables (not iptables)
- SSH uses Ed25519 keys and modern ciphers only
- nginx targets SSL Labs A+ rating
