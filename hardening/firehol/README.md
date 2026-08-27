# FireHOL Blocklist Firewall

Installs FireHOL and its `update-ipsets` utility from the AUR package, enables
the selected FireHOL aggregate list plus `fullbogons`, and creates a default-deny
iptables policy.

FireHOL is an alternative firewall backend. It must not be stacked on the
installer-owned nftables `inet filter` chains: an accept in one firewall cannot
override a drop in the other. The script detects that configuration and refuses
to proceed rather than silently producing a partially effective ruleset.

## Usage

Choose inbound services explicitly. Running without an inbound-policy choice is
refused so a remote operator cannot accidentally lock out the machine.

```bash
# SSH-only server
sudo ./firehol.sh --allow-ssh 22

# SSH plus a web server
sudo ./firehol.sh --allow-ssh 2222 --allow-http --allow-https

# Host that intentionally accepts no inbound connections
sudo ./firehol.sh --no-inbound

# Rebuild configuration without reinstalling the AUR package
sudo ./firehol.sh --update-only --allow-ssh 22
```

| Option | Meaning |
|---|---|
| `-l LEVEL` | FireHOL aggregate level 1, 2, or 3 (default: 1) |
| `-u`, `--update-only` | Skip package installation |
| `--allow-ssh PORT` | Allow inbound SSH on the specified TCP port |
| `--allow-http` | Allow inbound TCP 80 |
| `--allow-https` | Allow inbound TCP 443 |
| `--no-inbound` | Explicitly allow no inbound services |
| `-h`, `--help` | Show help |

`--no-inbound` cannot be combined with an allow option.

## Installation safety

- Repository dependencies are installed with a complete `pacman -Syu`; partial
  `pacman -Sy` upgrades are not used.
- Mutable AUR HEAD is never executed automatically. The complete `iprange` and
  `firehol` recipes are displayed with terminal control characters escaped,
  and each exact AUR commit requires an `INSTALL <package> <full-commit>`
  confirmation before `makepkg` evaluates it.
- AUR dependencies require their own review. Signed Arch-repository
  dependencies are installed only after the parent recipe is approved.
- Builds run as unique disposable users. Background build processes are killed,
  the identity is removed, and only the specifically requested package archive
  is passed to root `pacman -U`.
- Review records containing the AUR commit and built package SHA-256 are written
  under `/var/lib/awesomearchlinux/aur-reviews/`.
- `update-ipsets` is provided by the FireHOL package; there is no separate
  `update-ipsets` AUR package.
- A failed list enable/download or `firehol debug` validation aborts activation.

## Generated configuration

The script writes `/etc/firehol/firehol.conf` with:

- `firehol_level1`, `firehol_level2`, or `firehol_level3`;
- `fullbogons`;
- both blacklists declared before the first interface, as FireHOL requires;
- a default-drop inbound policy;
- unrestricted outbound client traffic;
- only the inbound services explicitly selected on the command line.

The daily `/etc/cron.d/firehol-ipsets` job reloads the active firewall only when
`update-ipsets` succeeds. It uses `firehol condrestart`; the interactive
30-second `firehol try` command is reserved for attended manual testing.

## Verification

```bash
sudo firehol debug
sudo systemctl status firehol
sudo ipset list -n
sudo journalctl -u firehol
```

Start with level 1. Higher aggregate levels increase false-positive risk and
should be tested against the machine's actual dependencies.

## References

- [Arch User Repository security guidance](https://wiki.archlinux.org/title/Arch_User_Repository)
- [`makepkg(8)`](https://man.archlinux.org/man/makepkg.8.en)
- [FireHOL configuration reference](https://firehol.org/firehol-manual/firehol-conf/)
- [FireHOL blacklist reference](https://firehol.org/firehol-manual/firehol-blacklist/)
- [FireHOL command reference](https://firehol.org/firehol-manual/firehol/)
- [nftables — ArchWiki](https://wiki.archlinux.org/title/Nftables)
