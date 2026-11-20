# FireHOL Blocklist Firewall

Installs FireHOL and its `update-ipsets` utility from the AUR package, enables
the selected FireHOL aggregate list (together with the lists it is merged from)
plus `fullbogons`, and creates a default-deny iptables policy.

FireHOL is an alternative firewall backend. It must not be stacked on the
installer-owned nftables `inet filter` chains or enabled alongside
`nftables.service` (which can shadow or flush rules across reboots): an accept in
one firewall cannot override a drop in the other. The script detects active
`inet filter` chains as well as active or enabled `nftables.service` units and
refuses to proceed rather than silently producing a conflicting ruleset.

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
| `-l LEVEL` | FireHOL aggregate level 1, 2, or 3 (default: 1). Each level is its own list; level 2 does not include level 1 |
| `-u`, `--update-only` | Skip package installation |
| `--allow-ssh PORT` | Allow inbound SSH on the specified TCP port (decimal; a leading zero is ignored) |
| `--allow-http` | Allow inbound TCP 80 |
| `--allow-https` | Allow inbound TCP 443 |
| `--no-inbound` | Explicitly allow no inbound services |
| `-h`, `--help` | Show help |

`--no-inbound` cannot be combined with an allow option.

## Installation safety

- Repository dependencies (including `curl` and `unzip` required by
  `update-ipsets`) are installed with a complete `pacman -Syu`; partial
  `pacman -Sy` upgrades are not used.
- Configuration staging uses `/etc/firehol/.firehol.conf.XXXXXX` (`0600`, cleaned
  up via `EXIT` trap) and preserves `0600` permissions on configuration backups.
- FireHOL compiles temporary helper scripts at runtime, which fails on hardened
  hosts where `/tmp` is mounted `noexec`. The script creates `/run/firehol-tmp`
  (`0700`) and sets `TMPDIR=/run/firehol-tmp` and
  `FIREHOL_TMP_DIR=/run/firehol-tmp` across direct invocations,
  `firehol.service.d/runtime-tmp.conf`, and `/etc/cron.d/firehol-ipsets`.
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
- both blacklists declared before the first interface, as FireHOL requires,
  each with the exceptions described below;
- a default-drop inbound policy;
- IPv6 neighbour discovery, router advertisements and multicast listener
  reports (`ipv6neigh`, `ipv6router`, `ipv6mld`). These ICMPv6 messages are not
  connection-tracked, so the outbound client rule does not cover them and IPv6
  would stop working without them. The lines are wrapped in a test of
  FireHOL's `ENABLE_IPV6`, so they are skipped on hosts where FireHOL runs
  IPv4-only (no IPv6 in the kernel, or no usable `ip6tables`);
- unrestricted outbound client traffic;
- only the inbound services explicitly selected on the command line.

### Aggregate levels and their source lists

A `firehol_levelN` list is a merge that `update-ipsets` builds locally from
other lists, and it only merges the ones that are enabled themselves. The
script therefore enables the source lists of the selected level as well. Their
names are read from the installed `update-ipsets`; in FireHOL 3.1.8 they are:

| Level | Source lists |
|---|---|
| 1 | `dshield`, `feodo`, `fullbogons`, `spamhaus_drop` |
| 2 | `blocklist_de`, `dshield_1d`, `greensnow` |
| 3 | `bruteforceblocker`, `ciarmy`, `dshield_30d`, `myip`, `vxvault` |

`dshield_1d` and `dshield_30d` are history views derived from `dshield`, which
is enabled for them. A source list that cannot be downloaded is left out of
the merge with a warning from `update-ipsets`. If the aggregate list or
`fullbogons` ends up missing or empty, the script stops before the firewall is
changed. Installations made with an earlier version of this script had only
the bogons in `firehol_level1`; re-run with `--update-only` to enable the
missing source lists.

### Blacklist exceptions

`blacklist full` is stateless and bidirectional: packets from a listed address
are dropped and packets to one are rejected, before any interface rule is
consulted. `fullbogons` (also part of `firehol_level1`) lists every
special-purpose range, including the private networks. The generated
blacklists therefore carry an `except src "..."` clause:

- always: `169.254.0.0/16` (link-local: DHCP servers, cloud metadata service),
  `224.0.0.0/4` (multicast: IGMP, mDNS) and `255.255.255.255` (DHCP broadcast).
  These never cross a router, so filtering them as bogons protects nothing;
- when the host itself has a global-scope address in private or carrier-grade
  NAT space (LAN, cloud VPC, VPN, container bridge): `10.0.0.0/8`,
  `172.16.0.0/12`, `192.168.0.0/16` and `100.64.0.0/10`. Without this the host
  loses its gateway's DNS, its LAN peers and SSH from the LAN the moment
  FireHOL starts.

The exception only skips the blacklist; the interface policy still decides
what is accepted. The decision is made when the configuration is generated:
re-run `sudo ./firehol.sh --update-only ...` after the host's addressing
changes. The script prints the excepted ranges.

The daily `/etc/cron.d/firehol-ipsets` job sets explicit `SHELL=/usr/bin/bash`
and `PATH`, ensures `/run/firehol-tmp` (`0700`) exists, and reloads the active
firewall only when `update-ipsets` succeeds. It uses `firehol condrestart`; the
interactive 30-second `firehol try` command is reserved for attended manual
testing.

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
