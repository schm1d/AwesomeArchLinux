# Sysctl profiles

This module installs composable `sysctl.d` layers instead of generating one
opaque `99-sysctl.conf`. Every installer uses the same entry point,
[`sysctl.sh`](./sysctl.sh), and the default profile is the compatibility-oriented
`workstation` baseline.

## Profiles

| Profile | Installed layers | Intended use | Important tradeoffs |
|---|---|---|---|
| `workstation` | security core + workstation network | Desktops, laptops, development hosts, and general servers | Leaves io_uring and the distribution's user-namespace policy unchanged; IPv6 stays enabled |
| `strict` | workstation + strict overlay | Fixed-purpose hosts with tested workloads | Disables io_uring, unprivileged user namespaces, kexec, SysRq, and most unprivileged debugging; panics on oops |
| `performance` | workstation + performance overlay | Hosts where fq + BBR has been measured or is desired | Loads `tcp_bbr`; deliberately does not guess socket buffers, dirty-memory limits, keepalives, or TCP timeouts |

IPv6 is independent of the profile. It remains enabled, accepts router
advertisements for SLAAC, and rejects redirects and source-routing headers by
default. Add `--disable-ipv6` only when the host's network policy explicitly
forbids IPv6.

## Files and precedence

```text
60-awesome-security-core.conf          shared, compatibility-oriented hardening
70-awesome-workstation-network.conf    non-router IPv4/IPv6 policy
80-awesome-performance.conf            small fq + BBR performance overlay
80-awesome-bbr.modules                 tcp_bbr modules-load entry
90-awesome-strict.conf                 compatibility-breaking hardening overlay
90-awesome-ipv6-disabled.conf          optional IPv6-disable overlay
99-awesome-local.conf.example          administrator override template
lock-modules-now.sh                    explicit irreversible module-lock helper
sysctl.sh                              profile installer and migration entry point
```

`sysctl.d` processes files lexicographically. The numbered layers make
precedence visible: strict settings override the compatible core, while an
administrator can copy `99-awesome-local.conf.example` to
`/etc/sysctl.d/99-awesome-local.conf` for local overrides.

Settings prefixed with `-` are compatibility-sensitive or kernel-dependent.
`systemd-sysctl` logs failures for those assignments at debug level instead of
failing the boot.

## Manual installation

Preview a profile without writing:

```bash
./sysctl.sh workstation --dry-run
./sysctl.sh strict --disable-ipv6 --dry-run
```

Install and apply it to a running system:

```bash
sudo ./sysctl.sh workstation
sudo ./sysctl.sh performance
sudo ./sysctl.sh strict --disable-ipv6
```

For an offline root or image, install without touching the running kernel:

```bash
./sysctl.sh workstation --root /mnt/image --no-apply
```

The Arch installers use this no-apply path because applying settings inside an
installation chroot only changes the live ISO kernel. The installed files take
effect through `systemd-sysctl.service` on first boot.

## Migration behavior

The installer removes only its exact managed filenames. If it recognizes the
old generated `99-sysctl.conf` by its obsolete `tcp_fack` and
`tcp_challenge_ack_limit` entries, it moves that file to a recoverable
`.awesomearchlinux-legacy` backup. An unrelated `99-sysctl.conf` is preserved
and produces a warning because its later filename may override this profile.

The old profile names remain accepted as deprecated CLI aliases:

- `security` maps to `strict`
- `security-performance` and `full-performance` map to `performance`

New installer runs record only `workstation`, `strict`, or `performance`.
When switching a running host away from `strict`, the installer warns if the
one-way BPF or kexec controls remain active; removing their configuration only
restores the less restrictive policy after reboot.

## Why the old tuning set was removed

The previous configurations mixed security policy with universal performance
claims. This redesign removes fixed socket buffers, shared-memory caps,
`kernel.pid_max`, `vm.min_free_kbytes`, dirty-page byte limits, aggressive
keepalives, `tcp_fastopen = 3`, `tcp_tw_reuse = 1`, and short TCP timeouts.
Those values are workload and memory-size decisions, and several now duplicate
or fight modern kernel defaults.

It also corrects IPv6 source-route handling: Linux uses a negative value to
reject every IPv6 routing header; `0` still accepts routing header type 2.

## Irreversible module lockdown

`kernel.modules_disabled=1` is intentionally absent from every boot profile.
Once set, the running kernel cannot load or unload modules until reboot, which
can break later USB, GPU, storage, filesystem, VPN, and virtualization events.

If a fixed-purpose system has been tested with every required module loaded,
the helper requires both an explicit mode and confirmation token:

```bash
sudo ./lock-modules-now.sh --runtime --confirm LOCK-MODULES
sudo ./lock-modules-now.sh --persist --confirm LOCK-MODULES
```

Use `--runtime` first. `--persist` creates
`/etc/sysctl.d/90-awesome-modules-lockdown.conf`; remove that file from recovery
media if the machine cannot boot or initialize required hardware.

See [`WORKSTATION.md`](./WORKSTATION.md) for higher-value non-sysctl workstation
decisions such as swap, THP, IRQ balancing, CPU policy, and measurement.
