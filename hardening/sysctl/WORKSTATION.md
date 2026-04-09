# Secure Workstation Companion Checklist

This checklist covers the important **non-sysctl** settings that complement [`99-workstation-net.conf`](./99-workstation-net.conf) on a modern Arch Linux workstation.

It is aimed at machines like:
- high-core-count desktops and workstations
- large-RAM development hosts
- mixed GUI + terminal + browser + container workloads
- fast WAN links where `bbr` is useful

## 1. Keep the boot-time hardening flags

Recommended kernel command line baseline:

```text
slab_nomerge init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 pti=on randomize_kstack_offset=on vsyscall=none
```

Notes:
- Keep CPU microcode installed and updated.
- Keep Secure Boot enabled if your workflow supports it.
- Avoid adding low-value “performance” flags unless you have measured a real bottleneck.

## 2. Keep swap enabled

Do not run a large workstation swapless.

Recommended baseline:
- Keep a real swap partition or swap file.
- Optionally add zram for burst absorption on developer workstations.
- Pair low swap pressure with enough swap capacity rather than setting `vm.swappiness=0`.

Why:
- Prevents sudden OOM conditions during builds, browsers, VMs, containers, and large link steps.
- Makes `vm.overcommit_memory=0` practical on mixed workloads.

## 3. Transparent Huge Pages: prefer `madvise`

For mixed workstation/server use, `madvise` is usually the least risky default.

Recommended runtime policy:

```bash
cat /sys/kernel/mm/transparent_hugepage/enabled
cat /sys/kernel/mm/transparent_hugepage/defrag
```

Target:
- `enabled`: `madvise`
- `defrag`: `defer+madvise` or `madvise`

Why:
- Avoids worst-case latency spikes from always-on THP.
- Still allows databases, runtimes, and allocators that request THP to benefit.

## 4. Enable `irqbalance` unless you manually tune IRQ affinity

Recommended:

```bash
sudo systemctl enable --now irqbalance.service
```

Why:
- Sensible default on many-core systems.
- Helps spread NIC, NVMe, USB, and miscellaneous interrupt load without manual pinning.

Skip it only if you are explicitly managing IRQ affinity yourself.

## 5. Use a sane CPU scaling policy

For a general-purpose workstation:
- Use the default modern scheduler governor (`schedutil`) unless you have benchmarked a better alternative.
- Use `performance` only for dedicated benchmark, rendering, or lab systems where idle efficiency does not matter.

Check current state:

```bash
cpupower frequency-info
```

Why:
- Avoids pinning 128 threads at unnecessarily high clocks all day.
- Keeps interactive responsiveness without wasting thermal headroom.

## 6. Keep `systemd-oomd` policy intentional

Recommended approach:
- Leave `systemd-oomd` enabled for user sessions if you use a desktop environment.
- Do not blindly disable it globally.
- If you run large builds or local databases, tune service-level memory limits and `ManagedOOM*` policies instead of disabling OOM protection entirely.

Why:
- On GUI systems, memory pressure handling is often better with proactive user-session killing than with a hard kernel OOM event.

## 7. Prefer `fq + bbr` over ad-hoc socket inflation

Your sysctl profile already sets:
- `net.core.default_qdisc = fq`
- `net.ipv4.tcp_congestion_control = bbr`

Complementary guidance:
- Do not stack random NIC/socket tuning from internet guides unless you have packet captures or throughput data.
- Increase MTU only when your full path supports it.
- Change offloads only when troubleshooting a measured problem.

Useful checks:

```bash
ss -ti
ip -s link
ethtool -k <iface>
```

## 8. Keep firewall policy explicit

A workstation still benefits from a default-deny inbound firewall.

Recommended baseline:
- nftables enabled
- inbound default drop/reject
- outbound allow
- explicit exceptions for SSH, WireGuard, Tailscale, Syncthing, local development, or LAN services you intentionally expose

Why:
- Hardening is weakest when workstation exceptions quietly accumulate.

## 9. Keep coredumps and logs bounded

Recommended:
- Keep `fs.suid_dumpable = 0`.
- Decide whether you want `systemd-coredump` enabled on workstations.
- Set journald size limits to avoid log creep on long-lived systems.

Suggested journald review:

```bash
sudo editor /etc/systemd/journald.conf
```

Good starting points:
- `SystemMaxUse=1G`
- `RuntimeMaxUse=256M`
- `MaxRetentionSec=1month`

## 10. Containers and browser sandboxing: decide on user namespaces early

This is the main hardening tradeoff for desktop Arch systems.

If you need:
- Flatpak
- bubblewrap
- rootless Podman/Docker
- browser sandboxes depending on unprivileged user namespaces

then keep:

```conf
kernel.unprivileged_userns_clone = 1
```

If you prioritize hardening over those workflows, uncomment the stricter option in [`99-workstation-net.conf`](./99-workstation-net.conf):

```conf
kernel.unprivileged_userns_clone = 0
```

## 11. NVIDIA-specific note

On NVIDIA workstations:
- keep the proprietary driver current
- keep `nvidia-drm.modeset=1` if you want proper Wayland/KMS behavior
- avoid random PCIe, power-management, or interrupt tweaks without reproducing a real issue first

Performance tuning that usually matters more than sysctl here:
- compositor settings
- VRR/G-SYNC behavior
- power limits / thermal tuning
- CUDA toolkit / runtime alignment

## 12. Storage and filesystems

For a workstation, avoid cargo-cult mount options.

Practical baseline:
- keep `relatime` unless you have a measured reason to change it
- use `noatime` only if your workload benefits and you understand the tradeoff
- ensure TRIM/discard policy matches your storage and encryption design
- keep filesystem scrubs and SMART monitoring in place

## 13. What to benchmark after applying the profile

Validate changes with data, not vibes.

Recommended checks:

```bash
grep -E 'CommitLimit|Committed_AS' /proc/meminfo
free -h
sysctl vm.overcommit_memory vm.min_free_kbytes kernel.pid_max
sysctl net.core.default_qdisc net.ipv4.tcp_congestion_control
systemd-analyze blame
ss -s
```

Workload tests to care about:
- browser + IDE + terminal + local database open together
- `cargo build`, `npm install`, kernel compile, or your real dev build
- large file copies to NVMe
- WAN download/upload on your actual link
- container startup bursts

## 14. Recommended package/service baseline

Good companion components for a hardened Arch workstation:
- `irqbalance`
- `nftables`
- `systemd-oomd`
- `smartmontools`
- `fwupd`
- `reflector` or your preferred mirror maintenance workflow
- microcode package (`amd-ucode` or `intel-ucode`)

Optional, depending on workflow:
- `zram-generator`
- `powertop`
- `cpupower`
- `ethtool`
- `sysstat`

## 15. Suggested policy summary

For most secure, high-performance desktop/workstation builds:
- keep swap
- use `THP=madvise`
- enable `irqbalance`
- keep `fq + bbr`
- keep inbound firewall closed by default
- keep journald bounded
- keep user namespaces enabled unless you explicitly want the stricter tradeoff

That gives you a better day-2 workstation profile than trying to push more and more behavior into `sysctl` alone.
