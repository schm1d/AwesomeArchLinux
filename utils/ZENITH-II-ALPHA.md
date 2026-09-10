# ASUS ROG Zenith II Extreme Alpha on Linux

The supported profile requires both exact DMI strings:

```text
board_vendor = ASUSTeK COMPUTER INC.
board_name   = ROG ZENITH II EXTREME ALPHA
```

The original Zenith Extreme Alpha (X399), Zenith II Extreme without Alpha, and
generic ASUS machines do not match. Detection uses motherboard fields because
this machine's product name is the generic `System Product Name`.

## Automatic addition: thermal monitoring

The bare-metal installer enables `awesome-board-health.timer` on a matching
board. Existing installations can enable the same profile:

```bash
python3 utils/board-health.py --status
sudo python3 utils/board-health.py --install
systemctl status awesome-board-health.timer
journalctl -u awesome-board-health.service -p warning
```

The timer starts two minutes after boot, then samples every minute. It reads
kernel hwmon interfaces using a sandboxed dynamic user. It records CPU Tctl,
chipset, VRM, NVMe temperatures, and the ASUS fan readings in the journal. No fan
control or kernel tuning is performed. ASUS's in-kernel `asus_ec_sensors` driver
already matches this board through DMI and uses the firmware's ACPI mutex; extra
out-of-tree sensor drivers and forced resource access are unnecessary.

Operational warning thresholds are configurable in
`/etc/awesome-board-health.conf`:

| Sensor | Initial warning policy |
|---|---:|
| NVMe | 70 C |
| CPU Tctl | 85 C |
| Chipset | 85 C |
| VRM | 90 C |

These are conservative monitoring policy values, **not ASUS/AMD maximum ratings**.
A warning needs two consecutive samples. Recovery requires a reading more than
3 C below the warning threshold. Persistent warnings repeat every 30 minutes.
Missing fitted sensors, including an NVMe sensor that was previously visible,
also raise warnings after two samples. A missing sensor is a diagnostic clue,
not proof of a hardware failure. Missing ASUS sensors can mean the driver has
not loaded; inspect `journalctl -k -g 'asus|EC|mutex'` before changing drivers.

Optional water/temperature headers often report -40 C when disconnected. They
are excluded from temperature alarms. Zero CPU_Opt, VRM HS or water-flow RPM
alone does not establish a fan failure: those readings are logged without a
failure alarm. Fan controllers such as a Corsair Commander Pro are separate
devices; their fan curves remain under their existing controller.

Each invocation reads current threshold settings, so changing thresholds does
not require a service restart. Monitoring does not poll SMART health counters;
the existing `smartd` service retains that job. This timer makes short thermal
events easier to see alongside controller failures. Minute sampling can still
miss brief events, and NVMe sensor reads can wake an idle controller.

To disable the addition:

```bash
sudo systemctl disable --now awesome-board-health.timer
sudo systemctl stop awesome-board-health.service
```

For full removal, also remove these profile-owned files and reload systemd:

```bash
sudo rm /etc/systemd/system/awesome-board-health.service /etc/systemd/system/awesome-board-health.timer
sudo rm /usr/local/bin/awesome-board-health /etc/awesome-board-health.conf
sudo systemctl daemon-reload
```

## Findings on this machine, September 10, 2026

- Ryzen Threadripper 3990X, 64 cores / 128 threads.
- BIOS reports **2502**, build date **2025-10-14**. ASUS's support page lists
  2502 as its newest release, published **2026-01-21**. Build and publication
  dates differ; the date difference alone is not a reason to reflash.
- `amd-pstate-epp` is active, governor `powersave`, EPP `balance_performance`.
  In this mode `powersave` still permits dynamic frequency scaling and boost.
  Keep this baseline while diagnosing storage. A mandatory `performance`
  governor or disabled CPU idle states could add heat without fixing NVMe.
- IOMMU and interrupt remapping are enabled. No `iommu=pt`, IOMMU disabling or
  ACS override is justified by the current evidence.
- Native `asus_ec_sensors` and `k10temp` are loaded. Chipset measured **83 C**,
  VRM **60 C**, CPU Tctl about **74 C**, and NVMe drives **64–66 C** during the
  inspection. The chipset fan read approximately **4,568 RPM**. These snapshots
  establish a baseline; they do not establish the cause of the SSD dropouts.
- Firmware emits ACPI namespace/package errors. Avoid masking them with
  `acpi=off`, `acpi_osi=` guesses or `acpi_enforce_resources=lax`.

## Separate, evidence-driven changes

The [NVMe stability workaround](NVME-STABILITY.md) remains opt-in, including on
this motherboard. Board identity alone does not establish a power-state bug.
Keep the current experiment unchanged until it has been tested after reboot.

If the controller still drops out with all three workaround parameters active,
inspect the BIOS's PCIe/ASPM configuration: `pcie_aspm=off` leaves firmware's
ASPM configuration unchanged. A manual firmware change is a separate test.

With the box off, inspect chipset and M.2 airflow, dust, fan operation and thermal
pad contact. Review Q-Fan settings in UEFI rather than writing arbitrary PWM
values from Linux. If failures persist, consider vendor SSD firmware, a supported
LTS kernel and a different M.2 slot as separate tests. Pinning an affected slot
to PCIe Gen3 is a diagnostic experiment with a throughput cost, not a default
for every installation of this board. Kernel/driver bugs remain possible.

Keep Secure Boot and existing TPM enrollment. ASUS's 2502 notes describe an fTPM
firmware update, so any future BIOS update needs appropriate disk-encryption
recovery preparation; this profile does not flash firmware or re-enroll keys.

Sources:

- [ASUS BIOS releases for this exact board](https://www.asus.com/us/supportonly/rog%20zenith%20ii%20extreme%20alpha/helpdesk_bios/)
- [Linux ASUS EC sensor driver](https://docs.kernel.org/hwmon/asus_ec_sensors.html)
- [Exact DMI match and sensor set in the kernel](https://github.com/torvalds/linux/blob/master/drivers/hwmon/asus-ec-sensors.c)
- [AMD P-State operation and EPP](https://docs.kernel.org/admin-guide/pm/amd-pstate.html)
- [Kernel PCIe parameters](https://docs.kernel.org/admin-guide/kernel-parameters.html)
