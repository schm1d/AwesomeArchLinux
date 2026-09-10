# NVMe controller dropouts with signed UKIs

Use `nvme-stability.py` to test the Linux NVMe driver's suggested workaround for
controllers that disappear, fail a reset, and cause ext4 journals to abort:

```text
nvme_core.default_ps_max_latency_us=0 pcie_aspm=off pcie_port_pm=off
```

This is an opt-in diagnostic workaround, not proof that an SSD is healthy.
Successful use under Windows does not exclude hardware, cooling, or firmware
problems. Secure Boot authenticates boot images; it does not normally disconnect
an NVMe controller during a running session.

## Apply to an existing AwesomeArchLinux UKI install

First preserve important data on a separate healthy device and read the system
SSD's health report. Map the root volume with `lsblk` rather than assuming that
NVMe numbering stays the same between boots:

```bash
lsblk -o NAME,TYPE,SIZE,MODEL,FSTYPE,MOUNTPOINTS
sudo smartctl -x /dev/nvme0
sudo nvme error-log /dev/nvme0 -e 16
python3 utils/nvme-stability.py --status
sudo python3 utils/nvme-stability.py --apply
```

`/dev/nvme0` is a valid controller device for these tools. If it disappears during
a failure, changing to `/dev/nvme0n1` does not repair that controller.

The utility supports the project's `linux.preset` with default and fallback UKIs
at `/efi/EFI/Linux/arch-linux{,-fallback}.efi`, an empty default options value, and
fallback options `-S autodetect`. It requires Python 3, mkinitcpio, sbctl and the
existing signing keys. It refuses other preset layouts rather than guessing
which images will boot.

The utility preserves other command-line options, including LUKS, LVM, TPM and
kernel hardening. It saves the original command line and both signed UKIs under
`/var/lib/awesomearch/nvme-stability/backup-*`, builds new images in that directory,
and verifies the embedded arguments and sbctl signatures before replacing the
boot files. Signature checks use temporary copies on the ESP, outside the boot
entry directory, to respect sbctl's Landlock sandbox. Boot files are replaced
atomically one at a time. A failed install
attempts to restore the original images and command line. A failed build or
signature check leaves the installed boot files unchanged. A physical drive
failure can still prevent recovery; the on-disk copies are not a data backup.

Existing Secure Boot keys and TPM enrollment are retained. No reboot is automatic.
Have the LUKS passphrase or recovery key available: TPM policies bound to changed
measurements, such as PCR 11, may require it after a UKI rebuild. Do not erase or
re-enroll TPM tokens merely to test this workaround.

After reboot:

```bash
python3 utils/nvme-stability.py --status
sudo sbctl verify /efi/EFI/Linux/arch-linux.efi /efi/EFI/Linux/arch-linux-fallback.efi
journalctl -k -b --no-pager -g 'nvme|I/O error|aborted journal|Remounting filesystem'
```

All three parameters should be active, and the NVMe default latency should be
`0`. Observe normal use and suspend/resume before calling the issue resolved.
An error-free boot alone is insufficient. If the system disk disappears, the
last error messages may never reach its persistent journal.

The utility prints a `--restore BACKUP` command. This restores the entire saved
command line, rebuilding and signing UKIs with the currently installed kernel;
it uses the same staging and failure recovery as installation. Review any later
command-line changes before restoring an older backup.

## Temperature and remaining diagnosis

Disabling APST and PCIe port power management can raise idle power and temperature.
`pcie_aspm=off` means Linux leaves firmware ASPM configuration unchanged; it is
not a guarantee that firmware-enabled ASPM is disabled. It affects PCIe globally.

In the September 10, 2026 incident, the screenshot shows `nvme0` disabled after
a reset failure (`-19`), followed by I/O errors and aborted journals on multiple
LVM volumes. The surviving local journal records the system NVMe reaching 78 C
on September 8; current temperatures were approximately 64–69 C. This makes
cooling inspection relevant alongside the power-management test: check heatsink
contact, thermal pads and airflow with the machine powered off. Do not raise
SMART alert limits to hide the heat.

The system SSD's subsequent SMART report showed 0 media/data-integrity errors,
100% available spare, 3% life used, and self-tests aborted by controller resets.
The two populated error-log entries reported invalid command fields, not media
read/write failures. Its firmware reported warning/critical composite temperature
thresholds of 90/95 C and zero accumulated time above those thresholds. These
readings support testing controller power management but do not establish the
cause of the dropouts.

If dropouts persist, collect SMART critical warnings, media errors, thermal
warning time, the NVMe error log, firmware revision, and the first controller
failure messages. A clean SMART report does not rule out a PCIe link or controller
fault. Check vendor firmware availability and consider a supported LTS kernel
as separate tests; keep changes isolated enough to determine which helps.

## Check affected ext4 volumes offline

The workaround does not repair filesystem damage from failed writes. After a
backup and once the controller is stable, boot trusted recovery media, identify
the correct LUKS device by UUID, unlock it, and activate only its volume group.
Keep the filesystems unmounted:

```bash
lsblk -f
cryptsetup open /dev/disk/by-uuid/<LUKS-UUID> crypt_lvm
vgchange -ay lvm_arch
lsblk -o NAME,FSTYPE,MOUNTPOINTS
e2fsck -f -n /dev/mapper/lvm_arch-root
e2fsck -f -n /dev/mapper/lvm_arch-home
e2fsck -f -n /dev/mapper/lvm_arch-var
e2fsck -f -n /dev/mapper/lvm_arch-tmp
```

Replace `<LUKS-UUID>` and confirm the VG/LV names first. Run these checks only
when **all listed ext4 volumes are unmounted**. The `-n` checks make no repairs;
review their results before running interactive `e2fsck -f` on a stable device.
Do not run filesystem repair against the raw LUKS partition or force a failed
mounted filesystem back to read-write.

References: [Linux NVMe reset diagnostic](https://github.com/torvalds/linux/blob/master/drivers/nvme/host/pci.c),
[kernel PCIe parameters](https://docs.kernel.org/admin-guide/kernel-parameters.html),
[systemd-stub and embedded command lines](https://github.com/systemd/systemd/blob/main/man/systemd-stub.xml),
[sbctl signature verification](https://github.com/Foxboron/sbctl/blob/master/cmd/sbctl/verify.go).
