# Memory Encryption (AMD SME / Intel TME)

Opt-in only. The installer never injects `mem_encrypt=on`.

```bash
sudo ./memcrypt.sh              # Probe CPU flags and current state
sudo ./memcrypt.sh --enable     # AMD SME only, after firmware is on
sudo ./memcrypt.sh --disable
```

| Feature | Vendor | How it turns on |
|---------|--------|-----------------|
| SME | AMD | Firmware switch **and** `mem_encrypt=on` |
| SEV / SEV-SNP | AMD | Hypervisor + guest policy (not a desktop host feature) |
| TME | Intel | Firmware only. No portable kernel cmdline |

## Why this is not in the installer

- Firmware left off + `mem_encrypt=on` = panic or silent ignore, depending on generation.
- SME costs RAM bandwidth and commonly breaks VFIO / GPU passthrough.
- LUKS + optional fscrypt already cover data-at-rest. SME covers physical DIMM extraction.

## References

- [AMD Memory Encryption](https://docs.kernel.org/arch/x86/amd-memory-encryption.html)
- [Intel TME](https://www.intel.com/content/www/us/en/architecture-and-technology/total-memory-encryption.html)
