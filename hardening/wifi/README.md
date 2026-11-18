# Wi-Fi Hardening (MAC privacy + WPA3)

Tightens NetworkManager and iwd defaults so probe requests stop leaking the burned-in MAC, and offers an **opt-in** WPA3-Personal (SAE) path. It does not globally force WPA3.

```bash
sudo ./wifi.sh                         # Scan randomization + stable-per-SSID MAC (NM stable, iwd network + full range)
sudo ./wifi.sh --random-mac            # Randomize MAC (NM per-association random; iwd per-boot once)
sudo ./wifi.sh --wpa3-template         # SAE-only NM template (pmf=3; preserves existing UUID & MAC policy)
sudo ./wifi.sh --wpa3-connection Home  # Flip one saved connection to SAE + pmf=3 (preserves cloned-mac unless --random-mac)
sudo ./wifi.sh --status
```

The installer-owned `/etc/NetworkManager/conf.d/00-privacy.conf` is left intact. This module writes `20-wifi-hardening.conf` and sets `AddressRandomizationRange=full` under `[General]` in `/etc/iwd/main.conf` (restarting `iwd` automatically when active if `/etc/iwd/main.conf` changed).

- **Default mode** keeps NetworkManager `wifi.cloned-mac-address=stable` and `iwd` `AddressRandomization=network` (deterministic random MAC per SSID, so home DHCP reservations keep working).
- **`--random-mac`** sets NetworkManager `wifi.cloned-mac-address=random` (new MAC per association on `wpa_supplicant`) and `iwd` `AddressRandomization=once` (new random MAC per boot / interface creation; `iwd` supports `network` or `once` rather than per-association rotation).
- Running `--wpa3-template` or `--wpa3-connection` without `--random-mac` preserves any existing `cloned-mac-address` / `AddressRandomization` configuration and enforces Protected Management Frames (`pmf=3` / `wifi-sec.pmf 3`).

## Gotchas

- Do not set `key-mgmt=sae` as a global NM default. WPA2-only APs will refuse association.
- The bare-metal installer pins `wifi.backend=iwd`. This script does not change the backend; note that when `iwd` is the active backend, MAC generation follows `iwd`'s `AddressRandomization` (`network` per-SSID or `once` per-boot).
- Enterprise / 802.1X is a different `key-mgmt`. This script does not touch those profiles.

Revert a connection with `nmcli connection modify Home wifi-sec.key-mgmt wpa-psk wifi-sec.pmf 2`.

## References

- [ArchWiki: NetworkManager](https://wiki.archlinux.org/title/NetworkManager)
- [ArchWiki: iwd](https://wiki.archlinux.org/title/Iwd)
