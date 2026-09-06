# Wi-Fi Hardening (MAC privacy + WPA3)

Tightens NetworkManager and iwd defaults so probe requests stop leaking the burned-in MAC, and offers an **opt-in** WPA3-Personal (SAE) path. It does not globally force WPA3.

```bash
sudo ./wifi.sh                         # Scan randomization + stable-per-SSID cloned MAC
sudo ./wifi.sh --random-mac            # New MAC on every association
sudo ./wifi.sh --wpa3-template         # SAE-only NM template
sudo ./wifi.sh --wpa3-connection Home  # Flip one saved connection to SAE
sudo ./wifi.sh --status
```

The installer-owned `/etc/NetworkManager/conf.d/00-privacy.conf` is left intact. This module writes `20-wifi-hardening.conf`. Associated MACs stay `stable` unless you pass `--random-mac`, so home DHCP reservations keep working.

## Gotchas

- Do not set `key-mgmt=sae` as a global NM default. WPA2-only APs will refuse association.
- The bare-metal installer pins `wifi.backend=iwd`. This script does not change the backend.
- Enterprise / 802.1X is a different `key-mgmt`. This script does not touch those profiles.

Revert a connection with `nmcli connection modify Home wifi-sec.key-mgmt wpa-psk`.

## References

- [ArchWiki: NetworkManager](https://wiki.archlinux.org/title/NetworkManager)
- [ArchWiki: iwd](https://wiki.archlinux.org/title/Iwd)
