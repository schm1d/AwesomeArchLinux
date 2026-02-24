# WireGuard VPN Server Setup for Arch Linux

Automated WireGuard VPN server provisioning with hardened defaults, nftables integration, pre-shared keys for quantum resistance, and QR code generation for mobile clients.

## Quick Start

```bash
# Default setup: 1 client, port 51820, subnet 10.0.0.0/24, Quad9 DNS
sudo ./wireguard.sh

# Custom setup: 5 clients, custom port and subnet
sudo ./wireguard.sh -p 443 -s 172.16.0.0/24 -n 5 -c phone

# Use Cloudflare DNS instead of Quad9
sudo ./wireguard.sh -d 1.1.1.1,1.0.0.1
```

## Usage

```
sudo ./wireguard.sh [-p PORT] [-s SUBNET] [-c CLIENT_NAME] [-n NUM_CLIENTS] [-d DNS] [-h]
```

| Flag | Default | Description |
|------|---------|-------------|
| `-p PORT` | `51820` | WireGuard listen port (UDP) |
| `-s SUBNET` | `10.0.0.0/24` | VPN subnet in CIDR notation |
| `-c CLIENT_NAME` | `client` | Base name for client config files |
| `-n NUM_CLIENTS` | `1` | Number of client configs to generate |
| `-d DNS` | `9.9.9.9,149.112.112.112` | DNS servers pushed to clients (Quad9) |
| `-h` | | Show help |

## What the Script Does

1. **Installs packages** -- `wireguard-tools`, `qrencode` via pacman
2. **Enables IP forwarding** -- writes `/etc/sysctl.d/99-wireguard.conf` with `net.ipv4.ip_forward=1` and `net.ipv6.conf.all.forwarding=1`
3. **Generates server keys** -- private and public keys in `/etc/wireguard/`
4. **Creates server config** -- `/etc/wireguard/wg0.conf` with nftables PostUp/PostDown rules
5. **Generates client configs** -- each with its own private key, public key, and pre-shared key
6. **Adds clients as peers** -- `[Peer]` sections appended to `wg0.conf`
7. **Sets strict permissions** -- `600` on all keys and configs, `root:root` ownership
8. **Creates nftables include** -- `/etc/nftables.d/wireguard.conf` with firewall and NAT rules
9. **Enables the service** -- `wg-quick@wg0` enabled and started via systemd
10. **Displays QR codes** -- scannable from the WireGuard mobile app

## File Layout

```
/etc/wireguard/
  wg0.conf                  # Server config (Interface + Peers)
  server_private.key
  server_public.key
  client_private.key         # Per-client key files
  client_public.key
  client_preshared.key
  clients/
    client.conf              # Client tunnel config (ready to import)
    client2.conf
    ...

/etc/nftables.d/
  wireguard.conf             # nftables rules (include in main config)

/etc/sysctl.d/
  99-wireguard.conf          # IP forwarding settings
```

## Adding More Clients

After the initial setup, you can add clients manually:

```bash
# Generate keys
wg genkey | tee /etc/wireguard/newclient_private.key | wg pubkey > /etc/wireguard/newclient_public.key
wg genpsk > /etc/wireguard/newclient_preshared.key
chmod 600 /etc/wireguard/newclient_*.key

# Determine the next available IP in your subnet
# (check existing peers in wg0.conf to avoid conflicts)
CLIENT_IP="10.0.0.5"

# Read keys
CLIENT_PRIVKEY=$(cat /etc/wireguard/newclient_private.key)
CLIENT_PUBKEY=$(cat /etc/wireguard/newclient_public.key)
PSK=$(cat /etc/wireguard/newclient_preshared.key)
SERVER_PUBKEY=$(cat /etc/wireguard/server_public.key)

# Add peer to server config
cat >> /etc/wireguard/wg0.conf <<EOF

# Peer: newclient
[Peer]
PublicKey = $CLIENT_PUBKEY
PresharedKey = $PSK
AllowedIPs = ${CLIENT_IP}/32
EOF

# Create client config
cat > /etc/wireguard/clients/newclient.conf <<EOF
[Interface]
Address = ${CLIENT_IP}/32
PrivateKey = $CLIENT_PRIVKEY
DNS = 9.9.9.9,149.112.112.112

[Peer]
PublicKey = $SERVER_PUBKEY
PresharedKey = $PSK
Endpoint = YOUR_SERVER_IP:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

chmod 600 /etc/wireguard/clients/newclient.conf

# Reload WireGuard (no downtime for existing peers)
wg syncconf wg0 <(wg-quick strip wg0)

# Generate QR code
qrencode -t ansiutf8 < /etc/wireguard/clients/newclient.conf
```

## Revoking Clients

To revoke a client's access:

```bash
# 1. Remove the [Peer] section from wg0.conf
#    Find and delete the block matching the client's PublicKey.
#    You can identify the client by their public key or comment.

# 2. Reload the running config without restarting
wg syncconf wg0 <(wg-quick strip wg0)

# 3. Remove client files (optional but recommended)
rm /etc/wireguard/clients/clientname.conf
rm /etc/wireguard/clientname_private.key
rm /etc/wireguard/clientname_public.key
rm /etc/wireguard/clientname_preshared.key

# 4. Verify the peer is gone
wg show wg0
```

**Note:** Since WireGuard uses public-key authentication, removing the `[Peer]` entry from the server config is sufficient to deny access. The client will no longer be able to complete the handshake.

## nftables Integration

The script creates `/etc/nftables.d/wireguard.conf` with three rule sets:

- **Input filter** -- allows UDP traffic on the WireGuard port
- **Forward filter** -- allows packet forwarding through the `wg0` interface
- **NAT masquerade** -- rewrites source addresses for VPN traffic leaving the default interface

### Including in Your Main Config

Add this line to `/etc/nftables.conf`:

```
include "/etc/nftables.d/wireguard.conf"
```

Then reload:

```bash
nft -f /etc/nftables.conf
```

### Standalone nftables (if not using includes)

If you manage nftables differently, here are the equivalent manual rules (replace `eth0` with your interface and `51820` with your port):

```bash
# Allow WireGuard UDP port
nft add rule inet filter input udp dport 51820 accept

# Allow forwarding for wg0
nft add rule inet filter forward iifname "wg0" accept
nft add rule inet filter forward oifname "wg0" accept

# NAT masquerade
nft add table ip nat
nft add chain ip nat postrouting { type nat hook postrouting priority 100 \; }
nft add rule ip nat postrouting oifname "eth0" masquerade
```

### Coexistence with the PostUp/PostDown Rules

The server config (`wg0.conf`) includes its own `PostUp`/`PostDown` nftables rules that create a separate `ip wireguard` table for NAT. This is independent from the include file in `/etc/nftables.d/`. You have two options:

1. **Use both** -- the `PostUp` rules handle NAT dynamically when WireGuard starts/stops, while the include file provides persistent firewall rules for input and forwarding. This is the recommended approach.

2. **Use only the include file** -- remove the `PostUp`/`PostDown` lines from `wg0.conf` and rely entirely on the persistent nftables config. Make sure to reload nftables when the system boots.

## Mobile Setup (iOS / Android)

### Using QR Code (Recommended)

1. Install the **WireGuard** app from the App Store or Play Store.
2. Open the app and tap **+** (Add a tunnel).
3. Select **Create from QR code**.
4. Scan the QR code displayed by the setup script.
5. Name the tunnel (e.g., "Home VPN") and activate it.

### Using Config File

1. Securely transfer the `.conf` file to your device:
   - `scp /etc/wireguard/clients/client.conf user@phone:/tmp/` (then AirDrop/share)
   - Or use a temporary secure sharing method
2. Open the WireGuard app.
3. Tap **+** > **Import from file or archive**.
4. Select the `.conf` file.
5. Activate the tunnel.

### Verifying the Connection

After activating the tunnel on your device:

```bash
# On the server, check the peer's latest handshake
wg show wg0

# You should see a recent handshake timestamp and transfer data
# for the connected client
```

On the client device, visit [https://www.dnsleaktest.com](https://www.dnsleaktest.com) to verify:
- Your IP shows as the server's public IP
- DNS queries go through the configured DNS servers (Quad9 by default)

## Split Tunnel Configuration

The default client config routes **all traffic** through the VPN (`AllowedIPs = 0.0.0.0/0, ::/0`). To only route specific subnets (split tunnel), edit the client config:

```ini
[Peer]
# Only route the VPN subnet and a specific remote network
AllowedIPs = 10.0.0.0/24, 192.168.1.0/24
```

This is useful when you only need access to resources on the VPN network without routing all internet traffic through the server.

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Handshake never completes | Check that UDP port is open and forwarded. Verify `Endpoint` IP is correct. |
| Connected but no internet | Verify IP forwarding: `sysctl net.ipv4.ip_forward`. Check NAT rules: `nft list ruleset`. |
| DNS not resolving | Ensure the `DNS` line in client config is correct. Try `1.1.1.1` to rule out Quad9 issues. |
| `wg-quick` fails to start | Check `journalctl -xeu wg-quick@wg0`. Common cause: syntax error in `wg0.conf`. |
| "Address already in use" | Another WireGuard instance is running. Stop it: `systemctl stop wg-quick@wg0`. |
| Slow performance | Try a different port (some ISPs throttle UDP 51820). Use `-p 443` for better results. |

## Security Notes

- **Pre-shared keys** are generated for every client, providing an additional layer of symmetric encryption on top of the Curve25519 key exchange. This offers defense-in-depth against potential future quantum computing attacks on elliptic curve cryptography.
- All key files and configs are set to mode `600` (owner read/write only) with `root:root` ownership.
- `SaveConfig = false` prevents WireGuard from overwriting your carefully crafted config on shutdown.
- The server's `PostDown` rule automatically cleans up NAT rules when WireGuard stops.
- **Never transmit private keys or config files over unencrypted channels.** Use QR codes, `scp`, or another encrypted method.
