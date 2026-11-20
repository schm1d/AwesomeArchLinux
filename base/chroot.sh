#!/usr/bin/env bash

# Description: This is the chroot script for Arch Linux installation.
# Author: Bruno Schmid @brulliant
# LinkedIn: https://www.linkedin.com/in/schmidbruno/

set -euo pipefail
umask 022
source /root/.install-env || { echo "Failed to source /root/.install-env"; exit 1; }
# shellcheck source=bootloader.sh
source /bootloader.sh || { echo "Failed to source /bootloader.sh"; exit 1; }

# Set up the variables
BBlue='\033[1;34m'
BRed='\033[1;31m'
BGreen='\033[1;32m'
BYellow='\033[1;33m'
NC='\033[0m'

# Ensure the script is run as root
if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root" >&2
  exit 1
fi

# --- These values MUST be supplied by archinstall.sh ---
# The persisted install environment uses INSTALL_* while the one-shot chroot
# handoff historically used _INSTALL_*. Accept both so /root/.install-env is
# sufficient when recovering or deliberately rerunning this script.
DISK="${INSTALL_DISK:-${_INSTALL_DISK:-}}"       # Example: /dev/sda or /dev/nvme0n1
USERNAME="${INSTALL_USER:-${_INSTALL_USER:-}}" # Example: myuser
HOSTNAME="${INSTALL_HOST:-${_INSTALL_HOST:-}}" # Example: myhostname
: "${DISK:?Missing INSTALL_DISK/_INSTALL_DISK}"
: "${USERNAME:?Missing INSTALL_USER/_INSTALL_USER}"
: "${HOSTNAME:?Missing INSTALL_HOST/_INSTALL_HOST}"
# shellcheck disable=SC2034  # Cross-script env vars from installer
TIMEZONE="${INSTALL_TIMEZONE:-${_INSTALL_TIMEZONE:-UTC}}"
# shellcheck disable=SC2034
LOCALE="${INSTALL_LOCALE:-${_INSTALL_LOCALE:-en_US.UTF-8}}"
# shellcheck disable=SC2034
KEYMAP="${INSTALL_KEYMAP:-${_INSTALL_KEYMAP:-us}}"
LUKS_KEYS="${INSTALL_LUKS_KEYS:-${_INSTALL_LUKS_KEYS:-/etc/luksKeys/boot.key}}" # Location of the root partition key
SSH_PORT="${INSTALL_SSH_PORT:-${_INSTALL_SSH_PORT:-22}}"
SSH_PUBKEY="${INSTALL_SSH_PUBKEY:-${_INSTALL_SSH_PUBKEY:-}}"
# shellcheck disable=SC2034  # Consumed by sourced bootloader.sh functions.
CRYPT_NAME="${INSTALL_CRYPT:-${_INSTALL_CRYPT:-crypt_lvm}}"
# shellcheck disable=SC2034  # Consumed by sourced bootloader.sh functions.
LVM_NAME="${INSTALL_LVM:-${_INSTALL_LVM:-lvm_arch}}"
INSTALL_TPM="${INSTALL_TPM:-${_INSTALL_TPM:-false}}"
SYSCTL_PROFILE="${INSTALL_SYSCTL_PROFILE:-${_INSTALL_SYSCTL_PROFILE:-workstation}}"
SYSCTL_DISABLE_IPV6="${INSTALL_DISABLE_IPV6:-${_INSTALL_DISABLE_IPV6:-false}}"
INSTALL_BOOTLOADER="${INSTALL_BOOTLOADER:-${_INSTALL_BOOTLOADER:-}}"
: "${INSTALL_BOOTLOADER:?Missing INSTALL_BOOTLOADER/_INSTALL_BOOTLOADER}"
# shellcheck disable=SC2034  # Consumed by sourced bootloader.sh functions.
TPM_PCRS="${INSTALL_TPM_PCRS:-${_INSTALL_TPM_PCRS:-7}}"
INSTALL_GPU_UNLOCK="${INSTALL_GPU_UNLOCK:-${_INSTALL_GPU_UNLOCK:-false}}"
GPU_UNLOCK_TARGETS="${INSTALL_GPU_UNLOCK_TARGETS:-${_INSTALL_GPU_UNLOCK_TARGETS:-all}}"
BOOT_EXTRA_CMDLINE=()

case "$INSTALL_GPU_UNLOCK" in
    true|false) ;;
    *)
        echo "Invalid INSTALL_GPU_UNLOCK value: $INSTALL_GPU_UNLOCK" >&2
        exit 1
        ;;
esac

case "$INSTALL_BOOTLOADER" in
    grub|uki) ;;
    *)
        echo "Invalid bootloader profile: $INSTALL_BOOTLOADER" >&2
        exit 1
        ;;
esac

case "$SYSCTL_DISABLE_IPV6" in
    true|false) ;;
    *)
        echo "Invalid IPv6 policy value: $SYSCTL_DISABLE_IPV6" >&2
        exit 1
        ;;
esac

# shellcheck source=lib/chroot-security.sh
source /usr/local/lib/awesomearchlinux/chroot-security.sh

# --- Other Variables ---
SSH_CONFIG_FILE="/home/$USERNAME/.ssh/config"
SSH_KEY_TYPE="ed25519"
SSH_KEY_FILE="/home/$USERNAME/.ssh/id_$SSH_KEY_TYPE"

# --- Partition Handling ---
if [[ "$DISK" =~ [0-9]$ ]]; then
    PART_SUFFIX="p"
else
    PART_SUFFIX=""
fi

#PARTITION1="${DISK}${PART_SUFFIX}1"
#PARTITION2="${DISK}${PART_SUFFIX}2"
PARTITION3="${DISK}${PART_SUFFIX}3"

# shellcheck disable=SC2034  # Consumed by sourced bootloader.sh functions.
LUKS_UUID=$(cryptsetup luksUUID "$PARTITION3")

CPU_VENDOR_ID=$(lscpu | awk -F: '/Vendor ID/{gsub(/^[ \t]+/, "", $2); print $2}')

# --- Basic System Configuration ---
pacman-key --init
pacman-key --populate archlinux

# Keep dirmngr aligned with the selected IPv6 policy.
mkdir -p /etc/gnupg
{
  if [[ "$SYSCTL_DISABLE_IPV6" == true ]]; then
    printf '%s\n' 'disable-ipv6'
  fi
  printf '%s\n' 'honor-http-proxy'
} > /etc/gnupg/dirmngr.conf

echo -e "${BBlue}Removing unnecessary users and groups...${NC}"
# games is a group on Arch, not a user — userdel not needed
groupdel games 2>/dev/null || true

# timedatectl requires systemd to be running; inside arch-chroot it isn't,
# so the call silently fails and /etc/localtime is never created. GLib-based
# apps (GNOME calendar, epiphany, anything using GDateTime) then assert on
# NULL timezone and misbehave. Use the classic symlink approach instead.
ln -sf "/usr/share/zoneinfo/$TIMEZONE" /etc/localtime
echo "$TIMEZONE" > /etc/timezone
hwclock --systohc --utc || echo -e "${BYellow}Warning: hwclock --systohc failed (RTC unavailable); continuing.${NC}"

sed -i -E "s/^#(${LOCALE//./\\.}[[:space:]])/\1/" /etc/locale.gen
locale-gen
echo "LANG=$LOCALE" > /etc/locale.conf
export LANG="$LOCALE"

cat > /etc/vconsole.conf <<VCEOF
KEYMAP=$KEYMAP
FONT=lat9w-16
FONT_MAP=8859-1_to_uni
VCEOF

# --- X11 keyboard configuration ---
# Translate vconsole keymap to X11 layout using systemd's kbd-model-map.
vconsole_to_x11() {
    local keymap="$1"
    local layout="" model="" variant="" line
    local map_file="/usr/share/systemd/kbd-model-map"

    if [[ -f "$map_file" ]]; then
        # Columns: consolelayout xlayout xmodel xvariant xoptions.
        # Match the first column (console keymap) exactly.
        line=$(awk -v km="$keymap" '!/^#/ && $1 == km { print; exit }' "$map_file")
        if [[ -n "$line" ]]; then
            layout=$(awk '{print $2}' <<< "$line")
            model=$(awk '{print $3}' <<< "$line")
            variant=$(awk '{print $4}' <<< "$line")
            # kbd-model-map uses "-" for an empty field
            [[ "$layout" == "-" ]] && layout=""
            [[ "$model" == "-" ]] && model=""
            if [[ "$variant" == '""' || "$variant" == "-" ]]; then
                variant=""
            fi
        fi
    fi

    # Fallback heuristics if map lookup failed
    if [[ -z "$layout" ]]; then
        case "$keymap" in
            *_*-*)
                # e.g. de_CH-latin1 -> layout=ch, variant=de
                layout="${keymap#*_}"
                layout="${layout%%-*}"
                layout="${layout,,}"
                variant="${keymap%%_*}"
                ;;
            *-*)
                # e.g. de-latin1 -> layout=de
                layout="${keymap%%-*}"
                variant=""
                ;;
            *)
                layout="$keymap"
                variant=""
                ;;
        esac
    fi

    # Variant last: it is the only field that may be empty.
    echo "$layout" "${model:-pc105}" "$variant"
}

echo -e "${BBlue}Writing X11 keyboard configuration...${NC}"
read -r X11_LAYOUT X11_MODEL X11_VARIANT <<< "$(vconsole_to_x11 "$KEYMAP")"
install -d /etc/X11/xorg.conf.d
{
    echo 'Section "InputClass"'
    echo '    Identifier "system-keyboard"'
    echo '    MatchIsKeyboard "on"'
    echo "    Option \"XkbLayout\" \"$X11_LAYOUT\""
    echo "    Option \"XkbModel\" \"${X11_MODEL:-pc105}\""
    if [[ -n "$X11_VARIANT" ]]; then
        echo "    Option \"XkbVariant\" \"$X11_VARIANT\""
    fi
    echo '    Option "XkbOptions" ""'
    echo 'EndSection'
} > /etc/X11/xorg.conf.d/00-keyboard.conf

# Set hostname
echo -e "${BBlue}Setting hostname...${NC}"
hostnamectl set-hostname "$HOSTNAME" 2>/dev/null || true
echo "$HOSTNAME" > /etc/hostname

echo -e "${BBlue}Configuring /etc/hosts...${NC}"
cat > /etc/hosts <<EOF
# Static table lookup for hostnames
# IPv4
127.0.0.1       localhost
127.0.1.1       $HOSTNAME.localdomain $HOSTNAME

# IPv6
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters

# Block some tracking domains at host level
0.0.0.0         googleadservices.com
0.0.0.0         google-analytics.com
0.0.0.0         doubleclick.net
0.0.0.0         facebook.com
0.0.0.0         www.facebook.com
EOF

# Set proper permissions
chmod 644 /etc/hosts
chown root:root /etc/hosts

echo -e "${BBlue}Configuring network parameters...${NC}"
# Create networkd configuration for better network management
mkdir -p /etc/systemd/network/

# Configure network hardening via networkd
cat > /etc/systemd/network/20-wired.network <<EOF
[Match]
Name=en*
Name=eth*

[Network]
DHCP=yes
DNSSEC=yes
# DNS-over-TLS is enforced by systemd-resolved via the drop-in at
# /etc/systemd/resolved.conf.d/dns-over-tls.conf — leave networkd unset
# so resolved remains the single source of truth for DoT.
DNSOverTLS=no
IPv6PrivacyExtensions=yes

[DHCPv4]
# systemd does not allow a comment after a value on the same line: the whole
# "no  # ..." string is rejected and the setting silently keeps its default.
# Don't accept DNS from DHCP
UseDNS=no
UseDomains=no
# Use our own NTP configuration
UseNTP=no

[DHCPv6]
UseDNS=no
UseNTP=no

[IPv6AcceptRA]
UseDNS=no
DHCPv6Client=no
EOF

# Configure NetworkManager with privacy settings (if installed)
if [ -d /etc/NetworkManager ]; then
    echo -e "${BBlue}Configuring NetworkManager privacy...${NC}"
    mkdir -p /etc/NetworkManager/conf.d/
    cat > /etc/NetworkManager/conf.d/00-privacy.conf <<EOF
[main]
# Use systemd-resolved
systemd-resolved=true

[device]
# Randomize the source MAC on probe requests only. This does not
# rotate the associated (cloned) MAC, so DHCP reservations survive.
wifi.scan-rand-mac-address=yes

[connection]
# MAC address policy: "stable" derives a deterministic MAC from
# stable-id + SSID (Wi-Fi) or interface name (Ethernet). Same network
# always gets the same MAC -> same DHCP lease -> stable IP that you
# can SSH to. Hardware MAC stays hidden from the access point.
#
# Use "random" instead if you actively want to avoid being tracked
# across reconnects on hostile networks (coffee shops). The cost is
# a fresh DHCP lease and IP every time.
wifi.cloned-mac-address=stable
ethernet.cloned-mac-address=stable
# stable-id without \${BOOT} so the MAC is the same across reboots
# (with \${BOOT} the "stable" derivation reseeds every boot).
connection.stable-id=\${CONNECTION}
EOF

    # WPA3-only is intentionally NOT set globally. Hotel, printer, and
    # IoT APs still speak WPA2. Use hardening/wifi/wifi.sh to flip a
    # named connection to SAE.
fi


echo -e "${BBlue}Configuring systemd-resolved with native DNS-over-TLS...${NC}"
# Use systemd-resolved's native DoT instead of a local Stubby forwarder.
# Rationale: on desktops NetworkManager manages resolv.conf and talks to
# resolved over D-Bus; layering Stubby on top causes the handoff chain
# (iwd -> dhcpcd -> NetworkManager -> resolved -> Stubby) to drift out of
# sync and break DNS. Stubby can still be installed manually as an opt-in
# for servers/VPS — see README.md.
mkdir -p /etc/systemd/resolved.conf.d/
# Remove the legacy underscore filename from prior runs so the directory
# stays clean (merged result is identical either way).
rm -f /etc/systemd/resolved.conf.d/dns_over_tls.conf
cat > /etc/systemd/resolved.conf.d/dns-over-tls.conf <<'EOF'
[Resolve]
DNS=1.1.1.1#cloudflare-dns.com 1.0.0.1#cloudflare-dns.com
FallbackDNS=9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net
DNSOverTLS=yes
DNSSEC=allow-downgrade
Cache=yes
Domains=~.
MulticastDNS=no
LLMNR=no
EOF

# Hand DNS off to systemd-resolved when NetworkManager is present so NM
# does not fight resolved over /etc/resolv.conf.
if [ -d /etc/NetworkManager/conf.d ]; then
    cat > /etc/NetworkManager/conf.d/dns.conf <<'EOF'
[main]
dns=systemd-resolved
EOF

    # Use iwd as the Wi-Fi backend so NM and iwd don't fight for the
    # radio (iwd is installed by archinstall.sh; default NM backend is
    # wpa_supplicant, which causes scan failures and "Network is down"
    # errors when iwd is also enabled).
    cat > /etc/NetworkManager/conf.d/wifi-backend.conf <<'EOF'
[device]
wifi.backend=iwd
EOF
fi

# Disable wpa_supplicant from auto-starting (NM uses iwd as the Wi-Fi
# backend), but do NOT mask it: masking breaks D-Bus on-demand activation
# of fi.w1.wpa_supplicant1, which GNOME's network settings and some VPN
# plugins still depend on (dbus-broker logs "wpa_supplicant.service is
# masked" otherwise).
systemctl disable wpa_supplicant.service 2>/dev/null || true
systemctl enable iwd.service

# Keep working /etc/resolv.conf in chroot so pacman can resolve mirror domains.
# The symlink to stub-resolv.conf will be created right before exiting chroot.

echo -e "${BBlue}Enabling systemd-resolved...${NC}"
# chroot cannot start services — only enable. The unit will come up on
# first boot and NetworkManager's dns=systemd-resolved backend will wire
# /etc/resolv.conf through it automatically.
systemctl enable systemd-resolved

# Prefer IPv4 over IPv6 — many VPS providers lack IPv6 routing, and
# sshd is configured with AddressFamily inet (IPv4 only)
echo -e "${BBlue}Configuring IPv4 preference...${NC}"
grep -qxF 'precedence ::ffff:0:0/96 100' /etc/gai.conf 2>/dev/null || echo "precedence ::ffff:0:0/96 100" >> /etc/gai.conf

echo -e "${BBlue}DNS-over-TLS configuration completed!${NC}"

echo -e "${BBlue}Configuring firewall with nftables...${NC}"

pacman -S --noconfirm nftables

cat <<EOF > /etc/nftables.conf
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
    # Per-source SSH connection tracking for the rate limit below. A plain
    # "limit rate" is ONE bucket shared by every client, so background scan
    # noise on the SSH port would lock the legitimate admin out.
    set ssh_ratelimit4 {
        type ipv4_addr
        flags dynamic
        timeout 2m
        size 65535
    }

    set ssh_ratelimit6 {
        type ipv6_addr
        flags dynamic
        timeout 2m
        size 65535
    }

    chain input {
        type filter hook input priority filter; policy drop;

        # Allow loopback
        iif lo accept

        # Allow established connections
        ct state established,related accept

        # Drop invalid connections
        ct state invalid drop

        # Allow ICMP & ICMPv6 (Path MTU Discovery, IPv6 Neighbor Discovery, MLD).
        # "meta l4proto" also matches ICMPv6 behind extension headers, which
        # "ip6 nexthdr" does not; MLD queries must be answered or switches with
        # MLD snooping stop forwarding neighbour-discovery multicast to us.
        meta l4proto icmp icmp type { echo-request, destination-unreachable, time-exceeded } accept
        meta l4proto ipv6-icmp icmpv6 type { echo-request, destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, mld-listener-query, mld-listener-report, mld-listener-done, mld2-listener-report } accept

        # DHCPv6 client: server replies go to a link-local address that
        # conntrack cannot relate to our multicast solicit.
        ip6 saddr fe80::/10 udp sport 547 udp dport 546 accept

        # Allow SSH with per-source rate limiting (burst allows legitimate reconnects)
        tcp dport ${SSH_PORT} ct state new add @ssh_ratelimit4 { ip saddr limit rate over 4/minute burst 8 packets } drop
        tcp dport ${SSH_PORT} ct state new add @ssh_ratelimit6 { ip6 saddr limit rate over 4/minute burst 8 packets } drop
        tcp dport ${SSH_PORT} ct state new accept

        # Drop everything else
        counter drop
    }

    chain forward {
        type filter hook forward priority filter; policy drop;
    }

    chain output {
        type filter hook output priority filter; policy accept;
    }
}
EOF

systemctl enable nftables.service

echo -e "${BBlue}Firewall configuration with nftables completed.${NC}"

echo -e "${BBlue}Installing and configuring logrotate...${NC}"
pacman -S --noconfirm logrotate
echo -e "${BBlue}Enhancing logging configuration...${NC}"
cat <<EOF > /etc/logrotate.d/custom
/var/log/messages /var/log/secure /var/log/auth.log /var/log/boot.log /var/log/sudo.log /var/log/pacman-updates.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 640 root adm
}
EOF

echo -e "${BBlue}Installing and configuring rng-tools...${NC}"
pacman -S --noconfirm rng-tools
systemctl enable rngd
# Modern kernels (5.6+) have adequate entropy from the jitterentropy module.

echo -e "${BBlue}Installing file security utility pax-utils & arch-audit...${NC}"
pacman -S --noconfirm arch-audit pax-utils

echo -e "${BBlue}Installing lynis...${NC}"
pacman -S --noconfirm lynis

###############################################################################
# CLAMAV CONFIGURATION
###############################################################################

# ClamAV anti-virus
echo -e "${BBlue}Installing and configuring Clamav...${NC}"
pacman -S --noconfirm clamav

echo -e "${BBlue}Configuring ClamAV...${NC}"

# 1) Generate default configuration files if they do not exist.
#    clamconf -g writes sample config to stdout with an active Example line.
install -d -m 0755 /etc/clamav
for clam_cfg in freshclam.conf clamd.conf clamav-milter.conf; do
  if [ ! -f "/etc/clamav/$clam_cfg" ]; then
    echo "Generating /etc/clamav/$clam_cfg..."
    clamconf -g "$clam_cfg" | sed 's/^Example/#Example/' > "/etc/clamav/$clam_cfg"
  else
    sed -i 's/^Example/#Example/' "/etc/clamav/$clam_cfg"
  fi
done

# 2) Update /etc/clamav/clamd.conf with recommended settings.
#    You can fine-tune or remove options you do not need.
CLAMD_CONF="/etc/clamav/clamd.conf"

# Helper function to ensure a line is present in /etc/clamav/clamd.conf
ensure_clamd_option() {
  local KEY="$1"
  local VALUE="$2"
  # If the key exists, replace it; otherwise, append it. The option name is
  # matched as a whole word: a bare prefix match let "Bytecode" overwrite the
  # BytecodeSecurity/BytecodeTimeout lines and "AlertEncrypted" the
  # AlertEncryptedArchive/AlertEncryptedDoc ones.
  if grep -Eq "^#?\s*${KEY}(\s|\$)" "$CLAMD_CONF"; then
    sed -Ei "s|^#?\s*${KEY}(\s.*)?\$|${KEY} ${VALUE}|" "$CLAMD_CONF"
  else
    echo "${KEY} ${VALUE}" >> "$CLAMD_CONF"
  fi
}

# Apply recommended options (comment out any you do not need)
ensure_clamd_option LogTime "yes"
ensure_clamd_option ExtendedDetectionInfo "yes"
ensure_clamd_option User "clamav"
ensure_clamd_option MaxDirectoryRecursion "20"

ensure_clamd_option DetectPUA "yes"
ensure_clamd_option HeuristicAlerts "yes"
ensure_clamd_option ScanPE "yes"
ensure_clamd_option ScanELF "yes"
ensure_clamd_option ScanOLE2 "yes"
ensure_clamd_option ScanPDF "yes"
ensure_clamd_option ScanSWF "yes"
ensure_clamd_option ScanXMLDOCS "yes"
ensure_clamd_option ScanHWP3 "yes"
ensure_clamd_option ScanOneNote "yes"
ensure_clamd_option ScanMail "yes"
ensure_clamd_option ScanHTML "yes"
ensure_clamd_option ScanArchive "yes"
ensure_clamd_option Bytecode "yes"
ensure_clamd_option AlertBrokenExecutables "yes"
ensure_clamd_option AlertBrokenMedia "yes"
ensure_clamd_option AlertEncrypted "yes"
ensure_clamd_option AlertEncryptedArchive "yes"
ensure_clamd_option AlertEncryptedDoc "yes"
ensure_clamd_option AlertOLE2Macros "yes"
ensure_clamd_option AlertPartitionIntersection "yes"

# 3) Create freshclam log file and lock down permissions
echo "Creating and securing /var/log/clamav/freshclam.log..."
mkdir -p /var/log/clamav
touch /var/log/clamav/freshclam.log
chmod 600 /var/log/clamav/freshclam.log
chown clamav:clamav /var/log/clamav/freshclam.log

# 4) Enable freshclam and clamd (will start on first boot)
#    Alternatively, clamav-freshclam-once.timer can be used instead of the daemon.
echo "Enabling ClamAV services..."
systemctl enable clamav-freshclam.service
systemctl enable clamav-daemon.service

# freshclam update will run on first boot — cannot reliably update in chroot
echo -e "${BYellow}ClamAV definitions will update on first boot via freshclam.${NC}"

# 5) Final check of ClamAV config
echo -e "${BBlue}Running clamconf to check ClamAV configuration...${NC}"
clamconf >/dev/null || true
echo -e "${BBlue}ClamAV configuration completed!\n${NC}"

###############################################################################
# END OF CLAMAV CONFIGURATION
###############################################################################

# Rootkit Hunter (rkhunter --propupd runs near the end after all packages and
# binary permission adjustments are finalized)
echo -e "${BBlue}Installing and configuring rkhunter...${NC}"
pacman -S --noconfirm rkhunter

cat <<EOF > /etc/systemd/system/rkhunter-check.service
[Unit]
Description=Run rkhunter daily check
[Service]
Type=oneshot
ExecStart=/usr/bin/rkhunter --check --cronjob --rwo
SuccessExitStatus=0 1
EOF
cat <<EOF > /etc/systemd/system/rkhunter-check.timer
[Unit]
Description=Run rkhunter daily check
[Timer]
OnCalendar=daily
Persistent=true
[Install]
WantedBy=timers.target
EOF
systemctl enable rkhunter-check.timer

echo -e "${BBlue}Installing and configuring arpwatch...${NC}"
pacman -S --noconfirm arpwatch

echo -e "${BBlue}Installing disk health monitoring (SMART/NVMe)...${NC}"
# smartmontools watches SATA and NVMe health; nvme-cli provides the manual
# investigation tools (nvme smart-log, nvme error-log) needed after an
# unexplained freeze. Without these, a failing drive gives no warning and
# leaves no history to review after the fact.
pacman -S --noconfirm smartmontools nvme-cli

# -a          monitor all attributes
# -o on       enable automatic offline data collection
# -S on       enable attribute autosave
# -s ...      short self-test daily 02:00, long self-test Saturday 03:00
#             (non-NVMe devices only, see below)
# -W 4,50,70  DIFF,INFO,CRIT: log on 4C swings, log an advisory at 50C,
#             and treat 70C as critical (NVMe operating range).
#             Only the CRIT threshold invokes the -M exec handler.
#
# NVMe controllers have dropped off the bus as a scheduled self-test started
# (see utils/NVME-STABILITY.md), so NVMe drives are monitored without -s.
# DEVICESCAN ignores every later line and skips devices already listed, so
# each NVMe namespace is listed first. nvmeN numbering changes between boots;
# use the stable by-id name, one per namespace. NVMe drives added after
# installation are found by DEVICESCAN and do get the scheduled self-tests.
{
    echo 'DEFAULT -a -o on -S on -W 4,50,70 -m <nomailer> -M exec /usr/local/bin/smart-alert'
    declare -A nvme_seen=()
    for link in /dev/disk/by-id/nvme-*; do
        [[ -b $link && $link != *-part[0-9]* ]] || continue
        target=$(readlink -f -- "$link")
        [[ -v nvme_seen[$target] ]] && continue
        nvme_seen[$target]=1
        echo "$link -d nvme"
    done
    echo 'DEVICESCAN -s (S/../.././02|L/../../6/03)'
} > /etc/smartd.conf

install -Dm0755 /dev/stdin /usr/local/bin/smart-alert <<'SMARTALERT'
#!/usr/bin/env bash
# Invoked by smartd when a SMART event fires. smartd exports SMARTD_* in the
# environment. Log to the journal and the console so the alert survives even
# when no mail transport is configured.
set -uo pipefail

device="${SMARTD_DEVICE:-unknown device}"
message="${SMARTD_MESSAGE:-SMART event with no message}"

logger -t smartd -p daemon.crit "SMART alert on ${device}: ${message}"
wall "SMART alert on ${device}: ${message}" 2>/dev/null || true
SMARTALERT

systemctl enable smartd.service

# Native EC sensors expose chipset/VRM heat on this exact board. Add frequent
# read-only monitoring; power-state workarounds remain separate and opt-in.
if [[ -r /sys/class/dmi/id/board_vendor && -r /sys/class/dmi/id/board_name ]] &&
    [[ "$(</sys/class/dmi/id/board_vendor)" == "ASUSTeK COMPUTER INC." &&
       "$(</sys/class/dmi/id/board_name)" == "ROG ZENITH II EXTREME ALPHA" ]]; then
    /usr/local/lib/awesomearchlinux/board-health.sh --install --enable-only
fi

echo -e "${BBlue}Configuring usbguard...${NC}"
pacman -S --noconfirm usbguard

echo -e "${BBlue}Enhancing usbguard configuration...${NC}"
cat <<'EOF' > /etc/usbguard/usbguard-daemon.conf
RuleFile=/etc/usbguard/rules.conf
ImplicitPolicyTarget=block
PresentDevicePolicy=apply-policy
PresentControllerPolicy=keep
InsertedDevicePolicy=apply-policy
RestoreControllerDeviceState=false
DeviceRulesWithPort=false
IPCAccessControlFiles=/etc/usbguard/IPCAccessControl.d/
EOF

install -d -m 0755 /etc/usbguard/IPCAccessControl.d
install -m 0600 /dev/stdin /etc/usbguard/IPCAccessControl.d/root <<'EOF'
Devices=modify,list,listen
Policy=modify,list
Exceptions=listen
Parameters=modify,list,listen
EOF

install -Dm0755 /dev/stdin /usr/local/bin/usbguard-initial-policy <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

RULES=/etc/usbguard/rules.conf

if [[ -f "$RULES" ]] && grep -qvE '^[[:space:]]*(#|$)' "$RULES"; then
    exit 0
fi

tmp=$(mktemp /etc/usbguard/rules.conf.XXXXXX)

# Only a non-zero exit is a genuine failure. Empty output is a legitimate
# result on a machine with no USB devices attached, and must still install a
# policy so the daemon can start and enforce block-by-default.
if usbguard generate-policy > "$tmp"; then
    chmod 0600 "$tmp"
    mv -f "$tmp" "$RULES"
    exit 0
fi

# Generation genuinely failed. Leave any existing policy untouched and exit
# non-zero so ExecStartPre aborts the unit. USBGuard must NOT start with an
# empty policy: ImplicitPolicyTarget=block plus PresentDevicePolicy=apply-policy
# would block every attached device, including the console keyboard, and
# stopping the daemon would not restore them. A daemon that never starts leaves
# USB permissive -- unprotected, but reachable and recoverable.
rm -f "$tmp"
exit 1
EOF

# No "-" prefix: a failed policy generation must prevent USBGuard from starting.
install -Dm0644 /dev/stdin /etc/systemd/system/usbguard.service.d/10-initial-policy.conf <<'EOF'
[Service]
ExecStartPre=/usr/local/bin/usbguard-initial-policy
EOF

systemctl enable usbguard.service

# Hardening /etc/login.defs
echo -e "${BBlue}Changing the value of UMASK from 022 to 027...${NC}"
sed -i 's/^UMASK[[:space:]]\+022/UMASK\t\t027/' /etc/login.defs

echo -e "${BBlue}Configuring Password Hashing Rounds...${NC}"
sed -i '/#SHA_CRYPT_MIN_ROUNDS 5000/s/^#//;/#SHA_CRYPT_MAX_ROUNDS 5000/s/^#//' /etc/login.defs

echo -e "${BBlue}Increasing Fail Delay to 5 Seconds...${NC}"
sed -i 's/^FAIL_DELAY[[:space:]]\+3/FAIL_DELAY\t\t5/' /etc/login.defs

echo -e "${BBlue}Lowering Login Retries to 3...${NC}"
sed -i 's/^LOGIN_RETRIES[[:space:]]\+5/LOGIN_RETRIES\t\t3/' /etc/login.defs

echo -e "${BBlue}Reducing Login Timeout to 30 Seconds...${NC}"
sed -i 's/^LOGIN_TIMEOUT[[:space:]]\+60/LOGIN_TIMEOUT\t\t30/' /etc/login.defs

echo -e "${BBlue}Ensuring the Strongest Encryption Method is Used...${NC}"
sed -i 's/^ENCRYPT_METHOD[[:space:]]\+.*$/ENCRYPT_METHOD YESCRYPT/' /etc/login.defs

echo -e "${BBlue}Increasing YESCRYPT Cost Factor...${NC}"
sed -i 's/^#YESCRYPT_COST_FACTOR[[:space:]]\+.*$/YESCRYPT_COST_FACTOR 7/' /etc/login.defs

echo -e "${BBlue}Setting Maximum Members Per Group...${NC}"
sed -i 's/^#MAX_MEMBERS_PER_GROUP[[:space:]]\+0/MAX_MEMBERS_PER_GROUP\t100/' /etc/login.defs

echo -e "${BBlue}Setting HMAC Crypto Algorithm to SHA512...${NC}"
sed -i 's/^#HMAC_CRYPTO_ALGO[[:space:]]\+.*$/HMAC_CRYPTO_ALGO SHA512/' /etc/login.defs

echo -e "${BBlue}Setting password expiring dates...${NC}"
sed -i '/^PASS_MAX_DAYS/c\PASS_MAX_DAYS 730' /etc/login.defs # modify here the amount of MAX days

# HOME_MODE 0700 so new user homes aren't world-readable.
# The value is replaced in-place if present, appended otherwise.
if grep -qE '^[#[:space:]]*HOME_MODE' /etc/login.defs; then
    sed -i 's/^[#[:space:]]*HOME_MODE.*/HOME_MODE\t\t0700/' /etc/login.defs
else
    echo -e "HOME_MODE\t\t0700" >> /etc/login.defs
fi

# Logging Failed Login Attempts
echo -e "${BBlue}Configuring PAM to Log Failed Attempts...${NC}"


# More umasking
echo -e "${BBlue}Setting additional UMASK 027s...${NC}"
grep -qxF 'umask 027' /etc/profile    || echo "umask 027" >> /etc/profile
grep -qxF 'umask 027' /etc/bash.bashrc || echo "umask 027" >> /etc/bash.bashrc

# Disable unwanted protocols (truncate to avoid duplicates on re-run)
echo -e "${BBlue}Disabling unwanted protocols...${NC}"
cat > /etc/modprobe.d/disable-protocols.conf << 'MODPROBE_EOF'
blacklist dccp
blacklist sctp
blacklist rds
blacklist tipc
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false
MODPROBE_EOF

# Disabling core dump. Please feel free to comment if you need it.
echo -e "${BBlue}Disabling core dump...${NC}"
grep -qxF '* hard core 0' /etc/security/limits.conf 2>/dev/null || echo "* hard core 0" >> /etc/security/limits.conf

# Using chrony for NTP (preferred over ntpd — lighter, more accurate, handles VM clock drift)
echo -e "${BBlue}Installing chrony for NTP...${NC}"
pacman -S --noconfirm chrony
install -d -o chrony -g chrony -m 0750 /var/log/chrony
systemctl enable chronyd

# Sysstem monitoring tool
echo -e "${BBlue}Enabling sysstat to Collect Accounting...${NC}"
pacman -S --noconfirm sysstat
systemctl enable sysstat

# System auditing tool
echo -e "${BBlue}Enabling auditd to Collect Audit Information...${NC}"
pacman -S --noconfirm audit
configure_audit_rules
# Loading audit rules here would change the live installer kernel.
systemctl enable auditd

# Enable and configure necessary services
echo -e "${BBlue}Enabling NetworkManager...${NC}"
systemctl enable NetworkManager
# NetworkManager-dispatcher.service is D-Bus activated by NM on demand
# (via org.freedesktop.nm_dispatcher). On Arch we do NOT enable it
# directly — the unit is designed for D-Bus activation and a direct
# `systemctl enable` causes "unit is invalid" errors. The dispatcher
# will activate automatically if any script in /etc/NetworkManager/
# dispatcher.d/ is registered.

echo -e "${BBlue}Enabling automatic firmware metadata refresh...${NC}"
systemctl enable fwupd-refresh.timer
# ModemManager is D-Bus activated on demand. NetworkManager discovers WWAN
# modems through it without a separately enabled long-running service.

echo -e "${BBlue}Enabling OpenSSH...${NC}"
systemctl enable sshd

# Mask dhcpcd: pacstrap installs it but NetworkManager owns DHCP.
# When both run, they race for the lease and dhcpcd has been observed
# to segfault (journalctl: dhcpcd[N]: segfault at 0). Masking is
# stronger than disable — prevents accidental re-enablement by deps.
echo -e "${BBlue}Masking dhcpcd (NetworkManager owns DHCP)...${NC}"
systemctl mask dhcpcd.service 2>/dev/null || true

# Wi-Fi regulatory domain: the wireless-regdb package ships a udev hook
# (/usr/bin/set-wireless-regdom) that reads /etc/conf.d/wireless-regdom
# and applies it. If the file is missing the hook exits 1 every udev
# event. Derive the 2-letter country code from where the machine is: the
# timezone (Europe/Zurich -> CH via tzdata's zone.tab). The locale is only a
# fallback, and never the en_US default, which says nothing about location and
# would apply US channel/power rules everywhere. If nothing can be inferred,
# leave a commented line (the kernel then keeps the conservative world domain).
WIRELESS_COUNTRY=""
WIRELESS_COUNTRY_SOURCE=""
if [[ -r /usr/share/zoneinfo/zone.tab ]]; then
    WIRELESS_COUNTRY=$(awk -F '\t' -v tz="$TIMEZONE" '!/^#/ && $3 == tz { print $1; exit }' /usr/share/zoneinfo/zone.tab)
    WIRELESS_COUNTRY_SOURCE="timezone $TIMEZONE"
fi
if [[ -z "$WIRELESS_COUNTRY" && "$TIMEZONE" == US/* ]]; then
    WIRELESS_COUNTRY="US"
    WIRELESS_COUNTRY_SOURCE="timezone $TIMEZONE"
fi
if [[ -z "$WIRELESS_COUNTRY" && "$LOCALE" != en_US* ]]; then
    case "$LOCALE" in
        *_*) WIRELESS_COUNTRY="${LOCALE#*_}"; WIRELESS_COUNTRY="${WIRELESS_COUNTRY%%.*}" ;;
    esac
    WIRELESS_COUNTRY_SOURCE="locale $LOCALE"
fi
mkdir -p /etc/conf.d
if [[ "$WIRELESS_COUNTRY" =~ ^[A-Z]{2}$ ]]; then
    echo "WIRELESS_REGDOM=\"$WIRELESS_COUNTRY\"" > /etc/conf.d/wireless-regdom
    echo -e "${BBlue}Wi-Fi regulatory domain set to $WIRELESS_COUNTRY (from $WIRELESS_COUNTRY_SOURCE).${NC}"
else
    echo "# WIRELESS_REGDOM=\"XX\"  # set your 2-letter country code (ISO 3166)" > /etc/conf.d/wireless-regdom
    echo -e "${BYellow}Could not infer WIRELESS_REGDOM from the timezone or locale; edit /etc/conf.d/wireless-regdom${NC}"
fi

# Installing Fail2ban
echo -e "${BBlue}Installing and configuring Fail2ban...${NC}"
pacman -S --noconfirm fail2ban

install -d -m 0755 /etc/fail2ban/filter.d /etc/fail2ban/jail.d
cat <<'EOF' > /etc/fail2ban/filter.d/sshd.local
[Definition]
_daemon = sshd(?:-session|-auth)?

[Init]
journalmatch = _SYSTEMD_UNIT=sshd.service
EOF

cat <<EOF > /etc/fail2ban/jail.d/sshd.conf
[sshd]
enabled = true
port    = ${SSH_PORT}
maxretry = 5
banaction = nftables-multiport
# OpenSSH 10.x splits into sshd, sshd-auth, sshd-session — match all via journal
backend = systemd
journalmatch = _SYSTEMD_UNIT=sshd.service
EOF

systemctl enable fail2ban

echo -e "${BBlue}Improving journald configuration...${NC}"
configure_journal_sealing
# Key setup and journal rotation run on the installed system at boot.

# Configure sudo
# Create local groups required by the hidepid /proc policy and sudo access.
echo -e "${BBlue}Hardening sudo...${NC}"
groupadd -r proc 2>/dev/null || true
groupadd sudo 2>/dev/null || true

# Write sudoers atomically via private /etc temp file + visudo validation
SUDOERS_TMP=$(mktemp /etc/.sudoers.XXXXXX)
chmod 0440 "$SUDOERS_TMP"
cat > "$SUDOERS_TMP" << 'SUDOERS_EOF'
# Hardened sudoers — generated by chroot.sh

Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Defaults !rootpw
Defaults umask=077
Defaults editor=/usr/bin/vim:/usr/bin/nvim:/usr/bin/nano:/usr/bin/vi
Defaults env_reset
Defaults env_keep="COLORS DISPLAY HOSTNAME HISTSIZE INPUTRC KDEDIR LS_COLORS"
Defaults env_keep += "MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE"
Defaults env_keep += "LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES"
Defaults env_keep += "LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE"
Defaults env_keep += "LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY"
Defaults timestamp_timeout=30
Defaults !visiblepw
Defaults always_set_home
Defaults match_group_by_gid
Defaults always_query_group_plugin
Defaults passwd_timeout=10
Defaults passwd_tries=3
Defaults loglinelen=0
Defaults insults
Defaults lecture=once
Defaults logfile=/var/log/sudo.log
Defaults log_input, log_output
# log_input records everything typed under sudo. Keep passwords entered at
# prompts of the commands being run (passwd, cryptsetup, ssh, ...) out of
# /var/log/sudo-io, and cap the number of session logs so they cannot fill /var.
Defaults !log_passwords
Defaults maxseq=10000

# Allow root and sudo group full access
root ALL=(ALL:ALL) ALL
%sudo ALL=(ALL:ALL) ALL

@includedir /etc/sudoers.d
SUDOERS_EOF

# Validate before installing
if visudo -c -f "$SUDOERS_TMP"; then
    install -m 0440 -o root -g root "$SUDOERS_TMP" /etc/sudoers
    echo -e "${BGreen}Sudoers validated and installed successfully.${NC}"
else
    echo -e "${BRed}ERROR: sudoers validation failed! Keeping original file.${NC}" >&2
fi
rm -f "$SUDOERS_TMP"

# arch-audit was installed above; enable the scheduled check for first boot.
configure_vulnerability_check
systemctl enable arch-audit.timer

# --- IMPORTANT: User creation MUST come before home directory configuration ---
# Add the user
echo -e "${BBlue}Adding the user $USERNAME...${NC}"
if ! id -u "$USERNAME" >/dev/null 2>&1; then
  # Groups breakdown:
  #   sudo,wheel    -> privilege escalation (wheel is the Arch default, sudo
  #                    is the Debian alias; kept for cross-distro tooling)
  #   uucp          -> serial port / modem access (tty devices)
  #   proc          -> required because we mount /proc with
  #                    hidepid=2,gid=proc (see archinstall.sh). Without
  #                    membership the user can only see their own /proc
  #                    entries, and GNOME's sd_pid_get_user_unit()-style
  #                    lookups silently fail with ESRCH, breaking logind
  #                    session tracking — symptoms include
  #                    "Error fetching user unit for own pid",
  #                    "Failed to register AuthenticationAgent", and
  #                    GNOME apps not showing their windows. (Same root
  #                    cause as the NixOS discourse/42440 thread.)
  #   video         -> GPU + webcam enumeration (/dev/video*)
  #   render        -> DRM render node (/dev/dri/renderD*) access for GPU
  #                    compute / GBM / Wayland / VA-API hardware decode.
  #                    Without it, GTK4 GSK falls back to software renderer,
  #                    Wayland apps render slowly, and dma-buf screen share
  #                    fails.
  #   audio         -> ALSA (/dev/snd/*). PipeWire routes via logind.
  #   storage       -> removable media mount access under polkit fallback
  # NOTE: input group is omitted — logind assigns seat ACLs; static input membership allows keyloggers
  useradd -m -G sudo,wheel,uucp,proc,video,render,audio,storage -s /bin/zsh "$USERNAME"
  chown "$USERNAME:$USERNAME" /home/"$USERNAME"  # Fix home dir ownership right away.
  chmod 700 /home/"$USERNAME"                   # Private home (not world-readable)
  echo -e "${BBlue}User $USERNAME created.${NC}"

else
    echo "User $USERNAME already exists." >&2
fi

# Pre-create private user cache directories (including nano backups)
install -d -m 0700 -o "$USERNAME" -g "$USERNAME" \
    "/home/$USERNAME/.cache" \
    "/home/$USERNAME/.cache/nano" \
    "/home/$USERNAME/.cache/nano/backups"

# Set password for user (with loop for incorrect input)
echo -e "${BBlue}Configuring password policy before setting passwords...${NC}"
pacman -S --needed --noconfirm pambase pam libpwquality
configure_password_policy

set +e # Disable 'exit on error' temporarily
while true; do
    echo -e "${BBlue}Setting password for user $USERNAME...${NC}"
    echo -e "${BBlue}Password should be at least 12 characters long, contain 1 symbol, 1 number, upper and lowercase letters.${NC}"
    if passwd "$USERNAME"; then
        break # Exit loop if password change successful
    else
        echo -e "${BBlue}Password change failed. Please try again.${NC}"
        sleep 1
    fi
done

# Set password for root (with loop for incorrect input)
while true; do
    echo -e "${BBlue}Setting root password...${NC}"
    if passwd root; then
        break # Exit loop if password change successful
    else
        echo -e "${BBlue}Root password change failed. Please try again.${NC}"
        sleep 1
    fi
done
set -e # Re-enable 'exit on error'

# --- Configure Nano settings idempotently (after user creation) ---
echo -e "${BBlue}Installing nano syntax highlighting...${NC}"
pacman -S --needed --noconfirm nano-syntax-highlighting 2>/dev/null || true

{
    cat << 'NANO_EOF'
set backup
set backupdir "~/.cache/nano/backups/"
set constantshow
set locking
set nohelp
set nonewlines
set nowrap
set minibar
set zap
set linenumbers
set tabsize 4
set tabstospaces
NANO_EOF
    if compgen -G '/usr/share/nano-syntax-highlighting/*.nanorc' >/dev/null; then
        echo 'include "/usr/share/nano-syntax-highlighting/*.nanorc"'
    fi
} > "/home/$USERNAME/.nanorc"
chown "$USERNAME:$USERNAME" "/home/$USERNAME/.nanorc"
chmod 600 "/home/$USERNAME/.nanorc"

echo -e "${BBlue}Staging SSH access for $USERNAME (authorized_keys first)...${NC}"

# --- SSH Configuration ---
configure_ssh() {
  # --- SSH Key Generation ---

  mkdir -p "/home/$USERNAME/.ssh"  # Ensure directory exists

  if [ ! -f "$SSH_KEY_FILE" ]; then
    echo -e "${BBlue}Generating a new SSH key pair ($SSH_KEY_TYPE)...${NC}"
    ssh-keygen -t "$SSH_KEY_TYPE" -C "$USERNAME@$HOSTNAME" -f "$SSH_KEY_FILE" -q -N "" # -q for quiet, -N for no passphrase
  else
    echo -e "${BBlue}SSH key ($SSH_KEY_FILE) already exists.${NC}"
  fi

  # --- SSH Client Configuration ---
  echo -e "${BBlue}Configuring SSH client settings in $SSH_CONFIG_FILE...${NC}"

  # Backup existing config (improved)
  if [ -f "$SSH_CONFIG_FILE" ] && [ ! -f "$SSH_CONFIG_FILE.bak" ]; then
    cp "$SSH_CONFIG_FILE" "$SSH_CONFIG_FILE.bak"
  fi

  # Use 'install' for atomic file writing — values must NOT be quoted in SSH config
  install -Dm644 /dev/stdin "$SSH_CONFIG_FILE" <<EOF
Host ${HOSTNAME}
  HostName ${HOSTNAME}
  Port ${SSH_PORT}
  User ${USERNAME}
  IdentityFile ${SSH_KEY_FILE}
  HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
  KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group18-sha512,diffie-hellman-group16-sha512
  Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
  MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
EOF

echo "SSH client configuration updated."

# --- SSH Server Configuration (Optional) ---
# ... (Add server-side configuration here if needed) ...

# --- SSH Finalization ---
echo -e "${BBlue}Hashing known_hosts file...${NC}"
ssh-keygen -H -f "/home/$USERNAME/.ssh/known_hosts" 2>/dev/null || true # Suppress stderr if file doesn't exist

touch "/home/$USERNAME/.ssh/authorized_keys"
if [[ -n "$SSH_PUBKEY" ]]; then
    grep -qxF "$SSH_PUBKEY" "/home/$USERNAME/.ssh/authorized_keys" 2>/dev/null || \
        printf '%s\n' "$SSH_PUBKEY" >> "/home/$USERNAME/.ssh/authorized_keys"
    echo -e "${BGreen}SSH public key installed for $USERNAME.${NC}"
else
    echo -e "${BYellow}No SSH public key provided — add one manually before disconnecting.${NC}"
fi
chmod 700 "/home/$USERNAME/.ssh"
chmod 600 "/home/$USERNAME/.ssh/authorized_keys"
chown -R "$USERNAME:$USERNAME" "/home/$USERNAME"

} # End of configure_ssh() function


configure_ssh # Call the SSH configuration function

# Now harden sshd. If the user pasted a pubkey at install time it is already
# in authorized_keys; otherwise pass -k to bypass the lockout check (bare-metal
# only — console access guarantees the user can add a key post-reboot).
# Defer shredding /ssh.sh until the end of chroot.sh so recovery-mount.sh can
# resume cleanly if a later step fails.
echo -e "${BBlue}Hardening sshd on port $SSH_PORT...${NC}"
if [[ -s "/home/$USERNAME/.ssh/authorized_keys" ]]; then
    /ssh.sh -u "$USERNAME" -p "$SSH_PORT"
else
    echo -e "${BYellow}No SSH pubkey was provided — invoking ssh.sh with -k (console fallback).${NC}"
    echo -e "${BYellow}After reboot, log in at the console and add your key to ~/.ssh/authorized_keys${NC}"
    echo -e "${BYellow}before attempting any remote SSH login.${NC}"
    /ssh.sh -u "$USERNAME" -p "$SSH_PORT" -k
fi

sleep 1

echo -e "${BBlue}Applying hardened compiler flags...${NC}"
harden_makepkg_conf() {
    local conf="/etc/makepkg.conf"
    [[ -f "$conf" ]] || return 0
    if ! grep -q -- '-fstack-protector-strong' "$conf"; then
        awk '
            /^CFLAGS="/ { in_cflags = 1 }
            in_cflags && /"[[:space:]]*$/ {
                sub(/"[[:space:]]*$/, " -fstack-protector-strong\"")
                in_cflags = 0
            }
            { print }
        ' "$conf" > "${conf}.tmp" && cat "${conf}.tmp" > "$conf" && rm -f "${conf}.tmp"
    fi
    if ! grep -q -- '_FORTIFY_SOURCE' "$conf"; then
        awk '
            /^CFLAGS="/ { in_cflags = 1 }
            in_cflags && /"[[:space:]]*$/ {
                sub(/"[[:space:]]*$/, " -Wp,-D_FORTIFY_SOURCE=3\"")
                in_cflags = 0
            }
            { print }
        ' "$conf" > "${conf}.tmp" && cat "${conf}.tmp" > "$conf" && rm -f "${conf}.tmp"
    fi
    if ! grep -q -- '-z,now' "$conf"; then
        awk '
            /^LDFLAGS="/ { in_ldflags = 1 }
            in_ldflags && /"[[:space:]]*$/ {
                sub(/"[[:space:]]*$/, " -Wl,-z,relro,-z,now\"")
                in_ldflags = 0
            }
            { print }
        ' "$conf" > "${conf}.tmp" && cat "${conf}.tmp" > "$conf" && rm -f "${conf}.tmp"
    fi
    sed -i '/^OPTIONS=/ s/!pie/pie/' "$conf"
}
harden_makepkg_conf

# Restrict compiler access via the 'compilers' group and persist across pacman upgrades
echo -e "${BBlue}Restricting access to compilers using a 'compilers' group...${NC}"
groupadd compilers 2>/dev/null || true
usermod -aG compilers "$USERNAME"

install -Dm0755 /dev/stdin /usr/local/lib/awesomearchlinux/fix-compilers-perms.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
getent group compilers >/dev/null 2>&1 || exit 0
for compiler in gcc g++ clang make as ld ld.bfd ld.lld; do
    compiler_path=$(command -v "$compiler" 2>/dev/null) || continue
    resolved=$(realpath -e "$compiler_path" 2>/dev/null) || continue
    [[ -f "$resolved" ]] || continue
    chown root:compilers "$resolved"
    chmod 0750 "$resolved"
done
EOF

install -Dm0644 /dev/stdin /etc/pacman.d/hooks/90-awesome-compilers.hook <<'EOF'
[Trigger]
Operation = Install
Operation = Upgrade
Type = Path
Target = usr/bin/gcc
Target = usr/bin/g++
Target = usr/bin/clang
Target = usr/bin/make
Target = usr/bin/as
Target = usr/bin/ld
Target = usr/bin/ld.bfd
Target = usr/bin/ld.lld

[Action]
Description = Restoring compiler group permissions (root:compilers 0750)...
When = PostTransaction
Exec = /usr/local/lib/awesomearchlinux/fix-compilers-perms.sh
EOF

/usr/local/lib/awesomearchlinux/fix-compilers-perms.sh

# Keep /root private (0700) without default ACLs so root-built files/configs do
# not inherit 0600 masks. On /home/$USERNAME, set a private default ACL while
# clearing default ACLs from ~/.cache/{yay,paru} so AUR makepkg $pkgdir trees
# never inherit group/other --- permissions into built packages.
echo -e "${BBlue}Configuring /root permissions and default ACLs on /home/$USERNAME...${NC}"
chmod 0700 /root
setfacl -b -k /root 2>/dev/null || true
setfacl -d -m u::rwx,g::---,o::--- "/home/$USERNAME"
mkdir -p "/home/$USERNAME/.cache/yay" "/home/$USERNAME/.cache/paru" "/home/$USERNAME/.cache/nano/backups"
chmod 0700 "/home/$USERNAME/.cache" "/home/$USERNAME/.cache/nano" "/home/$USERNAME/.cache/nano/backups"
setfacl -b -k "/home/$USERNAME/.cache" "/home/$USERNAME/.cache/yay" "/home/$USERNAME/.cache/paru"
chown -hR "$USERNAME:$USERNAME" "/home/$USERNAME/.cache"

# Establish the profile-specific encryption hooks before hardware-specific
# modules are discovered. The final image/UKI is generated after GPU setup.
echo -e "${BBlue}Preparing boot hooks for the $INSTALL_BOOTLOADER profile...${NC}"
bl_set_hooks
if [[ "$INSTALL_BOOTLOADER" == "grub" ]]; then
    chmod 400 "$LUKS_KEYS"
fi

sleep 1

# --- CPU Microcode Installation ---
install_cpu_microcode() {
  echo -e "${BBlue}Installing CPU ucode...${NC}"

  if [[ "$CPU_VENDOR_ID" =~ "GenuineIntel" ]]; then
    if ! pacman -Qi intel-ucode &>/dev/null; then  # Check if already installed
      pacman -S --noconfirm intel-ucode
    fi
  elif [[ "$CPU_VENDOR_ID" =~ "AuthenticAMD" ]]; then
    if ! pacman -Qi amd-ucode &>/dev/null; then  # Check if already installed
      pacman -S --noconfirm amd-ucode
    fi
  else
    echo -e "${BBlue}Unknown CPU vendor: $CPU_VENDOR_ID. Skipping microcode installation.${NC}"
  fi
}

install_cpu_microcode # Call the function

sleep 1

# --- Bluetooth Configuration ---
# Radio profile for BlueZ (hardware-agnostic):
#   dual  - default. Classic audio (A2DP) + BLE keyboards/mice/tags
#   bredr - classic only; use if you want no BLE
#   le    - BLE only; A2DP headphones/speakers will not work
: "${BLUETOOTH_CONTROLLER_MODE:=dual}"

# True when a Bluetooth controller is present. Asks the kernel first: many
# adapters (MediaTek, some Realtek combo cards) do not carry the word
# "Bluetooth" in their USB/PCI descriptor. The lsusb/lspci text match is only
# a fallback, and its output is captured first because "cmd | grep -q" under
# pipefail can report failure (SIGPIPE) on a match.
bluetooth_hardware_present() {
  local entry hw_list
  for entry in /sys/class/bluetooth/hci*; do
    [[ -e "$entry" ]] && return 0
  done
  # USB Wireless Controller class, Bluetooth programming interface (e0/01/01)
  for entry in /sys/bus/usb/devices/*/bInterfaceClass; do
    [[ -r "$entry" ]] || continue
    if [[ "$(< "$entry")" == "e0" &&
          "$(cat "${entry%/*}/bInterfaceSubClass" 2>/dev/null)" == "01" &&
          "$(cat "${entry%/*}/bInterfaceProtocol" 2>/dev/null)" == "01" ]]; then
      return 0
    fi
  done
  hw_list=$( { lsusb 2>/dev/null || true; lspci 2>/dev/null || true; } )
  grep -qi "bluetooth" <<< "$hw_list"
}

configure_bluetooth() {
  if bluetooth_hardware_present; then
    echo -e "${BBlue}Bluetooth hardware detected.${NC}"

    if ! pacman -Qi bluez bluez-utils &>/dev/null; then
      pacman -S --noconfirm bluez bluez-utils
    fi

    case "${BLUETOOTH_CONTROLLER_MODE}" in
      dual|bredr|le) ;;
      *)
        echo -e "${BRed}Invalid BLUETOOTH_CONTROLLER_MODE=${BLUETOOTH_CONTROLLER_MODE} (use dual, bredr, or le).${NC}"
        return 1
        ;;
    esac

    install -Dm644 /etc/bluetooth/main.conf{,.bak} 2>/dev/null || true

    cat <<EOF >/etc/bluetooth/main.conf
[General]
# BlueZ ignores unknown keys and does not support inline comments on option lines.
Name=Bluetooth
DiscoverableTimeout=90
AlwaysPairable=false
PairableTimeout=90
DebugKeys=false
ControllerMode=${BLUETOOTH_CONTROLLER_MODE}
FastConnectable=true
Privacy=device
JustWorksRepairing=confirm
SecureConnections=on
Experimental=false
Testing=false
KernelExperimental=false
FilterDiscoverable=true
TemporaryTimeout=30

[GATT]
KeySize=16
  
  [Policy]
  AutoEnable=true
  # BlueZ defaults (Headset AG, Handsfree AG, A2DP Source) plus Audio Sink, AVRCP, HID
  ReconnectUUIDs=00001112-0000-1000-8000-00805f9b34fb,0000111f-0000-1000-8000-00805f9b34fb,0000110a-0000-1000-8000-00805f9b34fb,0000110b-0000-1000-8000-00805f9b34fb,0000110e-0000-1000-8000-00805f9b34fb,00001124-0000-1000-8000-00805f9b34fb
EOF
  
      mkdir -p /etc/systemd/system/bluetooth.service.d
      cat <<'EOF' | install -Dm644 /dev/stdin /etc/systemd/system/bluetooth.service.d/override.conf
  [Service]
  ProtectHome=true
  # bluetoothd needs more than AF_BLUETOOTH + AF_UNIX: AF_ALG for the kernel
  # crypto it uses to generate the IRK (without it "Privacy=device" silently
  # stays off: "Failed to open crypto"), AF_NETLINK for udev-based plugins,
  # and AF_INET for the ioctl socket that brings PAN (bnep) interfaces up.
  RestrictAddressFamilies=AF_UNIX AF_BLUETOOTH AF_ALG AF_NETLINK AF_INET
EOF
  
  
  # Do not use --now inside an arch-chroot as systemd is not PID 1
  systemctl daemon-reload 2>/dev/null || true
  systemctl enable bluetooth
  
  echo -e "${BBlue}Bluetooth configured (ControllerMode=${BLUETOOTH_CONTROLLER_MODE}).${NC}"
    else
      echo -e "${BBlue}No Bluetooth hardware detected.${NC}"
    fi
    }
    configure_bluetooth # Call the function

sleep 2

# --- GPU Detection & Driver Installation ---
NVIDIA_CARD=false
NVIDIA_OPEN_SUPPORTED=false
AMD_CARD=false
INTEL_CARD=false

# Select prebuilt NVIDIA open-kernel modules from the kernels installed in the
# target, never from uname(1): inside arch-chroot uname reports the live ISO
# kernel. Only Turing+ (GSP-equipped) GPUs are supported by nvidia-open.
install_nvidia_driver_for_installed_kernels() {
    local -a driver_packages=(nvidia-utils)
    local found_prebuilt_kernel=false

    if pacman -Qq linux &>/dev/null; then
        driver_packages+=(nvidia-open)
        found_prebuilt_kernel=true
    fi
    if pacman -Qq linux-lts &>/dev/null; then
        driver_packages+=(nvidia-open-lts)
        found_prebuilt_kernel=true
    fi
    if [[ "$found_prebuilt_kernel" == false ]]; then
        driver_packages+=(dkms nvidia-open-dkms)
    fi

    echo "Installing NVIDIA Turing+ packages for the installed kernel(s): ${driver_packages[*]}"
    pacman -S --needed --noconfirm "${driver_packages[@]}"
}

# --- Detect NVIDIA (discrete or primary) ---
if lspci | grep -Ei "VGA|3D|Display" | grep -qi nvidia &>/dev/null; then
    NVIDIA_CARD=true
    echo -e "${BBlue}Found an NVIDIA GPU...${NC}"
fi

if [[ "$NVIDIA_CARD" == true ]]; then
    nvidia_gpu_model=$(lspci | grep -Ei 'vga|3d|2d|display' | grep -i nvidia | cut -d ':' -f3-)
    echo "Detected NVIDIA GPU:$nvidia_gpu_model"

    case "$nvidia_gpu_model" in
        # Turing data-centre cards are still sold as "Tesla" (TU104GL [Tesla T4]).
        # Match them before the pre-Turing "Tesla" catch-all below, which
        # otherwise sends them to nouveau.
        *"Tesla T4"*|*"TU10"*|*"TU11"*)
            NVIDIA_OPEN_SUPPORTED=true
            ;;
        # Pre-Turing architectures (Tesla, Fermi, Kepler, Maxwell, Pascal, Volta):
        # nvidia-open requires Turing+ GSP firmware, and legacy closed drivers live
        # only in the AUR. Fall back to open-source mesa (nouveau) so the system
        # boots reliably with KMS, and advise the operator on AUR driver packages.
        *"Tesla"*|*"NV50"*|*"G80"*|*"G90"*|*"GT2"*|\
        *"Fermi"*|*"GeForce 400"*|*"GeForce 500"*|*"GT 6"*|*"GTX 4"*|*"GTX 5"*|*"NVC"*|*"NVD"*|*"GF1"*|\
        *"Kepler"*|*"GTX 6"*|*"GTX 7"*|*"GT 7"*|*"NVE"*|*"NVF"*|*"GK1"*|*"GK2"*|*"Quadro K"*|\
        *"Maxwell"*|*"GTX 750"*|*"GTX 8"*|*"GTX 9"*|*"GM1"*|*"GM2"*|*"NV11"*|*"NV12"*|*"Quadro M"*|\
        *"Pascal"*|*"GTX 10"*|*"GT 10"*|*"GP10"*|*"NV13"*|*"TITAN X"*|*"TITAN Xp"*|*"Quadro P"*|\
        *"Volta"*|*"TITAN V"*|*"GV100"*)
            echo -e "${BYellow}WARNING: Pre-Turing NVIDIA GPU detected ($nvidia_gpu_model).${NC}"
            echo -e "${BYellow}Arch's official nvidia-open package requires Turing (RTX 20 / GTX 16) or newer.${NC}"
            echo -e "${BYellow}Installing open-source mesa (nouveau) so the system boots cleanly.${NC}"
            echo -e "${BYellow}Optional proprietary AUR drivers after reboot: nvidia-580xx-dkms (Maxwell/Pascal/Volta) or nvidia-470xx-dkms (Kepler).${NC}"
            pacman -S --needed --noconfirm mesa libva-utils
            ;;
        # Turing, Ampere, Ada Lovelace, Hopper, Blackwell+:
        *"Turing"*|*"RTX 20"*|*"GTX 16"*|*"TU10"*|*"TU11"*|*"Quadro RTX"*|*"T4"*|*"T500"*|*"T600"*|*"T1000"*|*"T1200"*|*"T2000"*|\
        *"Ampere"*|*"RTX 30"*|*"GA10"*|*"RTX A"*|*"A100"*|*"A10"*|*"A30"*|*"A40"*|\
        *"Ada"*|*"RTX 40"*|*"AD10"*|\
        *"Hopper"*|*"GH100"*|*"H100"*|\
        *"Blackwell"*|*"RTX 50"*|*"GB10"*|*"GB20"*)
            NVIDIA_OPEN_SUPPORTED=true
            ;;
        *)
            echo -e "${BYellow}WARNING: Unrecognized NVIDIA GPU model ($nvidia_gpu_model).${NC}"
            echo -e "${BYellow}Falling back to open-source mesa (nouveau) to avoid blacklisting KMS on potentially pre-Turing hardware.${NC}"
            echo -e "${BYellow}If this is a Turing+ GPU, install nvidia-open and nvidia-utils after reboot; for Maxwell/Pascal use AUR nvidia-580xx-dkms.${NC}"
            pacman -S --needed --noconfirm mesa libva-utils
            ;;
    esac

    if [[ "$NVIDIA_OPEN_SUPPORTED" == true ]]; then
        echo -e "${BBlue}Installing official NVIDIA Turing+ open-kernel drivers...${NC}"
        mkdir -p /etc/modprobe.d
        touch /etc/modprobe.d/blacklist-nouveau.conf
        if ! grep -qxF "blacklist nouveau" /etc/modprobe.d/blacklist-nouveau.conf; then
            echo "blacklist nouveau" >> /etc/modprobe.d/blacklist-nouveau.conf
        fi

        install_nvidia_driver_for_installed_kernels
        pacman -S --needed --noconfirm egl-wayland libva-nvidia-driver libva-utils || true

        echo -e "${BBlue}Adjusting /etc/mkinitcpio.conf for NVIDIA...${NC}"
        bl_set_hooks \
            --hook kms \
            --module nvidia \
            --module nvidia_drm \
            --module nvidia_uvm \
            --module nvidia_modeset

        echo -e "${BBlue}Writing NVIDIA modprobe options for suspend/resume...${NC}"
        cat > /etc/modprobe.d/nvidia.conf <<'EOF'
# Preserve GPU memory across suspend/hibernate.
# Pair with nvidia-suspend.service / nvidia-resume.service / nvidia-hibernate.service.
options nvidia NVreg_PreserveVideoMemoryAllocations=1
EOF

        systemctl enable nvidia-suspend.service 2>/dev/null || true
        systemctl enable nvidia-resume.service 2>/dev/null || true
        systemctl enable nvidia-hibernate.service 2>/dev/null || true

        BOOT_EXTRA_CMDLINE+=(nvidia-drm.modeset=1 nvidia-drm.fbdev=1)
    fi
fi

# --- Optional NVIDIA tensor-core unlock (Zagitta/gpu-unlock) ---
if [[ "$INSTALL_GPU_UNLOCK" == "true" ]]; then
    echo -e "${BBlue}Installing optional NVIDIA tensor-core unlock (Zagitta/gpu-unlock)...${NC}"
    if /usr/local/lib/awesomearchlinux/gpu-unlock.sh \
        --install \
        --yes \
        --no-bootloader \
        --build-user "$USERNAME" \
        --targets "$GPU_UNLOCK_TARGETS"; then
        BOOT_EXTRA_CMDLINE+=("gpu_unlock.targets=${GPU_UNLOCK_TARGETS}")
        echo -e "${BGreen}gpu-unlock installed; queued gpu_unlock.targets=${GPU_UNLOCK_TARGETS} for bootloader configuration.${NC}"
    else
        echo -e "${BYellow}WARNING: gpu-unlock build/install failed during chroot (e.g. transient network download issue).${NC}" >&2
        echo -e "${BYellow}Continuing bootloader configuration so the system remains bootable. Retry after first boot with:${NC}" >&2
        echo -e "${BYellow}  sudo awesome-gpu-unlock --install --targets ${GPU_UNLOCK_TARGETS}${NC}" >&2
    fi
fi

# --- Detect AMD/Radeon (standalone or hybrid iGPU + NVIDIA dGPU) ---
if lspci | grep -Ei "VGA|3D|Display" | grep -Ei 'amd|radeon|advanced micro devices' &>/dev/null; then
    AMD_CARD=true
    echo -e "${BBlue}Found an AMD/Radeon GPU...${NC}"
    amd_gpu_model=$(lspci | grep -Ei 'vga|3d|2d|display' | grep -Ei 'amd|radeon|advanced micro devices' | cut -d ':' -f3-)
    echo "Detected AMD GPU:$amd_gpu_model"

    case "$amd_gpu_model" in
        *"APU"*|*"Ryzen"*|*"Athlon"*|*"Radeon Graphics"*)
            pacman -S --needed --noconfirm mesa vulkan-radeon libva-utils
            ;;
        *)
            pacman -S --needed --noconfirm xf86-video-amdgpu mesa vulkan-radeon libva-utils
            ;;
    esac
fi

# --- Detect Intel GPU (standalone or hybrid Optimus iGPU + NVIDIA dGPU) ---
if lspci | grep -Ei "VGA|3D|Display" | grep -qi intel &>/dev/null; then
    INTEL_CARD=true
    echo -e "${BBlue}Found an Intel GPU...${NC}"
    intel_gpu_model=$(lspci | grep -Ei 'vga|3d|display' | grep -i intel | cut -d ':' -f3-)
    echo "Detected Intel GPU:$intel_gpu_model"
    # xf86-video-intel is deprecated and fights modesetting. mesa +
    # intel-media-driver (iHD) + libva-intel-driver (i965 fallback)
    # covers Gen5 through current Arc.
    pacman -S --needed --noconfirm mesa vulkan-intel intel-media-driver libva-intel-driver libva-utils intel-gpu-tools
fi

# --- If neither NVIDIA, AMD, nor Intel was found, install basic drivers ---
if [[ "$NVIDIA_CARD" == false && "$AMD_CARD" == false && "$INTEL_CARD" == false ]]; then
    echo -e "${BBlue}No supported NVIDIA, AMD, or Intel GPU detected. Installing basic drivers...${NC}"
    pacman -S --needed --noconfirm xf86-video-vesa mesa
    # Do NOT touch mkinitcpio or grub in this fallback.
fi

# I/O scheduler policy: BFQ for HDDs, mq-deadline for SATA/virtio SSD, none
# for NVMe. Live systems can refresh this with utils/iosched.sh.
mkdir -p /etc/udev/rules.d
cat > /etc/udev/rules.d/60-awesome-ioschedulers.rules <<'EOF'
ACTION=="add|change", SUBSYSTEM=="block", KERNEL=="sd[a-z]|vd[a-z]|xvd[a-z]|hd[a-z]", ATTR{queue/rotational}=="1", ATTR{queue/scheduler}="bfq"
ACTION=="add|change", SUBSYSTEM=="block", KERNEL=="sd[a-z]|vd[a-z]|xvd[a-z]", ATTR{queue/rotational}=="0", ATTR{queue/scheduler}="mq-deadline"
ACTION=="add|change", SUBSYSTEM=="block", KERNEL=="nvme[0-9]*n[0-9]*", ATTR{queue/scheduler}="none"
ACTION=="add|change", SUBSYSTEM=="block", KERNEL=="mmcblk[0-9]", ATTR{queue/scheduler}="bfq"
EOF

sleep 2

case "$INSTALL_BOOTLOADER" in
    grub)
        configure_grub
        ;;
    uki)
        configure_systemd_boot_uki
        ;;
esac

sleep 2

if [[ "$INSTALL_BOOTLOADER" == "grub" ]]; then
    chmod 600 "$LUKS_KEYS"
fi

# Creating pre-login banners (/etc/issue for console, /etc/issue.net for SSH without getty escapes)
echo -e "${BBlue}Creating Banners (/etc/issue and /etc/issue.net).${NC}"

cat > /etc/issue.net << 'EOF'
                     .ed"""" """$$$$be.
                   -"           ^""**$$$e.
                 ."                   '$$$c
                /                      "4$$b
               d  3                     $$$$
               $  *                   .$$$$$$
              .$  ^c           $$$$$e$$$$$$$$.
              d$L  4.         4$$$$$$$$$$$$$$b
              $$$$b ^ceeeee. 4$$ECL.F*$$$$$$$
  e$""=.      $$$$P d$$$$F $ $$$$$$$$- $$$$$$
 z$$b. ^c     3$$$F "$$$$b   $"$$$$$$$  $$$$*"      .=""$c
4$$$$L   \     $$P"  "$$b   .$ $$$$$...e$$        .=  e$$$.
^*$$$$$c  %..   *c    ..    $$ 3$$$$$$$$$$eF     zP  d$$$$$
  "**$$$ec   "\   %ce""    $$$  $$$$$$$$$$*    .r" =$$$$P""
        "*$b. "c  *$e.    *** d$$$$$"L$$    .d"  e$$***"
          ^*$$c ^$c $$$      4J$$$$$% $$$ .e*".eeP"
             "$$$$$$"'$=e....$*$$**$cz$$" "..d$*"
               "*$$$  *=%4.$ L L$ P3$$$F $$$P"
                  "$   "%*ebJLzb$e$$$$$b $P"
                    %..      4$$$$$$$$$$ "
                     $$$e   z$$$$$$$$$$%
                      "*$c  "$$$$$$$P"
                       ."""*$$$$$$$$bc
                    .-"    .$***$$$"""*e.
                 .-"    .e$"     "*$c  ^*b.
          .=*""""    .e$*"          "*bc  "*$e..
        .$"        .z*"               ^*$e.   "*****e.
        $$ee$c   .d"                     "*$.        3.
        ^*$E")$..$"                         *   .ee==d%
           $.d$$$*                           *  J$$$e*
            """""                             "$$$"

********************************************************************
*                                                                  *
* This system is for the use of authorized users only. Usage of    *
* this system may be monitored and recorded by system personnel.   *
*                                                                  *
* Anyone using this system expressly consents to such monitoring   *
* and is advised that if such monitoring reveals possible          *
* evidence of criminal activity, system personnel may provide the  *
* evidence from such monitoring to law enforcement officials.      *
*                                                                  *
********************************************************************
EOF
cp /etc/issue.net /etc/issue

echo -e "${BBlue}Setting permission on config files...${NC}"

chmod 0700 /boot
# /home is traversable (users can reach their own dir) but not listable:
# `ls /home` reveals no usernames to non-root observers. Per-user dirs
# stay 700 via HOME_MODE in login.defs.
#
# We set it two ways: a one-shot chmod here, AND a tmpfiles.d rule that
# re-applies the mode on every boot. The tmpfiles rule is the
# authoritative one — it survives package post-install hooks (pambase,
# systemd, etc.) that sometimes chmod /home back to 755.
chmod 0711 /home
install -Dm644 /dev/stdin /etc/tmpfiles.d/home-perms.conf <<'EOF'
# Keep /home traversable-but-not-listable across boots. See chroot.sh.
d /home 0711 root root -
EOF
chmod 644 /etc/passwd
chown root:root /etc/passwd
chmod 644 /etc/group
chown root:root /etc/group
chmod 600 /etc/shadow
chown root:root /etc/shadow
chmod 600 /etc/gshadow
chown root:root /etc/gshadow
chown root:root /etc/ssh/sshd_config
chmod 600 /etc/ssh/sshd_config
chown root:root /etc/fstab
chmod 644 /etc/fstab
chown root:root /etc/issue /etc/issue.net
chmod 644 /etc/issue /etc/issue.net
if [[ "$INSTALL_BOOTLOADER" == "grub" && -f /boot/grub/grub.cfg ]]; then
    chown root:root /boot/grub/grub.cfg
    chmod og-rwx /boot/grub/grub.cfg
fi
chown root:root /etc/sudoers.d/
chmod 750 /etc/sudoers.d
chown -c root:root /etc/sudoers
chmod -c 0440 /etc/sudoers
# Never set the 2000 setgid bit on root-owned binaries or break normal user ping/whereis.
if [[ -g /usr/bin/ping ]]; then
    chmod 00755 /usr/bin/ping
    setcap cap_net_raw=ep /usr/bin/ping 2>/dev/null || true
fi
chmod 00755 /usr/bin/whereis
chown root:proc /usr/bin/w /usr/bin/who
chmod 00750 /usr/bin/w /usr/bin/who
chmod 0644 /etc/login.defs

sleep 1

# Password policy is configured before the initial passwd calls above.


echo -e "${BBlue}Setting up daily package update checks...${NC}"
pacman -S --noconfirm pacman-contrib
cat <<'EOF' > /etc/systemd/system/pacman-autoupdate.timer
[Unit]
Description=Run package update check daily

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF
cat <<'EOF' > /etc/systemd/system/pacman-autoupdate.service
[Unit]
Description=Check for available package updates (notification only)
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
# checkupdates syncs a temporary database, leaving pacman's live sync database
# untouched. Exit 2 means there are no pending updates and is not an error.
ExecStart=/usr/bin/checkupdates
# truncate: (not file:) so a shorter list does not keep the tail of an older one.
StandardOutput=truncate:/var/log/pacman-updates.log
StandardError=inherit
SuccessExitStatus=2
EOF
systemctl enable pacman-autoupdate.timer

sleep 2

# --- Systemd Services Hardening ---
echo -e "${BBlue}Hardening systemd services...${NC}"

# SSH Service
echo -e "${BBlue}Hardening SSH service...${NC}"
mkdir -p /etc/systemd/system/sshd.service.d/
cat > /etc/systemd/system/sshd.service.d/hardening.conf <<'EOF'
[Service]
# sshd spawns interactive user sessions: PrivateTmp=yes and ProtectControlGroups=yes
# isolate local /tmp IPC sockets and break rootless container cgroup delegation.
PrivateTmp=no
NoNewPrivileges=no
ProtectSystem=no
ProtectHome=no
ProtectKernelTunables=no
ProtectKernelModules=no
ProtectKernelLogs=no
ProtectControlGroups=no
# RestrictAddressFamilies=, LockPersonality= and RestrictRealtime= are seccomp
# filters. They are inherited by every process sshd starts, i.e. by each login
# session, and not even sudo can lift them: tcpdump, nmap, AF_ALG users and
# setarch would all fail over SSH. They are therefore deliberately not set.
IPAddressAllow=any
IPAddressDeny=
PrivateDevices=no
DevicePolicy=auto
Restart=on-failure
RestartSec=5s
EOF

# NetworkManager hardening
echo -e "${BBlue}Hardening NetworkManager...${NC}"
mkdir -p /etc/systemd/system/NetworkManager.service.d/
cat > /etc/systemd/system/NetworkManager.service.d/hardening.conf <<'EOF'
[Service]
RuntimeDirectory=NetworkManager
# Keep /run/NetworkManager across a restart: it holds the state NM uses to
# take its devices over again without tearing the connections down.
RuntimeDirectoryPreserve=yes
StateDirectory=NetworkManager
ProtectSystem=strict
ReadWritePaths=-/etc/NetworkManager -/etc/resolv.conf
# read-only like the upstream unit, not "yes": 802.1X and VPN profiles
# commonly reference certificates and keys stored under /home.
ProtectHome=read-only
ProtectKernelTunables=no
ProtectKernelModules=no
ProtectControlGroups=yes
ProtectKernelLogs=yes
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_DAC_OVERRIDE CAP_SETUID CAP_SETGID CAP_SYS_MODULE
NoNewPrivileges=no
PrivateDevices=no
DevicePolicy=auto
RestrictRealtime=yes
LockPersonality=yes
Restart=on-failure
RestartSec=5s
EOF

# Auditd hardening
echo -e "${BBlue}Hardening auditd...${NC}"
mkdir -p /etc/systemd/system/auditd.service.d/
cat > /etc/systemd/system/auditd.service.d/hardening.conf <<'EOF'
[Service]
# auditd manages the kernel audit subsystem — ProtectControlGroups=yes breaks
# /proc audit rule operations and is explicitly unsupported upstream.
ProtectSystem=full
ProtectHome=yes
ReadWritePaths=/var/log/audit /run
CapabilityBoundingSet=CAP_AUDIT_CONTROL CAP_AUDIT_READ CAP_AUDIT_WRITE CAP_DAC_READ_SEARCH CAP_SYS_NICE CAP_SYS_RESOURCE
PrivateDevices=yes
PrivateTmp=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
EOF

# ClamAV hardening
echo -e "${BBlue}Hardening ClamAV services...${NC}"
mkdir -p /etc/systemd/system/clamav-daemon.service.d/
cat > /etc/systemd/system/clamav-daemon.service.d/hardening.conf <<'EOF'
[Service]
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/lib/clamav /var/log/clamav /run
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictRealtime=yes
LockPersonality=yes
LimitNOFILE=8192
# clamd's default MaxThreads is 10, plus the listener, a database-reload
# thread and helpers; 16 made multi-threaded scans fail to spawn workers.
TasksMax=64
Restart=on-failure
RestartSec=10s
EOF

# Fail2ban hardening
echo -e "${BBlue}Hardening fail2ban...${NC}"
mkdir -p /etc/systemd/system/fail2ban.service.d/
cat > /etc/systemd/system/fail2ban.service.d/hardening.conf <<'EOF'
[Service]
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=
ReadWritePaths=/var/lib/fail2ban /var/log /run/fail2ban
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
CapabilityBoundingSet=
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_READ_SEARCH CAP_DAC_OVERRIDE
NoNewPrivileges=no
PrivateTmp=yes
PrivateDevices=yes
RestrictAddressFamilies=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
RestrictRealtime=yes
LockPersonality=yes
Restart=on-failure
RestartSec=5s
EOF

# Stubby is no longer part of the default install — native systemd-resolved
# DoT is used instead (see the DNS section above). Users who want Stubby
# can install and harden it manually as a server-side opt-in.

# systemd-resolved is already well-hardened by its upstream unit file.
# A custom drop-in would replace (not extend) its tuned SystemCallFilter,
# which can break resolved. Trust the upstream hardening.

# Chrony NTP hardening
echo -e "${BBlue}Hardening Chrony NTP...${NC}"
install -d -o chrony -g chrony -m 0750 /var/log/chrony
mkdir -p /etc/systemd/system/chronyd.service.d/
cat > /etc/systemd/system/chronyd.service.d/hardening.conf <<'EOF'
[Service]
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=
ReadWritePaths=/run /var/lib/chrony -/var/log/chrony
ProtectKernelTunables=no
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=no
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=no
CapabilityBoundingSet=
CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_CHOWN CAP_DAC_OVERRIDE CAP_SYS_TIME CAP_NET_BIND_SERVICE
SystemCallFilter=
SystemCallFilter=@system-service @clock
SystemCallErrorNumber=EPERM
RestrictAddressFamilies=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
RestrictRealtime=yes
LockPersonality=yes
Restart=on-failure
RestartSec=5s
EOF

# NOTE: systemd-journald and rngd are NOT hardened via the generic template.
# journald is already well-hardened upstream; the generic template breaks logging.
# rngd needs direct device access (/dev/hwrng) which the generic template blocks.

# Reload systemd to apply all changes
echo -e "${BBlue}Reloading systemd daemon to apply hardening...${NC}"
systemctl daemon-reload

# Parse the complete units after composing upstream files and local drop-ins.
# This works inside arch-chroot without a running systemd and catches unknown
# directives, malformed values, and broken dependencies before first boot.
SYSTEMD_HARDENING_CANDIDATES=(
    sshd.service
    NetworkManager.service
    auditd.service
    audit-rules.service
    awesome-journal-sealing.service
    systemd-journal-flush.service
    awesome-board-health.service
    awesome-board-health.timer
    clamav-daemon.service
    fail2ban.service
    chronyd.service
    usbguard.service
    bluetooth.service
    arch-audit.service
    arch-audit-alert.service
    arch-audit.timer
    rkhunter-check.service
    rkhunter-check.timer
    pacman-autoupdate.service
    pacman-autoupdate.timer
)
SYSTEMD_HARDENED_UNITS=()
for unit in "${SYSTEMD_HARDENING_CANDIDATES[@]}"; do
    if [[ -e "/etc/systemd/system/$unit" || -L "/etc/systemd/system/$unit" ||
          -e "/usr/local/lib/systemd/system/$unit" || -L "/usr/local/lib/systemd/system/$unit" ||
          -e "/usr/lib/systemd/system/$unit" || -L "/usr/lib/systemd/system/$unit" ]]; then
        SYSTEMD_HARDENED_UNITS+=("$unit")
    fi
done
if ! systemd-analyze verify "${SYSTEMD_HARDENED_UNITS[@]}"; then
    echo -e "${BRed}Systemd unit verification failed; refusing to leave broken service configuration.${NC}" >&2
    exit 1
fi

echo -e "${BGreen}Systemd services hardening completed!${NC}"

sleep 2

# --- System Hardening (sysctl) ---
harden_sysctl() {

  echo -e "${BBlue}Applying sysctl profile: ${SYSCTL_PROFILE}...${NC}"

  if [ -x "/sysctl-profile/sysctl.sh" ]; then
    local -a sysctl_args=("$SYSCTL_PROFILE" "--no-apply")
    if [[ "$SYSCTL_DISABLE_IPV6" == true ]]; then
      sysctl_args+=("--disable-ipv6")
    fi
    /sysctl-profile/sysctl.sh "${sysctl_args[@]}"
    rm -rf -- /sysctl-profile
    sleep 2
    return
  fi

  # Compatibility with installers from before the composable profile bundle.
  if [ -f "/sysctl-profile.conf" ]; then
    install -m 0644 /sysctl-profile.conf /etc/sysctl.d/99-sysctl.conf
    sysctl --load=/etc/sysctl.d/99-sysctl.conf
    rm -f /sysctl-profile.conf
    sleep 2
    return
  fi

  if [ -x "/sysctl.sh" ]; then
    /sysctl.sh
    sleep 2
    shred -u /sysctl.sh
    return
  fi

  echo "Error: no sysctl profile or sysctl.sh found" >&2
  exit 1
}

harden_sysctl

# Finalize rkhunter file property baseline AFTER all packages and binary
# permission changes (compilers group, w/who, sshd, bootloaders) are in place.
echo -e "${BBlue}Updating rkhunter file property database...${NC}"
rkhunter --propupd

sleep 2

echo -e "${BBlue}Pointing /etc/resolv.conf at the resolved stub for first boot...${NC}"
chattr -i /etc/resolv.conf 2>/dev/null || true
umount /etc/resolv.conf 2>/dev/null || true
rm -f /etc/resolv.conf
ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf

echo -e "${BBlue}Installation completed! You can reboot the system now.${NC}"
# Securely remove sensitive files at the very end so intermediate failures
# remain resumable via recovery-mount.sh
shred -u /ssh.sh 2>/dev/null || true
shred -u /nftables.sh 2>/dev/null || true
# Leave a small permanent record of the install profile. /root/.install-env is
# removed below (it holds install-time details), and utils/audit-check.sh must
# not have to guess from "runs in a VM" whether this is a workstation or a VPS.
printf 'INSTALL_TYPE=baremetal\n' > /etc/awesome-install-profile
chmod 0644 /etc/awesome-install-profile
shred -u /root/.install-env 2>/dev/null || true
shred -u /bootloader.sh 2>/dev/null || true
shred -u /chroot.sh 2>/dev/null || true
exit
