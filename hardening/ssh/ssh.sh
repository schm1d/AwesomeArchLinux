#!/usr/bin/env bash

# =============================================================================
# Script:      ssh.sh
# Description: Hardens OpenSSH server and client configuration on Arch Linux.
#              Regenerates host keys (Ed25519 + RSA 4096) on the first run,
#              enforces modern cryptographic algorithms, restricts access,
#              and applies CIS Benchmark recommendations for SSH.
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
#
# Usage:       sudo ./ssh.sh [-u ALLOWED_USER] [-p PORT] [-k] [-r] [-h]
#
# =============================================================================

set -euo pipefail
umask 022

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck disable=SC1090,SC1091
if [[ -f "$SCRIPT_DIR/../lib/nftables.sh" ]]; then
    source "$SCRIPT_DIR/../lib/nftables.sh"
elif [[ -f "$SCRIPT_DIR/nftables.sh" ]]; then
    source "$SCRIPT_DIR/nftables.sh"
else
    echo "ERROR: required nftables.sh helper not found; copy it beside ssh.sh before running." >&2
    exit 1
fi
if ! declare -F aal_nft_persist_block >/dev/null || ! declare -F aal_nft_remove_live_rules >/dev/null; then
    echo "ERROR: nftables.sh is missing required functions; refusing to change SSH configuration." >&2
    exit 1
fi

BBlue='\033[1;34m'
BRed='\033[1;31m'
BGreen='\033[1;32m'
BYellow='\033[1;33m'
NC='\033[0m'

SSH_PORT=22
REVOKED_KEYS_FILE='/etc/ssh/revokedKeys'

# --- Parse Arguments ---
show_help() {
    echo "Usage: sudo $0 [-u ALLOWED_USER] [-p PORT] [-k] [-r] [-h]"
    echo "  -u USER   User to allow SSH access (required, must not be root)"
    echo "  -p PORT   SSH listening port (default: 22)"
    echo "  -k        Skip the authorized_keys lockout check. Use ONLY on bare-metal"
    echo "            installs where console access is guaranteed. Never use on VPS."
    echo "  -r        Regenerate the host keys even if this script already created"
    echo "            them. Every client then has to accept the new fingerprints."
    echo "  -h        Show this help"
    exit 0
}

ALLOWED_USERS=""
SKIP_KEY_CHECK=0
REGENERATE_HOST_KEYS=0
while getopts ":u:p:krh" opt; do
    case "$opt" in
        u) ALLOWED_USERS="$OPTARG" ;;
        p) SSH_PORT="$OPTARG" ;;
        k) SKIP_KEY_CHECK=1 ;;
        r) REGENERATE_HOST_KEYS=1 ;;
        h) show_help ;;
        :) echo -e "${BRed}ERROR: -${OPTARG} requires an argument.${NC}" >&2; exit 1 ;;
        \?) echo -e "${BRed}ERROR: Unknown option: -${OPTARG}.${NC}" >&2; exit 1 ;;
    esac
done

# Check if the user is root
if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root." 1>&2
   exit 1
fi
if [[ ! "$SSH_PORT" =~ ^[0-9]+$ ]] || (( 10#$SSH_PORT < 1 || 10#$SSH_PORT > 65535 )); then
    echo -e "${BRed}ERROR: SSH port must be between 1 and 65535.${NC}" >&2
    exit 1
fi
# Store the canonical decimal form. sshd reads "02222" as 2222 while nft reads
# it as octal 1170, so a leading zero would open the wrong firewall port.
SSH_PORT=$((10#$SSH_PORT))

# Resolve ALLOWED_USERS: flag > SUDO_USER > prompt
if [ -z "$ALLOWED_USERS" ]; then
    ALLOWED_USERS="${SUDO_USER:-}"
fi
if [ -z "$ALLOWED_USERS" ] || [ "$ALLOWED_USERS" = "root" ]; then
    echo -e "${BRed}ERROR: ALLOWED_USERS must be a non-root user.${NC}" >&2
    echo "Specify with: sudo $0 -u <username>" >&2
    echo "Or run via: sudo -u root ./ssh.sh (SUDO_USER will be detected)" >&2
    exit 1
fi
if [[ ! "$ALLOWED_USERS" =~ ^[a-z_][a-z0-9_-]*[$]?$ ]] || (( ${#ALLOWED_USERS} > 32 )); then
    echo -e "${BRed}ERROR: Invalid username format for ALLOWED_USERS: '${ALLOWED_USERS}'.${NC}" >&2
    exit 1
fi
echo -e "${BGreen}SSH access will be granted to: ${ALLOWED_USERS}${NC}"

# SAFETY: refuse to disable password auth unless the allowed user already has
# a usable authorized_keys file — prevents instant lockout.
ALLOWED_HOME="$(getent passwd "$ALLOWED_USERS" | cut -d: -f6)"
if [[ -z "${ALLOWED_HOME:-}" || ! -d "$ALLOWED_HOME" ]]; then
    echo -e "${BRed}ERROR: Could not resolve home directory for ${ALLOWED_USERS}.${NC}" >&2
    exit 1
fi
ALLOWED_GROUP="$(id -gn "$ALLOWED_USERS")"

in_chroot() {
    if command -v systemd-detect-virt &>/dev/null && systemd-detect-virt --chroot --quiet 2>/dev/null; then
        return 0
    fi
    [[ "$(stat -c %d:%i /)" != "$(stat -c %d:%i /proc/1/root/. 2>/dev/null || echo chroot)" ]]
}

# The sshd_config written below only accepts the key types listed in its
# PubkeyAcceptedAlgorithms line. A non-empty authorized_keys that holds only
# other types (plain ECDSA, DSA) passes an emptiness check and still locks the
# user out, so look at what the keys actually are. ssh-keygen prints one line
# per key that ends in the type; RSA keys below 1024 bits are refused by sshd
# (RequiredRSASize default).
has_accepted_authorized_key() {
    local key_file="$1" listing
    listing=$(ssh-keygen -lf "$key_file" 2>/dev/null || true)
    awk '
        { type = $NF }
        type == "(ED25519)" || type == "(ED25519-SK)" || type == "(ECDSA-SK)" { ok = 1 }
        type == "(RSA)" && $1 + 0 >= 1024 { ok = 1 }
        END { exit ok ? 0 : 1 }
    ' <<< "$listing"
}

AUTHORIZED_KEYS_FILE="${ALLOWED_HOME}/.ssh/authorized_keys"
if [[ ! -s "$AUTHORIZED_KEYS_FILE" ]]; then
    if [[ "$SKIP_KEY_CHECK" -eq 1 ]]; then
        echo -e "${BYellow}WARNING: ${AUTHORIZED_KEYS_FILE} is missing or empty.${NC}" >&2
        echo -e "${BYellow}Proceeding anyway because -k was passed. Password auth will be disabled.${NC}" >&2
        echo -e "${BYellow}You MUST add a key via console login before remote SSH will work.${NC}" >&2
        install -d -m 700 -o "$ALLOWED_USERS" -g "$ALLOWED_GROUP" "${ALLOWED_HOME}/.ssh"
        install -m 600 -o "$ALLOWED_USERS" -g "$ALLOWED_GROUP" /dev/null "$AUTHORIZED_KEYS_FILE"
    else
        echo -e "${BRed}ERROR: ${AUTHORIZED_KEYS_FILE} is missing or empty.${NC}" >&2
        echo -e "${BYellow}Refusing to apply PasswordAuthentication=no / AllowUsers / restart sshd (lockout prevention).${NC}" >&2
        echo -e "${BYellow}On a bare-metal install with console access, re-run with -k to bypass.${NC}" >&2
        exit 1
    fi
elif ! has_accepted_authorized_key "$AUTHORIZED_KEYS_FILE"; then
    if [[ "$SKIP_KEY_CHECK" -eq 1 ]]; then
        echo -e "${BYellow}WARNING: ${AUTHORIZED_KEYS_FILE} holds no key type the hardened sshd accepts.${NC}" >&2
        echo -e "${BYellow}Proceeding anyway because -k was passed. Remote SSH will not work until an${NC}" >&2
        echo -e "${BYellow}Ed25519, FIDO2 (sk-) or RSA key is added via console login.${NC}" >&2
    else
        echo -e "${BRed}ERROR: ${AUTHORIZED_KEYS_FILE} holds no key type the hardened sshd accepts.${NC}" >&2
        echo -e "${BYellow}Accepted: ssh-ed25519, sk-ssh-ed25519@openssh.com, sk-ecdsa-sha2-nistp256@openssh.com${NC}" >&2
        echo -e "${BYellow}and ssh-rsa. Plain ECDSA (ecdsa-sha2-*) and DSA keys are rejected.${NC}" >&2
        echo -e "${BYellow}Add such a key (ssh-keygen -t ed25519) and re-run; refusing to change sshd (lockout prevention).${NC}" >&2
        exit 1
    fi
fi

if [ ! -d /etc/ssh ]; then
    echo -e "${BRed}ERROR: /etc/ssh does not exist. Is openssh installed?${NC}" >&2
    exit 1
fi

# Ports of the configuration that is in effect before this run. They decide
# whether sshd is being moved to another port, which is the one case where a
# firewall mistake cuts off the session this script is running in.
# (sshd -T prints the keyword as "port" or "Port" depending on the version.)
OLD_SSH_PORTS=()
while IFS= read -r old_ssh_port; do
    if [[ "$old_ssh_port" =~ ^[0-9]+$ ]]; then
        OLD_SSH_PORTS+=("$old_ssh_port")
    fi
done < <(sshd -T 2>/dev/null | awk 'tolower($1) == "port" { print $2 }' || true)
if (( ${#OLD_SSH_PORTS[@]} == 0 )); then
    OLD_SSH_PORTS=(22)
fi
SSH_PORT_MOVES=1
for old_ssh_port in "${OLD_SSH_PORTS[@]}"; do
    if [[ "$old_ssh_port" == "$SSH_PORT" ]]; then
        SSH_PORT_MOVES=0
    fi
done

# --- TOTP second factor (hardening/totp/totp.sh) ---
# totp.sh keeps its sshd settings (public key + TOTP) in this drop-in. The
# sshd_config written below includes that one file before any other setting,
# and sshd keeps the first value it reads for a keyword, so the drop-in stays
# authoritative when this script is run again. Without the drop-in the
# public-key-only settings of the main file apply.
TOTP_DROPIN="/etc/ssh/sshd_config.d/00-awesome-totp.conf"
PREV_AUTH_METHODS=$(sshd -T 2>/dev/null |
    awk 'tolower($1) == "authenticationmethods" { $1 = ""; sub(/^[[:space:]]+/, ""); print; exit }' || true)
TOTP_NOTICE=()
if [[ -s "$TOTP_DROPIN" ]]; then
    if [[ "$PREV_AUTH_METHODS" == *keyboard-interactive* ]]; then
        echo -e "${BBlue}TOTP drop-in ${TOTP_DROPIN} found: it stays in force (public key + TOTP).${NC}"
    else
        # The drop-in exists but the running configuration did not read it
        # (sshd_config written by an earlier version of this script).
        TOTP_NOTICE+=(
            "WARNING: ${TOTP_DROPIN} (written by totp.sh) was not in effect before this run."
            "This run includes it again: once it completes, SSH logins require the public key AND a"
            "TOTP code. Test a new login before closing this session. To stay with public key only,"
            "delete that file and re-run this script."
        )
    fi
elif [[ "$PREV_AUTH_METHODS" == *keyboard-interactive* ]]; then
    # TOTP was configured in the main sshd_config, which is rewritten below.
    TOTP_NOTICE+=(
        "WARNING: the previous sshd_config required keyboard-interactive (TOTP) in addition to the"
        "public key. This run rewrites sshd_config with public key only: TOTP IS OFF once it completes."
        "Re-run hardening/totp/totp.sh afterwards to enable it again: it stores its settings in"
        "${TOTP_DROPIN}, which later runs of this script keep."
    )
fi

# --- Firewall backend ---
# Decided before anything is changed, so that a port move that cannot be
# opened in the firewall is refused while the system is still untouched.
NFT_CONF_PATH="${AAL_NFT_CONFIG:-/etc/nftables.conf}"

# The managed block can only be persisted into the installer-owned ruleset,
# which starts with "flush ruleset". Any other /etc/nftables.conf (stock Arch
# ships one) is left alone; it only matters when nftables.service loads it.
FIREWALL_MODE=none
NFT_PERSIST=0
NFT_LIVE=0
NFT_CONF_FOREIGN=0
if command -v nft &>/dev/null; then
    if [[ -f "$NFT_CONF_PATH" ]]; then
        if grep -Eq '^[[:space:]]*flush[[:space:]]+ruleset([[:space:]]|$)' "$NFT_CONF_PATH"; then
            NFT_PERSIST=1
        elif systemctl is-enabled --quiet nftables.service 2>/dev/null; then
            NFT_CONF_FOREIGN=1
        fi
    fi
    if ! in_chroot && nft list chain inet filter input &>/dev/null; then
        NFT_LIVE=1
    fi
fi

# Succeeds when a rule of the foreign ruleset names the new SSH port, i.e. the
# administrator has already opened it there.
foreign_ruleset_names_ssh_port() {
    local port_re="$SSH_PORT"
    if (( SSH_PORT == 22 )); then
        port_re='(22|ssh)'
    fi
    grep -Eq "^[^#]*dport[^#]*[^[:alnum:]]${port_re}([^[:alnum:]]|\$)" "$NFT_CONF_PATH"
}

if (( NFT_CONF_FOREIGN )); then
    # The port cannot be opened in a ruleset this script does not own. Moving
    # sshd anyway would end in a lockout, so stop before anything is changed.
    if (( SSH_PORT_MOVES )) && ! foreign_ruleset_names_ssh_port; then
        echo -e "${BRed}ERROR: ${NFT_CONF_PATH} is loaded by nftables.service but is not the installer-owned${NC}" >&2
        echo -e "${BRed}ruleset (no \"flush ruleset\"), so port ${SSH_PORT} cannot be opened in it.${NC}" >&2
        echo -e "${BYellow}sshd currently uses port(s) ${OLD_SSH_PORTS[*]}. Add a rule such as \"tcp dport ${SSH_PORT} accept\" to${NC}" >&2
        echo -e "${BYellow}your ruleset, reload it and re-run, or keep the current port.${NC}" >&2
        echo -e "${BYellow}Refusing to move sshd (lockout prevention); nothing was changed.${NC}" >&2
        exit 1
    fi
    echo -e "${BYellow}WARNING: ${NFT_CONF_PATH} is not the installer-owned ruleset (no \"flush ruleset\").${NC}" >&2
    echo -e "${BYellow}The firewall is left untouched and no SSH rate limit will be installed.${NC}" >&2
    if (( SSH_PORT_MOVES )); then
        echo -e "${BYellow}It names port ${SSH_PORT}; make sure that ruleset is loaded before you disconnect.${NC}" >&2
    fi
    FIREWALL_MODE=unmanaged
elif (( NFT_PERSIST || NFT_LIVE )); then
    FIREWALL_MODE=nft
elif ! in_chroot && command -v iptables &>/dev/null && iptables -L -n &>/dev/null; then
    FIREWALL_MODE=iptables
fi

BACKUP_SUFFIX="bak.$(date +%Y%m%d%H%M%S)"
HOSTKEY_OLD_DIR=""
SSH_ROLLBACK_ARMED=0

# Undo everything this run changed under /etc/ssh. Used when validation or
# the firewall step fails, so sshd keeps the configuration it is running with.
rollback_ssh_changes() {
    local old_host_key
    SSH_ROLLBACK_ARMED=0
    echo -e "${BYellow}Rolling back to previous configuration...${NC}" >&2
    if [[ -f "/etc/ssh/sshd_config.${BACKUP_SUFFIX}" ]]; then
        cp "/etc/ssh/sshd_config.${BACKUP_SUFFIX}" /etc/ssh/sshd_config
        chmod 0600 /etc/ssh/sshd_config
    fi
    if [[ -f "/etc/ssh/ssh_config.${BACKUP_SUFFIX}" ]]; then
        cp "/etc/ssh/ssh_config.${BACKUP_SUFFIX}" /etc/ssh/ssh_config
        chmod 0644 /etc/ssh/ssh_config
    fi
    if [[ -n "$HOSTKEY_OLD_DIR" && -d "$HOSTKEY_OLD_DIR" ]]; then
        shred -u /etc/ssh/ssh_host_*key* 2>/dev/null || true
        for old_host_key in "$HOSTKEY_OLD_DIR"/ssh_host_*; do
            [[ -e "$old_host_key" ]] || continue
            mv -f -- "$old_host_key" /etc/ssh/
        done
        rmdir -- "$HOSTKEY_OLD_DIR" 2>/dev/null || true
        HOSTKEY_OLD_DIR=""
    fi
}

# Safety net for failures that are not handled explicitly below (set -e, a
# signal): until sshd has taken over the new configuration, an aborted run
# must not leave a half-applied one behind for the next sshd restart.
rollback_on_abort() {
    local status=$?
    if (( status != 0 && SSH_ROLLBACK_ARMED )); then
        echo -e "${BRed}ERROR: ssh.sh stopped unexpectedly (exit status ${status}).${NC}" >&2
        if declare -F undo_firewall_changes >/dev/null; then
            undo_firewall_changes || true
        fi
        rollback_ssh_changes || true
        if (( SSHD_RELOAD_ISSUED )); then
            systemctl reload-or-restart sshd.service || true
        fi
    fi
}
SSHD_RELOAD_ISSUED=0
trap rollback_on_abort EXIT
SSH_ROLLBACK_ARMED=1

# --- Host keys ---
# The first hardening run replaces whatever keys the system came with (images
# and templates frequently share theirs). Later runs keep the keys this script
# created: regenerating them makes every client fail with "REMOTE HOST
# IDENTIFICATION HAS CHANGED". Pass -r to force new keys.
host_key_bits() {
    ssh-keygen -lf "$1" 2>/dev/null | awk '{ print $1; exit }' || true
}

HOST_KEYS_REGENERATED=0
ALREADY_HARDENED=0
if grep -Fq 'generated by ssh.sh' /etc/ssh/sshd_config 2>/dev/null; then
    ALREADY_HARDENED=1
fi
RSA_HOST_KEY_BITS=$(host_key_bits /etc/ssh/ssh_host_rsa_key.pub)
if (( REGENERATE_HOST_KEYS == 0 && ALREADY_HARDENED == 1 )) &&
    [[ -s /etc/ssh/ssh_host_ed25519_key && -s /etc/ssh/ssh_host_ed25519_key.pub ]] &&
    [[ -s /etc/ssh/ssh_host_rsa_key && "${RSA_HOST_KEY_BITS:-0}" =~ ^[0-9]+$ ]] &&
    (( RSA_HOST_KEY_BITS >= 4096 )); then
    echo -e "${BBlue}Keeping the existing Ed25519 and RSA host keys (use -r to regenerate them).${NC}"
else
    echo -e "${BBlue}Creating ed25519 and RSA host keys...${NC}"
    # Generate into a private directory first so a failed ssh-keygen cannot
    # leave the host without keys, and keep the old keys until the new
    # configuration is live so a rollback can restore them.
    HOSTKEY_NEW_DIR=$(umask 077; mktemp -d /etc/ssh/.hostkeys-new.XXXXXX)
    if ! ssh-keygen -t ed25519 -f "$HOSTKEY_NEW_DIR/ssh_host_ed25519_key" -N "" < /dev/null ||
        ! ssh-keygen -t rsa -b 4096 -f "$HOSTKEY_NEW_DIR/ssh_host_rsa_key" -N "" < /dev/null; then
        rm -rf -- "$HOSTKEY_NEW_DIR"
        SSH_ROLLBACK_ARMED=0
        echo -e "${BRed}ERROR: Could not generate host keys; nothing was changed.${NC}" >&2
        exit 1
    fi
    HOSTKEY_OLD_DIR=$(umask 077; mktemp -d /etc/ssh/.hostkeys-old.XXXXXX)
    for old_host_key in /etc/ssh/ssh_host_*key*; do
        [[ -e "$old_host_key" ]] || continue
        mv -f -- "$old_host_key" "$HOSTKEY_OLD_DIR/"
    done
    mv -f -- "$HOSTKEY_NEW_DIR"/ssh_host_* /etc/ssh/
    rmdir -- "$HOSTKEY_NEW_DIR"
    HOST_KEYS_REGENERATED=1
fi

# Set correct permissions on host keys
chmod 600 /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_rsa_key
chmod 644 /etc/ssh/ssh_host_ed25519_key.pub /etc/ssh/ssh_host_rsa_key.pub
chown root:root /etc/ssh/ssh_host_*

echo -e "${BBlue}Hardening \"/etc/ssh/sshd_config\"...${NC}"
# Shown here, once nothing can refuse the run any more, and again at the end.
for totp_notice_line in "${TOTP_NOTICE[@]}"; do
    echo -e "${BYellow}${totp_notice_line}${NC}" >&2
done

# Back up original config
cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.${BACKUP_SUFFIX}"
chmod 0600 "/etc/ssh/sshd_config.${BACKUP_SUFFIX}"

touch "$REVOKED_KEYS_FILE"

# totp.sh only uses its drop-in when this directory exists.
install -d -o root -g root -m 0755 "${TOTP_DROPIN%/*}"

# Write a complete hardened sshd_config (truncate, not append — avoids first-match-wins issues)
cat > /etc/ssh/sshd_config << SSHD_EOF
# =============================================================================
# Hardened sshd_config — generated by ssh.sh
# Original backed up to: /etc/ssh/sshd_config.${BACKUP_SUFFIX}
# =============================================================================

# --- TOTP drop-in (owned by hardening/totp/totp.sh) ---
# Read first on purpose: sshd keeps the first value it reads for a keyword, so
# the public key + TOTP settings in this file override the public-key-only
# settings below. A missing file is ignored. No other drop-in is read.
Include ${TOTP_DROPIN}

# --- Network ---
Port ${SSH_PORT}
AddressFamily any
StrictModes yes

# --- Host Keys ---
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

# --- Cryptographic Algorithms (OpenSSH 9.x+ modern) ---
HostKeyAlgorithms ssh-ed25519-cert-v01@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group18-sha512,diffie-hellman-group16-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com

# --- Key Types ---
CASignatureAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519
HostbasedAcceptedAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
PubkeyAcceptedAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,sk-ecdsa-sha2-nistp256@openssh.com,rsa-sha2-512,rsa-sha2-256

# --- Authentication ---
AuthenticationMethods publickey
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PasswordAuthentication no
PermitEmptyPasswords no
KbdInteractiveAuthentication no
KerberosAuthentication no
GSSAPIAuthentication no
HostbasedAuthentication no
IgnoreRhosts yes
PermitUserEnvironment no
UsePAM yes

# --- Access Control ---
PermitRootLogin no
AllowUsers ${ALLOWED_USERS}
MaxAuthTries 3
MaxSessions 2
MaxStartups 10:30:60
LoginGraceTime 60

# --- Forwarding (all disabled) ---
DisableForwarding yes

# --- Session ---
X11Forwarding no
Banner /etc/issue.net
RekeyLimit 512M 1h
ClientAliveInterval 300
ClientAliveCountMax 3
TCPKeepAlive no
Compression no
PermitUserRC no
VersionAddendum none

# --- Logging ---
LogLevel VERBOSE
SyslogFacility AUTH
UseDNS no

# --- Revoked Keys ---
RevokedKeys ${REVOKED_KEYS_FILE}

# --- Subsystem ---
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/ssh/sftp-server -f AUTHPRIV -l INFO
SSHD_EOF

echo -e "${BBlue}Hardening \"/etc/ssh/ssh_config\"...${NC}"
cp /etc/ssh/ssh_config "/etc/ssh/ssh_config.${BACKUP_SUFFIX}" 2>/dev/null || true

cat > /etc/ssh/ssh_config << 'SSH_CLIENT_EOF'
# Hardened ssh_config — generated by ssh.sh

HashKnownHosts yes

Host *
    ConnectTimeout 30
    ServerAliveInterval 10
    HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
    KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group18-sha512,diffie-hellman-group16-sha512
    Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
    MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
    StrictHostKeyChecking accept-new
    UpdateHostKeys ask
SSH_CLIENT_EOF

# Connection multiplexing is scoped to the allowed user, the only account the
# socket directory is created for. Set for every user, a ControlPath inside a
# directory that does not exist makes ssh, scp, rsync and git over ssh fail
# outright for root and all other accounts. %C keeps the socket path short
# enough for the 108-byte UNIX socket limit.
cat >> /etc/ssh/ssh_config << SSH_CLIENT_MUX_EOF

Match localuser ${ALLOWED_USERS}
    ControlMaster auto
    ControlPersist 10m
    ControlPath ~/.ssh/sockets/%C
SSH_CLIENT_MUX_EOF

# Create ControlPath socket directory for SSH multiplexing
if [ -n "$ALLOWED_HOME" ]; then
    install -d -m 700 -o "$ALLOWED_USERS" -g "$ALLOWED_GROUP" "$ALLOWED_HOME/.ssh" "$ALLOWED_HOME/.ssh/sockets"
fi

echo -e "${BBlue}Hardening permissions...${NC}"
chown root:root /etc/ssh/sshd_config /etc/ssh/ssh_config "$REVOKED_KEYS_FILE"
chmod 0600 /etc/ssh/sshd_config
chmod 0644 /etc/ssh/ssh_config "$REVOKED_KEYS_FILE"

echo -e "${BBlue}Creating Banner (/etc/issue.net).${NC}"

cat > /etc/issue.net << EOF
                     .ed"""" """\$\$\$\$be.
                   -"           ^""**\$\$\$e.
                 ."                   '\$\$\$c
                /                      "4\$\$b
               d  3                     \$\$\$\$
               \$  *                   .\$\$\$\$\$\$
              .\$  ^c           \$\$\$\$\$e\$\$\$\$\$\$\$\$.
              d\$L  4.         4\$\$\$\$\$\$\$\$\$\$\$\$\$\$b
              \$\$\$\$b ^ceeeee.  4\$\$ECL.F*\$\$\$\$\$\$\$
  e\$""=.      \$\$\$\$P d\$\$\$\$F \$ \$\$\$\$\$\$\$\$\$- \$\$\$\$\$\$
 z\$\$b. ^c     3\$\$\$F "\$\$\$\$b   \$"\$\$\$\$\$\$\$  \$\$\$\$*"      .=""\$c
4\$\$\$\$L   \     \$\$P"  "\$\$b   .\$ \$\$\$\$\$...e\$\$        .=  e\$\$\$.
^*\$\$\$\$\$c  %..   *c    ..    \$\$ 3\$\$\$\$\$\$\$\$\$\$eF     zP  d\$\$\$\$\$
  "**\$\$\$ec   "\   %ce""    \$\$\$  \$\$\$\$\$\$\$\$\$\$*    .r" =\$\$\$\$P""
        "*\$b.  "c  *\$e.    *** d\$\$\$\$\$"L\$\$    .d"  e\$\$***"
          ^*\$\$c ^\$c \$\$\$      4J\$\$\$\$\$% \$\$\$ .e*".eeP"
             "\$\$\$\$\$\$"'\$=e....\$*\$\$**\$cz\$\$" "..d\$*"
               "*\$\$\$  *=%4.\$ L L\$ P3\$\$\$F \$\$\$P"
                  "\$   "%*ebJLzb\$e\$\$\$\$\$b \$P"
                    %..      4\$\$\$\$\$\$\$\$\$\$ "
                     \$\$\$e   z\$\$\$\$\$\$\$\$\$\$%
                      "*\$c  "\$\$\$\$\$\$\$P"
                       ."""*\$\$\$\$\$\$\$\$bc
                    .-"    .\$***\$\$\$"""*e.
                 .-"    .e\$"     "*\$c  ^*b.
          .=*""""    .e\$*"          "*bc  "*\$e..
        .\$"        .z*"               ^*\$e.   "*****e.
        \$\$ee\$c   .d"                     "*\$.        3.
        ^*\$E")\$..\$"                         *   .ee==d%
           \$.d\$\$\$*                           *  J\$\$\$e*
            """""                             "\$\$\$"

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

chown root:root /etc/issue.net
chmod 644 /etc/issue.net

# Validate sshd configuration before the firewall or the daemon is touched
echo -e "${BBlue}Validating sshd configuration...${NC}"
if ! sshd -t; then
    echo -e "${BRed}ERROR: sshd_config validation failed! NOT restarting.${NC}" >&2
    rollback_ssh_changes
    echo "Review the generated settings and fix errors before re-running." >&2
    exit 1
fi
echo -e "${BGreen}Configuration valid.${NC}"

# =============================================================================
# Firewall and daemon, in an order that cannot lock out the running session:
#   1. open the new port (persisted ruleset first, then the live one),
#   2. reload sshd and wait until it listens on the new port,
#   3. only then close the ports sshd no longer uses.
# A failure in step 1 or 2 restores the previous sshd configuration.
# =============================================================================
echo -e "${BBlue}Rate Limiting to avoid brute-forcing...${NC}"
IPT_SCRIPT=/usr/local/lib/awesomearchlinux/ssh-rate-limit.sh

# Per-source limit: every address may open 4 new connections per minute
# (burst 4). One bucket shared by all sources would let anybody who sends a
# few SYNs per minute keep every other client, the administrator included,
# out. Scoping the rules to iifname != "lo" keeps loopback SSH unlimited.
# "insert" prepends, so the statements are listed bottom-up: the two drop
# rules end up above the accept.
SSH_NFT_BLOCK=$(cat <<EOF
add set inet filter awesome_ssh_ratelimit4 { type ipv4_addr; flags dynamic; timeout 2m; size 65535; }
add set inet filter awesome_ssh_ratelimit6 { type ipv6_addr; flags dynamic; timeout 2m; size 65535; }
insert rule inet filter input iifname != "lo" tcp dport $SSH_PORT ct state new accept comment "awesome-ssh-rate-accept"
insert rule inet filter input iifname != "lo" tcp dport $SSH_PORT ct state new add @awesome_ssh_ratelimit6 { ip6 saddr limit rate over 4/minute burst 4 packets } drop comment "awesome-ssh-rate-drop6"
insert rule inet filter input iifname != "lo" tcp dport $SSH_PORT ct state new add @awesome_ssh_ratelimit4 { ip saddr limit rate over 4/minute burst 4 packets } drop comment "awesome-ssh-rate-drop"
EOF
)

# Handles of the live rules this script owns.
ssh_live_rule_handles() {
    nft -a list chain inet filter input 2>/dev/null | awk '
        /comment "awesome-ssh-rate-(accept|drop|drop6)"/ {
            for (i = 1; i <= NF; i++) if ($i == "handle") print $(i + 1)
        }
    ' || true
}

# 0 = sshd listens on the port, 1 = it does not, 2 = cannot tell.
ssh_port_listening() {
    local port="$1" listeners
    command -v ss &>/dev/null || return 2
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        listeners=$(ss -H -ltnp "sport = :${port}" 2>/dev/null || true)
        # Without process information any listener on the port has to do.
        if [[ "$listeners" == *'"sshd"'* ]] || [[ -n "$listeners" && "$listeners" != *'users:('* ]]; then
            return 0
        fi
        sleep 0.5
    done
    return 1
}

NFT_CONF_SNAPSHOT=""
OLD_LIVE_HANDLES=()
NFT_LIVE_APPLIED=0
IPT_SCRIPT_PREV=""
IPT_SCRIPT_WRITTEN=0

# Put the firewall back the way it was before step 1. Only what step 1 has
# actually done is undone: rules of an earlier run are never removed here.
undo_firewall_changes() {
    local handle old_handle keep_rule
    if [[ -n "$NFT_CONF_SNAPSHOT" && -f "$NFT_CONF_SNAPSHOT" ]]; then
        cat -- "$NFT_CONF_SNAPSHOT" > "$NFT_CONF_PATH"
        rm -f -- "$NFT_CONF_SNAPSHOT"
    fi
    NFT_CONF_SNAPSHOT=""
    if (( NFT_LIVE_APPLIED )); then
        while IFS= read -r handle; do
            [[ "$handle" =~ ^[0-9]+$ ]] || continue
            keep_rule=0
            for old_handle in "${OLD_LIVE_HANDLES[@]}"; do
                if [[ "$old_handle" == "$handle" ]]; then
                    keep_rule=1
                fi
            done
            if (( ! keep_rule )); then
                nft delete rule inet filter input handle "$handle" 2>/dev/null || true
            fi
        done < <(ssh_live_rule_handles)
        NFT_LIVE_APPLIED=0
    fi
    if (( IPT_SCRIPT_WRITTEN )); then
        if [[ -n "$IPT_SCRIPT_PREV" && -f "$IPT_SCRIPT_PREV" ]]; then
            cat -- "$IPT_SCRIPT_PREV" > "$IPT_SCRIPT"
            "$IPT_SCRIPT" || true
        else
            "$IPT_SCRIPT" remove || true
            rm -f -- "$IPT_SCRIPT"
        fi
        IPT_SCRIPT_WRITTEN=0
    fi
    if [[ -n "$IPT_SCRIPT_PREV" ]]; then
        rm -f -- "$IPT_SCRIPT_PREV"
        IPT_SCRIPT_PREV=""
    fi
}

# Writes the idempotent iptables helper that the systemd unit below runs.
write_iptables_rate_limit_script() {
    # Persist only the owned rules through an idempotent oneshot unit. Saving
    # the whole live table here would also capture transient Docker rules.
    rm -f /usr/local/libexec/awesome-ssh-rate-limit
    install -d -o root -g root -m 0755 /usr/local/lib/awesomearchlinux /etc/systemd/system || return 1
    if [[ -f "$IPT_SCRIPT" ]]; then
        IPT_SCRIPT_PREV=$(umask 077; mktemp "${IPT_SCRIPT}.prev.XXXXXX") || return 1
        cat -- "$IPT_SCRIPT" > "$IPT_SCRIPT_PREV" || return 1
    fi
    IPT_SCRIPT_WRITTEN=1
    cat > "$IPT_SCRIPT" <<EOF || return 1
#!/usr/bin/env bash
set -euo pipefail
SSH_PORT=$SSH_PORT
# Without an argument every rule this unit owns is replaced. "open" only adds
# the rules for SSH_PORT (used while sshd is being moved to another port);
# "remove" only deletes the owned rules.
MODE="\${1:-replace}"
delete_rules_by_comment() {
    local marker="\$1" rule_number
    while rule_number=\$(iptables -L INPUT --line-numbers -n | awk -v marker="\$marker" '
        index(\$0, "/* " marker " */") { print \$1; exit }
    '); [[ -n "\$rule_number" ]]; do
        iptables -D INPUT "\$rule_number"
    done
}
if [[ "\$MODE" != open ]]; then
    delete_rules_by_comment awesome-ssh-rate-accept
    delete_rules_by_comment awesome-ssh-rate-drop
fi
if [[ "\$MODE" == remove ]]; then
    exit 0
fi
iptables -I INPUT 1 ! -i lo -p tcp --dport "\$SSH_PORT" -m conntrack --ctstate NEW \\
    -m comment --comment awesome-ssh-rate-accept -j ACCEPT
# Per-source limit: more than 4 new connections per minute from one address
# are dropped. Without xt_hashlimit the port stays open without a limit; one
# bucket shared by all sources would let any sender lock everybody else out.
if ! iptables -I INPUT 1 ! -i lo -p tcp --dport "\$SSH_PORT" -m conntrack --ctstate NEW \\
    -m hashlimit --hashlimit-name awesome-ssh --hashlimit-mode srcip \\
    --hashlimit-above 4/minute --hashlimit-burst 4 --hashlimit-htable-expire 120000 \\
    -m comment --comment awesome-ssh-rate-drop -j DROP; then
    echo "xt_hashlimit is unavailable: SSH port \$SSH_PORT is open without a rate limit." >&2
fi
EOF
    chmod 0755 "$IPT_SCRIPT"
}

# --- Step 1: open the new port ------------------------------------------------
case "$FIREWALL_MODE" in
    nft)
        if (( NFT_PERSIST )); then
            NFT_CONF_SNAPSHOT=$(umask 077; mktemp "$(dirname "$NFT_CONF_PATH")/.nftables.ssh-rollback.XXXXXX")
            cat -- "$NFT_CONF_PATH" > "$NFT_CONF_SNAPSHOT"
            # Run as a plain command: inside "if" the helper's own "set -e"
            # would be ignored and a failed write could go unnoticed.
            set +e
            aal_nft_persist_block ssh-rate-limit <<< "$SSH_NFT_BLOCK"
            persist_status=$?
            set -e
            if (( persist_status != 0 )); then
                echo -e "${BRed}ERROR: Could not persist the firewall rules for SSH port ${SSH_PORT}; sshd was not touched.${NC}" >&2
                undo_firewall_changes
                rollback_ssh_changes
                exit 1
            fi
        fi
        if (( NFT_LIVE )); then
            while IFS= read -r live_handle; do
                if [[ "$live_handle" =~ ^[0-9]+$ ]]; then
                    OLD_LIVE_HANDLES+=("$live_handle")
                fi
            done < <(ssh_live_rule_handles)
            # One transaction: the new rules are inserted above the old ones,
            # which stay in place until sshd answers on the new port.
            if ! nft -f - <<< "$SSH_NFT_BLOCK"; then
                echo -e "${BRed}ERROR: Could not open SSH port ${SSH_PORT} in the live ruleset; sshd was not touched.${NC}" >&2
                undo_firewall_changes
                rollback_ssh_changes
                exit 1
            fi
            NFT_LIVE_APPLIED=1
            if (( ! NFT_PERSIST )); then
                echo -e "${BYellow}WARNING: ${NFT_CONF_PATH} is not an installer-owned ruleset. The SSH rules were added${NC}" >&2
                echo -e "${BYellow}to the live ruleset only and will not survive a reboot.${NC}" >&2
            fi
        fi
        ;;
    iptables)
        if ! write_iptables_rate_limit_script || ! "$IPT_SCRIPT" open; then
            echo -e "${BRed}ERROR: Could not open SSH port ${SSH_PORT} with iptables; sshd was not touched.${NC}" >&2
            undo_firewall_changes
            rollback_ssh_changes
            exit 1
        fi
        ;;
esac

# --- Step 2: reload sshd and confirm the listener -----------------------------
echo -e "${BBlue}Enabling and reloading SSHD...${NC}"
systemctl enable sshd.service
LISTENER_STATE=chroot
if in_chroot; then
    echo -e "${BBlue}Chroot environment detected — sshd.service enabled for first boot.${NC}"
else
    sshd_reloaded=1
    SSHD_RELOAD_ISSUED=1
    if systemctl is-active --quiet sshd.service; then
        # Reload preserves existing sessions; restart kills them via cgroup teardown
        systemctl reload sshd.service || systemctl reload-or-restart sshd.service || sshd_reloaded=0
    else
        systemctl start sshd.service || sshd_reloaded=0
    fi
    LISTENER_STATE=missing
    if (( sshd_reloaded )); then
        listener_status=0
        ssh_port_listening "$SSH_PORT" || listener_status=$?
        case "$listener_status" in
            0) LISTENER_STATE=confirmed ;;
            2) LISTENER_STATE=unknown ;;
        esac
    fi
    if [[ "$LISTENER_STATE" == missing ]]; then
        if (( sshd_reloaded )); then
            echo -e "${BRed}ERROR: sshd is not listening on port ${SSH_PORT} after the reload.${NC}" >&2
        else
            echo -e "${BRed}ERROR: sshd.service could not be reloaded or started with the new configuration.${NC}" >&2
        fi
        undo_firewall_changes
        rollback_ssh_changes
        systemctl reload-or-restart sshd.service || true
        echo -e "${BYellow}The previous sshd configuration and firewall rules were restored.${NC}" >&2
        exit 1
    fi
    systemctl status sshd.service --no-pager || true
fi
# sshd runs (or will boot) with the new configuration: from here on a failure
# must not restore the old files underneath it.
SSH_ROLLBACK_ARMED=0

# The new configuration is live (or staged for first boot), so the previous
# host keys kept for a rollback can go.
if [[ -n "$HOSTKEY_OLD_DIR" && -d "$HOSTKEY_OLD_DIR" ]]; then
    shred -u "$HOSTKEY_OLD_DIR"/ssh_host_* 2>/dev/null || true
    rm -rf -- "$HOSTKEY_OLD_DIR"
    HOSTKEY_OLD_DIR=""
fi

# --- Step 3: close the ports sshd no longer uses ------------------------------
# Port 22 and the ports of the previous configuration, unless still in use.
PORTS_TO_CLOSE=()
for candidate_port in 22 "${OLD_SSH_PORTS[@]}"; do
    if [[ "$candidate_port" == "$SSH_PORT" ]]; then
        continue
    fi
    already_listed=0
    for listed_port in "${PORTS_TO_CLOSE[@]}"; do
        if [[ "$listed_port" == "$candidate_port" ]]; then
            already_listed=1
        fi
    done
    if (( ! already_listed )); then
        PORTS_TO_CLOSE+=("$candidate_port")
    fi
done

# The installer's base ruleset carries its own SSH rule, in one of two forms:
#   tcp dport P ct state new limit rate 4/minute burst 8 packets accept
# or, with per-source limiting,
#   tcp dport P ct state new add @ssh_ratelimit4 { ip saddr limit rate over ... } drop
#   tcp dport P ct state new add @ssh_ratelimit6 { ip6 saddr limit rate over ... } drop
#   tcp dport P ct state new accept
# Both are removed for a port sshd has left, together with the comment line
# above them. The set definitions and all managed blocks are kept.
strip_base_ssh_rules_from_file() {
    local strip_current strip_next port
    strip_current=$(umask 077; mktemp "$(dirname "$NFT_CONF_PATH")/.nftables.sshstrip.XXXXXX")
    strip_next=$(umask 077; mktemp "$(dirname "$NFT_CONF_PATH")/.nftables.sshstrip.XXXXXX")
    cat -- "$NFT_CONF_PATH" > "$strip_current"
    for port in "$@"; do
        awk -v port="$port" '
            BEGIN {
                sp = "[[:space:]]+"
                head = "^[[:space:]]*tcp" sp "dport" sp port sp "ct" sp "state" sp "new" sp
                global_rule = head "limit" sp "rate[[:space:]].*accept([[:space:]]|$)"
                source_drop = head "add" sp "@ssh_ratelimit[46][[:space:]].*drop([[:space:]]|$)"
                plain_accept = head "accept([[:space:]]|$)"
            }
            /^# BEGIN AwesomeArchLinux: / { managed = 1 }
            /^# END AwesomeArchLinux: /   { managed = 0 }
            !managed && /^[[:space:]]*#[[:space:]]*Allow SSH with (per-source )?rate limiting/ {
                if (has_comment) print pending_comment
                pending_comment = $0
                has_comment = 1
                next
            }
            !managed && ($0 ~ global_rule || $0 ~ source_drop || $0 ~ plain_accept) && $0 !~ /comment "awesome-/ {
                has_comment = 0
                next
            }
            {
                if (has_comment) {
                    print pending_comment
                    has_comment = 0
                }
                print
            }
            END {
                if (has_comment) print pending_comment
            }
        ' "$strip_current" > "$strip_next"
        cat -- "$strip_next" > "$strip_current"
    done
    if ! cmp -s -- "$strip_current" "$NFT_CONF_PATH"; then
        if nft -c -f "$strip_current" 2>/dev/null; then
            install -o root -g root -m 0644 "$strip_current" "$NFT_CONF_PATH"
            echo -e "${BBlue}Removed the base SSH rule for port(s) $* from ${NFT_CONF_PATH}.${NC}"
        else
            echo -e "${BYellow}WARNING: ${NFT_CONF_PATH} did not validate without the base SSH rule for port(s) $*;${NC}" >&2
            echo -e "${BYellow}the rule was left in place. Remove it manually to close the port.${NC}" >&2
        fi
    fi
    rm -f -- "$strip_current" "$strip_next"
}

strip_base_ssh_rules_from_live() {
    local port handle
    for port in "$@"; do
        while IFS= read -r handle; do
            [[ "$handle" =~ ^[0-9]+$ ]] || continue
            nft delete rule inet filter input handle "$handle" 2>/dev/null || true
        done < <(
            nft -a list chain inet filter input 2>/dev/null | awk -v port="$port" '
                BEGIN { head = "^[[:space:]]*tcp dport " port " ct state new " }
                /comment "awesome-/ { next }
                $0 ~ (head "limit rate ") || $0 ~ (head "(add|update) @ssh_ratelimit[46] ") || $0 ~ (head "accept( |$)") {
                    for (i = 1; i <= NF; i++) if ($i == "handle") print $(i + 1)
                }
            ' || true
        )
    done
}

# Closing a port is only safe once sshd is known to answer on the new one.
CLOSE_OLD_PORTS=0
if [[ "$LISTENER_STATE" == confirmed || "$LISTENER_STATE" == chroot ]]; then
    CLOSE_OLD_PORTS=1
elif (( SSH_PORT_MOVES )); then
    echo -e "${BYellow}WARNING: Could not confirm that sshd listens on port ${SSH_PORT} (ss is unavailable).${NC}" >&2
    echo -e "${BYellow}The previous SSH port stays open in the firewall; re-run this script once the new port works.${NC}" >&2
fi

case "$FIREWALL_MODE" in
    nft)
        if (( CLOSE_OLD_PORTS && ${#PORTS_TO_CLOSE[@]} > 0 )); then
            if (( NFT_PERSIST )); then
                strip_base_ssh_rules_from_file "${PORTS_TO_CLOSE[@]}"
            fi
            if (( NFT_LIVE )); then
                strip_base_ssh_rules_from_live "${PORTS_TO_CLOSE[@]}"
            fi
        fi
        # Retire the rules a previous run installed. They sit below the new
        # ones, so they are redundant when the port did not change.
        if (( NFT_LIVE )) && (( CLOSE_OLD_PORTS || ! SSH_PORT_MOVES )); then
            for live_handle in "${OLD_LIVE_HANDLES[@]}"; do
                nft delete rule inet filter input handle "$live_handle" 2>/dev/null || true
            done
        fi
        # Keep drop-only blocks of other scripts (container isolation) above
        # the accept that was just inserted.
        if (( NFT_LIVE )) && declare -F aal_nft_raise_guard_rules >/dev/null; then
            aal_nft_raise_guard_rules || true
        fi
        if [[ -n "$NFT_CONF_SNAPSHOT" ]]; then
            rm -f -- "$NFT_CONF_SNAPSHOT"
        fi
        echo -e "${BGreen}nftables per-source SSH rate limit configured without replacing unrelated rules.${NC}"
        ;;
    iptables)
        cat > /etc/systemd/system/awesome-ssh-rate-limit.service <<'EOF'
[Unit]
Description=Install AwesomeArchLinux SSH rate-limit rules
After=iptables.service
Before=sshd.service

[Service]
Type=oneshot
ExecStart=/usr/local/lib/awesomearchlinux/ssh-rate-limit.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
        chmod 0644 /etc/systemd/system/awesome-ssh-rate-limit.service
        systemctl daemon-reload
        systemctl enable awesome-ssh-rate-limit.service
        if (( CLOSE_OLD_PORTS || ! SSH_PORT_MOVES )); then
            # Replaces every owned rule, which also retires those of the old port.
            systemctl restart awesome-ssh-rate-limit.service
        fi
        if [[ -n "$IPT_SCRIPT_PREV" ]]; then
            rm -f -- "$IPT_SCRIPT_PREV"
        fi
        echo -e "${BGreen}iptables per-source SSH rate limit applied and persisted by an idempotent systemd unit.${NC}"
        ;;
    unmanaged)
        ;;
    *)
        echo -e "${BYellow}Neither nftables nor iptables is functional — skipping rate limiting.${NC}"
        echo -e "${BYellow}Rate limiting is already configured if you ran the base installation.${NC}"
        ;;
esac

echo -e "${BBlue}Host key fingerprints (compare them on the first connection):${NC}"
for host_key_pub in /etc/ssh/ssh_host_ed25519_key.pub /etc/ssh/ssh_host_rsa_key.pub; do
    ssh-keygen -lf "$host_key_pub" || true
done
if (( HOST_KEYS_REGENERATED )); then
    echo -e "${BYellow}WARNING: The host keys were regenerated. Clients that connected before will report${NC}"
    echo -e "${BYellow}\"REMOTE HOST IDENTIFICATION HAS CHANGED\": verify the fingerprints above, then run${NC}"
    echo -e "${BYellow}ssh-keygen -R <this host> on each client. Later runs keep these keys unless -r is passed.${NC}"
fi

for totp_notice_line in "${TOTP_NOTICE[@]}"; do
    echo -e "${BYellow}${totp_notice_line}${NC}" >&2
done

echo -e "${BGreen}SSH hardening complete. Running on port ${SSH_PORT}.${NC}"
echo -e "${BBlue}Allowed user: ${ALLOWED_USERS}${NC}"
echo -e "${BYellow}IMPORTANT: Ensure ${ALLOWED_USERS} has an SSH key in ~/.ssh/authorized_keys${NC}"
echo -e "${BYellow}before disconnecting, as password authentication is now disabled.${NC}"
