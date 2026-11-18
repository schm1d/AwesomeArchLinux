#!/usr/bin/env bash

# =============================================================================
# Script:      ssh.sh
# Description: Hardens OpenSSH server and client configuration on Arch Linux.
#              Regenerates host keys (Ed25519 + RSA 4096), enforces modern
#              cryptographic algorithms, restricts access, and applies
#              CIS Benchmark recommendations for SSH.
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
#
# Usage:       sudo ./ssh.sh [-u ALLOWED_USER] [-p PORT] [-h]
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
    echo "Usage: sudo $0 [-u ALLOWED_USER] [-p PORT] [-k] [-h]"
    echo "  -u USER   User to allow SSH access (required, must not be root)"
    echo "  -p PORT   SSH listening port (default: 22)"
    echo "  -k        Skip the authorized_keys lockout check. Use ONLY on bare-metal"
    echo "            installs where console access is guaranteed. Never use on VPS."
    echo "  -h        Show this help"
    exit 0
}

ALLOWED_USERS=""
SKIP_KEY_CHECK=0
while getopts ":u:p:kh" opt; do
    case "$opt" in
        u) ALLOWED_USERS="$OPTARG" ;;
        p) SSH_PORT="$OPTARG" ;;
        k) SKIP_KEY_CHECK=1 ;;
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

if [[ ! -s "${ALLOWED_HOME}/.ssh/authorized_keys" ]]; then
    if [[ "$SKIP_KEY_CHECK" -eq 1 ]]; then
        echo -e "${BYellow}WARNING: ${ALLOWED_HOME}/.ssh/authorized_keys is missing or empty.${NC}" >&2
        echo -e "${BYellow}Proceeding anyway because -k was passed. Password auth will be disabled.${NC}" >&2
        echo -e "${BYellow}You MUST add a key via console login before remote SSH will work.${NC}" >&2
        install -d -m 700 -o "$ALLOWED_USERS" -g "$ALLOWED_GROUP" "${ALLOWED_HOME}/.ssh"
        install -m 600 -o "$ALLOWED_USERS" -g "$ALLOWED_GROUP" /dev/null "${ALLOWED_HOME}/.ssh/authorized_keys"
    else
        echo -e "${BRed}ERROR: ${ALLOWED_HOME}/.ssh/authorized_keys is missing or empty.${NC}" >&2
        echo -e "${BYellow}Refusing to apply PasswordAuthentication=no / AllowUsers / restart sshd (lockout prevention).${NC}" >&2
        echo -e "${BYellow}On a bare-metal install with console access, re-run with -k to bypass.${NC}" >&2
        exit 1
    fi
fi

echo -e "${BBlue}Cleaning old keys...${NC}"
if [ ! -d /etc/ssh ]; then
    echo -e "${BRed}ERROR: /etc/ssh does not exist. Is openssh installed?${NC}" >&2
    exit 1
fi
shred -u /etc/ssh/ssh_host_*key* 2>/dev/null || true

echo -e "${BBlue}Creating ed25519 and RSA keys...${NC}"
ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N "" < /dev/null
ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N "" < /dev/null

# Set correct permissions on host keys
chmod 600 /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_rsa_key
chmod 644 /etc/ssh/ssh_host_ed25519_key.pub /etc/ssh/ssh_host_rsa_key.pub
chown root:root /etc/ssh/ssh_host_*

echo -e "${BBlue}Hardening \"/etc/ssh/sshd_config\"...${NC}"

# Back up original config
BACKUP_SUFFIX="bak.$(date +%Y%m%d%H%M%S)"
cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.${BACKUP_SUFFIX}"
chmod 0600 "/etc/ssh/sshd_config.${BACKUP_SUFFIX}"

touch "$REVOKED_KEYS_FILE"

# Write a complete hardened sshd_config (truncate, not append — avoids first-match-wins issues)
cat > /etc/ssh/sshd_config << SSHD_EOF
# =============================================================================
# Hardened sshd_config — generated by ssh.sh
# Original backed up to: /etc/ssh/sshd_config.${BACKUP_SUFFIX}
# =============================================================================

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
    ControlMaster auto
    ControlPersist 10m
    ControlPath ~/.ssh/sockets/%r@%h:%p
SSH_CLIENT_EOF

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

# Validate sshd configuration before restarting
echo -e "${BBlue}Validating sshd configuration...${NC}"
if sshd -t; then
    echo -e "${BGreen}Configuration valid.${NC}"
    echo -e "${BBlue}Enabling and reloading SSHD...${NC}"
    systemctl enable sshd.service
    if in_chroot; then
        echo -e "${BBlue}Chroot environment detected — sshd.service enabled for first boot.${NC}"
    else
        if systemctl is-active --quiet sshd.service; then
            # Reload preserves existing sessions; restart kills them via cgroup teardown
            systemctl reload sshd.service || systemctl reload-or-restart sshd.service
        else
            systemctl start sshd.service
        fi
        systemctl status sshd.service --no-pager
    fi
else
    echo -e "${BRed}ERROR: sshd_config validation failed! NOT restarting.${NC}" >&2
    echo -e "${BYellow}Rolling back to previous configuration...${NC}"
    cp "/etc/ssh/sshd_config.${BACKUP_SUFFIX}" /etc/ssh/sshd_config
    chmod 0600 /etc/ssh/sshd_config
    echo "Review /etc/ssh/sshd_config and fix errors before restarting manually." >&2
    exit 1
fi

# Rate limiting — prefer the installer-owned nftables ruleset
echo -e "${BBlue}Rate Limiting to avoid brute-forcing...${NC}"
NFT_CONF_PATH="${AAL_NFT_CONFIG:-/etc/nftables.conf}"
if command -v nft &>/dev/null && { [[ -f "$NFT_CONF_PATH" ]] || { ! in_chroot && nft list chain inet filter input &>/dev/null; }; }; then
    # If SSH moved off port 22, strip any hardcoded port-22 baseline accept rule
    # from /etc/nftables.conf so port 22 does not remain exposed alongside $SSH_PORT.
    if (( 10#$SSH_PORT != 22 )) && [[ -f "$NFT_CONF_PATH" ]]; then
        if grep -Eq '^[[:space:]]*tcp[[:space:]]+dport[[:space:]]+22[[:space:]]+ct[[:space:]]+state[[:space:]]+new[[:space:]]+limit[[:space:]]+rate[[:space:]].*accept' "$NFT_CONF_PATH"; then
            nft_strip_tmp=$(umask 077; mktemp "$(dirname "$NFT_CONF_PATH")/.nftables.ssh22.XXXXXX")
            awk '
                /^[[:space:]]*#[[:space:]]*Allow SSH with rate limiting/ {
                    pending_comment = $0
                    has_comment = 1
                    next
                }
                /^[[:space:]]*tcp[[:space:]]+dport[[:space:]]+22[[:space:]]+ct[[:space:]]+state[[:space:]]+new[[:space:]]+limit[[:space:]]+rate[[:space:]].*accept([[:space:]]|$)/ && $0 !~ /comment "awesome-ssh-/ {
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
            ' "$NFT_CONF_PATH" > "$nft_strip_tmp"
            if nft -c -f "$nft_strip_tmp" 2>/dev/null; then
                install -o root -g root -m 0644 "$nft_strip_tmp" "$NFT_CONF_PATH"
            fi
            rm -f -- "$nft_strip_tmp"
        fi
    fi

    # Persist the managed block when /etc/nftables.conf exists. Scoping rules to
    # iifname != "lo" guarantees loopback SSH is never rate-limited.
    if [[ -f "$NFT_CONF_PATH" ]]; then
        aal_nft_persist_block ssh-rate-limit <<EOF
insert rule inet filter input iifname != "lo" tcp dport $SSH_PORT ct state new drop comment "awesome-ssh-rate-drop"
insert rule inet filter input iifname != "lo" tcp dport $SSH_PORT ct state new limit rate 4/minute burst 4 packets accept comment "awesome-ssh-rate-accept"
EOF
    fi

    if ! in_chroot && nft list chain inet filter input &>/dev/null; then
        aal_nft_remove_live_rules inet filter input awesome-ssh-rate-accept 2>/dev/null || true
        aal_nft_remove_live_rules inet filter input awesome-ssh-rate-drop 2>/dev/null || true

        if (( 10#$SSH_PORT != 22 )); then
            while IFS= read -r ssh22_handle; do
                [[ "$ssh22_handle" =~ ^[0-9]+$ ]] || continue
                nft delete rule inet filter input handle "$ssh22_handle" 2>/dev/null || true
            done < <(
                nft -a list chain inet filter input 2>/dev/null | awk '
                    /tcp dport 22 ct state new limit rate/ && $0 !~ /comment "awesome-ssh-/ {
                        for (i = 1; i <= NF; i++) if ($i == "handle") print $(i + 1)
                    }
                '
            )
        fi

        lo_handle=$(nft -a list chain inet filter input 2>/dev/null | awk '
            /iif(name)? "?(lo)"? accept/ {
                for (i = 1; i <= NF; i++) if ($i == "handle") { print $(i + 1); exit }
            }
        ')
        if [[ -n "$lo_handle" ]]; then
            # add ... position <lo_handle> places rules immediately AFTER iif lo accept
            nft add rule inet filter input position "$lo_handle" iifname != "lo" tcp dport "$SSH_PORT" ct state new drop comment "awesome-ssh-rate-drop" 2>/dev/null || true
            nft add rule inet filter input position "$lo_handle" iifname != "lo" tcp dport "$SSH_PORT" ct state new \
                limit rate 4/minute burst 4 packets accept comment "awesome-ssh-rate-accept" 2>/dev/null || true
        else
            nft insert rule inet filter input iifname != "lo" tcp dport "$SSH_PORT" ct state new drop comment "awesome-ssh-rate-drop" 2>/dev/null || true
            nft insert rule inet filter input iifname != "lo" tcp dport "$SSH_PORT" ct state new \
                limit rate 4/minute burst 4 packets accept comment "awesome-ssh-rate-accept" 2>/dev/null || true
        fi
    fi
    echo -e "${BGreen}nftables SSH rate limit configured without replacing unrelated rules.${NC}"
elif ! in_chroot && command -v iptables &>/dev/null && iptables -L -n &>/dev/null; then
    # Persist only the owned rules through an idempotent oneshot unit. Saving
    # the whole live table here would also capture transient Docker rules.
    rm -f /usr/local/libexec/awesome-ssh-rate-limit
    install -d -o root -g root -m 0755 /usr/local/lib/awesomearchlinux /etc/systemd/system
    cat > /usr/local/lib/awesomearchlinux/ssh-rate-limit.sh <<EOF
#!/usr/bin/env bash
set -euo pipefail
SSH_PORT=$SSH_PORT
delete_rules_by_comment() {
    local marker="\$1" rule_number
    while rule_number=\$(iptables -L INPUT --line-numbers -n | awk -v marker="\$marker" '
        index(\$0, "/* " marker " */") { print \$1; exit }
    '); [[ -n "\$rule_number" ]]; do
        iptables -D INPUT "\$rule_number"
    done
}
delete_rules_by_comment awesome-ssh-rate-accept
delete_rules_by_comment awesome-ssh-rate-drop
iptables -I INPUT 1 ! -i lo -p tcp --dport "\$SSH_PORT" -m conntrack --ctstate NEW \
    -m comment --comment awesome-ssh-rate-drop -j DROP
iptables -I INPUT 1 ! -i lo -p tcp --dport "\$SSH_PORT" -m conntrack --ctstate NEW \
    -m limit --limit 4/min --limit-burst 4 \
    -m comment --comment awesome-ssh-rate-accept -j ACCEPT
EOF
    chmod 0755 /usr/local/lib/awesomearchlinux/ssh-rate-limit.sh
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
    systemctl restart awesome-ssh-rate-limit.service
    echo -e "${BGreen}iptables SSH rate limit applied and persisted by an idempotent systemd unit.${NC}"
else
    echo -e "${BYellow}Neither nftables nor iptables is functional — skipping rate limiting.${NC}"
    echo -e "${BYellow}Rate limiting is already configured if you ran the base installation.${NC}"
fi

echo -e "${BGreen}SSH hardening complete. Running on port ${SSH_PORT}.${NC}"
echo -e "${BBlue}Allowed user: ${ALLOWED_USERS}${NC}"
echo -e "${BYellow}IMPORTANT: Ensure ${ALLOWED_USERS} has an SSH key in ~/.ssh/authorized_keys${NC}"
echo -e "${BYellow}before disconnecting, as password authentication is now disabled.${NC}"
