#!/usr/bin/env bash

# =============================================================================
# Script:      u2f.sh
# Description: Enrolls FIDO2/U2F hardware keys (YubiKey and peers) and wires
#              pam_u2f for local login. SSH hardware-key auth is handled with
#              OpenSSH native sk- keys rather than stacking pam_u2f on top of
#              the existing publickey + TOTP path.
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
#
# Usage:       sudo ./u2f.sh [-u USERNAME] [--enroll] [--sudo] [--login]
#                            [--allow-missing] [--status] [-h]
# =============================================================================

set -euo pipefail

readonly C_BLUE='\033[1;34m'
readonly C_RED='\033[1;31m'
readonly C_GREEN='\033[1;32m'
readonly C_YELLOW='\033[1;33m'
readonly C_NC='\033[0m'

msg()  { printf "%b[+]%b %s\n" "$C_GREEN" "$C_NC" "$1"; }
info() { printf "%b[*]%b %s\n" "$C_BLUE"  "$C_NC" "$1"; }
warn() { printf "%b[!]%b %s\n" "$C_YELLOW" "$C_NC" "$1"; }
err()  { printf "%b[!]%b %s\n" "$C_RED"   "$C_NC" "$1" >&2; exit 1; }

USERNAME=""
DO_ENROLL=false
DO_SUDO=false
DO_LOGIN=true
DO_STATUS=false
ALLOW_MISSING=false
AUTHFILE="/etc/u2f_mappings"
ORIGIN=""

usage() {
    cat <<EOF
Usage: sudo $0 [options]

Options:
  -u USERNAME     Target user (default: \$SUDO_USER)
  --enroll        Interactively enroll a hardware key for the target user
  --login         Wire pam_u2f into local login stacks (default)
  --no-login      Skip local login PAM changes
  --sudo          Also require the key for sudo (keep a session open)
  --allow-missing Permit users with no mapping to fall through (nouserok)
  --status        Report enrollment and PAM state, then exit
  -h              Show this help

Gotchas this script refuses to automate:
  - pam_u2f is NOT stacked onto sshd when TOTP is already configured.
    Use OpenSSH resident FIDO2 keys instead (see the README).
  - --sudo without a second enrolled key is a lockout risk.
  - A single key is not a backup. Enroll at least two authenticators.
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -u)               USERNAME="${2:-}"; [[ -n "$USERNAME" ]] || err "-u requires a username"; shift 2 ;;
        --enroll)         DO_ENROLL=true; shift ;;
        --login)          DO_LOGIN=true; shift ;;
        --no-login)       DO_LOGIN=false; shift ;;
        --sudo)           DO_SUDO=true; shift ;;
        --allow-missing)  ALLOW_MISSING=true; shift ;;
        --status)         DO_STATUS=true; shift ;;
        -h|--help)        usage ;;
        *)                err "Unknown option: $1" ;;
    esac
done

[[ $(id -u) -eq 0 ]] || err "Must be run as root"

if [[ -z "$USERNAME" ]]; then
    if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
        USERNAME="$SUDO_USER"
    else
        USERNAME=$(awk -F: '$3 >= 1000 && $3 < 65534 && $7 !~ /(nologin|false)/ { print $1; exit }' /etc/passwd)
        [[ -n "$USERNAME" ]] || err "Could not determine target user. Specify with -u USERNAME"
    fi
fi

id "$USERNAME" &>/dev/null || err "User '$USERNAME' does not exist"
ORIGIN="pam://$(hostname -s)"

pam_options() {
    local extra="cue origin=${ORIGIN} appid=${ORIGIN} authfile=${AUTHFILE}"
    if [[ "$ALLOW_MISSING" == true ]]; then
        extra="${extra} nouserok"
    fi
    printf '%s' "$extra"
}

pam_line() {
    printf 'auth    required    pam_u2f.so %s\n' "$(pam_options)"
}

install_packages() {
    msg "Installing pam-u2f, libfido2, and pcsc-tools..."
    pacman -Syu --noconfirm --needed pam-u2f libfido2 pcsclite ccid
    systemctl enable --now pcscd.socket 2>/dev/null || systemctl enable --now pcscd.service 2>/dev/null || true
}

ensure_authfile() {
    if [[ ! -f "$AUTHFILE" ]]; then
        umask 077
        touch "$AUTHFILE"
        chmod 644 "$AUTHFILE"
        chown root:root "$AUTHFILE"
        info "Created $AUTHFILE"
    fi
}

user_enrolled() {
    grep -E "^${USERNAME}:" "$AUTHFILE" >/dev/null 2>&1
}

enroll_key() {
    command -v pamu2fcfg >/dev/null || err "pamu2fcfg not found after package install"
    ensure_authfile

    info "Touch the authenticator when it blinks."
    info "If the key has a FIDO2 PIN, you will be prompted for it."
    echo

    local tmp mapping
    tmp=$(mktemp)
    if ! su -s /bin/bash "$USERNAME" -c "pamu2fcfg -u '$USERNAME' -o '$ORIGIN' -i '$ORIGIN'" >"$tmp"; then
        rm -f "$tmp"
        err "Enrollment failed. Is the key plugged in? Try: fido2-token -L"
    fi
    mapping=$(tr -d '\n' <"$tmp")
    rm -f "$tmp"
    [[ -n "$mapping" ]] || err "pamu2fcfg produced an empty mapping"

    if user_enrolled; then
        local extra
        extra=$(printf '%s' "$mapping" | cut -d: -f2-)
        awk -v user="$USERNAME" -v extra="$extra" -F: '
            $1 == user { print $0 ":" extra; next }
            { print }
        ' "$AUTHFILE" >"${AUTHFILE}.new"
        mv "${AUTHFILE}.new" "$AUTHFILE"
        chmod 644 "$AUTHFILE"
        msg "Appended an additional key for $USERNAME"
    else
        printf '%s\n' "$mapping" >>"$AUTHFILE"
        msg "Enrolled first key for $USERNAME"
    fi

    local count
    count=$(awk -F: -v user="$USERNAME" '$1==user { print NF-1 }' "$AUTHFILE")
    if [[ "${count:-0}" -lt 2 ]]; then
        warn "Only $count key(s) enrolled for $USERNAME. Enroll a backup key before you rely on this."
        warn "Re-run: sudo $0 -u $USERNAME --enroll"
    fi
}

insert_pam_line() {
    local pam_file="$1"
    local line
    line=$(pam_line)

    [[ -f "$pam_file" ]] || { warn "Skipping missing PAM stack $pam_file"; return 0; }

    if grep -Eq '^[[:space:]]*auth[[:space:]]+.*pam_u2f\.so' "$pam_file"; then
        info "pam_u2f already present in $pam_file — refreshing options"
        local ts
        ts=$(date +%Y%m%d-%H%M%S)
        cp "$pam_file" "${pam_file}.bak.${ts}"
        sed -i -E 's|^[[:space:]]*auth[[:space:]]+.*pam_u2f\.so.*|'"$line"'|' "$pam_file"
        return 0
    fi

    local ts
    ts=$(date +%Y%m%d-%H%M%S)
    cp "$pam_file" "${pam_file}.bak.${ts}"

    awk -v line="$line" '
        BEGIN { done=0 }
        /^[[:space:]]*auth[[:space:]]/ && !done {
            print "# FIDO2/U2F (added by u2f.sh)"
            print line
            done=1
        }
        { print }
        END {
            if (!done) {
                print "# FIDO2/U2F (added by u2f.sh)"
                print line
            }
        }
    ' "$pam_file" >"${pam_file}.new"
    mv "${pam_file}.new" "$pam_file"
    msg "Wired pam_u2f into $pam_file"
}

configure_login() {
    msg "Configuring local login PAM stacks..."
    insert_pam_line /etc/pam.d/system-local-login
    insert_pam_line /etc/pam.d/gdm-password
    insert_pam_line /etc/pam.d/sddm
    insert_pam_line /etc/pam.d/lightdm
    insert_pam_line /etc/pam.d/login
}

configure_sudo() {
    msg "Configuring sudo PAM..."
    warn "Keep this root session open and test 'sudo -k && sudo true' in another terminal."
    insert_pam_line /etc/pam.d/sudo
}

print_ssh_guidance() {
    echo
    if grep -Eq 'pam_google_authenticator' /etc/pam.d/sshd 2>/dev/null; then
        warn "TOTP is already stacked on sshd. pam_u2f will NOT be added to SSH."
        info "Stacking publickey + TOTP + pam_u2f is a lockout factory."
    else
        info "pam_u2f was not added to sshd. Prefer OpenSSH native FIDO2 keys."
    fi
    cat <<EOF

OpenSSH FIDO2 (phishing-resistant, no PAM stack change):

  # As $USERNAME, with the key plugged in:
  ssh-keygen -t ed25519-sk -O resident -O verify-required -f ~/.ssh/id_ed25519_sk -C "${USERNAME}@$(hostname -s)"
  ssh-copy-id -i ~/.ssh/id_ed25519_sk.pub ${USERNAME}@<host>

Resident keys can be pulled onto a new machine with:
  ssh-keygen -K

EOF
}

show_status() {
    echo
    info "User:     $USERNAME"
    info "Origin:   $ORIGIN"
    info "Authfile: $AUTHFILE"
    if [[ -f "$AUTHFILE" ]] && user_enrolled; then
        local count
        count=$(awk -F: -v user="$USERNAME" '$1==user { print NF-1 }' "$AUTHFILE")
        msg "$USERNAME has $count enrolled key handle(s)"
    else
        warn "$USERNAME has no mapping in $AUTHFILE"
    fi
    echo
    info "PAM stacks mentioning pam_u2f:"
    grep -Rl 'pam_u2f' /etc/pam.d 2>/dev/null | sed 's/^/  /' || info "  (none)"
    echo
    if command -v fido2-token >/dev/null; then
        info "Attached FIDO2 tokens:"
        fido2-token -L || true
    fi
}

if [[ "$DO_STATUS" == true ]]; then
    show_status
    exit 0
fi

install_packages
ensure_authfile

if [[ "$DO_ENROLL" == true ]]; then
    enroll_key
elif ! user_enrolled; then
    warn "No mapping for $USERNAME yet. Run with --enroll before enforcing login."
    if [[ "$ALLOW_MISSING" != true ]]; then
        err "Refusing to change PAM without an enrolled key (pass --enroll or --allow-missing)"
    fi
fi

if [[ "$DO_LOGIN" == true ]]; then
    configure_login
fi
if [[ "$DO_SUDO" == true ]]; then
    configure_sudo
fi

print_ssh_guidance
show_status

echo
msg "Done. Test a new login before closing this session."
if [[ "$ALLOW_MISSING" == true ]]; then
    warn "nouserok is set: users without a mapping skip the key. Re-run without --allow-missing after everyone is enrolled."
fi
echo -e "${C_YELLOW}If locked out:${C_NC} recover from console and restore the .bak.* files next to the PAM stacks."
