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
umask 022

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

need_arg() { [[ $# -ge 2 && -n "${2:-}" ]] || err "Option $1 requires a value"; }
while [[ $# -gt 0 ]]; do
    case "$1" in
        -u)               need_arg "$@"; USERNAME="$2"; shift 2 ;;
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
[[ "$USERNAME" =~ ^[a-z_][a-z0-9_-]*[$]?$ ]] || err "Invalid username format: $USERNAME"

# Derive hostname strictly from system sources (never trust inherited $HOSTNAME)
HOST_RAW=""
if [[ -s /etc/hostname ]]; then
    IFS= read -r HOST_RAW < /etc/hostname || true
fi
if [[ -z "${HOST_RAW//[[:space:]]/}" ]] && command -v hostnamectl >/dev/null 2>&1; then
    HOST_RAW=$(hostnamectl --static 2>/dev/null || true)
fi
if [[ -z "${HOST_RAW//[[:space:]]/}" ]]; then
    HOST_RAW=$(uname -n 2>/dev/null || true)
fi
HOST_RAW="${HOST_RAW//[[:space:]]/}"
HOST_RAW="${HOST_RAW,,}"
HOST_SHORT="${HOST_RAW%%.*}"
HOST_SHORT="${HOST_SHORT:-localhost}"
if [[ ! "$HOST_SHORT" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]]; then
    err "Invalid system hostname '${HOST_SHORT}' for pam_u2f origin"
fi
ORIGIN="pam://${HOST_SHORT}"

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
    msg "Installing pam-u2f, libfido2, pcsclite, and ccid..."
    pacman -Syu --noconfirm --needed pam-u2f libfido2 pcsclite ccid
    systemctl enable --now pcscd.socket 2>/dev/null || systemctl enable --now pcscd.service 2>/dev/null || true
}

ensure_authfile() {
    if [[ ! -f "$AUTHFILE" ]]; then
        ( umask 077 && : > "$AUTHFILE" )
        chown root:root "$AUTHFILE"
        chmod 0644 "$AUTHFILE"
        info "Created $AUTHFILE"
    fi
}

user_enrolled() {
    [[ -f "$AUTHFILE" ]] || return 1
    USER_TARGET="$USERNAME" awk -F: '
        $1 == ENVIRON["USER_TARGET"] { found = 1; exit }
        END { exit !found }
    ' "$AUTHFILE"
}

user_key_count() {
    [[ -f "$AUTHFILE" ]] || { printf '0\n'; return 0; }
    USER_TARGET="$USERNAME" awk -F: '
        $1 == ENVIRON["USER_TARGET"] { print NF - 1; found = 1; exit }
        END { if (!found) print 0 }
    ' "$AUTHFILE"
}

root_enrolled() {
    [[ -f "$AUTHFILE" ]] || return 1
    awk -F: '$1 == "root" { found = 1; exit } END { exit !found }' "$AUTHFILE"
}

enroll_key() {
    command -v pamu2fcfg >/dev/null || err "pamu2fcfg not found after package install"
    ensure_authfile

    info "Touch the authenticator when it blinks."
    info "If the key has a FIDO2 PIN, you will be prompted for it."
    echo

    local tmp mapping
    tmp=$(umask 077; mktemp)
    # Run pamu2fcfg directly as root with -u "$USERNAME" so /dev/hidraw* seat ACLs
    # never block enrollment over SSH or when enrolling another local user.
    if ! pamu2fcfg -u "$USERNAME" -o "$ORIGIN" -i "$ORIGIN" > "$tmp"; then
        rm -f -- "$tmp"
        err "Enrollment failed. Is the key plugged in? Try: fido2-token -L"
    fi
    mapping=$(tr -d '\n' < "$tmp")
    rm -f -- "$tmp"
    [[ -n "$mapping" ]] || err "pamu2fcfg produced an empty mapping"

    if user_enrolled; then
        local extra
        extra=$(printf '%s' "$mapping" | cut -d: -f2-)
        USER_TARGET="$USERNAME" EXTRA_MAPPING="$extra" awk -F: '
            !done && $1 == ENVIRON["USER_TARGET"] {
                print $0 ":" ENVIRON["EXTRA_MAPPING"]
                done = 1
                next
            }
            { print }
        ' "$AUTHFILE" > "${AUTHFILE}.new"
        chown root:root "${AUTHFILE}.new"
        chmod 0644 "${AUTHFILE}.new"
        mv "${AUTHFILE}.new" "$AUTHFILE"
        msg "Appended an additional key for $USERNAME"
    else
        printf '%s\n' "$mapping" >> "$AUTHFILE"
        chown root:root "$AUTHFILE"
        chmod 0644 "$AUTHFILE"
        msg "Enrolled first key for $USERNAME"
    fi

    local count
    count=$(user_key_count)
    if [[ "${count:-0}" -lt 2 ]]; then
        warn "Only $count key(s) enrolled for $USERNAME. Enroll a backup key before you rely on this."
        warn "Re-run: sudo $0 -u $USERNAME --enroll"
    fi
}

insert_pam_line() {
    local pam_file="$1"
    local line ts already_present=false
    line=$(pam_line)

    [[ -f "$pam_file" ]] || { warn "Skipping missing PAM stack $pam_file"; return 0; }

    if grep -Eq '^[[:space:]]*-?auth[[:space:]]+.*pam_u2f\.so' "$pam_file"; then
        already_present=true
        info "pam_u2f already present in $pam_file — refreshing options and stack order"
    fi

    ts=$(date +%Y%m%d-%H%M%S)
    cp "$pam_file" "${pam_file}.bak.${ts}"
    chmod 0644 "${pam_file}.bak.${ts}"

    # Place pam_u2f AFTER 'auth include system-login' / 'auth include system-auth'
    # so pam_faillock preauth and password verification run first (and [default=die]
    # aborts bad passwords without prompting the FIDO2 key).
    PAM_U2F_LINE="$line" awk '
        /^# FIDO2\/U2F \(added by u2f\.sh\)[[:space:]]*$/ { next }
        /^[[:space:]]*-?auth[[:space:]]+.*pam_u2f\.so/ { next }
        {
            n++
            lines[n] = $0
            if ($0 ~ /^[[:space:]]*-?auth[[:space:]]+(include|substack)[[:space:]]+(system-login|system-auth)([[:space:]]|$)/) {
                include_idx = n
            }
            if ($0 ~ /^[[:space:]]*-?auth[[:space:]]/) {
                last_auth_idx = n
            }
        }
        END {
            insert_after = (include_idx > 0 ? include_idx : last_auth_idx)
            for (i = 1; i <= n; i++) {
                print lines[i]
                if (i == insert_after) {
                    print "# FIDO2/U2F (added by u2f.sh)"
                    print ENVIRON["PAM_U2F_LINE"]
                }
            }
            if (insert_after == 0) {
                print "# FIDO2/U2F (added by u2f.sh)"
                print ENVIRON["PAM_U2F_LINE"]
            }
        }
    ' "$pam_file" > "${pam_file}.new"
    chown root:root "${pam_file}.new"
    chmod 0644 "${pam_file}.new"
    mv "${pam_file}.new" "$pam_file"
    if [[ "$already_present" == false ]]; then
        msg "Wired pam_u2f into $pam_file (after primary password auth)"
    fi
}

configure_login() {
    msg "Configuring local login PAM stacks..."
    insert_pam_line /etc/pam.d/system-local-login

    local dm_pam
    for dm_pam in /etc/pam.d/gdm-password /etc/pam.d/sddm /etc/pam.d/lightdm /etc/pam.d/login; do
        [[ -f "$dm_pam" ]] || continue
        if grep -Eq '^[[:space:]]*-?auth[[:space:]]+(include|substack)[[:space:]]+system-local-login([[:space:]]|$)' "$dm_pam"; then
            info "Skipping $dm_pam (already includes system-local-login)"
            continue
        fi
        insert_pam_line "$dm_pam"
    done
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
  ssh-keygen -t ed25519-sk -O resident -O verify-required -f ~/.ssh/id_ed25519_sk -C "${USERNAME}@${HOST_SHORT}"
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
        count=$(user_key_count)
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
elif [[ "$DO_LOGIN" == true ]] && ! root_enrolled; then
    warn "Local TTY root login ALSO uses system-local-login and requires U2F when nouserok is absent!"
    warn "Unless you enroll root ('sudo $0 -u root --enroll') or pass --allow-missing, local console root login cannot bypass U2F (lockout recovery requires an open root/SSH session or live/rescue media)."
fi
echo -e "${C_YELLOW}If locked out:${C_NC} restore the .bak.* files next to the PAM stacks from an open root/SSH session or live/rescue media."
