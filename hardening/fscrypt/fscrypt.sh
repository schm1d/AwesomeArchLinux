#!/usr/bin/env bash

# =============================================================================
# Script:      fscrypt.sh
# Description: Sets up ext4 per-user home directory encryption using fscrypt
#              with pam_fscrypt. Home directories become encrypted at rest and
#              are transparently unlocked on login via the user's login
#              password. Complements LUKS FDE by protecting users' data from
#              each other and from root when they are not logged in.
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
#
# Usage:       sudo ./fscrypt.sh [--setup] [--encrypt-user USER]
#                                [--status] [--uninstall] [-h]
#
# Requirements:
#   - Arch Linux with pacman
#   - Root privileges
#   - ext4 root and home filesystems with the 'encrypt' feature enabled
#     (enable from a rescue environment: tune2fs -O encrypt <device>)
#
# What this script does:
#   --setup            Install fscrypt, verify ext4 'encrypt' feature,
#                      initialise /etc/fscrypt.conf, wire up pam_fscrypt
#                      in system-login and passwd PAM stacks.
#   --encrypt-user     Move an existing user's home aside, create an empty
#                      encrypted replacement tied to their login password,
#                      and write recovery instructions.
#   --status           Show current fscrypt state.
#   --uninstall        Remove pam_fscrypt wiring. Does not decrypt data.
# =============================================================================

set -euo pipefail

# --- Colors (kept together — some may be unused depending on code path) ---
# shellcheck disable=SC2034
BBlue='\033[1;34m'
# shellcheck disable=SC2034
BRed='\033[1;31m'
# shellcheck disable=SC2034
BGreen='\033[1;32m'
# shellcheck disable=SC2034
BYellow='\033[1;33m'
# shellcheck disable=SC2034
NC='\033[0m'

# --- Paths ---
FSCRYPT_CONF="/etc/fscrypt.conf"
PAM_SYSTEM_LOGIN="/etc/pam.d/system-login"
PAM_PASSWD="/etc/pam.d/passwd"
PAM_FSCRYPT_SO="/usr/lib/security/pam_fscrypt.so"

# --- PAM lines we own (exact strings used for idempotent grep-guard) ---
PAM_AUTH_LINE="auth      optional  pam_fscrypt.so"
PAM_SESSION_LINE="session   optional  pam_fscrypt.so drop_caches lock_policies"
PAM_PASSWORD_LINE="password  optional  pam_fscrypt.so"

MARK="# added by fscrypt.sh"

# --- Logging helpers ---
info() { echo -e "${BBlue}[*]${NC} $*"; }
ok()   { echo -e "${BGreen}[+]${NC} $*"; }
warn() { echo -e "${BYellow}[!]${NC} $*" >&2; }
err()  { echo -e "${BRed}[x]${NC} $*" >&2; exit 1; }

# --- Usage ---
show_help() {
    cat <<EOF
Usage: sudo $0 [--setup] [--encrypt-user USER] [--status] [--uninstall] [-h]

  --setup                 Install fscrypt, verify ext4 'encrypt' feature,
                          create /etc/fscrypt.conf, wire up PAM (default).
  --encrypt-user USER     Encrypt USER's home directory with their login
                          password as the protector. Saves recovery notes
                          to /root/fscrypt-recovery-<user>.txt (0600).
  --status                Show current fscrypt state.
  --uninstall             Remove pam_fscrypt wiring (does NOT decrypt data).
  -h, --help              Show this help.

Examples:
  sudo $0 --setup
  sudo $0 --encrypt-user alice
  sudo $0 --status
  sudo $0 --uninstall
EOF
    exit 0
}

# --- Parse args ---
ACTION="setup"
TARGET_USER=""

if [[ $# -eq 0 ]]; then
    ACTION="setup"
else
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --setup)         ACTION="setup"; shift ;;
            --encrypt-user)  ACTION="encrypt-user"; TARGET_USER="${2:-}"; shift 2 ;;
            --status)        ACTION="status"; shift ;;
            --uninstall)     ACTION="uninstall"; shift ;;
            -h|--help)       show_help ;;
            *)               warn "Unknown option: $1"; show_help ;;
        esac
    done
fi

# --- Root check ---
if [[ "$(id -u)" -ne 0 ]]; then
    err "This script must be run as root."
fi

# =============================================================================
# Helpers
# =============================================================================

backup_file() {
    # Timestamped backup, idempotent per-second (only once per invocation).
    local path="$1"
    local stamp
    stamp="$(date +%s)"
    if [[ -f "$path" && ! -f "${path}.bak.${stamp}" ]]; then
        cp -a "$path" "${path}.bak.${stamp}"
        info "Backed up $path -> ${path}.bak.${stamp}"
    fi
}

get_root_device() {
    # findmnt gives us the source device for /. May be /dev/mapper/... under LUKS+LVM.
    findmnt -n -o SOURCE / 2>/dev/null || true
}

is_ext4() {
    [[ "$(findmnt -n -o FSTYPE -T "${1:-/}")" == ext4 ]]
}

has_encrypt_feature() {
    local dev="$1"
    [[ -n "$dev" && -b "$dev" ]] || return 2
    # tune2fs -l prints a "Filesystem features:" line with space-separated flags.
    if tune2fs -l "$dev" 2>/dev/null | grep -E '^Filesystem features:' | grep -qw encrypt; then
        return 0
    fi
    return 1
}

validate_encryption_filesystem() {
    local path="$1" dev
    is_ext4 "$path" || err "The filesystem containing $path is not ext4."
    dev=$(findmnt -n -o SOURCE -T "$path") || err "Cannot find the device containing $path."
    [[ -n "$dev" ]] || err "Cannot find the device containing $path."
    if ! has_encrypt_feature "$dev"; then
        err "The ext4 'encrypt' feature is missing on $dev (containing $path). Boot rescue media, unmount that filesystem, run 'tune2fs -O encrypt $dev', then retry."
    fi
}

prepare_encryption_filesystem() {
    local path="$1" mountpoint metadata
    mountpoint=$(findmnt -n -o TARGET -T "$path") || err "Cannot find the mount containing $path."
    [[ "$mountpoint" == /* ]] || err "Invalid mount point for $path."
    metadata="${mountpoint%/}/.fscrypt"
    if [[ ! -e "$metadata" ]]; then
        info "Initialising fscrypt metadata on $mountpoint ..."
        fscrypt setup "$mountpoint" --quiet || err "fscrypt setup failed on $mountpoint; home directories have not been moved."
    fi
    [[ -d "$metadata/policies" && -d "$metadata/protectors" ]] || \
        err "Incomplete fscrypt metadata on $mountpoint. Repair it before encrypting homes."
    fscrypt status "$mountpoint" >/dev/null || err "Cannot read fscrypt metadata on $mountpoint."
}

pam_line_present() {
    # Exact-match grep on the PAM file.
    local file="$1" needle="$2"
    [[ -f "$file" ]] || return 1
    grep -Fqx "$needle" "$file"
}

append_pam_line() {
    local file="$1" line="$2"
    if pam_line_present "$file" "$line"; then
        info "Already present in $file: $line"
        return 0
    fi
    backup_file "$file"
    {
        echo ""
        echo "$MARK"
        echo "$line"
    } >> "$file"
    ok "Appended to $file: $line"
}

remove_pam_lines() {
    # Remove lines matching any of our exact PAM strings plus preceding MARK
    # comments. Uses a tmp file to keep things simple and portable.
    local file="$1"
    [[ -f "$file" ]] || return 0
    backup_file "$file"
    local tmp
    tmp="$(mktemp)"
    # Drop any line that is exactly one of our managed lines or our marker.
    awk -v m="$MARK" \
        -v a="$PAM_AUTH_LINE" \
        -v s="$PAM_SESSION_LINE" \
        -v p="$PAM_PASSWORD_LINE" \
        '$0 != m && $0 != a && $0 != s && $0 != p { print }' "$file" > "$tmp"
    mv "$tmp" "$file"
    chmod 644 "$file"
    ok "Cleaned pam_fscrypt lines from $file"
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || err "Required command not found: $1"
}

# =============================================================================
# Actions
# =============================================================================

do_status() {
    info "fscrypt status"
    local dev
    dev="$(get_root_device)"
    echo "Root device           : ${dev:-unknown}"

    if is_ext4; then
        echo "Root filesystem type  : ext4"
    else
        echo "Root filesystem type  : $(stat -f -c %T / 2>/dev/null || echo unknown) (NOT ext4)"
    fi

    if [[ -n "$dev" && -b "$dev" ]]; then
        if has_encrypt_feature "$dev"; then
            echo "ext4 'encrypt' feat.  : enabled"
        else
            echo "ext4 'encrypt' feat.  : DISABLED (needs: tune2fs -O encrypt $dev from rescue)"
        fi
    fi

    if command -v fscrypt >/dev/null 2>&1; then
        echo "fscrypt package       : installed ($(fscrypt --version 2>&1 | head -n1))"
    else
        echo "fscrypt package       : NOT installed"
    fi

    if [[ -f "$FSCRYPT_CONF" ]]; then
        echo "$FSCRYPT_CONF       : present"
    else
        echo "$FSCRYPT_CONF       : MISSING (run --setup)"
    fi

    if [[ -f "$PAM_FSCRYPT_SO" ]]; then
        echo "pam_fscrypt.so        : $PAM_FSCRYPT_SO"
    else
        echo "pam_fscrypt.so        : NOT FOUND"
    fi

    # PAM wiring
    local wired=1
    pam_line_present "$PAM_SYSTEM_LOGIN" "$PAM_AUTH_LINE"     || wired=0
    pam_line_present "$PAM_SYSTEM_LOGIN" "$PAM_SESSION_LINE"  || wired=0
    pam_line_present "$PAM_PASSWD"       "$PAM_PASSWORD_LINE" || wired=0
    if [[ "$wired" -eq 1 ]]; then
        echo "PAM wiring            : complete"
    else
        echo "PAM wiring            : incomplete or absent"
    fi

    # Encrypted users
    if command -v fscrypt >/dev/null 2>&1; then
        echo "---- fscrypt status ----"
        fscrypt status 2>&1 || warn "fscrypt status failed (not set up yet?)"
    fi
}

do_setup() {
    info "Starting fscrypt system-wide setup"

    # Validate both devices before installing packages or changing PAM.
    # The base installer puts /home on a separate logical volume.
    validate_encryption_filesystem /
    validate_encryption_filesystem /home

    # 3. Install fscrypt
    require_cmd pacman
    if ! command -v fscrypt >/dev/null 2>&1; then
        info "Installing fscrypt via pacman..."
        pacman -S --needed --noconfirm fscrypt
    else
        info "fscrypt already installed"
    fi

    # 4. Verify pam_fscrypt.so shipped by the package
    if [[ ! -f "$PAM_FSCRYPT_SO" ]]; then
        err "pam_fscrypt.so not found at $PAM_FSCRYPT_SO. \
Package install may have failed or the module path has changed. \
Check: pacman -Ql fscrypt | grep pam_fscrypt"
    fi
    ok "pam_fscrypt.so present at $PAM_FSCRYPT_SO"

    # 5. fscrypt setup (creates /etc/fscrypt.conf + /.fscrypt metadata dir)
    if [[ -f "$FSCRYPT_CONF" ]]; then
        info "$FSCRYPT_CONF already exists — skipping 'fscrypt setup'"
    else
        info "Running 'fscrypt setup'..."
        # --quiet --force answer all prompts non-interactively where possible.
        # This also initialises the metadata directory on the root mount.
        if ! fscrypt setup --quiet --force 2>/dev/null; then
            warn "'fscrypt setup --quiet --force' did not succeed non-interactively."
            warn "Falling back to interactive run. Accept the defaults when prompted."
            fscrypt setup || err "fscrypt setup failed."
        fi
        ok "fscrypt setup complete"
    fi

    # Login protectors live on /; policies live on the home's filesystem.
    prepare_encryption_filesystem /
    prepare_encryption_filesystem /home

    # 6. PAM wiring
    info "Wiring pam_fscrypt into PAM stacks..."
    [[ -f "$PAM_SYSTEM_LOGIN" ]] || err "$PAM_SYSTEM_LOGIN not found — is pambase installed?"
    [[ -f "$PAM_PASSWD" ]]       || err "$PAM_PASSWD not found — is pambase installed?"

    append_pam_line "$PAM_SYSTEM_LOGIN" "$PAM_AUTH_LINE"
    append_pam_line "$PAM_SYSTEM_LOGIN" "$PAM_SESSION_LINE"
    append_pam_line "$PAM_PASSWD"       "$PAM_PASSWORD_LINE"

    ok "PAM wiring complete"

    # 7. Post-setup summary
    cat <<EOF

${MARK%# *}
================================================================================
 fscrypt system-wide setup complete.
================================================================================

 What this means:
   - The system is READY to host per-user encrypted home directories.
   - No users are encrypted yet. Encryption is strictly opt-in per user.

 Next steps:

   To encrypt an existing user's home:
       sudo $0 --encrypt-user <name>

   Newly created users (useradd) are NOT automatically encrypted — you must
   run --encrypt-user for each account that should have an encrypted home.

 CRITICAL:
   - If a user forgets their login password, their home data is LOST unless
     a recovery key (protector) is stored somewhere safe.
   - fscrypt does not protect against attackers who gain root while a user
     is logged in. It protects data at rest when the user is logged out.

 Check state any time with:
     sudo $0 --status

EOF
}

do_encrypt_user() {
    local u="$TARGET_USER"
    [[ -n "$u" ]] || err "--encrypt-user requires a USERNAME argument."

    # Verify user exists
    id -u "$u" >/dev/null 2>&1 || err "User '$u' does not exist."

    # Prereqs: setup must already have run
    command -v fscrypt >/dev/null 2>&1 || err "fscrypt is not installed. Run: sudo $0 --setup"
    [[ -f "$FSCRYPT_CONF" ]]           || err "$FSCRYPT_CONF missing. Run: sudo $0 --setup"
    [[ -f "$PAM_FSCRYPT_SO" ]]         || err "pam_fscrypt.so missing. Run: sudo $0 --setup"

    local home
    home="$(getent passwd "$u" | cut -d: -f6)"
    [[ -n "$home" && -d "$home" ]] || err "Home directory for '$u' not found."
    [[ "$home" == /* && ! -L "$home" ]] || err "Home must be an absolute, non-symlink directory."
    mountpoint -q -- "$home" && err "Home is itself a mount point; this migration requires a directory below the mount."

    info "Target user : $u"
    info "Home        : $home"

    # Detect whether the home is already encrypted
    if fscrypt status "$home" >/dev/null 2>&1; then
        warn "$home appears to already be encrypted. Nothing to do."
        return 0
    fi

    # Confirm the move-aside approach with the operator
    local moved="${home}.pre-encrypt"
    if [[ -e "$moved" || -L "$moved" ]]; then
        err "$moved already exists. Refusing to clobber. Remove or rename it first."
    fi

    # Resolve the actual home, including homes outside /home, before moving
    # any data or terminating the user's sessions. Setup errors are fatal.
    validate_encryption_filesystem /
    validate_encryption_filesystem "$home"
    prepare_encryption_filesystem /
    prepare_encryption_filesystem "$home"

    cat <<EOF

 About to encrypt $home for user '$u'.

 Plan:
   1. Encrypt an empty sibling directory using '$u''s login passphrase.
   2. Terminate any active sessions for '$u' (loginctl terminate-user).
   3. Move $home aside to $moved  (YOUR DATA, preserved, NOT deleted).
   4. Put the encrypted directory at $home, mode 700, owned by '$u'.
   5. Write instructions for adding a recovery protector.

 You will need the user's login password to complete step 1.

EOF
    read -r -p "Type YES to proceed: " confirm
    [[ "$confirm" == "YES" ]] || err "Aborted by operator."

    # Capture ownership/mode of existing home so we recreate faithfully.
    local owner group mode
    owner="$(stat -c %U "$home")"
    group="$(stat -c %G "$home")"
    mode="$(stat -c %a "$home")"
    info "Current home ownership: ${owner}:${group} mode ${mode}"

    # Encrypt before moving the original home. Root manages the metadata;
    # --user selects the target user's login protector and keyring without
    # requiring world-writable metadata directories.
    local staged
    staged=$(mktemp -d -- "${home}.encrypt.XXXXXX")
    chown "$u:$group" "$staged"
    info "Running 'fscrypt encrypt' — the user's LOGIN PASSWORD will be requested."
    if ! fscrypt encrypt "$staged" --user="$u" --source=pam_passphrase; then
        rmdir -- "$staged" 2>/dev/null || warn "Inspect the failed encryption directory: $staged"
        err "fscrypt encrypt failed. The original home remains at $home."
    fi

    # An account with no sessions is absent from logind; terminating it would
    # fail even though it is already safe to proceed.
    local active_users uid
    uid=$(id -u "$u")
    active_users=$(loginctl list-users --no-legend --no-pager) || err "Cannot check active sessions; original home remains at $home."
    if awk -v uid="$uid" '$1 == uid { found=1 } END { exit !found }' <<< "$active_users"; then
        info "Terminating active sessions for '$u'..."
        loginctl terminate-user "$u" || err "Could not terminate sessions; original home remains at $home, encrypted directory at $staged."
        sleep 1
    fi
    info "Moving $home -> $moved"
    mv -T -- "$home" "$moved"
    if ! mv -T -- "$staged" "$home"; then
        mv -T -- "$moved" "$home" || err "Restore $moved to $home manually; encrypted directory is at $staged."
        err "Could not activate encrypted home; the original home has been restored."
    fi
    ok "fscrypt encrypt succeeded on $home"

    # 5. Recovery key handling.
    #
    # NOTE: fscrypt does not have a first-class '--emit-recovery-key' flag on
    # every release. The portable way to add a second protector is:
    #     fscrypt metadata create protector --source=custom_passphrase \
    #         --name=<user>-recovery /
    # followed by linking it with:
    #     fscrypt metadata add-protector-to-policy ...
    # The exact flag names have moved between releases, so rather than bake
    # a fragile command in, we emit a TODO banner and direct the admin to
    # the README for the manual recipe. The encrypted directory is already
    # live and the login-password protector is already in place.
    local recovery_file="/root/fscrypt-recovery-${u}.txt"
    umask 077
    cat > "$recovery_file" <<EOF
fscrypt recovery information for user: $u
Generated: $(date -Iseconds)
Home     : $home
Original : $moved   (still present — remove manually once verified)

NO automatic recovery key was generated by this script. fscrypt's CLI for
creating a secondary recovery protector varies by release. To add one
manually, run (as root), then record the passphrase here:

    fscrypt metadata create protector --source=custom_passphrase \\
        --name=${u}-recovery /

    # then attach it to the policy protecting $home — see 'fscrypt metadata --help'
    # for the exact add-protector-to-policy invocation on your release.

Store that passphrase in a password manager. If '$u' forgets their login
password, unlocking $home will require this recovery protector.
EOF
    chmod 600 "$recovery_file"
    ok "Recovery notes written to $recovery_file (mode 600)"

    # Next-step instructions for the user
    cat <<EOF

================================================================================
 $home is now ENCRYPTED.
================================================================================

 What '$u' must do next:

   1. Log in as '$u' at the console / display manager using their normal
      login password. pam_fscrypt will unlock $home automatically.

   2. Copy their previous files back into the now-encrypted home, e.g.:

         cp -a $moved/. $home/
         # or, if they prefer, move selected files only.

   3. Once they have verified the copy is intact and everything works,
      they can remove the old unencrypted copy:

         sudo rm -rf $moved

      The script intentionally leaves $moved in place so nothing is lost
      if something goes wrong.

 Recovery notes: $recovery_file
 (Read it — no automatic recovery key was generated. See README.md.)

 Reminder: if '$u' forgets their login password AND no recovery protector
 has been added, the contents of $home are UNRECOVERABLE.

EOF
}

do_uninstall() {
    info "Removing pam_fscrypt wiring..."

    remove_pam_lines "$PAM_SYSTEM_LOGIN"
    remove_pam_lines "$PAM_PASSWD"

    ok "PAM wiring removed."

    cat <<EOF

${MARK%# *}
================================================================================
 fscrypt PAM wiring has been removed.
================================================================================

 IMPORTANT — what this did NOT do:

   * It did NOT uninstall the fscrypt package.
   * It did NOT remove /etc/fscrypt.conf or the metadata under /.fscrypt.
   * It did NOT decrypt any user's home directory.

 Why not: decrypting a user's home requires that user's login passphrase
 (or their recovery protector). We cannot do that from a root script.

 To fully decrypt and dismantle:

   Per user (must be done interactively, as that user, with their password):
       fscrypt lock /home/<user>          # if currently unlocked
       # back up their data, then destroy the policy:
       fscrypt purge / --user=<user>      # removes their policies
       # or move data out, remove the directory, recreate unencrypted.

   System-wide:
       pacman -R fscrypt
       rm -rf /etc/fscrypt.conf /.fscrypt

 Log in managers / SSH sessions may need a restart to fully drop the PAM
 module from their running configuration:
       systemctl restart sshd
       (or reboot for display managers)

EOF
}

# =============================================================================
# Dispatch
# =============================================================================

case "$ACTION" in
    setup)         do_setup ;;
    encrypt-user)  do_encrypt_user ;;
    status)        do_status ;;
    uninstall)     do_uninstall ;;
    *)             show_help ;;
esac
