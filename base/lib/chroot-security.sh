#!/usr/bin/env bash
# Shared security setup for the bare-metal and VPS chroots.
# Functions accept a filesystem prefix for offline configuration and tests.

render_password_stack() {
    awk '
        /^[[:space:]]*#/ { print; next }
        /pam_faillock\.so/ {
            # Let faillock.conf own these values without changing PAM jumps.
            gsub(/[[:space:]]+(deny|unlock_time)=[^[:space:]]+/, "")
        }
        $1 ~ /^-?password$/ {
            if ($0 ~ /[[:space:]]pam_pwquality\.so([[:space:]]|$)/) next
            if (!inserted++)
                print "password requisite pam_pwquality.so retry=3 enforce_for_root"
            if ($0 ~ /[[:space:]]pam_unix\.so([[:space:]]|$)/) {
                unix_count++
                # An inline comment must not swallow the new module option.
                comment = ""
                if (match($0, /[[:space:]]+#/)) {
                    comment = substr($0, RSTART)
                    $0 = substr($0, 1, RSTART - 1)
                }
                if ($0 !~ /[[:space:]]use_authtok([[:space:]]|$)/)
                    $0 = $0 " use_authtok"
                $0 = $0 comment
            }
        }
        { print }
        END {
            if (unix_count != 1) {
                print "Expected exactly one local pam_unix password entry; refusing to rewrite this PAM stack." > "/dev/stderr"
                exit 1
            }
        }
    ' "$1"
}

configure_password_policy() (
    set -euo pipefail
    local root="${1:-}" pam work path
    pam="$root/etc/pam.d/system-auth"
    # Arch already supplies the complete faillock control flow. Preserve it.
    for phase in preauth authfail authsucc; do
        grep -Eq "^[[:space:]]*auth[[:space:]].*pam_faillock[.]so[[:space:]].*${phase}([[:space:]]|$)" "$pam" || {
            echo "Missing Arch pam_faillock $phase entry in $pam; review this PAM stack before continuing." >&2
            return 1
        }
    done
    work=$(mktemp -d "$root/etc/pam.d/.awesome-policy.XXXXXX")
    trap 'rm -rf -- "$work"' EXIT
    render_password_stack "$pam" > "$work/system-auth"
    cat > "$work/pwquality.conf" <<'EOF'
# Managed by AwesomeArchLinux; checked before initial password creation.
minlen = 12
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
difok = 5
enforce_for_root
EOF
    # Keep unrelated faillock settings and comments; avoid duplicate overrides.
    if [[ -f "$root/etc/security/faillock.conf" ]]; then
        sed -E '/^[[:space:]]*(deny|unlock_time)[[:space:]]*=/d' \
            "$root/etc/security/faillock.conf" > "$work/faillock.conf"
    fi
    printf 'deny = 5\nunlock_time = 900\n' >> "$work/faillock.conf"
    for path in pam.d/system-auth security/pwquality.conf security/faillock.conf; do
        if [[ -f "$root/etc/$path" && ! -e "$root/etc/$path.before-awesome" ]]; then
            cp -p -- "$root/etc/$path" "$root/etc/$path.before-awesome"
        fi
    done
    install -m 0644 "$work/pwquality.conf" "$root/etc/security/pwquality.conf"
    install -m 0644 "$work/faillock.conf" "$root/etc/security/faillock.conf"
    # Rename a complete file, so an interrupted write cannot truncate PAM.
    chmod 0644 "$work/system-auth"
    mv -f -- "$work/system-auth" "$pam"
)
