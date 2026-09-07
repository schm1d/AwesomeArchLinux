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

render_audit_rules() (
    set -euo pipefail
    local template="$1" root="${2:-}" line path resolved field i skip
    local -a words
    local -A seen=()
    # These watches form the required baseline; other paths depend on packages
    # and runtime files. Re-render at boot so newly installed tools are covered.
    for path in /etc/audit /etc/pam.d /etc/pam.d/system-auth /etc/passwd \
        /etc/shadow /etc/group /etc/gshadow /etc/sudoers /usr/bin/sudo \
        /usr/bin/pacman /etc/pacman.conf; do
        [[ -e "$root$path" ]] || {
            echo "Required audit path is missing: $path" >&2
            return 1
        }
    done
    while IFS= read -r line || [[ -n "$line" ]]; do
        read -r -a words <<< "$line"
        [[ ${#words[@]} -gt 0 && ${words[0]} != \#* ]] || continue
        skip=0
        for ((i=0; i<${#words[@]}; i++)); do
            field=""
            case "${words[i]}" in
                -w) i=$((i + 1)); path="${words[i]:-}" ;;
                path=*|dir=*) field="${words[i]%%=*}="; path="${words[i]#*=}" ;;
                *) continue ;;
            esac
            [[ "$path" == /* && "$path" != *[\*\?\[]* ]] || {
                echo "Invalid audit path: $path" >&2
                return 1
            }
            if [[ ! -e "$root$path" ]]; then
                echo "Audit watch omitted (path absent): $path" >&2
                skip=1
                break
            fi
            # Arch's /bin and /sbin aliases can otherwise create duplicate rules.
            resolved=$(realpath -e -- "$root$path")
            if [[ -n "$root" && "$resolved" != "$root/"* ]]; then
                echo "Audit path escapes the target filesystem: $path" >&2
                return 1
            fi
            words[i]="$field${resolved#"$root"}"
        done
        (( skip == 0 )) || continue
        line="${words[*]}"
        [[ -z "${seen[$line]:-}" ]] || continue
        seen[$line]=1
        printf '%s\n' "$line"
    done < "$template"
)

audit_rules_without_lock() {
    # Check the assembled policy too: another .rules file must not reintroduce
    # ignored errors or lock a partially loaded policy. auditctl validates the
    # actual rule syntax against the running kernel at boot, never in chroot.
    awk '
        /^[[:space:]]*(#|$)/ { next }
        {
            if (locked) bad=1
            for (i=1; i<=NF; i++) if ($i == "-i" || $i == "-c") bad=1
            if ($1 == "-e") {
                if (NF != 2 || $2 != 2) bad=1
                locked++
                next
            }
            if ($1 !~ /^(-D|-b|-f|-r|-a|-A|-w|--backlog_wait_time|--loginuid-immutable)$/) bad=1
            print
        }
        END {
            if (bad || locked != 1) {
                print "Invalid audit controls: require one final -e 2 and no ignored errors." > "/dev/stderr"
                exit 1
            }
        }
    ' "$1"
}

load_audit_rules() (
    set -euo pipefail
    local root="${1:-}" work status
    status=$(auditctl -s)
    if grep -Eq '^enabled[[:space:]]+2$' <<< "$status"; then
        echo "Audit rules are already immutable; reboot to load policy changes." >&2
        return 1
    fi
    work=$(mktemp -d "$root/etc/audit/.awesome-rules.XXXXXX")
    trap 'rm -rf -- "$work"' EXIT
    render_audit_rules "$root/usr/local/share/awesomearchlinux/auditd-attack.rules" "$root" > "$work/managed"
    audit_rules_without_lock "$work/managed" > /dev/null
    install -m 0600 "$work/managed" "$root/etc/audit/rules.d/auditd-attack.rules"
    # Merge local administrator rules using audit's normal ordering semantics.
    # augenrules queries the kernel even without --load, so this runs at boot.
    augenrules
    audit_rules_without_lock "$root/etc/audit/audit.rules" > "$work/load.rules"
    chmod 0600 "$work/load.rules" "$root/etc/audit/audit.rules"
    if ! auditctl -R "$work/load.rules"; then
        echo "Audit rule loading failed; policy remains unlocked for repair. Check audit-rules.service." >&2
        return 1
    fi
    auditctl -e 2
)

configure_audit_rules() (
    set -euo pipefail
    local root="${1:-}"
    install -d -m 0755 "$root/etc/audit/rules.d" "$root/usr/local/sbin" \
        "$root/etc/systemd/system/audit-rules.service.d"
    cat > "$root/usr/local/sbin/awesome-load-audit-rules" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
source /usr/local/lib/awesomearchlinux/chroot-security.sh
load_audit_rules
EOF
    chmod 0755 "$root/usr/local/sbin/awesome-load-audit-rules"
    cat > "$root/etc/systemd/system/audit-rules.service.d/10-awesome.conf" <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/local/sbin/awesome-load-audit-rules
EOF
    echo "Bundled audit policy staged; audit-rules.service will render, load and lock it at boot."
)

run_vulnerability_check() (
    set -euo pipefail
    umask 077
    local root="${1:-}" report work rc
    report="$root/var/log/arch-audit.log"
    work=$(mktemp "$root/var/log/.arch-audit.XXXXXX")
    trap 'rm -f -- "$work"' EXIT
    # arch-audit can exit successfully with findings. An explicit format gives
    # one nonempty line per vulnerable package, including unfixed advisories.
    if arch-audit --color never --format '%n | severity: %s | CVEs: %c | fixed: %v' > "$work"; then
        rc=0
    else
        rc=$?
        echo "Vulnerability scan failed (exit $rc); previous report retained at $report. See journalctl -u arch-audit.service." >&2
        return "$rc"
    fi
    if [[ -s "$work" ]]; then
        cat "$work"
        rc=1
    fi
    # Only publish complete scans; a failed fetch must not erase old findings.
    mv -f -- "$work" "$report"
    if (( rc != 0 )); then
        echo "Vulnerable packages found. Review $report, apply available updates with pacman -Syu, and rerun arch-audit; unfixed advisories need manual review." >&2
    else
        echo "Vulnerability scan completed: no known vulnerable packages reported."
    fi
    return "$rc"
)

configure_vulnerability_check() (
    set -euo pipefail
    local root="${1:-}"
    install -d -m 0755 "$root/usr/local/bin" "$root/etc/systemd/system"
    cat > "$root/usr/local/bin/arch-audit-check" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
source /usr/local/lib/awesomearchlinux/chroot-security.sh
run_vulnerability_check
EOF
    chmod 0755 "$root/usr/local/bin/arch-audit-check"
    cat > "$root/etc/systemd/system/arch-audit.service" <<'EOF'
[Unit]
Description=Check installed Arch packages for known vulnerabilities
Wants=network-online.target
After=network-online.target
OnFailure=arch-audit-alert.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/arch-audit-check
TimeoutStartSec=5min
UMask=0077
EOF
    cat > "$root/etc/systemd/system/arch-audit-alert.service" <<'EOF'
[Unit]
Description=Notify logged-in users that the vulnerability scan needs attention

[Service]
Type=oneshot
ExecStart=/usr/bin/wall --nobanner "Arch vulnerability scan needs attention. Check systemctl status arch-audit.service and journalctl -u arch-audit.service; the last completed report is /var/log/arch-audit.log."
EOF
    cat > "$root/etc/systemd/system/arch-audit.timer" <<'EOF'
[Unit]
Description=Run arch-audit after boot and daily

[Timer]
OnBootSec=15min
OnCalendar=daily
RandomizedDelaySec=30min
Persistent=true

[Install]
WantedBy=timers.target
EOF
)

initialize_journal_sealing() (
    set -euo pipefail
    umask 077
    local root="${1:-}" machine_id state keydir verification diagnostic rc
    # PID 1 establishes the installed machine's ID before this boot service runs.
    # Never generate keys in the installer chroot using the live ISO's identity.
    machine_id=$(cat "$root/etc/machine-id")
    [[ "$machine_id" =~ ^[0-9a-f]{32}$ && "$machine_id" != 00000000000000000000000000000000 ]] || {
        echo "Journal sealing requires a valid machine-id from the installed system." >&2
        return 1
    }
    state="$root/var/log/journal/$machine_id/fss"
    keydir="$root/root/journal-sealing"
    verification="$keydir/verification-$machine_id.txt"
    diagnostic="$keydir/setup-$machine_id.log"
    install -d -m 0700 "$keydir"
    exec 9> "$keydir/.setup.lock"
    flock -n 9 || { echo "Journal sealing setup is already running." >&2; return 1; }
    if [[ -e "$state" || -L "$state" ]]; then
        [[ -f "$state" && ! -L "$state" && -s "$state" ]] || {
            echo "Invalid journal sealing state at $state; refusing to replace it." >&2
            return 1
        }
        chmod 0600 "$state"
        echo "Existing journal sealing key preserved."
    else
        # A saved verification key without its sealing state needs investigation,
        # not automatic key replacement that would discard the verification chain.
        if [[ -e "$verification" || -L "$verification" ]]; then
            echo "Saved verification output exists without sealing state; inspect $verification and $diagnostic before retrying. No keys replaced." >&2
            return 1
        fi
        install -d -m 0755 "$root/var/log/journal" "${state%/fss}"
        # Capture directly in a private, durable location. Even an interruption
        # after key creation must not delete the only copy of the verification key.
        if (set -o noclobber
            SYSTEMD_LOG_TARGET=console SYSTEMD_COLORS=0 journalctl --quiet --setup-keys \
                > "$verification" 2>> "$diagnostic"); then
            rc=0
        else
            rc=$?
            echo "Journal sealing setup failed (exit $rc). Private output retained in $keydir for recovery." >&2
            return "$rc"
        fi
        if [[ ! -s "$state" ]] || ! grep -Eq '^[0-9a-f-]+/[0-9a-f]+-[0-9a-f]+$' "$verification"; then
            echo "Journal sealing setup did not produce both keys; inspect $keydir. No success assumed." >&2
            return 1
        fi
        chmod 0600 "$state" "$verification" "$diagnostic"
        sync -f "$verification"
        sync -f "$state"
        echo "Journal sealing keys initialized for this machine."
    fi
    if [[ -e "$verification" ]]; then
        if ! grep -Eq '^[0-9a-f-]+/[0-9a-f]+-[0-9a-f]+$' "$verification"; then
            echo "Incomplete verification output at $verification; recover it before relying on journal sealing. Existing keys preserved." >&2
            return 1
        fi
        echo "ACTION REQUIRED: Move $verification to trusted off-machine storage, verify the copy, then remove the local copy. Never move the fss sealing state."
    fi
)

configure_journal_sealing() (
    set -euo pipefail
    local root="${1:-}"
    install -d -m 0755 "$root/etc/systemd/journald.conf.d" "$root/usr/local/sbin" \
        "$root/etc/systemd/system/systemd-journal-flush.service.d"
    # Repair the invalid value written by earlier versions, including on reruns.
    if [[ -f "$root/etc/systemd/journald.conf" ]]; then
        sed -i -E 's/^[[:space:]]*SplitMode[[:space:]]*=[[:space:]]*login[[:space:]]*$/SplitMode=uid/' \
            "$root/etc/systemd/journald.conf"
    fi
    cat > "$root/etc/systemd/journald.conf.d/60-awesome.conf" <<'EOF'
[Journal]
Storage=persistent
Compress=yes
Seal=yes
SplitMode=uid
ForwardToSyslog=no
SystemMaxUse=200M
EOF
    cat > "$root/usr/local/sbin/awesome-journal-sealing" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
source /usr/local/lib/awesomearchlinux/chroot-security.sh
initialize_journal_sealing
EOF
    chmod 0755 "$root/usr/local/sbin/awesome-journal-sealing"
    cat > "$root/etc/systemd/system/awesome-journal-sealing.service" <<'EOF'
[Unit]
Description=Initialize journal sealing keys for this machine
DefaultDependencies=no
Wants=systemd-journald.service
After=systemd-remount-fs.service systemd-journald.service
Before=systemd-journal-flush.service
RequiresMountsFor=/var/log/journal /root
ConditionPathExists=!/etc/initrd-release

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/awesome-journal-sealing
UMask=0077
TimeoutStartSec=2min
EOF
    cat > "$root/etc/systemd/system/systemd-journal-flush.service.d/60-awesome-sealing.conf" <<'EOF'
[Unit]
# Keep logging even if key setup fails; the sealing service remains visibly failed.
Wants=awesome-journal-sealing.service
After=awesome-journal-sealing.service

[Service]
# New persistent files pick up the key; old files cannot be retroactively sealed.
ExecStartPost=/usr/bin/journalctl --rotate
EOF
    echo "Journal sealing staged for boot; export the verification key from /root/journal-sealing after setup."
)
