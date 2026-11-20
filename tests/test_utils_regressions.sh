#!/usr/bin/env bash
# Regression tests for utils/: generated container, monitoring and cpupower
# configuration, audit-check.sh verdicts, reviewed AUR installs, and the
# pinned third-party downloads of the desktop helper scripts.
#
# Nothing here needs root, network access or the real tools: every external
# command is replaced by a shell function (not a PATH stub, which a noexec
# /tmp would silently skip in favour of the real binary).

set -euo pipefail

# shellcheck disable=SC1090,SC1091
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

# Body of the first here-document in FILE whose opening line matches the
# extended regex RE. The delimiter is taken from that line.
heredoc_body() {
    local file="$1" re="$2"
    awk -v re="$re" '
        !capture && $0 ~ re {
            delim = $0
            sub(/.*<<-?[[:space:]]*/, "", delim)
            sub(/[[:space:]].*$/, "", delim)
            gsub(/["\047]/, "", delim)
            capture = 1
            next
        }
        capture && $0 == delim { found = 1; exit }
        capture { print }
        END { if (!found) exit 1 }
    ' "$file"
}

# -----------------------------------------------------------------------------
# docker.sh
# -----------------------------------------------------------------------------

test_docker_generated_configs_match_what_the_daemons_accept() {
    local docker_sh="$REPO_ROOT/utils/docker.sh"
    local daemon_json dropin registries code

    # dockerd turns each default-ulimits entry into RLIMIT_<Name>; an entry
    # without "Name" makes every container start fail.
    daemon_json="$(heredoc_body "$docker_sh" 'daemon[.]json <<')"
    grep -Eq '"nofile":[[:space:]]*\{[^}]*"Name":[[:space:]]*"nofile"' <<<"$daemon_json" || fail 'default-ulimits.nofile has no "Name"'
    grep -Eq '"nproc":[[:space:]]*\{[^}]*"Name":[[:space:]]*"nproc"' <<<"$daemon_json" || fail 'default-ulimits.nproc has no "Name"'
    code="$(script_code "$docker_sh")"
    assert_contains "$code" "dockerd --validate --config-file /etc/docker/daemon.json" "daemon.json is validated before the restart"

    # dockerd manages mounts, devices and setuid files for containers: unit
    # sandboxing that gives it a private mount namespace breaks it.
    dropin="$(heredoc_body "$docker_sh" 'docker[.]service[.]d/hardened[.]conf <<' | grep -v '^[[:space:]]*#' || true)"
    assert_contains "$dropin" "[Service]"
    if grep -E '^(Protect|Private|ReadWritePaths|ReadOnlyPaths|InaccessiblePaths|RestrictSUIDSGID|RestrictNamespaces|NoNewPrivileges|MemoryDenyWriteExecute|SystemCallFilter|CapabilityBoundingSet)' <<<"$dropin"; then
        fail "docker.service drop-in contains sandboxing that dockerd cannot run under"
    fi

    # registries.conf: v2 keys only. One v1 table ([registries.search], ...)
    # next to them makes Podman reject the file and every pull.
    registries="$(heredoc_body "$docker_sh" 'containers/registries[.]conf <<')"
    assert_contains "$registries" 'unqualified-search-registries = ["docker.io"]'
    assert_contains "$registries" 'short-name-mode = "enforcing"'
    assert_not_contains "$registries" "[registries" "no v1 [registries.*] table in a v2 registries.conf"

    # Root never writes through the user-owned ~/.config/containers.
    assert_not_contains "$code" '> "${USER_CONTAINERS_DIR}' "storage.conf is not written by root through a user-controlled path"
    assert_contains "$code" "' _ \"\${USER_CONTAINERS_DIR}/storage.conf\" <<" "storage.conf is written by the target user"
}

test_docker_install_config_backs_up_changed_files() {
    local tmp fn
    tmp="$(mktemp -d)"
    trap 'trap - RETURN EXIT; [[ -n "${tmp:-}" ]] && rm -rf -- "$tmp"' RETURN EXIT
    fn="$(extract_shell_function "utils/docker.sh" "install_config")"

    printf 'old\n' > "$tmp/app.conf"
    bash -c '
        set -euo pipefail
        info() { :; }
        '"$fn"'
        printf "new\n" | install_config 0640 "$1/app.conf"
        printf "new\n" | install_config 0640 "$1/app.conf"
        printf "fresh\n" | install_config 0600 "$1/other.conf"
    ' _ "$tmp"

    assert_eq "$(cat "$tmp/app.conf")" "new"
    assert_file_mode "$tmp/app.conf" "640"
    assert_eq "$(find "$tmp" -name 'app.conf.bak.*' | wc -l | tr -d ' ')" "1" "one backup for one change, none for the identical re-run"
    assert_eq "$(cat "$tmp"/app.conf.bak.*)" "old" "backup holds the previous content"
    assert_file_mode "$tmp/other.conf" "600"
    assert_eq "$(find "$tmp" -name 'other.conf.bak.*' | wc -l | tr -d ' ')" "0" "no backup for a new file"
    assert_eq "$(find "$tmp" -type f | wc -l | tr -d ' ')" "3" "no temporary files left behind"
}

# -----------------------------------------------------------------------------
# monitoring.sh
# -----------------------------------------------------------------------------

# Run the generated security collector once. checkupdates is a function that
# prints UPDATES_LINES package lines and returns UPDATES_RC (0 = updates,
# 2 = none, 1 = the check failed), logging each call.
run_collector() {
    local tmp="$1"
    STATE_DIRECTORY="$tmp/state" CALLS="$tmp/calls" \
    UPDATES_RC="${UPDATES_RC:-0}" UPDATES_LINES="${UPDATES_LINES:-0}" \
    bash -c '
        checkupdates() {
            printf "checkupdates db=%s\n" "${CHECKUPDATES_DB:-unset}" >> "$CALLS"
            local i
            for (( i = 0; i < UPDATES_LINES; i++ )); do printf "pkg%d 1.0-1 -> 1.1-1\n" "$i"; done
            return "$UPDATES_RC"
        }
        journalctl() { :; }
        fail2ban-client() { return 1; }
        systemctl() { :; }
        source "$1"
    ' _ "$tmp/collector.sh"
}

test_monitoring_collector_never_reports_a_failed_update_check_as_zero() {
    local tmp prom
    tmp="$(mktemp -d)"
    trap 'trap - RETURN EXIT; [[ -n "${tmp:-}" ]] && rm -rf -- "$tmp"' RETURN EXIT
    mkdir -p "$tmp/textfile"
    heredoc_body "$REPO_ROOT/utils/monitoring.sh" 'node-exporter-textfile-security[.]sh <<' \
        | sed "s|^TEXTFILE_DIR=.*|TEXTFILE_DIR=\"$tmp/textfile\"|" > "$tmp/collector.sh"
    grep -q "^TEXTFILE_DIR=\"$tmp/textfile\"$" "$tmp/collector.sh" || fail "collector fixture was not redirected"
    prom="$tmp/textfile/security.prom"

    # 1. First check fails (mirror down): no sample, rather than "0 pending".
    UPDATES_RC=1 run_collector "$tmp"
    assert_not_contains "$(cat "$prom")" "security_packages_upgradable " "failed check exports no update count"
    assert_contains "$(cat "$prom")" "security_systemd_failed_units 0" "other metrics are still written"

    # 2. A successful check is exported with its timestamp, and the sync
    #    database lives in the persistent state directory.
    UPDATES_RC=0 UPDATES_LINES=3 run_collector "$tmp"
    assert_contains "$(cat "$prom")" $'\nsecurity_packages_upgradable 3\n'
    assert_contains "$(cat "$prom")" "security_packages_check_timestamp_seconds "
    assert_contains "$(tail -n1 "$tmp/calls")" "db=$tmp/state/checkup-db"

    # 3. Within the hour the result is reused: no database sync per run.
    : > "$tmp/calls"
    UPDATES_RC=0 UPDATES_LINES=9 run_collector "$tmp"
    assert_eq "$(cat "$tmp/calls")" "" "checkupdates is not run again while the cached result is fresh"
    assert_contains "$(cat "$prom")" $'\nsecurity_packages_upgradable 3\n'

    # 4. Stale cache, "no updates" (exit status 2) is a real zero.
    touch -d '2 hours ago' "$tmp/state/pending-updates"
    UPDATES_RC=2 run_collector "$tmp"
    assert_contains "$(cat "$prom")" $'\nsecurity_packages_upgradable 0\n'

    # 5. Stale cache and a failing check: the last good value and its old
    #    timestamp stay, so staleness is visible instead of a fake fresh 0.
    printf '7\n' > "$tmp/state/pending-updates"
    touch -d '2 hours ago' "$tmp/state/pending-updates"
    local stamp
    stamp="$(stat -c %Y "$tmp/state/pending-updates")"
    UPDATES_RC=1 run_collector "$tmp"
    assert_contains "$(cat "$prom")" $'\nsecurity_packages_upgradable 7\n'
    assert_contains "$(cat "$prom")" "security_packages_check_timestamp_seconds $stamp"
    assert_eq "$(find "$tmp/textfile" -name '.security.prom.*' | wc -l | tr -d ' ')" "0" "no temporary metric files left behind"
}

test_monitoring_refuses_listeners_beyond_loopback() {
    local fn out rc spec addrs expected
    fn="$(extract_shell_function "utils/monitoring.sh" "require_loopback_listener")"

    # addresses printed by ss (one per listener, "|"-separated) -> expected exit status
    for spec in '127.0.0.1:3000=0' '127.0.0.1:3000|[::1]:3000=0' '*:3000=1' '0.0.0.0:3000=1' '127.0.0.1:3000|[::]:3000=1' '=1'; do
        addrs="${spec%=*}"
        expected="${spec##*=}"
        rc=0
        out="$(SS_ADDRS="$addrs" bash -c '
            set -euo pipefail
            err() { echo "ERR $1"; exit 1; }
            warn() { echo "WARN $1"; }
            sleep() { :; }
            ss() {
                local a
                [[ -n "$SS_ADDRS" ]] || return 0
                while IFS= read -r -d "|" a; do
                    printf "LISTEN 0 4096 %s 0.0.0.0:*\n" "$a"
                done <<<"${SS_ADDRS}|"
            }
            '"$fn"'
            require_loopback_listener "Grafana" 3000
        ' 2>&1)" || rc=$?
        assert_eq "$rc" "$expected" "listeners [$addrs]: $out"
    done
}

test_monitoring_matches_the_packaged_units() {
    local code
    code="$(script_code "$REPO_ROOT/utils/monitoring.sh")"

    # Arch's grafana.service starts with --config=/etc/grafana.ini; a config
    # written anywhere else is never read (default: all interfaces, admin/admin).
    assert_contains "$code" 'GRAFANA_INI="/etc/grafana.ini"'
    assert_contains "$code" 'cat > "$GRAFANA_INI" <<'
    assert_contains "$code" 'require_loopback_listener "Grafana" 3000'
    assert_contains "$code" "/api/user/password" "the default admin password is replaced"

    # prometheus.service already passes --config.file and --storage.tsdb.path;
    # repeating them in PROMETHEUS_ARGS makes the daemon exit.
    local prom_args
    prom_args="$(heredoc_body "$REPO_ROOT/utils/monitoring.sh" 'conf[.]d/prometheus <<')"
    assert_contains "$prom_args" "--web.listen-address=127.0.0.1:9090"
    assert_not_contains "$prom_args" "--config.file" "flag already set by the packaged unit"
    assert_not_contains "$prom_args" "--storage.tsdb.path" "flag already set by the packaged unit"

    # node_exporter keeps the packaged ProtectHome=read-only: "yes" would hide
    # /home from the filesystem collector.
    local exporter_dropin
    exporter_dropin="$(heredoc_body "$REPO_ROOT/utils/monitoring.sh" 'prometheus-node-exporter[.]service[.]d/hardening[.]conf <<')"
    assert_contains "$exporter_dropin" "ProtectHome=read-only"
    assert_not_contains "$exporter_dropin" "ProtectHome=yes"
}

# -----------------------------------------------------------------------------
# zram.sh / cpufreq.sh
# -----------------------------------------------------------------------------

test_zram_size_expression_validation() {
    local expr out
    # zram-generator's own documented default must be accepted. Parsing ends at
    # the root check, which the id stub fails on purpose.
    for expr in 'ram / 2' 'min(ram / 2, 4096)' 'min(ram * 0.75, 8192)'; do
        out="$(bash -c 'id() { echo 1000; }; source "$1" --size "$2"' _ "$REPO_ROOT/utils/zram.sh" "$expr" 2>&1 || true)"
        assert_not_contains "$out" "Invalid --size expression" "accepted: $expr"
        assert_contains "$out" "Must be run as root"
    done
    for expr in 'ram; reboot' 'ram / 2 $(id)' $'ram\nfoo = 1' 'ram`id`'; do
        out="$(bash -c 'id() { echo 1000; }; source "$1" --size "$2"' _ "$REPO_ROOT/utils/zram.sh" "$expr" 2>&1 || true)"
        assert_contains "$out" "Invalid --size expression" "rejected: $expr"
    done
}

# Run a copy of zram.sh with /etc and /sys redirected below $1. ZRAM_ACTIVE
# says whether the zram unit already runs.
run_zram() {
    local tmp="$1"
    shift
    sed -e "s|/etc/|$tmp/etc/|g" -e "s|/sys/module/zswap|$tmp/sys/zswap|g" "$REPO_ROOT/utils/zram.sh" > "$tmp/zram.sh"
    CALLS="$tmp/calls" ZRAM_ACTIVE="${ZRAM_ACTIVE:-false}" bash -c '
        id() { echo 0; }
        pacman() { echo "pacman $*" >> "$CALLS"; }
        swapon() { :; }
        systemctl() {
            echo "systemctl $*" >> "$CALLS"
            if [[ "$1" == is-active ]]; then [[ "$ZRAM_ACTIVE" == true ]]; return; fi
            return 0
        }
        source "$1" "${@:2}"
    ' _ "$tmp/zram.sh" "$@"
}

test_zram_resize_restarts_an_active_device() {
    local tmp
    tmp="$(mktemp -d)"
    trap 'trap - RETURN EXIT; [[ -n "${tmp:-}" ]] && rm -rf -- "$tmp"' RETURN EXIT
    mkdir -p "$tmp/etc/systemd"

    run_zram "$tmp" --size 'min(ram / 2, 4096)' >/dev/null 2>&1
    assert_contains "$(cat "$tmp/etc/systemd/zram-generator.conf")" "zram-size = min(ram / 2, 4096)"
    assert_contains "$(cat "$tmp/calls")" "systemctl start systemd-zram-setup@zram0.service"

    # "start" does nothing on a running unit: a new size needs a restart.
    : > "$tmp/calls"
    ZRAM_ACTIVE=true run_zram "$tmp" --size 'ram / 4' >/dev/null 2>&1
    assert_contains "$(cat "$tmp/etc/systemd/zram-generator.conf")" "zram-size = ram / 4"
    assert_contains "$(cat "$tmp/calls")" "systemctl restart systemd-zram-setup@zram0.service"
    assert_not_contains "$(cat "$tmp/calls")" "systemctl start " "an active device is restarted, not started"
}

# Run a copy of cpufreq.sh against a fake cpufreq sysfs directory and unit.
run_cpufreq() {
    local tmp="$1"
    shift
    sed -e "s|/sys/devices/system/cpu/cpu0/cpufreq|$tmp/cpufreq|g" \
        -e "s|/etc/default|$tmp/etc/default|g" \
        -e "s|/usr/lib/systemd/system/cpupower.service|$tmp/cpupower.service|g" \
        "$REPO_ROOT/utils/cpufreq.sh" > "$tmp/cpufreq.sh"
    CALLS="$tmp/calls" bash -c '
        id() { echo 0; }
        pacman() { echo "pacman $*" >> "$CALLS"; }
        cpupower() { echo "cpupower $*" >> "$CALLS"; }
        systemctl() {
            echo "systemctl $*" >> "$CALLS"
            case "$1" in is-active|is-enabled) return 1 ;; esac
            return 0
        }
        source "$1" "${@:2}"
    ' _ "$tmp/cpufreq.sh" "$@"
}

test_cpufreq_installs_cpupower_and_writes_the_file_its_unit_reads() {
    local tmp conf
    tmp="$(mktemp -d)"
    trap 'trap - RETURN EXIT; [[ -n "${tmp:-}" ]] && rm -rf -- "$tmp"' RETURN EXIT
    mkdir -p "$tmp/cpufreq" "$tmp/etc/default"
    printf 'performance powersave schedutil\n' > "$tmp/cpufreq/scaling_available_governors"

    # Current packaging: the unit reads cpupower-service.conf (GOVERNOR=).
    printf '[Service]\nEnvironmentFile=-/etc/default/cpupower-service.conf\n' > "$tmp/cpupower.service"
    conf="$tmp/etc/default/cpupower-service.conf"
    printf "# packaged comment\n#GOVERNOR='ondemand'\nMIN_FREQ='1GHz'\nGOVERNOR='powersave'\n" > "$conf"
    run_cpufreq "$tmp" --governor performance >/dev/null 2>&1

    # The package is called cpupower; "linux-cpupower" does not exist on Arch.
    grep -Eq '^pacman .* cpupower$' "$tmp/calls" || fail "cpupower package not installed: $(cat "$tmp/calls")"
    assert_not_contains "$(cat "$tmp/calls")" "linux-cpupower"
    assert_eq "$(grep -c '^GOVERNOR=' "$conf")" "1" "exactly one active GOVERNOR line"
    assert_contains "$(cat "$conf")" "GOVERNOR='performance'"
    assert_contains "$(cat "$conf")" "MIN_FREQ='1GHz'" "other tuning kept"
    assert_contains "$(cat "$conf")" "# packaged comment" "packaged comments kept"
    assert_file_mode "$conf" "644"
    [[ ! -e "$tmp/etc/default/cpupower" ]] || fail "wrote the legacy file although the unit reads cpupower-service.conf"

    # Re-running does not pile up marker or governor lines.
    run_cpufreq "$tmp" --governor schedutil >/dev/null 2>&1
    assert_eq "$(grep -c '^GOVERNOR=' "$conf")" "1"
    assert_eq "$(grep -c '^# Written by utils/cpufreq.sh$' "$conf")" "1"
    assert_contains "$(cat "$conf")" "GOVERNOR='schedutil'"

    # Older packaging: the unit sources /etc/default/cpupower (governor=).
    printf '[Service]\nEnvironmentFile=/etc/default/cpupower\n' > "$tmp/cpupower.service"
    run_cpufreq "$tmp" --governor powersave >/dev/null 2>&1
    assert_contains "$(cat "$tmp/etc/default/cpupower")" "governor='powersave'"
}

# -----------------------------------------------------------------------------
# audit-check.sh
# -----------------------------------------------------------------------------

# Reporter stubs shared by the audit-check.sh function tests.
AUDIT_PRELUDE='
    set -euo pipefail
    JSON_OUTPUT=false; VERBOSE=true
    CURRENT_CATEGORY=""
    category_header() { CURRENT_CATEGORY="$1"; }
    result_pass() { echo "PASS: $1"; }
    result_fail() { echo "FAIL: $1 (${2:-})"; }
    result_warn() { echo "WARN: $1 (${2:-})"; }
'

test_audit_check_reads_camelcase_sshd_effective_config() {
    local tmp fn out
    tmp="$(mktemp -d)"
    trap 'trap - RETURN EXIT; [[ -n "${tmp:-}" ]] && rm -rf -- "$tmp"' RETURN EXIT
    fn="$(extract_shell_function "utils/audit-check.sh" "check_ssh_hardening")"

    # The file says "insecure", the effective configuration (sshd -T, which
    # current OpenSSH prints with CamelCase keywords) says "hardened", as when
    # a drop-in overrides the main file. The effective values must win.
    printf 'PermitRootLogin yes\nPasswordAuthentication yes\nMaxAuthTries 10\nX11Forwarding yes\n' > "$tmp/sshd_config"
    out="$(bash -c "$AUDIT_PRELUDE"'
        sshd() {
            printf "%s\n" "Port 22" "PermitRootLogin no" "PasswordAuthentication no" "MaxAuthTries 3" \
                "X11Forwarding no" "DisableForwarding yes" "AllowTcpForwarding no" "AllowAgentForwarding no"
        }
        fn_body="$2"
        fn_body="${fn_body//\/etc\/ssh\/sshd_config/$1}"
        eval "$fn_body"
        check_ssh_hardening
    ' _ "$tmp/sshd_config" "$fn")"

    assert_contains "$out" "PASS: PermitRootLogin = no"
    assert_contains "$out" "PASS: PasswordAuthentication = no"
    assert_not_contains "$out" "FAIL:" "effective sshd -T values are used, not the overridden file"
}

test_audit_check_warns_about_complain_mode_sshd_profile() {
    local tmp fn out mode
    tmp="$(mktemp -d)"
    trap 'trap - RETURN EXIT; [[ -n "${tmp:-}" ]] && rm -rf -- "$tmp"' RETURN EXIT
    fn="$(extract_shell_function "utils/audit-check.sh" "check_service_security")"

    for mode in complain enforce; do
        printf 'nginx (enforce)\nsshd (%s)\nsshd//null-/usr/bin/true (complain)\n' "$mode" > "$tmp/profiles"
        out="$(bash -c "$AUDIT_PRELUDE"'
            systemctl() { return 1; }
            fn_body="$2"
            fn_body="${fn_body//\/sys\/kernel\/security\/apparmor\/profiles/$1}"
            eval "$fn_body"
            check_service_security
        ' _ "$tmp/profiles" "$fn")"
        if [[ "$mode" == complain ]]; then
            assert_contains "$out" "WARN: AppArmor sshd profile is in complain mode"
            assert_contains "$out" "apparmor.sh --enforce"
            assert_not_contains "$out" "FAIL: AppArmor sshd" "complain mode is a warning, not a failure"
        else
            assert_not_contains "$out" "sshd profile is in complain mode"
        fi
    done
}

test_audit_check_faillock_needs_the_project_policy() {
    local tmp fn out spec conf expected
    tmp="$(mktemp -d)"
    trap 'trap - RETURN EXIT; [[ -n "${tmp:-}" ]] && rm -rf -- "$tmp"' RETURN EXIT
    fn="$(extract_shell_function "utils/audit-check.sh" "check_authentication")"
    mkdir -p "$tmp/pam.d"
    printf 'auth required pam_faillock.so preauth\n' > "$tmp/pam.d/system-auth"

    # faillock.conf content -> verdict. Stock Arch ships the module with every
    # key commented out (defaults: deny=3, unlock_time=600), which must not pass.
    for spec in \
        '# deny = 3|FAIL' \
        'deny = 5;unlock_time = 900|PASS' \
        'deny = 3;unlock_time = never|PASS' \
        'deny = 10;unlock_time = 900|FAIL' \
        'deny = 5;unlock_time = 60|FAIL' \
        'deny = 0;unlock_time = 900|FAIL'; do
        conf="${spec%%|*}"
        expected="${spec##*|}"
        printf '%s\n' "${conf//;/$'\n'}" > "$tmp/faillock.conf"
        out="$(bash -c "$AUDIT_PRELUDE"'
            fn_body="$2"
            fn_body="${fn_body//\/etc\/security\/faillock.conf/$1/faillock.conf}"
            fn_body="${fn_body//\/etc\/pam.d\//$1/pam.d/}"
            eval "$fn_body"
            check_authentication
        ' _ "$tmp" "$fn" | grep -i 'faillock')"
        assert_eq "${out%%:*}" "$expected" "faillock.conf [$conf] -> $out"
    done

    # Policy present but the module is only mentioned in a comment.
    printf 'deny = 5\nunlock_time = 900\n' > "$tmp/faillock.conf"
    printf '#auth required pam_faillock.so preauth\n' > "$tmp/pam.d/system-auth"
    out="$(bash -c "$AUDIT_PRELUDE"'
        fn_body="$2"
        fn_body="${fn_body//\/etc\/security\/faillock.conf/$1/faillock.conf}"
        fn_body="${fn_body//\/etc\/pam.d\//$1/pam.d/}"
        eval "$fn_body"
        check_authentication
    ' _ "$tmp" "$fn" | grep -i 'faillock')"
    assert_contains "$out" "FAIL: PAM faillock is not configured"
}

test_audit_check_dns_over_tls_uses_the_last_assignment() {
    local fn_dot fn_net out spec merged expected
    fn_dot="$(extract_shell_function "utils/audit-check.sh" "resolved_dnsovertls")"
    fn_net="$(extract_shell_function "utils/audit-check.sh" "check_network_security")"

    # merged resolved.conf as systemd-analyze cat-config prints it (main file,
    # then drop-ins in the order they apply) -> verdict of the DoT check
    for spec in \
        'DNSOverTLS=yes|PASS' \
        'DNSOverTLS=opportunistic|PASS' \
        'DNSOverTLS=yes;# /etc/systemd/resolved.conf.d/90-local.conf;DNSOverTLS=no|FAIL' \
        'DNSOverTLS=no;# /etc/systemd/resolved.conf.d/90-local.conf;DNSOverTLS = yes|PASS' \
        '#DNSOverTLS=yes|FAIL' \
        'DNS=9.9.9.9|FAIL'; do
        merged="${spec%%|*}"
        expected="${spec##*|}"
        out="$(MERGED="${merged//;/$'\n'}" bash -c "$AUDIT_PRELUDE"'
            systemd-analyze() { printf "%s\n" "$MERGED"; }
            systemctl() { [[ "$*" == "is-active --quiet systemd-resolved" ]]; }
            ss() { :; }
            '"$fn_dot"'
            '"$fn_net"'
            check_network_security
        ' | grep 'DNS-over-TLS')"
        assert_eq "${out%%:*}" "$expected" "resolved.conf [$merged] -> $out"
    done
}

# Exit status of is_vps_profile ($3 = its source) when /etc/awesome-install-profile
# and /root/.install-env are $1/install-profile and $1/install-env, on a
# virtual machine ($2 = vm) or on bare metal ($2 = metal).
is_vps_profile_rc() {
    local rc=0
    VIRT="$2" bash -c '
        set -euo pipefail
        systemd-detect-virt() { [[ "$VIRT" == vm ]]; }
        fn_body="$2"
        fn_body="${fn_body//\/etc\/awesome-install-profile/$1/install-profile}"
        fn_body="${fn_body//\/root\/.install-env/$1/install-env}"
        eval "$fn_body"
        is_vps_profile
    ' _ "$1" "$3" || rc=$?
    printf '%s' "$rc"
}

test_audit_check_profile_follows_the_installer_record() {
    local tmp fn spec marker env_content virt expected
    tmp="$(mktemp -d)"
    trap 'trap - RETURN EXIT; [[ -n "${tmp:-}" ]] && rm -rf -- "$tmp"' RETURN EXIT
    fn="$(extract_shell_function "utils/audit-check.sh" "is_vps_profile")"

    # persistent marker | installer environment file | virtualization | VPS profile? (0 = yes)
    # "-" = file absent, ";" = line break
    for spec in \
        'INSTALL_TYPE=baremetal|-|vm|1' \
        'INSTALL_TYPE=vps|-|metal|0' \
        'INSTALL_TYPE=vps-harden|-|metal|0' \
        '# installer record;INSTALL_TYPE="vps-harden"|-|metal|0' \
        'INSTALL_TYPE=baremetal|INSTALL_TYPE=vps|vm|1' \
        'INSTALL_TYPE=vps|INSTALL_TYPE=baremetal|metal|0' \
        'INSTALL_TYPE=desktop|-|vm|0' \
        'INSTALL_TYPE=desktop|-|metal|1' \
        'INSTALL_TYPE=|INSTALL_TYPE=vps|metal|0' \
        'OTHER_INSTALL_TYPE=vps|-|metal|1' \
        '-|INSTALL_TYPE=vps|vm|0' \
        '-|INSTALL_TYPE="vps"|metal|0' \
        '-|HOSTNAME=desk|vm|1' \
        '-|INSTALL_TYPE=desktop|vm|1' \
        '-|-|vm|0' \
        '-|-|metal|1'; do
        IFS='|' read -r marker env_content virt expected <<<"$spec"
        rm -f -- "$tmp/install-profile" "$tmp/install-env"
        [[ "$marker" == "-" ]] || printf '%s\n' "${marker//;/$'\n'}" > "$tmp/install-profile"
        [[ "$env_content" == "-" ]] || printf '%s\n' "$env_content" > "$tmp/install-env"
        assert_eq "$(is_vps_profile_rc "$tmp" "$virt" "$fn")" "$expected" \
            "marker [$marker], install-env [$env_content], $virt"
    done

    # The marker is read as data: nothing in it is expanded or executed.
    rm -f -- "$tmp/install-env"
    printf 'INSTALL_TYPE=vps$(touch %s)\ntouch %s\n' "$tmp/expanded" "$tmp/sourced" > "$tmp/install-profile"
    assert_eq "$(is_vps_profile_rc "$tmp" metal "$fn")" "0" "value that starts with vps"
    [[ ! -e "$tmp/expanded" && ! -e "$tmp/sourced" ]] || fail "content of the install-profile marker was executed"
}

# -----------------------------------------------------------------------------
# aide-config.sh / nano.sh
# -----------------------------------------------------------------------------

test_aide_config_help_log_truncation_and_reinit_backup() {
    local tmp out rc fn
    tmp="$(mktemp -d)"
    trap 'trap - RETURN EXIT; [[ -n "${tmp:-}" ]] && rm -rf -- "$tmp"' RETURN EXIT

    # --help is answered before the root check (safe to run as anyone).
    if [[ "$(id -u)" -ne 0 ]]; then
        rc=0
        out="$(bash "$REPO_ROOT/utils/aide-config.sh" --help 2>&1)" || rc=$?
        assert_eq "$rc" "0" "--help works without root"
        assert_contains "$out" "Usage:"
        rc=0
        out="$(bash "$REPO_ROOT/utils/aide-config.sh" --check 2>&1)" || rc=$?
        assert_ne "$rc" "0" "real modes still need root"
        assert_contains "$out" "must be run as root"
    fi

    # file: writes from offset 0 without truncating, which leaves the tail of
    # a longer, older report under a shorter new one.
    local unit
    unit="$(heredoc_body "$REPO_ROOT/utils/aide-config.sh" 'AIDE_SERVICE[}"]* <<')"
    assert_contains "$unit" 'StandardOutput=truncate:${AIDE_LOG_DIR}/aide-check.log'
    assert_not_contains "$unit" "StandardOutput=file:"

    # Re-running --init keeps the previous reference database.
    fn="$(extract_shell_function "utils/aide-config.sh" "mode_init")"
    printf 'previous baseline' > "$tmp/aide.db"
    AIDE_DB="$tmp/aide.db" AIDE_DB_NEW="$tmp/aide.db.new" bash -c '
        set -euo pipefail
        info() { :; }; warn() { :; }; success() { :; }
        die() { echo "DIE $*" >&2; exit 1; }
        install_aide() { :; }; create_db_dir() { :; }; create_log_dir() { :; }
        write_aide_conf() { :; }; create_systemd_units() { :; }
        systemctl() { :; }
        aide() { printf "new baseline" > "$AIDE_DB_NEW"; }
        '"$fn"'
        mode_init
    ' >/dev/null
    assert_eq "$(cat "$tmp/aide.db")" "new baseline"
    assert_eq "$(find "$tmp" -name 'aide.db.bak.*' | wc -l | tr -d ' ')" "1" "previous database backed up"
    assert_eq "$(cat "$tmp"/aide.db.bak.*)" "previous baseline"
    assert_file_mode "$(find "$tmp" -name 'aide.db.bak.*')" "600"
}

# Function stubs for the desktop helper scripts, which are plain top-level
# scripts: each test sources this file and then the script itself with HOME
# pointing at a scratch directory. Everything that would touch the system or
# the network is recorded in $CALLS instead.
write_user_script_stubs() {
    cat > "$1" <<'STUBS'
id() { if [[ "$*" == "-u" ]]; then echo 1000; else command id "$@"; fi; }
sudo() {
    printf 'SUDO %s\n' "$*" >> "$CALLS"
    if [[ "${1:-}" == "bash" && "${2:-}" == "-c" ]]; then
        # Reviewed AUR install: run the real snippet against a fake library.
        [[ -r "$5" ]] || { echo "aur-review.sh path is not readable: $5" >&2; return 96; }
        bash -c "$3" _ "$FAKE_AUR_LIB" "$6"
        return
    fi
    if [[ "${1:-}" == "bash" && "${2:-}" == "-s" ]]; then
        cat > "$ROOT_STDIN"
        return 0
    fi
    if [[ "${1:-}" == "test" ]]; then return "${SUDO_TEST_RC:-1}"; fi
    return 0
}
pacman() { printf 'PACMAN %s\n' "$*" >> "$CALLS"; return 1; }
chsh() { printf 'CHSH %s\n' "$*" >> "$CALLS"; }
zsh() { :; }
vim() { printf 'VIM %s\n' "$*" >> "$CALLS"; }
nvim() { printf 'NVIM %s\n' "$*" >> "$CALLS"; }
curl() {
    printf 'CURL %s\n' "$*" >> "$CALLS"
    local dest="" prev="" arg
    for arg in "$@"; do
        [[ "$prev" != "-fLo" ]] || dest="$arg"
        prev="$arg"
    done
    printf 'not the pinned plug.vim\n' > "$dest"
}
git() {
    printf 'GIT %s\n' "$*" >> "$CALLS"
    local -a args=("$@")
    local dest="${args[-1]}" i tag=""
    for (( i = 0; i < ${#args[@]}; i++ )); do
        if [[ "${args[i]}" == "--branch" ]]; then tag="${args[i + 1]}"; fi
    done
    case " $* " in
        *" clone "*)
            mkdir -p "$dest/templates"
            printf 'plugins=(git)\nsource $ZSH/oh-my-zsh.sh\n' > "$dest/templates/zshrc.zsh-template"
            printf '%s\n' "$tag" > "$dest/.stub-tag"
            # A stand-in for the upstream installer: records its arguments and
            # creates what "-g DIR" would generate.
            {
                printf '#!/usr/bin/env bash\n'
                printf 'printf "INSTALLER %%s %%s\\n" "${0##*/build}" "$*" >> %q\n' "$CALLS"
                printf 'prev=""; for a in "$@"; do if [[ "$prev" == "-g" ]]; then mkdir -p "$a/vimix"; echo theme > "$a/vimix/theme.txt"; fi; prev="$a"; done\n'
            } > "$dest/install.sh"
            ;;
        *" rev-parse HEAD "*)
            if [[ -n "${GIT_WRONG_HEAD:-}" ]]; then
                echo "1111111111111111111111111111111111111111"
            else
                printf '%s\n' "${STUB_TAG_COMMITS[$(cat "${args[1]}/.stub-tag")]:-0000000000000000000000000000000000000000}"
            fi
            ;;
        *" checkout "*) return "${GIT_CHECKOUT_RC:-0}" ;;
    esac
}
command() {
    if [[ "${1:-}" == "-v" && " ${HIDE_CMDS:-} " == *" ${2:-} "* ]]; then return 1; fi
    builtin command "$@"
}
STUBS
    cat > "${1%/*}/fake-aur-review.sh" <<'FAKELIB'
aal_aur_install_reviewed() { printf 'REVIEWED %s\n' "$*" >> "$CALLS"; return "${FAKE_AUR_RC:-0}"; }
FAKELIB
}

# run_user_script TMP SCRIPT [VAR=value ...]: source utils/SCRIPT with the stubs.
run_user_script() {
    local tmp="$1" script="$2"
    shift 2
    [[ -f "$tmp/stubs.sh" ]] || write_user_script_stubs "$tmp/stubs.sh"
    mkdir -p "$tmp/home"
    env "$@" HOME="$tmp/home" CALLS="$tmp/calls" ROOT_STDIN="$tmp/root-stdin.sh" \
        FAKE_AUR_LIB="$tmp/fake-aur-review.sh" STUBS="$tmp/stubs.sh" \
        bash -c '
            declare -A STUB_TAG_COMMITS=()
            # tag=commit pairs the git stub reports for a clone of that tag
            for pair in ${TAG_COMMITS:-}; do STUB_TAG_COMMITS["${pair%%=*}"]="${pair#*=}"; done
            source "$STUBS"
            source "$1"
        ' _ "$REPO_ROOT/utils/$script"
}

# Value of a NAME="value" assignment at the start of a line in a utils script.
script_var() {
    sed -n "s/^$2=\"\\([^\"]*\\)\".*/\\1/p" "$REPO_ROOT/utils/$1" | head -n1
}

test_nano_keeps_a_differing_nanorc_as_backup() {
    local tmp
    tmp="$(mktemp -d)"
    trap 'trap - RETURN EXIT; [[ -n "${tmp:-}" ]] && rm -rf -- "$tmp"' RETURN EXIT
    mkdir -p "$tmp/home"
    printf 'set mouse\n# my own settings\n' > "$tmp/home/.nanorc"

    run_user_script "$tmp" nano.sh >/dev/null 2>&1
    assert_contains "$(cat "$tmp/home/.nanorc")" "set tabstospaces"
    assert_file_mode "$tmp/home/.nanorc" "600"
    assert_eq "$(find "$tmp/home" -maxdepth 1 -name '.nanorc.bak.*' | wc -l | tr -d ' ')" "1" "hand-written ~/.nanorc backed up"
    assert_contains "$(cat "$tmp/home"/.nanorc.bak.*)" "# my own settings"

    # An identical re-run changes nothing and makes no second backup.
    run_user_script "$tmp" nano.sh >/dev/null 2>&1
    assert_eq "$(find "$tmp/home" -maxdepth 1 -name '.nanorc*' | wc -l | tr -d ' ')" "2" "no extra backup or temp file"
}

# -----------------------------------------------------------------------------
# brave.sh
# -----------------------------------------------------------------------------

test_brave_policy_blocks_third_party_cookies_without_wiping_sessions() {
    local policy
    policy="$(heredoc_body "$REPO_ROOT/utils/brave.sh" 'policy_json="[$][(]cat <<')"
    assert_contains "$policy" '"BlockThirdPartyCookies": true'
    # DefaultCookiesSetting 4 is "session only": every cookie is deleted when
    # the browser closes, which logs the user out of everything on each restart.
    assert_not_contains "$policy" "DefaultCookiesSetting" "no blanket session-only cookie policy"
    # Still one JSON object with no trailing comma before the closing brace.
    assert_eq "$(head -n1 <<<"$policy")" "{"
    assert_eq "$(tail -n1 <<<"$policy")" "}"
    if grep -B1 -x '}' <<<"$policy" | head -n1 | grep -q ',[[:space:]]*$'; then
        fail "managed policy ends with a trailing comma (invalid JSON)"
    fi
}

# -----------------------------------------------------------------------------
# Reviewed AUR installs and pinned third-party code
# -----------------------------------------------------------------------------

test_aur_packages_go_through_the_reviewed_builder() {
    local tmp out rc calls script code
    tmp="$(mktemp -d)"
    trap 'trap - RETURN EXIT; [[ -n "${tmp:-}" ]] && rm -rf -- "$tmp"' RETURN EXIT

    # No utils script may hand an AUR recipe to a helper or to makepkg itself.
    # (gpu-unlock.sh builds a pinned upstream repository, not an AUR recipe.)
    for script in "$REPO_ROOT"/utils/*.sh; do
        [[ "${script##*/}" != "gpu-unlock.sh" ]] || continue
        code="$(script_code "$script")"
        if grep -nE '(^|[^a-zA-Z_/.-])(yay|paru)[[:space:]]+(-S|--sync)|"\$\{?(AUR_HELPER|helper)\}?"[[:space:]]+-S|makepkg[[:space:]]+-' <<<"$code"; then
            fail "${script##*/} builds AUR packages outside hardening/lib/aur-review.sh"
        fi
    done

    # yay.sh: built through aal_aur_install_reviewed; a declined review is an error.
    mkdir -p "$tmp/yay"
    rc=0
    out="$(run_user_script "$tmp/yay" yay.sh HIDE_CMDS="yay" 2>&1)" || rc=$?
    assert_eq "$rc" "0" "accepted review installs yay: $out"
    calls="$(cat "$tmp/yay/calls")"
    assert_contains "$calls" "REVIEWED yay"
    assert_contains "$calls" "hardening/lib/aur-review.sh yay" "the repository's review library is the one sourced"
    rc=0
    : > "$tmp/yay/calls"
    out="$(run_user_script "$tmp/yay" yay.sh HIDE_CMDS="yay" FAKE_AUR_RC=1 2>&1)" || rc=$?
    assert_eq "$rc" "1" "declined review fails yay.sh"
    assert_contains "$out" "yay was not installed"

    # brave.sh and vmware-workstation.sh: same route, by function.
    local fn_find fn_install
    fn_find="$(extract_shell_function "utils/brave.sh" "find_aur_review_lib")"
    fn_install="$(extract_shell_function "utils/brave.sh" "install_brave")"
    mkdir -p "$tmp/brave"
    write_user_script_stubs "$tmp/brave/stubs.sh"
    out="$(cd "$REPO_ROOT/utils" && CALLS="$tmp/brave/calls" FAKE_AUR_LIB="$tmp/brave/fake-aur-review.sh" bash -c '
        set -euo pipefail
        source "$1"
        msg() { :; }; info() { :; }
        err() { echo "ERR $1" >&2; exit 1; }
        sudo_run() { sudo "$@"; }
        sanitize_aur_cache_acls() { :; }
        install_pacman_hook() { :; }
        '"$fn_find"'
        '"$fn_install"'
        install_brave
    ' _ "$tmp/brave/stubs.sh" 2>&1)"
    assert_contains "$(cat "$tmp/brave/calls")" "REVIEWED brave-bin"

    fn_find="$(awk '/^find_aur_review_lib\(\) \{/,/^}/' "$REPO_ROOT/utils/vmware-workstation.sh")"
    fn_install="$(awk '/^install_package\(\) \{/,/^}/' "$REPO_ROOT/utils/vmware-workstation.sh")"
    [[ -n "$fn_find" && -n "$fn_install" ]] || fail "vmware-workstation.sh functions not found"
    mkdir -p "$tmp/vmware"
    write_user_script_stubs "$tmp/vmware/stubs.sh"
    out="$(cd "$REPO_ROOT/utils" && CALLS="$tmp/vmware/calls" FAKE_AUR_LIB="$tmp/vmware/fake-aur-review.sh" bash -c '
        set -euo pipefail
        source "$1"
        log() { :; }; warn() { echo "WARN $*"; }
        die() { echo "DIE $*" >&2; exit 1; }
        sudo_run() { sudo "$@"; }
        REAL_USER=alice; PKG=vmware-workstation; AUR_HELPER=yay
        '"$fn_find"'
        '"$fn_install"'
        install_package
    ' _ "$tmp/vmware/stubs.sh" 2>&1)"
    calls="$(grep '^REVIEWED' "$tmp/vmware/calls")"
    assert_eq "$calls" $'REVIEWED vmware-keymaps\nREVIEWED vmware-workstation' "both VMware recipes are reviewed, keymaps first"
    assert_contains "$out" "AUR_HELPER=yay is ignored" "the old AUR_HELPER interface is accepted but no longer used"
}

test_zsh_installs_pinned_revisions_and_reviewed_theme() {
    local tmp out rc calls omz_commit as_tag as_commit sh_tag sh_commit tags
    tmp="$(mktemp -d)"
    trap 'trap - RETURN EXIT; [[ -n "${tmp:-}" ]] && rm -rf -- "$tmp"' RETURN EXIT

    omz_commit="$(script_var zsh.sh OHMYZSH_COMMIT)"
    as_tag="$(script_var zsh.sh ZSH_AUTOSUGGESTIONS_TAG)"
    as_commit="$(script_var zsh.sh ZSH_AUTOSUGGESTIONS_COMMIT)"
    sh_tag="$(script_var zsh.sh ZSH_SYNTAX_HIGHLIGHTING_TAG)"
    sh_commit="$(script_var zsh.sh ZSH_SYNTAX_HIGHLIGHTING_COMMIT)"
    local value
    for value in "$omz_commit" "$as_commit" "$sh_commit"; do
        [[ "$value" =~ ^[0-9a-f]{40}$ ]] || fail "zsh.sh pin is not a full commit hash: '$value'"
    done
    tags="$as_tag=$as_commit $sh_tag=$sh_commit"

    # 1. Fresh home: pinned checkouts, both AUR recipes through the review.
    mkdir -p "$tmp/a"
    run_user_script "$tmp/a" zsh.sh TAG_COMMITS="$tags" >/dev/null 2>&1
    calls="$(cat "$tmp/a/calls")"
    assert_contains "$calls" "checkout -q -B master $omz_commit" "Oh My Zsh checked out at the pinned commit"
    assert_contains "$calls" "clone --depth=1 --branch $as_tag -- https://github.com/zsh-users/zsh-autosuggestions.git"
    assert_contains "$calls" "clone --depth=1 --branch $sh_tag -- https://github.com/zsh-users/zsh-syntax-highlighting.git"
    assert_contains "$calls" "REVIEWED ttf-meslo-nerd-font-powerlevel10k"
    assert_contains "$calls" "REVIEWED zsh-theme-powerlevel10k-git"
    assert_contains "$(cat "$tmp/a/home/.zshrc")" "plugins=(git zsh-autosuggestions zsh-syntax-highlighting)"
    assert_contains "$(cat "$tmp/a/home/.zshrc")" "umask 027"

    # 2. A tag that no longer points at the pinned commit is not installed.
    mkdir -p "$tmp/b"
    rc=0
    out="$(run_user_script "$tmp/b" zsh.sh TAG_COMMITS="$tags" GIT_WRONG_HEAD=1 2>&1)" || rc=$?
    assert_eq "$rc" "1" "moved tag aborts zsh.sh"
    assert_contains "$out" "expected $as_commit"
    [[ ! -e "$tmp/b/home/.oh-my-zsh/custom/plugins/zsh-autosuggestions" ]] || fail "unverified plugin checkout left where the shell would load it"

    # 3. Declining the optional theme does not abort the shell hardening.
    mkdir -p "$tmp/c"
    rc=0
    out="$(run_user_script "$tmp/c" zsh.sh TAG_COMMITS="$tags" FAKE_AUR_RC=1 2>&1)" || rc=$?
    assert_eq "$rc" "0" "declined theme review is not fatal"
    assert_contains "$out" "zsh-theme-powerlevel10k-git was not installed"
    assert_contains "$(cat "$tmp/c/home/.zshrc")" "setopt HIST_IGNORE_SPACE HIST_IGNORE_ALL_DUPS"
}

test_theme_runs_pinned_installers_and_keeps_them_unprivileged() {
    local tmp out rc calls ws_tag ws_commit g2_tag g2_commit tags
    tmp="$(mktemp -d)"
    trap 'trap - RETURN EXIT; [[ -n "${tmp:-}" ]] && rm -rf -- "$tmp"' RETURN EXIT

    ws_tag="$(script_var theme.sh WHITESUR_TAG)"
    ws_commit="$(script_var theme.sh WHITESUR_COMMIT)"
    g2_tag="$(script_var theme.sh GRUB_THEMES_TAG)"
    g2_commit="$(script_var theme.sh GRUB_THEMES_COMMIT)"
    [[ "$ws_commit" =~ ^[0-9a-f]{40}$ && "$g2_commit" =~ ^[0-9a-f]{40}$ ]] || fail "theme.sh pins are not full commit hashes"
    tags="$ws_tag=$ws_commit $g2_tag=$g2_commit"

    mkdir -p "$tmp/a"
    run_user_script "$tmp/a" theme.sh TAG_COMMITS="$tags" SUDO_TEST_RC=0 >/dev/null 2>&1
    calls="$(cat "$tmp/a/calls")"
    assert_contains "$calls" "clone --depth=1 --branch $ws_tag -- https://github.com/vinceliuice/WhiteSur-gtk-theme.git"
    assert_contains "$calls" "clone --depth=1 --branch $g2_tag -- https://github.com/vinceliuice/grub2-themes.git"
    # Options as the pinned WhiteSur release parses them: --shell with the
    # sub-option "-i ICON" (--gnomeshell and -icon are rejected and abort it).
    assert_contains "$calls" "/WhiteSur-gtk-theme/install.sh --color dark --theme blue --shell -i arch --roundedmaxwindow"
    # grub2-themes only generates the theme (-g DIR) as the user ...
    grep -Eq 'INSTALLER [^ ]*/grub2-themes/install.sh -t vimix -s ultrawide -i whitesur -g [^ ]+/grub-theme$' <<<"$calls" || \
        fail "grub2-themes was not run in generate mode: $calls"
    # ... and no third-party installer is started through sudo.
    if grep -E '^SUDO .*install\.sh' <<<"$calls"; then
        fail "an upstream installer was run as root"
    fi
    assert_contains "$calls" "SUDO bash -s -- "
    # The root part is this repository's own snippet; it must at least parse.
    bash -n "$tmp/a/root-stdin.sh" || fail "root snippet of theme.sh has a syntax error"
    assert_contains "$(cat "$tmp/a/root-stdin.sh")" 'set_grub_var GRUB_THEME'
    assert_contains "$(cat "$tmp/a/root-stdin.sh")" 'grub-mkconfig -o /boot/grub/grub.cfg'
    assert_eq "$(find "$tmp/a/home/.cache" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')" "0" "build directory removed"

    # A tag that moved upstream is refused before its installer runs.
    mkdir -p "$tmp/b"
    rc=0
    out="$(run_user_script "$tmp/b" theme.sh TAG_COMMITS="$tags" SUDO_TEST_RC=0 GIT_WRONG_HEAD=1 2>&1)" || rc=$?
    assert_eq "$rc" "1"
    assert_contains "$out" "Refusing to run it"
    assert_not_contains "$(cat "$tmp/b/calls")" "INSTALLER" "installer of an unverified checkout never runs"
}

test_theme_root_snippet_installs_theme_and_edits_grub_default() {
    local tmp
    tmp="$(mktemp -d)"
    trap 'trap - RETURN EXIT; [[ -n "${tmp:-}" ]] && rm -rf -- "$tmp"' RETURN EXIT

    mkdir -p "$tmp/boot/grub" "$tmp/etc/default" "$tmp/gen/vimix/icons"
    printf 'theme\n' > "$tmp/gen/vimix/theme.txt"
    printf 'x' > "$tmp/gen/vimix/icons/a.png"
    chmod 600 "$tmp/gen/vimix/theme.txt"
    chmod 700 "$tmp/gen/vimix/icons"
    printf '%s\n' 'GRUB_TIMEOUT=5' 'GRUB_GFXMODE=1024x768,auto' 'GRUB_TERMINAL_INPUT=console' \
        'GRUB_TERMINAL_OUTPUT="console"' '#GRUB_THEME="/path/to/gfxtheme"' > "$tmp/etc/default/grub"

    {
        printf 'grub-mkconfig() { echo "grub-mkconfig $*" >> %q; : > "$2"; }\n' "$tmp/calls"
        heredoc_body "$REPO_ROOT/utils/theme.sh" "<<'ROOT_EOF'" \
            | sed -e "s|/boot/grub|$tmp/boot/grub|g" -e "s|/etc/default/grub|$tmp/etc/default/grub|g"
    } > "$tmp/root.sh"

    bash "$tmp/root.sh" "$tmp/gen/vimix" vimix
    bash "$tmp/root.sh" "$tmp/gen/vimix" vimix

    local grub
    grub="$(cat "$tmp/etc/default/grub")"
    assert_eq "$(grep -c '^GRUB_THEME=' <<<"$grub")" "1" "one active GRUB_THEME after two runs"
    assert_contains "$grub" "GRUB_THEME=\"$tmp/boot/grub/themes/vimix/theme.txt\""
    assert_contains "$grub" "GRUB_GFXMODE=2560x1080,auto"
    assert_contains "$grub" '#GRUB_TERMINAL_OUTPUT="console"' "text-only terminal output disabled"
    assert_contains "$grub" "GRUB_TERMINAL_INPUT=console" "terminal input left alone"
    # Installed copy does not inherit the build directory's private modes.
    assert_file_mode "$tmp/boot/grub/themes/vimix/theme.txt" "644"
    assert_file_mode "$tmp/boot/grub/themes/vimix/icons" "755"
    assert_contains "$(cat "$tmp/calls")" "grub-mkconfig -o $tmp/boot/grub/grub.cfg"
    [[ -n "$(find "$tmp/etc/default" -name 'grub.bak.*')" ]] || fail "/etc/default/grub was not backed up"

    # Unexpected arguments are refused before anything is removed or copied.
    local rc=0
    bash "$tmp/root.sh" "$tmp/gen" "../x" >/dev/null 2>&1 || rc=$?
    assert_eq "$rc" "1" "theme name with a slash is refused"
}

test_editors_use_pinned_plugins_and_respect_init_lua() {
    local tmp out rc commit sha
    tmp="$(mktemp -d)"
    trap 'trap - RETURN EXIT; [[ -n "${tmp:-}" ]] && rm -rf -- "$tmp"' RETURN EXIT

    local script
    for script in vim.sh neovim.sh; do
        commit="$(script_var "$script" PLUG_VIM_COMMIT)"
        sha="$(script_var "$script" PLUG_VIM_SHA256)"
        [[ "$commit" =~ ^[0-9a-f]{40}$ && "$sha" =~ ^[0-9a-f]{64}$ ]] || fail "$script: vim-plug is not pinned by commit and SHA-256"
    done

    # 1. A download that is not the pinned plug.vim is refused and removed.
    #    (The curl stub always delivers different content.)
    mkdir -p "$tmp/vim"
    rc=0
    out="$(run_user_script "$tmp/vim" vim.sh 2>&1)" || rc=$?
    assert_eq "$rc" "1" "vim.sh stops on a checksum mismatch"
    assert_contains "$out" "does not match the pinned SHA-256"
    assert_contains "$(cat "$tmp/vim/calls")" "https://raw.githubusercontent.com/junegunn/vim-plug/$(script_var vim.sh PLUG_VIM_COMMIT)/plug.vim"
    assert_eq "$(find "$tmp/vim/home/.vim/autoload" -type f | wc -l | tr -d ' ')" "0" "nothing left in autoload/"

    mkdir -p "$tmp/nvim"
    rc=0
    out="$(run_user_script "$tmp/nvim" neovim.sh 2>&1)" || rc=$?
    assert_eq "$rc" "1" "neovim.sh stops on a checksum mismatch"
    assert_eq "$(find "$tmp/nvim/home/.local/share/nvim/site/autoload" -type f | wc -l | tr -d ' ')" "0"

    # 2. With vim-plug already in place, the plugin lists are pinned to commits.
    mkdir -p "$tmp/vim2/home/.vim/autoload"
    : > "$tmp/vim2/home/.vim/autoload/plug.vim"
    run_user_script "$tmp/vim2" vim.sh >/dev/null 2>&1
    local plug_lines
    plug_lines="$(grep "^Plug " "$tmp/vim2/home/.vimrc")"
    [[ -n "$plug_lines" ]] || fail "vim.sh wrote no Plug lines"
    if grep -vE "^Plug '[^']+', \{ 'commit': '[0-9a-f]{40}' \}$" <<<"$plug_lines"; then
        fail "vim.sh has a plugin that is not pinned to a commit"
    fi
    assert_contains "$(cat "$tmp/vim2/home/.vimrc")" "set nomodeline"

    mkdir -p "$tmp/nvim2/home/.local/share/nvim/site/autoload"
    : > "$tmp/nvim2/home/.local/share/nvim/site/autoload/plug.vim"
    run_user_script "$tmp/nvim2" neovim.sh >/dev/null 2>&1
    grep -Eq "^Plug 'nvim-treesitter/nvim-treesitter', \{'branch': 'master', 'commit': '[0-9a-f]{40}', 'do': ':TSUpdate'\}$" \
        "$tmp/nvim2/home/.config/nvim/plugins.vim" || fail "nvim-treesitter is not pinned: $(cat "$tmp/nvim2/home/.config/nvim/plugins.vim")"
    assert_contains "$(cat "$tmp/nvim2/home/.config/nvim/init.vim")" "set nomodeline"

    # 3. An existing init.lua: no init.vim next to it (Neovim would stop with
    #    E5422 and load neither), the hardening goes into a Lua plugin file.
    mkdir -p "$tmp/nvim3/home/.config/nvim"
    printf 'vim.o.modeline = true\n' > "$tmp/nvim3/home/.config/nvim/init.lua"
    out="$(run_user_script "$tmp/nvim3" neovim.sh 2>&1)"
    [[ ! -e "$tmp/nvim3/home/.config/nvim/init.vim" ]] || fail "init.vim created next to init.lua"
    assert_contains "$(cat "$tmp/nvim3/home/.config/nvim/plugin/00-awesome-hardening.lua")" "vim.o.modeline = false"
    assert_eq "$(cat "$tmp/nvim3/home/.config/nvim/init.lua")" "vim.o.modeline = true" "the user's init.lua is not edited"
    assert_not_contains "$(cat "$tmp/nvim3/calls" 2>/dev/null || true)" "NVIM" "no plugin installation is attempted"
    assert_contains "$out" "NeoVim modeline hardening installed"
}

run_test "docker.sh: daemon.json, unit drop-in and registries.conf are ones the daemons accept" test_docker_generated_configs_match_what_the_daemons_accept
run_test "docker.sh: install_config backs up a changed file and leaves no temp files" test_docker_install_config_backs_up_changed_files
run_test "monitoring.sh: collector never exports a failed update check as zero and caches the sync" test_monitoring_collector_never_reports_a_failed_update_check_as_zero
run_test "monitoring.sh: a listener beyond loopback is an error" test_monitoring_refuses_listeners_beyond_loopback
run_test "monitoring.sh: Grafana/Prometheus/node_exporter settings match the packaged units" test_monitoring_matches_the_packaged_units
run_test "zram.sh: --size accepts zram-generator expressions and rejects injection" test_zram_size_expression_validation
run_test "zram.sh: a new size restarts an already active zram device" test_zram_resize_restarts_an_active_device
run_test "cpufreq.sh: installs cpupower and writes the file its unit reads" test_cpufreq_installs_cpupower_and_writes_the_file_its_unit_reads
run_test "audit-check.sh: CamelCase sshd -T output is used as the effective SSH config" test_audit_check_reads_camelcase_sshd_effective_config
run_test "audit-check.sh: sshd AppArmor profile in complain mode is a warning" test_audit_check_warns_about_complain_mode_sshd_profile
run_test "audit-check.sh: faillock passes only with the project's lockout policy" test_audit_check_faillock_needs_the_project_policy
run_test "audit-check.sh: DNS-over-TLS verdict follows the last DNSOverTLS= assignment" test_audit_check_dns_over_tls_uses_the_last_assignment
run_test "audit-check.sh: profile follows the install-profile marker, then the installer record" test_audit_check_profile_follows_the_installer_record
run_test "aide-config.sh: --help without root, truncated log, --init keeps the old database" test_aide_config_help_log_truncation_and_reinit_backup
run_test "nano.sh: a differing ~/.nanorc is kept as a backup" test_nano_keeps_a_differing_nanorc_as_backup
run_test "brave.sh: managed policy blocks third-party cookies without session-only cookies" test_brave_policy_blocks_third_party_cookies_without_wiping_sessions
run_test "AUR packages (yay, brave-bin, vmware, aide) go through the reviewed builder" test_aur_packages_go_through_the_reviewed_builder
run_test "zsh.sh: pinned Oh My Zsh/plugins, moved tag refused, reviewed optional theme" test_zsh_installs_pinned_revisions_and_reviewed_theme
run_test "theme.sh: pinned installers, valid options, no upstream installer as root" test_theme_runs_pinned_installers_and_keeps_them_unprivileged
run_test "theme.sh: root snippet installs the generated theme and edits /etc/default/grub" test_theme_root_snippet_installs_theme_and_edits_grub_default
run_test "vim.sh/neovim.sh: checksum-pinned vim-plug, commit-pinned plugins, init.lua respected" test_editors_use_pinned_plugins_and_respect_init_lua

finish_test_file "test_utils_regressions.sh"
