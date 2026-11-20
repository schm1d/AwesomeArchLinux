#!/usr/bin/env bash

# =============================================================================
# Script:      monitoring.sh
# Description: Prometheus node_exporter + optional Prometheus & Grafana stack
#              for Arch Linux with systemd hardening and security collectors.
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
#
# Usage:       sudo ./monitoring.sh [--with-prometheus] [--with-grafana]
#                                    [--port PORT] [-h]
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

PORT=9100
WITH_PROMETHEUS=false
WITH_GRAFANA=false
TEXTFILE_DIR="/var/lib/node_exporter/textfile_collector"
# Used by earlier versions of this script. It sits inside Prometheus' private
# state directory (0750 prometheus:prometheus as packaged), which the
# node_exporter user cannot enter.
OLD_TEXTFILE_DIR="/var/lib/prometheus/node-exporter"

resolve_hostname() {
    if [[ -n "${HOSTNAME:-}" ]]; then
        printf '%s' "$HOSTNAME"
    elif [[ -r /etc/hostname ]]; then
        tr -d '[:space:]' < /etc/hostname
    else
        uname -n
    fi
}

usage() {
    cat <<EOF
Usage: sudo $0 [options]

Options:
  --with-prometheus   Install and configure Prometheus server
  --with-grafana      Install and configure Grafana with Prometheus datasource
  --port PORT         node_exporter listen port (default: $PORT)
  -h, --help          Show this help
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --with-prometheus) WITH_PROMETHEUS=true; shift ;;
        --with-grafana)    WITH_GRAFANA=true; shift ;;
        --port)
            [[ $# -ge 2 && -n "${2:-}" ]] || err "--port requires a port number"
            PORT="$2"
            shift 2
            ;;
        -h|--help)         usage ;;
        *)                 err "Unknown option: $1" ;;
    esac
done

[[ $(id -u) -eq 0 ]] || err "Must be run as root"

if ! [[ "$PORT" =~ ^[0-9]+$ ]] || (( 10#$PORT < 1 || 10#$PORT > 65535 )); then
    err "Invalid port: $PORT (must be 1-65535)"
fi
PORT=$(( 10#$PORT ))
HOST_LABEL="$(resolve_hostname)"

# Type=simple services report "started" before a rejected flag or config makes
# them exit, and "enable --now" leaves an already running service on its old
# settings. Restart, then confirm the unit stays up.
restart_and_verify() {
    local unit="$1"
    systemctl enable "$unit"
    systemctl restart "$unit"
    sleep 2
    systemctl is-active --quiet "$unit" || \
        err "$unit did not stay up. Check: journalctl -u $unit -n 50 --no-pager"
}

# Abort unless every listener on PORT is bound to loopback.
require_loopback_listener() {
    local label="$1" port="$2" addrs=""
    if ! command -v ss >/dev/null 2>&1; then
        warn "ss (iproute2) not found; cannot verify that $label is loopback-only"
        return 0
    fi
    for _ in {1..45}; do
        addrs="$(ss -H -ltn "sport = :${port}" 2>/dev/null | awk '{ print $4 }')"
        [[ -z "$addrs" ]] || break
        sleep 2
    done
    [[ -n "$addrs" ]] || err "$label is not listening on port ${port}"
    if grep -qvE '^(127\.0\.0\.1|\[::1\]):[0-9]+$' <<<"$addrs"; then
        err "$label (port ${port}) is reachable beyond loopback: $(tr '\n' ' ' <<<"$addrs")"
    fi
}

info "node_exporter port: $PORT"
info "Prometheus server:  $WITH_PROMETHEUS"
info "Grafana:            $WITH_GRAFANA"

# =============================================================================
# 1. NODE_EXPORTER (always installed)
# =============================================================================

msg "Installing prometheus-node-exporter..."
pacman -Syu --noconfirm --needed prometheus-node-exporter

msg "Configuring node_exporter..."
install -d -m 0755 /etc/conf.d
cat > /etc/conf.d/prometheus-node-exporter <<EOF
# Managed by monitoring.sh — do not edit manually
NODE_EXPORTER_ARGS="\\
  --web.listen-address=127.0.0.1:${PORT} \\
  --collector.systemd \\
  --collector.textfile \\
  --collector.textfile.directory=${TEXTFILE_DIR} \\
  --collector.filesystem \\
  --collector.cpu \\
  --collector.meminfo \\
  --collector.netdev \\
  --collector.diskstats \\
  --collector.loadavg \\
  --collector.processes \\
  --no-collector.wifi \\
  --no-collector.infiniband \\
  --no-collector.fibrechannel \\
  --no-collector.nfs \\
  --no-collector.btrfs"
EOF
chmod 0644 /etc/conf.d/prometheus-node-exporter

msg "Creating textfile collector directory..."
# Root-owned and world-readable: the root collector writes the metrics, the
# packaged unit's node_exporter user only reads them.
install -d -m 0755 -o root -g root /var/lib/node_exporter "$TEXTFILE_DIR"
if [[ -d "$OLD_TEXTFILE_DIR" && ! -L "$OLD_TEXTFILE_DIR" ]]; then
    rm -f -- "$OLD_TEXTFILE_DIR/security.prom"
    rmdir -- "$OLD_TEXTFILE_DIR" 2>/dev/null || \
        warn "$OLD_TEXTFILE_DIR is no longer used but is not empty; left in place"
    info "Textfile collector directory is now $TEXTFILE_DIR"
fi

msg "Applying systemd hardening for node_exporter..."
install -d -m 0755 /etc/systemd/system/prometheus-node-exporter.service.d
# ProtectHome stays read-only as packaged: "yes" hides /home behind an empty
# tmpfs and the filesystem collector then reports wrong numbers for it.
# node_exporter writes nothing, so no ReadWritePaths= (a listed path that does
# not exist would also stop the unit with 226/NAMESPACE).
cat > /etc/systemd/system/prometheus-node-exporter.service.d/hardening.conf <<EOF
[Service]
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
NoNewPrivileges=yes
CapabilityBoundingSet=
EOF
chmod 0644 /etc/systemd/system/prometheus-node-exporter.service.d/hardening.conf

systemctl daemon-reload
restart_and_verify prometheus-node-exporter
require_loopback_listener "node_exporter" "$PORT"
msg "node_exporter enabled and started on 127.0.0.1:${PORT}"

# =============================================================================
# 2. PROMETHEUS SERVER (optional)
# =============================================================================

if [[ "$WITH_PROMETHEUS" == true ]]; then
    msg "Installing Prometheus server..."
    pacman -S --noconfirm --needed prometheus

    msg "Configuring Prometheus..."
    install -d -m 0755 /etc/prometheus
    cat > /etc/prometheus/prometheus.yml <<EOF
# Managed by monitoring.sh — do not edit manually
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: "node"
    static_configs:
      - targets:
          - "127.0.0.1:${PORT}"
        labels:
          instance: "${HOST_LABEL}"
EOF
    chmod 0644 /etc/prometheus/prometheus.yml

    # The packaged unit already passes --config.file=/etc/prometheus/prometheus.yml
    # and --storage.tsdb.path=/var/lib/prometheus/data; Prometheus refuses to
    # start when a flag is given twice, so only add what the unit does not set.
    cat > /etc/conf.d/prometheus <<EOF
# Managed by monitoring.sh — do not edit manually
PROMETHEUS_ARGS="\\
  --web.listen-address=127.0.0.1:9090 \\
  --storage.tsdb.retention.time=30d"
EOF
    chmod 0644 /etc/conf.d/prometheus

    # The package ships /var/lib/prometheus as 0750 prometheus:prometheus. Earlier
    # versions of this script pre-created it as root:root, which pacman keeps
    # and which stops Prometheus from creating its data directory.
    install -d -m 0750 -o prometheus -g prometheus /var/lib/prometheus

    install -d -m 0755 /etc/systemd/system/prometheus.service.d
    cat > /etc/systemd/system/prometheus.service.d/hardening.conf <<EOF
[Service]
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
ReadWritePaths=/var/lib/prometheus
CapabilityBoundingSet=
EOF
    chmod 0644 /etc/systemd/system/prometheus.service.d/hardening.conf

    systemctl daemon-reload
    restart_and_verify prometheus
    require_loopback_listener "Prometheus" 9090
    msg "Prometheus enabled and started on 127.0.0.1:9090"
fi

# =============================================================================
# 3. GRAFANA (optional)
# =============================================================================

if [[ "$WITH_GRAFANA" == true ]]; then
    msg "Installing Grafana..."
    pacman -S --noconfirm --needed grafana

    msg "Configuring Grafana..."
    # Arch's grafana.service runs "grafana server --config=/etc/grafana.ini";
    # nothing reads /etc/grafana/grafana.ini, where earlier versions of this
    # script wrote (leaving Grafana on its defaults: all interfaces, admin/admin).
    GRAFANA_INI="/etc/grafana.ini"
    GRAFANA_PROVISIONING="/etc/grafana/provisioning"
    GRAFANA_URL="http://127.0.0.1:3000"
    GRAFANA_PW_FILE="/root/.grafana-admin-password"
    if [[ -f "$GRAFANA_INI" && ! -f "${GRAFANA_INI}.orig" ]]; then
        cp -p "$GRAFANA_INI" "${GRAFANA_INI}.orig"
        info "Original grafana.ini backed up to ${GRAFANA_INI}.orig"
    fi
    if grep -qs '^# Managed by monitoring.sh' /etc/grafana/grafana.ini; then
        rm -f -- /etc/grafana/grafana.ini
    fi

    # Note: Grafana listens on loopback HTTP (127.0.0.1:3000); setting
    # cookie_secure = true over plain HTTP causes browsers to drop session
    # cookies and loop on login. Flip cookie_secure = true when fronting
    # Grafana with an HTTPS reverse proxy (e.g., hardening/nginx/nginx.sh).
    cat > "$GRAFANA_INI" <<'GRAFANA_EOF'
# Managed by monitoring.sh — do not edit manually

[paths]
# Root-owned provisioning tree (the packaged default is /var/lib/grafana/conf/provisioning).
provisioning = /etc/grafana/provisioning

[server]
http_addr = 127.0.0.1
http_port = 3000
domain = localhost
root_url = %(protocol)s://%(domain)s:%(http_port)s/

[security]
disable_gravatar = true
cookie_secure = false
cookie_samesite = strict
content_security_policy = true

[analytics]
reporting_enabled = false
check_for_updates = false
check_for_plugin_updates = false

[log]
mode = syslog
level = warn
GRAFANA_EOF
    chown root:grafana "$GRAFANA_INI"
    chmod 0640 "$GRAFANA_INI"

    install -d -m 0750 "$GRAFANA_PROVISIONING" \
        "$GRAFANA_PROVISIONING"/{datasources,dashboards,plugins,alerting}
    chown -R root:grafana "$GRAFANA_PROVISIONING"
    cat > "$GRAFANA_PROVISIONING/datasources/prometheus.yml" <<EOF
# Managed by monitoring.sh — do not edit manually
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://127.0.0.1:9090
    isDefault: true
    editable: false
    jsonData:
      timeInterval: "15s"
EOF
    chown root:grafana "$GRAFANA_PROVISIONING/datasources/prometheus.yml"
    chmod 0640 "$GRAFANA_PROVISIONING/datasources/prometheus.yml"

    systemctl daemon-reload
    restart_and_verify grafana
    require_loopback_listener "Grafana" 3000
    msg "Grafana enabled and started on 127.0.0.1:3000"

    # A new Grafana database starts with the well-known admin/admin login, and
    # installs made by earlier versions of this script still have it. Replace
    # exactly that password; one the operator already changed is left alone.
    grafana_ready=false
    for _ in {1..45}; do
        if curl -fsS -o /dev/null --max-time 3 "${GRAFANA_URL}/api/health" 2>/dev/null; then
            grafana_ready=true
            break
        fi
        sleep 2
    done
    [[ "$grafana_ready" == true ]] || \
        err "Grafana does not answer on ${GRAFANA_URL}; its admin password could not be checked."

    if curl -fsS -o /dev/null --max-time 5 -u admin:admin "${GRAFANA_URL}/api/user" 2>/dev/null; then
        grafana_pw="$(head -c 24 /dev/urandom | base64 -w 0 | tr '+/' '-_')"
        grafana_pw_tmp="$(mktemp "${GRAFANA_PW_FILE}.XXXXXX")"
        printf '%s\n' "$grafana_pw" > "$grafana_pw_tmp"
        # The new password travels on stdin, never in a process argument list.
        if printf '{"oldPassword":"admin","newPassword":"%s"}' "$grafana_pw" | \
            curl -fsS -o /dev/null --max-time 10 -X PUT -u admin:admin \
                -H 'Content-Type: application/json' --data-binary @- \
                "${GRAFANA_URL}/api/user/password"; then
            mv -f -- "$grafana_pw_tmp" "$GRAFANA_PW_FILE"
        else
            err "Could not replace Grafana's default admin password (candidate kept in $grafana_pw_tmp)."
        fi
        if curl -fsS -o /dev/null --max-time 5 -u admin:admin "${GRAFANA_URL}/api/user" 2>/dev/null; then
            err "Grafana still accepts admin/admin after the password change."
        fi
        msg "Default Grafana admin password replaced; the new one is in $GRAFANA_PW_FILE (root only)"
    else
        info "Grafana does not accept the default admin/admin login; admin password left unchanged"
    fi
fi

# =============================================================================
# 4. NFTABLES RULES SNIPPET
# =============================================================================

msg "Creating nftables rules snippet for monitoring ports..."
install -d -m 0755 /etc/nftables.d
cat > /etc/nftables.d/monitoring.conf <<EOF
# Managed by monitoring.sh — nftables rules for monitoring services
# By default, all services listen on 127.0.0.1 only.
# ip saddr 10.0.0.0/24 tcp dport { ${PORT}, 9090, 3000 } accept comment "monitoring stack"
EOF
chmod 0644 /etc/nftables.d/monitoring.conf

# =============================================================================
# 5. SECURITY TEXTFILE COLLECTOR
# =============================================================================

msg "Creating security textfile collector script..."
install -d -m 0755 /usr/local/bin
cat > /usr/local/bin/node-exporter-textfile-security.sh <<'COLLECTOR_EOF'
#!/usr/bin/env bash
# =============================================================================
# Security metrics collector for Prometheus node_exporter textfile directory.
# Managed by monitoring.sh — do not edit manually
# =============================================================================

set -euo pipefail
umask 022

TEXTFILE_DIR="/var/lib/node_exporter/textfile_collector"
OUTFILE="${TEXTFILE_DIR}/security.prom"
# systemd sets STATE_DIRECTORY (StateDirectory=); the fallback covers manual runs.
STATE_DIR="${STATE_DIRECTORY:-/var/lib/node-exporter-security}"
UPDATES_CACHE="${STATE_DIR}/pending-updates"
UPDATES_MAX_AGE=3600
mkdir -p "$STATE_DIR"
TMPFILE="$(mktemp "${TEXTFILE_DIR}/.security.prom.XXXXXX")"
trap 'rm -f -- "$TMPFILE"' EXIT

# --- Pending package updates ---
# checkupdates syncs a private copy of the pacman databases. That copy lives in
# the state directory (the unit's /tmp is discarded after every run) and is
# refreshed at most once an hour instead of on each 5-minute collection.
# Exit status: 0 = updates listed, 2 = none pending, 1 = the check failed. A
# failed check keeps the previous result and is retried on the next run; it is
# never reported as "0 pending updates".
if command -v checkupdates &>/dev/null; then
    export CHECKUPDATES_DB="${STATE_DIR}/checkup-db"
    cache_age=$(( $(date +%s) - $(stat -c %Y "$UPDATES_CACHE" 2>/dev/null || echo 0) ))
    if (( cache_age >= UPDATES_MAX_AGE )); then
        updates_rc=0
        updates_out="$(checkupdates 2>/dev/null)" || updates_rc=$?
        updates_count=""
        if (( updates_rc == 0 )) && [[ -n "$updates_out" ]]; then
            updates_count="$(awk 'END { print NR }' <<<"$updates_out")"
        elif (( updates_rc == 2 )); then
            updates_count=0
        fi
        if [[ -n "$updates_count" ]]; then
            printf '%s\n' "$updates_count" > "${UPDATES_CACHE}.tmp"
            mv -f "${UPDATES_CACHE}.tmp" "$UPDATES_CACHE"
        fi
    fi
fi
PENDING_UPDATES=""
UPDATES_CHECKED_AT=""
if [[ -s "$UPDATES_CACHE" ]]; then
    read -r PENDING_UPDATES < "$UPDATES_CACHE" || true
    [[ "$PENDING_UPDATES" =~ ^[0-9]+$ ]] || PENDING_UPDATES=""
    UPDATES_CHECKED_AT="$(stat -c %Y "$UPDATES_CACHE")"
fi

# --- Failed SSH logins in the last hour ---
FAILED_SSH=0
if command -v journalctl &>/dev/null; then
    FAILED_SSH="$(journalctl --no-pager -u sshd.service --since "1 hour ago" 2>/dev/null \
        | awk 'tolower($0) ~ /failed|invalid user|authentication failure/ { c++ } END { print c+0 }')"
fi

# --- Fail2ban banned IPs ---
FAIL2BAN_BANNED=0
if command -v fail2ban-client &>/dev/null && fail2ban-client ping &>/dev/null; then
    jails="$(fail2ban-client status 2>/dev/null | awk -F: '/Jail list/ { gsub(/,/, " ", $2); print $2 }')"
    for jail in $jails; do
        banned="$(fail2ban-client status "$jail" 2>/dev/null | awk '/Currently banned:/ { print $NF+0; exit }')"
        FAIL2BAN_BANNED=$(( FAIL2BAN_BANNED + ${banned:-0} ))
    done
fi

# --- Failed systemd units ---
FAILED_UNITS=0
if command -v systemctl &>/dev/null; then
    failed_out="$(systemctl --failed --no-legend --no-pager --plain 2>/dev/null || true)"
    if [[ -n "$failed_out" ]]; then
        FAILED_UNITS="$(awk 'NF > 0 { c++ } END { print c+0 }' <<<"$failed_out")"
    fi
fi

{
    # No sample at all (rather than a misleading 0) until a check has succeeded.
    if [[ -n "$PENDING_UPDATES" ]]; then
        cat <<METRICS
# HELP security_packages_upgradable Number of packages with pending updates at the last successful check.
# TYPE security_packages_upgradable gauge
security_packages_upgradable ${PENDING_UPDATES}

# HELP security_packages_check_timestamp_seconds Unix time of the last successful pending-updates check.
# TYPE security_packages_check_timestamp_seconds gauge
security_packages_check_timestamp_seconds ${UPDATES_CHECKED_AT}

METRICS
    fi
    cat <<METRICS
# HELP security_failed_ssh_logins Failed SSH login attempts in the last hour.
# TYPE security_failed_ssh_logins gauge
security_failed_ssh_logins ${FAILED_SSH}

# HELP security_fail2ban_banned_total Total IPs currently banned by fail2ban.
# TYPE security_fail2ban_banned_total gauge
security_fail2ban_banned_total ${FAIL2BAN_BANNED}

# HELP security_systemd_failed_units Number of systemd units in failed state.
# TYPE security_systemd_failed_units gauge
security_systemd_failed_units ${FAILED_UNITS}
METRICS
} > "$TMPFILE"

chmod 0644 "$TMPFILE"
mv -f "$TMPFILE" "$OUTFILE"
COLLECTOR_EOF

chmod 0755 /usr/local/bin/node-exporter-textfile-security.sh

msg "Creating systemd timer for security collector (every 5 minutes)..."
# Collector runs as root (with strict filesystem sandboxing) so it can read
# sshd's journal under SplitMode=uid and query /run/fail2ban/fail2ban.sock.
cat > /etc/systemd/system/node-exporter-security-collector.service <<EOF
[Unit]
Description=Prometheus node_exporter security textfile collector
After=prometheus-node-exporter.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/node-exporter-textfile-security.sh
Nice=19
IOSchedulingClass=idle
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
NoNewPrivileges=yes
StateDirectory=node-exporter-security
ReadWritePaths=${TEXTFILE_DIR}
EOF
chmod 0644 /etc/systemd/system/node-exporter-security-collector.service

cat > /etc/systemd/system/node-exporter-security-collector.timer <<EOF
[Unit]
Description=Run security textfile collector every 5 minutes

[Timer]
OnBootSec=1min
OnUnitActiveSec=5min
AccuracySec=30s

[Install]
WantedBy=timers.target
EOF
chmod 0644 /etc/systemd/system/node-exporter-security-collector.timer

systemctl daemon-reload
systemctl enable --now node-exporter-security-collector.timer
msg "Security collector timer enabled (every 5 minutes)"

# Started through its unit so the first run uses the same sandbox as the timer.
info "Running initial security metrics collection..."
systemctl start node-exporter-security-collector.service || \
    warn "Initial collection failed (non-fatal). Check: journalctl -u node-exporter-security-collector.service"

echo
echo -e "${C_GREEN}========================================================================${C_NC}"
echo -e "${C_GREEN} Monitoring stack setup complete!${C_NC}"
echo -e "${C_GREEN}========================================================================${C_NC}"
echo "  node_exporter:  http://127.0.0.1:${PORT}/metrics"
[[ "$WITH_PROMETHEUS" == true ]] && echo "  Prometheus:     http://127.0.0.1:9090"
[[ "$WITH_GRAFANA" == true ]]    && echo "  Grafana:        http://localhost:3000"
[[ "$WITH_GRAFANA" == true && -f /root/.grafana-admin-password ]] && \
    echo "  Grafana admin:  user 'admin', password in /root/.grafana-admin-password"
echo -e "${C_GREEN}Done.${C_NC}"
