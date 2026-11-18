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
TEXTFILE_DIR="/var/lib/prometheus/node-exporter"

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
install -d -m 0755 /var/lib/prometheus "$TEXTFILE_DIR"
chown prometheus:prometheus "$TEXTFILE_DIR" 2>/dev/null || chown nobody:nobody "$TEXTFILE_DIR"

msg "Applying systemd hardening for node_exporter..."
install -d -m 0755 /etc/systemd/system/prometheus-node-exporter.service.d
cat > /etc/systemd/system/prometheus-node-exporter.service.d/hardening.conf <<EOF
[Service]
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
ReadWritePaths=/var/lib/prometheus
CapabilityBoundingSet=
EOF
chmod 0644 /etc/systemd/system/prometheus-node-exporter.service.d/hardening.conf

systemctl daemon-reload
systemctl enable --now prometheus-node-exporter
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

    cat > /etc/conf.d/prometheus <<EOF
# Managed by monitoring.sh — do not edit manually
PROMETHEUS_ARGS="\\
  --web.listen-address=127.0.0.1:9090 \\
  --storage.tsdb.retention.time=30d \\
  --config.file=/etc/prometheus/prometheus.yml \\
  --storage.tsdb.path=/var/lib/prometheus/data"
EOF
    chmod 0644 /etc/conf.d/prometheus

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
    systemctl enable --now prometheus
    msg "Prometheus enabled and started on 127.0.0.1:9090"
fi

# =============================================================================
# 3. GRAFANA (optional)
# =============================================================================

if [[ "$WITH_GRAFANA" == true ]]; then
    msg "Installing Grafana..."
    pacman -S --noconfirm --needed grafana

    msg "Configuring Grafana..."
    if [[ -f /etc/grafana/grafana.ini && ! -f /etc/grafana/grafana.ini.orig ]]; then
        cp -p /etc/grafana/grafana.ini /etc/grafana/grafana.ini.orig
        info "Original grafana.ini backed up to /etc/grafana/grafana.ini.orig"
    fi

    # Note: Grafana listens on loopback HTTP (127.0.0.1:3000); setting
    # cookie_secure = true over plain HTTP causes browsers to drop session
    # cookies and loop on login. Flip cookie_secure = true when fronting
    # Grafana with an HTTPS reverse proxy (e.g., hardening/nginx/nginx.sh).
    cat > /etc/grafana/grafana.ini <<'GRAFANA_EOF'
# Managed by monitoring.sh — do not edit manually

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
    chown root:grafana /etc/grafana/grafana.ini 2>/dev/null || true
    chmod 0640 /etc/grafana/grafana.ini

    install -d -m 0750 /etc/grafana/provisioning /etc/grafana/provisioning/datasources
    chown -R root:grafana /etc/grafana/provisioning 2>/dev/null || true
    cat > /etc/grafana/provisioning/datasources/prometheus.yml <<EOF
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
    chown root:grafana /etc/grafana/provisioning/datasources/prometheus.yml 2>/dev/null || true
    chmod 0640 /etc/grafana/provisioning/datasources/prometheus.yml

    systemctl daemon-reload
    systemctl enable --now grafana
    msg "Grafana enabled and started on 127.0.0.1:3000"
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

TEXTFILE_DIR="/var/lib/prometheus/node-exporter"
OUTFILE="${TEXTFILE_DIR}/security.prom"
TMPFILE="$(mktemp "${TEXTFILE_DIR}/.security.prom.XXXXXX")"
trap 'rm -f -- "$TMPFILE"' EXIT

# --- Pending package updates (checkupdates exits 2 when 0 updates exist) ---
PENDING_UPDATES=0
if command -v checkupdates &>/dev/null; then
    updates_out="$(checkupdates 2>/dev/null || true)"
    if [[ -n "$updates_out" ]]; then
        PENDING_UPDATES="$(awk 'END { print NR }' <<<"$updates_out")"
    fi
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

cat > "$TMPFILE" <<METRICS
# HELP security_packages_upgradable Number of packages with pending updates.
# TYPE security_packages_upgradable gauge
security_packages_upgradable ${PENDING_UPDATES}

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

info "Running initial security metrics collection..."
/usr/local/bin/node-exporter-textfile-security.sh || warn "Initial collection had warnings (non-fatal)"

echo
echo -e "${C_GREEN}========================================================================${C_NC}"
echo -e "${C_GREEN} Monitoring stack setup complete!${C_NC}"
echo -e "${C_GREEN}========================================================================${C_NC}"
echo "  node_exporter:  http://127.0.0.1:${PORT}/metrics"
[[ "$WITH_PROMETHEUS" == true ]] && echo "  Prometheus:     http://127.0.0.1:9090"
[[ "$WITH_GRAFANA" == true ]]    && echo "  Grafana:        http://localhost:3000"
echo -e "${C_GREEN}Done.${C_NC}"
