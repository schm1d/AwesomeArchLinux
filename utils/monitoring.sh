#!/usr/bin/env bash

# =============================================================================
# Script:      monitoring.sh
# Description: Prometheus node_exporter + optional Grafana monitoring stack
#              for Arch Linux with systemd hardening and security collectors.
#
#   Components:
#     - node_exporter (always): Exposes host-level metrics (CPU, memory, disk,
#       network, systemd units, etc.) on a local HTTP endpoint for Prometheus
#       to scrape. Runs as a lightweight daemon with minimal privileges.
#
#     - Prometheus (--with-prometheus): Time-series database that scrapes
#       node_exporter metrics at regular intervals and stores them with
#       configurable retention. Provides PromQL query language.
#
#     - Grafana (--with-grafana): Web-based dashboarding and visualization
#       platform. Auto-provisioned with Prometheus as the default datasource.
#       Default login: admin / admin (change on first login).
#
#     - Security textfile collector: A custom script run every 5 minutes via
#       systemd timer that exports security-relevant gauges (pending updates,
#       failed SSH logins, fail2ban bans, failed systemd units) into the
#       node_exporter textfile directory.
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
#
# Usage:       sudo ./monitoring.sh [--with-prometheus] [--with-grafana]
#                                    [--port PORT] [-h]
#
# Requirements:
#   - Arch Linux with pacman
#   - Root privileges
#
# What this script does:
#   1. Installs and configures prometheus-node-exporter with useful collectors
#   2. Applies systemd hardening overrides for all monitoring services
#   3. (Optional) Installs Prometheus server with 30-day retention
#   4. (Optional) Installs Grafana with auto-provisioned Prometheus datasource
#   5. Creates security-oriented textfile collector script + systemd timer
#   6. Generates nftables rules snippet for monitoring ports
#   7. Prints summary with URLs, credentials, and next steps
# =============================================================================

set -euo pipefail

# --- Colors ---
readonly C_BLUE='\033[1;34m'
readonly C_RED='\033[1;31m'
readonly C_GREEN='\033[1;32m'
readonly C_YELLOW='\033[1;33m'
readonly C_NC='\033[0m'

msg()  { printf "%b[+]%b %s\n" "$C_GREEN" "$C_NC" "$1"; }
info() { printf "%b[*]%b %s\n" "$C_BLUE"  "$C_NC" "$1"; }
warn() { printf "%b[!]%b %s\n" "$C_YELLOW" "$C_NC" "$1"; }
err()  { printf "%b[!]%b %s\n" "$C_RED"   "$C_NC" "$1" >&2; exit 1; }

# --- Defaults ---
PORT=9100
WITH_PROMETHEUS=false
WITH_GRAFANA=false
TEXTFILE_DIR="/var/lib/prometheus/node-exporter"

# --- Usage ---
usage() {
    cat <<EOF
Usage: sudo $0 [options]

Options:
  --with-prometheus   Install and configure Prometheus server
  --with-grafana      Install and configure Grafana with Prometheus datasource
  --port PORT         node_exporter listen port (default: $PORT)
  -h, --help          Show this help

Examples:
  sudo $0                                  # node_exporter only
  sudo $0 --with-prometheus                # node_exporter + Prometheus
  sudo $0 --with-prometheus --with-grafana # Full monitoring stack
  sudo $0 --port 9200                      # node_exporter on custom port
EOF
    exit 0
}

# --- Parse Arguments ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --with-prometheus) WITH_PROMETHEUS=true; shift ;;
        --with-grafana)    WITH_GRAFANA=true; shift ;;
        --port)            PORT="$2"; shift 2 ;;
        -h|--help)         usage ;;
        *)                 err "Unknown option: $1" ;;
    esac
done

# --- Validate ---
[[ $(id -u) -eq 0 ]] || err "Must be run as root"

# Validate port is a number in valid range
if ! [[ "$PORT" =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then
    err "Invalid port: $PORT (must be 1-65535)"
fi

info "node_exporter port: $PORT"
info "Prometheus server:  $WITH_PROMETHEUS"
info "Grafana:            $WITH_GRAFANA"

# =============================================================================
# 1. NODE_EXPORTER (always installed)
# =============================================================================

msg "Installing prometheus-node-exporter..."
pacman -Syu --noconfirm --needed prometheus-node-exporter

# --- Configure node_exporter ---
msg "Configuring node_exporter..."

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

info "node_exporter configured at /etc/conf.d/prometheus-node-exporter"

# --- Create textfile collector directory ---
msg "Creating textfile collector directory..."
mkdir -p "$TEXTFILE_DIR"
chown prometheus:prometheus "$TEXTFILE_DIR" 2>/dev/null || \
    chown nobody:nobody "$TEXTFILE_DIR"
chmod 755 "$TEXTFILE_DIR"

info "Textfile directory: $TEXTFILE_DIR"

# --- Systemd hardening override for node_exporter ---
msg "Applying systemd hardening for node_exporter..."

mkdir -p /etc/systemd/system/prometheus-node-exporter.service.d

cat > /etc/systemd/system/prometheus-node-exporter.service.d/hardening.conf <<EOF
[Service]
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
ReadWritePaths=/var/lib/prometheus
CapabilityBoundingSet=
EOF

info "Hardening override: /etc/systemd/system/prometheus-node-exporter.service.d/hardening.conf"

# --- Enable and start node_exporter ---
systemctl daemon-reload
systemctl enable --now prometheus-node-exporter

msg "node_exporter enabled and started on 127.0.0.1:${PORT}"

# =============================================================================
# 2. PROMETHEUS SERVER (optional)
# =============================================================================

if [[ "$WITH_PROMETHEUS" == true ]]; then
    msg "Installing Prometheus server..."
    pacman -S --noconfirm --needed prometheus

    # --- Configure prometheus.yml ---
    msg "Configuring Prometheus..."

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
          instance: "$(hostname)"
EOF

    info "Prometheus config: /etc/prometheus/prometheus.yml"

    # --- Configure Prometheus CLI flags for retention and listen address ---
    mkdir -p /etc/conf.d

    cat > /etc/conf.d/prometheus <<EOF
# Managed by monitoring.sh — do not edit manually
PROMETHEUS_ARGS="\\
  --web.listen-address=127.0.0.1:9090 \\
  --storage.tsdb.retention.time=30d \\
  --config.file=/etc/prometheus/prometheus.yml \\
  --storage.tsdb.path=/var/lib/prometheus/data"
EOF

    info "Prometheus flags: /etc/conf.d/prometheus"

    # --- Systemd hardening override for Prometheus ---
    msg "Applying systemd hardening for Prometheus..."

    mkdir -p /etc/systemd/system/prometheus.service.d

    cat > /etc/systemd/system/prometheus.service.d/hardening.conf <<EOF
[Service]
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
ReadWritePaths=/var/lib/prometheus
CapabilityBoundingSet=
EOF

    info "Hardening override: /etc/systemd/system/prometheus.service.d/hardening.conf"

    # --- Enable and start Prometheus ---
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

    # --- Configure grafana.ini ---
    msg "Configuring Grafana..."

    # Back up original config if it exists and we haven't backed it up before
    if [[ -f /etc/grafana/grafana.ini && ! -f /etc/grafana/grafana.ini.orig ]]; then
        cp /etc/grafana/grafana.ini /etc/grafana/grafana.ini.orig
        info "Original grafana.ini backed up to /etc/grafana/grafana.ini.orig"
    fi

    cat > /etc/grafana/grafana.ini <<'GRAFANA_EOF'
# Managed by monitoring.sh — do not edit manually

[server]
http_addr = 127.0.0.1
http_port = 3000
domain = localhost
root_url = %(protocol)s://%(domain)s:%(http_port)s/

[security]
disable_gravatar = true
cookie_secure = true
cookie_samesite = strict
content_security_policy = true
strict_transport_security = true

[analytics]
reporting_enabled = false
check_for_updates = false
check_for_plugin_updates = false

[log]
mode = syslog
level = warn
GRAFANA_EOF

    info "Grafana config: /etc/grafana/grafana.ini"

    # --- Provision Prometheus as default datasource ---
    msg "Provisioning Prometheus datasource for Grafana..."

    mkdir -p /etc/grafana/provisioning/datasources

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

    info "Datasource provisioned: /etc/grafana/provisioning/datasources/prometheus.yml"

    # --- Enable and start Grafana ---
    systemctl daemon-reload
    systemctl enable --now grafana

    msg "Grafana enabled and started on 127.0.0.1:3000"
fi

# =============================================================================
# 4. NFTABLES RULES SNIPPET
# =============================================================================

msg "Creating nftables rules snippet for monitoring ports..."

mkdir -p /etc/nftables.d

cat > /etc/nftables.d/monitoring.conf <<EOF
# Managed by monitoring.sh — nftables rules for monitoring services
# Include this from your main nftables.conf if you need remote access.
#
# By default, all services listen on 127.0.0.1 only.
# Uncomment and adjust rules below if you need to expose them to the network.

# Allow node_exporter from monitoring subnet
# tcp dport ${PORT} accept comment "node_exporter"

# Allow Prometheus from monitoring subnet
# tcp dport 9090 accept comment "prometheus"

# Allow Grafana from monitoring subnet
# tcp dport 3000 accept comment "grafana"

# Example: restrict to specific subnet
# ip saddr 10.0.0.0/24 tcp dport { ${PORT}, 9090, 3000 } accept comment "monitoring stack"
EOF

info "nftables snippet: /etc/nftables.d/monitoring.conf"

# =============================================================================
# 5. SECURITY TEXTFILE COLLECTOR
# =============================================================================

msg "Creating security textfile collector script..."

cat > /usr/local/bin/node-exporter-textfile-security.sh <<'COLLECTOR_EOF'
#!/usr/bin/env bash
# =============================================================================
# Security metrics collector for Prometheus node_exporter textfile directory.
# Exports gauges for pending updates, failed SSH logins, fail2ban bans,
# and failed systemd units.
#
# Managed by monitoring.sh — do not edit manually
# =============================================================================

set -euo pipefail

TEXTFILE_DIR="/var/lib/prometheus/node-exporter"
OUTFILE="${TEXTFILE_DIR}/security.prom"
TMPFILE="${OUTFILE}.tmp"

# --- Pending package updates ---
PENDING_UPDATES=0
if command -v checkupdates &>/dev/null; then
    PENDING_UPDATES=$(checkupdates 2>/dev/null | wc -l || echo 0)
fi

# --- Failed SSH logins in the last hour ---
FAILED_SSH=0
if journalctl --no-pager -u sshd --since "1 hour ago" &>/dev/null; then
    FAILED_SSH=$(journalctl --no-pager -u sshd --since "1 hour ago" 2>/dev/null \
        | grep -ci "failed\|invalid user\|authentication failure" || echo 0)
fi

# --- Fail2ban banned IPs ---
FAIL2BAN_BANNED=0
if command -v fail2ban-client &>/dev/null; then
    # Sum banned counts across all jails
    FAIL2BAN_BANNED=$(fail2ban-client status 2>/dev/null \
        | grep "Jail list" \
        | sed 's/.*://;s/,/ /g' \
        | xargs -n1 fail2ban-client status 2>/dev/null \
        | grep "Currently banned" \
        | awk '{sum += $NF} END {print sum+0}' || echo 0)
fi

# --- Failed systemd units ---
FAILED_UNITS=0
FAILED_UNITS=$(systemctl --failed --no-legend --no-pager 2>/dev/null | wc -l || echo 0)

# --- Write metrics atomically ---
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

mv "$TMPFILE" "$OUTFILE"
COLLECTOR_EOF

chmod 755 /usr/local/bin/node-exporter-textfile-security.sh

info "Collector script: /usr/local/bin/node-exporter-textfile-security.sh"

# --- systemd service and timer for the collector ---
msg "Creating systemd timer for security collector (every 5 minutes)..."

cat > /etc/systemd/system/node-exporter-security-collector.service <<EOF
[Unit]
Description=Prometheus node_exporter security textfile collector
After=prometheus-node-exporter.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/node-exporter-textfile-security.sh
User=prometheus
Group=prometheus
Nice=19
IOSchedulingClass=idle
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
ReadWritePaths=/var/lib/prometheus
EOF

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

systemctl daemon-reload
systemctl enable --now node-exporter-security-collector.timer

msg "Security collector timer enabled (every 5 minutes)"

# Run the collector once immediately so metrics are available right away
info "Running initial security metrics collection..."
/usr/local/bin/node-exporter-textfile-security.sh || warn "Initial collection had warnings (non-fatal)"

# =============================================================================
# 6. SUMMARY
# =============================================================================

echo
echo -e "${C_GREEN}========================================================================${C_NC}"
echo -e "${C_GREEN} Monitoring stack setup complete!${C_NC}"
echo -e "${C_GREEN}========================================================================${C_NC}"
echo
echo -e "${C_BLUE}Services installed:${C_NC}"
echo "  - prometheus-node-exporter  (always)"
[[ "$WITH_PROMETHEUS" == true ]] && echo "  - prometheus                (--with-prometheus)"
[[ "$WITH_GRAFANA" == true ]]    && echo "  - grafana                   (--with-grafana)"
echo

echo -e "${C_BLUE}Endpoints (localhost only):${C_NC}"
echo "  node_exporter:  http://127.0.0.1:${PORT}/metrics"
[[ "$WITH_PROMETHEUS" == true ]] && echo "  Prometheus:     http://127.0.0.1:9090"
[[ "$WITH_GRAFANA" == true ]]    && echo "  Grafana:        http://127.0.0.1:3000"
echo

if [[ "$WITH_GRAFANA" == true ]]; then
    echo -e "${C_YELLOW}Grafana default credentials:${C_NC}"
    echo "  Username: admin"
    echo "  Password: admin"
    echo -e "${C_YELLOW}  You will be prompted to change the password on first login.${C_NC}"
    echo
fi

echo -e "${C_BLUE}Security textfile collector:${C_NC}"
echo "  Script:   /usr/local/bin/node-exporter-textfile-security.sh"
echo "  Timer:    node-exporter-security-collector.timer (every 5 min)"
echo "  Metrics:  ${TEXTFILE_DIR}/security.prom"
echo
echo -e "${C_BLUE}Configuration files:${C_NC}"
echo "  node_exporter:  /etc/conf.d/prometheus-node-exporter"
[[ "$WITH_PROMETHEUS" == true ]] && echo "  Prometheus:     /etc/prometheus/prometheus.yml"
[[ "$WITH_PROMETHEUS" == true ]] && echo "  Prometheus:     /etc/conf.d/prometheus"
[[ "$WITH_GRAFANA" == true ]]    && echo "  Grafana:        /etc/grafana/grafana.ini"
[[ "$WITH_GRAFANA" == true ]]    && echo "  Datasource:     /etc/grafana/provisioning/datasources/prometheus.yml"
echo "  nftables:       /etc/nftables.d/monitoring.conf"
echo

echo -e "${C_BLUE}Systemd hardening:${C_NC}"
echo "  All services run with ProtectSystem=strict, ProtectHome=yes,"
echo "  PrivateTmp=yes, NoNewPrivileges=yes, empty CapabilityBoundingSet."
echo

echo -e "${C_BLUE}Useful commands:${C_NC}"
echo "  Check node_exporter: curl -s http://127.0.0.1:${PORT}/metrics | head"
echo "  Service status:      systemctl status prometheus-node-exporter"
[[ "$WITH_PROMETHEUS" == true ]] && echo "  Prometheus status:   systemctl status prometheus"
[[ "$WITH_GRAFANA" == true ]]    && echo "  Grafana status:      systemctl status grafana"
echo "  Security metrics:    cat ${TEXTFILE_DIR}/security.prom"
echo "  List timers:         systemctl list-timers 'node-exporter-*'"
echo

echo -e "${C_BLUE}Next steps:${C_NC}"
echo "  1. Verify metrics:  curl -s http://127.0.0.1:${PORT}/metrics | grep node_"
if [[ "$WITH_PROMETHEUS" == true ]]; then
    echo "  2. Check targets:   Open http://127.0.0.1:9090/targets in a browser"
    echo "     (or use SSH tunnel: ssh -L 9090:127.0.0.1:9090 yourserver)"
fi
if [[ "$WITH_GRAFANA" == true ]]; then
    echo "  3. Login to Grafana: http://127.0.0.1:3000 (admin/admin)"
    echo "     Import Node Exporter Full dashboard: ID 1860"
    echo "     (or use SSH tunnel: ssh -L 3000:127.0.0.1:3000 yourserver)"
fi
echo "  - To expose services remotely, edit /etc/nftables.d/monitoring.conf"
echo "    and change listen addresses from 127.0.0.1 to 0.0.0.0"
echo

echo -e "${C_GREEN}Done.${C_NC}"
