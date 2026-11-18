#!/usr/bin/env bash
# =============================================================================
# Script:      board-health.sh
# Description: Thermal monitoring for explicitly supported motherboard models
#              (ASUS ROG Zenith II Extreme Alpha). Samples CPU Tctl, chipset,
#              VRM, NVMe temperatures, and EC fan RPMs via sysfs hwmon without
#              requiring Python or out-of-tree drivers.
#
# Usage:       ./board-health.sh [--status | --check | --install [--enable-only]]
# =============================================================================

set -euo pipefail

umask 022

readonly EXPECTED_VENDOR="ASUSTeK COMPUTER INC."
readonly EXPECTED_BOARD="ROG ZENITH II EXTREME ALPHA"
readonly REPEAT_SECONDS=1800
readonly HYSTERESIS_MC=3000

DMI_DIR="${BOARD_HEALTH_DMI_DIR:-/sys/class/dmi/id}"
HWMON_DIR="${BOARD_HEALTH_HWMON_DIR:-/sys/class/hwmon}"
CPUFREQ_DIR="${BOARD_HEALTH_CPUFREQ_DIR:-/sys/devices/system/cpu/cpu0/cpufreq}"
INSTALLED_BIN="${BOARD_HEALTH_INSTALLED:-/usr/local/bin/awesome-board-health}"
CONFIG_FILE="${BOARD_HEALTH_CONFIG:-/etc/awesome-board-health.conf}"
UNITS_DIR="${BOARD_HEALTH_UNITS_DIR:-/etc/systemd/system}"
STATE_FILE="${BOARD_HEALTH_STATE:-/run/awesome-board-health/state}"

declare -A LIMITS=(
    [nvme]=70
    [cpu]=85
    [chipset]=85
    [vrm]=90
)

die() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
Usage: board-health.sh [--status | --check | --install [--enable-only]] [-h|--help]

Thermal monitoring for explicitly supported motherboard models.

Options:
  --status        Show detected board and sensors (default)
  --check         Sample sensors and update runtime alarm state
  --install       Enable monitoring on the exact supported board
  --enable-only   With --install: enable timer for next boot (for chroots)
  -h, --help      Show this help message
EOF
}

trim() {
    local s="$1"
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    printf '%s' "$s"
}

read_sysfs() {
    local path="$1"
    local default="${2:-unknown}"
    local content=""
    if [[ -r "$path" ]] && IFS= read -r content < "$path" 2>/dev/null; then
        trim "$content"
    else
        printf '%s' "$default"
    fi
}

is_supported_board() {
    local vendor name
    vendor="$(read_sysfs "$DMI_DIR/board_vendor")"
    name="$(read_sysfs "$DMI_DIR/board_name")"
    [[ "$vendor" == "$EXPECTED_VENDOR" && "$name" == "$EXPECTED_BOARD" ]]
}

atomic_write() {
    local target="$1"
    local mode="$2"
    local content="$3"
    local dir tmp

    dir="$(dirname -- "$target")"
    mkdir -p -- "$dir"
    tmp="$(mktemp "$dir/.${target##*/}.XXXXXX")"
    # Clean up temp file if anything fails before mv
    if ! {
        printf '%s' "$content" > "$tmp" &&
        chmod "$mode" -- "$tmp" &&
        mv -f -- "$tmp" "$target"
    }; then
        rm -f -- "$tmp"
        die "Failed to write $target"
    fi
}

load_thresholds() {
    LIMITS=(
        [nvme]=70
        [cpu]=85
        [chipset]=85
        [vrm]=90
    )

    [[ -f "$CONFIG_FILE" ]] || return 0
    [[ -r "$CONFIG_FILE" ]] || die "Cannot read $CONFIG_FILE"

    local raw line section="" key val
    while IFS= read -r raw || [[ -n "$raw" ]]; do
        line="$(trim "$raw")"
        [[ -z "$line" || "$line" == \#* || "$line" == \;* ]] && continue

        if [[ "$line" =~ ^\[([^]]+)\]$ ]]; then
            section="$(trim "${BASH_REMATCH[1]}")"
            [[ "$section" == "temperature" ]] || die "Unknown configuration section: [$section]"
            continue
        fi

        [[ "$section" == "temperature" ]] || die "Configuration setting outside [temperature] section: $line"
        [[ "$line" == *=* ]] || die "Malformed configuration line: $line"

        key="$(trim "${line%%=*}")"
        val="$(trim "${line#*=}")"
        key="${key,,}"

        case "$key" in
            nvme|cpu|chipset|vrm) ;;
            *) die "Unknown temperature setting: $key" ;;
        esac

        [[ "$val" =~ ^[0-9]+$ ]] || die "$key: expected an integer temperature between 40 and 110 C"
        if (( 10#$val < 40 || 10#$val > 110 )); then
            die "$key: expected a warning temperature between 40 and 110 C"
        fi
        LIMITS[$key]=$(( 10#$val ))
    done < "$CONFIG_FILE"
}

format_mdeg() {
    local mc="$1"
    local sign="" abs_mc whole tenth
    if (( mc < 0 )); then
        sign="-"
        abs_mc=$(( -mc ))
    else
        abs_mc=$mc
    fi
    # Round nearest 100 millidegrees (0.1 C)
    abs_mc=$(( abs_mc + 50 ))
    whole=$(( abs_mc / 1000 ))
    tenth=$(( (abs_mc % 1000) / 100 ))
    printf '%s%d.%d' "$sign" "$whole" "$tenth"
}

declare -A SAMPLE_KIND=()
declare -A SAMPLE_MC=()
declare -A FAN_RPM=()

collect_sensors() {
    SAMPLE_KIND=()
    SAMPLE_MC=()
    FAN_RPM=()

    local device driver source base label kind dev_link key raw_val mc
    local -a hwmon_dirs=()
    if [[ -d "$HWMON_DIR" ]]; then
        shopt -s nullglob
        hwmon_dirs=("$HWMON_DIR"/hwmon*)
        shopt -u nullglob
    fi

    if (( ${#hwmon_dirs[@]} > 0 )); then
        IFS=$'\n' read -r -d '' -a hwmon_dirs < <(printf '%s\n' "${hwmon_dirs[@]}" | LC_ALL=C sort && printf '\0') || true
    fi

    for device in "${hwmon_dirs[@]}"; do
        [[ -d "$device" ]] || continue
        driver="$(read_sysfs "$device/name" "")"
        case "$driver" in
            nvme|asusec|k10temp) ;;
            *) continue ;;
        esac

        local -a temp_inputs=()
        shopt -s nullglob
        temp_inputs=("$device"/temp*_input)
        shopt -u nullglob
        if (( ${#temp_inputs[@]} > 0 )); then
            IFS=$'\n' read -r -d '' -a temp_inputs < <(printf '%s\n' "${temp_inputs[@]}" | LC_ALL=C sort && printf '\0') || true
        fi

        for source in "${temp_inputs[@]}"; do
            base="${source##*/}"
            label="$(read_sysfs "${source%_input}_label" "")"
            kind=""

            if [[ "$driver" == "nvme" && "$base" == "temp1_input" ]]; then
                kind="nvme"
                if dev_link="$(readlink -f -- "$device/device" 2>/dev/null)" && [[ -n "$dev_link" ]]; then
                    label="${dev_link##*/}"
                else
                    label="${device##*/}"
                fi
            elif [[ "$driver" == "asusec" ]]; then
                case "$label" in
                    Chipset) kind="chipset" ;;
                    VRM)     kind="vrm" ;;
                esac
            elif [[ "$label" == "Tctl" ]]; then
                kind="cpu"
            fi

            [[ -n "$kind" ]] || continue
            key="${driver}:${label}"
            SAMPLE_KIND[$key]="$kind"

            raw_val="$(read_sysfs "$source" "")"
            if [[ "$raw_val" =~ ^-?[0-9]+$ ]]; then
                mc=$(( raw_val ))
                if (( mc >= -20000 && mc <= 150000 )); then
                    SAMPLE_MC[$key]="$mc"
                else
                    SAMPLE_MC[$key]="unavailable"
                fi
            else
                SAMPLE_MC[$key]="unavailable"
            fi
        done

        if [[ "$driver" == "asusec" ]]; then
            local -a fan_inputs=()
            shopt -s nullglob
            fan_inputs=("$device"/fan*_input)
            shopt -u nullglob
            if (( ${#fan_inputs[@]} > 0 )); then
                IFS=$'\n' read -r -d '' -a fan_inputs < <(printf '%s\n' "${fan_inputs[@]}" | LC_ALL=C sort && printf '\0') || true
            fi
            for source in "${fan_inputs[@]}"; do
                base="${source##*/}"
                label="$(read_sysfs "${source%_input}_label" "${base%_input}")"
                [[ -n "$label" ]] || label="${base%_input}"
                FAN_RPM[$label]="$(read_sysfs "$source" "unknown")"
            done
        fi
    done

    # Mandatory fitted sensors on the supported board/CPU
    local mandatory_entry m_key m_kind
    for mandatory_entry in "asusec:Chipset=chipset" "asusec:VRM=vrm" "k10temp:Tctl=cpu"; do
        m_key="${mandatory_entry%%=*}"
        m_kind="${mandatory_entry#*=}"
        if [[ ! -v SAMPLE_KIND[$m_key] ]]; then
            SAMPLE_KIND[$m_key]="$m_kind"
            SAMPLE_MC[$m_key]="unavailable"
        fi
    done
}

format_fans() {
    if (( ${#FAN_RPM[@]} == 0 )); then
        printf 'none'
        return
    fi
    local -a keys=()
    local k out=""
    IFS=$'\n' read -r -d '' -a keys < <(printf '%s\n' "${!FAN_RPM[@]}" | LC_ALL=C sort && printf '\0') || true
    for k in "${keys[@]}"; do
        [[ -n "$out" ]] && out+=", "
        out+="${k}=${FAN_RPM[$k]}"
    done
    printf '%s' "$out"
}

declare -A PREV_KIND=()
declare -A PREV_REASON=()
declare -A PREV_COUNT=()
declare -A PREV_ALARM=()
declare -A PREV_LAST=()

load_state() {
    PREV_KIND=()
    PREV_REASON=()
    PREV_COUNT=()
    PREV_ALARM=()
    PREV_LAST=()

    [[ -r "$STATE_FILE" ]] || return 0

    local k="" kind="" reason="" count="" alarm="" last=""
    while IFS='|' read -r k kind reason count alarm last || [[ -n "$k" ]]; do
        [[ -n "$k" ]] || continue
        case "$kind" in
            nvme|cpu|chipset|vrm) ;;
            *) continue ;;
        esac
        [[ "$count" =~ ^[0-9]+$ ]] || count=0
        [[ "$last" =~ ^[0-9]+$ ]] || last=0
        PREV_KIND[$k]="$kind"
        PREV_REASON[$k]="$reason"
        PREV_COUNT[$k]=$(( 10#$count ))
        PREV_ALARM[$k]="$alarm"
        PREV_LAST[$k]=$(( 10#$last ))
    done < "$STATE_FILE" || true
}

monotonic_seconds() {
    if [[ -n "${BOARD_HEALTH_NOW:-}" ]]; then
        printf '%d' "$BOARD_HEALTH_NOW"
        return
    fi
    if [[ -r /proc/uptime ]]; then
        awk '{ printf "%d", $1 }' /proc/uptime
    else
        date +%s
    fi
}

declare -A NEXT_KIND=()
declare -A NEXT_REASON=()
declare -A NEXT_COUNT=()
declare -A NEXT_ALARM=()
declare -A NEXT_LAST=()
declare -a EVENTS=()

evaluate_state() {
    local now="$1"
    NEXT_KIND=()
    NEXT_REASON=()
    NEXT_COUNT=()
    NEXT_ALARM=()
    NEXT_LAST=()
    EVENTS=()

    local -A all_keys_map=()
    local k
    for k in "${!SAMPLE_KIND[@]}"; do all_keys_map[$k]=1; done
    for k in "${!PREV_KIND[@]}";   do all_keys_map[$k]=1; done

    local -a sorted_keys=()
    if (( ${#all_keys_map[@]} > 0 )); then
        IFS=$'\n' read -r -d '' -a sorted_keys < <(printf '%s\n' "${!all_keys_map[@]}" | LC_ALL=C sort && printf '\0') || true
    fi

    local kind val_mc limit_mc reason old_reason old_count old_alarm old_last count alarm last detail formatted_c
    for k in "${sorted_keys[@]}"; do
        if [[ -v SAMPLE_KIND[$k] ]]; then
            kind="${SAMPLE_KIND[$k]}"
            val_mc="${SAMPLE_MC[$k]}"
        else
            kind="${PREV_KIND[$k]}"
            val_mc="unavailable"
        fi

        [[ -v LIMITS[$kind] ]] || continue
        limit_mc=$(( LIMITS[$kind] * 1000 ))

        old_reason="${PREV_REASON[$k]:-}"
        old_count="${PREV_COUNT[$k]:-0}"
        old_alarm="${PREV_ALARM[$k]:-}"
        old_last="${PREV_LAST[$k]:-0}"

        if [[ "$val_mc" == "unavailable" ]]; then
            reason="missing"
        elif (( val_mc >= limit_mc )); then
            reason="hot"
        elif [[ "$old_alarm" == "hot" ]] && (( val_mc >= limit_mc - HYSTERESIS_MC )); then
            reason="hot"
        else
            reason=""
        fi

        if [[ -n "$reason" && "$old_reason" == "$reason" ]]; then
            count=$(( old_count + 1 ))
        elif [[ -n "$reason" ]]; then
            count=1
        else
            count=0
        fi

        if (( count >= 2 )); then
            alarm="$reason"
        else
            alarm="$old_alarm"
        fi
        last=$old_last

        if [[ -n "$reason" ]] && (( count >= 2 )) && { [[ "$alarm" != "$old_alarm" ]] || (( now - last >= REPEAT_SECONDS )); }; then
            if [[ "$val_mc" == "unavailable" ]]; then
                detail="sensor unavailable"
            else
                formatted_c="$(format_mdeg "$val_mc")"
                detail="${formatted_c} C (warning ${LIMITS[$kind]} C)"
            fi
            EVENTS+=("4|${k}: ${detail} for at least two samples; inspect cooling/storage logs")
            last=$now
        elif [[ -z "$reason" && -n "$old_alarm" ]]; then
            formatted_c="$(format_mdeg "$val_mc")"
            EVENTS+=("6|${k}: recovered, ${formatted_c} C")
            alarm=""
        fi

        NEXT_KIND[$k]="$kind"
        NEXT_REASON[$k]="$reason"
        NEXT_COUNT[$k]="$count"
        NEXT_ALARM[$k]="$alarm"
        NEXT_LAST[$k]="$last"
    done
}

serialize_state() {
    local -a sorted_keys=()
    if (( ${#NEXT_KIND[@]} > 0 )); then
        IFS=$'\n' read -r -d '' -a sorted_keys < <(printf '%s\n' "${!NEXT_KIND[@]}" | LC_ALL=C sort && printf '\0') || true
    fi
    local k
    for k in "${sorted_keys[@]}"; do
        printf '%s|%s|%s|%d|%s|%d\n' \
            "$k" "${NEXT_KIND[$k]}" "${NEXT_REASON[$k]}" \
            "${NEXT_COUNT[$k]}" "${NEXT_ALARM[$k]}" "${NEXT_LAST[$k]}"
    done
}

cmd_check() {
    if ! is_supported_board; then
        printf 'No motherboard profile matched; no monitoring actions taken.\n'
        return 0
    fi

    load_thresholds
    collect_sensors
    load_state

    local now
    now="$(monotonic_seconds)"
    evaluate_state "$now"

    atomic_write "$STATE_FILE" 0600 "$(serialize_state)"$'\n'

    local -a sorted_samples=() summary_parts=()
    local k
    if (( ${#SAMPLE_KIND[@]} > 0 )); then
        IFS=$'\n' read -r -d '' -a sorted_samples < <(printf '%s\n' "${!SAMPLE_KIND[@]}" | LC_ALL=C sort && printf '\0') || true
    fi
    for k in "${sorted_samples[@]}"; do
        if [[ "${SAMPLE_MC[$k]}" == "unavailable" ]]; then
            summary_parts+=("${k}=unavailable")
        else
            summary_parts+=("${k}=$(format_mdeg "${SAMPLE_MC[$k]}")C")
        fi
    done

    local summary_joined=""
    local i
    for i in "${!summary_parts[@]}"; do
        if (( i > 0 )); then
            summary_joined+=", "
        fi
        summary_joined+="${summary_parts[i]}"
    done

    printf '<6>%s; fans (RPM): %s\n' "$summary_joined" "$(format_fans)"

    local event prio msg_text
    for event in "${EVENTS[@]}"; do
        prio="${event%%|*}"
        msg_text="${event#*|}"
        printf '<%s>%s\n' "$prio" "$msg_text"
    done
}

cmd_install() {
    local enable_only="$1"

    if ! is_supported_board; then
        printf 'No motherboard profile matched; no files or services changed.\n'
        return 0
    fi

    if [[ "$(id -u)" -ne 0 ]]; then
        die "Run --install with sudo"
    fi

    # Validate existing overrides before making any changes.
    load_thresholds

    local self_path installed_real=""
    self_path="$(readlink -f -- "${BASH_SOURCE[0]}")"
    installed_real="$(readlink -m -- "$INSTALLED_BIN")"

    if [[ "$self_path" != "$installed_real" ]]; then
        atomic_write "$INSTALLED_BIN" 0755 "$(<"$self_path")"$'\n'
    fi

    if [[ ! -e "$CONFIG_FILE" ]]; then
        local default_config
        default_config="$(cat <<'EOF'
# Operational warning levels in Celsius, not hardware maximum ratings.
# Alerts require two consecutive samples; recovery requires 3 C below the limit.
[temperature]
nvme = 70
cpu = 85
chipset = 85
vrm = 90
EOF
)"
        atomic_write "$CONFIG_FILE" 0644 "${default_config}"$'\n'
    fi

    local service_unit timer_unit
    service_unit="$(cat <<EOF
[Unit]
Description=AwesomeArchLinux motherboard thermal monitoring
After=systemd-modules-load.service
ConditionVirtualization=no

[Service]
Type=oneshot
ExecStart=${INSTALLED_BIN} --check
DynamicUser=yes
RuntimeDirectory=awesome-board-health
RuntimeDirectoryPreserve=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
PrivateDevices=yes
PrivateTmp=yes
RestrictAddressFamilies=AF_UNIX
CapabilityBoundingSet=
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
TimeoutStartSec=30
SyslogIdentifier=awesome-board-health
SyslogLevelPrefix=yes
EOF
)"

    timer_unit="$(cat <<'EOF'
[Unit]
Description=Check motherboard and NVMe temperatures every minute

[Timer]
OnBootSec=2min
OnUnitActiveSec=1min
AccuracySec=5s

[Install]
WantedBy=timers.target
EOF
)"

    atomic_write "$UNITS_DIR/awesome-board-health.service" 0644 "${service_unit}"$'\n'
    atomic_write "$UNITS_DIR/awesome-board-health.timer" 0644 "${timer_unit}"$'\n'

    if [[ "$enable_only" == false ]]; then
        systemctl daemon-reload
        systemctl enable --now awesome-board-health.timer
    else
        systemctl enable awesome-board-health.timer
    fi

    printf 'Enabled thermal monitoring for %s.\n' "$EXPECTED_BOARD"
}

cmd_status() {
    printf 'Board: %s / %s\n' "$(read_sysfs "$DMI_DIR/board_vendor")" "$(read_sysfs "$DMI_DIR/board_name")"
    printf 'BIOS: %s (%s)\n' "$(read_sysfs "$DMI_DIR/bios_version")" "$(read_sysfs "$DMI_DIR/bios_date")"

    if ! is_supported_board; then
        printf 'No supported profile. No changes made.\n'
        return 0
    fi

    local attr
    for attr in scaling_driver scaling_governor energy_performance_preference; do
        printf '%s: %s\n' "$attr" "$(read_sysfs "$CPUFREQ_DIR/$attr")"
    done

    load_thresholds
    collect_sensors

    local -a sorted_samples=()
    local k kind val_str
    if (( ${#SAMPLE_KIND[@]} > 0 )); then
        IFS=$'\n' read -r -d '' -a sorted_samples < <(printf '%s\n' "${!SAMPLE_KIND[@]}" | LC_ALL=C sort && printf '\0') || true
    fi
    for k in "${sorted_samples[@]}"; do
        kind="${SAMPLE_KIND[$k]}"
        if [[ "${SAMPLE_MC[$k]}" == "unavailable" ]]; then
            val_str="unavailable"
        else
            val_str="$(format_mdeg "${SAMPLE_MC[$k]}")"
        fi
        printf '%s: %s C; warning %d C\n' "$k" "$val_str" "${LIMITS[$kind]}"
    done

    printf 'Fan readings (RPM): %s\n' "$(format_fans)"
    printf 'Alerts: journalctl -u awesome-board-health.service -p warning\n'
}

main() {
    local action=""
    local enable_only=false

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --status|--check|--install)
                if [[ -n "$action" && "$action" != "${1#--}" ]]; then
                    die "Options --status, --check, and --install are mutually exclusive"
                fi
                action="${1#--}"
                shift
                ;;
            --enable-only)
                enable_only=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                die "Unknown option: $1"
                ;;
        esac
    done

    if [[ "$enable_only" == true && "$action" != "install" ]]; then
        die "--enable-only requires --install"
    fi

    case "${action:-status}" in
        install) cmd_install "$enable_only" ;;
        check)   cmd_check ;;
        status)  cmd_status ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
