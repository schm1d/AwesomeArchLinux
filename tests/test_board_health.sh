#!/usr/bin/env bash
# Board matching and thermal alarm behavior using isolated sysfs fixtures.

set -euo pipefail

# shellcheck disable=SC1090,SC1091
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

BOARD_SCRIPT="$REPO_ROOT/utils/board-health.sh"

setup_fixture() {
    local root="$1"
    mkdir -p "$root/dmi" "$root/hwmon" "$root/cpufreq"
    printf '%s\n' "ASUSTeK COMPUTER INC." > "$root/dmi/board_vendor"
    printf '%s\n' "ROG ZENITH II EXTREME ALPHA" > "$root/dmi/board_name"
}

run_board() {
    local root="$1"
    shift
    BOARD_HEALTH_DMI_DIR="$root/dmi" \
    BOARD_HEALTH_HWMON_DIR="$root/hwmon" \
    BOARD_HEALTH_CPUFREQ_DIR="$root/cpufreq" \
    BOARD_HEALTH_CONFIG="$root/etc/board.conf" \
    BOARD_HEALTH_INSTALLED="$root/lib/awesome-board-health" \
    BOARD_HEALTH_UNITS_DIR="$root/units" \
    BOARD_HEALTH_STATE="$root/run/state" \
    "$@"
}

test_exact_dmi_match() {
    local tmp
    tmp="$(mktemp -d)"
    trap 'trap - RETURN EXIT; [[ -n "${tmp:-}" ]] && rm -rf -- "$tmp"' RETURN EXIT
    setup_fixture "$tmp"

    local out
    out="$(run_board "$tmp" bash "$BOARD_SCRIPT" --status)"
    assert_contains "$out" "Alerts: journalctl"

    local vendor name
    for pair in \
        "ASUSTeK COMPUTER INC.|ROG ZENITH II EXTREME" \
        "ASUSTeK COMPUTER INC.|ROG ZENITH EXTREME ALPHA" \
        "Other vendor|ROG ZENITH II EXTREME ALPHA"; do
        vendor="${pair%%|*}"
        name="${pair#*|}"
        printf '%s\n' "$vendor" > "$tmp/dmi/board_vendor"
        printf '%s\n' "$name"   > "$tmp/dmi/board_name"
        out="$(run_board "$tmp" bash "$BOARD_SCRIPT" --status)"
        assert_contains "$out" "No supported profile."
    done

    rm -f "$tmp/dmi/board_name"
    out="$(run_board "$tmp" bash "$BOARD_SCRIPT" --status)"
    assert_contains "$out" "No supported profile."
}

test_unsupported_install_and_check_noop() {
    local tmp
    tmp="$(mktemp -d)"
    trap 'trap - RETURN EXIT; [[ -n "${tmp:-}" ]] && rm -rf -- "$tmp"' RETURN EXIT
    setup_fixture "$tmp"
    printf 'Other\n' > "$tmp/dmi/board_vendor"

    run_board "$tmp" bash "$BOARD_SCRIPT" --install >/dev/null
    run_board "$tmp" bash "$BOARD_SCRIPT" --check   >/dev/null

    [[ ! -e "$tmp/run/state" ]]      || fail "state file should not exist"
    [[ ! -e "$tmp/etc/board.conf" ]] || fail "config should not exist"
    [[ ! -e "$tmp/units" ]]          || fail "units dir should not exist"
}

test_chroot_install_preserves_thresholds() {
    local tmp
    tmp="$(mktemp -d)"
    trap 'trap - RETURN EXIT; [[ -n "${tmp:-}" ]] && rm -rf -- "$tmp"' RETURN EXIT
    setup_fixture "$tmp"
    mkdir -p "$tmp/etc"
    local override=$'[temperature]\nnvme = 72\n'
    printf '%s' "$override" > "$tmp/etc/board.conf"

    run_board "$tmp" bash -c '
        set -euo pipefail
        id() { echo 0; }
        calls="$1"; shift
        systemctl() { printf "%s\n" "$*" >> "$calls"; }
        source "$1"
        main --install --enable-only
        main --install --enable-only
    ' _ "$tmp/calls" "$BOARD_SCRIPT" >/dev/null

    assert_eq "$(cat "$tmp/etc/board.conf")" "${override%$'\n'}" "user override preserved"
    assert_eq "$(wc -l < "$tmp/calls" | tr -d ' ')" "2" "two systemctl calls"
    assert_eq "$(tail -n 1 "$tmp/calls")" "enable awesome-board-health.timer" "enable-only unit call"
    assert_file_mode "$tmp/lib/awesome-board-health" "755"
    assert_not_contains "$(cat "$tmp/units/awesome-board-health.service")" "python" "unit runs bash directly"
}

test_sensor_labels_and_invalid_config() {
    local tmp
    tmp="$(mktemp -d)"
    trap 'trap - RETURN EXIT; [[ -n "${tmp:-}" ]] && rm -rf -- "$tmp"' RETURN EXIT
    setup_fixture "$tmp"

    mkdir -p "$tmp/hwmon/hwmon93"
    printf 'asusec\n'  > "$tmp/hwmon/hwmon93/name"
    printf 'Chipset\n' > "$tmp/hwmon/hwmon93/temp5_label"
    printf '83000\n'   > "$tmp/hwmon/hwmon93/temp5_input"
    printf 'VRM\n'     > "$tmp/hwmon/hwmon93/temp2_label"
    printf '61000\n'   > "$tmp/hwmon/hwmon93/temp2_input"
    printf 'Water_In\n' > "$tmp/hwmon/hwmon93/temp9_label"
    printf -- '-40000\n' > "$tmp/hwmon/hwmon93/temp9_input"
    printf 'CPU_Opt\n' > "$tmp/hwmon/hwmon93/fan8_label"
    printf '0\n'       > "$tmp/hwmon/hwmon93/fan8_input"

    local out
    out="$(run_board "$tmp" bash "$BOARD_SCRIPT" --status)"
    assert_contains "$out" "asusec:Chipset: 83.0 C"
    assert_contains "$out" "asusec:VRM: 61.0 C"
    assert_not_contains "$out" "Water_In"
    assert_contains "$out" "CPU_Opt=0"
    assert_contains "$out" "k10temp:Tctl: unavailable C"

    mkdir -p "$tmp/etc"
    local bad rc
    for bad in $'[temperature]\ncpux=80\n' $'[temperature]\nchipset=500\n' $'[wrong]\ncpu=80\n'; do
        printf '%s' "$bad" > "$tmp/etc/board.conf"
        rc=0
        run_board "$tmp" bash "$BOARD_SCRIPT" --status >/dev/null 2>&1 || rc=$?
        assert_ne "$rc" "0" "invalid config rejected"
    done
}

test_alarm_hysteresis_repeat_and_disappearing_nvme() {
    local tmp
    tmp="$(mktemp -d)"
    trap 'trap - RETURN EXIT; [[ -n "${tmp:-}" ]] && rm -rf -- "$tmp"' RETURN EXIT
    setup_fixture "$tmp"

    mkdir -p "$tmp/hwmon/hwmon1" "$tmp/hwmon/hwmon2" "$tmp/nvme0"
    ln -s "$tmp/nvme0" "$tmp/hwmon/hwmon2/device"
    printf 'asusec\n'  > "$tmp/hwmon/hwmon1/name"
    printf 'Chipset\n' > "$tmp/hwmon/hwmon1/temp1_label"
    printf '50000\n'   > "$tmp/hwmon/hwmon1/temp1_input"
    printf 'VRM\n'     > "$tmp/hwmon/hwmon1/temp2_label"
    printf '50000\n'   > "$tmp/hwmon/hwmon1/temp2_input"
    mkdir -p "$tmp/hwmon/hwmon3"
    printf 'k10temp\n' > "$tmp/hwmon/hwmon3/name"
    printf 'Tctl\n'    > "$tmp/hwmon/hwmon3/temp1_label"
    printf '50000\n'   > "$tmp/hwmon/hwmon3/temp1_input"
    printf 'nvme\n'    > "$tmp/hwmon/hwmon2/name"

    local out
    # Transient spike (1 sample at 71 C -> no <4> warning)
    printf '71000\n' > "$tmp/hwmon/hwmon2/temp1_input"
    out="$(BOARD_HEALTH_NOW=0 run_board "$tmp" bash "$BOARD_SCRIPT" --check)"
    assert_not_contains "$out" "<4>"

    # Cool again at 65 C -> no events
    printf '65000\n' > "$tmp/hwmon/hwmon2/temp1_input"
    out="$(BOARD_HEALTH_NOW=60 run_board "$tmp" bash "$BOARD_SCRIPT" --check)"
    assert_not_contains "$out" "<4>"

    # Two consecutive hot samples -> <4> warning on second sample
    printf '72000\n' > "$tmp/hwmon/hwmon2/temp1_input"
    BOARD_HEALTH_NOW=120 run_board "$tmp" bash "$BOARD_SCRIPT" --check >/dev/null
    printf '73000\n' > "$tmp/hwmon/hwmon2/temp1_input"
    out="$(BOARD_HEALTH_NOW=180 run_board "$tmp" bash "$BOARD_SCRIPT" --check)"
    assert_contains "$out" "<4>nvme:nvme0: 73.0 C"

    # Hysteresis at 69 C (limit 70, hysteresis 3 -> >= 67 holds alarm without repeating)
    printf '69000\n' > "$tmp/hwmon/hwmon2/temp1_input"
    out="$(BOARD_HEALTH_NOW=240 run_board "$tmp" bash "$BOARD_SCRIPT" --check)"
    assert_not_contains "$out" "<4>"
    assert_not_contains "$out" "<6>nvme:nvme0: recovered"

    # Repeat after 1800s (180 + 1800 = 1980)
    printf '72000\n' > "$tmp/hwmon/hwmon2/temp1_input"
    out="$(BOARD_HEALTH_NOW=1980 run_board "$tmp" bash "$BOARD_SCRIPT" --check)"
    assert_contains "$out" "<4>nvme:nvme0:"

    # Recovery at 66 C (< 67 C)
    printf '66000\n' > "$tmp/hwmon/hwmon2/temp1_input"
    out="$(BOARD_HEALTH_NOW=2040 run_board "$tmp" bash "$BOARD_SCRIPT" --check)"
    assert_contains "$out" "<6>nvme:nvme0: recovered, 66.0 C"

    # Disappearing NVMe warns after 2 samples instead of vanishing silently
    rm -rf "$tmp/hwmon/hwmon2"
    out="$(BOARD_HEALTH_NOW=2100 run_board "$tmp" bash "$BOARD_SCRIPT" --check)"
    assert_not_contains "$out" "<4>nvme:nvme0"
    out="$(BOARD_HEALTH_NOW=2160 run_board "$tmp" bash "$BOARD_SCRIPT" --check)"
    assert_contains "$out" "<4>nvme:nvme0: sensor unavailable"
}

run_test "exact DMI match excludes non-Alpha and missing DMI" test_exact_dmi_match
run_test "unsupported board check and install are no-ops" test_unsupported_install_and_check_noop
run_test "chroot install enables timer only and preserves overrides" test_chroot_install_preserves_thresholds
run_test "sensor labels parsed and invalid configs rejected" test_sensor_labels_and_invalid_config
run_test "alarm spike, hysteresis, repeat, recovery, and missing NVMe" test_alarm_hysteresis_repeat_and_disappearing_nvme

finish_test_file "test_board_health.sh"
