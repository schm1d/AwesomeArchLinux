#!/usr/bin/env bash
set -euo pipefail

# References: https://docs.kernel.org/admin-guide/sysctl/
#             https://www.freedesktop.org/software/systemd/man/latest/systemd-sysctl.html

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly CORE_FILE="60-awesome-security-core.conf"
readonly NETWORK_FILE="70-awesome-workstation-network.conf"
readonly PERFORMANCE_FILE="80-awesome-performance.conf"
readonly BBR_MODULE_SOURCE="80-awesome-bbr.modules"
readonly STRICT_FILE="90-awesome-strict.conf"
readonly IPV6_DISABLED_FILE="90-awesome-ipv6-disabled.conf"

readonly -a MANAGED_SYSCTL_FILES=(
    "$CORE_FILE"
    "$NETWORK_FILE"
    "$PERFORMANCE_FILE"
    "$STRICT_FILE"
    "$IPV6_DISABLED_FILE"
)
readonly -a LEGACY_PROFILE_FILES=(
    "99-workstation-net.conf"
    "99-full-performance.conf"
)

PROFILE=""
TARGET_ROOT="/"
DISABLE_IPV6=false
APPLY_SETTINGS=true
DRY_RUN=false

usage() {
    cat <<EOF
Usage: $0 PROFILE [OPTIONS]

Install an AwesomeArchLinux sysctl profile.

Profiles:
  workstation   Compatible security baseline; IPv6 and io_uring stay enabled
  strict        Workstation baseline plus compatibility-breaking restrictions
  performance   Workstation baseline plus fq + BBR and MTU black-hole probing

Options:
  --disable-ipv6  Install the explicit IPv6-disable overlay
  --no-apply      Install files without changing the running kernel
  --root PATH     Install below PATH; requires --no-apply
  --dry-run       Validate and print the selected files without writing
  -h, --help      Show this help

Deprecated profile aliases are accepted for installer compatibility:
  security -> strict, security-performance -> performance,
  full-performance -> performance
EOF
}

die() {
    printf 'Error: %s\n' "$1" >&2
    exit 1
}

warn() {
    printf 'Warning: %s\n' "$1" >&2
}

canonicalize_profile() {
    case "$1" in
        workstation|strict|performance)
            printf '%s\n' "$1"
            ;;
        security)
            warn "profile 'security' is deprecated; using 'strict'"
            printf '%s\n' "strict"
            ;;
        security-performance|security+performance|full-performance)
            warn "profile '$1' is deprecated; using 'performance'"
            printf '%s\n' "performance"
            ;;
        *)
            die "unknown profile '$1'"
            ;;
    esac
}

while (($# > 0)); do
    case "$1" in
        --disable-ipv6)
            DISABLE_IPV6=true
            shift
            ;;
        --no-apply)
            APPLY_SETTINGS=false
            shift
            ;;
        --root)
            (($# >= 2)) || die "--root requires an absolute path"
            TARGET_ROOT="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=true
            APPLY_SETTINGS=false
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --*)
            die "unknown option '$1'"
            ;;
        *)
            [[ -z "$PROFILE" ]] || die "only one profile may be selected"
            PROFILE="$1"
            shift
            ;;
    esac
done

[[ -n "$PROFILE" ]] || {
    usage >&2
    exit 2
}
PROFILE="$(canonicalize_profile "$PROFILE")"

[[ "$TARGET_ROOT" == /* ]] || die "--root must be an absolute path"
[[ -d "$TARGET_ROOT" ]] || die "target root does not exist: $TARGET_ROOT"
TARGET_ROOT="$(realpath -e -- "$TARGET_ROOT")"

if [[ "$TARGET_ROOT" != "/" && "$APPLY_SETTINGS" == true ]]; then
    die "--root may only be used with --no-apply"
fi
if [[ "$DRY_RUN" == false && "$TARGET_ROOT" == "/" && $EUID -ne 0 ]]; then
    die "run as root when installing into /"
fi

declare -a SELECTED_FILES=("$CORE_FILE" "$NETWORK_FILE")
case "$PROFILE" in
    strict)
        SELECTED_FILES+=("$STRICT_FILE")
        ;;
    performance)
        SELECTED_FILES+=("$PERFORMANCE_FILE")
        ;;
esac
if [[ "$DISABLE_IPV6" == true ]]; then
    SELECTED_FILES+=("$IPV6_DISABLED_FILE")
fi

validate_config() {
    local file="$1"

    [[ -f "$file" ]] || die "missing profile component: $file"
    awk '
        /^[[:space:]]*($|#|;)/ { next }
        {
            line = $0
            sub(/^[[:space:]]*-/, "", line)
            if (line !~ /^[[:alnum:]_.\/*-]+[[:space:]]*=/) {
                printf "%s:%d: invalid assignment: %s\n", FILENAME, FNR, $0 > "/dev/stderr"
                bad = 1
                next
            }
            key = line
            sub(/[[:space:]]*=.*/, "", key)
            if (seen[key]++) {
                printf "%s:%d: duplicate key: %s\n", FILENAME, FNR, key > "/dev/stderr"
                bad = 1
            }
        }
        END { exit bad }
    ' "$file" || die "invalid sysctl profile component: $file"
}

for component in "${SELECTED_FILES[@]}"; do
    validate_config "$SCRIPT_DIR/$component"
done
if [[ "$PROFILE" == "performance" ]]; then
    [[ -f "$SCRIPT_DIR/$BBR_MODULE_SOURCE" ]] || \
        die "missing profile component: $SCRIPT_DIR/$BBR_MODULE_SOURCE"
fi

if [[ "$DRY_RUN" == true ]]; then
    printf 'Profile: %s\n' "$PROFILE"
    printf 'Target:  %s\n' "$TARGET_ROOT"
    printf 'Apply:   no (dry-run)\n'
    printf 'Files:\n'
    printf '  %s\n' "${SELECTED_FILES[@]}"
    if [[ "$PROFILE" == "performance" ]]; then
        printf '  %s -> /etc/modules-load.d/80-awesome-bbr.conf\n' "$BBR_MODULE_SOURCE"
    fi
    if sysctl --help 2>&1 | grep -q -- '--dry-run'; then
        for component in "${SELECTED_FILES[@]}"; do
            sysctl --dry-run --ignore --load "$SCRIPT_DIR/$component" >/dev/null
        done
    else
        warn "installed sysctl lacks --dry-run; structural validation only"
    fi
    exit 0
fi

if [[ "$PROFILE" == "performance" && "$APPLY_SETTINGS" == true ]]; then
    command -v modprobe >/dev/null 2>&1 || die "modprobe is required for BBR"
    modprobe tcp_bbr || die "the running kernel cannot load tcp_bbr"
fi

readonly SYSCTL_DIR="${TARGET_ROOT%/}/etc/sysctl.d"
readonly MODULES_DIR="${TARGET_ROOT%/}/etc/modules-load.d"
install -d -m 0755 -- "$SYSCTL_DIR" "$MODULES_DIR"

backup_path() {
    local path="$1"
    local candidate="${path}.awesomearchlinux-legacy"
    local suffix=1

    while [[ -e "$candidate" || -L "$candidate" ]]; do
        candidate="${path}.awesomearchlinux-legacy.${suffix}"
        ((suffix += 1))
    done
    printf '%s\n' "$candidate"
}

move_legacy_file() {
    local path="$1"
    local backup

    [[ -e "$path" || -L "$path" ]] || return 0
    [[ ! -d "$path" ]] || die "refusing to replace directory: $path"
    backup="$(backup_path "$path")"
    mv -- "$path" "$backup"
    warn "moved legacy configuration to $backup"
}

for legacy_name in "${LEGACY_PROFILE_FILES[@]}"; do
    move_legacy_file "$SYSCTL_DIR/$legacy_name"
done

legacy_monolith="$SYSCTL_DIR/99-sysctl.conf"
if [[ -f "$legacy_monolith" ]]; then
    if grep -qE '^[[:space:]]*net\.ipv4\.tcp_fack[[:space:]]*=[[:space:]]*1' "$legacy_monolith" &&
       grep -qE '^[[:space:]]*net\.ipv4\.tcp_challenge_ack_limit[[:space:]]*=[[:space:]]*2147483647' "$legacy_monolith"; then
        move_legacy_file "$legacy_monolith"
    else
        warn "$legacy_monolith is not managed by this script and may override the selected profile"
    fi
fi

for managed_name in "${MANAGED_SYSCTL_FILES[@]}"; do
    managed_path="$SYSCTL_DIR/$managed_name"
    if [[ -e "$managed_path" || -L "$managed_path" ]]; then
        [[ ! -d "$managed_path" ]] || die "refusing to replace directory: $managed_path"
        rm -- "$managed_path"
    fi
done

for component in "${SELECTED_FILES[@]}"; do
    install -m 0644 -- "$SCRIPT_DIR/$component" "$SYSCTL_DIR/$component"
done

bbr_module_target="$MODULES_DIR/80-awesome-bbr.conf"
if [[ "$PROFILE" == "performance" ]]; then
    install -m 0644 -- "$SCRIPT_DIR/$BBR_MODULE_SOURCE" "$bbr_module_target"
elif [[ -e "$bbr_module_target" || -L "$bbr_module_target" ]]; then
    [[ ! -d "$bbr_module_target" ]] || die "refusing to replace directory: $bbr_module_target"
    rm -- "$bbr_module_target"
fi

if [[ "$APPLY_SETTINGS" == true ]]; then
    if [[ -x /usr/lib/systemd/systemd-sysctl ]]; then
        /usr/lib/systemd/systemd-sysctl
    else
        warn "systemd-sysctl not found; falling back to procps sysctl"
        sysctl --ignore --system
    fi
fi

if [[ "$APPLY_SETTINGS" == true && "$PROFILE" != "strict" ]]; then
    declare -a irreversible_runtime_controls=()
    if [[ "$(sysctl -n kernel.unprivileged_bpf_disabled 2>/dev/null || true)" == "1" ]]; then
        irreversible_runtime_controls+=("kernel.unprivileged_bpf_disabled=1")
    fi
    if [[ "$(sysctl -n kernel.kexec_load_disabled 2>/dev/null || true)" == "1" ]]; then
        irreversible_runtime_controls+=("kernel.kexec_load_disabled=1")
    fi
    if ((${#irreversible_runtime_controls[@]} > 0)); then
        warn "one-way strict controls remain active until reboot: ${irreversible_runtime_controls[*]}"
    fi
fi

printf 'Installed AwesomeArchLinux sysctl profile: %s\n' "$PROFILE"
if [[ "$DISABLE_IPV6" == true ]]; then
    printf 'IPv6 policy: disabled by explicit overlay\n'
else
    printf 'IPv6 policy: enabled and hardened\n'
fi
if [[ "$APPLY_SETTINGS" == false ]]; then
    printf 'Settings will take effect at the next boot.\n'
fi
