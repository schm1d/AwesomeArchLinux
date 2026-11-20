#!/usr/bin/env bash

# =============================================================================
# Script:      wordpress.sh
# Description: Hardens an existing WordPress installation on Arch Linux,
#              targeting:
#                - wp-config.php security constants and salts
#                - Strict file permissions (root:http ownership)
#                - Hardened nginx server block with PHP-FPM
#                - fail2ban jails for wp-login.php and xmlrpc.php
#                - PHP .user.ini hardening
#                - systemd-based wp-cron replacement
#                - Privilege-separated updates (the code stays read-only for PHP)
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
#
# Usage:       sudo ./wordpress.sh -d DOMAIN -w WP_PATH [--db-name DB]
#                                  [--db-user USER] [--db-host HOST]
#                                  [--fresh-install]
#                                  [--auto-update all|core|off] [-h]
#
# Requirements:
#   - Arch Linux with pacman
#   - Root privileges
#   - An existing WordPress installation (this script does NOT install WordPress)
#   - nginx-mainline installed (see ../nginx/nginx.sh)
#   - PHP-FPM installed and running
#   - wp-cli for updates (optional; without it the update timer stays off)
#
# What this script does:
#   1. Verifies WordPress exists at WP_PATH
#   2. Hardens wp-config.php (security constants, salts, table prefix)
#   3. Sets strict file permissions (root:http, 640/750)
#   4. Writes a hardened nginx server block with PHP-FPM
#   5. Creates fail2ban jails for wp-login.php and xmlrpc.php
#   6. Creates .user.ini for PHP runtime hardening
#   7. Replaces wp-cron with a systemd timer
#   8. Sets up updates: /usr/local/bin/awesome-wordpress-update and a daily timer
#   9. Prints a security summary and checklist
# =============================================================================

set -euo pipefail
umask 022

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck disable=SC1090,SC1091
source "$SCRIPT_DIR/../lib/validation.sh"

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
DOMAIN=""
WP_PATH="/var/www/wordpress"
DB_NAME="wordpress"
DB_USER="wpuser"
DB_HOST="localhost"
DB_NAME_SET=false
DB_USER_SET=false
DB_HOST_SET=false
FRESH_INSTALL=false
AUTO_UPDATE="all"
WP_BACKUP_ROOT="/var/backups/wordpress-hardening"
# The code is owned by root and read-only for PHP. Updates are applied by
# $UPDATE_HELPER, which hands the code to $WP_UPDATE_USER for the duration of
# a wp-cli run and seals it again; it also implements the permission model of
# step 3.
UPDATE_HELPER="/usr/local/bin/awesome-wordpress-update"
WP_UPDATE_USER="wp-update"
LOGFILE="/var/log/wordpress-hardening-$(date +%Y%m%d-%H%M%S).log"

# --- Usage ---
usage() {
    cat <<EOF
Usage: sudo $0 [options]

Required:
  -d DOMAIN         Domain name for the WordPress site

Optional:
  -w WP_PATH        WordPress installation path (default: $WP_PATH)
  --db-name DB      Database name (default: $DB_NAME)
  --db-user USER    Database user (default: $DB_USER)
  --db-host HOST    Database host (default: $DB_HOST)
  --fresh-install   Randomize \$table_prefix even if DB credentials are already set
  --auto-update MODE
                    What the daily update timer applies (default: $AUTO_UPDATE):
                      all   core (minor releases), plugins and themes
                      core  core (minor releases) only
                      off   nothing; run $UPDATE_HELPER by hand
  -h                Show this help

Examples:
  sudo $0 -d example.com
  sudo $0 -d example.com -w /srv/http/wordpress
  sudo $0 -d blog.example.com --db-name wpblog --db-user bloguser
  sudo $0 -d example.com --auto-update core
EOF
    exit 0
}

# --- Parse Arguments ---
need_arg() { [[ $# -ge 2 && -n "${2:-}" ]] || err "Option $1 requires a value"; }
while [[ $# -gt 0 ]]; do
    case "$1" in
        -d)              need_arg "$@"; DOMAIN="$2"; shift 2 ;;
        -w)              need_arg "$@"; WP_PATH="$2"; shift 2 ;;
        --db-name)       need_arg "$@"; DB_NAME="$2"; DB_NAME_SET=true; shift 2 ;;
        --db-user)       need_arg "$@"; DB_USER="$2"; DB_USER_SET=true; shift 2 ;;
        --db-host)       need_arg "$@"; DB_HOST="$2"; DB_HOST_SET=true; shift 2 ;;
        --fresh-install) FRESH_INSTALL=true; shift ;;
        --auto-update)
            need_arg "$@"
            case "$2" in
                all|core|off) AUTO_UPDATE="$2" ;;
                *)            err "Invalid --auto-update value: $2 (use all, core or off)" ;;
            esac
            shift 2 ;;
        -h|--help)       usage ;;
        *)               err "Unknown option: $1" ;;
    esac
done

# --- Validate ---
[[ $(id -u) -eq 0 ]] || err "Must be run as root"
[[ -n "$DOMAIN" ]]   || err "Domain is required (-d example.com)"
DOMAIN="${DOMAIN,,}"
aal_valid_hostname "$DOMAIN" || err "Invalid domain name: $DOMAIN"
[[ "$DB_NAME" =~ ^[A-Za-z0-9_$-]{1,64}$ ]] || err "Invalid database name: $DB_NAME"
[[ "$DB_USER" =~ ^[A-Za-z0-9_.-]{1,64}$ ]] || err "Invalid database user: $DB_USER"
[[ "$DB_HOST" =~ ^[\[\]A-Za-z0-9_.:/-]{1,253}$ ]] || err "Invalid database host: $DB_HOST"
command -v nginx &>/dev/null || err "nginx is not installed. Run ../nginx/nginx.sh first or: pacman -S nginx-mainline"

[[ -d "$WP_PATH" ]] || err "WordPress directory does not exist: $WP_PATH"
WP_PATH=$(realpath -- "$WP_PATH") || err "Could not resolve WordPress path"
case "$WP_PATH" in
    /var/www/*|/srv/http/*) ;;
    *) err "Unsafe WordPress path '$WP_PATH'. Use a dedicated directory below /var/www/ or /srv/http/." ;;
esac
[[ "$WP_PATH" =~ ^/(var/www|srv/http)/[A-Za-z0-9._/-]+$ ]] || \
    err "WordPress path contains unsupported characters: $WP_PATH"
# Root-only backups live outside every served directory, one tree per site.
WP_BACKUP_DIR="$WP_BACKUP_ROOT$WP_PATH"

# =============================================================================
# UPDATE HELPER (installed by step 3, scheduled by step 8)
# =============================================================================

# Install $UPDATE_HELPER. It is replaced as a new file, so a run that the
# update timer started keeps reading the copy it opened.
install_update_helper() {
    install -d -o root -g root -m 0755 "${UPDATE_HELPER%/*}"
    install -o root -g root -m 0755 /dev/stdin "$UPDATE_HELPER" <<'WP_UPDATE_HELPER'
#!/usr/bin/env bash
# =============================================================================
# awesome-wordpress-update
# Generated by AwesomeArchLinux/hardening/wordpress/wordpress.sh
#
# Applies WordPress updates to an installation whose code is owned by root and
# read-only for PHP. PHP-FPM (http) never gets write access to the code:
#
#   1. Pending updates are looked up without write access.
#   2. Only when there is something to apply, the code is handed to the locked
#      account wp-update, and wp-cli runs as that account in a transient
#      systemd unit that can write to the installation and nowhere else.
#      Plugins and themes are not loaded while it runs.
#   3. The root:http read-only permissions are restored, also when an update
#      fails or the run is interrupted.
#
# wordpress.sh applies its permission model through "--seal" of this helper,
# so hardening and updates share one implementation.
# =============================================================================

set -euo pipefail

PATH=/usr/local/sbin:/usr/local/bin:/usr/bin
export PATH

SEAL_OWNER="root"        # owns the code at rest
WEB_USER="http"          # PHP-FPM and nginx; owns uploads/ and cache/
WEB_GROUP="http"         # may read the code
UPDATE_USER="wp-update"  # owns the code while an update is applied
PATH_RE='^/(var/www|srv/http)/[A-Za-z0-9._/-]+$'
LOCK_DIR="/run"
LOCK_WAIT=900
PHP_CONF_DIR="/etc/php"
PHP_FPM_UNIT="php-fpm.service"

WP_PATH=""
ALLOW_MAJOR=false
CORE_ONLY=false
WINDOW_OPEN=false
RUN_UNIT=""
RUN_SEQ=0
WP_CMD=()
WP_ENV=()

wpu_log()  { printf '[*] %s\n' "$*"; }
wpu_warn() { printf '[!] %s\n' "$*" >&2; }
wpu_die()  { printf '[!] %s\n' "$*" >&2; exit 1; }

wpu_usage() {
    cat <<'USAGE'
Usage: awesome-wordpress-update -w WP_PATH [--major] [--core-only]
       awesome-wordpress-update -w WP_PATH -- WP_CLI_COMMAND...
       awesome-wordpress-update -w WP_PATH --seal

Without a command, pending updates are applied: WordPress core, plugins,
themes and their translations. Core stays on its release branch (6.8.1 ->
6.8.2) unless --major is given.

  -w WP_PATH    WordPress installation (below /var/www/ or /srv/http/)
  --major       Also apply a new major core release (6.8 -> 6.9)
  --core-only   Leave plugins and themes alone
  -- COMMAND    Run one wp-cli command with write access to the code instead,
                for example: -- plugin install akismet --activate
  --seal        Only restore the read-only permissions
  -h            Show this help

The code is writable only while a command runs, and only for the account
wp-update. Plugins and themes are not loaded by wp-cli (--skip-plugins
--skip-themes).
USAGE
}

wpu_validate_path() {
    [[ -n "$WP_PATH" ]] || wpu_die "A WordPress path is required (-w /var/www/wordpress)"
    [[ -d "$WP_PATH" ]] || wpu_die "WordPress directory does not exist: $WP_PATH"
    WP_PATH=$(realpath -- "$WP_PATH") || wpu_die "Could not resolve the WordPress path"
    [[ "$WP_PATH" =~ $PATH_RE ]] || \
        wpu_die "Unsafe WordPress path '$WP_PATH': use a dedicated directory below /var/www/ or /srv/http/"
    [[ -f "$WP_PATH/wp-config.php" || -d "$WP_PATH/wp-includes" ]] || \
        wpu_die "Not a WordPress installation: $WP_PATH (missing wp-config.php and wp-includes/)"
}

# One run per installation at a time: a second run (or "--seal" from
# wordpress.sh) waits for the first instead of sealing a tree mid-update.
wpu_lock() {
    exec 9> "$LOCK_DIR/awesome-wordpress-update${WP_PATH//\//-}.lock"
    flock -w "$LOCK_WAIT" 9 || wpu_die "Another awesome-wordpress-update run still holds the lock for $WP_PATH"
}

# Restore the permission model. Symbolic links are never followed.
#   code                 root:http   directories 750, files 640
#   uploads/ and cache/  http:http   directories 770, files 660
wpu_seal() {
    local wp="$1" sub dir rc=0
    local -a writable=(-path "$wp/wp-content/uploads" -o -path "$wp/wp-content/cache")

    if [[ ! -e "$wp/wp-content/uploads" && ! -L "$wp/wp-content/uploads" ]]; then
        mkdir -p -- "$wp/wp-content/uploads" || rc=1
    fi

    # http cannot write to a directory outside uploads/ and cache/, and no
    # wp-update process is left when this runs, so nothing can swap a path
    # under find. Only entries that deviate are touched: a tree that is already
    # sealed keeps its timestamps.
    find "$wp" \( "${writable[@]}" \) -prune -o \
        \( ! -user "$SEAL_OWNER" -o ! -group "$WEB_GROUP" \) \
        -exec chown -h "$SEAL_OWNER:$WEB_GROUP" -- {} + || rc=1
    find "$wp" \( "${writable[@]}" \) -prune -o \
        -type d ! -perm 0750 -exec chmod 0750 -- {} + || rc=1
    find "$wp" \( "${writable[@]}" \) -prune -o \
        -type f ! -perm 0640 -exec chmod 0640 -- {} + || rc=1

    for sub in uploads cache; do
        dir="$wp/wp-content/$sub"
        if [[ -L "$dir" ]]; then
            wpu_warn "$dir is a symbolic link: its target is left as it is"
            continue
        fi
        [[ -d "$dir" ]] || continue
        # http can write here at any time. chown -R and chmod -R walk the tree
        # themselves and do not follow an entry that is swapped for a symbolic
        # link, which a find/chmod pair would.
        chown -R "$WEB_USER:$WEB_GROUP" -- "$dir" || rc=1
        chmod -R a-x,u=rwX,g=rwX,o= -- "$dir" || rc=1
    done
    return "$rc"
}

# Hand the code (not uploads/ or cache/) to $UPDATE_USER. The group stays
# http and the modes stay 750/640, so PHP-FPM keeps reading and still cannot
# write.
wpu_open_window() {
    WINDOW_OPEN=true
    find "$WP_PATH" \( -path "$WP_PATH/wp-content/uploads" -o -path "$WP_PATH/wp-content/cache" \) -prune -o \
        ! -user "$UPDATE_USER" -exec chown -h "$UPDATE_USER" -- {} +
}

# PHP-FPM keeps serving the old code from its opcache when timestamp
# validation is switched off; a reload makes it pick up the update.
wpu_reload_php() {
    [[ -d "$PHP_CONF_DIR" ]] || return 0
    if grep -rEqis '^[[:space:]]*(php_admin_(value|flag)\[)?opcache\.validate_timestamps\]?[[:space:]]*=[[:space:]]*"?(0|off|false|no)"?[[:space:]]*(;.*)?$' "$PHP_CONF_DIR"; then
        systemctl try-reload-or-restart "$PHP_FPM_UNIT" || \
            wpu_warn "Could not reload $PHP_FPM_UNIT: restart it to serve the updated code"
    fi
}

wpu_close_window() {
    local rc=0
    if ! wpu_seal "$WP_PATH"; then
        wpu_warn "Could not restore every permission below $WP_PATH; run: awesome-wordpress-update -w $WP_PATH --seal"
        rc=1
    fi
    WINDOW_OPEN=false
    wpu_reload_php
    return "$rc"
}

wpu_on_exit() {
    local rc=$?
    trap - EXIT
    if [[ -n "$RUN_UNIT" ]]; then
        # The wp-cli unit outlives an interrupted systemd-run: stop it before
        # the permissions are restored underneath it.
        systemctl stop "$RUN_UNIT" 2>/dev/null || true
    fi
    if [[ "$WINDOW_OPEN" == true ]]; then
        wpu_warn "The run did not finish: restoring the read-only permissions of $WP_PATH"
        if ! wpu_seal "$WP_PATH"; then
            wpu_warn "Could not restore every permission below $WP_PATH; run: awesome-wordpress-update -w $WP_PATH --seal"
            (( rc != 0 )) || rc=1
        fi
        WINDOW_OPEN=false
    fi
    exit "$rc"
}

# A run that was killed outright (SIGKILL, power loss) leaves the code owned
# by $UPDATE_USER. PHP-FPM still cannot write it; put root back in charge.
wpu_recover() {
    local leftover
    leftover=$(find "$WP_PATH" \( -path "$WP_PATH/wp-content/uploads" -o -path "$WP_PATH/wp-content/cache" \) -prune -o \
        -user "$UPDATE_USER" -print -quit)
    [[ -n "$leftover" ]] || return 0
    wpu_warn "An earlier run did not finish: restoring the read-only permissions of $WP_PATH"
    wpu_seal "$WP_PATH"
}

# True when $1 is owned by root and not writable by group or others.
wpu_root_owned() {
    local owner_mode
    owner_mode=$(stat -c '%u %a' -- "$1") || return 1
    [[ "${owner_mode% *}" == 0 ]] && (( (0${owner_mode#* } & 022) == 0 ))
}

# wp-cli runs with write access to the code, so it has to be root's own copy.
# php.ini restrictions written by ../php/php.sh (open_basedir, disable_functions)
# also apply to the PHP CLI and would stop wp-cli from starting or downloading;
# they are lifted for this trusted command only. The sandbox in wpu_wp still
# confines it.
wpu_resolve_wp_cli() {
    local wp_bin php_bin real first_line=""
    local -a php_args=(-d open_basedir= -d disable_functions=)

    wp_bin=$(command -v wp 2>/dev/null || true)
    [[ "$wp_bin" == /* && -x "$wp_bin" ]] || \
        wpu_die "wp-cli (wp) is not installed. Install it as root, for example to /usr/local/bin/wp (https://wp-cli.org/#installing)"
    real=$(realpath -- "$wp_bin") || wpu_die "Could not resolve $wp_bin"
    case "$real" in
        /root/*|/home/*|/run/user/*|/tmp/*|/var/tmp/*)
            wpu_die "wp-cli at $real cannot be reached from the update sandbox: install it below /usr/local/bin or /usr/bin" ;;
    esac
    wpu_root_owned "$real" || \
        wpu_die "wp-cli at $real must be owned by root and not writable by group or others"

    php_bin=$(command -v php 2>/dev/null || true)
    IFS= read -r first_line < "$real" 2>/dev/null || true
    if [[ "$php_bin" == /* && "$first_line" == '#!'*php* ]]; then
        # A PHP script or phar: start it through php with the overrides.
        WP_CMD=("$php_bin" "${php_args[@]}" "$real")
        WP_ENV=()
    else
        # A wrapper starts php itself; wp-cli's own wrapper passes
        # WP_CLI_PHP_ARGS on to it.
        WP_CMD=("$real")
        WP_ENV=(-E "WP_CLI_PHP_ARGS=${php_args[*]}")
    fi
}

wpu_require_runtime() {
    getent passwd "$UPDATE_USER" >/dev/null || \
        wpu_die "The account $UPDATE_USER does not exist: run wordpress.sh for this site first"
    command -v systemd-run >/dev/null || wpu_die "systemd-run not found"
    wpu_resolve_wp_cli
}

# Run wp-cli as $UPDATE_USER in a transient systemd unit. $1 is "ro" (nothing
# on disk is writable) or "rw" (the installation is writable, nothing else).
# Plugin and theme code is never loaded: it could have been tampered with
# through the database or uploads/ and would run with write access here.
wpu_wp() {
    local access="$1" rc=0
    shift
    local -a unit=(
        --quiet --wait --collect --pipe --expand-environment=no
        -p "User=$UPDATE_USER" -p "Group=$WEB_GROUP" -p UMask=0027
        -p NoNewPrivileges=yes -p CapabilityBoundingSet=
        -p ProtectSystem=strict -p ProtectHome=yes
        -p PrivateTmp=yes -p PrivateDevices=yes
        -p ProtectKernelTunables=yes -p ProtectKernelModules=yes
        -p ProtectControlGroups=yes -p RestrictSUIDSGID=yes -p LockPersonality=yes
        -p "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK"
        -p RuntimeMaxSec=3600
        -E WP_CLI_CACHE_DIR=/tmp/wp-cli-cache
    )
    if [[ "$access" == rw ]]; then
        RUN_SEQ=$(( RUN_SEQ + 1 ))
        RUN_UNIT="awesome-wordpress-update-$$-$RUN_SEQ.service"
        unit+=(--unit="$RUN_UNIT" -p "ReadWritePaths=$WP_PATH")
    fi
    systemd-run "${unit[@]}" "${WP_ENV[@]}" -- "${WP_CMD[@]}" \
        --path="$WP_PATH" --skip-plugins --skip-themes --no-color "$@" </dev/null || rc=$?
    RUN_UNIT=""
    return "$rc"
}

# Print one line per pending update: "core VERSION" (in scope), "major VERSION"
# (needs --major), "plugin NAME", "theme NAME". Nothing is writable meanwhile.
wpu_pending() {
    local out version release kind name rc=0

    if out=$(wpu_wp ro core check-update --fields=version,update_type --format=csv); then
        while IFS=, read -r version release _; do
            # Skips the CSV header and the "at the latest version" message.
            [[ "$version" =~ ^[0-9]+(\.[0-9]+)+ ]] || continue
            if [[ "$release" == minor || "$ALLOW_MAJOR" == true ]]; then
                printf 'core %s\n' "$version"
            else
                printf 'major %s\n' "$version"
            fi
        done <<< "$out"
    else
        rc=1
    fi

    if [[ "$CORE_ONLY" == false ]]; then
        for kind in plugin theme; do
            if out=$(wpu_wp ro "$kind" list --update=available --field=name); then
                while IFS= read -r name; do
                    [[ "$name" =~ ^[A-Za-z0-9._-]+$ ]] || continue
                    printf '%s %s\n' "$kind" "$name"
                done <<< "$out"
            else
                rc=1
            fi
        done
    fi
    return "$rc"
}

wpu_auto_update() {
    local out pending="" kind item
    local check_failed=false failed=false
    local want_core=false want_plugins=false want_themes=false
    local -a core_scope=(--minor)
    if [[ "$ALLOW_MAJOR" == true ]]; then
        core_scope=()
    fi

    if ! out=$(wpu_wp ro core is-installed 2>&1); then
        if [[ -n "$out" ]]; then
            printf '%s\n' "$out" >&2
            wpu_die "wp-cli could not load WordPress at $WP_PATH"
        fi
        wpu_log "WordPress is not installed yet at $WP_PATH: nothing to update"
        return 0
    fi

    pending=$(wpu_pending) || check_failed=true
    while IFS=' ' read -r kind item; do
        case "$kind" in
            core)   want_core=true ;;
            plugin) want_plugins=true ;;
            theme)  want_themes=true ;;
            major)
                wpu_log "WordPress $item is a new major release: apply it with: awesome-wordpress-update -w $WP_PATH --major"
                continue ;;
            *)      continue ;;
        esac
        wpu_log "Pending: $kind $item"
    done <<< "$pending"

    if [[ "$want_core" == false && "$want_plugins" == false && "$want_themes" == false ]]; then
        if [[ "$check_failed" == true ]]; then
            wpu_warn "The update check for $WP_PATH did not complete"
            return 1
        fi
        wpu_log "WordPress at $WP_PATH is up to date"
        return 0
    fi

    wpu_open_window
    if [[ "$want_core" == true ]]; then
        wpu_wp rw core update "${core_scope[@]}" || failed=true
        if wpu_wp ro core is-installed --network; then
            wpu_wp rw core update-db --network || failed=true
        else
            wpu_wp rw core update-db || failed=true
        fi
    fi
    if [[ "$want_plugins" == true ]]; then
        wpu_wp rw plugin update --all || failed=true
    fi
    if [[ "$want_themes" == true ]]; then
        wpu_wp rw theme update --all || failed=true
    fi
    # Translations follow the code; a failure here does not fail the run.
    wpu_wp rw language core update || wpu_warn "Core translations were not updated"
    if [[ "$CORE_ONLY" == false ]]; then
        wpu_wp rw language plugin update --all || wpu_warn "Plugin translations were not updated"
        wpu_wp rw language theme update --all || wpu_warn "Theme translations were not updated"
    fi
    wpu_close_window || failed=true

    if [[ "$failed" == true || "$check_failed" == true ]]; then
        wpu_warn "Not every update for $WP_PATH was applied; see the messages above"
        return 1
    fi
    wpu_log "Updates applied; $WP_PATH is read-only for PHP again"
}

wpu_run_command() {
    local rc=0
    wpu_open_window
    wpu_wp rw "$@" || rc=$?
    if ! wpu_close_window; then
        (( rc != 0 )) || rc=1
    fi
    return "$rc"
}

wpu_main() {
    local mode=auto
    local -a wp_command=()

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -w)
                [[ $# -ge 2 && -n "$2" ]] || wpu_die "Option -w requires a path"
                WP_PATH="$2"
                shift 2 ;;
            --major)     ALLOW_MAJOR=true; shift ;;
            --core-only) CORE_ONLY=true; shift ;;
            --seal)      mode=seal; shift ;;
            --)
                shift
                [[ $# -gt 0 ]] || wpu_die "-- must be followed by a wp-cli command"
                mode=run
                wp_command=("$@")
                break ;;
            -h|--help)   wpu_usage; exit 0 ;;
            *)           wpu_die "Unknown option: $1 (see --help)" ;;
        esac
    done

    [[ $(id -u) -eq 0 ]] || wpu_die "Must be run as root"
    wpu_validate_path
    wpu_lock

    if [[ "$mode" == seal ]]; then
        wpu_seal "$WP_PATH"
        return
    fi

    wpu_require_runtime
    trap wpu_on_exit EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    wpu_recover

    if [[ "$mode" == run ]]; then
        wpu_run_command "${wp_command[@]}"
    else
        wpu_auto_update
    fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    wpu_main "$@"
fi
WP_UPDATE_HELPER
}

# Redirect output to logfile as well
install -d -m 0755 /var/log
( umask 077 && : > "$LOGFILE" )
chmod 0600 "$LOGFILE"
exec > >(tee -a "$LOGFILE") 2>&1

info "Domain: $DOMAIN"
info "WordPress path: $WP_PATH"
info "Database: $DB_NAME@$DB_HOST (user: $DB_USER)"
info "Log: $LOGFILE"

# =============================================================================
# 1. VERIFY WORDPRESS EXISTS
# =============================================================================

msg "Verifying WordPress installation at $WP_PATH..."

if [[ ! -f "$WP_PATH/wp-config.php" && ! -d "$WP_PATH/wp-includes" ]]; then
    err "Not a WordPress installation: $WP_PATH (missing wp-config.php and wp-includes/)"
fi

if [[ -f "$WP_PATH/wp-config.php" ]]; then
    info "Found wp-config.php"
else
    warn "wp-config.php not found — skipping wp-config hardening"
fi

if [[ -d "$WP_PATH/wp-includes" ]]; then
    info "Found wp-includes/"
fi

# Detect SSL certificates BEFORE Step 2 so wp-config.php, nginx, .user.ini, and
# wp-cron all agree on HTTPS vs HTTP-only mode (preventing admin lockout).
USE_SSL=false
CERT_DIR="/etc/letsencrypt/live/$DOMAIN"
if [[ -f "$CERT_DIR/fullchain.pem" && -f "$CERT_DIR/privkey.pem" ]]; then
    USE_SSL=true
    info "SSL certificates found for $DOMAIN"
else
    warn "No SSL certificates found at $CERT_DIR — configuring HTTP-only"
    warn "Run ../nginx/nginx.sh for HTTPS setup, then re-run this script"
fi

wp_get_define_val() {
    local name="$1"
    [[ -f "$WP_PATH/wp-config.php" ]] || return 0
    WP_DEF_NAME="$name" awk -F"['\"]" '
        BEGIN {
            re = "^[[:space:]]*define[[:space:]]*\\([[:space:]]*[\x27\"]" ENVIRON["WP_DEF_NAME"] "[\x27\"]"
        }
        $0 ~ re { print $4; exit }
    ' "$WP_PATH/wp-config.php"
}

wp_db_has_placeholders() {
    [[ -f "$WP_PATH/wp-config.php" ]] || return 0
    local db_name_val db_user_val db_pass_val
    db_name_val=$(wp_get_define_val "DB_NAME")
    db_user_val=$(wp_get_define_val "DB_USER")
    db_pass_val=$(wp_get_define_val "DB_PASSWORD")
    # Only the literal wp-config-sample.php values mean "not installed yet". An
    # empty result means the define() could not be parsed (getenv(), a constant,
    # a multi-line call, ...): treating that as a placeholder would randomise
    # $table_prefix and keep install.php reachable on a live site.
    [[ "$db_name_val" == "database_name_here" || \
       "$db_user_val" == "username_here" || \
       "$db_pass_val" == "password_here" ]]
}

INITIAL_DB_PLACEHOLDER=false
if wp_db_has_placeholders; then
    INITIAL_DB_PLACEHOLDER=true
fi

# =============================================================================
# 2. WP-CONFIG.PHP HARDENING
# =============================================================================

install -d -o root -g root -m 0700 "$WP_BACKUP_ROOT" "$WP_BACKUP_DIR"

# Earlier versions of this script left wp-config.php.bak.<timestamp> copies in
# the document root, where nginx serves them as plain text. Move them out.
shopt -s nullglob
for stale_backup in "$WP_PATH"/wp-config.php.bak.*; do
    [[ -f "$stale_backup" && ! -L "$stale_backup" ]] || continue
    stale_target="$WP_BACKUP_DIR/${stale_backup##*/}"
    if [[ -e "$stale_target" ]]; then
        stale_target+=".moved-$(date +%Y%m%d-%H%M%S)"
    fi
    mv -- "$stale_backup" "$stale_target"
    chown root:root "$stale_target"
    chmod 600 "$stale_target"
    warn "Moved a wp-config.php backup out of the document root: $stale_backup -> $stale_target"
done
shopt -u nullglob
unset stale_backup stale_target

if [[ -f "$WP_PATH/wp-config.php" ]]; then
    msg "Hardening wp-config.php..."

    WP_CONFIG="$WP_PATH/wp-config.php"

    # Back up wp-config.php outside the document root. A copy next to the
    # original would be re-owned root:http 640 by Step 3 and served as plain text
    # by nginx (the name no longer ends in .php), exposing the DB credentials.
    BACKUP="$WP_BACKUP_DIR/wp-config.php.bak.$(date +%Y%m%d-%H%M%S)"
    ( umask 077 && cp -- "$WP_CONFIG" "$BACKUP" )
    chmod 600 "$BACKUP"
    info "wp-config.php backed up to $BACKUP"

    # --- Helper: add or update an active define() constant ---
    # Matches only active non-comment lines using POSIX ERE. If absent, inserts
    # before "stop editing" or before require_once ... wp-settings.php.
    wp_define() {
        local name="$1"
        local value="$2"
        local active_re="^[[:space:]]*define[[:space:]]*\\([[:space:]]*['\"]${name}['\"]"
        local tmp_cfg
        tmp_cfg=$(umask 077; mktemp "$WP_PATH/.wp-config.def.XXXXXX")

        if grep -Eq "$active_re" "$WP_CONFIG"; then
            WP_DEF_NAME="$name" WP_DEF_VAL="$value" awk '
                BEGIN {
                    re = "^[[:space:]]*define[[:space:]]*\\([[:space:]]*[\x27\"]" ENVIRON["WP_DEF_NAME"] "[\x27\"]"
                }
                !updated && $0 ~ re {
                    printf "define(\x27%s\x27, %s);\n", ENVIRON["WP_DEF_NAME"], ENVIRON["WP_DEF_VAL"]
                    updated = 1
                    next
                }
                { print }
            ' "$WP_CONFIG" > "$tmp_cfg"
            chown root:http "$tmp_cfg" 2>/dev/null || true
            chmod 0640 "$tmp_cfg"
            mv -f -- "$tmp_cfg" "$WP_CONFIG"
            info "Updated: define('${name}', ${value})"
        else
            WP_DEF_NAME="$name" WP_DEF_VAL="$value" awk '
                !inserted && (/stop editing/ || /^[[:space:]]*require(_once)?[[:space:]\(].*wp-settings\.php/) {
                    printf "define(\x27%s\x27, %s);\n", ENVIRON["WP_DEF_NAME"], ENVIRON["WP_DEF_VAL"]
                    inserted = 1
                }
                { print }
                END {
                    if (!inserted) {
                        printf "define(\x27%s\x27, %s);\n", ENVIRON["WP_DEF_NAME"], ENVIRON["WP_DEF_VAL"]
                    }
                }
            ' "$WP_CONFIG" > "$tmp_cfg"
            chown root:http "$tmp_cfg" 2>/dev/null || true
            chmod 0640 "$tmp_cfg"
            mv -f -- "$tmp_cfg" "$WP_CONFIG"
            info "Added:   define('${name}', ${value})"
        fi
    }

    # --- Apply --db-name / --db-user / --db-host when explicitly passed or still placeholder ---
    CUR_DB_NAME=$(wp_get_define_val "DB_NAME")
    CUR_DB_USER=$(wp_get_define_val "DB_USER")
    CUR_DB_HOST=$(wp_get_define_val "DB_HOST")
    if [[ "$DB_NAME_SET" == true || "$CUR_DB_NAME" == "database_name_here" ]]; then
        wp_define "DB_NAME" "'${DB_NAME}'"
    fi
    if [[ "$DB_USER_SET" == true || "$CUR_DB_USER" == "username_here" ]]; then
        wp_define "DB_USER" "'${DB_USER}'"
    fi
    if [[ "$DB_HOST_SET" == true || -z "$CUR_DB_HOST" ]]; then
        wp_define "DB_HOST" "'${DB_HOST}'"
    fi

    # --- Security constants ---
    wp_define "DISALLOW_FILE_EDIT" "true"
    wp_define "DISALLOW_FILE_MODS" "false"
    if [[ "$USE_SSL" == true ]]; then
        wp_define "FORCE_SSL_ADMIN" "true"
    else
        wp_define "FORCE_SSL_ADMIN" "false"
    fi
    wp_define "WP_AUTO_UPDATE_CORE" "'minor'"
    wp_define "WP_DEBUG" "false"
    wp_define "WP_DEBUG_DISPLAY" "false"
    wp_define "WP_DEBUG_LOG" "false"
    wp_define "CONCATENATE_SCRIPTS" "false"
    wp_define "WP_MEMORY_LIMIT" "'256M'"
    wp_define "WP_MAX_MEMORY_LIMIT" "'512M'"
    wp_define "DISABLE_WP_CRON" "true"

    # --- Generate and set security keys/salts (pure awk splice, no sed /e shell execution) ---
    msg "Fetching fresh security keys/salts from WordPress API..."

    SALTS=$(curl -fsS --max-time 10 "https://api.wordpress.org/secret-key/1.1/salt/" 2>/dev/null || true)
    SALTS_VALID=false
    if [[ -n "$SALTS" ]]; then
        SALT_LINE_COUNT=$(awk '
            /^[[:space:]]*$/ { next }
            /^define\(['\''"](AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY|AUTH_SALT|SECURE_AUTH_SALT|LOGGED_IN_SALT|NONCE_SALT)['\''"],[[:space:]]*['\''"].+['\''"]\);$/ {
                valid++
                next
            }
            { invalid = 1 }
            END { print (invalid ? 0 : valid + 0) }
        ' <<< "$SALTS")
        (( SALT_LINE_COUNT == 8 )) && SALTS_VALID=true
    fi

    if [[ "$SALTS_VALID" == true ]]; then
        WP_DIR=$(dirname -- "$WP_CONFIG")
        SALT_TMPFILE=$(umask 077; mktemp "$WP_DIR/.wp-salts.XXXXXX")
        WP_CONFIG_TMP=$(umask 077; mktemp "$WP_DIR/.wp-config.XXXXXX")
        printf '%s\n' "$SALTS" > "$SALT_TMPFILE"

        awk -v salt_file="$SALT_TMPFILE" '
            /^[[:space:]]*define[[:space:]]*\([[:space:]]*['\''"](AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY|AUTH_SALT|SECURE_AUTH_SALT|LOGGED_IN_SALT|NONCE_SALT)['\''"]/ { next }
            !inserted && (/stop editing/ || /^[[:space:]]*require(_once)?[[:space:]\(].*wp-settings\.php/) {
                while ((getline salt_line < salt_file) > 0) {
                    print salt_line
                }
                close(salt_file)
                inserted = 1
            }
            { print }
            END {
                if (!inserted) {
                    while ((getline salt_line < salt_file) > 0) {
                        print salt_line
                    }
                    close(salt_file)
                }
            }
        ' "$WP_CONFIG" > "$WP_CONFIG_TMP"
        chown root:http "$WP_CONFIG_TMP"
        chmod 0640 "$WP_CONFIG_TMP"
        mv -f -- "$WP_CONFIG_TMP" "$WP_CONFIG"
        rm -f -- "$SALT_TMPFILE"
        msg "Security keys/salts updated from WordPress API"
    else
        warn "Could not fetch valid salts from WordPress API — existing keys unchanged"
        warn "Manually visit: https://api.wordpress.org/secret-key/1.1/salt/"
    fi

    # --- Randomize table prefix only on unconfigured/fresh installs ---
    if grep -qE '^[[:space:]]*\$table_prefix[[:space:]]*=[[:space:]]*["\x27]wp_["\x27]' "$WP_CONFIG"; then
        if [[ "$FRESH_INSTALL" == true || "$INITIAL_DB_PLACEHOLDER" == true ]] || wp_db_has_placeholders; then
            RANDOM_PREFIX=""
            while (( ${#RANDOM_PREFIX} < 4 )); do
                RANDOM_PREFIX+=$(dd if=/dev/urandom bs=64 count=1 2>/dev/null | LC_ALL=C tr -dc 'a-z')
            done
            RANDOM_PREFIX="${RANDOM_PREFIX:0:4}_"
            sed -i "s|^[[:space:]]*\\\$table_prefix[[:space:]]*=[[:space:]]*['\"]wp_['\"]|\$table_prefix = '${RANDOM_PREFIX}'|" "$WP_CONFIG"
            msg "Table prefix changed from 'wp_' to '${RANDOM_PREFIX}'"
            if [[ "$FRESH_INSTALL" == true && "$INITIAL_DB_PLACEHOLDER" == false ]]; then
                warn "IMPORTANT: Ensure database table names match '${RANDOM_PREFIX}' if tables already exist."
            fi
        else
            info "Keeping existing \$table_prefix = 'wp_' (DB credentials are already configured; pass --fresh-install before installation to randomize)"
        fi
    else
        info "Table prefix is already custom — no change needed"
    fi

    # --- Add content directory comment ---
    if ! grep -q "WP_CONTENT_DIR" "$WP_CONFIG"; then
        WP_SCHEME="http"
        [[ "$USE_SSL" == true ]] && WP_SCHEME="https"
        WP_CONFIG_TMP=$(umask 077; mktemp "$WP_PATH/.wp-config.cnt.XXXXXX")
        WP_URL="${WP_SCHEME}://${DOMAIN}/wp-content" awk '
            !inserted && (/stop editing/ || /^[[:space:]]*require(_once)?[[:space:]\(].*wp-settings\.php/) {
                print "// Optional: Move wp-content outside the web root for extra security"
                print "// define(\x27WP_CONTENT_DIR\x27, dirname(__FILE__) . \x27/wp-content\x27);"
                print "// define(\x27WP_CONTENT_URL\x27, \x27" ENVIRON["WP_URL"] "\x27);"
                inserted = 1
            }
            { print }
        ' "$WP_CONFIG" > "$WP_CONFIG_TMP"
        chown root:http "$WP_CONFIG_TMP" 2>/dev/null || true
        chmod 0640 "$WP_CONFIG_TMP"
        mv -f -- "$WP_CONFIG_TMP" "$WP_CONFIG"
        info "Added WP_CONTENT_DIR comment block"
    fi

    msg "wp-config.php hardening complete"
fi

# =============================================================================
# 3. FILE PERMISSIONS
# =============================================================================

msg "Setting WordPress file permissions..."

# --- Ensure parent webroot hierarchy is traversable by nginx (http) ---
for base_root in /var/www /srv/http; do
    if [[ "$WP_PATH" == "$base_root"/* ]]; then
        chmod 0755 "$base_root"
        parent_walk=$(dirname -- "$WP_PATH")
        while [[ "$parent_walk" != "$base_root" && "$parent_walk" != "/" ]]; do
            chown root:http "$parent_walk"
            chmod 0750 "$parent_walk"
            parent_walk=$(dirname -- "$parent_walk")
        done
    fi
done

# --- Permission model, applied by the update helper ---
# The helper restores exactly this state after every update, so it is the one
# place that implements it:
#   code (core, wp-config.php, plugins, themes)  root:http  750/640  read-only for PHP
#   wp-content/uploads, wp-content/cache         http:http  770/660  writable
# It waits for an update that the timer may be applying right now.
install_update_helper
info "Update helper installed: $UPDATE_HELPER"
bash "$UPDATE_HELPER" --seal -w "$WP_PATH" || \
    err "Could not apply the file permissions below $WP_PATH"
info "Code (core, wp-config.php, plugins, themes): 750/640 root:http (read-only for PHP)"
info "wp-content/uploads: 770/660 http:http (writable)"
if [[ -d "$WP_PATH/wp-content/cache" && ! -L "$WP_PATH/wp-content/cache" ]]; then
    info "wp-content/cache: 770/660 http:http (writable)"
fi

# --- Remove sensitive default files ---
REMOVED_FILES=()
for f in wp-config-sample.php readme.html license.txt; do
    if [[ -f "$WP_PATH/$f" ]]; then
        rm -f "$WP_PATH/$f"
        REMOVED_FILES+=("$f")
    fi
done

# Block xmlrpc.php via nginx (removal is optional since nginx blocks it)
if [[ -f "$WP_PATH/xmlrpc.php" ]]; then
    info "xmlrpc.php exists — will be blocked by nginx (not removed)"
fi

# Remove install.php ONLY when WordPress is already configured (never on --fresh-install
# or when DB credentials are still placeholders)
if [[ -f "$WP_PATH/wp-admin/install.php" ]]; then
    if [[ "$FRESH_INSTALL" == true || "$INITIAL_DB_PLACEHOLDER" == true ]] || wp_db_has_placeholders; then
        info "Preserving wp-admin/install.php (fresh install or placeholder DB credentials)"
    else
        rm -f "$WP_PATH/wp-admin/install.php"
        REMOVED_FILES+=("wp-admin/install.php")
    fi
fi

if [[ ${#REMOVED_FILES[@]} -gt 0 ]]; then
    msg "Removed: ${REMOVED_FILES[*]}"
else
    info "No default sensitive files found to remove"
fi

msg "File permissions set"

# =============================================================================
# 4. NGINX SERVER BLOCK
# =============================================================================

msg "Writing nginx server block..."

CONF_FILE="/etc/nginx/sites-enabled/${DOMAIN}.conf"
CONF_BACKUP=""
CONF_PREEXISTED=false
DEFAULT_SITE="/etc/nginx/sites-enabled/default.conf"
DEFAULT_SITE_BACKUP=""

restore_nginx_conf() {
    if [[ "$CONF_PREEXISTED" == true ]]; then
        cp -- "$CONF_BACKUP" "$CONF_FILE"
        warn "Restored the previous nginx server block"
    else
        rm -f -- "$CONF_FILE"
        warn "Removed the new nginx server block"
    fi
    if [[ -n "$DEFAULT_SITE_BACKUP" && -f "$DEFAULT_SITE_BACKUP" ]]; then
        cp -p -- "$DEFAULT_SITE_BACKUP" "$DEFAULT_SITE"
        warn "Restored $DEFAULT_SITE"
    fi
}

# nginx honours only the first server block per name and listen socket, in
# include (alphabetical) order, so a default.conf from ../nginx/nginx.sh that
# declares the same name on ports 80/443 either hides this vhost or is hidden
# by it. Take the name over instead of leaving the outcome to file naming:
#   - default.conf serves nothing else  -> it is superseded and removed
#   - it serves other names as well     -> only our names are dropped from it
# The original is saved to $1 first and restored if nginx rejects the new vhost.
# Call it once the new vhost is written, immediately before "nginx -t".
# Usage: resolve_default_site_overlap BACKUP_PATH NAME...
resolve_default_site_overlap() {
    local backup_path="$1" state
    shift
    [[ -f "$DEFAULT_SITE" && "$CONF_FILE" != "$DEFAULT_SITE" ]] || return 0

    state=$(OUR_NAMES=" $* " awk '
        function ours(name) { return index(tolower(ENVIRON["OUR_NAMES"]), " " tolower(name) " ") > 0 }
        {
            line = $0
            sub(/#.*/, "", line)
            if (line ~ /^[[:space:]]*server_name[[:space:]]/) {
                sub(/^[[:space:]]*server_name[[:space:]]+/, "", line)
                sub(/;.*/, "", line)
                n = split(line, names, /[[:space:]]+/)
                mine = 0
                others = 0
                for (i = 1; i <= n; i++) {
                    if (names[i] == "") {
                        continue
                    }
                    if (ours(names[i])) {
                        mine++
                    } else {
                        others++
                    }
                }
                if (mine && others)  { partial = 1 }
                if (mine && !others) { whole = 1 }
                if (!mine && others) { foreign = 1 }
            } else if (line ~ /^[[:space:]]*listen[[:space:]]/) {
                sub(/^[[:space:]]*listen[[:space:]]+/, "", line)
                sub(/[[:space:]]*;.*/, "", line)
                if (line !~ /^(\[::\]:)?(80|443 ssl)$/) {
                    odd_listen = 1
                }
            }
        }
        END {
            if (!partial && !whole) {
                print "none"
            } else if (whole && !partial && !foreign && !odd_listen) {
                print "only"
            } else if (partial && !whole) {
                print "shared"
            } else {
                print "mixed"
            }
        }
    ' "$DEFAULT_SITE")

    case "$state" in
        only)
            cp -p -- "$DEFAULT_SITE" "$backup_path"
            DEFAULT_SITE_BACKUP="$backup_path"
            rm -f -- "$DEFAULT_SITE"
            warn "$DEFAULT_SITE served only $* and is superseded by $CONF_FILE; it was moved to $backup_path"
            ;;
        shared)
            cp -p -- "$DEFAULT_SITE" "$backup_path"
            DEFAULT_SITE_BACKUP="$backup_path"
            OUR_NAMES=" $* " awk '
                function ours(name) { return index(tolower(ENVIRON["OUR_NAMES"]), " " tolower(name) " ") > 0 }
                {
                    line = $0
                    sub(/#.*/, "", line)
                    if (line ~ /^[[:space:]]*server_name[[:space:]]+[^;]*;[[:space:]]*$/) {
                        match($0, /^[[:space:]]*/)
                        indent = substr($0, 1, RLENGTH)
                        sub(/^[[:space:]]*server_name[[:space:]]+/, "", line)
                        sub(/;.*/, "", line)
                        n = split(line, names, /[[:space:]]+/)
                        kept = ""
                        dropped = 0
                        for (i = 1; i <= n; i++) {
                            if (names[i] == "") {
                                continue
                            }
                            if (ours(names[i])) {
                                dropped = 1
                                continue
                            }
                            kept = kept " " names[i]
                        }
                        if (dropped && kept != "") {
                            print indent "server_name" kept ";"
                            next
                        }
                    }
                    print
                }
            ' "$backup_path" > "$DEFAULT_SITE"
            warn "Removed $* from the server_name lines of $DEFAULT_SITE (now served by $CONF_FILE); original saved to $backup_path"
            ;;
        mixed)
            if ( LC_ALL=C; [[ "${CONF_FILE##*/}" < "${DEFAULT_SITE##*/}" ]] ); then
                warn "$DEFAULT_SITE also declares $*. nginx will use $CONF_FILE (read first) and log 'conflicting server name' warnings; remove the name(s) from $DEFAULT_SITE to silence them."
            else
                restore_nginx_conf
                err "$DEFAULT_SITE also declares $* and is read before $CONF_FILE, so nginx would ignore this vhost. Remove the name(s) from $DEFAULT_SITE, then re-run this script."
            fi
            ;;
    esac
}

# Print the webroot certbot recorded for DOMAIN ($1) when its certificate was
# issued (../nginx/nginx.sh passes its own -w directory), or FALLBACK ($2).
# Renewals are validated through that directory, so the vhost has to serve
# /.well-known/acme-challenge/ from it rather than assume its own root.
acme_webroot_for() {
    local domain="$1" fallback="$2" renewal_dir="/etc/letsencrypt/renewal" renewal_conf recorded=""
    # The certificate may be named after another domain (nginx.sh names it after
    # its first -d), so look for this name in the webroot map of every lineage,
    # starting with the one named after the domain itself.
    for renewal_conf in "$renewal_dir/$domain.conf" "$renewal_dir"/*.conf; do
        [[ -f "$renewal_conf" ]] || continue
        recorded=$(DOMAIN_TARGET="$domain" awk '
            /^\[\[webroot_map\]\]/ { in_map = 1; next }
            /^\[/                  { in_map = 0 }
            in_map && $1 == ENVIRON["DOMAIN_TARGET"] && $2 == "=" { print $3; exit }
        ' "$renewal_conf")
        [[ -z "$recorded" ]] || break
    done
    if [[ -z "$recorded" && -f "$renewal_dir/$domain.conf" ]]; then
        recorded=$(awk '
            /^webroot_path[[:space:]]*=/ {
                val = $0
                sub(/^[^=]*=[[:space:]]*/, "", val)
                sub(/[[:space:]]*,.*$/, "", val)
                print val
                exit
            }
        ' "$renewal_dir/$domain.conf")
    fi
    if [[ "$recorded" =~ ^/[A-Za-z0-9._/-]+$ && -d "$recorded" ]]; then
        printf '%s\n' "$recorded"
    else
        printf '%s\n' "$fallback"
    fi
}

# Ensure directories exist and sites-enabled is included by nginx.conf
install -d -m 0755 /etc/nginx/sites-enabled /etc/nginx/conf.d

if [[ -f /etc/nginx/nginx.conf ]] && ! grep -Eq '^[[:space:]]*include[[:space:]]+/etc/nginx/sites-enabled/' /etc/nginx/nginx.conf; then
    cp /etc/nginx/nginx.conf "/etc/nginx/nginx.conf.bak.$(date +%Y%m%d-%H%M%S)"
    NGINX_TMP=$(mktemp /etc/nginx/.nginx.conf.XXXXXX)
    awk '
        !inserted && /^[[:space:]]*http[[:space:]]*\{/ { in_http = 1 }
        in_http {
            line = $0
            gsub(/#.*/, "", line)
            opens = gsub(/\{/, "{", line)
            closes = gsub(/\}/, "}", line)
            depth += opens - closes
            if (depth == 0) {
                print "    include /etc/nginx/sites-enabled/*.conf;"
                in_http = 0
                inserted = 1
            }
        }
        { print }
    ' /etc/nginx/nginx.conf > "$NGINX_TMP"
    install -o root -g root -m 0644 "$NGINX_TMP" /etc/nginx/nginx.conf
    rm -f -- "$NGINX_TMP"
    info "Added sites-enabled include to /etc/nginx/nginx.conf"
fi

# Back up existing config
if [[ -f "$CONF_FILE" ]]; then
    CONF_PREEXISTED=true
    BACKUP="${CONF_FILE}.bak.$(date +%Y%m%d-%H%M%S)"
    cp "$CONF_FILE" "$BACKUP"
    CONF_BACKUP="$BACKUP"
    info "Existing nginx config backed up to $BACKUP"
fi

# Avoid www.www.example.com when $DOMAIN already starts with www. or is single-label
if [[ "$DOMAIN" == www.* || "$DOMAIN" != *.* ]]; then
    SERVER_NAMES="$DOMAIN"
else
    SERVER_NAMES="$DOMAIN www.$DOMAIN"
fi

ACME_ROOT=$(acme_webroot_for "$DOMAIN" "$WP_PATH")
if [[ "$ACME_ROOT" != "$WP_PATH" ]]; then
    info "ACME challenges are served from $ACME_ROOT (webroot recorded by certbot for $DOMAIN)"
fi
ACME_LOCATION="    # ACME challenge (certbot issuance and renewal)
    location ^~ /.well-known/acme-challenge/ {
        root $ACME_ROOT;
        default_type \"text/plain\";
        try_files \$uri =404;
    }"

# Detect PHP-FPM socket
PHP_SOCKET="/run/php-fpm/php-fpm.sock"
if [[ ! -S "$PHP_SOCKET" ]]; then
    # Try alternative socket paths
    for sock in /run/php-fpm/www.sock /var/run/php-fpm/php-fpm.sock /run/php/php-fpm.sock; do
        if [[ -S "$sock" ]]; then
            PHP_SOCKET="$sock"
            break
        fi
    done
fi
info "PHP-FPM socket: $PHP_SOCKET"

# Build listen, SSL, HSTS, and CSP directives
if [[ "$USE_SSL" == true ]]; then
    LISTEN_BLOCK="    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;"
    SSL_PROTOCOLS_LINE=""
    if [[ ! -f /etc/nginx/conf.d/ssl-hardening.conf ]]; then
        SSL_PROTOCOLS_LINE=$'\n'"    ssl_protocols       TLSv1.2 TLSv1.3;"
    fi
    SSL_BLOCK="
    # --- SSL certificates ---
    ssl_certificate     $CERT_DIR/fullchain.pem;
    ssl_certificate_key $CERT_DIR/privkey.pem;${SSL_PROTOCOLS_LINE}"
    CSP_UPGRADE=" upgrade-insecure-requests;"
    HSTS_SERVER_LINE=$'    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;\n'
    HSTS_LOC_LINE=$'        add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;\n'
    MAIN_ACME_LOCATION=""
else
    LISTEN_BLOCK="    listen 80;
    listen [::]:80;"
    SSL_BLOCK=""
    # HTTP-only: this server block also answers the first ACME challenge.
    MAIN_ACME_LOCATION=$'\n'"$ACME_LOCATION"$'\n'
    CSP_UPGRADE=""
    HSTS_SERVER_LINE=""
    HSTS_LOC_LINE=""
fi

WP_CSP="default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data: https:; font-src 'self' https://fonts.gstatic.com data:; connect-src 'self' https:; frame-ancestors 'self'; form-action 'self'; base-uri 'self';${CSP_UPGRADE}"

cat > "$CONF_FILE" <<EOF
# =============================================================================
# nginx server block — WordPress production hardening
# Generated by AwesomeArchLinux/hardening/wordpress/wordpress.sh
#
# Domain: $DOMAIN
# Root:   $WP_PATH
# SSL:    $USE_SSL
# =============================================================================
# ACME-Webroot: $ACME_ROOT

# --- Rate limiting zones ---
limit_req_zone \$binary_remote_addr zone=wp_login_${DOMAIN//./_}:10m rate=1r/s;
limit_req_zone \$binary_remote_addr zone=wp_ajax_${DOMAIN//./_}:10m rate=10r/s;

# --- FastCGI cache (optional — uncomment to enable) ---
# fastcgi_cache_path /var/cache/nginx/wordpress levels=1:2 keys_zone=WPCACHE:100m inactive=60m max_size=512m;
# fastcgi_cache_key "\$scheme\$request_method\$host\$request_uri";

EOF

# HTTP to HTTPS redirect block (only when SSL is enabled)
if [[ "$USE_SSL" == true ]]; then
    cat >> "$CONF_FILE" <<EOF
# --- HTTP: Redirect all to HTTPS ---
server {
    listen 80;
    listen [::]:80;
    server_name $SERVER_NAMES;

$ACME_LOCATION

    location / {
        return 301 https://\$host\$request_uri;
    }
}

EOF
fi

cat >> "$CONF_FILE" <<EOF
# --- Main server block ---
server {
$LISTEN_BLOCK
    server_name $SERVER_NAMES;
$SSL_BLOCK

    root $WP_PATH;
    index index.php index.html;
$MAIN_ACME_LOCATION
    # Hide PHP version
    fastcgi_hide_header X-Powered-By;

    # --- Security headers ---
${HSTS_SERVER_LINE}    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;
    add_header Cross-Origin-Opener-Policy "same-origin" always;

    # --- Content-Security-Policy (tuned for WordPress) ---
    # WordPress admin requires 'unsafe-inline' and 'unsafe-eval' for scripts/styles.
    # Adjust connect-src, img-src, and font-src for your themes and plugins.
    add_header Content-Security-Policy "${WP_CSP}" always;

    # =========================================================================
    # WORDPRESS PERMALINKS
    # =========================================================================

    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }

    # =========================================================================
    # EXACT & REGEX DENY RULES (evaluated before FastCGI PHP handler)
    # =========================================================================

    # --- Block xmlrpc.php (brute-force and DDoS vector) ---
    location = /xmlrpc.php {
        deny all;
        return 403;
    }

    # --- Block wp-config.php access ---
    location = /wp-config.php {
        deny all;
        return 403;
    }

    # --- Block .htaccess, .htpasswd ---
    location ~ /\.ht {
        deny all;
        return 403;
    }

    # --- Block hidden files (except .well-known) ---
    location ~ /\.(?!well-known) {
        deny all;
        return 404;
    }

    # --- Block PHP execution in uploads ---
    location ~* /wp-content/uploads/.*\.php$ {
        deny all;
        return 403;
    }

    # --- Block direct PHP execution in wp-includes ---
    location ~* /wp-includes/.*\.php$ {
        deny all;
        return 403;
    }

    # --- Block all direct PHP execution in wp-content (no index.php exception!) ---
    location ~* /wp-content/.*\.php$ {
        deny all;
        return 403;
    }

    # --- Block access to readme, license, and sample config files ---
    location ~* /(readme\.html|readme\.txt|license\.txt|wp-config-sample\.php)$ {
        deny all;
        return 403;
    }

    # --- Block access to backup, SQL, editor swap, and log files ---
    # Also matches suffixed copies such as wp-config.php.bak.20260101-120000,
    # dump.sql.gz, debug.log.1, wp-config.php.save and wp-config.php~.
    location ~* (?:\.(?:sql|bak|orig|old|save|swp|swo|log)|\.(?:sql|bak|save|log)\.[^/]*|~)\$ {
        deny all;
        return 404;
    }

    # =========================================================================
    # RATE-LIMITED & ADMIN ENDPOINTS
    # =========================================================================

    # --- Rate limit wp-login.php ---
    location = /wp-login.php {
        try_files \$uri =404;
        limit_req zone=wp_login_${DOMAIN//./_} burst=3 nodelay;
        limit_req_status 429;

        fastcgi_split_path_info ^(.+\.php)(/.+)\$;
        fastcgi_pass unix:$PHP_SOCKET;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
        fastcgi_hide_header X-Powered-By;
    }

    # --- Rate limit admin-ajax.php ---
    location = /wp-admin/admin-ajax.php {
        try_files \$uri =404;
        limit_req zone=wp_ajax_${DOMAIN//./_} burst=20 nodelay;
        limit_req_status 429;

        fastcgi_split_path_info ^(.+\.php)(/.+)\$;
        fastcgi_pass unix:$PHP_SOCKET;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
        fastcgi_hide_header X-Powered-By;
    }

    # --- Noindex wp-admin for search engines (re-add server security headers) ---
    location /wp-admin/ {
        add_header X-Robots-Tag "noindex, nofollow" always;
${HSTS_LOC_LINE}        add_header X-Content-Type-Options "nosniff" always;
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;
        add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;
        add_header Cross-Origin-Opener-Policy "same-origin" always;
        add_header Content-Security-Policy "${WP_CSP}" always;

        location ~ /\.(?!well-known) {
            deny all;
            return 404;
        }

        location ~* (?:\.(?:sql|bak|orig|old|save|swp|swo|log)|\.(?:sql|bak|save|log)\.[^/]*|~)\$ {
            deny all;
            return 404;
        }

        location ~ \.php$ {
            try_files \$uri =404;
            fastcgi_split_path_info ^(.+\.php)(/.+)\$;
            fastcgi_pass unix:$PHP_SOCKET;
            fastcgi_index index.php;
            fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
            include fastcgi_params;
            fastcgi_hide_header X-Powered-By;
        }
    }

    # =========================================================================
    # STATIC ASSET CACHING
    # =========================================================================

    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|webp|avif|woff|woff2|ttf|eot|mp4|webm|ogg|pdf)$ {
        expires 1y;
        add_header Cache-Control "public, immutable" always;
${HSTS_LOC_LINE}        add_header X-Content-Type-Options "nosniff" always;
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;
        access_log off;
        log_not_found off;
    }

    # =========================================================================
    # PHP-FPM (evaluated AFTER all deny regexes above!)
    # =========================================================================

    location ~ \.php$ {
        try_files \$uri =404;

        fastcgi_split_path_info ^(.+\.php)(/.+)\$;
        fastcgi_pass unix:$PHP_SOCKET;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
        fastcgi_hide_header X-Powered-By;

        # Performance
        fastcgi_buffers 16 16k;
        fastcgi_buffer_size 32k;
        fastcgi_intercept_errors on;

        # FastCGI cache (uncomment to enable)
        # fastcgi_cache WPCACHE;
        # fastcgi_cache_valid 200 60m;
        # fastcgi_cache_valid 404 1m;
        # fastcgi_cache_bypass \$skip_cache;
        # fastcgi_no_cache \$skip_cache;
        # add_header X-FastCGI-Cache \$upstream_cache_status;
    }
}
EOF

chmod 0644 "$CONF_FILE"
msg "nginx server block written: $CONF_FILE"

# shellcheck disable=SC2086  # SERVER_NAMES is a space-separated list of names
resolve_default_site_overlap "$WP_BACKUP_DIR/nginx-default.conf.$(date +%Y%m%d-%H%M%S)" $SERVER_NAMES

# Test and start/reload nginx configuration
if nginx -t 2>&1; then
    msg "nginx configuration test passed"
    NGINX_APPLIED=false
    if systemctl is-active --quiet nginx; then
        systemctl reload nginx && NGINX_APPLIED=true
    else
        systemctl enable --now nginx && NGINX_APPLIED=true
    fi
    if [[ "$NGINX_APPLIED" == true ]]; then
        msg "nginx is active and serving the updated configuration"
    else
        restore_nginx_conf
        if systemctl is-active --quiet nginx; then
            systemctl reload nginx 2>/dev/null || \
                warn "Could not reload nginx after restoring its previous configuration"
        fi
        err "nginx start/reload failed; the server block was rolled back"
    fi
else
    restore_nginx_conf
    err "nginx configuration test failed; no invalid server block was left enabled"
fi

# =============================================================================
# 5. FAIL2BAN JAILS FOR WORDPRESS
# =============================================================================

msg "Configuring fail2ban jails for WordPress..."

# Ensure fail2ban and nginx log directories exist. An existing log directory is
# left exactly as it is: ../nginx/nginx.sh keeps it root-owned on purpose and
# "install -d -m" would re-mode it on every run.
install -d -m 0755 /etc/fail2ban/filter.d /etc/fail2ban/jail.d
[[ -d /var/log/nginx ]] || install -d -o root -g root -m 0755 /var/log/nginx
[[ -f /var/log/nginx/access.log ]] || install -m 0640 -o http -g root /dev/null /var/log/nginx/access.log 2>/dev/null || touch /var/log/nginx/access.log

# --- WordPress authentication filter ---
cat > /etc/fail2ban/filter.d/wordpress-auth.conf <<'EOF'
# =============================================================================
# fail2ban filter: wordpress-auth
# Generated by AwesomeArchLinux/hardening/wordpress/wordpress.sh
#
# Matches failed WordPress login attempts from nginx access log.
# Failed logins re-render wp-login.php with HTTP 200; successful logins return
# HTTP 302 to /wp-admin/ and must NOT be matched here.
# =============================================================================

[Definition]
failregex = ^<HOST> .* "POST /wp-login\.php[^"]*" 200\b

ignoreregex =
EOF
chmod 0644 /etc/fail2ban/filter.d/wordpress-auth.conf

msg "WordPress auth filter created: /etc/fail2ban/filter.d/wordpress-auth.conf"

# --- WordPress xmlrpc filter ---
cat > /etc/fail2ban/filter.d/wordpress-xmlrpc.conf <<'EOF'
# =============================================================================
# fail2ban filter: wordpress-xmlrpc
# Generated by AwesomeArchLinux/hardening/wordpress/wordpress.sh
#
# Matches any request to xmlrpc.php from nginx access log.
# xmlrpc.php is blocked by nginx, but this catches attempts before
# they are blocked (or if nginx config is modified).
# =============================================================================

[Definition]
failregex = ^<HOST> .* "(GET|POST) /xmlrpc\.php

ignoreregex =
EOF
chmod 0644 /etc/fail2ban/filter.d/wordpress-xmlrpc.conf

msg "WordPress xmlrpc filter created: /etc/fail2ban/filter.d/wordpress-xmlrpc.conf"

# --- WordPress jail configuration (backend = auto for file logpath on Arch) ---
cat > /etc/fail2ban/jail.d/wordpress.conf <<EOF
# =============================================================================
# fail2ban jails: WordPress
# Generated by AwesomeArchLinux/hardening/wordpress/wordpress.sh
# =============================================================================

[wordpress-auth]
enabled  = true
backend  = auto
filter   = wordpress-auth
port     = http,https
logpath  = /var/log/nginx/access.log
maxretry = 5
bantime  = 1h
findtime = 10m

[wordpress-xmlrpc]
enabled  = true
backend  = auto
filter   = wordpress-xmlrpc
port     = http,https
logpath  = /var/log/nginx/access.log
maxretry = 2
bantime  = 24h
findtime = 1h
EOF
chmod 0644 /etc/fail2ban/jail.d/wordpress.conf

msg "WordPress jails created: /etc/fail2ban/jail.d/wordpress.conf"

# Reload fail2ban if running
if systemctl is-active --quiet fail2ban; then
    systemctl reload fail2ban
    msg "fail2ban reloaded"
else
    warn "fail2ban is not running — start it with: systemctl enable --now fail2ban"
fi

# =============================================================================
# 6. PHP .user.ini HARDENING
# =============================================================================

msg "Creating .user.ini for PHP hardening..."

# Create the PHP log directory only when it is missing. ../php/php.sh owns its
# layout (root-owned, so PHP code cannot swap a log file for a symlink) and an
# existing directory must not be re-owned or re-moded here.
[[ -d /var/log/php ]] || install -d -o root -g http -m 0750 /var/log/php
[[ -f /var/log/php/wordpress-errors.log ]] || install -o http -g http -m 0640 /dev/null /var/log/php/wordpress-errors.log

COOKIE_SECURE=0
[[ "$USE_SSL" == true ]] && COOKIE_SECURE=1

cat > "$WP_PATH/.user.ini" <<EOF
; =============================================================================
; PHP .user.ini — WordPress runtime hardening
; Generated by AwesomeArchLinux/hardening/wordpress/wordpress.sh
;
; This file is read by PHP-FPM at runtime (no restart needed, cached for
; user_ini.cache_ttl seconds, default 300s).
; =============================================================================

; --- Upload limits ---
upload_max_filesize = 10M
post_max_size = 10M

; --- Execution limits ---
max_execution_time = 30
max_input_time = 60
max_input_vars = 3000

; --- Path restriction ---
; Restrict PHP file access to WordPress directory, /tmp, and dedicated PHP log dir
open_basedir = ${WP_PATH}:/tmp:/var/log/php:/usr/share/php

; --- Session hardening ---
session.cookie_httponly = 1
session.cookie_secure = ${COOKIE_SECURE}
session.use_strict_mode = 1

; --- Disable dangerous functions (WordPress does not need these) ---
; Note: Some plugins may require proc_open or exec. Add exceptions as needed.
; disable_functions = exec,passthru,shell_exec,system,proc_open,popen,parse_ini_file,show_source

; --- Error handling (production, logged outside public webroot) ---
display_errors = Off
log_errors = On
error_log = /var/log/php/wordpress-errors.log
EOF

chown root:http "$WP_PATH/.user.ini"
chmod 640 "$WP_PATH/.user.ini"

msg ".user.ini created at $WP_PATH/.user.ini"

# Check php.ini / php-fpm pool overrides (e.g. from ../php/php.sh) for conflicts
PHP_INI_FILE="/etc/php/php.ini"
shopt -s nullglob
FPM_POOL_FILES=(/etc/php/php-fpm.d/*.conf)
shopt -u nullglob

CURL_EXEC_DISABLED=false
URL_FOPEN_OFF=false
if [[ -f "$PHP_INI_FILE" ]]; then
    if grep -Eq '^[[:space:]]*disable_functions[[:space:]]*=.*(^|[,[:space:]])curl_exec([,[:space:]]|$)' "$PHP_INI_FILE"; then
        CURL_EXEC_DISABLED=true
    fi
    if grep -Eqi '^[[:space:]]*allow_url_fopen[[:space:]]*=[[:space:]]*(off|0|false|no)([[:space:];]|$)' "$PHP_INI_FILE"; then
        URL_FOPEN_OFF=true
    fi
fi
for pool_conf in "${FPM_POOL_FILES[@]}"; do
    if grep -Eq '^[[:space:]]*php_admin_value\[disable_functions\][[:space:]]*=.*(^|[,[:space:]])curl_exec([,[:space:]]|$)' "$pool_conf"; then
        CURL_EXEC_DISABLED=true
    fi
    if grep -Eqi '^[[:space:]]*php_admin_(flag|value)\[allow_url_fopen\][[:space:]]*=[[:space:]]*(off|0|false|no)([[:space:];]|$)' "$pool_conf"; then
        URL_FOPEN_OFF=true
    fi
    while IFS= read -r basedir_val; do
        [[ -n "$basedir_val" ]] || continue
        wp_covered=false
        log_covered=false
        IFS=':' read -r -a basedir_paths <<< "$basedir_val"
        for bd_path in "${basedir_paths[@]}"; do
            bd_clean="${bd_path%/}"
            [[ -n "$bd_clean" ]] || continue
            if [[ "$WP_PATH" == "$bd_clean" || "$WP_PATH" == "$bd_clean"/* ]]; then
                wp_covered=true
            fi
            if [[ "/var/log/php" == "$bd_clean" || "/var/log/php" == "$bd_clean"/* ]]; then
                log_covered=true
            fi
        done
        if [[ "$wp_covered" == false || "$log_covered" == false ]]; then
            warn "$pool_conf sets php_admin_value[open_basedir]='$basedir_val', which overrides .user.ini and excludes $( [[ "$wp_covered" == false ]] && printf '%s ' "$WP_PATH" )$( [[ "$log_covered" == false ]] && printf '/var/log/php' )."
            warn "Add $WP_PATH and /var/log/php to php_admin_value[open_basedir] in $pool_conf, then reload php-fpm."
        fi
    done < <(
        awk '/^[[:space:]]*php_admin_value\[open_basedir\][[:space:]]*=/ {
            val = substr($0, index($0, "=") + 1)
            sub(/;.*/, "", val)
            gsub(/^[[:space:]"'\'']+|[[:space:]"'\'']+$/, "", val)
            print val
        }' "$pool_conf"
    )
done
if [[ "$CURL_EXEC_DISABLED" == true && "$URL_FOPEN_OFF" == true ]]; then
    warn "PHP has both curl_exec disabled and allow_url_fopen=Off (e.g. from ../php/php.sh)."
    warn "WordPress updates, loopback cron, and remote API calls require outbound HTTP — re-enable curl_exec in /etc/php/php.ini and reload php-fpm."
fi

# =============================================================================
# 7. WORDPRESS CRON REPLACEMENT (per-domain systemd timer)
# =============================================================================

msg "Setting up systemd wp-cron timer..."

# DISABLE_WP_CRON was already added in wp-config.php hardening (step 2)
CRON_UNIT_BASE="wordpress-cron-${DOMAIN//./-}"

# Clean up legacy single-site unit if it belonged to this exact domain
if [[ -f /etc/systemd/system/wordpress-cron.service ]] && \
   grep -Fqx "Description=WordPress cron for $DOMAIN" /etc/systemd/system/wordpress-cron.service; then
    systemctl disable --now wordpress-cron.timer 2>/dev/null || true
    rm -f /etc/systemd/system/wordpress-cron.service /etc/systemd/system/wordpress-cron.timer
fi

# Determine cron method: wp-cli if available, curl fallback
CRON_METHOD="curl"
WP_CLI_BIN=$(command -v wp 2>/dev/null || true)
PHP_BIN=$(command -v php 2>/dev/null || true)
if [[ "$WP_CLI_BIN" != /* || ! -x "$WP_CLI_BIN" ]]; then
    info "wp-cli not found — using curl to trigger wp-cron.php"
elif [[ "$WP_CLI_BIN" == /root/* || "$WP_CLI_BIN" == /home/* ]]; then
    # ProtectHome=yes hides these trees from the cron unit.
    warn "wp-cli at $WP_CLI_BIN is not reachable by the sandboxed cron unit — using curl to trigger wp-cron.php"
else
    CRON_METHOD="wp-cli"
    # Use the resolved path (wp-cli is often installed to /usr/local/bin). When it
    # is a PHP script/phar, run it through php with open_basedir cleared: a global
    # open_basedir in php.ini (set by ../php/php.sh) also applies to the CLI and
    # would stop PHP from opening wp-cli itself. The unit's systemd sandbox below
    # still confines what the cron run can write.
    WP_CLI_FIRST_LINE=""
    CRON_ENV=""
    IFS= read -r WP_CLI_FIRST_LINE < "$WP_CLI_BIN" 2>/dev/null || true
    if [[ "$PHP_BIN" == /* && "$WP_CLI_FIRST_LINE" == '#!'*php* ]]; then
        CRON_EXEC="$PHP_BIN -d open_basedir= $WP_CLI_BIN cron event run --due-now --path=$WP_PATH"
    else
        # A wrapper script starts php itself; wp-cli's own wrapper passes
        # WP_CLI_PHP_ARGS on to it.
        CRON_EXEC="$WP_CLI_BIN cron event run --due-now --path=$WP_PATH"
        CRON_ENV='Environment="WP_CLI_PHP_ARGS=-d open_basedir="'
    fi
    info "wp-cli found at $WP_CLI_BIN — using 'wp cron event run --due-now'"
fi

install -d -m 0755 /etc/systemd/system
# Create the per-domain systemd service
cat > "/etc/systemd/system/${CRON_UNIT_BASE}.service" <<EOF
[Unit]
Description=WordPress cron for $DOMAIN
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=http
Group=http
EOF

if [[ "$CRON_METHOD" == "wp-cli" ]]; then
    {
        [[ -z "$CRON_ENV" ]] || printf '%s\n' "$CRON_ENV"
        printf 'ExecStart=%s\n' "$CRON_EXEC"
    } >> "/etc/systemd/system/${CRON_UNIT_BASE}.service"
else
    if [[ "$USE_SSL" == true ]]; then
        CRON_PORT=443
        CRON_URL="https://${DOMAIN}/wp-cron.php?doing_wp_cron"
    else
        CRON_PORT=80
        CRON_URL="http://${DOMAIN}/wp-cron.php?doing_wp_cron"
    fi
    cat >> "/etc/systemd/system/${CRON_UNIT_BASE}.service" <<EOF
ExecStart=/usr/bin/curl -fsS --max-time 30 --resolve "${DOMAIN}:${CRON_PORT}:127.0.0.1" "${CRON_URL}" -o /dev/null
EOF
fi

cat >> "/etc/systemd/system/${CRON_UNIT_BASE}.service" <<EOF

# Security hardening
ProtectSystem=strict
ReadWritePaths=-${WP_PATH}/wp-content/uploads -${WP_PATH}/wp-content/cache -/var/log/php
PrivateTmp=true
ProtectHome=yes
NoNewPrivileges=yes
EOF

# Create the per-domain systemd timer
cat > "/etc/systemd/system/${CRON_UNIT_BASE}.timer" <<EOF
[Unit]
Description=Run WordPress cron every 15 minutes for $DOMAIN

[Timer]
OnCalendar=*:0/15
RandomizedDelaySec=60
Persistent=true

[Install]
WantedBy=timers.target
EOF
chmod 0644 "/etc/systemd/system/${CRON_UNIT_BASE}.service" "/etc/systemd/system/${CRON_UNIT_BASE}.timer"

systemctl daemon-reload
systemctl enable --now "${CRON_UNIT_BASE}.timer"

msg "WordPress cron timer active: ${CRON_UNIT_BASE}.timer (every 15 minutes)"
info "Check: systemctl list-timers ${CRON_UNIT_BASE}.timer"

# =============================================================================
# 8. UPDATES (privilege-separated, per-domain systemd timer)
# =============================================================================

msg "Setting up WordPress updates..."

# Step 3 leaves the code owned by root and read-only for PHP, so WordPress can
# apply none of its own updates (dashboard, background updater, wp-cli as
# http). $UPDATE_HELPER applies them instead: it hands the code to the locked
# account $WP_UPDATE_USER for the duration of a sandboxed wp-cli run and seals
# it again. PHP-FPM never gets write access.
if ! getent passwd "$WP_UPDATE_USER" >/dev/null; then
    useradd -r -U -M -d /var/empty -s /usr/bin/nologin -c "WordPress updates" "$WP_UPDATE_USER"
    info "Created the locked system account $WP_UPDATE_USER"
fi

UPDATE_UNIT_BASE="wordpress-update-${DOMAIN//./-}"
UPDATE_EXEC="$UPDATE_HELPER -w $WP_PATH"
[[ "$AUTO_UPDATE" != core ]] || UPDATE_EXEC+=" --core-only"

cat > "/etc/systemd/system/${UPDATE_UNIT_BASE}.service" <<EOF
[Unit]
Description=WordPress updates for $DOMAIN
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$UPDATE_EXEC

# The helper needs root to hand the code to $WP_UPDATE_USER and to seal it
# again. wp-cli itself runs as $WP_UPDATE_USER in a transient unit of its own
# that can write to $WP_PATH and nowhere else.
NoNewPrivileges=yes
ProtectSystem=full
ProtectHome=yes
PrivateTmp=true
EOF

cat > "/etc/systemd/system/${UPDATE_UNIT_BASE}.timer" <<EOF
[Unit]
Description=Daily WordPress updates for $DOMAIN

[Timer]
OnCalendar=*-*-* 03:30:00
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF
chmod 0644 "/etc/systemd/system/${UPDATE_UNIT_BASE}.service" "/etc/systemd/system/${UPDATE_UNIT_BASE}.timer"

systemctl daemon-reload

# The timer only runs when it can do its job: wp-cli has to be installed
# outside /root and /home (the helper's sandbox hides both), and WordPress has
# to be installed (wp-cli cannot load a site without a database).
UPDATE_TIMER="off"
if [[ "$AUTO_UPDATE" == off ]]; then
    UPDATE_TIMER_NOTE="switched off with --auto-update off"
elif [[ "$WP_CLI_BIN" != /* || ! -x "$WP_CLI_BIN" ]]; then
    UPDATE_TIMER_NOTE="wp-cli is not installed"
elif [[ "$WP_CLI_BIN" == /root/* || "$WP_CLI_BIN" == /home/* ]]; then
    UPDATE_TIMER_NOTE="wp-cli at $WP_CLI_BIN is not reachable from the update sandbox"
elif [[ "$FRESH_INSTALL" == true || "$INITIAL_DB_PLACEHOLDER" == true ]] || wp_db_has_placeholders; then
    UPDATE_TIMER_NOTE="WordPress is not installed yet"
else
    UPDATE_TIMER="on"
    UPDATE_TIMER_NOTE=""
fi

if [[ "$UPDATE_TIMER" == on ]]; then
    systemctl enable --now "${UPDATE_UNIT_BASE}.timer"
    msg "WordPress update timer active: ${UPDATE_UNIT_BASE}.timer (daily, scope: $AUTO_UPDATE)"
    info "Check: systemctl list-timers ${UPDATE_UNIT_BASE}.timer"
else
    systemctl disable --now "${UPDATE_UNIT_BASE}.timer" 2>/dev/null || true
    if [[ "$AUTO_UPDATE" == off ]]; then
        info "Automatic updates are off; apply updates with: $UPDATE_HELPER -w $WP_PATH"
    else
        warn "Automatic updates are NOT active: $UPDATE_TIMER_NOTE"
        warn "Until that is fixed and this script has run again, WordPress receives no updates."
    fi
fi

# =============================================================================
# 9. SUMMARY
# =============================================================================

echo
echo -e "${C_GREEN}========================================================================${C_NC}"
echo -e "${C_GREEN} WordPress production hardening complete!${C_NC}"
echo -e "${C_GREEN}========================================================================${C_NC}"
echo

echo -e "${C_BLUE}Configuration:${C_NC}"
echo "  Domain:            $DOMAIN"
echo "  WordPress path:    $WP_PATH"
echo "  SSL enabled:       $USE_SSL"
echo "  Cron method:       $CRON_METHOD"
echo "  Log:               $LOGFILE"
echo

echo -e "${C_BLUE}Security hardening applied:${C_NC}"
echo "  - wp-config.php: security constants, fresh salts, custom table prefix"
echo "  - File editor disabled (DISALLOW_FILE_EDIT)"
echo "  - Admin SSL policy: FORCE_SSL_ADMIN = $USE_SSL"
echo "  - Core update policy: WP_AUTO_UPDATE_CORE = 'minor' (applied by the update timer; see Updates)"
echo "  - Debug output disabled in production"
echo "  - Script concatenation disabled (CONCATENATE_SCRIPTS)"
echo

echo -e "${C_BLUE}File permissions:${C_NC}"
echo "  wp-config.php:         640  root:http"
echo "  PHP files:             640  root:http"
echo "  Directories:           750  root:http"
echo "  wp-content/uploads:    770  http:http  (writable)"
echo "  wp-content/cache:      770  http:http  (writable, if exists)"
echo "  wp-content/themes:     750  root:http  (read-only)"
echo "  wp-content/plugins:    750  root:http  (read-only)"
echo "  While an update runs:  code owned by $WP_UPDATE_USER (still read-only for http)"
echo

echo -e "${C_BLUE}nginx config:${C_NC}"
echo "  Server block:    $CONF_FILE"
echo "  Rate limiting:   wp-login.php (1r/s), admin-ajax.php (10r/s)"
echo "  Blocked:         xmlrpc.php, wp-config.php, .ht*, PHP in uploads/includes"
echo "  Static caching:  1 year immutable for images, CSS, JS, fonts"
echo "  Security:        CSP, X-Frame-Options, X-Content-Type-Options, COOP"
echo "  ACME webroot:    $ACME_ROOT"
echo

echo -e "${C_BLUE}fail2ban jails:${C_NC}"
echo "  wordpress-auth:    5 retries -> 1h ban  (wp-login.php failures)"
echo "  wordpress-xmlrpc:  2 retries -> 24h ban (xmlrpc.php requests)"
echo "  Filter configs:    /etc/fail2ban/filter.d/wordpress-auth.conf"
echo "                     /etc/fail2ban/filter.d/wordpress-xmlrpc.conf"
echo "  Jail config:       /etc/fail2ban/jail.d/wordpress.conf"
echo

echo -e "${C_BLUE}PHP hardening:${C_NC}"
echo "  .user.ini:         $WP_PATH/.user.ini"
echo "  upload limit:      10M"
echo "  open_basedir:      $WP_PATH:/tmp:/var/log/php:/usr/share/php"
echo "  error_log:         /var/log/php/wordpress-errors.log"
echo "  max_input_vars:    3000"
echo

echo -e "${C_BLUE}WP-Cron:${C_NC}"
echo "  Built-in wp-cron:  Disabled (DISABLE_WP_CRON = true)"
echo "  systemd timer:     ${CRON_UNIT_BASE}.timer (every 15 minutes)"
echo "  Check status:      systemctl list-timers ${CRON_UNIT_BASE}.timer"
echo

echo -e "${C_YELLOW}Updates:${C_NC}"
echo "  Core, themes and plugins are owned by root and read-only for PHP, so the"
echo "  dashboard cannot install or update anything. Updates are applied by"
echo "  $UPDATE_HELPER, which hands the code to the locked account"
echo "  $WP_UPDATE_USER for one sandboxed wp-cli run and seals it again."
if [[ "$UPDATE_TIMER" == on ]]; then
    if [[ "$AUTO_UPDATE" == core ]]; then
        echo "  Automatic:         ${UPDATE_UNIT_BASE}.timer (daily): core minor releases"
    else
        echo "  Automatic:         ${UPDATE_UNIT_BASE}.timer (daily): core minor releases,"
        echo "                     all plugins and themes (--auto-update core|off narrows this)"
    fi
    echo "  Last run:          journalctl -u ${UPDATE_UNIT_BASE}.service"
elif [[ "$AUTO_UPDATE" == off ]]; then
    echo "  Automatic:         off (--auto-update off)"
else
    echo -e "  Automatic:         ${C_RED}NOT ACTIVE${C_NC}: $UPDATE_TIMER_NOTE"
    if [[ "$UPDATE_TIMER_NOTE" == wp-cli* ]]; then
        echo "                     Install wp-cli as root (for example /usr/local/bin/wp,"
        echo "                     https://wp-cli.org/#installing), then run this script again."
    else
        echo "                     Finish the WordPress installation, then run this script again."
    fi
fi
echo "  Update now:        $UPDATE_HELPER -w $WP_PATH"
echo "  Major release:     $UPDATE_HELPER -w $WP_PATH --major"
echo "  Any wp-cli command with write access (new plugin, theme, ...):"
echo "                     $UPDATE_HELPER -w $WP_PATH -- plugin install NAME --activate"
echo
if [[ -f "$WP_PATH/wp-config.php" ]]; then
    echo -e "${C_BLUE}Backups:${C_NC}"
    echo "  wp-config.php:     $WP_BACKUP_DIR/ (root-only, outside the document root)"
    echo
fi

echo -e "${C_YELLOW}WordPress security checklist:${C_NC}"
echo "  1. Change the default 'admin' username to something unique"
echo "  2. Use a strong, unique password (20+ characters)"
echo "  3. Enable two-factor authentication (2FA) for all admin accounts"
echo "  4. Install a security plugin (Wordfence, Sucuri, or iThemes Security)"
echo "  5. Keep WordPress core, themes, and plugins updated"
echo "  6. Remove unused themes and plugins"
echo "  7. Set up regular backups (database + files)"
echo "  8. Monitor login attempts and file changes"
echo "  9. Limit login attempts (handled by fail2ban above)"
echo " 10. Review user roles — use the principle of least privilege"
echo

echo -e "${C_YELLOW}Recommended security plugins:${C_NC}"
echo "  - Wordfence Security: Firewall, malware scanner, login security"
echo "    https://wordpress.org/plugins/wordfence/"
echo "  - Sucuri Security: Auditing, file integrity, remote scanning"
echo "    https://wordpress.org/plugins/sucuri-scanner/"
echo "  - iThemes Security: Brute-force protection, file change detection"
echo "    https://wordpress.org/plugins/better-wp-security/"
echo

echo -e "${C_GREEN}Done.${C_NC}"
