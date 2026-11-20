#!/usr/bin/env bash
# Regression tests for WordPress updates on a read-only installation:
# the awesome-wordpress-update helper that hardening/wordpress/wordpress.sh
# embeds (permission model, update window, sandboxed wp-cli runs, cleanup on
# failure) and the per-domain update timer the script sets up.

set -euo pipefail

# shellcheck disable=SC1090,SC1091
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

WP_SH="$REPO_ROOT/hardening/wordpress/wordpress.sh"

# Write the helper that wordpress.sh installs to $1.
write_update_helper() {
    awk '
        !capture && /<<.WP_UPDATE_HELPER.$/ { capture = 1; next }
        capture && $0 == "WP_UPDATE_HELPER" { found = 1; exit }
        capture { print }
        END { if (!found) exit 1 }
    ' "$WP_SH" > "$1" || { printf 'Update helper not found in %s\n' "$WP_SH" >&2; return 1; }
}

# Run Bash code ($2) against the sourced helper with wp-cli, the update window
# and the seal replaced by recorders. Every wp-cli call is logged to $1 as
# "ro|rw COMMAND"; the full systemd-run command lines go to $1.args. wp-cli's
# answers come from FAKE_CORE, FAKE_PLUGINS, FAKE_THEMES and FAKE_INSTALLED;
# a command matching the glob FAKE_FAIL fails.
run_update_flow() {
    local log="$1" code="$2" helper
    helper="$(mktemp)"
    write_update_helper "$helper"
    LOG="$log" HELPER="$helper" bash -c '
        set -euo pipefail
        source "$HELPER"
        WP_PATH=/var/www/site
        WP_CMD=(wp)
        systemd-run() {
            local access=ro arg wp_args after_separator=false
            local -a rest=()
            for arg in "$@"; do
                if [[ "$after_separator" == true ]]; then
                    rest+=("$arg")
                elif [[ "$arg" == "--" ]]; then
                    after_separator=true
                elif [[ "$arg" == ReadWritePaths=* ]]; then
                    access=rw
                fi
            done
            # rest: wp --path=... --skip-plugins --skip-themes --no-color COMMAND...
            wp_args="${rest[*]:5}"
            printf "%s %s\n" "$access" "$wp_args" >> "$LOG"
            printf "%s\n" "$*" >> "$LOG.args"
            case "$wp_args" in
                "core is-installed")
                    if [[ "${FAKE_INSTALLED:-yes}" != yes ]]; then
                        [[ "$FAKE_INSTALLED" == no ]] || printf "%s\n" "$FAKE_INSTALLED" >&2
                        return 1
                    fi ;;
                "core is-installed --network") return 1 ;;
                "core check-update"*) printf "%s\n" "${FAKE_CORE:-version,update_type}" ;;
                "plugin list"*)       printf "%s\n" "${FAKE_PLUGINS:-}" ;;
                "theme list"*)        printf "%s\n" "${FAKE_THEMES:-}" ;;
            esac
            # shellcheck disable=SC2053  # FAKE_FAIL is a glob on purpose
            if [[ -n "${FAKE_FAIL:-}" && "$wp_args" == $FAKE_FAIL ]]; then
                return 1
            fi
            return 0
        }
        systemctl() { printf "systemctl %s\n" "$*" >> "$LOG"; }
        wpu_open_window() { WINDOW_OPEN=true; printf "OPEN\n" >> "$LOG"; }
        wpu_seal() { printf "SEAL\n" >> "$LOG"; return "${FAKE_SEAL_RC:-0}"; }
        wpu_reload_php() { :; }
        '"$code"'
    '
}

# -----------------------------------------------------------------------------
# The helper as a program
# -----------------------------------------------------------------------------

test_helper_is_embedded_and_guarded() {
    local tmp out rc=0
    tmp="$(mktemp -d)"
    write_update_helper "$tmp/helper"

    bash -n "$tmp/helper"
    assert_contains "$(head -n1 "$tmp/helper")" "#!/usr/bin/env bash" "helper starts with a shebang"

    # Sourcing must define functions only: wordpress.sh never sources it, but
    # the tests do, and a helper that runs on source would seal a path here.
    out="$(bash -c 'source "$1"; declare -F wpu_seal wpu_main >/dev/null && echo sourced' _ "$tmp/helper" 2>&1)"
    assert_eq "$out" "sourced" "sourcing the helper runs nothing"

    out="$(bash "$tmp/helper" --help 2>&1)"
    assert_contains "$out" "--major" "--help documents --major"
    assert_contains "$out" "--seal" "--help documents --seal"

    out="$(bash "$tmp/helper" --bogus 2>&1)" || rc=$?
    assert_ne "$rc" "0" "unknown options are rejected"
    assert_contains "$out" "Unknown option: --bogus"

    rc=0
    out="$(bash "$tmp/helper" -w /var/www/site -- 2>&1)" || rc=$?
    assert_ne "$rc" "0" "-- without a command is rejected"
    assert_contains "$out" "must be followed by a wp-cli command"
}

test_helper_refuses_paths_outside_the_web_roots() {
    local tmp out rc path
    tmp="$(mktemp -d)"
    write_update_helper "$tmp/helper"
    mkdir -p "$tmp/site/wp-includes"
    ln -s /etc "$tmp/link-to-etc"

    # The helper chowns recursively as root: /, /etc, a path that only resolves
    # into a web root by name, and a scratch directory must all be refused.
    for path in / /etc "$tmp/link-to-etc" "$tmp/site" /var/www /srv/http; do
        rc=0
        out="$(bash -c 'source "$1"; WP_PATH="$2"; wpu_validate_path; echo "ACCEPTED $WP_PATH"' _ "$tmp/helper" "$path" 2>&1)" || rc=$?
        assert_ne "$rc" "0" "wpu_validate_path refuses $path"
        assert_not_contains "$out" "ACCEPTED" "wpu_validate_path refuses $path"
    done

    # Same rule with the roots relaxed: a WordPress tree passes, another
    # directory does not.
    out="$(bash -c 'source "$1"; PATH_RE="^/.+"; WP_PATH="$2"; wpu_validate_path; echo "ACCEPTED $WP_PATH"' _ "$tmp/helper" "$tmp/site" 2>&1)"
    assert_contains "$out" "ACCEPTED" "a WordPress tree is accepted"
    rc=0
    out="$(bash -c 'source "$1"; PATH_RE="^/.+"; WP_PATH="$2"; wpu_validate_path' _ "$tmp/helper" "$tmp" 2>&1)" || rc=$?
    assert_ne "$rc" "0" "a directory without WordPress is refused"
    assert_contains "$out" "Not a WordPress installation"
}

test_wp_cli_must_be_root_owned() {
    local tmp out
    tmp="$(mktemp -d)"
    write_update_helper "$tmp/helper"
    : > "$tmp/world-writable"
    chmod 0666 "$tmp/world-writable"
    : > "$tmp/group-writable"
    chmod 0664 "$tmp/group-writable"
    : > "$tmp/mine"
    chmod 0755 "$tmp/mine"

    out="$(bash -c '
        source "$1"
        for file in "$2/world-writable" "$2/group-writable" "$2/missing"; do
            if wpu_root_owned "$file"; then echo "TRUSTED ${file##*/}"; fi
        done
        if (( EUID != 0 )) && wpu_root_owned "$2/mine"; then echo "TRUSTED mine"; fi
        if wpu_root_owned /usr/bin/env; then echo "TRUSTED env"; fi
    ' _ "$tmp/helper" "$tmp" 2>/dev/null)"
    assert_eq "$out" "TRUSTED env" "only a root-owned file nobody else can write is trusted"

    # wp-cli runs with write access to the code: it is resolved to a real
    # file, checked, and started with the php.ini limits lifted.
    out="$(awk '/^wpu_resolve_wp_cli\(\) \{$/,/^\}$/' "$tmp/helper")"
    assert_contains "$out" 'wpu_root_owned "$real"'
    assert_contains "$out" "/root/*|/home/*"
    assert_contains "$out" "-d open_basedir= -d disable_functions="
}

# -----------------------------------------------------------------------------
# Permission model (--seal)
# -----------------------------------------------------------------------------

test_seal_applies_the_permission_model() {
    local tmp wp outside before after out
    tmp="$(mktemp -d)"
    write_update_helper "$tmp/helper"
    wp="$tmp/site"
    outside="$tmp/outside"

    mkdir -p "$wp/wp-admin" "$wp/wp-includes" \
        "$wp/wp-content/plugins/demo/bin" "$wp/wp-content/themes/demo" \
        "$wp/wp-content/uploads/2026/11" "$outside/real-cache"
    : > "$wp/wp-config.php";                       chmod 0666 "$wp/wp-config.php"
    : > "$wp/index.php";                           chmod 0644 "$wp/index.php"
    : > "$wp/wp-content/plugins/demo/bin/tool.sh"; chmod 4755 "$wp/wp-content/plugins/demo/bin/tool.sh"
    : > "$wp/wp-content/themes/demo/style.css";    chmod 0600 "$wp/wp-content/themes/demo/style.css"
    : > "$wp/wp-content/uploads/2026/11/photo.jpg"; chmod 0644 "$wp/wp-content/uploads/2026/11/photo.jpg"
    : > "$wp/wp-content/uploads/2026/11/shell.php"; chmod 0755 "$wp/wp-content/uploads/2026/11/shell.php"
    chmod 0777 "$wp/wp-content/plugins" "$wp/wp-content/uploads/2026"
    chmod 0700 "$wp/wp-content/uploads"
    # Symbolic links out of the tree: from the code, from uploads/, and cache/
    # itself. None of their targets may change.
    : > "$outside/secret";            chmod 0604 "$outside/secret"
    : > "$outside/real-cache/entry";  chmod 0604 "$outside/real-cache/entry"
    chmod 0705 "$outside" "$outside/real-cache"
    ln -s "$outside/secret" "$wp/wp-content/plugins/demo/link"
    ln -s "$outside" "$wp/wp-content/plugins/demo/dirlink"
    ln -s "$outside/secret" "$wp/wp-content/uploads/2026/link"
    ln -s "$outside/real-cache" "$wp/wp-content/cache"

    out="$(bash -c '
        source "$1"
        SEAL_OWNER="$(id -un)"; WEB_USER="$(id -un)"; WEB_GROUP="$(id -gn)"
        wpu_seal "$2"
    ' _ "$tmp/helper" "$wp" 2>&1)"
    assert_contains "$out" "wp-content/cache is a symbolic link" "a symlinked cache/ is reported, not followed"

    assert_file_mode "$wp" 750
    assert_file_mode "$wp/wp-config.php" 640
    assert_file_mode "$wp/index.php" 640
    assert_file_mode "$wp/wp-content" 750
    assert_file_mode "$wp/wp-content/plugins" 750
    assert_file_mode "$wp/wp-content/plugins/demo/bin" 750
    assert_file_mode "$wp/wp-content/plugins/demo/bin/tool.sh" 640
    assert_file_mode "$wp/wp-content/themes/demo/style.css" 640
    assert_file_mode "$wp/wp-content/uploads" 770
    assert_file_mode "$wp/wp-content/uploads/2026" 770
    assert_file_mode "$wp/wp-content/uploads/2026/11" 770
    assert_file_mode "$wp/wp-content/uploads/2026/11/photo.jpg" 660
    assert_file_mode "$wp/wp-content/uploads/2026/11/shell.php" 660

    assert_file_mode "$outside" 705
    assert_file_mode "$outside/secret" 604
    assert_file_mode "$outside/real-cache" 705
    assert_file_mode "$outside/real-cache/entry" 604

    # A sealed tree is left alone: the daily run must not rewrite the change
    # time of every file (backups and integrity checkers key on it).
    before="$(stat -c '%n %z' "$wp" "$wp/index.php" "$wp/wp-content/plugins/demo/bin/tool.sh")"
    bash -c '
        source "$1"
        SEAL_OWNER="$(id -un)"; WEB_USER="$(id -un)"; WEB_GROUP="$(id -gn)"
        wpu_seal "$2"
    ' _ "$tmp/helper" "$wp" >/dev/null 2>&1
    after="$(stat -c '%n %z' "$wp" "$wp/index.php" "$wp/wp-content/plugins/demo/bin/tool.sh")"
    assert_eq "$after" "$before" "sealing a sealed tree changes nothing in the code"
}

test_seal_creates_uploads_and_reports_failure() {
    local tmp wp rc=0
    tmp="$(mktemp -d)"
    write_update_helper "$tmp/helper"
    wp="$tmp/site"
    mkdir -p "$wp/wp-includes"

    bash -c '
        source "$1"
        SEAL_OWNER="$(id -un)"; WEB_USER="$(id -un)"; WEB_GROUP="$(id -gn)"
        wpu_seal "$2"
    ' _ "$tmp/helper" "$wp"
    assert_file_mode "$wp/wp-content" 750
    assert_file_mode "$wp/wp-content/uploads" 770

    # A step that fails must surface, and the remaining steps still run.
    : > "$wp/wp-content/uploads/a.jpg"
    chmod 0644 "$wp/wp-content/uploads/a.jpg" "$wp/wp-includes"
    bash -c '
        source "$1"
        SEAL_OWNER="$(id -un)"; WEB_USER="$(id -un)"; WEB_GROUP="$(id -gn)"
        chown() { return 1; }
        wpu_seal "$2"
    ' _ "$tmp/helper" "$wp" 2>/dev/null || rc=$?
    assert_ne "$rc" "0" "a failing chown makes the seal fail"
    assert_file_mode "$wp/wp-includes" 750
    assert_file_mode "$wp/wp-content/uploads/a.jpg" 660
}

test_update_window_excludes_writable_directories() {
    local tmp body
    tmp="$(mktemp -d)"
    write_update_helper "$tmp/helper"
    body="$(awk '/^wpu_open_window\(\) \{$/,/^\}$/' "$tmp/helper")"

    # The window hands the code to wp-update and nothing else: uploads/ and
    # cache/ stay with http, the group stays http, links are not followed.
    assert_contains "$body" '-path "$WP_PATH/wp-content/uploads" -o -path "$WP_PATH/wp-content/cache" \) -prune'
    assert_contains "$body" 'chown -h "$UPDATE_USER" -- {} +'
    assert_not_contains "$body" 'chown -R' "the window never chowns blindly"
    assert_not_contains "$body" '$WEB_USER' "the window never hands code to the web user"
    assert_contains "$body" "WINDOW_OPEN=true"
}

# -----------------------------------------------------------------------------
# Update flow
# -----------------------------------------------------------------------------

test_nothing_pending_touches_nothing() {
    local tmp out log
    tmp="$(mktemp -d)"
    log="$tmp/log"
    out="$(run_update_flow "$log" 'wpu_auto_update' 2>&1)"

    assert_contains "$out" "is up to date"
    assert_eq "$(cat "$log")" "ro core is-installed
ro core check-update --fields=version,update_type --format=csv
ro plugin list --update=available --field=name
ro theme list --update=available --field=name" "an up-to-date site is only checked, read-only"
}

test_pending_updates_run_inside_one_sealed_window() {
    local tmp out log
    tmp="$(mktemp -d)"
    log="$tmp/log"
    out="$(FAKE_CORE=$'version,update_type\n6.9,major\n6.8.2,minor' \
           FAKE_PLUGINS=$'akismet\nDeprecated: noise from PHP on stdout\nhello' \
           run_update_flow "$log" 'wpu_auto_update' 2>&1)"

    assert_contains "$out" "Pending: core 6.8.2"
    assert_contains "$out" "Pending: plugin akismet"
    assert_contains "$out" "Pending: plugin hello"
    assert_not_contains "$out" "Pending: plugin Deprecated" "stray PHP output is not taken for a plugin"
    assert_contains "$out" "WordPress 6.9 is a new major release" "a major release is announced"
    assert_contains "$out" "--major"
    assert_eq "$(cat "$log")" "ro core is-installed
ro core check-update --fields=version,update_type --format=csv
ro plugin list --update=available --field=name
ro theme list --update=available --field=name
OPEN
rw core update --minor
ro core is-installed --network
rw core update-db
rw plugin update --all
rw language core update
rw language plugin update --all
rw language theme update --all
SEAL" "minor core and plugin updates are applied between OPEN and SEAL; themes had nothing"
}

test_major_and_core_only_scopes() {
    local tmp out log
    tmp="$(mktemp -d)"

    # A major release alone is not applied without --major.
    log="$tmp/major-held"
    out="$(FAKE_CORE=$'version,update_type\n6.9,major' run_update_flow "$log" 'wpu_auto_update' 2>&1)"
    assert_contains "$out" "new major release"
    assert_not_contains "$(cat "$log")" "OPEN" "a major release does not open the window on its own"

    log="$tmp/major-allowed"
    out="$(FAKE_CORE=$'version,update_type\n6.9,major' run_update_flow "$log" 'ALLOW_MAJOR=true; wpu_auto_update' 2>&1)"
    assert_contains "$(cat "$log")" "
rw core update
" "--major runs core update without --minor"
    assert_not_contains "$(cat "$log")" "core update --minor"

    # --core-only neither looks at nor updates plugins and themes.
    log="$tmp/core-only"
    out="$(FAKE_CORE=$'version,update_type\n6.8.2,minor' FAKE_PLUGINS=akismet FAKE_THEMES=twentytwentyfive \
           run_update_flow "$log" 'CORE_ONLY=true; wpu_auto_update' 2>&1)"
    assert_contains "$(cat "$log")" "rw core update --minor"
    assert_not_contains "$(cat "$log")" "plugin" "--core-only leaves plugins alone"
    assert_not_contains "$(cat "$log")" "theme" "--core-only leaves themes alone"

    log="$tmp/themes"
    out="$(FAKE_THEMES=twentytwentyfive run_update_flow "$log" 'wpu_auto_update' 2>&1)"
    assert_contains "$(cat "$log")" "rw theme update --all"
    assert_not_contains "$(cat "$log")" "rw core update" "core is left alone when only a theme is pending"
    assert_not_contains "$(cat "$log")" "rw plugin update"
}

test_failures_still_seal_and_fail_the_run() {
    local tmp out log rc

    tmp="$(mktemp -d)"

    # One failing update: the others still run, the tree is sealed, the run fails.
    log="$tmp/plugin-fails"
    rc=0
    out="$(FAKE_PLUGINS=akismet FAKE_THEMES=twentytwentyfive FAKE_FAIL='plugin update*' \
           run_update_flow "$log" 'wpu_auto_update' 2>&1)" || rc=$?
    assert_ne "$rc" "0" "a failed plugin update fails the run"
    assert_contains "$(cat "$log")" "rw theme update --all" "the remaining updates still run"
    assert_eq "$(tail -n1 "$log")" "SEAL" "the tree is sealed after a failed update"

    # The run dies inside the window: the EXIT handler stops the wp-cli unit
    # first, then seals, and keeps the exit status.
    log="$tmp/dies"
    rc=0
    out="$(run_update_flow "$log" '
        trap wpu_on_exit EXIT
        wpu_open_window
        RUN_UNIT=awesome-wordpress-update-1-1.service
        exit 3
    ' 2>&1)" || rc=$?
    assert_eq "$rc" "3" "the exit status survives the cleanup"
    assert_eq "$(cat "$log")" "OPEN
systemctl stop awesome-wordpress-update-1-1.service
SEAL" "an interrupted run stops wp-cli, then seals"

    # A seal that cannot finish turns a successful run into a failed one.
    log="$tmp/seal-fails"
    rc=0
    out="$(FAKE_PLUGINS=akismet FAKE_SEAL_RC=1 run_update_flow "$log" 'wpu_auto_update' 2>&1)" || rc=$?
    assert_ne "$rc" "0" "a failed seal fails the run"
    assert_contains "$out" "--seal" "the message names the repair command"

    # An update check that cannot complete is not reported as "up to date".
    log="$tmp/check-fails"
    rc=0
    out="$(FAKE_FAIL='plugin list*' run_update_flow "$log" 'wpu_auto_update' 2>&1)" || rc=$?
    assert_ne "$rc" "0" "a failed update check fails the run"
    assert_not_contains "$out" "is up to date"
    assert_not_contains "$(cat "$log")" "OPEN"
}

test_uninstalled_and_broken_sites() {
    local tmp out log rc=0
    tmp="$(mktemp -d)"

    log="$tmp/not-installed"
    out="$(FAKE_INSTALLED=no run_update_flow "$log" 'wpu_auto_update' 2>&1)"
    assert_contains "$out" "not installed yet"
    assert_eq "$(cat "$log")" "ro core is-installed" "an uninstalled site is left alone"

    # wp-cli printing an error (no database, PHP failure) is a failed run, not
    # a quiet "nothing to do" that would hide a site that never updates.
    log="$tmp/broken"
    out="$(FAKE_INSTALLED='Error: Error establishing a database connection.' \
           run_update_flow "$log" 'wpu_auto_update' 2>&1)" || rc=$?
    assert_ne "$rc" "0" "a site wp-cli cannot load fails the run"
    assert_contains "$out" "Error establishing a database connection"
    assert_not_contains "$(cat "$log")" "OPEN"
}

test_wp_cli_command_passthrough() {
    local tmp log rc=0
    tmp="$(mktemp -d)"

    log="$tmp/ok"
    run_update_flow "$log" 'wpu_run_command plugin install akismet --activate' >/dev/null 2>&1
    assert_eq "$(cat "$log")" "OPEN
rw plugin install akismet --activate
SEAL" "a wp-cli command runs inside a sealed window"

    log="$tmp/fails"
    run_update_flow "$log" 'FAKE_FAIL="plugin install*"; wpu_run_command plugin install nope' >/dev/null 2>&1 || rc=$?
    assert_ne "$rc" "0" "the command's failure is reported"
    assert_eq "$(tail -n1 "$log")" "SEAL" "the tree is sealed after a failed command"

    # Through the command line: arguments after -- reach wp-cli untouched.
    log="$tmp/main"
    run_update_flow "$log" '
        id() { echo 0; }
        wpu_validate_path() { :; }
        wpu_lock() { :; }
        wpu_require_runtime() { :; }
        wpu_recover() { :; }
        wpu_main -w /var/www/site -- eval "echo \$table_prefix;" --major
    ' >/dev/null 2>&1
    assert_contains "$(cat "$log")" 'rw eval echo $table_prefix; --major' "arguments after -- belong to wp-cli"

    log="$tmp/main-auto"
    FAKE_CORE=$'version,update_type\n6.9,major' FAKE_PLUGINS=akismet run_update_flow "$log" '
        id() { echo 0; }
        wpu_validate_path() { :; }
        wpu_lock() { :; }
        wpu_require_runtime() { :; }
        wpu_recover() { :; }
        wpu_main -w /var/www/site --major --core-only
    ' >/dev/null 2>&1
    assert_contains "$(cat "$log")" "
rw core update
"
    assert_not_contains "$(cat "$log")" "plugin"
}

test_wp_cli_runs_in_a_sandbox_as_the_update_account() {
    local tmp log line count=0
    tmp="$(mktemp -d)"
    log="$tmp/log"
    FAKE_CORE=$'version,update_type\n6.8.2,minor' FAKE_PLUGINS=akismet \
        run_update_flow "$log" 'wpu_auto_update' >/dev/null 2>&1

    while IFS= read -r line; do
        (( ++count ))
        assert_contains "$line" "User=wp-update" "wp-cli never runs as root or http"
        assert_contains "$line" "Group=http"
        assert_contains "$line" "NoNewPrivileges=yes"
        assert_contains "$line" "CapabilityBoundingSet= "
        assert_contains "$line" "ProtectSystem=strict"
        assert_contains "$line" "ProtectHome=yes"
        assert_contains "$line" "PrivateTmp=yes"
        assert_contains "$line" "--expand-environment=no" "a \$ in a wp-cli argument is not expanded by systemd"
        assert_contains "$line" "--wait"
        assert_contains "$line" "-- wp --path=/var/www/site --skip-plugins --skip-themes --no-color " \
            "plugin and theme code is never loaded"
        case "$line" in
            *"ReadWritePaths="*)
                assert_contains "$line" "ReadWritePaths=/var/www/site " "only the installation is writable"
                assert_contains "$line" "--unit=awesome-wordpress-update-" "a writing run is named so it can be stopped" ;;
            *)
                case "$line" in
                    *" core update"*|*" plugin update"*|*" theme update"*|*" language "*)
                        fail "a writing command ran without ReadWritePaths: $line" ;;
                esac ;;
        esac
    done < "$log.args"
    (( count >= 9 )) || fail "expected at least 9 wp-cli runs, saw $count"

    # The checks before the window must not be able to write anything.
    assert_not_contains "$(grep -E -- '-- wp .* (core check-update|plugin list|theme list)' "$log.args")" "ReadWritePaths"
}

# -----------------------------------------------------------------------------
# wordpress.sh: option, step 3, step 8, summary
# -----------------------------------------------------------------------------

test_wordpress_sh_uses_the_helper_for_permissions_and_updates() {
    local code out rc=0 summary
    code="$(script_code "$WP_SH")"

    out="$(bash "$WP_SH" --auto-update sometimes 2>&1)" || rc=$?
    assert_ne "$rc" "0" "--auto-update rejects unknown modes"
    assert_contains "$out" "Invalid --auto-update value: sometimes"
    out="$(bash "$WP_SH" --help 2>&1)"
    assert_contains "$out" "--auto-update MODE"

    # Step 3 applies the permissions through the installed helper, so the
    # state after an update is the state the script itself produces.
    assert_contains "$code" 'bash "$UPDATE_HELPER" --seal -w "$WP_PATH"'
    assert_contains "$code" 'install -o root -g root -m 0755 /dev/stdin "$UPDATE_HELPER"'

    # The old advice made every file writable by PHP-FPM for the update.
    summary="$(sed -n '/^# 9\. SUMMARY/,$p' "$WP_SH")"
    assert_not_contains "$summary" "chown -R http:http" "the summary no longer tells users to make the code writable for PHP"
    assert_contains "$summary" '$UPDATE_HELPER -w $WP_PATH --major'
    assert_not_contains "$(cat "$REPO_ROOT/hardening/wordpress/README.md")" "chown -R http:http /var/www/wordpress" \
        "the README no longer tells users to make the code writable for PHP"
}

# Run step 8 of wordpress.sh in a scratch root. $1 is the scratch directory,
# the remaining arguments are VAR=value settings for the step.
run_update_step() {
    local tmp="$1" step
    shift
    step="$(sed -n '/^# 8\. UPDATES/,/^# 9\. SUMMARY/p' "$WP_SH")"
    [[ -n "$step" ]] || { printf 'Step 8 not found in %s\n' "$WP_SH" >&2; return 1; }
    mkdir -p "$tmp/units"
    : > "$tmp/calls"
    env "$@" UNITS="$tmp/units" CALLS="$tmp/calls" STEP="${step//\/etc\/systemd\/system/$tmp/units}" bash -c '
        set -euo pipefail
        msg() { printf "msg %s\n" "$*"; }
        info() { printf "info %s\n" "$*"; }
        warn() { printf "warn %s\n" "$*"; }
        getent() { [[ "${HAVE_ACCOUNT:-yes}" == yes ]]; }
        useradd() { printf "useradd %s\n" "$*" >> "$CALLS"; }
        systemctl() { printf "systemctl %s\n" "$*" >> "$CALLS"; }
        wp_db_has_placeholders() { [[ "${PLACEHOLDERS:-no}" == yes ]]; }
        DOMAIN=blog.example.com
        WP_PATH=/var/www/wordpress
        UPDATE_HELPER=/usr/local/bin/awesome-wordpress-update
        WP_UPDATE_USER=wp-update
        # "=" and not ":=": an empty WP_CLI_BIN means "wp-cli is not installed".
        : "${AUTO_UPDATE=all}" "${WP_CLI_BIN=/usr/bin/env}" "${FRESH_INSTALL=false}" "${INITIAL_DB_PLACEHOLDER=false}"
        eval "$STEP"
        printf "UPDATE_TIMER=%s\n" "$UPDATE_TIMER"
    '
}

test_update_timer_is_enabled_only_when_it_can_work() {
    local tmp out service timer

    tmp="$(mktemp -d)"
    out="$(run_update_step "$tmp/all" HAVE_ACCOUNT=no)"
    service="$(cat "$tmp/all/units/wordpress-update-blog-example-com.service")"
    timer="$(cat "$tmp/all/units/wordpress-update-blog-example-com.timer")"
    assert_contains "$out" "UPDATE_TIMER=on"
    assert_contains "$service" "ExecStart=/usr/local/bin/awesome-wordpress-update -w /var/www/wordpress
" "the timer runs the helper for this site"
    assert_contains "$service" "Type=oneshot"
    assert_not_contains "$service" "User=" "the helper itself needs root; wp-cli is confined by the helper"
    assert_contains "$timer" "OnCalendar="
    assert_contains "$timer" "Persistent=true"
    assert_contains "$(cat "$tmp/all/calls")" "useradd -r -U -M -d /var/empty -s /usr/bin/nologin" "the update account is locked and has no shell"
    assert_contains "$(cat "$tmp/all/calls")" "systemctl enable --now wordpress-update-blog-example-com.timer"

    out="$(run_update_step "$tmp/core" AUTO_UPDATE=core)"
    assert_contains "$(cat "$tmp/core/units/wordpress-update-blog-example-com.service")" \
        "ExecStart=/usr/local/bin/awesome-wordpress-update -w /var/www/wordpress --core-only"
    assert_not_contains "$(cat "$tmp/core/calls")" "useradd" "an existing account is kept"
    assert_contains "$(cat "$tmp/core/calls")" "systemctl enable --now"

    out="$(run_update_step "$tmp/off" AUTO_UPDATE=off)"
    assert_contains "$out" "UPDATE_TIMER=off"
    assert_contains "$(cat "$tmp/off/calls")" "systemctl disable --now wordpress-update-blog-example-com.timer"
    assert_not_contains "$(cat "$tmp/off/calls")" "enable --now"
    assert_not_contains "$out" "warn " "--auto-update off is a choice, not a problem"

    # Without wp-cli, with wp-cli where the sandbox cannot see it, and before
    # WordPress is installed, an enabled timer would only fail every day:
    # leave it off and say that the site receives no updates.
    out="$(run_update_step "$tmp/no-wp-cli" WP_CLI_BIN=)"
    assert_contains "$out" "UPDATE_TIMER=off"
    assert_contains "$out" "warn Automatic updates are NOT active: wp-cli is not installed"
    assert_not_contains "$(cat "$tmp/no-wp-cli/calls")" "enable --now"

    out="$(run_update_step "$tmp/home-wp-cli" WP_CLI_BIN=/home/admin/bin/wp)"
    assert_contains "$out" "UPDATE_TIMER=off"
    assert_contains "$out" "NOT active"

    out="$(run_update_step "$tmp/fresh" PLACEHOLDERS=yes)"
    assert_contains "$out" "UPDATE_TIMER=off"
    assert_contains "$out" "warn Automatic updates are NOT active: WordPress is not installed yet"
    out="$(run_update_step "$tmp/fresh-flag" FRESH_INSTALL=true)"
    assert_contains "$out" "UPDATE_TIMER=off"
}

run_test "update helper: embedded in wordpress.sh, valid Bash, runs only when executed" test_helper_is_embedded_and_guarded
run_test "update helper: refuses paths outside /var/www and /srv/http" test_helper_refuses_paths_outside_the_web_roots
run_test "update helper: wp-cli must be root's own file" test_wp_cli_must_be_root_owned
run_test "update helper: --seal applies 750/640 and 770/660 without following links" test_seal_applies_the_permission_model
run_test "update helper: --seal creates uploads/ and reports a failed step" test_seal_creates_uploads_and_reports_failure
run_test "update helper: the update window covers the code only" test_update_window_excludes_writable_directories
run_test "update helper: an up-to-date site is checked read-only and not touched" test_nothing_pending_touches_nothing
run_test "update helper: pending updates are applied inside one sealed window" test_pending_updates_run_inside_one_sealed_window
run_test "update helper: --major and --core-only scopes" test_major_and_core_only_scopes
run_test "update helper: failures and interruptions still seal the code" test_failures_still_seal_and_fail_the_run
run_test "update helper: uninstalled sites are skipped, broken sites fail" test_uninstalled_and_broken_sites
run_test "update helper: wp-cli commands after -- run inside a sealed window" test_wp_cli_command_passthrough
run_test "update helper: wp-cli is sandboxed as wp-update without plugin code" test_wp_cli_runs_in_a_sandbox_as_the_update_account
run_test "wordpress.sh: permissions and updates go through the helper" test_wordpress_sh_uses_the_helper_for_permissions_and_updates
run_test "wordpress.sh: the update timer is enabled only when it can work" test_update_timer_is_enabled_only_when_it_can_work

finish_test_file "test_wordpress_update.sh"
