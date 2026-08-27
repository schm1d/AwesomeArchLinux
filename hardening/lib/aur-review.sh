#!/usr/bin/env bash

# Review-gated AUR package installation shared by hardening scripts.
#
# AUR recipes are mutable, user-produced build instructions. This helper
# checks out one exact AUR commit, renders every tracked recipe file with
# terminal control characters escaped, and requires an exact confirmation
# before evaluating PKGBUILD through makepkg. Builds run as a disposable,
# unprivileged user; only the specifically requested package is handed to
# pacman as root.
# Reference: https://wiki.archlinux.org/title/Arch_User_Repository
# Reference: https://man.archlinux.org/man/makepkg.8.en

_aal_aur_error() { printf '[AUR REVIEW ERROR] %s\n' "$*" >&2; }
_aal_aur_info()  { printf '[AUR REVIEW] %s\n' "$*"; }

_aal_aur_declared_dependencies() {
    local srcinfo=$1 package=$2 build_arch=$3

    awk -v target="$package" -v build_arch="$build_arch" '
        BEGIN { section = "base" }
        /^[[:space:]]*pkgname[[:space:]]*=/ {
            value = $0
            sub(/^[^=]*=[[:space:]]*/, "", value)
            section = (value == target ? "target" : "other")
            next
        }
        section == "base" || section == "target" {
            line = $0
            sub(/^[[:space:]]*/, "", line)
            split_at = index(line, " = ")
            if (!split_at) next
            key = substr(line, 1, split_at - 1)
            value = substr(line, split_at + 3)
            if (key ~ /^(depends|makedepends|checkdepends)$/ ||
                key ~ "^(depends|makedepends|checkdepends)_" build_arch "$") {
                print value
            }
        }
    ' "$srcinfo" | LC_ALL=C sort -u
}

_aal_aur_show_review() {
    local builddir=$1 package=$2 pkgbase=$3 commit=$4 file

    printf '\n========================================================================\n'
    printf ' AUR PACKAGE REVIEW REQUIRED\n'
    printf '========================================================================\n'
    printf 'Requested package: %s\n' "$package"
    printf 'AUR package base:  %s\n' "$pkgbase"
    printf 'AUR repository:    https://aur.archlinux.org/%s.git\n' "$pkgbase"
    printf 'Exact commit:      %s\n' "$commit"
    printf 'Checkout path:     %s\n' "$builddir"
    printf '\nCommit metadata (control characters escaped):\n'
    git -C "$builddir" show --no-patch --format=fuller "$commit" | cat -vET

    if grep -Eq '^[[:space:]]*(b2|md5|sha[0-9]+)sums[^=]*=.*SKIP' "$builddir/PKGBUILD"; then
        printf '\nWARNING: PKGBUILD contains at least one SKIP checksum.\n'
    fi

    printf '\nTracked build-recipe files follow. Review all commands, sources,\n'
    printf 'checksums, install scripts, patches, and package() destinations.\n'
    while IFS= read -r -d '' file; do
        printf '\n------------------------------------------------------------------------\n'
        printf ' FILE: %q\n' "$file"
        printf '%s\n' '------------------------------------------------------------------------'
        cat -vET -- "$builddir/$file"
    done < <(git -C "$builddir" ls-files -z)
    printf '\n========================================================================\n'
}

_aal_aur_install_dependencies() {
    local builddir=$1 package=$2 dependency dependency_name
    local build_arch missing_output
    local -a dependencies=() missing=() repo_packages=() aur_packages=()

    build_arch=$(uname -m)
    # Arch Linux names its 32-bit ARMv7 architecture armv7h although uname
    # reports armv7l on those systems.
    [[ "$build_arch" == armv7l ]] && build_arch=armv7h
    [[ "$build_arch" =~ ^[A-Za-z0-9_]+$ ]] || {
        _aal_aur_error "Could not determine a safe build architecture: $build_arch"
        return 1
    }

    mapfile -t dependencies < <(
        _aal_aur_declared_dependencies "$builddir/.SRCINFO" "$package" "$build_arch"
    )
    (( ${#dependencies[@]} > 0 )) || return 0

    missing_output=$(pacman -T "${dependencies[@]}" 2>/dev/null || true)
    [[ -n "$missing_output" ]] || return 0
    mapfile -t missing <<< "$missing_output"

    for dependency in "${missing[@]}"; do
        dependency_name="${dependency%%[<>=]*}"
        [[ "$dependency_name" =~ ^[a-zA-Z0-9@._+-]+$ ]] || {
            _aal_aur_error "Unsafe dependency name in .SRCINFO: $dependency"
            return 1
        }
        if pacman -Si "$dependency_name" &>/dev/null; then
            repo_packages+=("$dependency_name")
        else
            aur_packages+=("$dependency_name")
        fi
    done

    if (( ${#repo_packages[@]} > 0 )); then
        _aal_aur_info "Installing reviewed recipe dependencies from signed Arch repositories: ${repo_packages[*]}"
        pacman -S --needed --noconfirm "${repo_packages[@]}"
    fi

    for dependency_name in "${aur_packages[@]}"; do
        _aal_aur_info "AUR dependency '$dependency_name' requires its own review."
        aal_aur_install_reviewed "$dependency_name"
    done

    missing_output=$(pacman -T "${dependencies[@]}" 2>/dev/null || true)
    if [[ -n "$missing_output" ]]; then
        _aal_aur_error "Unresolved dependencies remain after review: ${missing_output//$'\n'/, }"
        _aal_aur_error "Install an appropriate provider explicitly, then rerun the parent script."
        return 1
    fi
}

# Usage: aal_aur_install_reviewed PACKAGE [PACKAGE_BASE]
# PACKAGE_BASE is only needed for split AUR packages whose Git repository name
# differs from the requested binary package name.
aal_aur_install_reviewed() (
    set -euo pipefail
    IFS=$'\n\t'

    local package=${1:-} pkgbase=${2:-${1:-}}
    local tmpdir="" builddir="" build_user="" commit="" confirmation=""
    local review_fd="" selected_package="" package_sha256="" installed_version=""
    local package_file resolved_file built_name
    local build_user_created=false
    local -a package_files=() selected_packages=()

    [[ $# -ge 1 && $# -le 2 ]] || {
        _aal_aur_error "Usage: aal_aur_install_reviewed PACKAGE [PACKAGE_BASE]"
        return 2
    }
    for value in "$package" "$pkgbase"; do
        [[ "$value" =~ ^[a-zA-Z0-9@._+-]+$ ]] || {
            _aal_aur_error "Unsafe AUR package name: $value"
            return 2
        }
    done

    (( EUID == 0 )) || {
        _aal_aur_error "Reviewed AUR installation must be run as root."
        return 1
    }

    if pacman -Qq "$package" &>/dev/null; then
        _aal_aur_info "$package is already installed; no mutable AUR source was fetched."
        return 0
    fi

    for command in git makepkg pacman runuser useradd userdel pkill sha256sum; do
        command -v "$command" &>/dev/null || {
            _aal_aur_error "Required command is unavailable: $command"
            return 1
        }
    done

    case ":${AAL_AUR_RESOLUTION_STACK:-}:" in
        *":$package:"*)
            _aal_aur_error "AUR dependency cycle detected: ${AAL_AUR_RESOLUTION_STACK:-} -> $package"
            return 1
            ;;
    esac
    export AAL_AUR_RESOLUTION_STACK="${AAL_AUR_RESOLUTION_STACK:+${AAL_AUR_RESOLUTION_STACK}:}${package}"

    if ! exec {review_fd}<>/dev/tty; then
        _aal_aur_error "A controlling terminal is required for package review; refusing unattended AUR installation."
        return 1
    fi

    cleanup() {
        if [[ "$build_user_created" == true && -n "$build_user" ]]; then
            pkill -KILL -u "$build_user" 2>/dev/null || true
            userdel "$build_user" 2>/dev/null || true
        fi
        if [[ -n "$tmpdir" ]]; then
            case "$tmpdir" in
                /var/tmp/awesome-aur-review.*) rm -rf -- "$tmpdir" ;;
                *) _aal_aur_error "Refusing to clean unexpected temporary path: $tmpdir" ;;
            esac
        fi
    }
    trap cleanup EXIT
    trap 'exit 130' HUP INT TERM

    tmpdir=$(mktemp -d /var/tmp/awesome-aur-review.XXXXXX)
    builddir="$tmpdir/$pkgbase"
    _aal_aur_info "Fetching $pkgbase from the AUR without executing its recipe."
    git clone --quiet -- "https://aur.archlinux.org/${pkgbase}.git" "$builddir"
    commit=$(git -C "$builddir" rev-parse --verify HEAD)
    [[ "$commit" =~ ^[0-9a-f]{40,64}$ ]] || {
        _aal_aur_error "Could not resolve an exact AUR commit for $pkgbase."
        return 1
    }
    [[ -f "$builddir/PKGBUILD" && ! -L "$builddir/PKGBUILD" ]] || {
        _aal_aur_error "The AUR checkout has no regular PKGBUILD."
        return 1
    }
    [[ -f "$builddir/.SRCINFO" && ! -L "$builddir/.SRCINFO" ]] || {
        _aal_aur_error "The AUR checkout has no regular .SRCINFO; refusing to evaluate PKGBUILD."
        return 1
    }
    if git -C "$builddir" ls-files -s | awk '$1 != "100644" && $1 != "100755" { bad=1 } END { exit !bad }'; then
        _aal_aur_error "The AUR recipe contains a symlink, submodule, or unsupported tracked file mode."
        return 1
    fi
    if ! awk -v target="$package" '$1 == "pkgname" && $3 == target { found=1 } END { exit !found }' \
        "$builddir/.SRCINFO"; then
        _aal_aur_error "Package '$package' is not declared by AUR package base '$pkgbase'."
        return 1
    fi

    _aal_aur_show_review "$builddir" "$package" "$pkgbase" "$commit"
    printf 'Type exactly: INSTALL %s %s\n> ' "$package" "$commit" >&"$review_fd"
    IFS= read -r -u "$review_fd" confirmation || {
        _aal_aur_error "Could not read review confirmation."
        return 1
    }
    if [[ "$confirmation" != "INSTALL $package $commit" ]]; then
        _aal_aur_error "Review not confirmed; $package was not built or installed."
        return 1
    fi

    _aal_aur_install_dependencies "$builddir" "$package"

    build_user="_aalbuild_${BASHPID}"
    useradd -r -M -d /var/empty -s /usr/bin/nologin "$build_user"
    build_user_created=true
    chown root:"$build_user" "$tmpdir"
    chmod 0710 "$tmpdir"
    install -d -o "$build_user" -g "$build_user" -m 0700 "$builddir/.home"
    chown -R "$build_user":"$build_user" "$builddir"

    _aal_aur_info "Building reviewed commit $commit as disposable user $build_user."
    (
        cd "$builddir"
        runuser -u "$build_user" -- env HOME="$builddir/.home" \
            makepkg --cleanbuild --noconfirm
        mapfile -t package_files < <(
            runuser -u "$build_user" -- env HOME="$builddir/.home" makepkg --packagelist
        )
        (( ${#package_files[@]} > 0 )) || {
            _aal_aur_error "makepkg produced no package paths."
            exit 1
        }
        printf '%s\0' "${package_files[@]}" > "$tmpdir/package-paths"
    )

    # Terminate any recipe-spawned background process before root examines the
    # package archive, then revoke the disposable build identity.
    pkill -KILL -u "$build_user" 2>/dev/null || true
    userdel "$build_user"
    build_user_created=false

    while IFS= read -r -d '' package_file; do
        resolved_file=$(realpath -e -- "$package_file") || {
            _aal_aur_error "Could not resolve package artifact: $package_file"
            return 1
        }
        case "$resolved_file" in
            "$builddir"/*) ;;
            *)
                _aal_aur_error "Refusing package artifact outside the reviewed build directory: $resolved_file"
                return 1
                ;;
        esac
        [[ -f "$resolved_file" && ! -L "$resolved_file" ]] || {
            _aal_aur_error "Package artifact is not a regular file: $resolved_file"
            return 1
        }
        built_name=$(pacman -Qp -- "$resolved_file" | awk 'NR == 1 { print $1 }')
        if [[ "$built_name" == "$package" ]]; then
            selected_packages+=("$resolved_file")
        fi
    done < "$tmpdir/package-paths"

    (( ${#selected_packages[@]} == 1 )) || {
        _aal_aur_error "Expected exactly one '$package' artifact; found ${#selected_packages[@]}."
        return 1
    }
    selected_package=${selected_packages[0]}
    chown root:root "$selected_package"
    chmod 0600 "$selected_package"
    package_sha256=$(sha256sum -- "$selected_package" | awk '{ print $1 }')

    _aal_aur_info "Installing only the reviewed '$package' artifact (SHA-256: $package_sha256)."
    pacman -U --needed --noconfirm -- "$selected_package"
    installed_version=$(pacman -Q "$package" | awk '{ print $2 }')

    install -d -o root -g root -m 0700 /var/lib/awesomearchlinux/aur-reviews
    printf 'package=%s\npkgbase=%s\nversion=%s\naur_commit=%s\npackage_sha256=%s\nreviewed_at=%s\n' \
        "$package" "$pkgbase" "$installed_version" "$commit" "$package_sha256" \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        > "/var/lib/awesomearchlinux/aur-reviews/${package}.txt"
    chmod 0600 "/var/lib/awesomearchlinux/aur-reviews/${package}.txt"
    _aal_aur_info "Recorded the reviewed commit and package hash for $package."
)
