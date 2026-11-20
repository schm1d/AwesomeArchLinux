#!/usr/bin/env bash
# =============================================================================
# Script:      vmware-workstation.sh
# Description: Arch Linux installer & permission helper for AUR vmware-workstation.
#              Handles /tmp noexec, home default POSIX ACLs, SUID binaries,
#              desktop launchers, kernel modules, and installs a pacman hook
#              so permissions survive upgrades.
# =============================================================================
set -euo pipefail

umask 022

PKG="${PKG:-vmware-workstation}"
AUR_HELPER="${AUR_HELPER:-}"
RESTORE_TMP_NOEXEC=0

readonly HOOK_HELPER="/usr/local/lib/awesomearchlinux/vmware-fix-permissions.sh"
readonly PACMAN_HOOK="/etc/pacman.d/hooks/99-awesome-vmware-permissions.hook"

resolve_target_user() {
  local candidate="${SUDO_USER:-}"
  if [[ -z "$candidate" || "$candidate" == "root" ]]; then
    if [[ ${EUID} -ne 0 ]]; then
      candidate="$(id -un)"
    else
      candidate="$(awk -F: '$3 >= 1000 && $3 < 65534 && $7 !~ /(nologin|false)/ { print $1; exit }' /etc/passwd)"
    fi
  fi
  printf '%s' "${candidate:-root}"
}

REAL_USER="$(resolve_target_user)"
if [[ ${REAL_USER} == root ]]; then
  REAL_HOME="${HOME:-/root}"
else
  REAL_HOME="$(getent passwd "${REAL_USER}" | cut -d: -f6)"
  REAL_HOME="${REAL_HOME:-/home/${REAL_USER}}"
fi

log()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m==>\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m==>\033[0m %s\n' "$*" >&2; exit 1; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || die "missing command: $1"; }

sudo_run() {
  if [[ ${EUID} -eq 0 ]]; then
    "$@"
  else
    need_cmd sudo
    sudo "$@"
  fi
}

as_user() {
  if [[ ${EUID} -eq 0 && ${REAL_USER} != root ]]; then
    if command -v runuser >/dev/null 2>&1; then
      runuser -u "${REAL_USER}" -- "$@"
    else
      sudo -u "${REAL_USER}" "$@"
    fi
  else
    "$@"
  fi
}

# Review-gated AUR builder shared with the installer (base stages a copy as
# /root/aur-review.sh on installed systems).
find_aur_review_lib() {
  local script_dir candidate
  script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
  for candidate in "${script_dir}/../hardening/lib/aur-review.sh" "${script_dir}/aur-review.sh" /root/aur-review.sh; do
    if [[ -r ${candidate} ]]; then
      printf '%s' "${candidate}"
      return 0
    fi
  done
  return 1
}

tmp_has_noexec() {
  findmnt -n -o OPTIONS /tmp 2>/dev/null | grep -qw noexec
}

remount_tmp_exec() {
  if tmp_has_noexec; then
    log "/tmp is mounted noexec — remounting exec temporarily for the VMware bundle"
    sudo_run mount -o remount,exec /tmp
    RESTORE_TMP_NOEXEC=1
  else
    log "/tmp already allows exec"
  fi
}

restore_tmp() {
  if [[ ${RESTORE_TMP_NOEXEC} -eq 1 ]]; then
    log "restoring /tmp noexec"
    sudo_run mount -o remount,noexec /tmp || warn "could not restore noexec on /tmp"
  fi
}

install_deps() {
  local pkgs=(base-devel git dkms fuse2 gtk3 gtkmm3 libcanberra pcsclite hicolor-icon-theme desktop-file-utils pipewire-alsa)
  if pacman -Qq linux >/dev/null 2>&1; then
    pkgs+=(linux-headers)
  fi
  if pacman -Qq linux-lts >/dev/null 2>&1; then
    pkgs+=(linux-lts-headers)
  fi
  if pacman -Qq linux-zen >/dev/null 2>&1; then
    pkgs+=(linux-zen-headers)
  fi
  log "ensuring build/runtime packages"
  sudo_run pacman -S --needed --noconfirm "${pkgs[@]}"
}

# AUR recipes are mutable, user-submitted build instructions. Instead of
# `yay/paru -S --noconfirm`, each one goes through the reviewed builder: it
# shows the exact recipe commit, waits for a typed confirmation on the terminal
# and builds as a disposable unprivileged user. A package that is already
# installed is left alone (upgrade it with your usual AUR workflow).
install_package() {
  [[ ${REAL_USER} != root ]] || die "cannot determine non-root target user for VMware group ownership"
  if [[ -n ${AUR_HELPER} ]]; then
    warn "AUR_HELPER=${AUR_HELPER} is ignored: AUR packages are built through the reviewed builder"
  fi

  local aur_lib pkg
  aur_lib="$(find_aur_review_lib)" \
    || die "hardening/lib/aur-review.sh not found — run this script from a full checkout of the repository"

  for pkg in vmware-keymaps "${PKG}"; do
    log "installing ${pkg} from the AUR (the recipe is shown for review first)"
    # shellcheck disable=SC2016
    sudo_run bash -c 'set -euo pipefail; source "$1"; aal_aur_install_reviewed "$2"' _ "${aur_lib}" "${pkg}" \
      || die "${pkg} was not installed (review declined, no terminal, or the build failed). If pacman reported '/usr/lib/vmware/xkeymap/...: exists in filesystem', an older VMware installation left those files behind: move /usr/lib/vmware/xkeymap away and re-run."
  done
}

install_pacman_hook() {
  local rgroup="$1"
  local helper_content hook_content

  helper_content="$(cat <<EOF
#!/usr/bin/env bash
set -euo pipefail
umask 022
rgroup=${rgroup@Q}
[[ -d /usr/lib/vmware && ! -L /usr/lib/vmware ]] || exit 0
if command -v setfacl >/dev/null 2>&1; then
  setfacl -bR /usr/lib/vmware 2>/dev/null || true
fi
chown -hR root:"\${rgroup}" /usr/lib/vmware
chmod -R g+rX,o-rwx /usr/lib/vmware
for b in \\
  /usr/lib/vmware/bin/vmware-vmx \\
  /usr/lib/vmware/bin/vmware-vmx-debug \\
  /usr/lib/vmware/bin/vmware-vmx-stats \\
  /usr/lib/vmware/bin/vmware-authd; do
  if [[ -f "\${b}" && ! -L "\${b}" ]]; then
    chown root:"\${rgroup}" "\${b}"
    chmod 4750 "\${b}"
  fi
done
for p in \\
  /usr/bin/vmware /usr/bin/vmplayer /usr/bin/vmware-tray /usr/bin/vmware-netcfg \\
  /usr/bin/vmware-modconfig /usr/bin/vmware-mount /usr/bin/vmrun \\
  /usr/sbin/vmware-tray /usr/sbin/vmware-networks /usr/sbin/vmware-usbarbitrator; do
  if [[ -f "\${p}" && ! -L "\${p}" ]]; then
    command -v setfacl >/dev/null 2>&1 && setfacl -b "\${p}" 2>/dev/null || true
    chown root:"\${rgroup}" "\${p}"
    chmod 0750 "\${p}"
  fi
done
EOF
)"

  hook_content="$(cat <<EOF
[Trigger]
Operation = Install
Operation = Upgrade
Type = Path
Target = usr/lib/vmware/*

[Action]
Description = Hardening VMware Workstation permissions and SUID binaries...
When = PostTransaction
Exec = ${HOOK_HELPER}
EOF
)"

  sudo_run install -d -m 0755 -o root -g root "$(dirname "${HOOK_HELPER}")" "$(dirname "${PACMAN_HOOK}")"
  printf '%s\n' "${helper_content}" | sudo_run install -m 0755 -o root -g root /dev/stdin "${HOOK_HELPER}"
  printf '%s\n' "${hook_content}"   | sudo_run install -m 0644 -o root -g root /dev/stdin "${PACMAN_HOOK}"
}

fix_permissions() {
  [[ ${REAL_USER} != root ]] || die "cannot determine non-root target user for VMware group ownership"
  log "fixing modes under /usr/lib/vmware (restricting to ${REAL_USER} and restoring SUID bits)"

  [[ -d /usr/lib/vmware && ! -L /usr/lib/vmware ]] || die "/usr/lib/vmware missing — package not installed?"

  local rgroup
  rgroup="$(id -gn "${REAL_USER}")"

  install_pacman_hook "${rgroup}"
  sudo_run "${HOOK_HELPER}"

  sudo_run find /usr/share/applications -maxdepth 1 -iname '*vmware*' -type f \
    -exec chown -h root:"${rgroup}" {} + -exec chmod 0644 {} + 2>/dev/null || true
  sudo_run find /usr/share/icons /usr/share/pixmaps -iname '*vmware*' -type f \
    -exec chown -h root:"${rgroup}" {} + -exec chmod 0644 {} + 2>/dev/null || true

  if [[ -e /usr/lib/vmware/lib/libvmware.so/libvmware.so ]]; then
    log "libvmware.so mode: $(stat -c '%a %n' /usr/lib/vmware/lib/libvmware.so/libvmware.so)"
  fi
  if [[ -e /usr/bin/vmware ]]; then
    log "wrapper mode: $(stat -c '%a %n' /usr/bin/vmware)"
  fi
}

pick_icon() {
  local f
  local candidates=(
    /usr/share/icons/hicolor/256x256/apps/vmware-workstation.png
    /usr/share/icons/hicolor/128x128/apps/vmware-workstation.png
    /usr/share/icons/hicolor/48x48/apps/vmware-workstation.png
    /usr/share/icons/hicolor/256x256/apps/vmware-player.png
    /usr/share/pixmaps/vmware-workstation.png
    /usr/share/pixmaps/vmware-player.png
  )
  for f in "${candidates[@]}"; do
    [[ -r ${f} ]] && { printf '%s' "${f}"; return; }
  done
  f="$(find /usr/share/icons /usr/share/pixmaps /usr/lib/vmware \( -iname '*workstation*.png' -o -iname '*vmware-workstation.png' -o -iname 'vmware.png' \) -print -quit 2>/dev/null || true)"
  printf '%s' "${f}"
}

install_desktop() {
  [[ ${REAL_USER} != root ]] || return 0
  local user_dir user_desktop icon
  user_dir="${REAL_HOME}/.local/share/applications"
  user_desktop="${user_dir}/vmware-workstation.desktop"
  icon="$(pick_icon)"
  [[ -z ${icon} ]] && icon="vmware-workstation"

  log "installing desktop launcher for ${REAL_USER} (${user_desktop})"
  as_user mkdir -p "${user_dir}"

  as_user tee "${user_desktop}" >/dev/null <<EOF
[Desktop Entry]
Version=1.0
Name=VMware Workstation
GenericName=Virtual Machine Manager
Comment=Run multiple operating systems as virtual machines
Exec=vmware %U
TryExec=vmware
Icon=${icon}
Terminal=false
Type=Application
Categories=System;Emulator;
StartupNotify=true
StartupWMClass=vmware
Keywords=virtual;machine;vm;hypervisor;
MimeType=application/x-vmware-vm;application/x-vmware-team;application/x-vmware-enc-vm;application/x-vmware-vm-snapshot;
EOF
  as_user chmod 644 "${user_desktop}"

  if command -v update-desktop-database >/dev/null 2>&1; then
    as_user update-desktop-database "${user_dir}" 2>/dev/null || true
    sudo_run update-desktop-database /usr/share/applications 2>/dev/null || true
  fi
  if command -v gtk-update-icon-cache >/dev/null 2>&1 && [[ -d /usr/share/icons/hicolor ]]; then
    sudo_run gtk-update-icon-cache -f /usr/share/icons/hicolor 2>/dev/null || true
  fi
  if command -v desktop-file-validate >/dev/null 2>&1; then
    desktop-file-validate "${user_desktop}" || warn "desktop file has warnings"
  fi

  log "GNOME: Super → type VMware → Pin to Dash (desktop icons are off by default)"
}

load_modules() {
  log "loading vmw_vmci, vmmon, and vmnet"
  if ! sudo_run modprobe -a vmw_vmci vmmon vmnet; then
    warn "modprobe failed — Secure Boot may be blocking unsigned DKMS modules"
    if command -v sbctl >/dev/null 2>&1 && sbctl status 2>/dev/null | grep -qE 'Secure Boot:[[:space:]]*.*[Ee]nabled'; then
      warn "Secure Boot is ENABLED: sign DKMS modules or configure MOK/kernel module signing"
    fi
    warn "check: journalctl -k -b | grep -iE 'vmmon|vmnet|Lockdown|secure'"
    return 1
  fi
  lsmod | grep -E 'vmmon|vmw_vmci|vmnet' || warn "modules not visible in lsmod yet"
}

enable_services() {
  log "generating /etc/vmware/networking if needed"
  sudo_run systemctl start vmware-networks-configuration.service || true

  log "enabling network + USB services"
  sudo_run systemctl enable --now vmware-networks.service
  sudo_run systemctl enable --now vmware-usbarbitrator.service
}

print_status() {
  echo
  log "status"
  printf '  networks:     %s / %s\n' \
    "$(systemctl is-enabled vmware-networks.service 2>/dev/null || echo n/a)" \
    "$(systemctl is-active  vmware-networks.service 2>/dev/null || echo n/a)"
  printf '  usb:          %s\n' \
    "$(systemctl is-active vmware-usbarbitrator.service 2>/dev/null || echo n/a)"
  if [[ -e /usr/bin/vmware ]]; then
    printf '  /usr/bin/vmware: %s\n' "$(stat -c '%A %U %n' /usr/bin/vmware)"
  fi
  local lib=/usr/lib/vmware/lib/libvmware.so/libvmware.so
  [[ -e ${lib} ]] && printf '  libvmware.so:   %s\n' "$(stat -c '%A %n' "${lib}")"
  local desk="${REAL_HOME}/.local/share/applications/vmware-workstation.desktop"
  [[ -e ${desk} ]] && printf '  launcher:     %s\n' "${desk}"
  echo
  log "start as ${REAL_USER}, not root:  vmware"
}

post_install_fix() {
  fix_permissions
  install_desktop
  load_modules || true
  enable_services
  print_status
}

usage() {
  cat <<'EOF'
Usage: ./vmware-workstation.sh [command]

  install   (default) deps + AUR package + perms + desktop + modules + services
  fix       perms + desktop + modules + services (package already installed)
  perms     repair modes, SUID binaries, and pacman hook for /usr/lib/vmware
  desktop   write ~/.local/share/applications/vmware-workstation.desktop
  services  load modules and enable vmware-networks + vmware-usbarbitrator
  modules   only modprobe vmw_vmci vmmon vmnet
  help

Env:
  PKG=vmware-workstation
  AUR_HELPER is no longer used: vmware-keymaps and PKG are built through the
  reviewed AUR builder (hardening/lib/aur-review.sh), which shows each recipe
  and needs a typed confirmation on the terminal.

Do not launch the GUI with sudo.
EOF
}

main() {
  local cmd="${1:-install}"
  case "${cmd}" in
    help|-h|--help) usage; exit 0 ;;
  esac

  need_cmd pacman
  need_cmd findmnt
  trap restore_tmp EXIT

  case "${cmd}" in
    install)
      remount_tmp_exec
      install_deps
      install_package
      restore_tmp
      RESTORE_TMP_NOEXEC=0
      post_install_fix
      ;;
    fix)
      post_install_fix
      ;;
    perms)
      fix_permissions
      [[ -e /usr/bin/vmware ]] || die "/usr/bin/vmware not found"
      ;;
    desktop)
      install_desktop
      ;;
    services)
      load_modules || true
      enable_services
      print_status
      ;;
    modules)
      load_modules
      ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main "$@"
