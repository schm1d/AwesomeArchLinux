#!/usr/bin/env bash
# install-vmware-workstation.sh
# Arch Linux helper for AUR package vmware-workstation.
#
# Fixes seen on this host:
#   - /tmp mounted noexec → bundle: Permission denied on vmware-installer
#   - wrappers mode 711 (rwx--x--x) → scripts need +r or bash says Permission denied
#   - shipped .so mode 711 → AppLoader: cannot open shared object file: Permission denied
#   - missing / unreadable .desktop + icons → no GNOME launcher
set -euo pipefail

PKG="${PKG:-vmware-workstation}"
AUR_HELPER="${AUR_HELPER:-}"
RESTORE_TMP_NOEXEC=0

# Desktop file for the logged-in user, even if this script is run with sudo
REAL_USER="${SUDO_USER:-${USER:-$(id -un)}}"
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
    sudo -u "${REAL_USER}" "$@"
  else
    "$@"
  fi
}

detect_aur_helper() {
  if [[ -n ${AUR_HELPER} ]]; then
    need_cmd "${AUR_HELPER}"
    return
  fi
  local h
  for h in yay paru; do
    if command -v "${h}" >/dev/null 2>&1; then
      AUR_HELPER="${h}"
      return
    fi
  done
  die "no AUR helper found (install yay or paru, or set AUR_HELPER=)"
}

tmp_has_noexec() {
  findmnt -n -o OPTIONS /tmp 2>/dev/null | grep -qw noexec
}

remount_tmp_exec() {
  if tmp_has_noexec; then
    log "/tmp is mounted noexec — remounting exec for the VMware bundle"
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
  local pkgs=(base-devel dkms fuse2 gtk3 gtkmm3 libcanberra pcsclite hicolor-icon-theme desktop-file-utils linux-headers pipewire-alsa)
  if pacman -Qq linux-lts >/dev/null 2>&1; then
    pkgs+=(linux-lts-headers)
  fi
  log "ensuring build/runtime packages"
  sudo_run pacman -S --needed --noconfirm "${pkgs[@]}"
}

install_package() {
  detect_aur_helper
  log "installing ${PKG} with ${AUR_HELPER}"
  if [[ ${EUID} -eq 0 ]]; then
    die "do not run the AUR install as root; run this script as ${REAL_USER}"
  fi
  "${AUR_HELPER}" -S --needed --noconfirm "${PKG}"
}

# Mode 711 (rwx--x--x) is the recurring bug on this install:
#   wrappers are scripts → need +r or bash: Permission denied
#   .so files are ELF     → need +r or AppLoader: cannot open shared object
# Recurse the whole VMware tree; do not stop at /usr/bin.
fix_permissions() {
  log "fixing modes under /usr/lib/vmware (restricting to ${REAL_USER} and restoring SUID bits)"

  [[ -d /usr/lib/vmware ]] || die "/usr/lib/vmware missing — package not installed?"

  local rgroup
  rgroup="$(id -gn "${REAL_USER}")"

  # Change group ownership to the user's primary group so they can access it
  sudo_run chown -R root:"${rgroup}" /usr/lib/vmware

  # Allow root and the user's group to read/execute, but block all other users
  sudo_run chmod -R g+rX,o-rwx /usr/lib/vmware

  # Restore SUID bits for core binaries (CRITICAL for power-on)
  # 4750 means: SUID set (4), root rwx (7), group rx (5), others none (0)
  local suid_bins=(
    /usr/lib/vmware/bin/vmware-vmx
    /usr/lib/vmware/bin/vmware-vmx-debug
    /usr/lib/vmware/bin/vmware-vmx-stats
  )
  local b
  for b in "${suid_bins[@]}"; do
    [[ -e ${b} ]] && sudo_run chmod 4750 "${b}"
  done

  local wrappers=(
    /usr/bin/vmware
    /usr/bin/vmplayer
    /usr/bin/vmware-tray
    /usr/bin/vmware-netcfg
    /usr/bin/vmware-modconfig
    /usr/bin/vmware-mount
    /usr/bin/vmrun
    /usr/sbin/vmware-tray
    /usr/sbin/vmware-networks
    /usr/sbin/vmware-usbarbitrator
  )
  local p
  for p in "${wrappers[@]}"; do
    if [[ -e ${p} ]]; then
      sudo_run chown root:"${rgroup}" "${p}"
      sudo_run chmod 750 "${p}"
    fi
  done

  sudo_run find /usr/share/applications -maxdepth 1 -iname '*vmware*' -type f -exec chown root:"${rgroup}" {} + -exec chmod 640 {} + 2>/dev/null || true
  sudo_run find /usr/share/icons /usr/share/pixmaps -iname '*vmware*' -type f -exec chown root:"${rgroup}" {} + -exec chmod 640 {} + 2>/dev/null || true

  if [[ -e /usr/lib/vmware/lib/libvmware.so/libvmware.so ]]; then
    log "libvmware.so mode: $(stat -c '%a %n' /usr/lib/vmware/lib/libvmware.so/libvmware.so)"
  fi
  if [[ -e /usr/bin/vmware ]]; then
    log "wrapper mode: $(stat -c '%a %n' /usr/bin/vmware)"
  fi
}
 
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
  f="$(find /usr/share/icons /usr/share/pixmaps /usr/lib/vmware -iname '*workstation*.png' -o -iname '*vmware-workstation.png' -o -iname 'vmware.png' 2>/dev/null | head -n1 || true)"
  printf '%s' "${f}"
}

install_desktop() {
  local sys_desktop user_dir user_desktop icon
  sys_desktop="$(ls /usr/share/applications/*vmware*.desktop 2>/dev/null | head -n1 || true)"
  user_dir="${REAL_HOME}/.local/share/applications"
  user_desktop="${user_dir}/vmware-workstation.desktop"
  icon="$(pick_icon)"
  [[ -z ${icon} ]] && icon="vmware-workstation"

  log "installing desktop launcher for ${REAL_USER} (${user_desktop})"
  as_user mkdir -p "${user_dir}"

  if [[ -n ${sys_desktop} && -r ${sys_desktop} ]]; then
    log "found packaged desktop file: ${sys_desktop}"
    sudo_run chmod 644 "${sys_desktop}"
  fi

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

enable_services() {
  log "generating /etc/vmware/networking if needed"
  sudo_run systemctl start vmware-networks-configuration.service || true

  log "enabling network + USB services"
  sudo_run systemctl enable --now vmware-networks.service
  sudo_run systemctl enable --now vmware-usbarbitrator.service
}

load_modules() {
  log "loading vmw_vmci and vmmon"
  if ! sudo_run modprobe -a vmw_vmci vmmon; then
    warn "modprobe failed — Secure Boot may be blocking unsigned modules"
    warn "check: journalctl -k -b | grep -iE 'vmmon|Lockdown|secure'"
    return 1
  fi
  lsmod | grep -E 'vmmon|vmw_vmci|vmnet' || warn "modules not visible in lsmod yet"
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
  enable_services
  load_modules || true
  print_status
}

usage() {
  cat <<'EOF'
Usage: install-vmware-workstation.sh [command]

  install   (default) deps + AUR package + perms + desktop + services + modules
  fix       perms + desktop + services + modules (package already installed)
  perms     chmod 755 wrappers AND shipped libs under /usr/lib/vmware
  desktop   write ~/.local/share/applications/vmware-workstation.desktop
  services  enable vmware-networks + vmware-usbarbitrator, load modules
  modules   only modprobe vmw_vmci vmmon
  help

Env:
  AUR_HELPER=yay|paru
  PKG=vmware-workstation

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
      enable_services
      load_modules || true
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
