#!/usr/bin/env python3
"""Opt-in NVMe dropout workaround for this project's signed linux UKIs."""

import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile


CMDLINE = Path('/etc/kernel/cmdline')
PRESET = Path('/etc/mkinitcpio.d/linux.preset')
ESP = Path('/efi')
IMAGES = tuple(ESP / 'EFI/Linux' / name for name in (
    'arch-linux.efi', 'arch-linux-fallback.efi'))
STATE = Path('/var/lib/awesomearch/nvme-stability')
PARAMETERS = ('nvme_core.default_ps_max_latency_us=0',
              'pcie_aspm=off', 'pcie_port_pm=off')


def run(*args, capture=False):
    return subprocess.run([str(a) for a in args], check=True, text=True,
                          stdout=subprocess.PIPE if capture else None).stdout


def tokens(text):
    # Preserve kernel double quoting and backslashes; never evaluate shell text.
    text = ' '.join(line for line in text.splitlines()
                    if not line.lstrip().startswith('#'))
    if '\0' in text or text.count('"') % 2:
        raise ValueError('Invalid kernel command line')
    return re.findall(r'(?:[^\s"]|"[^"]*")+', text)


def with_workaround(text):
    current = tokens(text)
    if '--' in current:
        raise ValueError('Command lines containing an init argument separator are unsupported')
    if not any(t.startswith('root=') for t in current):
        raise ValueError('Refusing to change a command line without root=')
    keys = {p.split('=', 1)[0] for p in PARAMETERS}
    kept = [t for t in current if t.split('=', 1)[0].replace('-', '_') not in keys]
    return ' '.join(kept + list(PARAMETERS)) + '\n'


def embedded_cmdline(path):
    """Read only the PE section table and .cmdline, even for large UKIs."""
    with path.open('rb') as f:
        if f.read(2) != b'MZ':
            raise ValueError(f'{path}: not a PE image')
        f.seek(60)
        offset, = struct.unpack('<I', f.read(4))
        f.seek(offset)
        header = f.read(24)
        if header[:4] != b'PE\0\0':
            raise ValueError(f'{path}: invalid PE signature')
        count, = struct.unpack_from('<H', header, 6)
        optional_size, = struct.unpack_from('<H', header, 20)
        f.seek(optional_size, 1)
        for _ in range(count):
            section = f.read(40)
            if section[:8] == b'.cmdline':
                virtual_size, _, raw_size, start = struct.unpack_from('<IIII', section, 8)
                size = min(virtual_size, raw_size)
                if not 0 < size <= 1024 * 1024:
                    raise ValueError(f'{path}: invalid .cmdline size')
                f.seek(start)
                return f.read(size).rstrip(b'\0').decode().strip()
    raise ValueError(f'{path}: no embedded .cmdline')


def verify_signature(path):
    # sbctl verify can exit 0 for an unsigned file; check its JSON result too.
    result = json.loads(run('sbctl', '--json', 'verify', path, capture=True))
    if not isinstance(result, list) or not any(
            row.get('file_name') == str(path) and row.get('is_signed') == 1
            for row in result):
        raise ValueError(f'{path}: signature verification failed')


def verify_staged_signature(path):
    # sbctl's Landlock sandbox permits verification on the ESP, but may deny
    # arbitrary staging paths. Keep the sandbox enabled and copy one image at
    # a time outside EFI/Linux, where systemd-boot will not discover it.
    if shutil.disk_usage(ESP).free < path.stat().st_size + 16 * 1024**2:
        raise ValueError('Insufficient ESP space to verify a staged UKI')
    with tempfile.TemporaryDirectory(prefix='.nvme-verify-', dir=ESP) as directory:
        copy = Path(directory) / path.name
        shutil.copyfile(path, copy)
        verify_signature(copy)


def atomic_copy(source, target):
    fd, name = tempfile.mkstemp(prefix=f'.{target.name}.', dir=target.parent)
    try:
        with os.fdopen(fd, 'wb') as output, source.open('rb') as input_file:
            shutil.copyfileobj(input_file, output)
            output.flush()
            os.fsync(output.fileno())
        # FAT ignores Unix modes. cmdline on the root filesystem stays private.
        os.chmod(name, 0o600)
        os.replace(name, target)
        directory = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(name).unlink(missing_ok=True)


def preflight():
    if os.geteuid() != 0:
        raise ValueError('Administrator access required: run this command with sudo')
    for command in ('bash', 'mkinitcpio', 'sbctl', 'findmnt'):
        if shutil.which(command) is None:
            raise ValueError(f'Missing command: {command}')
    mount = json.loads(run('findmnt', '-J', '-M', ESP, '-o', 'TARGET,FSTYPE,OPTIONS', capture=True))
    filesystem = mount['filesystems'][0]
    if filesystem['fstype'] != 'vfat' or 'rw' not in filesystem['options'].split(','):
        raise ValueError('/efi must be a mounted, writable FAT EFI system partition')
    # Source only the existing root-owned mkinitcpio preset, as mkinitcpio does.
    settings = run('bash', '-c', '''
source "$1" || exit
printf '%s\n' "${PRESETS[*]}" "${default_uki}" "${fallback_uki}" "${default_options[*]}" "${fallback_options[*]}"
printf '%s' "${default_image}${fallback_image}${ALL_kerneldest}${default_kerneldest}${fallback_kerneldest}"
''', 'nvme-stability', PRESET, capture=True).splitlines()
    if settings != ['default fallback', *(str(p) for p in IMAGES), '', '-S autodetect']:
        raise ValueError('Unsupported linux.preset: expected this project\'s two UKI outputs only')
    for path in IMAGES:
        if not path.is_file() or path.is_symlink():
            raise ValueError(f'Missing or unsupported UKI: {path}')
        embedded_cmdline(path)
        verify_signature(path)


def deploy(sources, command_line):
    # Leave a complete old or new signed image at each path across copy failures.
    for source, target in zip(sources, IMAGES):
        atomic_copy(source, target)
    atomic_copy(command_line, CMDLINE)


def install_command_line(desired):
    original = CMDLINE.read_text()
    if tokens(original) == tokens(desired) and all(
            tokens(embedded_cmdline(p)) == tokens(desired) for p in IMAGES):
        print('Both signed UKIs already contain the requested command line. Check --status after boot.')
        return
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    required = 2 * sum(p.stat().st_size for p in IMAGES) + 1024**3
    if shutil.disk_usage(STATE).free < required:
        raise ValueError('Insufficient space for UKI staging and backups')
    backup = Path(tempfile.mkdtemp(prefix='backup-', dir=STATE))
    print(f'Backup and build directory: {backup}', flush=True)
    shutil.copy2(CMDLINE, backup / 'cmdline.before')
    shutil.copy2(PRESET, backup / 'linux.preset.before')
    for path in IMAGES:
        shutil.copyfile(path, backup / (path.name + '.before'))
    (backup / 'cmdline.after').write_text(desired)
    staged = [backup / p.name for p in IMAGES]
    # Preserve hooks, modules and kernel selection from the original preset.
    # Explicit final options force outputs into staging and use the new cmdline.
    wrapper = f'source {shlex.quote(str(PRESET))}\n'
    for preset, path in zip(('default', 'fallback'), staged):
        wrapper += f'{preset}_uki={shlex.quote(str(path))}\n'
    build_preset = backup / 'linux.preset'
    build_preset.write_text(wrapper)
    # Arguments after -- are forwarded to each preset's child mkinitcpio.
    run('mkinitcpio', '-p', build_preset, '--', '--cmdline', backup / 'cmdline.after', '--nopost')
    for path in staged:
        if tokens(embedded_cmdline(path)) != tokens(desired):
            raise ValueError(f'{path}: rebuilt command line differs; boot files unchanged')
        run('sbctl', 'sign', path)
        verify_staged_signature(path)
    # Atomic replacement requires room for one extra image, not both backups.
    growth = sum(max(0, new.stat().st_size - old.stat().st_size)
                 for new, old in zip(staged, IMAGES))
    if shutil.disk_usage(ESP).free < max(p.stat().st_size for p in staged) + growth + 16 * 1024**2:
        raise ValueError('Insufficient ESP space for atomic UKI replacement; boot files unchanged')
    try:
        deploy(staged, backup / 'cmdline.after')
        for path in IMAGES:
            verify_signature(path)
            if tokens(embedded_cmdline(path)) != tokens(desired):
                raise ValueError(f'{path}: installed command line differs')
    except BaseException:
        print('Installation failed; restoring original cmdline and signed UKIs.', file=sys.stderr)
        deploy([backup / (p.name + '.before') for p in IMAGES], backup / 'cmdline.before')
        raise
    print('Installed and verified both signed UKIs. The running kernel is unchanged.')
    print('Reboot when ready, then run this utility with --status.')
    print(f'Rollback: sudo python3 {shlex.quote(str(Path(__file__).resolve()))} --restore {backup}')


def restore(backup):
    preflight()
    backup = backup.resolve()
    if backup.parent != STATE.resolve() or backup.stat().st_uid != 0:
        raise ValueError(f'Expected a root-owned backup directory directly inside {STATE}')
    # Rebuild with the original command line using the currently installed kernel.
    # Restoring old kernel binaries after package upgrades could break module loading.
    before = (backup / 'cmdline.before').read_text()
    with_workaround(before)  # Validate without changing the saved command line.
    install_command_line(before)


def status():
    current = Path('/proc/cmdline').read_text()
    print('Running kernel parameters:')
    for parameter in PARAMETERS:
        print(f'  {parameter}: {"ACTIVE" if parameter in tokens(current) else "ABSENT"}')
    latency = Path('/sys/module/nvme_core/parameters/default_ps_max_latency_us')
    if latency.exists():
        print('NVMe APST default latency:', latency.read_text().strip())
    for path in IMAGES:
        try:
            active = all(p in tokens(embedded_cmdline(path)) for p in PARAMETERS)
            print(f'{path}: workaround {"embedded" if active else "absent"} (signature not checked)')
        except (OSError, ValueError, struct.error) as error:
            print(f'{path}: {error}')
    for hwmon in sorted(Path('/sys/class/hwmon').glob('hwmon*')):
        if (hwmon / 'name').read_text().strip() == 'nvme':
            temperature = int((hwmon / 'temp1_input').read_text()) / 1000
            device = (hwmon / 'device').resolve().name
            print(f'{device}: {temperature:.1f} C')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--status', action='store_true', help='read-only status (default)')
    group.add_argument('--apply', action='store_true', help='build, sign and install the workaround')
    group.add_argument('--restore', type=Path, metavar='BACKUP', help='restore a saved command line')
    args = parser.parse_args()
    if args.apply or args.restore:
        if os.geteuid() != 0:
            raise ValueError('Administrator access required: run this command with sudo')
        os.umask(0o077)
        with open('/run/awesome-nvme-stability.lock', 'w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if args.apply:
                preflight()
                print('Proposed kernel parameters:', ' '.join(PARAMETERS), flush=True)
                install_command_line(with_workaround(CMDLINE.read_text()))
            else:
                restore(args.restore)
    else:
        status()


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, struct.error, subprocess.CalledProcessError) as error:
        sys.exit(f'Error: {error}')
