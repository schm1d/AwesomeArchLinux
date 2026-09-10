#!/usr/bin/env python3
"""Thermal monitoring for explicitly supported motherboard models."""

import argparse
import configparser
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

DMI = Path('/sys/class/dmi/id')
HWMON = Path('/sys/class/hwmon')
BOARD = ('ASUSTeK COMPUTER INC.', 'ROG ZENITH II EXTREME ALPHA')
INSTALLED = Path('/usr/local/bin/awesome-board-health')
CONFIG = Path('/etc/awesome-board-health.conf')
UNITS = Path('/etc/systemd/system')
STATE = Path('/run/awesome-board-health/state.json')
DEFAULTS = {'nvme': 70, 'cpu': 85, 'chipset': 85, 'vrm': 90}
REPEAT_SECONDS = 1800
HYSTERESIS_C = 3

CONFIG_TEXT = '''# Operational warning levels in Celsius, not hardware maximum ratings.
# Alerts require two consecutive samples; recovery requires 3 C below the limit.
[temperature]
nvme = 70
cpu = 85
chipset = 85
vrm = 90
'''

SERVICE = '''[Unit]
Description=AwesomeArchLinux motherboard thermal monitoring
After=systemd-modules-load.service
ConditionVirtualization=no

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /usr/local/bin/awesome-board-health --check
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
'''

TIMER = '''[Unit]
Description=Check motherboard and NVMe temperatures every minute

[Timer]
OnBootSec=2min
OnUnitActiveSec=1min
AccuracySec=5s

[Install]
WantedBy=timers.target
'''


def read(path, default='unknown'):
    try:
        return path.read_text().strip()
    except OSError:
        return default


def supported():
    return (read(DMI / 'board_vendor'), read(DMI / 'board_name')) == BOARD


def thresholds():
    config = configparser.ConfigParser()
    config.read(CONFIG)
    result = dict(DEFAULTS)
    if config.has_section('temperature'):
        for key, value in config.items('temperature'):
            if key not in result:
                raise ValueError(f'Unknown temperature setting: {key}')
            number = int(value)
            if not 40 <= number <= 110:
                raise ValueError(f'{key}: expected a warning temperature between 40 and 110 C')
            result[key] = number
    return result


def collect():
    samples, fans = {}, {}
    for device in sorted(HWMON.glob('hwmon*')):
        driver = read(device / 'name')
        if driver not in ('nvme', 'asusec', 'k10temp'):
            continue
        for source in sorted(device.glob('temp*_input')):
            label = read(source.with_name(source.name.replace('_input', '_label')), '')
            kind = None
            if driver == 'nvme' and source.name == 'temp1_input':
                kind = 'nvme'
                label = (device / 'device').resolve().name
            elif driver == 'asusec':
                kind = {'Chipset': 'chipset', 'VRM': 'vrm'}.get(label)
            elif label == 'Tctl':
                kind = 'cpu'
            if kind is None:
                continue
            key = f'{driver}:{label}'
            # Keep a missing/unreadable sensor visible instead of treating it as cool.
            try:
                value = int(source.read_text()) / 1000
                samples[key] = {'kind': kind, 'value': value if -20 <= value <= 150 else None}
            except (OSError, ValueError):
                samples[key] = {'kind': kind, 'value': None}
        if driver == 'asusec':
            for source in sorted(device.glob('fan*_input')):
                label = read(source.with_name(source.name.replace('_input', '_label')), source.stem)
                fans[label] = read(source)
    # These are fitted sensors on the supported board/CPU, not optional headers.
    for key, kind in (('asusec:Chipset', 'chipset'), ('asusec:VRM', 'vrm'), ('k10temp:Tctl', 'cpu')):
        samples.setdefault(key, {'kind': kind, 'value': None})
    return samples, fans


def evaluate(samples, previous, limits, now):
    state, events = {}, []
    for key in sorted(samples.keys() | previous.keys()):
        sample = samples.get(key, {'kind': previous.get(key, {}).get('kind'), 'value': None})
        old = previous.get(key, {})
        value, kind = sample['value'], sample['kind']
        limit = limits[kind]
        reason = 'missing' if value is None else ('hot' if value >= limit else '')
        if old.get('alarm') == 'hot' and value is not None and value >= limit - HYSTERESIS_C:
            reason = 'hot'
        count = old.get('count', 0) + 1 if reason and old.get('reason') == reason else int(bool(reason))
        alarm = reason if count >= 2 else old.get('alarm', '')
        last = old.get('last', 0)
        if reason and count >= 2 and (alarm != old.get('alarm') or now - last >= REPEAT_SECONDS):
            detail = 'sensor unavailable' if value is None else f'{value:.1f} C (warning {limit} C)'
            events.append((4, f'{key}: {detail} for at least two samples; inspect cooling/storage logs'))
            last = now
        elif not reason and old.get('alarm'):
            events.append((6, f'{key}: recovered, {value:.1f} C'))
            alarm = ''
        state[key] = {'kind': kind, 'reason': reason, 'count': count, 'alarm': alarm, 'last': last}
    return state, events


def atomic_write(path, text, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f'.{path.name}.', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as output:
            output.write(text)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def check():
    if not supported():
        print('No motherboard profile matched; no monitoring actions taken.')
        return
    samples, fans = collect()
    previous = json.loads(read(STATE, '{}'))
    state, events = evaluate(samples, previous, thresholds(), time.monotonic())
    atomic_write(STATE, json.dumps(state), 0o600)
    summary = ', '.join(f'{key}={s["value"]:.1f}C' if s['value'] is not None
                        else f'{key}=unavailable' for key, s in sorted(samples.items()))
    print(f'<6>{summary}; fans (RPM): {fans}')
    for priority, message in events:
        print(f'<{priority}>{message}')


def install(enable_only=False):
    if not supported():
        print('No motherboard profile matched; no files or services changed.')
        return
    if os.geteuid() != 0:
        raise ValueError('Run --install with sudo')
    thresholds()  # Validate existing overrides before making changes.
    if Path(__file__).resolve() != INSTALLED.resolve():
        atomic_write(INSTALLED, Path(__file__).read_text(), 0o755)
    if not CONFIG.exists():
        atomic_write(CONFIG, CONFIG_TEXT)
    atomic_write(UNITS / 'awesome-board-health.service', SERVICE)
    atomic_write(UNITS / 'awesome-board-health.timer', TIMER)
    if not enable_only:
        subprocess.run(['systemctl', 'daemon-reload'], check=True)
    command = ['systemctl', 'enable']
    if not enable_only:
        command.append('--now')
    subprocess.run(command + ['awesome-board-health.timer'], check=True)
    print('Enabled thermal monitoring for ROG ZENITH II EXTREME ALPHA.')


def status():
    print(f'Board: {read(DMI / "board_vendor")} / {read(DMI / "board_name")}')
    print(f'BIOS: {read(DMI / "bios_version")} ({read(DMI / "bios_date")})')
    if not supported():
        print('No supported profile. No changes made.')
        return
    policy = Path('/sys/devices/system/cpu/cpu0/cpufreq')
    for name in ('scaling_driver', 'scaling_governor', 'energy_performance_preference'):
        print(f'{name}: {read(policy / name)}')
    limits = thresholds()
    samples, fans = collect()
    for key, sample in sorted(samples.items()):
        value = sample['value']
        print(f'{key}: {value if value is not None else "unavailable"} C; warning {limits[sample["kind"]]} C')
    print('Fan readings (RPM):', fans)
    print('Alerts: journalctl -u awesome-board-health.service -p warning')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument('--status', action='store_true', help='show detected board and sensors (default)')
    actions.add_argument('--check', action='store_true', help='sample sensors and update runtime alarm state')
    actions.add_argument('--install', action='store_true', help='enable monitoring on the exact supported board')
    parser.add_argument('--enable-only', action='store_true', help='with --install: enable for next boot, for chroots')
    args = parser.parse_args()
    if args.enable_only and not args.install:
        parser.error('--enable-only requires --install')
    if args.install:
        install(args.enable_only)
    elif args.check:
        check()
    else:
        status()


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, configparser.Error, subprocess.CalledProcessError) as error:
        sys.exit(f'Error: {error}')
