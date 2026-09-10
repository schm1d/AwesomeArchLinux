"""Board matching and thermal alarm behavior using isolated sysfs fixtures."""

import contextlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    'board_health', Path(__file__).resolve().parents[1] / 'utils/board-health.py')
board = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(board)


class BoardHealthTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for key, suffix in {'DMI': 'dmi', 'HWMON': 'hwmon', 'CONFIG': 'etc/board.conf',
                            'INSTALLED': 'lib/board.py', 'UNITS': 'units', 'STATE': 'run/state.json'}.items():
            p = patch.object(board, key, self.root / suffix)
            p.start()
            self.addCleanup(p.stop)
        board.DMI.mkdir()
        board.HWMON.mkdir()
        self.identity(*board.BOARD)

    def identity(self, vendor, name):
        (board.DMI / 'board_vendor').write_text(vendor)
        (board.DMI / 'board_name').write_text(name)

    def test_exact_match_excludes_other_zenith_models_and_missing_dmi(self):
        self.assertTrue(board.supported())
        for identity in [('ASUSTeK COMPUTER INC.', 'ROG ZENITH II EXTREME'),
                         ('ASUSTeK COMPUTER INC.', 'ROG ZENITH EXTREME ALPHA'),
                         ('Other vendor', board.BOARD[1])]:
            self.identity(*identity)
            self.assertFalse(board.supported())
        (board.DMI / 'board_name').unlink()
        self.assertFalse(board.supported())

    def test_unsupported_install_and_check_do_not_modify_or_run_commands(self):
        self.identity('Other', board.BOARD[1])
        with patch.object(board.subprocess, 'run') as run, contextlib.redirect_stdout(io.StringIO()):
            board.install()
            board.check()
        run.assert_not_called()
        self.assertFalse(board.STATE.exists())
        self.assertFalse(board.CONFIG.exists())
        self.assertFalse(board.UNITS.exists())

    def test_chroot_install_only_enables_and_preserves_user_thresholds(self):
        board.CONFIG.parent.mkdir()
        override = '[temperature]\nnvme = 72\n'
        board.CONFIG.write_text(override)
        with patch.object(board.os, 'geteuid', return_value=0), \
                patch.object(board.subprocess, 'run') as run, contextlib.redirect_stdout(io.StringIO()):
            board.install(enable_only=True)
            board.install(enable_only=True)
        self.assertEqual(board.CONFIG.read_text(), override)
        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args.args[0], ['systemctl', 'enable', 'awesome-board-health.timer'])
        self.assertTrue(board.INSTALLED.exists())
        self.assertEqual(board.INSTALLED.stat().st_mode & 0o777, 0o755)

    def test_sensor_labels_are_used_and_disconnected_optional_headers_ignored(self):
        device = board.HWMON / 'hwmon93'
        device.mkdir()
        (device / 'name').write_text('asusec')
        for index, label, value in [(5, 'Chipset', '83000'), (2, 'VRM', '61000'),
                                    (9, 'Water_In', '-40000')]:
            (device / f'temp{index}_label').write_text(label)
            (device / f'temp{index}_input').write_text(value)
        (device / 'fan8_label').write_text('CPU_Opt')
        (device / 'fan8_input').write_text('0')
        samples, fans = board.collect()
        self.assertEqual(samples['asusec:Chipset']['value'], 83)
        self.assertEqual(samples['asusec:VRM']['value'], 61)
        self.assertNotIn('asusec:Water_In', samples)
        self.assertEqual(fans['CPU_Opt'], '0')
        self.assertIsNone(samples['k10temp:Tctl']['value'])

    def test_configuration_rejects_typos_and_invalid_limits(self):
        board.CONFIG.parent.mkdir()
        for text in ('[temperature]\ncpux=80\n', '[temperature]\nchipset=500\n'):
            board.CONFIG.write_text(text)
            with self.assertRaises(ValueError):
                board.thresholds()


class AlarmTests(unittest.TestCase):
    def sample(self, value):
        return {'nvme:nvme0': {'kind': 'nvme', 'value': value}}

    def step(self, value, state, now):
        return board.evaluate(self.sample(value), state, board.DEFAULTS, now)

    def test_transient_spike_and_sustained_heat_repeat_hysteresis_recovery(self):
        state, events = self.step(71, {}, 0)
        self.assertEqual(events, [])
        state, events = self.step(65, state, 60)
        self.assertEqual(events, [])
        state, _ = self.step(72, state, 120)
        state, events = self.step(73, state, 180)
        self.assertEqual(events[0][0], 4)
        state, events = self.step(69, state, 240)
        self.assertEqual(events, [])  # Hysteresis holds alarm without repeating it.
        self.assertEqual(state['nvme:nvme0']['alarm'], 'hot')
        state, events = self.step(72, state, 1980)
        self.assertEqual(events[0][0], 4)
        state, events = self.step(66, state, 2040)
        self.assertEqual(events[0][0], 6)
        self.assertEqual(state['nvme:nvme0']['alarm'], '')

    def test_disappearing_nvme_warns_instead_of_reporting_recovery(self):
        state, _ = self.step(60, {}, 0)
        state, events = board.evaluate({}, state, board.DEFAULTS, 60)
        self.assertEqual(events, [])
        state, events = board.evaluate({}, state, board.DEFAULTS, 120)
        self.assertIn('unavailable', events[0][1])
        state, events = self.step(60, state, 180)
        self.assertIn('recovered', events[0][1])


if __name__ == '__main__':
    unittest.main()
