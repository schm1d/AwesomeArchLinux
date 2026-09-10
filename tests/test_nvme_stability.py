"""Exercise boot-file preservation and failure recovery without touching the host."""

import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    'nvme_stability', Path(__file__).resolve().parents[1] / 'utils/nvme-stability.py')
nvme = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(nvme)


def fake_uki(path, cmdline):
    data = bytearray(1024)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 60, 128)
    data[128:132] = b'PE\0\0'
    struct.pack_into('<H', data, 134, 1)
    data[152:160] = b'.cmdline'
    encoded = cmdline.encode() + b'\0'
    struct.pack_into('<IIII', data, 160, len(encoded), 4096, len(encoded), 512)
    data[512:512 + len(encoded)] = encoded
    path.write_bytes(data)


class CommandLineTests(unittest.TestCase):
    def test_preserves_encryption_and_quoting_replaces_duplicates_and_is_idempotent(self):
        original = ('# comment\nroot=/dev/mapper/lvm_arch-root rd.luks.name=uuid=crypt_lvm\n'
                    'rd.luks.options=uuid=tpm2-device=auto example="two words" '
                    'nvme-core.default-ps-max-latency-us=5500 pcie_aspm=force '
                    'pcie_aspm=off pcie_port_pm=force')
        result = nvme.with_workaround(original)
        self.assertIn('rd.luks.options=uuid=tpm2-device=auto example="two words"', result)
        self.assertEqual(result.count('pcie_aspm='), 1)
        self.assertNotIn('5500', result)
        self.assertEqual(nvme.with_workaround(result), result)
        self.assertEqual(result.count('\n'), 1)

    def test_refuses_missing_root_unclosed_quotes_and_init_arguments(self):
        for text in ('quiet', 'root=x x="broken', 'root=x -- initarg'):
            with self.assertRaises(ValueError):
                nvme.with_workaround(text)

    def test_unsigned_sbctl_success_exit_is_rejected(self):
        with patch.object(nvme, 'run', return_value=json.dumps([
                {'file_name': '/test.efi', 'is_signed': 0}])):
            with self.assertRaises(ValueError):
                nvme.verify_signature(Path('/test.efi'))


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cmdline = self.root / 'cmdline'
        self.original = 'root=/dev/mapper/root rd.luks.name=uuid=crypt_lvm\n'
        self.cmdline.write_text(self.original)
        self.preset = self.root / 'linux.preset'
        self.preset.write_text('# fixture\n')
        self.images = (self.root / 'arch-linux.efi', self.root / 'arch-linux-fallback.efi')
        for path in self.images:
            fake_uki(path, self.original)
        self.image_bytes = [p.read_bytes() for p in self.images]
        self.state = self.root / 'state'
        for key, value in {'CMDLINE': self.cmdline, 'PRESET': self.preset,
                           'ESP': self.root, 'IMAGES': self.images, 'STATE': self.state}.items():
            p = patch.object(nvme, key, value)
            p.start()
            self.addCleanup(p.stop)
        self.desired = nvme.with_workaround(self.original)

    def build(self, *args, **kwargs):
        if args[0] == 'mkinitcpio':
            self.assertEqual(args[3:5], ('--', '--cmdline'))
            self.assertEqual(args[-1], '--nopost')
            stage = Path(args[2]).parent
            for path in self.images:
                fake_uki(stage / path.name, (stage / 'cmdline.after').read_text())

    def assert_original(self):
        self.assertEqual(self.cmdline.read_text(), self.original)
        self.assertEqual([p.read_bytes() for p in self.images], self.image_bytes)

    def test_build_failure_keeps_boot_files_unchanged(self):
        with patch.object(nvme, 'run', side_effect=subprocess.CalledProcessError(1, 'mkinitcpio')):
            with self.assertRaises(subprocess.CalledProcessError):
                nvme.install_command_line(self.desired)
        self.assert_original()

    def test_wrong_embedded_arguments_never_reach_esp(self):
        def wrong(*args, **kwargs):
            self.build(*args, **kwargs)
            if args[0] == 'mkinitcpio':
                fake_uki(Path(args[2]).parent / self.images[0].name, self.original)
        with patch.object(nvme, 'run', side_effect=wrong):
            with self.assertRaises(ValueError):
                nvme.install_command_line(self.desired)
        self.assert_original()

    def test_signature_failure_keeps_boot_files_unchanged(self):
        with patch.object(nvme, 'run', side_effect=self.build), \
                patch.object(nvme, 'verify_signature', side_effect=ValueError('unsigned')):
            with self.assertRaises(ValueError):
                nvme.install_command_line(self.desired)
        self.assert_original()

    def test_staged_verification_uses_temporary_esp_copy_and_cleans_up(self):
        def verify(path):
            self.assertTrue(path.is_relative_to(self.root))
            self.assertTrue(path.parent.name.startswith('.nvme-verify-'))
            self.assertEqual(path.read_bytes(), self.image_bytes[0])
            raise ValueError('simulated signature failure')
        with patch.object(nvme, 'verify_signature', side_effect=verify):
            with self.assertRaises(ValueError):
                nvme.verify_staged_signature(self.images[0])
        self.assertEqual(list(self.root.glob('.nvme-verify-*')), [])
        self.assert_original()

    def test_copy_failure_restores_already_replaced_image(self):
        actual_copy = nvme.atomic_copy
        def fail_second(source, target):
            if source.name == self.images[1].name and target == self.images[1]:
                raise OSError('simulated full ESP')
            return actual_copy(source, target)
        with patch.object(nvme, 'run', side_effect=self.build), \
                patch.object(nvme, 'verify_signature'), \
                patch.object(nvme, 'atomic_copy', side_effect=fail_second):
            with self.assertRaises(OSError):
                nvme.install_command_line(self.desired)
        self.assert_original()

    def test_success_and_repeat_preserve_original_backup(self):
        with patch.object(nvme, 'run', side_effect=self.build) as run_mock, \
                patch.object(nvme, 'verify_signature'):
            nvme.install_command_line(self.desired)
            self.assertEqual(self.cmdline.read_text(), self.desired)
            for path in self.images:
                self.assertEqual(nvme.embedded_cmdline(path), self.desired.strip())
            count = run_mock.call_count
            nvme.install_command_line(self.desired)
            self.assertEqual(run_mock.call_count, count)
        backup, = self.state.iterdir()
        self.assertEqual((backup / 'cmdline.before').read_text(), self.original)
        self.assertEqual((backup / (self.images[0].name + '.before')).read_bytes(), self.image_bytes[0])

    def test_restore_build_failure_also_preserves_current_boot_files(self):
        with patch.object(nvme, 'run', side_effect=self.build), patch.object(nvme, 'verify_signature'):
            nvme.install_command_line(self.desired)
        backup, = self.state.iterdir()
        before = self.cmdline.read_bytes(), [p.read_bytes() for p in self.images]
        # Exercise the same staged transaction that restore uses.
        with patch.object(nvme, 'run', side_effect=subprocess.CalledProcessError(1, 'mkinitcpio')):
            with self.assertRaises(subprocess.CalledProcessError):
                nvme.install_command_line((backup / 'cmdline.before').read_text())
        self.assertEqual((self.cmdline.read_bytes(), [p.read_bytes() for p in self.images]), before)


if __name__ == '__main__':
    unittest.main()
