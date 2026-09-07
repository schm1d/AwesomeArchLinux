"""Unprivileged regression checks for medium-severity installer findings."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_high_severity import ROOT, shell_function


class NodeAuditTests(unittest.TestCase):
    def test_two_apps_keep_independent_audits_after_reconfiguration(self):
        source = (ROOT / "hardening/nodejs/nodejs.sh").read_text()
        section = source.split('msg "Setting up automated npm security audit..."', 1)[1]
        section = section.split('# 10. FILE PERMISSIONS', 1)[0]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("bin", "units", "logs"):
                (root / name).mkdir()
            section = section.replace("/usr/local/bin", str(root / "bin"))
            section = section.replace("/etc/systemd/system", str(root / "units"))
            section = section.replace("/var/log", str(root / "logs"))
            apps = {}
            for name, directory in (("first", "first app"), ("second", "second"),
                                    ("first", 'updated $literal "app"')):
                app = root / directory
                app.mkdir()
                apps[name] = app
                result = subprocess.run(["bash", "-c", 'set -euo pipefail\n'
                                         'msg() { :; }; systemctl() { :; }\n' + section],
                                        text=True, capture_output=True,
                                        env=dict(os.environ, APP_NAME=name, APP_PATH=str(app)))
                self.assertEqual(result.returncode, 0, result.stderr)
            for name, app in apps.items():
                service = (root / "units" / f"{name}-audit.service").read_text()
                command = next(line.removeprefix("ExecStart=") for line in service.splitlines()
                               if line.startswith("ExecStart="))
                result = subprocess.run(["bash", "-c", '''set -euo pipefail
npm() { printf '%s\\n' "$PWD" > "$AUDITED_PATH"; }
source "$1"
''', "test", command], text=True, capture_output=True,
                                        env=dict(os.environ, AUDITED_PATH=str(root / "audited")))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((root / "audited").read_text().strip(), str(app))
                self.assertEqual(len(list((root / "logs" / name).glob("npm-audit-*.log"))), 1)


class WipeTests(unittest.TestCase):
    def wipe(self, disk, size, source="/dev/zero"):
        script = '''set -euo pipefail
blockdev() { printf '%s\\n' "$DEVICE_SIZE"; }
''' + shell_function("base/archinstall.sh", "wipe_disk")
        script += '\nwipe_disk "$DISK" "$SOURCE"\necho NEXT_INSTALL_STEP\n'
        return subprocess.run(["bash", "-c", script], text=True, capture_output=True,
                              env=dict(os.environ, DISK=str(disk), DEVICE_SIZE=str(size),
                                       SOURCE=source))

    def test_exact_size_with_partial_final_block(self):
        for source in ("/dev/zero", "/dev/urandom"):
            with self.subTest(source=source), tempfile.TemporaryDirectory() as tmp:
                disk = Path(tmp) / "disk.img"
                size = 1024**2 + 512
                disk.write_bytes(b"x" * size)
                result = self.wipe(disk, size, source)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("NEXT_INSTALL_STEP", result.stdout)
                self.assertEqual(disk.stat().st_size, size)
                if source == "/dev/zero":
                    self.assertEqual(disk.read_bytes(), bytes(size))

    def test_write_error_stops_installation(self):
        result = self.wipe("/dev/full", 512)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("NEXT_INSTALL_STEP", result.stdout)

    def test_invalid_size_leaves_disk_untouched(self):
        with tempfile.TemporaryDirectory() as tmp:
            disk = Path(tmp) / "disk.img"
            disk.write_bytes(b"preserve this")
            for size in ("", "0", "unknown", "-1"):
                with self.subTest(size=size):
                    result = self.wipe(disk, size)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn("NEXT_INSTALL_STEP", result.stdout)
                    self.assertEqual(disk.read_bytes(), b"preserve this")


if __name__ == "__main__":
    unittest.main()
