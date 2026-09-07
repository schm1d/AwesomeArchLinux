"""Unprivileged regression checks for medium-severity installer findings."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_high_severity import ROOT, shell_function


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
