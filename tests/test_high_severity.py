"""Unprivileged regression checks; never run installers against the host."""

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def shell_function(path, name):
    source = (ROOT / path).read_text()
    match = re.search(rf"^{name}\(\) \{{\n.*?^\}}$", source, re.M | re.S)
    if not match:
        raise AssertionError(f"Function {name} missing from {path}")
    return match.group()


@unittest.skipUnless(shutil.which("sgdisk") and shutil.which("uuidgen"),
                     "sgdisk and uuidgen are required")
class PartitionTests(unittest.TestCase):
    def check_layout(self, numbers, expected):
        with tempfile.TemporaryDirectory(prefix="aal-partition-test-") as tmp:
            disk = Path(tmp) / "disk.img"
            with disk.open("wb") as stream:
                stream.truncate(2 * 1024**3)
            subprocess.run(["sgdisk", "-o", str(disk)], check=True, capture_output=True)
            for number in numbers:
                subprocess.run(["sgdisk", "-n", f"{number}:0:+16M",
                                "-c", f"{number}:existing-{number}", str(disk)],
                               check=True, capture_output=True)
            original = {
                number: subprocess.check_output(["sgdisk", "-i", str(number), str(disk)])
                for number in numbers
            }
            script = """set -euo pipefail
info() { :; }
msg() { :; }
err() { echo "$*" >&2; exit 1; }
partprobe() { :; }
udevadm() { :; }
mkfs.ext4() { echo 'UNEXPECTED FORMAT' >&2; exit 99; }
VAR_STRATEGY=partition
VAR_LOOP_SIZE=1
DRY_RUN=false
""" + shell_function("base/vps-harden.sh", "create_var_filesystem") + "\ncreate_var_filesystem\n"
            env = dict(os.environ, PARENT_DISK=str(disk))
            result = subprocess.run(["bash", "-c", script], env=env,
                                    text=True, capture_output=True)
            # A regular image has no udev block node: allocation succeeds, but
            # the formatter must refuse to proceed without the verified device.
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("New partition has not appeared", result.stderr)
            self.assertNotIn("UNEXPECTED FORMAT", result.stderr)
            created = subprocess.check_output(["sgdisk", "-i", str(expected), str(disk)], text=True)
            self.assertIn("Partition name: 'var'", created)
            for number, details in original.items():
                self.assertEqual(details, subprocess.check_output(
                    ["sgdisk", "-i", str(number), str(disk)]))

    def test_partition_number_gap_preserves_existing_data_partition(self):
        self.check_layout([1, 3], 2)

    def test_contiguous_partition_numbers(self):
        self.check_layout([1, 2], 3)

    def test_missing_first_partition(self):
        self.check_layout([2, 3], 1)


if __name__ == "__main__":
    unittest.main()
