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


class VarMigrationTests(unittest.TestCase):
    def test_rollback_refuses_a_completed_var_migration(self):
        with tempfile.TemporaryDirectory() as tmp:
            rollback = Path(tmp) / "rollback.sh"
            old_var = Path(tmp) / "var.old"
            old_var.mkdir()
            script = "set -euo pipefail\ninfo() { :; }; msg() { :; }\n"
            script += shell_function("base/vps-harden.sh", "create_rollback_script")
            script += "\ncreate_rollback_script\n"
            subprocess.run(["bash", "-c", script], check=True, capture_output=True,
                           env=dict(os.environ, ROLLBACK_SCRIPT=str(rollback),
                                    FSTAB_BACKUP=str(Path(tmp) / "fstab.backup")))
            # Redirect only the /var.old sentinel to a fixture. The guard must
            # exit before prompting or attempting any real restoration.
            rollback.write_text(rollback.read_text().replace("/var.old", str(old_var)))
            result = subprocess.run(["bash", "-c", 'id() { echo 0; }; source "$1"',
                                     "test", str(rollback)], input="", text=True, capture_output=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn("Refusing live rollback", result.stderr)

    def test_preparation_only_writes_offline_instructions(self):
        for strategy in ("partition", "volume", "loop"):
            with self.subTest(strategy=strategy), tempfile.TemporaryDirectory() as tmp:
                guide = Path(tmp) / "migration.txt"
                script = r'''set -euo pipefail
info() { :; }; msg() { :; }; warn() { :; }; log_action() { :; }
err() { echo "$*" >&2; exit 1; }
blkid() {
    if [[ "${!#}" == /dev/source ]]; then
        echo aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
    else
        echo bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb
    fi
}
rsync() { echo 'UNEXPECTED LIVE COPY' >&2; exit 99; }
mv() { echo 'UNEXPECTED LIVE MOVE' >&2; exit 99; }
mount() { echo 'UNEXPECTED LIVE MOUNT' >&2; exit 99; }
umount() { exit 99; }; systemctl() { exit 99; }
''' + shell_function("base/vps-harden.sh", "prepare_var_migration") + "\nprepare_var_migration\n"
                result = subprocess.run(["bash", "-c", script], text=True, capture_output=True,
                                        env=dict(os.environ, VAR_STRATEGY=strategy, DRY_RUN="false",
                                                 VAR_MIGRATION_GUIDE=str(guide),
                                                 ROOT_DEVICE="/dev/source", VAR_DEVICE="/dev/destination"))
                self.assertEqual(result.returncode, 0, result.stderr)
                notes = guide.read_text()
                self.assertIn("boot a rescue ISO", notes)
                self.assertIn("rsync -aHAXxnc", notes)
                if strategy == "loop":
                    self.assertIn("/mnt/awesome-root/root/var.img", notes)
                    self.assertIn("loop,nosuid,nodev", notes)
                else:
                    self.assertIn("UUID=bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb /var", notes)
                commands = notes[notes.index("set -euo pipefail"):notes.index("\nBoot the installed OS")]
                result = subprocess.run(["bash", "-n"], input=commands, text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(guide.stat().st_mode & 0o777, 0o600)


class SshStagingTests(unittest.TestCase):
    def stage(self, tmp, download=False, fail_component=""):
        script = r'''set -euo pipefail
err() { echo "$*" >&2; exit 1; }
curl() {
    local component="${2##*/hardening/}"
    [[ "$component" != "$FAIL_COMPONENT" ]] || return 22
    cp "$REPO_ROOT/hardening/$component" "$4"
}
''' + shell_function("base/vps-harden.sh", "stage_ssh_components") + '\nstage_ssh_components "$STAGE_ROOT"\n'
        source_dir = Path(tmp) / "download-only" if download else ROOT / "base"
        return subprocess.run(["bash", "-c", script], text=True, capture_output=True,
                              env=dict(os.environ, SCRIPT_DIR=str(source_dir), STAGE_ROOT=tmp,
                                       REPO_ROOT=str(ROOT), FAIL_COMPONENT=fail_component))

    def test_local_and_downloaded_bundles_load_the_helper(self):
        for download in (False, True):
            with self.subTest(download=download), tempfile.TemporaryDirectory() as tmp:
                result = self.stage(tmp, download=download)
                self.assertEqual(result.returncode, 0, result.stderr)
                result = subprocess.run(["bash", str(Path(tmp) / "ssh.sh"), "-h"],
                                        text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("Usage:", result.stdout)
                self.assertEqual(result.stderr, "")

    def test_download_failure_stops_before_staging_ssh(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.stage(tmp, download=True, fail_component="lib/nftables.sh")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Could not fetch required SSH component", result.stderr)
            self.assertFalse((Path(tmp) / "ssh.sh").exists())

    def test_missing_or_incomplete_helper_fails_before_root_check(self):
        for helper in (None, "#!/bin/bash\n"):
            with self.subTest(helper=helper), tempfile.TemporaryDirectory() as tmp:
                script = Path(tmp) / "ssh.sh"
                shutil.copyfile(ROOT / "hardening/ssh/ssh.sh", script)
                if helper is not None:
                    (Path(tmp) / "nftables.sh").write_text(helper)
                result = subprocess.run(["bash", str(script), "-h"], text=True, capture_output=True)
                self.assertEqual(result.returncode, 1)
                self.assertIn("ERROR:", result.stderr)
                self.assertIn("nftables.sh", result.stderr)
                self.assertNotIn("root", result.stderr)


if __name__ == "__main__":
    unittest.main()
