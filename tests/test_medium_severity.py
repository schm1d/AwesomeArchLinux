"""Unprivileged regression checks for medium-severity installer findings."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_high_severity import ROOT, shell_function


class FscryptTests(unittest.TestCase):
    def run_fixture(self, root, failure="", shared=False, action="encrypt", active=False):
        home = root / "homes" / "alice"
        home.mkdir(parents=True)
        (home / "original.txt").write_text("original data")
        (root / "rootfs").mkdir()
        (root / "config").touch()
        (root / "pam.so").touch()
        script = r'''set -euo pipefail
info() { :; }; ok() { :; }; warn() { echo "$*" >&2; }
err() { echo "$*" >&2; exit 1; }
id() { echo 1000; }
getent() { printf 'alice:x:1000:1000::%s:/bin/bash\n' "$USER_HOME"; }
mountpoint() { return 1; }
chown() { :; }; sleep() { :; }; require_cmd() { :; }
pacman() { echo UNEXPECTED_PACKAGE_INSTALL >&2; exit 99; }
append_pam_line() { echo PAM >> "$EVENTS"; }
findmnt() {
    local path="${!#}" kind="$3" mount="$FIXTURE/rootfs" dev=/dev/root
    if [[ "$path" != / && "$SHARED" != true ]]; then
        mount="$FIXTURE/homes"; dev=/dev/home
    fi
    case "$kind" in
        FSTYPE) if [[ "$path" != / && "$FAILURE" == type ]]; then echo xfs; else echo ext4; fi ;;
        SOURCE) echo "$dev" ;;
        TARGET) echo "$mount" ;;
    esac
}
has_encrypt_feature() { [[ "$1" != /dev/home || "$FAILURE" != feature ]]; }
fscrypt() {
    printf 'fscrypt %s\n' "$*" >> "$EVENTS"
    case "$1" in
        status)
            if [[ "$2" == "$USER_HOME" ]]; then
                [[ "$FAILURE" == encrypted ]]; return
            fi
            [[ -d "$2/.fscrypt/policies" ]] ;;
        setup)
            [[ "$2" != "$FIXTURE/homes" || "$FAILURE" != setup ]] || return 1
            mkdir -p "$2/.fscrypt/policies" "$2/.fscrypt/protectors" ;;
        encrypt)
            [[ "$FAILURE" != encrypt ]] || return 1
            [[ "$3" == --user=alice && "$4" == --source=pam_passphrase ]] || return 99
            touch "$2/encrypted-marker" ;;
    esac
}
loginctl() {
    printf 'loginctl %s\n' "$*" >> "$EVENTS"
    if [[ "$1" == list-users && "$ACTIVE" == true ]]; then echo '1000 alice'; fi
}
mv() {
    printf 'mv %s\n' "$*" >> "$EVENTS"
    if [[ "$FAILURE" == activate && "${@: -2:1}" == *.encrypt.* ]]; then return 1; fi
    command mv "$@"
}
'''
        for name in ("is_ext4", "validate_encryption_filesystem", "prepare_encryption_filesystem",
                     "do_setup", "do_encrypt_user"):
            script += shell_function("hardening/fscrypt/fscrypt.sh", name) + "\n"
        script = script.replace('/root/fscrypt-recovery-', str(root / 'recovery-'))
        script += "do_setup\n" if action == "setup" else "do_encrypt_user\n"
        result = subprocess.run(["bash", "-c", script], input="YES\n", text=True,
                                capture_output=True, env=dict(os.environ,
                                    FIXTURE=str(root), USER_HOME=str(home), TARGET_USER="alice",
                                    FSCRYPT_CONF=str(root / "config"), PAM_FSCRYPT_SO=str(root / "pam.so"),
                                    PAM_SYSTEM_LOGIN=str(root / "config"), PAM_PASSWD=str(root / "config"),
                                    PAM_AUTH_LINE="auth", PAM_SESSION_LINE="session", PAM_PASSWORD_LINE="password",
                                    MARK="# test", EVENTS=str(root / "events"), FAILURE=failure,
                                    SHARED=str(shared).lower(), ACTIVE=str(active).lower()))
        return result, home, (root / "events").read_text()

    def test_failed_preflight_or_encryption_preserves_home_and_sessions(self):
        for failure in ("type", "feature", "setup", "encrypt"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                result, home, events = self.run_fixture(Path(tmp), failure)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual((home / "original.txt").read_text(), "original data")
                self.assertFalse(Path(str(home) + ".pre-encrypt").exists())
                self.assertNotIn("mv ", events)
                self.assertNotIn("loginctl ", events)

    def test_shared_and_separate_home_filesystems(self):
        for shared in (False, True):
            for active in (False, True):
                with self.subTest(shared=shared, active=active), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    result, home, events = self.run_fixture(root, shared=shared, active=active)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertTrue((home / "encrypted-marker").exists())
                    self.assertEqual((Path(str(home) + ".pre-encrypt") / "original.txt").read_text(),
                                     "original data")
                    self.assertEqual(events.count("fscrypt setup "), 1 if shared else 2)
                    self.assertLess(events.index("fscrypt encrypt "), events.index("mv "))
                    self.assertEqual("loginctl terminate-user alice" in events, active)

    def test_failed_activation_restores_original_home(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, home, events = self.run_fixture(Path(tmp), "activate")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("original home has been restored", result.stderr)
            self.assertEqual((home / "original.txt").read_text(), "original data")

    def test_already_encrypted_home_is_untouched(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, home, events = self.run_fixture(Path(tmp), "encrypted")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("mv ", events)
            self.assertNotIn("fscrypt encrypt ", events)

    def test_setup_prepares_both_filesystems_before_pam(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, home, events = self.run_fixture(Path(tmp), action="setup")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(events.count("fscrypt setup "), 2)
            self.assertLess(events.rindex("fscrypt status "), events.index("PAM"))


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
