"""Unprivileged regression checks for medium-severity installer findings."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_high_severity import ROOT, shell_function


class AurSetupTests(unittest.TestCase):
    def stage(self, root, installer):
        source = (ROOT / installer).read_text()
        section = source.split('# Stage reviewed AUR installation', 1)[1].split(
            '# End post-install package staging.', 1)[0]
        section = section[section.index('\n') + 1:].replace('/mnt/root', str(root))
        subprocess.run(["bash", "-c", 'set -euo pipefail\n' + section], check=True,
                       capture_output=True, env=dict(os.environ, SCRIPT_DIR=str(ROOT / "base")))

    def test_both_installers_stage_complete_root_only_bundle(self):
        for installer in ("base/archinstall.sh", "base/vps-install.sh"):
            with self.subTest(installer=installer), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                self.stage(root, installer)
                for name, original, mode in (
                    ("install-aur-packages.sh", "base/install-aur-packages.sh", 0o700),
                    ("aur-review.sh", "hardening/lib/aur-review.sh", 0o600),
                    ("aide-config.sh", "utils/aide-config.sh", 0o700),
                ):
                    self.assertEqual((root / name).read_bytes(), (ROOT / original).read_bytes())
                    self.assertEqual((root / name).stat().st_mode & 0o777, mode)

    def test_review_failure_stops_setup_and_rerun_preserves_aide_baseline(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.stage(root, "base/archinstall.sh")
            entry = root / "install-aur-packages.sh"
            entry.write_text(entry.read_text().replace("/var/lib/aide", str(root)))
            (root / "aur-review.sh").write_text(r'''aal_aur_install_reviewed() {
    echo "REVIEW $1" >> "$EVENTS"
    [[ "$REJECT_REVIEW" != true ]] || return 1
    touch "$FIXTURE/$1.installed"
}
''')
            (root / "aide-config.sh").write_text('''echo "AIDE $*" >> "$EVENTS"
printf 'reference baseline' > "$FIXTURE/aide.db"
''')
            script = r'''set -euo pipefail
id() { echo 0; }
pacman() {
    echo "pacman $*" >> "$EVENTS"
    case "$1" in
        -Qq) [[ -f "$FIXTURE/$2.installed" ]] ;;
        -Si) [[ "$2" == acct ]] ;;
        -S) if [[ "${!#}" == acct ]]; then touch "$FIXTURE/acct.installed"; fi ;;
        *) exit 99 ;;
    esac
}
systemctl() { echo "systemctl $*" >> "$EVENTS"; }
makepkg() { echo UNEXPECTED_ROOT_BUILD >&2; exit 99; }
source "$1"
'''
            for reject in (True, False, False):
                (root / "events").write_text("")
                result = subprocess.run(["bash", "-c", script, "test", str(entry)],
                                        text=True, capture_output=True,
                                        env=dict(os.environ, FIXTURE=str(root),
                                                 EVENTS=str(root / "events"),
                                                 REJECT_REVIEW=str(reject).lower()))
                events = (root / "events").read_text()
                if reject:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn("systemctl", events)
                    self.assertNotIn("AIDE", events)
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("systemctl enable --now psacct.service", events)
                    self.assertEqual((root / "aide.db").read_text(), "reference baseline")
            self.assertNotIn("REVIEW", events)
            self.assertNotIn("AIDE", events)
            self.assertIn("Existing AIDE baseline preserved", result.stdout)

    def test_builds_delegate_to_disposable_user_with_compiler_access(self):
        source = (ROOT / "hardening/lib/aur-review.sh").read_text()
        start = source.index('    build_user="_aalbuild_')
        section = source[start:source.index('    # Terminate any recipe-spawned', start)]
        for restricted in (False, True):
            with self.subTest(restricted=restricted), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "bin").mkdir()
                build = root / "cache" / "example"
                build.mkdir(parents=True)
                makepkg = root / "bin" / "makepkg"
                makepkg.write_text('''#!/bin/bash
set -euo pipefail
[[ "$BUILD_AS" == _aalbuild_* ]]
[[ "$HOME" == "$PWD/.home" && "$TMPDIR" == "$PWD/.tmp" ]]
[[ -d "$HOME" && -d "$TMPDIR" ]]
printf 'makepkg %s %s\\n' "$BUILD_AS" "$*" >> "$EVENTS"
if [[ "$1" == --packagelist ]]; then echo "$PWD/example.pkg.tar.zst"; fi
''')
                makepkg.chmod(0o755)
                script = r'''set -euo pipefail
tmpdir="$FIXTURE/cache"; builddir="$tmpdir/example"; commit=test
build_groups=(); package_files=()
getent() { [[ "$RESTRICTED" == true ]]; }
useradd() { echo "useradd $*" >> "$EVENTS"; }
chown() { :; }
install() { mkdir -p "$builddir/.home" "$builddir/.tmp"; }
_aal_aur_info() { :; }
_aal_aur_error() { echo "$*" >&2; }
runuser() {
    [[ "$1" == -u && "$2" == _aalbuild_* && "$3" == -- ]]
    export BUILD_AS="$2"
    shift 3
    [[ "$1" == env && "$4" == makepkg ]]
    # /tmp itself may be noexec on the test host. Interpret the mock explicitly
    # instead of allowing PATH lookup to skip it and reach the real makepkg.
    env "$2" "$3" bash "$FIXTURE/bin/makepkg" "${@:5}"
}
''' + section
                result = subprocess.run(["bash", "-c", script], text=True, capture_output=True,
                                        env=dict(os.environ, FIXTURE=str(root), EVENTS=str(root / "events"),
                                                 RESTRICTED=str(restricted).lower()))
                self.assertEqual(result.returncode, 0, result.stderr)
                events = (root / "events").read_text()
                self.assertEqual("-G compilers" in events, restricted)
                self.assertIn("--cleanbuild --noconfirm", events)
                self.assertIn("--packagelist", events)
                self.assertEqual((root / "cache" / "package-paths").read_bytes(),
                                 str(build / "example.pkg.tar.zst").encode() + b"\0")


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
