"""Offline checks: never execute the installers or change host authentication."""

import ctypes
import ctypes.util
import os
from pathlib import Path
import pwd
import subprocess
import tempfile
import unittest

from test_high_severity import ROOT


LIBRARY = ROOT / "base/lib/chroot-security.sh"
PAM_STACK = """#%PAM-1.0
auth required pam_faillock.so preauth
-auth [success=2 default=ignore] pam_systemd_home.so
auth [success=1 default=bad] pam_unix.so try_first_pass nullok
auth [default=die] pam_faillock.so authfail
auth required pam_faillock.so authsucc
account required pam_unix.so
-password [success=1 default=ignore] pam_systemd_home.so
password required pam_unix.so try_first_pass shadow # local password
password optional pam_permit.so
session required pam_unix.so
"""


def call_helper(function, *args):
    return subprocess.run(["bash", "-c", 'set -euo pipefail; source "$1"; shift; "$@"',
                           "test", str(LIBRARY), function, *map(str, args)],
                          text=True, capture_output=True)


class PasswordPolicyTests(unittest.TestCase):
    def configure(self, root, source):
        (root / "etc/pam.d").mkdir(parents=True)
        (root / "etc/security").mkdir()
        (root / "etc/pam.d/system-auth").write_text(source)
        (root / "etc/security/pwquality.conf").write_text("minlen = 8\n")
        (root / "etc/security/faillock.conf").write_text("# existing\ndeny = 3\naudit\n")
        return call_helper("configure_password_policy", root)

    def test_old_wrong_order_is_repaired_and_reruns_preserve_auth_flow(self):
        old = PAM_STACK.replace("preauth", "preauth deny=5 unlock_time=900")
        old = old.replace("password optional", "password required pam_pwquality.so retry=3\npassword optional")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = self.configure(root, old)
            self.assertEqual(result.returncode, 0, result.stderr)
            pam = (root / "etc/pam.d/system-auth").read_text()
            lines = [line for line in pam.splitlines() if line.split() and
                     line.split()[0].lstrip("-") == "password"]
            self.assertEqual(lines[0], "password requisite pam_pwquality.so retry=3 enforce_for_root")
            self.assertEqual(pam.count("pam_pwquality.so"), 1)
            self.assertIn("shadow use_authtok # local password", pam)
            self.assertEqual(pam.split("-password", 1)[0].split("password requisite", 1)[0],
                             PAM_STACK.split("-password", 1)[0])
            self.assertIn("-password [success=1 default=ignore] pam_systemd_home.so", pam)
            result = call_helper("configure_password_policy", root)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((root / "etc/pam.d/system-auth").read_text(), pam)
            self.assertEqual((root / "etc/pam.d/system-auth.before-awesome").read_text(), old)
            self.assertEqual((root / "etc/security/faillock.conf").read_text(),
                             "# existing\naudit\ndeny = 5\nunlock_time = 900\n")

    def test_unsupported_stack_is_not_partially_installed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bad = PAM_STACK.replace("password required pam_unix.so", "password required pam_ldap.so")
            result = self.configure(root, bad)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((root / "etc/pam.d/system-auth").read_text(), bad)
            self.assertEqual((root / "etc/security/pwquality.conf").read_text(), "minlen = 8\n")

    def test_both_installers_configure_policy_before_passwords(self):
        for name in ("chroot.sh", "vps-chroot.sh"):
            source = (ROOT / "base" / name).read_text()
            self.assertLess(source.index("\nconfigure_password_policy\n"), source.index('passwd "$USERNAME"'))
            self.assertLess(source.index("\nconfigure_password_policy\n"), source.index("passwd root"))

    @unittest.skipUnless(Path("/usr/lib/security/pam_pwquality.so").exists(), "pam_pwquality unavailable")
    def test_real_pam_rejects_weak_password_without_a_password_writer(self):
        lib = ctypes.CDLL(ctypes.util.find_library("pam"))
        if not hasattr(lib, "pam_start_confdir"):
            self.skipTest("libpam lacks isolated configuration support")
        libc = ctypes.CDLL(None)
        libc.calloc.argtypes = [ctypes.c_size_t, ctypes.c_size_t]
        libc.calloc.restype = ctypes.c_void_p
        libc.strdup.argtypes = [ctypes.c_char_p]
        libc.strdup.restype = ctypes.c_void_p

        class Message(ctypes.Structure):
            _fields_ = [("style", ctypes.c_int), ("text", ctypes.c_char_p)]

        class Response(ctypes.Structure):
            _fields_ = [("text", ctypes.c_void_p), ("code", ctypes.c_int)]

        callback_type = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int,
            ctypes.POINTER(ctypes.POINTER(Message)), ctypes.POINTER(ctypes.POINTER(Response)), ctypes.c_void_p)

        class Conversation(ctypes.Structure):
            _fields_ = [("callback", callback_type), ("data", ctypes.c_void_p)]

        lib.pam_start_confdir.argtypes = [ctypes.c_char_p, ctypes.c_char_p,
            ctypes.POINTER(Conversation), ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p)]
        lib.pam_chauthtok.argtypes = [ctypes.c_void_p, ctypes.c_int]
        lib.pam_end.argtypes = [ctypes.c_void_p, ctypes.c_int]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = self.configure(root, PAM_STACK)
            self.assertEqual(result.returncode, 0, result.stderr)
            pam = (root / "etc/pam.d/system-auth").read_text()
            quality = next(line for line in pam.splitlines() if "pam_pwquality.so" in line)
            # Use real quality validation but ONLY pam_permit as the next module:
            # no host PAM files are loaded and no account password can be written.
            quality += " minlen=12 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1"
            (root / "policy-test").write_text(quality + "\npassword required pam_permit.so\n")
            for secret, succeeds in ((b"short", False), (b"V7!tQ3#nZ8@rL2$xM9", True)):
                messages_seen = []
                @callback_type
                def converse(count, messages, responses, data):
                    memory = libc.calloc(count, ctypes.sizeof(Response))
                    answer = ctypes.cast(memory, ctypes.POINTER(Response))
                    for i in range(count):
                        messages_seen.append(messages[i].contents.text.decode())
                        if messages[i].contents.style in (1, 2):
                            answer[i].text = libc.strdup(secret)
                    responses[0] = answer
                    return 0

                conv = Conversation(converse, None)
                handle = ctypes.c_void_p()
                rc = lib.pam_start_confdir(b"policy-test", pwd.getpwuid(os.getuid()).pw_name.encode(),
                                          ctypes.byref(conv), str(root).encode(), ctypes.byref(handle))
                self.assertEqual(rc, 0)
                rc = lib.pam_chauthtok(handle, 0)
                lib.pam_end(handle, rc)
                self.assertEqual(rc == 0, succeeds, f"PAM returned {rc}: {messages_seen}")


if __name__ == "__main__":
    unittest.main()
