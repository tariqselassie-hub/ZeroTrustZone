"""
`ztz service`: definition files and service-manager commands per platform.
Never touches the real service manager: commands go to a recording runner and
files land in the isolated test HOME (see conftest.py).
"""

import os
import plistlib
import sys
import tempfile
import unittest
from unittest.mock import patch

from ztz.runners import service


class Recorder:
    def __init__(self, fail=None):
        self.calls = []
        self.fail = fail or {}

    def __call__(self, cmd):
        self.calls.append(list(cmd))
        return self.fail.get(tuple(cmd[:2]), 0)


class TestServiceDefinitions(unittest.TestCase):
    def setUp(self):
        self.cfg = service.ServiceConfig(trust_store="keys dir", log_file="logs/proxy.log", no_cache=True)

    def test_proxy_args_are_absolute(self):
        args = self.cfg.proxy_args()
        self.assertEqual(args[:3], ["-m", "ztz", "proxy"])
        self.assertEqual(args[args.index("--trust-store") + 1], os.path.abspath("keys dir"))
        self.assertEqual(args[args.index("--log-file") + 1], os.path.abspath("logs/proxy.log"))
        self.assertIn("--no-cache", args)

    def test_systemd_unit_quotes_paths_with_spaces(self):
        unit = service.render("linux", self.cfg, "/opt/py 3/bin/python").decode()
        exec_line = next(l for l in unit.splitlines() if l.startswith("ExecStart="))
        self.assertTrue(exec_line.startswith('ExecStart="/opt/py 3/bin/python" -m ztz proxy'))
        self.assertIn('--trust-store "', exec_line)
        self.assertIn('keys dir" --no-cache', exec_line)
        self.assertIn("Restart=on-failure", unit)
        self.assertIn("WantedBy=default.target", unit)

    def test_launchd_plist_keeps_argv_intact(self):
        plist = plistlib.loads(service.render("darwin", self.cfg, "/usr/bin/python3"))
        self.assertEqual(plist["Label"], service.LAUNCHD_LABEL)
        self.assertEqual(plist["ProgramArguments"], ["/usr/bin/python3"] + self.cfg.proxy_args())
        self.assertTrue(plist["RunAtLoad"])

    def test_windows_task_xml_is_utf16_and_escaped(self):
        with patch.dict(os.environ, {"USERNAME": "a&b", "USERDOMAIN": "PC"}):
            xml = service.render("windows", self.cfg, r"C:\Py\pythonw.exe").decode("utf-16")
        self.assertIn("<UserId>PC\\a&amp;b</UserId>", xml)
        self.assertIn(r"<Command>C:\Py\pythonw.exe</Command>", xml)
        self.assertIn("<Hidden>true</Hidden>", xml)
        self.assertIn("<RunLevel>LeastPrivilege</RunLevel>", xml)
        self.assertIn("--no-cache", xml)

    def test_unknown_platform_rejected(self):
        with self.assertRaises(ValueError):
            service.service_file("plan9")


@patch.object(service, "_launchd_domain", return_value="gui/501")
class TestServiceLifecycle(unittest.TestCase):
    def setUp(self):
        self.cfg = service.ServiceConfig(log_file=os.path.join(tempfile.mkdtemp(), "proxy.log"))

    def _cleanup(self, platform):
        path = service.service_file(platform)
        if os.path.exists(path):
            os.remove(path)

    def test_install_writes_file_and_runs_manager(self, _):
        expected = {
            "linux": [["systemctl", "--user", "daemon-reload"],
                      ["systemctl", "--user", "enable", "--now", service.UNIT_NAME]],
            "darwin": [["launchctl", "bootout", "gui/501", service.service_file("darwin")],
                       ["launchctl", "bootstrap", "gui/501", service.service_file("darwin")]],
            "windows": [["schtasks", "/Create", "/TN", service.TASK_NAME, "/XML", service.service_file("windows"), "/F"],
                        ["schtasks", "/Run", "/TN", service.TASK_NAME]],
        }
        for platform, cmds in expected.items():
            with self.subTest(platform=platform):
                self.addCleanup(self._cleanup, platform)
                runner = Recorder()
                self.assertEqual(service.install(self.cfg, platform=platform, runner=runner), 0)
                self.assertEqual(runner.calls, cmds)
                self.assertTrue(os.path.exists(service.service_file(platform)))
                self.assertTrue(service.service_file(platform).startswith(os.path.expanduser("~")))

    def test_no_start_skips_starting(self, _):
        self.addCleanup(self._cleanup, "windows")
        runner = Recorder()
        service.install(self.cfg, platform="windows", start=False, runner=runner)
        self.assertEqual([c[1] for c in runner.calls], ["/Create"])

    def test_dry_run_writes_and_runs_nothing(self, _):
        runner = Recorder()
        self.assertEqual(service.install(self.cfg, platform="linux", dry_run=True, runner=runner), 0)
        self.assertEqual(runner.calls, [])
        self.assertFalse(os.path.exists(service.service_file("linux")))

    def test_tolerated_failure_on_reinstall(self, _):
        self.addCleanup(self._cleanup, "darwin")
        runner = Recorder(fail={("launchctl", "bootout"): 3})
        self.assertEqual(service.install(self.cfg, platform="darwin", runner=runner), 0)

    def test_manager_failure_is_reported(self, _):
        self.addCleanup(self._cleanup, "linux")
        runner = Recorder(fail={("systemctl", "--user"): 1})
        self.assertEqual(service.install(self.cfg, platform="linux", runner=runner), 1)

    def test_missing_manager_binary(self, _):
        self.addCleanup(self._cleanup, "linux")

        def missing(cmd):
            raise FileNotFoundError(cmd[0])

        self.assertEqual(service.install(self.cfg, platform="linux", runner=missing), 1)

    def test_uninstall_removes_file(self, _):
        runner = Recorder()
        service.install(self.cfg, platform="linux", runner=runner)
        runner.calls.clear()
        self.assertEqual(service.uninstall(platform="linux", runner=runner), 0)
        self.assertFalse(os.path.exists(service.service_file("linux")))
        self.assertEqual(runner.calls, [["systemctl", "--user", "disable", "--now", service.UNIT_NAME],
                                        ["systemctl", "--user", "daemon-reload"]])

    def test_uninstall_and_status_when_absent(self, _):
        runner = Recorder()
        self.assertEqual(service.uninstall(platform="windows", runner=runner), 0)
        self.assertEqual(service.status(platform="windows", runner=runner), 3)
        self.assertEqual(runner.calls, [])


class TestProxyLogFile(unittest.TestCase):
    def test_log_file_captures_proxy_output(self):
        from ztz import cli
        log = os.path.join(tempfile.mkdtemp(), "nested", "proxy.log")

        def fake_proxy(**kwargs):
            print("proxy up")

        argv = ["ztz", "proxy", "--log-file", log]
        old_out, old_err = sys.stdout, sys.stderr
        try:
            with patch.object(sys, "argv", argv), patch.object(cli, "run_proxy", fake_proxy), \
                 self.assertRaises(SystemExit) as cm:
                cli.main()
            sys.stdout.close()
        finally:
            sys.stdout, sys.stderr = old_out, old_err
        self.assertEqual(cm.exception.code, 0)
        with open(log, encoding="utf-8") as f:
            self.assertIn("proxy up", f.read())


if __name__ == "__main__":
    unittest.main()
