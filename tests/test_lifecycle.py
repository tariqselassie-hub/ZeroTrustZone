"""
Unit tests for ZeroTrustZone install, update, uninstall, service update, and models unsign.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from ztz.core import lifecycle
from ztz.core.crypto import generate_keypair
from ztz.runners import service


class TestLifecycle(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.ztz_home = os.path.join(self.tmp, ".ztz")
        self.keys_dir = os.path.join(self.ztz_home, "keys")
        self.config_path = os.path.join(self.ztz_home, "config.json")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_install_and_uninstall_preserves_keys_by_default(self):
        with patch("ztz.core.setup.ZTZ_HOME", self.ztz_home), \
             patch("ztz.core.setup.DEFAULT_ZTZ_STORE", self.keys_dir), \
             patch("ztz.core.setup.CONFIG_PATH", self.config_path), \
             patch("ztz.core.lifecycle.ZTZ_HOME", self.ztz_home), \
             patch("ztz.core.lifecycle.CONFIG_PATH", self.config_path):
            res = lifecycle.install_system(with_service=False)
            self.assertTrue(os.path.isfile(self.config_path))
            self.assertTrue(os.path.isdir(self.keys_dir))
            self.assertIn("version", res)

            # Create mock cache & logs to verify cleanup
            os.makedirs(os.path.join(self.ztz_home, "logs"), exist_ok=True)
            with open(os.path.join(self.ztz_home, "cache.db"), "wb") as f:
                f.write(b"sqlite")

            # Uninstall without --purge-keys: deletes config/logs/cache, keeps keys
            un_res = lifecycle.uninstall_system(
                purge_keys=False,
                home_dir=self.ztz_home,
                service_uninstall_fn=lambda: 0,
            )
            self.assertFalse(os.path.exists(self.config_path))
            self.assertFalse(os.path.exists(os.path.join(self.ztz_home, "cache.db")))
            self.assertTrue(un_res["keys_preserved"])
            self.assertTrue(os.path.isdir(self.keys_dir))

            # Uninstall with purge_keys=True: removes keys and empty home dir
            un_purge = lifecycle.uninstall_system(
                purge_keys=True,
                home_dir=self.ztz_home,
                service_uninstall_fn=lambda: 0,
            )
            self.assertFalse(un_purge["keys_preserved"])
            self.assertFalse(os.path.exists(self.keys_dir))
            self.assertTrue(un_purge["home_removed"])

    def test_update_check_and_execution(self):
        chk = lifecycle.update_system(check_only=True)
        self.assertTrue(chk["check_only"])
        self.assertTrue(len(chk["commands"]) >= 1)

        ran = []
        with patch("ztz.core.lifecycle.ZTZ_HOME", self.ztz_home), \
             patch("ztz.core.lifecycle.CONFIG_PATH", self.config_path):
            os.makedirs(self.ztz_home, exist_ok=True)
            res = lifecycle.update_system(
                restart_service=False,
                runner=lambda cmd: (ran.append(list(cmd)), 0)[1],
            )
        self.assertEqual(res["action"], "update")
        self.assertTrue(len(ran) >= 1)
        self.assertTrue(os.path.isfile(self.config_path))

    def test_service_config_strict_shield_and_update(self):
        cfg = service.ServiceConfig(strict_shield=True)
        self.assertIn("--strict-shield", cfg.proxy_args())
        ran = []
        with patch("ztz.runners.service.service_file", return_value=os.path.join(self.tmp, "svc.xml")):
            rc = service.update(
                cfg,
                platform="windows",
                start=True,
                runner=lambda cmd: (ran.append(list(cmd)), 0)[1],
            )
        self.assertEqual(rc, 0)
        self.assertTrue(any(cmd[:2] == ["schtasks", "/End"] for cmd in ran))
        self.assertTrue(any(cmd[:2] == ["schtasks", "/Create"] for cmd in ran))
        self.assertTrue(any(cmd[:2] == ["schtasks", "/Run"] for cmd in ran))

    def test_cli_models_unsign_and_uninstall_guard(self):
        keys = os.path.join(self.tmp, "k")
        priv, _ = generate_keypair(out_dir=keys, name="root")
        target = os.path.join(self.tmp, "m.gguf")
        with open(target, "wb") as f:
            f.write(b"GGUF\x03\x00\x00\x00" + b"\x00" * 16)

        subprocess.run([sys.executable, "-m", "ztz", "sign", target, "--key", priv], check=True, capture_output=True)
        self.assertTrue(os.path.isfile(f"{target}.sig"))

        r_unsign = subprocess.run(
            [sys.executable, "-m", "ztz", "models", "unsign", target, "--json"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(r_unsign.returncode, 0, r_unsign.stderr)
        self.assertFalse(os.path.exists(f"{target}.sig"))

        # --purge-keys without --yes must fail safely
        r_guard = subprocess.run(
            [sys.executable, "-m", "ztz", "uninstall", "--purge-keys"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(r_guard.returncode, 1)
