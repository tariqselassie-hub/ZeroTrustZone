"""
Anti-TOCTOU file pinning on Windows: verified files cannot be written, deleted
or renamed until the runtime (`ztz run`) or SDK block (`attested`) has finished.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from ztz.core.crypto import ZTZSigner, generate_keypair
from ztz.core.trust_store import TrustStore
from ztz.runners import llama_cpp
from ztz.core.file_pin import pin_files, unpin_files
from ztz.runners.llama_cpp import run_llama_protected

windows_only = unittest.skipUnless(os.name == "nt", "mandatory share-mode pinning is Windows-specific")


def _try_tamper(path: str) -> dict:
    results = {}
    try:
        with open(path, "ab") as f:
            f.write(b"x")
        results["write"] = True
    except PermissionError:
        results["write"] = False
    try:
        os.rename(path, path + ".moved")
        os.rename(path + ".moved", path)
        results["rename"] = True
    except PermissionError:
        results["rename"] = False
    try:
        with open(path, "rb") as f:
            f.read(4)
        results["read"] = True
    except PermissionError:
        results["read"] = False
    return results


@windows_only
class TestWindowsPinning(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.model = os.path.join(self.tmp, "w.gguf")
        with open(self.model, "wb") as f:
            f.write(b"GGUF\x03\x00\x00\x00" + b"\x00" * 16)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_pinned_file_is_read_only_until_released(self):
        locks = pin_files([self.model])
        try:
            self.assertEqual(_try_tamper(self.model), {"write": False, "rename": False, "read": True})
            with self.assertRaises(PermissionError):
                os.remove(self.model)
        finally:
            unpin_files(locks)
        self.assertEqual(_try_tamper(self.model), {"write": True, "rename": True, "read": True})

    def test_existing_writer_blocks_pinning(self):
        with open(self.model, "ab"):
            with self.assertRaises(OSError) as cm:
                pin_files([self.model])
        self.assertEqual(cm.exception.filename, self.model)

    def test_partial_failure_releases_earlier_pins(self):
        other = os.path.join(self.tmp, "ctx.txt")
        with open(other, "w") as f:
            f.write("ctx")
        with open(other, "ab"):
            with self.assertRaises(OSError):
                pin_files([self.model, other])
        self.assertTrue(_try_tamper(self.model)["write"])

    def test_separate_process_can_mmap_pinned_file(self):
        reader = (
            "import mmap, sys\n"
            "with open(sys.argv[1], 'rb') as f:\n"
            "    m = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)\n"
            "    assert m[:4] == b'GGUF'\n"
        )
        locks = pin_files([self.model])
        try:
            proc = subprocess.run([sys.executable, "-c", reader, self.model], capture_output=True)
        finally:
            unpin_files(locks)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode(errors="replace"))

    def test_missing_targets_are_skipped(self):
        locks = pin_files([os.path.join(self.tmp, "absent.gguf")])
        self.assertEqual(locks, [])


@windows_only
class TestRunHoldsPins(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        keys = os.path.join(self.tmp, "keys")
        priv, _ = generate_keypair(out_dir=keys, name="root")
        self.trust = TrustStore([keys])
        self.model = os.path.join(self.tmp, "w.gguf")
        with open(self.model, "wb") as f:
            f.write(b"GGUF\x03\x00\x00\x00" + b"\x00" * 16)
        ZTZSigner(priv).sign_file(self.model)
        patcher = patch.object(llama_cpp.shutil, "which", return_value="llama-cli")
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self):
        return run_llama_protected("llama-cli", ["-m", self.model], self.trust, use_cache=False)

    def test_model_cannot_be_swapped_while_runtime_runs(self):
        observed = {}
        model = self.model

        class FakeRuntime:
            returncode = 0

            def __init__(self, cmd, **kwargs):
                observed.update(_try_tamper(model))

            def wait(self):
                return 0

        with patch.object(llama_cpp.subprocess, "Popen", FakeRuntime):
            self.assertEqual(self._run(), 0)
        self.assertEqual(observed, {"write": False, "rename": False, "read": True})
        self.assertTrue(_try_tamper(self.model)["write"])

    def test_open_writer_aborts_before_launch(self):
        with patch.object(llama_cpp.subprocess, "Popen") as popen, open(self.model, "ab"):
            self.assertEqual(self._run(), 1)
        popen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
