"""
Anti-TOCTOU file pinning. Windows: verified files cannot be written, deleted or
renamed until the runtime (`ztz run`) or SDK block (`attested`) has finished.
Linux: verification and the runtime read the pinned descriptor, so swapping the
path is harmless and in-place writes abort the launch.
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
from ztz.core import file_pin
from ztz.core.file_pin import FD_BINDING, changed_files, pin_files, unpin_files
from ztz.core.validator import PreFlightValidator
from ztz.runners.llama_cpp import bind_target_files, expand_split_targets, run_llama_protected, split_shards

windows_only = unittest.skipUnless(os.name == "nt", "mandatory share-mode pinning is Windows-specific")
posix_only = unittest.skipIf(os.name == "nt", "POSIX descriptor pinning")
linux_only = unittest.skipUnless(FD_BINDING, "descriptor binding is Linux-specific")

MODEL_BYTES = b"GGUF\x03\x00\x00\x00" + b"\x00" * 16


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


class TestBindTargetFiles(unittest.TestCase):
    def test_rewrites_separate_and_inline_file_args_only(self):
        args = ["-m", "w.gguf", "--lora=a.gguf", "-p", "w.gguf", "-f", "ctx.txt"]
        mapping = {"w.gguf": "/proc/self/fd/5", "a.gguf": "/proc/self/fd/6"}
        self.assertEqual(
            bind_target_files(args, mapping),
            ["-m", "/proc/self/fd/5", "--lora=/proc/self/fd/6", "-p", "w.gguf", "-f", "ctx.txt"],
        )


class _PosixFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        keys = os.path.join(self.tmp, "keys")
        priv, _ = generate_keypair(out_dir=keys, name="root")
        self.trust = TrustStore([keys])
        self.model = os.path.join(self.tmp, "w.gguf")
        with open(self.model, "wb") as f:
            f.write(MODEL_BYTES)
        ZTZSigner(priv).sign_file(self.model)
        self.evil = os.path.join(self.tmp, "evil.gguf")
        with open(self.evil, "wb") as f:
            f.write(b"GGUF\x03\x00\x00\x00" + b"\xff" * 16)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


@posix_only
class TestPosixPinning(_PosixFixture):
    def test_inplace_write_after_pin_is_detected(self):
        pins = pin_files([self.model])
        try:
            with open(self.model, "ab") as f:
                f.write(b"backdoor")
            self.assertEqual(changed_files(pins), [self.model])
        finally:
            unpin_files(pins)

    def test_exclusive_lock_holder_blocks_pinning(self):
        import fcntl
        fd = os.open(self.model, os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            with self.assertRaises(OSError) as cm:
                pin_files([self.model])
            self.assertEqual(cm.exception.filename, self.model)
        finally:
            os.close(fd)

    def test_path_swap_detected_without_descriptor_binding(self):
        # The macOS code path: the original path is loaded, so a swap must abort.
        with patch.object(file_pin, "FD_BINDING", False):
            pins = pin_files([self.model])
            try:
                self.assertEqual(pins[0].load_path, self.model)
                os.replace(self.evil, self.model)
                self.assertEqual(changed_files(pins), [self.model])
            finally:
                unpin_files(pins)


@linux_only
class TestLinuxDescriptorBinding(_PosixFixture):
    def setUp(self):
        super().setUp()
        patcher = patch.object(llama_cpp.shutil, "which", return_value="llama-cli")
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_load_path_survives_path_swap(self):
        pins = pin_files([self.model])
        try:
            os.replace(self.evil, self.model)
            with open(pins[0].load_path, "rb") as f:
                self.assertEqual(f.read(), MODEL_BYTES)
            # Unlinking bumps the pinned inode's ctime; a swap before launch fails closed.
            self.assertEqual(changed_files(pins), [self.model])
        finally:
            unpin_files(pins)

    def test_validator_reads_pinned_descriptor(self):
        pins = pin_files([self.model])
        try:
            os.replace(self.evil, self.model)
            with PreFlightValidator(self.trust, use_cache=False) as v:
                row = v.validate_file(self.model, read_path=pins[0].load_path)
            self.assertEqual(row["status"], "VERIFIED")
        finally:
            unpin_files(pins)

    def test_runtime_loads_verified_bytes_after_swap(self):
        seen = {}
        model, evil = self.model, self.evil

        class FakeRuntime:
            returncode = 0

            def __init__(self, cmd, **kwargs):
                os.replace(evil, model)  # attacker swaps the path right at launch
                seen["arg"] = cmd[2]
                seen["pass_fds"] = kwargs.get("pass_fds")
                with open(cmd[2], "rb") as f:
                    seen["bytes"] = f.read()

            def wait(self):
                return 0

        with patch.object(llama_cpp.subprocess, "Popen", FakeRuntime):
            rc = run_llama_protected("llama-cli", ["-m", self.model], self.trust, use_cache=False)
        self.assertEqual(rc, 0)
        self.assertTrue(seen["arg"].startswith("/proc/self/fd/"))
        self.assertIn(int(seen["arg"].rsplit("/", 1)[1]), seen["pass_fds"])
        self.assertEqual(seen["bytes"], MODEL_BYTES)

    def test_inplace_write_during_verification_aborts_launch(self):
        real_audit = PreFlightValidator.audit_batch
        model = self.model

        def audit_then_tamper(self_, *args, **kwargs):
            result = real_audit(self_, *args, **kwargs)
            with open(model, "ab") as f:
                f.write(b"backdoor")
            return result

        with patch.object(PreFlightValidator, "audit_batch", audit_then_tamper), \
             patch.object(llama_cpp.subprocess, "Popen") as popen:
            rc = run_llama_protected("llama-cli", ["-m", self.model], self.trust, use_cache=False)
        self.assertEqual(rc, 1)
        popen.assert_not_called()


class TestSplitShardNames(unittest.TestCase):
    def test_head_expands_to_all_shards(self):
        self.assertEqual(split_shards("m/q-00001-of-00003.gguf"), [
            "m/q-00001-of-00003.gguf", "m/q-00002-of-00003.gguf", "m/q-00003-of-00003.gguf",
        ])

    def test_non_heads_are_left_alone(self):
        for path in ("w.gguf", "q-00002-of-00003.gguf", "q-00001-of-00001.gguf", "q-00001-of-3.gguf"):
            self.assertEqual(split_shards(path), [path])

    def test_expand_keeps_order_and_dedupes(self):
        self.assertEqual(
            expand_split_targets(["q-00001-of-00002.gguf", "ctx.txt", "q-00002-of-00002.gguf"]),
            ["q-00001-of-00002.gguf", "q-00002-of-00002.gguf", "ctx.txt"],
        )


class TestSplitModels(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        keys = os.path.join(self.tmp, "keys")
        self.priv, _ = generate_keypair(out_dir=keys, name="root")
        self.trust = TrustStore([keys])
        self.shards = []
        for i in (1, 2):
            path = os.path.join(self.tmp, f"q-0000{i}-of-00002.gguf")
            with open(path, "wb") as f:
                f.write(MODEL_BYTES + bytes([i]))
            self.shards.append(path)
        patcher = patch.object(llama_cpp.shutil, "which", return_value="llama-cli")
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self):
        return run_llama_protected("llama-cli", ["-m", self.shards[0]], self.trust, use_cache=False)

    def test_unsigned_second_shard_blocks_launch(self):
        ZTZSigner(self.priv).sign_file(self.shards[0])
        with patch.object(llama_cpp.subprocess, "Popen") as popen:
            self.assertEqual(self._run(), 1)
        popen.assert_not_called()

    def test_missing_second_shard_blocks_launch(self):
        ZTZSigner(self.priv).sign_file(self.shards[0])
        os.remove(self.shards[1])
        with patch.object(llama_cpp.subprocess, "Popen") as popen:
            self.assertEqual(self._run(), 1)
        popen.assert_not_called()

    def test_runtime_finds_verified_siblings(self):
        for s in self.shards:
            ZTZSigner(self.priv).sign_file(s)
        seen = {}
        shards = self.shards

        class FakeRuntime:
            returncode = 0

            def __init__(self, cmd, **kwargs):
                head = cmd[2]
                seen["head"] = head
                sibling = os.path.join(os.path.dirname(head), os.path.basename(shards[1]))
                if FD_BINDING:
                    # Attacker swaps shard 2's path; the runtime must still get the verified bytes.
                    with open(shards[1] + ".evil", "wb") as f:
                        f.write(b"evil")
                    os.replace(shards[1] + ".evil", shards[1])
                with open(sibling, "rb") as f:
                    seen["sibling"] = f.read()
                seen["split_dir"] = os.path.dirname(head)

            def wait(self):
                return 0

        with patch.object(llama_cpp.subprocess, "Popen", FakeRuntime):
            self.assertEqual(self._run(), 0)
        self.assertTrue(seen["head"].endswith("q-00001-of-00002.gguf"))
        if FD_BINDING:
            self.assertNotEqual(seen["head"], self.shards[0])
            self.assertEqual(seen["sibling"], MODEL_BYTES + b"\x02")
            self.assertFalse(os.path.exists(seen["split_dir"]), "split link dir must be removed")
        else:
            self.assertEqual(seen["sibling"], MODEL_BYTES + b"\x02")

    @windows_only
    def test_second_shard_is_pinned_while_runtime_runs(self):
        for s in self.shards:
            ZTZSigner(self.priv).sign_file(s)
        observed = {}
        second = self.shards[1]

        class FakeRuntime:
            returncode = 0

            def __init__(self, cmd, **kwargs):
                observed.update(_try_tamper(second))

            def wait(self):
                return 0

        with patch.object(llama_cpp.subprocess, "Popen", FakeRuntime):
            self.assertEqual(self._run(), 0)
        self.assertEqual(observed, {"write": False, "rename": False, "read": True})

    @linux_only
    def test_swapped_split_link_blocks_launch(self):
        for s in self.shards:
            ZTZSigner(self.priv).sign_file(s)
        real_link = llama_cpp._link_split_shards

        def link_then_swap(targets, bound):
            root, links = real_link(targets, bound)
            victim = next(link for link in links if "00002" in link)
            os.remove(victim)
            os.symlink(self.shards[1], victim)  # point at the path instead of the pinned fd
            return root, links

        with patch.object(llama_cpp, "_link_split_shards", link_then_swap), \
             patch.object(llama_cpp.subprocess, "Popen") as popen:
            self.assertEqual(self._run(), 1)
        popen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
