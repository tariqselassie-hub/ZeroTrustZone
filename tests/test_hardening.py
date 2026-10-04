"""
Regression tests for development-branch hardening (tests/test_hardening.py)
Verifies:
1. `ztz run` dispatches to the llama.cpp runner without crashing.
2. Instant cache is invalidated when the .sig is replaced or the authority is revoked.
3. llama.cpp side-loading flags (LoRA, mmproj, draft...) are attested; remote fetch flags are refused.
4. Pickle scanner flags dangerous imports statically and passes plain torch-style checkpoints.
5. Generated private keys are owner-only on POSIX.
"""

import os
import io
import sys
import pickle
import shutil
import tempfile
import unittest
import zipfile
import collections
from unittest.mock import patch

from ztz.core.cache import AttestationCache
from ztz.core.crypto import ZTZSigner, generate_keypair
from ztz.core.model_inspector import ModelFormatInspector
from ztz.core.trust_store import TrustStore
from ztz.core.validator import PreFlightValidator
from ztz.runners.llama_cpp import extract_target_files


class TestRunDispatch(unittest.TestCase):
    def test_run_reaches_runner(self):
        from ztz import cli
        argv = ["ztz", "run", "--llama-bin", "llama-cli", "-p", "hi"]
        with patch.object(sys, "argv", argv), \
             patch.object(cli, "run_llama_protected", return_value=0) as runner:
            with self.assertRaises(SystemExit) as cm:
                cli.main()
        self.assertEqual(cm.exception.code, 0)
        self.assertEqual(runner.call_args.kwargs["safe_args"], ["-p", "hi"])

    def test_run_does_not_swallow_llama_h_flags(self):
        from ztz import cli
        argv = ["ztz", "run", "--llama-bin", "llama-cli", "-hf", "org/repo", "--lic", "x"]
        with patch.object(sys, "argv", argv), \
             patch.object(cli, "run_llama_protected", return_value=0) as runner:
            with self.assertRaises(SystemExit):
                cli.main()
        self.assertEqual(runner.call_args.kwargs["safe_args"], ["-hf", "org/repo", "--lic", "x"])


class TestCacheRevocation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.keys = os.path.join(self.tmp, "keys")
        self.priv, self.pub = generate_keypair(out_dir=self.keys, name="root")
        self.model = os.path.join(self.tmp, "w.gguf")
        with open(self.model, "wb") as f:
            f.write(b"GGUF\x03\x00\x00\x00" + b"\x00" * 16)
        ZTZSigner(self.priv).sign_file(self.model)
        db = os.path.join(self.tmp, "cache.db")
        patcher = patch("ztz.core.validator.AttestationCache", lambda: AttestationCache(safe_db_path=db))
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _validate(self):
        with PreFlightValidator(TrustStore([self.keys])) as v:
            return v.validate_file(self.model)["status"]

    def test_cache_hit_then_revocation_misses(self):
        self.assertEqual(self._validate(), "VERIFIED")
        self.assertEqual(self._validate(), "VERIFIED_CACHE")
        os.remove(self.pub)  # revoke the authority
        self.assertEqual(self._validate(), "NO_ROOTS")

    def test_revoked_authority_with_other_root_present(self):
        self.assertEqual(self._validate(), "VERIFIED")
        generate_keypair(out_dir=self.keys, name="other")
        os.remove(self.pub)
        self.assertEqual(self._validate(), "TAMPERED")

    def test_replaced_signature_misses_cache(self):
        self.assertEqual(self._validate(), "VERIFIED")
        with open(self.model + ".sig", "wb") as f:
            f.write(b"\x00" * 64)
        self.assertEqual(self._validate(), "TAMPERED")


class TestLlamaArgExtraction(unittest.TestCase):
    def test_side_loading_flags_are_targets(self):
        args = ["-m", "a.gguf", "--lora", "l.gguf", "--lora-scaled", "s.gguf", "0.5",
                "--mmproj=p.gguf", "-md", "d.gguf", "--control-vector", "c.gguf", "-f", "p.txt"]
        self.assertEqual(
            extract_target_files(args),
            ["a.gguf", "l.gguf", "s.gguf", "p.gguf", "d.gguf", "c.gguf", "p.txt"],
        )

    def test_remote_fetch_refused(self):
        for args in (["-hf", "org/repo"], ["--model-url=http://x/m.gguf"], ["-m", "a.gguf", "-mu", "u"]):
            with self.assertRaises(ValueError):
                extract_target_files(args)

    def test_injection_and_dangling_flag(self):
        with self.assertRaises(ValueError):
            extract_target_files(["-m", "--lora"])
        with self.assertRaises(ValueError):
            extract_target_files(["-m"])


class _Evil:
    def __reduce__(self):
        return (os.system, ("echo pwned",))


class TestPickleScanner(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, name, data):
        path = os.path.join(self.tmp, name)
        with open(path, "wb") as f:
            f.write(data)
        return path

    def test_malicious_pickle_all_protocols(self):
        for proto in range(0, pickle.HIGHEST_PROTOCOL + 1):
            rep = ModelFormatInspector.inspect(self._write(f"evil{proto}.pt", pickle.dumps(_Evil(), protocol=proto)))
            self.assertEqual(rep.risk_level, "CRITICAL", f"protocol {proto}")
            self.assertTrue(rep.metadata["dangerous_imports"])

    def test_benign_pickle_is_medium_not_critical(self):
        state = collections.OrderedDict(("layer%d" % i, [1.0, 2.0]) for i in range(5))
        rep = ModelFormatInspector.inspect(self._write("ok.pt", pickle.dumps(state, protocol=2)))
        self.assertEqual(rep.risk_level, "MEDIUM")
        self.assertFalse(rep.is_safe_format)
        self.assertEqual(rep.metadata["dangerous_imports"], [])
        self.assertEqual(rep.metadata["unknown_imports"], [])

    def test_zip_checkpoint_member_scanned(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("archive/data.pkl", pickle.dumps(_Evil(), protocol=2))
            zf.writestr("archive/data/0", b"\x00" * 32)
        rep = ModelFormatInspector.inspect(self._write("zipped.pt", buf.getvalue()))
        self.assertEqual(rep.risk_level, "CRITICAL")


class TestLocalTrustOptIn(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.cwd = os.getcwd()
        os.chdir(self.tmp)
        generate_keypair(out_dir="./keys", name="planted")

    def tearDown(self):
        os.chdir(self.cwd)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_cwd_keys_not_trusted_by_default(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ZTZ_TRUST_LOCAL", None)
            ts = TrustStore()
        self.assertNotIn("./keys", ts.search_paths)
        self.assertIsNone(ts.get_authority("planted"))

    def test_cwd_keys_trusted_when_opted_in(self):
        with patch.dict(os.environ, {"ZTZ_TRUST_LOCAL": "1"}):
            self.assertIsNotNone(TrustStore().get_authority("planted"))
        self.assertIsNotNone(TrustStore(["./keys"]).get_authority("planted"))


@unittest.skipIf(os.name == "nt", "POSIX permission bits")
class TestKeyPermissions(unittest.TestCase):
    def test_private_key_owner_only(self):
        tmp = tempfile.mkdtemp()
        try:
            priv, _ = generate_keypair(out_dir=tmp)
            self.assertEqual(os.stat(priv).st_mode & 0o777, 0o600)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
