"""
Regression tests for development-branch hardening (tests/test_hardening.py)
Verifies:
1. `ztz run` dispatches to the llama.cpp runner without crashing.
2. Instant cache is invalidated when the .sig is replaced or the authority is revoked.
3. llama.cpp side-loading flags (LoRA, mmproj, draft...) are attested; remote fetch flags are refused.
4. Pickle scanner flags dangerous imports statically and passes plain torch-style checkpoints.
5. Generated private keys are owner-only on POSIX.
6. LLAMA_ARG_* variables naming files are refused; same-named keys in two roots are both trusted.
7. Ollama names keep their namespace / host; `ztz init` never replaces an existing private key.
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
from ztz.core import setup
from ztz.core.model_manager import manifest_model_name, normalize_model_name, discover_ollama_models
from ztz.runners.llama_cpp import extract_target_files, file_env_overrides, run_llama_protected


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

    def test_file_env_overrides(self):
        env = {"LLAMA_ARG_MODEL": "x.gguf", "LLAMA_ARG_HF_REPO": "o/r", "LLAMA_ARG_THREADS": "8",
               "LLAMA_ARG_SSL_KEY_FILE": "k.pem", "PATH": "/bin"}
        self.assertEqual(file_env_overrides(env), ["LLAMA_ARG_HF_REPO", "LLAMA_ARG_MODEL"])

    def test_runner_refuses_model_from_environment(self):
        with patch.dict(os.environ, {"LLAMA_ARG_MODEL": "unsigned.gguf"}), \
             patch("ztz.runners.llama_cpp.subprocess") as sp:
            rc = run_llama_protected(sys.executable, ["--version"], TrustStore([]))
        self.assertEqual(rc, 1)
        sp.run.assert_not_called()
        sp.Popen.assert_not_called()


class TestTrustStoreNameCollision(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.dirs = [os.path.join(self.tmp, d) for d in ("a", "b")]
        self.privs = [generate_keypair(out_dir=d)[0] for d in self.dirs]  # both authority_pub.pem

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_both_same_named_keys_are_trusted(self):
        ts = TrustStore(self.dirs)
        self.assertEqual(len(ts.list_authorities()), 2)
        target = os.path.join(self.tmp, "m.bin")
        with open(target, "wb") as f:
            f.write(b"weights-payload-0123456789")
        ZTZSigner(self.privs[1]).sign_file(target)
        with PreFlightValidator(ts, use_cache=False) as v:
            self.assertEqual(v.validate_file(target)["status"], "VERIFIED")

    def test_same_key_twice_is_listed_once(self):
        shutil.copy(os.path.join(self.dirs[0], "authority_pub.pem"), os.path.join(self.dirs[1], "copy_pub.pem"))
        self.assertEqual(len(TrustStore(self.dirs).list_authorities()), 2)


class TestOllamaModelNames(unittest.TestCase):
    def test_manifest_names(self):
        cases = {
            "registry.ollama.ai/library/llama3/latest": "llama3:latest",
            "registry.ollama.ai/someuser/llama3/latest": "someuser/llama3:latest",
            "hf.co/bartowski/Qwen-GGUF/Q4_K_M": "hf.co/bartowski/Qwen-GGUF:Q4_K_M",
            "deepseek-r1/latest": "deepseek-r1:latest",
        }
        for rel, name in cases.items():
            self.assertEqual(manifest_model_name(rel.split("/")), name)

    def test_user_names_normalized_like_ollama(self):
        self.assertEqual(normalize_model_name("Llama3"), "llama3:latest")
        self.assertEqual(normalize_model_name("registry.ollama.ai/library/llama3:8b"), "llama3:8b")
        self.assertEqual(normalize_model_name("hf.co/a/b:Q4"), "hf.co/a/b:q4")

    def test_namespaced_model_does_not_shadow_library_model(self):
        import json
        base = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(base, "blobs"))
            for i, rel in enumerate(("registry.ollama.ai/library/llama3/latest",
                                     "registry.ollama.ai/someuser/llama3/latest")):
                digest = str(i) * 64
                with open(os.path.join(base, "blobs", f"sha256-{digest}"), "wb") as f:
                    f.write(b"GGUF\x03\x00\x00\x00" + b"\x00" * 24)
                path = os.path.join(base, "manifests", *rel.split("/"))
                os.makedirs(os.path.dirname(path))
                with open(path, "w") as f:
                    json.dump({"layers": [{"mediaType": "application/vnd.ollama.image.model",
                                           "digest": f"sha256:{digest}"}]}, f)
            names = sorted(m["name"] for m in discover_ollama_models(base))
            self.assertEqual(names, ["llama3:latest", "someuser/llama3:latest"])
        finally:
            shutil.rmtree(base, ignore_errors=True)


class TestInitKeepsPrivateKey(unittest.TestCase):
    def test_missing_public_key_is_rebuilt_not_rotated(self):
        info = setup.init_environment()
        with open(info["private_key"], "rb") as f:
            priv_before = f.read()
        os.remove(info["public_key"])

        again = setup.init_environment()
        self.assertFalse(again["keys_created"])
        with open(info["private_key"], "rb") as f:
            self.assertEqual(f.read(), priv_before)
        target = os.path.join(os.path.dirname(info["private_key"]), "probe.bin")
        try:
            with open(target, "wb") as f:
                f.write(b"probe-payload-0123456789")
            ZTZSigner(info["private_key"]).sign_file(target)
            with PreFlightValidator(TrustStore([os.path.dirname(info["public_key"])]), use_cache=False) as v:
                self.assertEqual(v.validate_file(target)["status"], "VERIFIED")
        finally:
            for p in (target, f"{target}.sig"):
                if os.path.exists(p):
                    os.remove(p)


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


class TestLongApiKeyRedaction(unittest.TestCase):
    """Long modern keys must be masked whole; a partial mask leaks the remainder."""

    @staticmethod
    def _body(n):
        # Mixed alphabet with '-' and '_' so word boundaries occur inside the key.
        alphabet = "Ab3d_e-F9xQ"
        return "".join(alphabet[i % len(alphabet)] for i in range(n))

    def _assert_fully_masked(self, key, category):
        from ztz.core.context_shield import ContextShield
        res = ContextShield.sanitize(f"use {key} now")
        self.assertEqual(res.clean_text, f"use [ZTZ_QUENCHED:{category}] now")
        self.assertEqual(res.redactions_count, 1)

    def test_openai_project_key(self):
        self._assert_fully_masked("sk-proj-" + self._body(156), "OPENAI_API_KEY")

    def test_openai_service_account_key(self):
        self._assert_fully_masked("sk-svcacct-" + self._body(150), "OPENAI_API_KEY")

    def test_openai_legacy_key(self):
        self._assert_fully_masked("sk-" + "a1B2c3D4e5" * 4 + "f6G7h8J9", "OPENAI_API_KEY")

    def test_anthropic_api_key(self):
        self._assert_fully_masked("sk-ant-api03-" + self._body(95), "ANTHROPIC_API_KEY")

    def test_anthropic_key_without_internal_dashes(self):
        self._assert_fully_masked("sk-ant-api03-" + "Ab3_" * 23 + "xyzAA", "ANTHROPIC_API_KEY")

    def test_anthropic_admin_key(self):
        self._assert_fully_masked("sk-ant-admin01-" + self._body(93), "ANTHROPIC_API_KEY")

    def test_no_false_positive_inside_words(self):
        from ztz.core.context_shield import ContextShield
        text = "run task-" + "a" * 30 + " and disk-" + "b" * 30
        self.assertEqual(ContextShield.sanitize(text).redactions_count, 0)


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
