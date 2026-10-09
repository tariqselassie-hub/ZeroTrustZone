"""
Tests for ZeroTrustZone (ZTZ) Package Module Exports & Compatibility (tests/test_zerotrustzone_exports.py)
"""

import unittest


class TestZeroTrustZoneExports(unittest.TestCase):

    def test_import_zerotrustzone_submodules(self):
        """Verify all critical ZeroTrustZone modules import cleanly from zerotrustzone.* and ztz.*."""
        import zerotrustzone
        import ztz
        from zerotrustzone.core.trust_store import TrustStore
        from zerotrustzone.core.validator import PreFlightValidator
        from zerotrustzone.core.crypto import generate_keypair, ZTZSigner, ZTZVerifier
        from zerotrustzone.core.cache import AttestationCache
        from zerotrustzone.core.context_shield import ContextShield, ContextAuditResult, EnclaveSeal
        from zerotrustzone.core.model_inspector import ModelFormatInspector
        from zerotrustzone.core.setup import init_environment
        from zerotrustzone.core.doctor import run_diagnostics
        from zerotrustzone.core.model_manager import discover_ollama_models, sign_model_target
        from zerotrustzone.core.fingerprint import HardwareFingerprint
        from zerotrustzone.runners.llama_cpp import run_llama_protected
        from zerotrustzone.runners.proxy import run_proxy
        from zerotrustzone.ui.banners import print_header, print_audit_table

        self.assertIsNotNone(TrustStore)
        self.assertIsNotNone(PreFlightValidator)
        self.assertIsNotNone(ZTZSigner)
        self.assertIsNotNone(ZTZVerifier)
        self.assertIsNotNone(HardwareFingerprint)
        self.assertIsNotNone(ModelFormatInspector)
        self.assertIsNotNone(EnclaveSeal)
        self.assertIsNotNone(init_environment)
        self.assertIsNotNone(run_diagnostics)
        self.assertIsNotNone(discover_ollama_models)

    def test_alias_is_same_module_object(self):
        """zerotrustzone.* must be the very same module objects as ztz.*, not copies."""
        import ztz.core.crypto
        import ztz.core.file_pin
        import zerotrustzone
        import zerotrustzone.core.crypto
        from zerotrustzone.core import file_pin

        self.assertIs(zerotrustzone.core.crypto, ztz.core.crypto)
        self.assertIs(file_pin, ztz.core.file_pin)
        # Private helpers come through too (star-import shims dropped these).
        self.assertIs(file_pin._snapshot, ztz.core.file_pin._snapshot)
        self.assertIs(zerotrustzone.sdk, __import__("ztz.sdk").sdk)

    def test_alias_missing_attribute(self):
        import zerotrustzone
        with self.assertRaises(AttributeError):
            zerotrustzone.does_not_exist
        with self.assertRaises(ImportError):
            import zerotrustzone.nope  # noqa: F401

    def test_python_dash_m_entrypoint(self):
        import subprocess, sys
        out = subprocess.run([sys.executable, "-m", "zerotrustzone", "--help"],
                             capture_output=True, text=True, encoding="utf-8", timeout=60)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("ztz", out.stdout)


if __name__ == "__main__":
    unittest.main()
