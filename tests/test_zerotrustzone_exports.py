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
        from zerotrustzone.lic.fingerprint import HardwareFingerprint
        from zerotrustzone.lic.manager import LicenseManager
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


if __name__ == "__main__":
    unittest.main()
