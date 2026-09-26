"""
Tests for UserShield Package Module Exports & Compatibility (tests/test_usershield_exports.py)
"""

import unittest


class TestUserShieldExports(unittest.TestCase):

    def test_import_usershield_submodules(self):
        """Verify all critical UserShield modules import cleanly from usershield.*."""
        import usershield
        from usershield.core.trust_store import TrustStore
        from usershield.core.validator import PreFlightValidator
        from usershield.core.crypto import generate_keypair, UserShieldSigner, UserShieldVerifier
        from usershield.core.cache import AttestationCache
        from usershield.core.context_shield import ContextShield, ContextAuditResult, EnclaveSeal
        from usershield.core.model_inspector import ModelFormatInspector
        from usershield.lic.fingerprint import HardwareFingerprint
        from usershield.lic.manager import LicenseManager
        from usershield.runners.llama_cpp import run_llama_protected
        from usershield.runners.proxy import run_proxy
        from usershield.ui.banners import print_header, print_audit_table

        self.assertIsNotNone(TrustStore)
        self.assertIsNotNone(PreFlightValidator)
        self.assertIsNotNone(UserShieldSigner)
        self.assertIsNotNone(UserShieldVerifier)
        self.assertIsNotNone(HardwareFingerprint)
        self.assertIsNotNone(ModelFormatInspector)
        self.assertIsNotNone(EnclaveSeal)


if __name__ == "__main__":
    unittest.main()
