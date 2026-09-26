"""
Unit and Integration Tests for UserShield Pre-Flight Context Attestation (Pillar 5 -> Pillar 4).
Tests secret scrubbing, deterministic SHA-256 digests, and Security Den Enclave sealing.
"""

import unittest
from unittest.mock import patch, MagicMock
import json

from ztz.core.context_shield import ContextShield, ContextAuditResult, EnclaveSeal
from usershield.core.context_shield import (
    ContextShield as USContextShield,
    ContextAuditResult as USContextAuditResult,
    EnclaveSeal as USEnclaveSeal,
)


class TestContextAttestation(unittest.TestCase):

    def setUp(self):
        self.sample_leak = "Deploying model with key sk-1234567890abcdef1234567890abcdef1234 and AWS AKIAIOSFODNN7EXAMPLE"
        self.clean_sample = "Calculate the probability amplitude of 6-particle scattering at 9 loops."

    def test_reexports(self):
        """Verify EnclaveSeal and ContextShield are cleanly accessible via usershield.*."""
        self.assertIs(USContextShield, ContextShield)
        self.assertIs(USContextAuditResult, ContextAuditResult)
        self.assertIs(USEnclaveSeal, EnclaveSeal)

    def test_sanitize_scrubs_secrets(self):
        """Verify prompt scrubbing neutralizes OpenAI API keys and AWS keys."""
        result = ContextShield.sanitize(self.sample_leak)
        self.assertTrue(result.passed_preflight)
        self.assertEqual(result.redactions_count, 2)
        self.assertNotIn("sk-1234567890abcdef1234567890abcdef1234", result.clean_text)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", result.clean_text)
        self.assertIn("[ZTZ_QUENCHED:OPENAI_API_KEY]", result.clean_text)
        self.assertIn("[ZTZ_QUENCHED:AWS_ACCESS_KEY_ID]", result.clean_text)
        self.assertIsNotNone(result.digest_sha256)
        self.assertEqual(len(result.digest_sha256), 64)

    def test_local_sovereign_fallback_seal(self):
        """Verify fallback to local HMAC-SHA256 signature when Security Den is offline."""
        result = ContextShield.seal_and_attest(
            self.clean_sample,
            enclave_url="http://127.0.0.1:59999" # Deliberately dead port
        )
        self.assertIsNotNone(result.seal)
        self.assertTrue(result.seal.sealed)
        self.assertEqual(result.seal.mode, "LOCAL_SOVEREIGN_FALLBACK")
        self.assertEqual(result.seal.status, "LOCAL_ATTESTED")
        self.assertIsNotNone(result.seal.signature_hex)

    def test_mocked_security_den_dsa_seal(self):
        """Verify proper ingestion and parsing of Base-7 Heptal DSA signature from Security Den."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.__enter__.return_value = mock_response
        mock_response.read.return_value = json.dumps({
            "status": "secure",
            "message": "Signature Generated Successfully.",
            "egress_data": [10, 20, 30, 40, 50, 60, 70],
            "heptal_trace": [-3, -2, -1, 0, 1, 2, 3]
        }).encode("utf-8")

        with patch("urllib.request.urlopen", return_value=mock_response):
            result = ContextShield.seal_and_attest(
                self.clean_sample,
                enclave_url="http://127.0.0.1:5555"
            )
            self.assertIsNotNone(result.seal)
            self.assertTrue(result.seal.sealed)
            self.assertEqual(result.seal.mode, "SECURITY_DEN_DSA")
            self.assertEqual(result.seal.status, "SECURE")
            self.assertEqual(result.seal.signature_hex, "0a141e28323c46")
            self.assertEqual(result.seal.heptal_trace, [-3, -2, -1, 0, 1, 2, 3])

    def test_seal_messages_multi_turn(self):
        """Verify multi-turn chat message scrubbing and composite sealing."""
        messages = [
            {"role": "system", "content": "You are a cyber defense agent."},
            {"role": "user", "content": "Database creds: postgresql://admin:supersecret@10.0.0.1:5432/db"},
            {"role": "assistant", "content": "Acknowledged."}
        ]

        clean_msgs, findings, total_redacted, seal = ContextShield.seal_messages(messages)
        self.assertEqual(total_redacted, 1)
        self.assertNotIn("supersecret", clean_msgs[1]["content"])
        self.assertIn("[ZTZ_QUENCHED:DATABASE_CREDENTIALS]", clean_msgs[1]["content"])
        self.assertTrue(seal.sealed)


if __name__ == "__main__":
    unittest.main()
