"""
Unit and Integration Tests for ZeroTrustZone (ZTZ) Pre-Flight Context Attestation (Pillar 5 -> Pillar 4).
Tests secret scrubbing, deterministic SHA-256 digests, and Security Den Enclave sealing.
"""

import os
import shutil
import tempfile
import unittest
from unittest.mock import patch, MagicMock
import json

from ztz.core.crypto import generate_keypair
from ztz.core.trust_store import TrustStore

from ztz.core.context_shield import ContextShield, ContextAuditResult, EnclaveSeal
from zerotrustzone.core.context_shield import (
    ContextShield as ZTZContextShield,
    ContextAuditResult as ZTZContextAuditResult,
    EnclaveSeal as ZTZEnclaveSeal,
)


class TestContextAttestation(unittest.TestCase):

    def setUp(self):
        # Pin an explicit sealing key so results don't depend on the machine's ~/.ztz state.
        self.key_dir = tempfile.mkdtemp()
        self.seal_priv, _ = generate_keypair(out_dir=self.key_dir, name="sealer")
        env = patch.dict(os.environ, {"ZTZ_SEAL_KEY": self.seal_priv})
        env.start()
        self.addCleanup(env.stop)
        self.addCleanup(shutil.rmtree, self.key_dir, True)
        self.sample_leak = "Deploying model with key sk-1234567890abcdef1234567890abcdef1234 and AWS AKIAIOSFODNN7EXAMPLE"
        self.clean_sample = "Calculate the probability amplitude of 6-particle scattering at 9 loops."

    def test_reexports(self):
        """Verify EnclaveSeal and ContextShield are cleanly accessible via zerotrustzone.*."""
        self.assertIs(ZTZContextShield, ContextShield)
        self.assertIs(ZTZContextAuditResult, ContextAuditResult)
        self.assertIs(ZTZEnclaveSeal, EnclaveSeal)

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

    def test_local_authority_fallback_seal(self):
        """Verify fallback to a verifiable authority signature when Security Den is offline."""
        result = ContextShield.seal_and_attest(
            self.clean_sample,
            enclave_url="http://127.0.0.1:59999" # Deliberately dead port
        )
        self.assertIsNotNone(result.seal)
        self.assertTrue(result.seal.sealed)
        self.assertEqual(result.seal.mode, "LOCAL_AUTHORITY_SIG")
        self.assertEqual(result.seal.status, "LOCAL_ATTESTED")
        self.assertIsNotNone(result.seal.key_id)

        store = TrustStore([self.key_dir])
        self.assertEqual(ContextShield.verify_local_seal(result.digest_sha256, result.seal, store), "sealer")
        # Seal must not transfer to a different payload.
        self.assertIsNone(ContextShield.verify_local_seal("0" * 64, result.seal, store))

    def test_fallback_seal_not_forgeable_without_key(self):
        """A seal from an untrusted key must not verify against the trust store."""
        rogue_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, rogue_dir, True)
        rogue_priv, _ = generate_keypair(out_dir=rogue_dir, name="rogue")
        with patch.dict(os.environ, {"ZTZ_SEAL_KEY": rogue_priv}):
            seal = ContextShield.request_enclave_seal("ab" * 32, enclave_url="http://127.0.0.1:59999")
        self.assertIsNone(ContextShield.verify_local_seal("ab" * 32, seal, TrustStore([self.key_dir])))

    def test_unsealed_when_no_key(self):
        """With the Enclave offline and no key, report UNSEALED instead of a fake seal."""
        with patch.dict(os.environ, {"ZTZ_SEAL_KEY": ""}),              patch("ztz.core.trust_store.find_private_key", return_value=None):
            seal = ContextShield.request_enclave_seal("ab" * 32, enclave_url="http://127.0.0.1:59999")
        self.assertFalse(seal.sealed)
        self.assertEqual(seal.status, "UNSEALED")
        self.assertIsNone(seal.signature_hex)

    def test_mocked_ztz_enclave_dsa_seal(self):
        """Verify proper ingestion and parsing of ZTZ DSA signature from ZTZ Enclave."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.__enter__.return_value = mock_response
        mock_response.read.return_value = json.dumps({
            "status": "secure",
            "message": "Signature Generated Successfully.",
            "egress_data": [10, 20, 30, 40, 50, 60, 70],
            "ztz_trace": [-3, -2, -1, 0, 1, 2, 3]
        }).encode("utf-8")

        with patch("urllib.request.urlopen", return_value=mock_response):
            result = ContextShield.seal_and_attest(
                self.clean_sample,
                enclave_url="http://127.0.0.1:5555"
            )
            self.assertIsNotNone(result.seal)
            self.assertTrue(result.seal.sealed)
            self.assertEqual(result.seal.mode, "ZTZ_DSA")
            self.assertEqual(result.seal.status, "SECURE")
            self.assertEqual(result.seal.signature_hex, "0a141e28323c46")
            self.assertEqual(result.seal.ztz_trace, [-3, -2, -1, 0, 1, 2, 3])

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
