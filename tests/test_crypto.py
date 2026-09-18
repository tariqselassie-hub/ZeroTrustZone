import os
import tempfile
import unittest
from usershield.core.crypto import (
    generate_keypair,
    UserShieldSigner,
    UserShieldVerifier,
    compute_file_sha256,
)
from cryptography.hazmat.primitives import serialization

class TestCrypto(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        self.dir_path = self.test_dir.name

    def tearDown(self):
        self.test_dir.cleanup()

    def test_ed25519_sign_and_verify(self):
        priv_path, pub_path = generate_keypair(
            key_type="ed25519",
            out_dir=self.dir_path,
            name="test_auth",
        )

        # Create dummy model file
        dummy_model = os.path.join(self.dir_path, "test_weights.gguf")
        with open(dummy_model, "wb") as f:
            f.write(b"GGUF_MAGIC_HEADER" + b"\x00" * 4096)

        # Sign
        signer = UserShieldSigner(priv_path)
        sig_path = signer.sign_file(dummy_model)
        self.assertTrue(os.path.exists(sig_path))

        # Load public key
        with open(pub_path, "rb") as pf:
            pub_key = serialization.load_pem_public_key(pf.read())

        # Verify clean file
        is_valid, algo = UserShieldVerifier.verify_file(dummy_model, sig_path, pub_key)
        self.assertTrue(is_valid)
        self.assertEqual(algo, "Ed25519")

        # Mutate 1 byte (tampering)
        with open(dummy_model, "r+b") as f:
            f.seek(10)
            f.write(b"\xFF")

        # Verify tampered file -> must fail
        is_valid_tampered, _ = UserShieldVerifier.verify_file(dummy_model, sig_path, pub_key)
        self.assertFalse(is_valid_tampered)

    def test_rsa_sign_and_verify(self):
        priv_path, pub_path = generate_keypair(
            key_type="rsa",
            out_dir=self.dir_path,
            name="test_rsa",
            rsa_bits=2048,
        )

        dummy_file = os.path.join(self.dir_path, "prompt.txt")
        with open(dummy_file, "wb") as f:
            f.write(b"You are an offline assistant.")

        signer = UserShieldSigner(priv_path)
        sig_path = signer.sign_file(dummy_file)

        with open(pub_path, "rb") as pf:
            pub_key = serialization.load_pem_public_key(pf.read())

        is_valid, algo = UserShieldVerifier.verify_file(dummy_file, sig_path, pub_key)
        self.assertTrue(is_valid)
        self.assertEqual(algo, "RSA-PSS")

if __name__ == "__main__":
    unittest.main()
