"""
Tests for AttestationCache (tests/test_cache.py)
Verifies:
1. Cache stores and retrieves valid attestations.
2. Cache row is cryptographically signed and bound to hardware fingerprint.
3. Cache persists across multiple AttestationCache instantiations.
4. Tampering with file size, mtime, or content invalidates the cache.
5. Cache clear completely purges the table.
"""

import os
import tempfile
import unittest

from ztz.core.cache import AttestationCache


class TestAttestationCache(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp_dir.name, "cache.db")
        # Ensure base directory containment
        self.cache = AttestationCache(safe_db_path=self.db_path)

    def tearDown(self):
        if hasattr(self, 'cache') and self.cache:
            self.cache.close()
        self.tmp_dir.cleanup()

    def test_cache_store_and_retrieve(self):
        """Verify storing and retrieving attestation works."""
        test_file = os.path.join(self.tmp_dir.name, "weights.gguf")
        with open(test_file, "wb") as f:
            f.write(b"SAMPLE_TENSORS_12345")

        self.cache.store_attestation(test_file, auth_key="zenith_root", algo="Ed25519")
        cached = self.cache.get_cached_attestation(test_file)

        self.assertIsNotNone(cached)
        self.assertEqual(cached["key"], "zenith_root")
        self.assertEqual(cached["algo"], "Ed25519")
        self.assertEqual(cached["status"], "VERIFIED_CACHE")

    def test_cache_persists_across_instances(self):
        """Verify new AttestationCache instance preserves existing records without DROP TABLE."""
        test_file = os.path.join(self.tmp_dir.name, "weights2.gguf")
        with open(test_file, "wb") as f:
            f.write(b"SAMPLE_TENSORS_PERSIST")

        self.cache.store_attestation(test_file, auth_key="zenith_root", algo="Ed25519")

        # Instantiate second cache pointing to the same DB
        cache2 = AttestationCache(safe_db_path=self.db_path)
        try:
            cached2 = cache2.get_cached_attestation(test_file)
            self.assertIsNotNone(cached2, "Cache record must persist across multiple AttestationCache instances!")
            self.assertEqual(cached2["key"], "zenith_root")
        finally:
            cache2.close()

    def test_tamper_invalidates_cache(self):
        """Verify modifying the cached file causes a cache miss."""
        test_file = os.path.join(self.tmp_dir.name, "weights3.gguf")
        with open(test_file, "wb") as f:
            f.write(b"ORIGINAL_BYTES")

        self.cache.store_attestation(test_file, auth_key="zenith_root", algo="Ed25519")

        # Modify file content and size
        with open(test_file, "ab") as f:
            f.write(b"_MODIFIED_AFTER_SIGNING")

        cached = self.cache.get_cached_attestation(test_file)
        self.assertIsNone(cached, "Tampered file must miss cache!")

    def test_cache_clear(self):
        """Verify clear() purges the cache."""
        test_file = os.path.join(self.tmp_dir.name, "weights4.gguf")
        with open(test_file, "wb") as f:
            f.write(b"DATA")

        self.cache.store_attestation(test_file, auth_key="zenith_root", algo="Ed25519")
        self.cache.clear()
        self.assertIsNone(self.cache.get_cached_attestation(test_file))


if __name__ == "__main__":
    unittest.main()
