import unittest
from ztz.lic.fingerprint import HardwareFingerprint

class TestHardwareFingerprint(unittest.TestCase):
    def test_fingerprint_deterministic(self):
        fp1 = HardwareFingerprint.compute_fingerprint()
        fp2 = HardwareFingerprint.compute_fingerprint()
        self.assertEqual(fp1, fp2, "Fingerprint must be deterministic across executions")
        self.assertEqual(len(fp1), 64, "Fingerprint must be 64-character SHA-256 hex string")

    def test_raw_components(self):
        raw = HardwareFingerprint.get_raw_components()
        self.assertIsInstance(raw, str)
        self.assertIn(":", raw)

if __name__ == "__main__":
    unittest.main()
