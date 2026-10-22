"""
Tests for ModelFormatInspector (tests/test_model_inspector.py)
Verifies:
1. GGUF magic header, version, tensor & metadata parsing.
2. Safetensors 8-byte uint64 header length & JSON metadata parsing.
3. PyTorch / Pickle opcode trap detection.
4. Truncated & missing file handling.
"""

import os
import json
import struct
import tempfile
import unittest

from ztz.core.model_inspector import ModelFormatInspector, ModelInspectionReport


class TestModelFormatInspector(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_gguf_valid_header(self):
        """Verify standard GGUF v3 header is recognized and validated."""
        file_path = os.path.join(self.tmp_dir.name, "test_model.gguf")
        with open(file_path, "wb") as f:
            f.write(b"GGUF")  # magic
            f.write(struct.pack("<I", 3))  # version 3
            f.write(struct.pack("<Q", 320))  # tensor count
            f.write(struct.pack("<Q", 18))  # kv count
            f.write(b"\x00" * 1024)  # mock payload

        rep = ModelFormatInspector.inspect(file_path)
        self.assertEqual(rep.format, "GGUF")
        self.assertTrue(rep.is_safe_format)
        self.assertEqual(rep.risk_level, "LOW")
        self.assertEqual(rep.metadata["gguf_version"], 3)
        self.assertEqual(rep.metadata["tensor_count"], 320)
        self.assertEqual(rep.metadata["kv_metadata_count"], 18)

    def test_safetensors_valid_header(self):
        """Verify Safetensors header is recognized and tensor count extracted."""
        file_path = os.path.join(self.tmp_dir.name, "model.safetensors")
        header_dict = {
            "weight1": {"dtype": "F16", "shape": [1024, 1024], "data_offsets": [0, 2097152]},
            "weight2": {"dtype": "F16", "shape": [1024, 1024], "data_offsets": [2097152, 4194304]},
            "__metadata__": {"format": "pt"}
        }
        header_json = json.dumps(header_dict).encode("utf-8")
        header_len = len(header_json)

        with open(file_path, "wb") as f:
            f.write(struct.pack("<Q", header_len))
            f.write(header_json)
            f.write(b"\x00" * 4096)

        rep = ModelFormatInspector.inspect(file_path)
        self.assertEqual(rep.format, "SAFETENSORS")
        self.assertTrue(rep.is_safe_format)
        self.assertEqual(rep.risk_level, "LOW")
        self.assertEqual(rep.metadata["tensor_count"], 2)

    def test_pytorch_pickle_trap(self):
        """Verify PyTorch pickle files containing suspicious opcodes trigger CRITICAL risk."""
        file_path = os.path.join(self.tmp_dir.name, "malicious_weights.pt")
        # Simulate PyTorch checkpoint with os.system pickle opcode
        with open(file_path, "wb") as f:
            f.write(b"\x80\x04\x95\x00\x00\x00\x00\x00\x00\x00\x00")
            f.write(b"cos\nsystem\n(S'whoami'\ntR.")

        rep = ModelFormatInspector.inspect(file_path)
        self.assertEqual(rep.format, "PYTORCH_PICKLE")
        self.assertFalse(rep.is_safe_format)
        self.assertEqual(rep.risk_level, "CRITICAL")
        self.assertTrue(any("pickle opcode" in w for w in rep.warnings))

    def test_unresolved_stack_global_is_critical(self):
        """A POP between the pushes hides 'os system' from the stack mirror; it must still block."""
        file_path = os.path.join(self.tmp_dir.name, "obfuscated.pt")
        with open(file_path, "wb") as f:
            # 'os', 'system', 'x', POP, STACK_GLOBAL -> os.system('id')
            f.write(b"\x80\x04\x8c\x02os\x8c\x06system\x8c\x01x0\x93\x8c\x02id\x85R.")

        rep = ModelFormatInspector.inspect(file_path)
        self.assertEqual(rep.risk_level, "CRITICAL")
        self.assertIn("<unresolved STACK_GLOBAL>", rep.metadata["dangerous_imports"])

    def test_scan_limit_padding_is_critical(self):
        """Padding the stream past the scan limit must not hide a later import."""
        file_path = os.path.join(self.tmp_dir.name, "padded.pt")
        with open(file_path, "wb") as f:
            # 64-byte BINBYTES pad then POP, then os.system('id') via GLOBAL
            f.write(b"\x80\x04B" + struct.pack("<I", 64) + b"\x00" * 64 + b"0")
            f.write(b"cos\nsystem\n\x8c\x02id\x85R.")

        orig = ModelFormatInspector.MAX_PICKLE_SCAN_BYTES
        ModelFormatInspector.MAX_PICKLE_SCAN_BYTES = 32
        try:
            rep = ModelFormatInspector.inspect(file_path)
        finally:
            ModelFormatInspector.MAX_PICKLE_SCAN_BYTES = orig
        self.assertEqual(rep.risk_level, "CRITICAL")
        self.assertIn("<pickle scan limit exceeded>", rep.metadata["dangerous_imports"])

    def test_read_path_keeps_extension_checks_on_original_name(self):
        """A pinned descriptor path has no extension; pickle detection must still use the real name."""
        blob = os.path.join(self.tmp_dir.name, "blob")
        with open(blob, "wb") as f:
            f.write(b"\x80\x04\x95\x00\x00\x00\x00\x00\x00\x00\x00")
            f.write(b"cos\nsystem\n(S'whoami'\ntR.")

        rep = ModelFormatInspector.inspect("malicious_weights.pt", read_path=blob)
        self.assertEqual(rep.format, "PYTORCH_PICKLE")
        self.assertEqual(rep.risk_level, "CRITICAL")
        self.assertEqual(rep.file_path, "malicious_weights.pt")

    def test_missing_and_truncated_files(self):
        """Verify missing and truncated files are safely quarantined."""
        missing_rep = ModelFormatInspector.inspect(os.path.join(self.tmp_dir.name, "nonexistent.gguf"))
        self.assertEqual(missing_rep.format, "MISSING")
        self.assertEqual(missing_rep.risk_level, "CRITICAL")

        trunc_file = os.path.join(self.tmp_dir.name, "tiny.bin")
        with open(trunc_file, "wb") as f:
            f.write(b"ABC")
        trunc_rep = ModelFormatInspector.inspect(trunc_file)
        self.assertEqual(trunc_rep.format, "TRUNCATED")
        self.assertEqual(trunc_rep.risk_level, "CRITICAL")


if __name__ == "__main__":
    unittest.main()
