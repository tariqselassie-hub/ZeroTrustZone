"""
Unit tests for ZeroTrustZone upgrades:
- ONNX protobuf container inspection, custom domains, and external_data path traversal
- GGUF chat_template Jinja2 SSTI detection
- Safetensors tensor offset bounds and overlap validation
- ContextShield custom rules (ZTZ_SHIELD_RULES) and strict mode (ZTZ_STRICT_SHIELD)
- CLI `ztz sign --recursive` and `ztz models verify`
"""

import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from ztz.core.context_shield import ContextShield, STRICT_SHIELD_ENV, SHIELD_RULES_ENV
from ztz.core.crypto import generate_keypair
from ztz.core.model_inspector import ModelFormatInspector


def _pb_varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def _pb_tag(field: int, wire: int) -> bytes:
    return _pb_varint((field << 3) | wire)


def _pb_bytes(field: int, data: bytes) -> bytes:
    return _pb_tag(field, 2) + _pb_varint(len(data)) + data


def _pb_int(field: int, val: int) -> bytes:
    return _pb_tag(field, 0) + _pb_varint(val)


def _build_onnx(
    ir_version: int = 9,
    producer: str = "pytorch",
    opset_domain: str = "",
    opset_ver: int = 17,
    node_domain: str = "",
    ext_location: str = "",
) -> bytes:
    opset = _pb_bytes(1, opset_domain.encode()) + _pb_int(2, opset_ver)
    node = _pb_bytes(4, b"Relu") + (_pb_bytes(7, node_domain.encode()) if node_domain else b"")
    graph_parts = [_pb_bytes(1, node)]
    if ext_location:
        kv = _pb_bytes(1, b"location") + _pb_bytes(2, ext_location.encode())
        tensor = _pb_int(9, 1) + _pb_bytes(13, kv)
        graph_parts.append(_pb_bytes(5, tensor))
    graph = b"".join(graph_parts)
    return (
        _pb_int(1, ir_version)
        + _pb_bytes(2, producer.encode())
        + _pb_bytes(7, graph)
        + _pb_bytes(8, opset)
    )


def _build_gguf_with_kv(kv_pairs: dict) -> bytes:
    def _gguf_str(s: str) -> bytes:
        b = s.encode("utf-8")
        return struct.pack("<Q", len(b)) + b

    buf = bytearray()
    buf += b"GGUF"
    buf += struct.pack("<I", 3)
    buf += struct.pack("<Q", 0)
    buf += struct.pack("<Q", len(kv_pairs))
    for k, v in kv_pairs.items():
        buf += _gguf_str(k)
        buf += struct.pack("<I", 8)  # GGUF string type
        buf += _gguf_str(v)
    return bytes(buf)


class TestInspectorUpgrades(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, name: str, data: bytes) -> str:
        p = os.path.join(self.tmp, name)
        with open(p, "wb") as f:
            f.write(data)
        return p

    def test_onnx_valid_model(self):
        path = self._write("model.onnx", _build_onnx())
        rep = ModelFormatInspector.inspect(path)
        self.assertEqual(rep.format, "ONNX")
        self.assertTrue(rep.is_safe_format)
        self.assertEqual(rep.risk_level, "LOW")
        self.assertEqual(rep.metadata["ir_version"], 9)
        self.assertEqual(rep.metadata["producer_name"], "pytorch")
        self.assertEqual(rep.metadata["node_count"], 1)

    def test_onnx_custom_domain_warns(self):
        path = self._write("custom.onnx", _build_onnx(node_domain="com.evil.custom"))
        rep = ModelFormatInspector.inspect(path)
        self.assertEqual(rep.format, "ONNX")
        self.assertTrue(rep.is_safe_format)
        self.assertEqual(rep.risk_level, "MEDIUM")
        self.assertIn("com.evil.custom", rep.metadata["custom_domains"])

    def test_onnx_external_data_traversal_is_critical(self):
        path = self._write("trav.onnx", _build_onnx(ext_location="../../etc/passwd"))
        rep = ModelFormatInspector.inspect(path)
        self.assertEqual(rep.format, "ONNX")
        self.assertFalse(rep.is_safe_format)
        self.assertEqual(rep.risk_level, "CRITICAL")

    def test_onnx_corrupt_warns_and_marks_invalid_magic(self):
        path = self._write("bad.onnx", b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")
        rep = ModelFormatInspector.inspect(path)
        self.assertEqual(rep.format, "ONNX")
        self.assertFalse(rep.magic_bytes_valid)
        self.assertEqual(rep.risk_level, "MEDIUM")

    def test_gguf_chat_template_ssti_is_critical(self):
        data = _build_gguf_with_kv({
            "general.architecture": "llama",
            "tokenizer.chat_template": "{{ ''.__class__.__mro__[1].__subclasses__() }}",
        })
        path = self._write("ssti.gguf", data)
        rep = ModelFormatInspector.inspect(path)
        self.assertEqual(rep.format, "GGUF")
        self.assertFalse(rep.is_safe_format)
        self.assertEqual(rep.risk_level, "CRITICAL")
        self.assertTrue(rep.metadata.get("chat_template_risk"))

    def test_safetensors_oob_and_overlapping_offsets(self):
        header_oob = json.dumps({"w": {"dtype": "F32", "shape": [2], "data_offsets": [0, 9999]}}).encode()
        p_oob = self._write("oob.safetensors", struct.pack("<Q", len(header_oob)) + header_oob + b"\x00" * 8)
        rep_oob = ModelFormatInspector.inspect(p_oob)
        self.assertTrue(rep_oob.metadata.get("truncated_payload"))

        header_ov = json.dumps({
            "a": {"dtype": "F32", "shape": [1], "data_offsets": [0, 8]},
            "b": {"dtype": "F32", "shape": [1], "data_offsets": [4, 12]},
        }).encode()
        p_ov = self._write("ov.safetensors", struct.pack("<Q", len(header_ov)) + header_ov + b"\x00" * 16)
        rep_ov = ModelFormatInspector.inspect(p_ov)
        self.assertFalse(rep_ov.is_safe_format)
        self.assertEqual(rep_ov.risk_level, "CRITICAL")


class TestContextShieldUpgrades(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_custom_rules_from_env(self):
        rules_path = os.path.join(self.tmp, "rules.json")
        with open(rules_path, "w", encoding="utf-8") as f:
            json.dump([{"name": "INTERNAL_CORP_KEY", "pattern": r"corp_[a-z0-9]{12}"}], f)
        with patch.dict(os.environ, {SHIELD_RULES_ENV: rules_path}):
            res = ContextShield.sanitize("Use token corp_abc123def456 for staging")
        self.assertEqual(res.redactions_count, 1)
        self.assertIn("[ZTZ_QUENCHED:INTERNAL_CORP_KEY]", res.clean_text)
        self.assertNotIn("corp_abc123def456", res.clean_text)

    def test_strict_mode_blocks_on_leak(self):
        with patch.dict(os.environ, {STRICT_SHIELD_ENV: "1"}):
            bad = ContextShield.sanitize("AWS key AKIAIOSFODNN7EXAMPLE")
            good = ContextShield.sanitize("Hello world")
        self.assertFalse(bad.passed_preflight)
        self.assertTrue(good.passed_preflight)


class TestCLIUpgrades(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.keys = os.path.join(self.tmp, "keys")
        self.priv, _ = generate_keypair(out_dir=self.keys, name="root")
        self.models_dir = os.path.join(self.tmp, "models")
        os.makedirs(os.path.join(self.models_dir, "sub"), exist_ok=True)
        for rel in ("a.txt", os.path.join("sub", "b.txt")):
            with open(os.path.join(self.models_dir, rel), "w", encoding="utf-8") as f:
                f.write(f"payload {rel}")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run_cli(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "ztz", *args],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_sign_recursive_and_models_verify(self):
        r_sign = self._run_cli("sign", "--recursive", self.models_dir, "--key", self.priv)
        self.assertEqual(r_sign.returncode, 0, r_sign.stderr)
        a_path = os.path.join(self.models_dir, "a.txt")
        b_path = os.path.join(self.models_dir, "sub", "b.txt")
        self.assertTrue(os.path.isfile(f"{a_path}.sig"))
        self.assertTrue(os.path.isfile(f"{b_path}.sig"))

        r_ver = self._run_cli("models", "verify", a_path, "--trust-store", self.keys, "--no-cache", "--json")
        self.assertEqual(r_ver.returncode, 0, r_ver.stderr)
        payload = json.loads(r_ver.stdout)
        self.assertTrue(payload["verified"])

        # Tamper and re-verify
        with open(a_path, "w", encoding="utf-8") as f:
            f.write("tampered!")
        r_bad = self._run_cli("models", "verify", a_path, "--trust-store", self.keys, "--no-cache", "--json")
        self.assertEqual(r_bad.returncode, 1)
