"""
Tests for ZeroTrustZone (ZTZ) enhancements:
- Environment initialization (init)
- System diagnostics (doctor)
- Ollama & local model management (discovery, resolution, signing)
- Cascading trust store resolution
- CLI json and subcommands
"""

import os
import sys
import json
import shutil
import tempfile
import unittest
from unittest.mock import patch

from ztz.core.trust_store import TrustStore, find_private_key
from ztz.core.setup import init_environment
from ztz.core.doctor import run_diagnostics
from ztz.core.model_manager import (
    get_ollama_base_dir,
    discover_ollama_models,
    resolve_model_target,
    sign_model_target,
)
from ztz.cli import main, build_parser

class TestZeroTrustZoneEnhancements(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_cascading_trust_store(self):
        # Empty search path defaults to DEFAULT_SEARCH_PATHS without crashing
        ts = TrustStore(search_paths=[])
        self.assertIsInstance(ts.list_authorities(), list)

        # Custom dir works
        custom_dir = os.path.join(self.test_dir, "keys")
        os.makedirs(custom_dir, exist_ok=True)
        ts2 = TrustStore(search_paths=[custom_dir])
        self.assertEqual(len(ts2.list_authorities()), 0)

    def test_doctor_diagnostics(self):
        checks = run_diagnostics()
        self.assertIn("platform", checks)
        self.assertIn("crypto", checks)
        self.assertIn("trust_store", checks)
        self.assertIn("ollama", checks)
        self.assertIn("cache", checks)
        self.assertIn("context_shield", checks)
        self.assertIn("verdict", checks)
        self.assertTrue(checks["crypto"]["ok"])
        self.assertGreater(checks["context_shield"]["active_rules_count"], 0)

    def test_model_manager_mock_ollama(self):
        # Create a mock Ollama structure
        mock_ollama = os.path.join(self.test_dir, "ollama_models")
        manifests = os.path.join(mock_ollama, "manifests", "registry.ollama.ai", "library", "phi3")
        blobs = os.path.join(mock_ollama, "blobs")
        os.makedirs(manifests, exist_ok=True)
        os.makedirs(blobs, exist_ok=True)

        blob_hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        blob_path = os.path.join(blobs, f"sha256-{blob_hash}")
        # Write GGUF header magic
        with open(blob_path, "wb") as f:
            f.write(b"GGUF\x03\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")

        manifest_content = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "layers": [
                {
                    "mediaType": "application/vnd.ollama.image.model",
                    "digest": f"sha256:{blob_hash}",
                    "size": os.path.getsize(blob_path),
                }
            ]
        }
        with open(os.path.join(manifests, "latest"), "w") as f:
            json.dump(manifest_content, f)

        # 1. Discover models
        models = discover_ollama_models(mock_ollama)
        self.assertEqual(len(models), 1)
        self.assertEqual(models[0]["name"], "phi3:latest")
        self.assertEqual(models[0]["format"], "GGUF")
        self.assertFalse(models[0]["has_sig"])

        # 2. Resolve model by name
        resolved = resolve_model_target("phi3", mock_ollama)
        self.assertIsNotNone(resolved)
        self.assertEqual(resolved["blob_path"], blob_path)

        # 3. Sign model with generated key
        key_dir = os.path.join(self.test_dir, "keys")
        init_res = init_environment(force=True)
        sign_res = sign_model_target("phi3:latest", model_base_dir=mock_ollama)
        self.assertEqual(sign_res["status"], "SIGNED")
        self.assertTrue(os.path.exists(f"{blob_path}.sig"))

        # Re-discover and verify attestation passes
        models_after = discover_ollama_models(mock_ollama)
        self.assertEqual(models_after[0]["status"], "VERIFIED")

    def test_cli_parser_and_json(self):
        parser = build_parser()
        
        # Test init parser
        args = parser.parse_args(["init", "--json"])
        self.assertEqual(args.command, "init")
        self.assertTrue(args.json)

        # Test doctor parser
        args = parser.parse_args(["doctor", "--json"])
        self.assertEqual(args.command, "doctor")
        self.assertTrue(args.json)

        # Test models list parser
        args = parser.parse_args(["models", "list", "--json"])
        self.assertEqual(args.command, "models")
        self.assertEqual(args.models_action, "list")
        self.assertTrue(args.json)

        # Test context-scan with json
        args = parser.parse_args(["context-scan", "hello world", "--json"])
        self.assertEqual(args.command, "context-scan")
        self.assertTrue(args.json)

if __name__ == "__main__":
    unittest.main()
