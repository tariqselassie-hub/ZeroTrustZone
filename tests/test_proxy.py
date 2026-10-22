"""
ZTZ proxy: model files come from the backend's /api/show, every loaded file
(weights, projector, adapters) is attested, every model-loading endpoint is
covered, and the proxy refuses to share its port with another server.
Runs against a fake Ollama upstream; never touches a real backend.
"""

import asyncio
import json
import os
import shutil
import socket
import sqlite3
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from ztz.core import model_manager, netcheck
from ztz.core.crypto import ZTZSigner, generate_keypair
from ztz.core.model_manager import parse_modelfile_paths
from ztz.core.trust_store import TrustStore
from ztz.runners.proxy import InferenceProxy, assert_port_free, build_app

GGUF = b"GGUF\x03\x00\x00\x00" + b"\x00" * 24


class FakeOllama:
    """Upstream double: /api/show serves a modelfile, everything else is recorded."""

    def __init__(self, modelfiles):
        self.modelfiles = modelfiles  # model name -> modelfile text (None -> 404)
        self.forwarded = []
        self.bodies = []

    async def show(self, request):
        name = (await request.json())["model"]
        if self.modelfiles.get(name) is None:
            return web.json_response({"error": "model not found"}, status=404)
        return web.json_response({"modelfile": self.modelfiles[name]})

    async def other(self, request):
        self.forwarded.append(request.path)
        self.bodies.append(await request.read())
        return web.json_response({"ok": True, "path": request.path})

    def app(self):
        app = web.Application()
        app.router.add_post("/api/show", self.show)
        app.router.add_route("*", "/{tail:.*}", self.other)
        return app


class ProxyHarness(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        keys = os.path.join(self.tmp, "keys")
        priv, _ = generate_keypair(out_dir=keys, name="root")
        self.signer = ZTZSigner(priv)
        self.trust = TrustStore([keys])
        self.weights = self._blob("weights", sign=True)
        self.projector = self._blob("projector", sign=True)
        self.unsigned = self._blob("unsigned", sign=False)
        self.upstream = FakeOllama({
            "good": f"# FROM good:latest\nFROM {self.weights}\nFROM {self.projector}\n",
            "bad-projector": f"FROM {self.weights}\nFROM {self.unsigned}\n",
            "cloud": "FROM gpt-oss:120b-cloud\nTEMPLATE {{ .Prompt }}\n",
            "missing": None,
        })

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _blob(self, name, sign):
        path = os.path.join(self.tmp, f"sha256-{name}")
        with open(path, "wb") as f:
            f.write(GGUF + name.encode())
        if sign:
            self.signer.sign_file(path)
        return path

    def request(self, method, path, body=None):
        """Sends one request through the proxy; returns (status, json, headers)."""

        async def run():
            up_server = TestServer(self.upstream.app())
            await up_server.start_server()
            proxy = InferenceProxy(self.trust, upstream_port=up_server.port, use_cache=False)
            client = TestClient(TestServer(build_app(proxy)))
            await client.start_server()
            try:
                resp = await client.request(method, path, json=body)
                data = await resp.json(content_type=None)
                return resp.status, data, dict(resp.headers)
            finally:
                await client.close()
                await up_server.close()

        return asyncio.run(run())


class TestProxyAttestation(ProxyHarness):
    def test_signed_weights_and_projector_pass(self):
        status, data, _ = self.request("POST", "/api/generate", {"model": "good", "prompt": "hi"})
        self.assertEqual(status, 200, data)
        self.assertEqual(self.upstream.forwarded, ["/api/generate"])

    def test_unsigned_projector_blocks(self):
        status, data, _ = self.request("POST", "/api/chat", {"model": "bad-projector", "messages": []})
        self.assertEqual(status, 403)
        self.assertEqual(data["details"]["full_path"], self.unsigned)
        self.assertEqual(self.upstream.forwarded, [])

    def test_embed_and_openai_routes_are_attested(self):
        for path in ("/api/embed", "/api/embeddings", "/v1/embeddings", "/v1/responses"):
            with self.subTest(path=path):
                status, _, _ = self.request("POST", path, {"model": "bad-projector", "input": "x"})
                self.assertEqual(status, 403)
        self.assertEqual(self.upstream.forwarded, [])

    def test_multimodal_chat_is_scrubbed_and_forwarded(self):
        content = [{"type": "text", "text": "key AKIAIOSFODNN7EXAMPLE"},
                   {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}}]
        status, data, _ = self.request("POST", "/v1/chat/completions",
                                       {"model": "good", "messages": [{"role": "user", "content": content}]})
        self.assertEqual(status, 200, data)
        sent = json.loads(self.upstream.bodies[-1])
        self.assertNotIn("AKIA", sent["messages"][0]["content"][0]["text"])
        self.assertEqual(sent["messages"][0]["content"][1], content[1])

    def test_generate_system_prompt_is_scrubbed(self):
        status, _, _ = self.request("POST", "/api/generate",
                                    {"model": "good", "prompt": "hi", "system": "use AKIAIOSFODNN7EXAMPLE"})
        self.assertEqual(status, 200)
        self.assertNotIn(b"AKIA", self.upstream.bodies[-1])

    def test_management_endpoints_pass_untouched(self):
        status, _, _ = self.request("POST", "/api/pull", {"model": "bad-projector"})
        self.assertEqual(status, 200)
        self.assertEqual(self.upstream.forwarded, ["/api/pull"])

    def test_unknown_model_is_refused(self):
        status, _, _ = self.request("POST", "/api/generate", {"model": "missing", "prompt": "x"})
        self.assertEqual(status, 404)
        self.assertEqual(self.upstream.forwarded, [])

    def test_model_without_local_files_is_refused(self):
        status, data, _ = self.request("POST", "/api/generate", {"model": "cloud", "prompt": "x"})
        self.assertEqual(status, 403)
        self.assertIn("cannot be attested", data["message"])

    def test_every_response_carries_proxy_header(self):
        for method, path, body in (("GET", "/", None), ("POST", "/api/generate", {"model": "missing"})):
            _, _, headers = self.request(method, path, body)
            self.assertEqual(headers.get(netcheck.PROXY_HEADER), "1")


class TestModelfileParsing(unittest.TestCase):
    def test_paths_comments_blocks_and_model_refs(self):
        modelfile = "\n".join([
            "# FROM llama3:latest",
            "FROM /models/blobs/sha256-aa",
            'TEMPLATE """{{ .System }}',
            "FROM /evil/inside/template",
            '"""',
            "FROM C:\\Users\\me\\Models\\blobs\\sha256-bb",
            "ADAPTER /models/blobs/sha256-cc",
            "FROM llama3",
            'SYSTEM """one line"""',
            "PARAMETER stop <eos>",
        ])
        self.assertEqual(parse_modelfile_paths(modelfile), [
            "/models/blobs/sha256-aa",
            "C:\\Users\\me\\Models\\blobs\\sha256-bb",
            "/models/blobs/sha256-cc",
        ])


class TestPortGuard(unittest.TestCase):
    def test_refuses_when_port_taken(self):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        port = sock.getsockname()[1]
        try:
            with self.assertRaises(RuntimeError) as cm:
                assert_port_free("127.0.0.1", port, 11435)
            self.assertIn("127.0.0.1", str(cm.exception))
        finally:
            sock.close()

    def test_running_ztz_proxy_gets_its_own_message(self):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        port = sock.getsockname()[1]
        try:
            with patch("ztz.runners.proxy.classify_endpoint", return_value="ztz"), \
                 self.assertRaises(RuntimeError) as cm:
                assert_port_free("127.0.0.1", port, 11435)
            self.assertIn("ZTZ proxy is already running", str(cm.exception))
        finally:
            sock.close()

    def test_free_port_passes(self):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        assert_port_free("127.0.0.1", port, 11435)


class TestEndpointClassification(unittest.TestCase):
    def _serve(self, with_header):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                if with_header:
                    self.send_header(netcheck.PROXY_HEADER, "1")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server.server_address[1]

    def test_ztz_direct_and_closed(self):
        self.assertEqual(netcheck.classify_endpoint("127.0.0.1", self._serve(True)), "ztz")
        self.assertEqual(netcheck.classify_endpoint("127.0.0.1", self._serve(False)), "direct")
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        free = sock.getsockname()[1]
        sock.close()
        self.assertEqual(netcheck.classify_endpoint("127.0.0.1", free), "closed")


class TestOllamaModelStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.base = os.path.join(self.tmp, "models")
        self.blobs = os.path.join(self.base, "blobs")
        os.makedirs(self.blobs)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _model(self, name, tag, layers):
        """layers: [(media suffix, hex digest)]; writes blobs and the manifest."""
        manifest_dir = os.path.join(self.base, "manifests", "registry.ollama.ai", "library", name)
        os.makedirs(manifest_dir, exist_ok=True)
        entries = []
        for kind, digest in layers:
            with open(os.path.join(self.blobs, f"sha256-{digest}"), "wb") as f:
                f.write(GGUF + digest.encode())
            entries.append({"mediaType": f"application/vnd.ollama.image.{kind}", "digest": f"sha256:{digest}"})
        with open(os.path.join(manifest_dir, tag), "w") as f:
            json.dump({"layers": entries}, f)

    def test_projector_is_a_loadable_layer(self):
        self._model("vis", "latest", [("model", "aa" * 32), ("projector", "bb" * 32), ("license", "cc" * 32)])
        target = model_manager.resolve_model_target("vis", self.base)
        self.assertEqual([os.path.basename(p) for p in target["blob_paths"]],
                         [f"sha256-{'aa' * 32}", f"sha256-{'bb' * 32}"])

    def test_bare_name_means_latest_only(self):
        self._model("gemma4", "12b", [("model", "dd" * 32)])
        self.assertIsNone(model_manager.resolve_model_target("gemma4", self.base))
        self.assertIsNotNone(model_manager.resolve_model_target("gemma4:12b", self.base))

    def test_non_hex_digest_rejected(self):
        self._model("evil", "latest", [("model", "aa" * 32)])
        manifest = os.path.join(self.base, "manifests", "registry.ollama.ai", "library", "evil", "latest")
        with open(manifest, "w") as f:
            json.dump({"layers": [{"mediaType": "application/vnd.ollama.image.model",
                                   "digest": "sha256:../../../etc/passwd"}]}, f)
        self.assertIsNone(model_manager.parse_ollama_manifest_file(manifest, self.base))

    def test_ollama_app_models_setting_is_used(self):
        appdata = os.path.join(self.tmp, "appdata")
        os.makedirs(os.path.join(appdata, "Ollama"))
        db = sqlite3.connect(os.path.join(appdata, "Ollama", "db.sqlite"))
        db.execute("CREATE TABLE settings (id INTEGER, models TEXT)")
        db.execute("INSERT INTO settings VALUES (1, ?)", (self.base,))
        db.commit()
        db.close()
        env = {"LOCALAPPDATA": appdata}
        with patch.dict(os.environ, env), patch.object(model_manager.os, "name", "nt"):
            os.environ.pop("OLLAMA_MODELS", None)
            self.assertEqual(model_manager.get_ollama_base_dir(), self.base)


if __name__ == "__main__":
    unittest.main()
