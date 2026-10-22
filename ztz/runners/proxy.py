"""
Ollama API Reverse Proxy for ZTZ.
Intercepts local inference traffic to cryptographically verify models before allowing execution.

Every file a model loads (weights, vision projector, LoRA adapters) is resolved by
asking the backend itself (`/api/show`), so ZTZ attests exactly what Ollama will
map into memory, wherever its models directory is.
"""

import os
import sys
import json
import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional, Tuple
from aiohttp import web, ClientSession, ClientTimeout
from ztz.core.validator import PreFlightValidator
from ztz.core.trust_store import TrustStore
from ztz.core.context_shield import ContextShield
from ztz.core.model_manager import parse_modelfile_paths
from ztz.core.netcheck import (
    HEALTH_PATH, PROXY_HEADER, classify_endpoint, listening_addresses, probe_hosts,
)

logger = logging.getLogger(__name__)

# Hop-by-hop headers (RFC 9110 section 7.6.1) plus framing headers aiohttp recomputes itself.
# Content-Encoding is dropped because aiohttp transparently decompresses upstream bodies.
_STRIP_RESPONSE_HEADERS = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade",
    "content-length", "content-encoding",
})
_STRIP_REQUEST_HEADERS = frozenset({"host", "content-length", "transfer-encoding", "connection"})

# Ollama endpoints that name a model without loading it into memory. Every other
# POST naming a model (generate, chat, embed, OpenAI-compatible routes, and any
# endpoint added later) is attested first.
_MANAGEMENT_PATHS = frozenset({
    "/api/show", "/api/pull", "/api/push", "/api/delete", "/api/copy", "/api/create",
})

_VERIFIED = ("VERIFIED", "VERIFIED_CACHE")


def _tag(color: str, text: str) -> str:
    """ANSI-coloured tag on a terminal, plain text in log files."""
    codes = {"red": "91", "green": "92", "yellow": "93"}
    stream = sys.stdout
    if stream is not None and hasattr(stream, "isatty") and stream.isatty():
        return f"\033[{codes[color]}m{text}\033[0m"
    return text


class InferenceProxy:
    def __init__(self, trust_store: TrustStore, upstream_host: str = "127.0.0.1", upstream_port: int = 11435, use_cache: bool = True):
        self.trust_store = trust_store
        self.validator = PreFlightValidator(self.trust_store, use_cache=use_cache)
        self.upstream_url = f"http://{upstream_host}:{upstream_port}"
        self.upstream_port = upstream_port
        self.use_cache = use_cache

        # In-memory cache to completely bypass SQLite latency on sub-millisecond hot loops
        # Maps model_path -> (model stat key, sig stat key)
        self._memory_cache = {}

        # Single worker: keeps SHA-256 streaming off the event loop and serializes
        # access to the validator's SQLite connection.
        self._validation_pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="ztz-validate")
        self._session: ClientSession = None

    async def on_startup(self, app: web.Application):
        # No total timeout: streamed generations can legitimately run for minutes.
        self._session = ClientSession(timeout=ClientTimeout(total=None, sock_connect=10))

    async def on_cleanup(self, app: web.Application):
        if self._session:
            await self._session.close()
        self._validation_pool.shutdown(wait=False)
        self.validator.close()

    @staticmethod
    async def mark_response(request: web.Request, response: web.StreamResponse):
        # Lets `ztz doctor` tell the proxy apart from a backend on the same port.
        response.headers[PROXY_HEADER] = "1"

    async def health(self, request: web.Request) -> web.Response:
        """Answered locally, so probes get a fast reply whether or not the backend is up."""
        return web.json_response({"status": "ok", "upstream_port": self.upstream_port})

    def _backend_offline(self) -> str:
        return (f"Backend not reachable at {self.upstream_url}. Start Ollama there "
                f"(OLLAMA_HOST=127.0.0.1:{self.upstream_port}) and retry.")

    async def _proxy_request(self, request: web.Request, data_override: bytes = None, extra_headers: dict = None) -> web.StreamResponse:
        """Forward the request to the real backend and stream the response back natively."""
        data = data_override if data_override is not None else await request.read()
        headers = {k: v for k, v in request.headers.items() if k.lower() not in _STRIP_REQUEST_HEADERS}
        if extra_headers:
            headers.update(extra_headers)

        proxy_resp = None
        try:
            async with self._session.request(
                method=request.method,
                url=f"{self.upstream_url}{request.path_qs}",
                headers=headers,
                data=data
            ) as backend_resp:
                resp_headers = {
                    k: v for k, v in backend_resp.headers.items()
                    if k.lower() not in _STRIP_RESPONSE_HEADERS
                }
                proxy_resp = web.StreamResponse(status=backend_resp.status, headers=resp_headers)
                await proxy_resp.prepare(request)

                # Use iter_any() to instantly forward chunks without buffering, crucial for terminal streaming
                async for chunk in backend_resp.content.iter_any():
                    await proxy_resp.write(chunk)
                await proxy_resp.write_eof()
                return proxy_resp
        except Exception as e:
            logger.error(f"Proxy upstream error: {e}")
            if proxy_resp is not None and proxy_resp.prepared:
                # Headers already sent; can't switch to a 502 mid-stream.
                return proxy_resp
            return web.json_response(
                {"error": "Upstream backend unreachable", "message": self._backend_offline()}, status=502
            )

    async def _resolve_model_files(self, model_name: str) -> Tuple[List[str], Optional[str], int]:
        """
        Asks the backend which files model_name loads (FROM / ADAPTER lines of its
        modelfile). Returns (paths, error, http_status). Fails closed: anything the
        backend cannot pin to local files is refused.
        """
        try:
            async with self._session.post(
                f"{self.upstream_url}/api/show",
                json={"model": model_name},
                timeout=ClientTimeout(total=30),
            ) as resp:
                if resp.status == 404:
                    return [], f"Model '{model_name}' is not installed in the backend.", 404
                if resp.status != 200:
                    return [], f"Backend could not describe model '{model_name}' (HTTP {resp.status}).", 502
                info = await resp.json(content_type=None)
        except Exception as e:
            return [], f"{self._backend_offline()} ({e})", 502

        paths = parse_modelfile_paths((info or {}).get("modelfile") or "")
        if not paths:
            return [], (f"Model '{model_name}' has no local weight files (remote or cloud model); "
                        "it cannot be attested."), 403
        return paths, None, 200

    @staticmethod
    def _stat_key(path: str):
        try:
            st = os.stat(path)
        except OSError:
            return None
        return (st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)

    def _memory_cache_key(self, model_path: str):
        # Covers the detached .sig too: swapping or deleting it must force a re-check.
        return (self._stat_key(model_path), self._stat_key(f"{model_path}.sig"))

    def _check_memory_cache(self, model_path: str) -> bool:
        if not self.use_cache:
            return False

        cached = self._memory_cache.get(model_path)
        if cached is None:
            return False

        current = self._memory_cache_key(model_path)
        if None not in current and current == cached:
            return True

        # Invalidate if metadata drift
        del self._memory_cache[model_path]
        return False

    def _update_memory_cache(self, model_path: str):
        if not self.use_cache:
            return
        key = self._memory_cache_key(model_path)
        if None not in key:
            self._memory_cache[model_path] = key

    async def _attest_model(self, model_name: str) -> Optional[web.Response]:
        """None if every file model_name loads is attested, else the refusal to send."""
        paths, error, status = await self._resolve_model_files(model_name)
        if error:
            print(f"[{_tag('red', 'BLOCK')}] {error}")
            return web.json_response({"error": "ZTZ Security Lockdown", "message": error}, status=status)

        for model_path in paths:
            # 1. Ultra-fast L1 In-Memory Cache (Sub-millisecond)
            if self._check_memory_cache(model_path):
                continue

            print(f"\n[ZTZ Proxy] Cold check for model: '{model_name}'")
            print(f"[ZTZ Proxy] Target physical file: {model_path}")

            # 2. L2 SQLite Cache / L3 Cryptographic Stream
            row = await asyncio.get_running_loop().run_in_executor(
                self._validation_pool, self.validator.validate_file, model_path
            )
            if row["status"] not in _VERIFIED:
                print(f"[{_tag('red', 'BLOCK')}] Cryptographic signature invalid or missing for {model_name}!")
                print(f"  File  : {model_path}")
                print(f"  Reason: {row.get('error', 'Unknown')}")
                return web.json_response({
                    "error": "ZTZ Security Lockdown",
                    "message": f"Model '{model_name}' failed cryptographic attestation. Execution blocked.",
                    "details": row
                }, status=403)

            print(f"[{_tag('green', 'PASS')}] Model attested. Forwarding request to {self.upstream_url}...")
            # Populate L1 cache on pass
            self._update_memory_cache(model_path)
        return None

    async def handle_inference_request(self, request: web.Request, body: Optional[dict] = None) -> web.StreamResponse:
        if body is None:
            try:
                body = await request.json()
            except Exception:
                return web.json_response({"error": "Invalid JSON"}, status=400)
        if not isinstance(body, dict):
            return web.json_response({"error": "Invalid JSON"}, status=400)

        # Pre-Flight Context Attestation (Prompts / Messages)
        attestation_headers = {}
        redactions = 0
        if "prompt" in body and isinstance(body["prompt"], str):
            audit = ContextShield.seal_and_attest(body["prompt"])
            body["prompt"] = audit.clean_text
            redactions = audit.redactions_count
            attestation_headers["X-ZTZ-Digest"] = audit.digest_sha256
            if audit.seal:
                attestation_headers["X-ZTZ-Enclave-Seal"] = audit.seal.mode
                attestation_headers["X-ZTZ-Enclave-Status"] = audit.seal.status
            if redactions > 0:
                print(f"[{_tag('yellow', 'QUENCH')}] Neutralized {redactions} secret(s) in prompt before inference.")
        elif "messages" in body and isinstance(body["messages"], list):
            clean_msgs, findings, total_redacted, seal = ContextShield.seal_messages(body["messages"])
            body["messages"] = clean_msgs
            redactions = total_redacted
            attestation_headers["X-ZTZ-Enclave-Seal"] = seal.mode
            attestation_headers["X-ZTZ-Enclave-Status"] = seal.status
            if redactions > 0:
                print(f"[{_tag('yellow', 'QUENCH')}] Neutralized {redactions} secret(s) across messages before inference.")

        # /api/generate carries a separate system prompt next to the prompt.
        if isinstance(body.get("system"), str) and body["system"]:
            audit = ContextShield.sanitize(body["system"])
            body["system"] = audit.clean_text
            if audit.redactions_count > 0:
                print(f"[{_tag('yellow', 'QUENCH')}] Neutralized {audit.redactions_count} secret(s) in system prompt before inference.")

        sanitized_data = json.dumps(body).encode("utf-8")

        model_name = body.get("model")
        if model_name:
            if not isinstance(model_name, str):
                return web.json_response({"error": "Invalid model name"}, status=400)
            refusal = await self._attest_model(model_name)
            if refusal is not None:
                return refusal

        return await self._proxy_request(request, data_override=sanitized_data, extra_headers=attestation_headers)

    async def passthrough(self, request: web.Request) -> web.StreamResponse:
        # Any other POST that names a model may load it (embed, embeddings, responses,
        # future endpoints): attest it too. Only management endpoints pass untouched.
        if request.method == "POST" and request.path not in _MANAGEMENT_PATHS and request.can_read_body:
            raw = await request.read()
            try:
                body = json.loads(raw)
            except (ValueError, UnicodeDecodeError):
                body = None
            if isinstance(body, dict) and "model" in body:
                return await self.handle_inference_request(request, body=body)
        return await self._proxy_request(request)


def build_app(proxy: InferenceProxy) -> web.Application:
    app = web.Application()
    app.on_startup.append(proxy.on_startup)
    app.on_cleanup.append(proxy.on_cleanup)
    app.on_response_prepare.append(proxy.mark_response)

    # Native Ollama / LocalAI
    app.router.add_get(HEALTH_PATH, proxy.health)

    app.router.add_post("/api/generate", proxy.handle_inference_request)
    app.router.add_post("/api/chat", proxy.handle_inference_request)

    # OpenAI-Compatible Routes
    app.router.add_post("/v1/chat/completions", proxy.handle_inference_request)
    app.router.add_post("/v1/completions", proxy.handle_inference_request)

    app.router.add_route("*", "/{tail:.*}", proxy.passthrough)
    return app


def assert_port_free(host: str, port: int, upstream_port: int):
    """
    Refuses to start while anything already listens on port at a loopback (or the
    bind) address: clients resolving to that address would bypass ZTZ.
    """
    taken = listening_addresses(port, probe_hosts(host))
    if taken and all(classify_endpoint(h, port) == "ztz" for h in taken):
        raise RuntimeError(
            f"a ZTZ proxy is already running on port {port} ({', '.join(taken)}); "
            "stop it first (e.g. 'ztz service uninstall') or pick another --port."
        )
    if taken:
        raise RuntimeError(
            f"port {port} is already in use on {', '.join(taken)}. Clients reaching that "
            f"address would bypass ZTZ. Move the backend to the upstream port first "
            f"(Ollama: OLLAMA_HOST=127.0.0.1:{upstream_port}, and turn off "
            "'Expose Ollama to the network', which forces port 11434 on all addresses)."
        )


def run_proxy(host: str = "127.0.0.1", port: int = 11434, upstream_port: int = 11435, trust_store_path: str = None, use_cache: bool = True):
    assert_port_free(host, port, upstream_port)
    trust_store = TrustStore([trust_store_path] if trust_store_path else None)
    proxy = InferenceProxy(trust_store, upstream_port=upstream_port, use_cache=use_cache)
    app = build_app(proxy)

    print(f"\n🛡️  ZTZ Interceptor Proxy starting...")
    print(f"   Listening on: http://{host}:{port}")
    print(f"   Forwarding to: {proxy.upstream_url}\n")

    web.run_app(app, host=host, port=port, print=None)
