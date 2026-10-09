"""
Ollama / LM Studio API Reverse Proxy for ZTZ.
Intercepts local inference traffic to cryptographically verify models before allowing execution.
"""

import os
import json
import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from aiohttp import web, ClientSession, ClientTimeout
from ztz.core.validator import PreFlightValidator
from ztz.core.trust_store import TrustStore
from ztz.core.context_shield import ContextShield, ContextAuditResult, EnclaveSeal
from ztz.core.model_manager import get_ollama_base_dir

logger = logging.getLogger(__name__)

# Hop-by-hop headers (RFC 9110 section 7.6.1) plus framing headers aiohttp recomputes itself.
# Content-Encoding is dropped because aiohttp transparently decompresses upstream bodies.
_STRIP_RESPONSE_HEADERS = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade",
    "content-length", "content-encoding",
})
_STRIP_REQUEST_HEADERS = frozenset({"host", "content-length", "transfer-encoding", "connection"})

class InferenceProxy:
    def __init__(self, trust_store: TrustStore, upstream_host: str = "127.0.0.1", upstream_port: int = 11435, use_cache: bool = True):
        self.trust_store = trust_store
        self.validator = PreFlightValidator(self.trust_store, use_cache=use_cache)
        self.upstream_url = f"http://{upstream_host}:{upstream_port}"
        self.use_cache = use_cache
        
        self.model_base_dir = get_ollama_base_dir()
        
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
            return web.json_response({"error": "Upstream backend unreachable"}, status=502)

    def _parse_ollama_manifest(self, model_name: str) -> str:
        """
        Parses Ollama OCI manifests to resolve logical models (e.g. llama3:latest) 
        to their underlying physical sha256 blob on disk.
        """
        # Default to latest if no tag provided
        if ":" not in model_name:
            model_name += ":latest"
            
        repo, tag = model_name.split(":", 1)
        
        # In Ollama, models pulled without a namespace go to registry.ollama.ai/library/
        # Check standard library path first, then exact path
        manifest_paths = [
            os.path.join(self.model_base_dir, "manifests", "registry.ollama.ai", "library", repo, tag),
            os.path.join(self.model_base_dir, "manifests", repo, tag)
        ]
        
        target_manifest = None
        for path in manifest_paths:
            if os.path.exists(path):
                target_manifest = path
                break
                
        if not target_manifest:
            return None
            
        try:
            with open(target_manifest, "r") as f:
                manifest = json.load(f)
                
            # Find the layer that represents the actual model weight (GGUF)
            for layer in manifest.get("layers", []):
                if layer.get("mediaType") == "application/vnd.ollama.image.model":
                    digest = layer.get("digest")
                    if digest and digest.startswith("sha256:"):
                        hash_val = digest.split(":")[1]
                        blob_path = os.path.join(self.model_base_dir, "blobs", f"sha256-{hash_val}")
                        if os.path.exists(blob_path):
                            return blob_path
        except Exception as e:
            logger.warning(f"Failed to parse Ollama manifest for {model_name}: {e}")
            
        return None

    def _resolve_model_path(self, model_name: str) -> str:
        if model_name.endswith(".gguf") and os.path.exists(model_name):
            return model_name
            
        # Attempt OCI Manifest resolution
        blob_path = self._parse_ollama_manifest(model_name)
        if blob_path:
            return blob_path
            
        # Fallback
        return model_name

    @staticmethod
    def _stat_key(path: str):
        try:
            st = os.stat(path)
        except OSError:
            return None
        return (st.st_ino, st.st_size, st.st_mtime_ns)

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

    async def handle_inference_request(self, request: web.Request) -> web.Response:
        try:
            body = await request.json()
        except Exception:
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
                print(f"[\033[93mQUENCH\033[0m] Neutralized {redactions} secret(s) in prompt before inference.")
        elif "messages" in body and isinstance(body["messages"], list):
            clean_msgs, findings, total_redacted, seal = ContextShield.seal_messages(body["messages"])
            body["messages"] = clean_msgs
            redactions = total_redacted
            attestation_headers["X-ZTZ-Enclave-Seal"] = seal.mode
            attestation_headers["X-ZTZ-Enclave-Status"] = seal.status
            if redactions > 0:
                print(f"[\033[93mQUENCH\033[0m] Neutralized {redactions} secret(s) across messages before inference.")

        sanitized_data = json.dumps(body).encode("utf-8")

        model_name = body.get("model")
        if not model_name:
            return await self._proxy_request(request, data_override=sanitized_data, extra_headers=attestation_headers)
            
        model_path = self._resolve_model_path(model_name)
        
        if not os.path.exists(model_path):
            print(f"[\033[91mBLOCK\033[0m] Model file not found on disk: {model_path}")
            return web.json_response({"error": "ZTZ: Model binary not found on local disk."}, status=404)
            
        # 1. Ultra-fast L1 In-Memory Cache (Sub-millisecond)
        if self._check_memory_cache(model_path):
            return await self._proxy_request(request, data_override=sanitized_data, extra_headers=attestation_headers)
            
        print(f"\n[ZTZ Proxy] Cold check for model: '{model_name}'")
        print(f"[ZTZ Proxy] Target physical file: {model_path}")
            
        # 2. L2 SQLite Cache / L3 Cryptographic Stream
        row = await asyncio.get_running_loop().run_in_executor(
            self._validation_pool, self.validator.validate_file, model_path
        )

        if row["status"] not in ("VERIFIED", "VERIFIED_CACHE"):
            print(f"[\033[91mBLOCK\033[0m] Cryptographic signature invalid or missing for {model_name}!")
            print(f"  Reason: {row.get('error', 'Unknown')}")
            return web.json_response({
                "error": "ZTZ Security Lockdown",
                "message": f"Model '{model_name}' failed cryptographic attestation. Execution blocked.",
                "details": row
            }, status=403)
            
        print(f"[\033[92mPASS\033[0m] Model attested. Forwarding request to {self.upstream_url}...")
        
        # Populate L1 cache on pass
        self._update_memory_cache(model_path)
        
        return await self._proxy_request(request, data_override=sanitized_data, extra_headers=attestation_headers)

    async def passthrough(self, request: web.Request) -> web.Response:
        return await self._proxy_request(request)

def run_proxy(host: str = "127.0.0.1", port: int = 11434, upstream_port: int = 11435, trust_store_path: str = None, use_cache: bool = True):
    trust_store = TrustStore([trust_store_path] if trust_store_path else None)
    proxy = InferenceProxy(trust_store, upstream_port=upstream_port, use_cache=use_cache)
    
    app = web.Application()
    app.on_startup.append(proxy.on_startup)
    app.on_cleanup.append(proxy.on_cleanup)

    # Native Ollama / LocalAI
    app.router.add_post("/api/generate", proxy.handle_inference_request)
    app.router.add_post("/api/chat", proxy.handle_inference_request)
    
    # OpenAI-Compatible Routes
    app.router.add_post("/v1/chat/completions", proxy.handle_inference_request)
    app.router.add_post("/v1/completions", proxy.handle_inference_request)
    
    app.router.add_route("*", "/{tail:.*}", proxy.passthrough)
    
    print(f"\n🛡️  ZTZ Interceptor Proxy starting...")
    print(f"   Listening on: http://{host}:{port}")
    print(f"   Forwarding to: http://{host}:{upstream_port}\n")
    
    web.run_app(app, host=host, port=port, print=None)
