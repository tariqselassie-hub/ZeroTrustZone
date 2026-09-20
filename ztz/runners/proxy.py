"""
Ollama / LM Studio API Reverse Proxy for ZTZ Pro.
Intercepts local inference traffic to cryptographically verify models before allowing execution.
"""

import os
import json
import logging
from aiohttp import web, ClientSession
from ztz.core.validator import PreFlightValidator
from ztz.core.trust_store import TrustStore

logger = logging.getLogger(__name__)

class InferenceProxy:
    def __init__(self, trust_store: TrustStore, upstream_host: str = "127.0.0.1", upstream_port: int = 11435, use_cache: bool = True):
        self.trust_store = trust_store
        self.validator = PreFlightValidator(self.trust_store, use_cache=use_cache)
        self.upstream_url = f"http://{upstream_host}:{upstream_port}"
        self.use_cache = use_cache
        
        self.model_base_dir = os.path.expanduser("~/.ollama/models")
        
        # In-memory LRU cache to completely bypass SQLite latency on sub-millisecond hot loops
        # Maps absolute_path -> {"inode": x, "size": y, "mtime_ns": z, "status": "VERIFIED"}
        self._memory_cache = {}
        
    async def _proxy_request(self, request: web.Request) -> web.StreamResponse:
        """Forward the request to the real backend and stream the response back natively."""
        async with ClientSession() as session:
            data = await request.read()
            headers = {k: v for k, v in request.headers.items() if k.lower() != 'host'}
            
            try:
                async with session.request(
                    method=request.method,
                    url=f"{self.upstream_url}{request.path_qs}",
                    headers=headers,
                    data=data
                ) as backend_resp:
                    proxy_resp = web.StreamResponse(status=backend_resp.status,
                                                    headers=backend_resp.headers)
                    await proxy_resp.prepare(request)
                    
                    # Use iter_any() to instantly forward chunks without buffering, crucial for terminal streaming
                    async for chunk in backend_resp.content.iter_any():
                        await proxy_resp.write(chunk)
                    return proxy_resp
            except Exception as e:
                logger.error(f"Proxy upstream error: {e}")
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

    def _check_memory_cache(self, model_path: str) -> bool:
        if not self.use_cache:
            return False
            
        cached = self._memory_cache.get(model_path)
        if not cached:
            return False
            
        stat = os.stat(model_path)
        if stat.st_ino == cached["inode"] and stat.st_size == cached["size"] and stat.st_mtime_ns == cached["mtime_ns"]:
            return True
            
        # Invalidate if metadata drift
        del self._memory_cache[model_path]
        return False

    def _update_memory_cache(self, model_path: str):
        if not self.use_cache:
            return
        stat = os.stat(model_path)
        self._memory_cache[model_path] = {
            "inode": stat.st_ino,
            "size": stat.st_size,
            "mtime_ns": stat.st_mtime_ns,
            "status": "VERIFIED"
        }

    async def handle_inference_request(self, request: web.Request) -> web.Response:
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON"}, status=400)
            
        model_name = body.get("model")
        if not model_name:
            return await self._proxy_request(request)
            
        model_path = self._resolve_model_path(model_name)
        
        if not os.path.exists(model_path):
            print(f"[\033[91mBLOCK\033[0m] Model file not found on disk: {model_path}")
            return web.json_response({"error": "ZTZ: Model binary not found on local disk."}, status=404)
            
        # 1. Ultra-fast L1 In-Memory Cache (Sub-millisecond)
        if self._check_memory_cache(model_path):
            return await self._proxy_request(request)
            
        print(f"\n[ZTZ Proxy] Cold check for model: '{model_name}'")
        print(f"[ZTZ Proxy] Target physical file: {model_path}")
            
        # 2. L2 SQLite Cache / L3 Cryptographic Stream
        row = self.validator.validate_file(model_path)
        
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
        
        return await self._proxy_request(request)

    async def passthrough(self, request: web.Request) -> web.Response:
        return await self._proxy_request(request)

def run_proxy(host: str = "127.0.0.1", port: int = 11434, upstream_port: int = 11435, trust_store_path: str = "./keys", use_cache: bool = True):
    trust_store = TrustStore([trust_store_path] if trust_store_path else None)
    proxy = InferenceProxy(trust_store, upstream_port=upstream_port, use_cache=use_cache)
    
    app = web.Application()
    
    # Native Ollama / LocalAI
    app.router.add_post("/api/generate", proxy.handle_inference_request)
    app.router.add_post("/api/chat", proxy.handle_inference_request)
    
    # OpenAI-Compatible Routes
    app.router.add_post("/v1/chat/completions", proxy.handle_inference_request)
    app.router.add_post("/v1/completions", proxy.handle_inference_request)
    
    app.router.add_route("*", "/{tail:.*}", proxy.passthrough)
    
    print(f"\n🛡️  ZTZ Pro Interceptor Proxy starting...")
    print(f"   Listening on: http://{host}:{port}")
    print(f"   Forwarding to: http://{host}:{upstream_port}\n")
    
    web.run_app(app, host=host, port=port, print=None)
