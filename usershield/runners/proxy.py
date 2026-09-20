"""
Ollama / LM Studio API Reverse Proxy for UserShield Pro.
Intercepts local inference traffic to cryptographically verify models before allowing execution.
"""

import os
import json
import logging
from aiohttp import web, ClientSession
from usershield.core.validator import PreFlightValidator
from usershield.core.trust_store import TrustStore

logger = logging.getLogger(__name__)

class InferenceProxy:
    def __init__(self, trust_store: TrustStore, upstream_host: str = "127.0.0.1", upstream_port: int = 11435):
        self.trust_store = trust_store
        self.validator = PreFlightValidator(self.trust_store)
        self.upstream_url = f"http://{upstream_host}:{upstream_port}"
        
        # Simplified Ollama local mapping for prototyping
        # In a real environment, this would parse ~/.ollama/models/manifests
        self.model_dir = os.path.expanduser("~/.ollama/models/blobs")
        
    async def _proxy_request(self, request: web.Request) -> web.StreamResponse:
        """Forward the request to the real backend and stream the response back."""
        async with ClientSession() as session:
            # Read payload and headers
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
                    async for chunk in backend_resp.content.iter_chunked(4096):
                        await proxy_resp.write(chunk)
                    return proxy_resp
            except Exception as e:
                logger.error(f"Proxy upstream error: {e}")
                return web.json_response({"error": "Upstream backend unreachable"}, status=502)

    def _resolve_model_path(self, model_name: str) -> str:
        """
        Maps a model name (e.g. 'llama3') to its physical blob/GGUF file on disk.
        For the sake of this implementation, we will look for a local `.gguf` file matching the name,
        or simulate the lookup.
        """
        if model_name.endswith(".gguf") and os.path.exists(model_name):
            return model_name
            
        simulated_path = os.path.join(self.model_dir, f"{model_name}.gguf")
        if os.path.exists(simulated_path):
            return simulated_path
            
        return model_name

    async def handle_inference_request(self, request: web.Request) -> web.Response:
        """
        Intercepts /api/generate or /api/chat. 
        Extracts the requested model, verifies it, and forwards if valid.
        """
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON"}, status=400)
            
        model_name = body.get("model")
        if not model_name:
            return await self._proxy_request(request)
            
        model_path = self._resolve_model_path(model_name)
        
        print(f"\n[UserShield Proxy] Intercepted request for model: '{model_name}'")
        print(f"[UserShield Proxy] Target physical file: {model_path}")
        
        if not os.path.exists(model_path):
            print(f"[\033[91mBLOCK\033[0m] Model file not found on disk: {model_path}")
            return web.json_response({"error": "UserShield: Model binary not found on local disk."}, status=404)
            
        row = self.validator.validate_file(model_path)
        
        if row["status"] != "VERIFIED":
            print(f"[\033[91mBLOCK\033[0m] Cryptographic signature invalid or missing for {model_name}!")
            print(f"  Reason: {row.get('error', 'Unknown')}")
            return web.json_response({
                "error": "UserShield Security Lockdown",
                "message": f"Model '{model_name}' failed cryptographic attestation. Execution blocked.",
                "details": row
            }, status=403)
            
        print(f"[\033[92mPASS\033[0m] Model attested. Forwarding request to {self.upstream_url}...")
        
        return await self._proxy_request(request)

    async def passthrough(self, request: web.Request) -> web.Response:
        """Passthrough for non-inference endpoints."""
        return await self._proxy_request(request)

def run_proxy(host: str = "127.0.0.1", port: int = 11434, upstream_port: int = 11435, trust_store_path: str = "./keys"):
    """Starts the UserShield AIOHTTP Reverse Proxy."""
    trust_store = TrustStore([trust_store_path] if trust_store_path else None)
    proxy = InferenceProxy(trust_store, upstream_port=upstream_port)
    
    app = web.Application()
    
    app.router.add_post("/api/generate", proxy.handle_inference_request)
    app.router.add_post("/api/chat", proxy.handle_inference_request)
    app.router.add_post("/v1/chat/completions", proxy.handle_inference_request)
    app.router.add_route("*", "/{tail:.*}", proxy.passthrough)
    
    print(f"\n🛡️  UserShield Pro Interceptor Proxy starting...")
    print(f"   Listening on: http://{host}:{port}")
    print(f"   Forwarding to: http://{host}:{upstream_port}\n")
    
    web.run_app(app, host=host, port=port, print=None)
