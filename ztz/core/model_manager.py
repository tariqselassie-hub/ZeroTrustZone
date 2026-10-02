"""
Model Manager for ZeroTrustZone / ZTZ (ztz/core/model_manager.py).
Discovers local Ollama / LM Studio / GGUF models, parses OCI manifests,
checks attestation status, and performs one-command signing.
"""

import os
import json
import glob
from typing import List, Dict, Any, Optional

from ztz.core.crypto import ZTZSigner
from ztz.core.trust_store import TrustStore, find_private_key
from ztz.core.validator import PreFlightValidator
from ztz.core.model_inspector import ModelFormatInspector

def get_ollama_base_dir() -> str:
    """
    Resolves the base directory for Ollama models, respecting:
    1. OLLAMA_MODELS environment variable
    2. ~/.ollama/models
    3. %LOCALAPPDATA%/Ollama/models (Windows fallback)
    """
    env_dir = os.environ.get("OLLAMA_MODELS")
    if env_dir and os.path.exists(env_dir):
        return env_dir

    default_home = os.path.expanduser("~/.ollama/models")
    if os.path.exists(default_home):
        return default_home

    if os.name == "nt":
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            win_path = os.path.join(local_app_data, "Ollama", "models")
            if os.path.exists(win_path):
                return win_path

    return default_home

def parse_ollama_manifest_file(manifest_path: str, model_base_dir: str) -> Optional[Dict[str, Any]]:
    """Reads an Ollama manifest JSON and extracts the model layer blob path and digest."""
    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
    except Exception:
        return None

    layers = manifest.get("layers", [])
    model_digest = None
    model_size = 0
    for layer in layers:
        if layer.get("mediaType") == "application/vnd.ollama.image.model":
            model_digest = layer.get("digest")
            model_size = layer.get("size", 0)
            break

    if not model_digest or not model_digest.startswith("sha256:"):
        return None

    hash_val = model_digest.split(":")[1]
    blob_path = os.path.join(model_base_dir, "blobs", f"sha256-{hash_val}")
    return {
        "digest": model_digest,
        "blob_path": blob_path,
        "blob_exists": os.path.exists(blob_path),
        "size_bytes": os.path.getsize(blob_path) if os.path.exists(blob_path) else model_size,
    }

def discover_ollama_models(model_base_dir: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Discovers all models registered in Ollama manifest directory.
    Returns a list of model records with paths, digests, signature status, and container safety.
    """
    base_dir = model_base_dir or get_ollama_base_dir()
    manifests_dir = os.path.join(base_dir, "manifests")
    if not os.path.isdir(manifests_dir):
        return []

    models = []
    trust_store = TrustStore()
    validator = PreFlightValidator(trust_store, use_cache=True)

    for root, _, files in os.walk(manifests_dir):
        for file in files:
            full_manifest_path = os.path.join(root, file)
            # Reconstruct model tag from relative path
            # e.g. manifests/registry.ollama.ai/library/llama3/latest -> llama3:latest
            # or manifests/deepseek-r1/latest -> deepseek-r1:latest
            rel = os.path.relpath(full_manifest_path, manifests_dir)
            parts = rel.replace("\\", "/").split("/")
            
            if "library" in parts:
                idx = parts.index("library")
                tag_parts = parts[idx + 1:]
            elif len(parts) >= 2:
                tag_parts = parts[-2:]
            else:
                tag_parts = parts

            tag = ":".join(tag_parts) if len(tag_parts) == 2 else "/".join(tag_parts)

            info = parse_ollama_manifest_file(full_manifest_path, base_dir)
            if not info:
                continue

            blob_path = info["blob_path"]
            sig_path = f"{blob_path}.sig"
            has_sig = os.path.exists(sig_path)
            
            status = "UNSIGNED"
            attestation_details = {}
            if info["blob_exists"] and has_sig:
                attest = validator.validate_file(blob_path, sig_path=sig_path)
                status = attest.get("status", "FAILED")
                attestation_details = attest

            # Model safety check
            format_name = "UNKNOWN"
            is_safe = False
            if info["blob_exists"]:
                try:
                    insp = ModelFormatInspector.inspect(blob_path)
                    format_name = insp.format
                    is_safe = insp.is_safe_format
                except Exception:
                    pass

            models.append({
                "name": tag,
                "manifest_path": full_manifest_path,
                "blob_path": blob_path,
                "exists": info["blob_exists"],
                "size_bytes": info["size_bytes"],
                "digest": info["digest"],
                "sig_path": sig_path,
                "has_sig": has_sig,
                "status": status,
                "format": format_name,
                "is_safe_container": is_safe,
                "attestation": attestation_details,
            })

    return models

def resolve_model_target(model_name: str, model_base_dir: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Resolves a model name (e.g. 'llama3.2', 'llama3:latest', or a direct file path)
    to its physical file path on disk.
    """
    # 1. Direct path check
    if os.path.exists(model_name):
        return {
            "name": os.path.basename(model_name),
            "blob_path": os.path.abspath(model_name),
            "exists": True,
            "size_bytes": os.path.getsize(model_name),
            "sig_path": f"{os.path.abspath(model_name)}.sig",
            "has_sig": os.path.exists(f"{os.path.abspath(model_name)}.sig"),
        }

    # 2. Ollama manifest search
    base_dir = model_base_dir or get_ollama_base_dir()
    search_tag = model_name if ":" in model_name else f"{model_name}:latest"
    all_models = discover_ollama_models(base_dir)
    
    for m in all_models:
        if m["name"] == search_tag or m["name"].lower() == search_tag.lower():
            return m
        # Also match if user passed just the repo name e.g. "llama3" and model name is "llama3:latest"
        if m["name"].split(":")[0].lower() == model_name.lower():
            return m

    return None

def sign_model_target(
    model_name: str,
    private_key_path: Optional[str] = None,
    model_base_dir: Optional[str] = None
) -> Dict[str, Any]:
    """
    Signs a model (by name or file path) using the authority private key.
    Automatically generates and stores the detached .sig alongside the model weight.
    """
    target = resolve_model_target(model_name, model_base_dir)
    if not target:
        raise FileNotFoundError(f"Model '{model_name}' could not be located on disk or in Ollama repository.")

    blob_path = target["blob_path"]
    if not os.path.exists(blob_path):
        raise FileNotFoundError(f"Physical model blob missing at: {blob_path}")

    # Locate private key
    resolved_key = find_private_key(private_key_path)
    if not resolved_key:
        raise FileNotFoundError(
            "No private signing key found. Please run 'ztz init' or provide --key <path>."
        )

    signer = ZTZSigner(resolved_key)
    sig_path = signer.sign_file(blob_path)

    return {
        "name": target.get("name", os.path.basename(blob_path)),
        "blob_path": blob_path,
        "sig_path": sig_path,
        "signer_key": resolved_key,
        "size_bytes": target.get("size_bytes", os.path.getsize(blob_path)),
        "status": "SIGNED",
    }
