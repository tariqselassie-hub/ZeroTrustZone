"""
Model Manager for ZeroTrustZone / ZTZ (ztz/core/model_manager.py).
Discovers local Ollama / GGUF models, parses OCI manifests,
checks attestation status, and performs one-command signing.
"""

import os
import json
import sqlite3
from typing import List, Dict, Any, Optional

from ztz.core.crypto import ZTZSigner
from ztz.core.trust_store import TrustStore, find_private_key
from ztz.core.validator import PreFlightValidator
from ztz.core.model_inspector import ModelFormatInspector

# Manifest layers Ollama loads into memory alongside (or as) the weights.
LOADABLE_LAYER_TYPES = (
    "application/vnd.ollama.image.model",
    "application/vnd.ollama.image.projector",
    "application/vnd.ollama.image.adapter",
)

def ollama_app_settings_db() -> Optional[str]:
    """The Ollama desktop app's settings database (Windows), if present."""
    if os.name == "nt" and os.environ.get("LOCALAPPDATA"):
        path = os.path.join(os.environ["LOCALAPPDATA"], "Ollama", "db.sqlite")
        if os.path.isfile(path):
            return path
    return None

def _ollama_app_models_dir() -> Optional[str]:
    """
    Models directory chosen in the Ollama desktop app's settings. The app passes it
    to `ollama serve` as OLLAMA_MODELS without exporting it, so other processes
    (ZTZ included) would otherwise fall back to ~/.ollama/models.
    """
    db = ollama_app_settings_db()
    if not db:
        return None
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=1)
        try:
            row = conn.execute("SELECT models FROM settings LIMIT 1").fetchone()
        finally:
            conn.close()
    except sqlite3.Error:
        return None
    path = row[0] if row else None
    return path if path and os.path.isdir(path) else None

def get_ollama_base_dir() -> str:
    """
    Resolves the base directory for Ollama models, respecting:
    1. OLLAMA_MODELS environment variable
    2. The Ollama desktop app's models setting (Windows)
    3. ~/.ollama/models
    4. %LOCALAPPDATA%/Ollama/models (Windows fallback)
    """
    env_dir = os.environ.get("OLLAMA_MODELS")
    if env_dir and os.path.exists(env_dir):
        return env_dir

    app_dir = _ollama_app_models_dir()
    if app_dir:
        return app_dir

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

def _blob_path(model_base_dir: str, digest: Any) -> Optional[str]:
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        return None
    hash_val = digest.split(":", 1)[1]
    if not hash_val or not all(c in "0123456789abcdef" for c in hash_val):
        return None  # never let a manifest steer the path outside blobs/
    return os.path.join(model_base_dir, "blobs", f"sha256-{hash_val}")

def parse_ollama_manifest_file(manifest_path: str, model_base_dir: str) -> Optional[Dict[str, Any]]:
    """
    Reads an Ollama manifest JSON. blob_path is the weights layer; blob_paths lists
    every layer Ollama loads (weights first, then projector / adapters), all of
    which must be signed.
    """
    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
    except Exception:
        return None

    loadable = []
    model_digest = None
    model_size = 0
    for layer in manifest.get("layers", []):
        media_type = layer.get("mediaType")
        if media_type not in LOADABLE_LAYER_TYPES:
            continue
        path = _blob_path(model_base_dir, layer.get("digest"))
        if path is None:
            return None
        if media_type == LOADABLE_LAYER_TYPES[0] and model_digest is None:
            model_digest = layer["digest"]
            model_size = layer.get("size", 0)
            loadable.insert(0, path)
        else:
            loadable.append(path)

    if model_digest is None:
        return None

    blob_path = loadable[0]
    return {
        "digest": model_digest,
        "blob_path": blob_path,
        "blob_paths": loadable,
        "blob_exists": all(os.path.exists(p) for p in loadable),
        "size_bytes": os.path.getsize(blob_path) if os.path.exists(blob_path) else model_size,
    }

_TRIPLE_QUOTE = '"' * 3

def parse_modelfile_paths(modelfile: str) -> List[str]:
    """
    Files an Ollama modelfile (from /api/show) loads: every FROM / ADAPTER line
    that names a local path (weights, projector, LoRA adapters). Commented lines
    and triple-quoted blocks (TEMPLATE, SYSTEM, LICENSE, MESSAGE) are skipped.
    A FROM naming another model (e.g. 'FROM llama3') is not a path and is ignored.
    """
    paths = []
    in_block = False
    for raw in modelfile.splitlines():
        line = raw.strip()
        opens_or_closes = line.count(_TRIPLE_QUOTE) % 2 == 1
        if in_block:
            in_block = not opens_or_closes
            continue
        if opens_or_closes:
            in_block = True
            continue
        if not line or line.startswith("#"):
            continue
        keyword, _, value = line.partition(" ")
        if keyword.upper() not in ("FROM", "ADAPTER"):
            continue
        value = value.strip().strip('"')
        if os.path.isabs(value) or value.startswith(("/", "\\")) or (len(value) > 2 and value[1] == ":"):
            paths.append(value)
    return paths

DEFAULT_REGISTRY = "registry.ollama.ai"
DEFAULT_NAMESPACE = "library"

def _short_repo(repo: List[str]) -> List[str]:
    """Drops the default registry and namespace, as Ollama does when it prints names."""
    if len(repo) >= 3 and repo[0].lower() == DEFAULT_REGISTRY:
        repo = repo[1:]
    if len(repo) >= 2 and repo[0].lower() == DEFAULT_NAMESPACE:
        repo = repo[1:]
    return repo

def manifest_model_name(parts: List[str]) -> str:
    """
    The name Ollama uses for the manifest at manifests/<parts...>:
      registry.ollama.ai/library/llama3/latest -> llama3:latest
      registry.ollama.ai/someuser/llama3/latest -> someuser/llama3:latest
      hf.co/bartowski/Qwen-GGUF/Q4_K_M -> hf.co/bartowski/Qwen-GGUF:Q4_K_M
    Keeping the namespace and host keeps two models that share a short name apart.
    """
    if len(parts) < 2:
        return "/".join(parts)
    *repo, tag = parts
    return "/".join(_short_repo(repo)) + ":" + tag

def normalize_model_name(name: str) -> str:
    """Ollama's reading of a user-typed name: ':latest' by default, default registry/namespace dropped."""
    repo, _, tag = name.rpartition(":") if ":" in name.rsplit("/", 1)[-1] else (name, "", "latest")
    return "/".join(_short_repo(repo.split("/"))).lower() + ":" + tag.lower()

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
    # Closed when done: the validator holds an SQLite connection to the cache.
    with PreFlightValidator(trust_store, use_cache=True) as validator:
        for root, _, files in os.walk(manifests_dir):
            for file in files:
                full_manifest_path = os.path.join(root, file)
                rel = os.path.relpath(full_manifest_path, manifests_dir)
                tag = manifest_model_name(rel.replace("\\", "/").split("/"))

                info = parse_ollama_manifest_file(full_manifest_path, base_dir)
                if not info:
                    continue

                blob_path = info["blob_path"]
                sig_path = f"{blob_path}.sig"
                # Every loaded layer (weights, projector, adapters) must carry a valid .sig.
                has_sig = all(os.path.exists(f"{p}.sig") for p in info["blob_paths"])

                status = "UNSIGNED"
                attestation_details = {}
                if info["blob_exists"] and has_sig:
                    for p in info["blob_paths"]:
                        attest = validator.validate_file(p)
                        status = attest.get("status", "FAILED")
                        attestation_details = attest
                        if status not in ("VERIFIED", "VERIFIED_CACHE"):
                            break

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
                    "blob_paths": info["blob_paths"],
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
            "blob_paths": [os.path.abspath(model_name)],
            "exists": True,
            "size_bytes": os.path.getsize(model_name),
            "sig_path": f"{os.path.abspath(model_name)}.sig",
            "has_sig": os.path.exists(f"{os.path.abspath(model_name)}.sig"),
        }

    # 2. Ollama manifest search. Same rule as Ollama: a bare name means ':latest';
    # never fall back to another tag, or ZTZ would sign a different model than
    # the one Ollama loads.
    base_dir = model_base_dir or get_ollama_base_dir()
    search_tag = normalize_model_name(model_name)
    for m in discover_ollama_models(base_dir):
        if m["name"].lower() == search_tag:
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
    blob_paths = target.get("blob_paths") or [blob_path]
    for p in blob_paths:
        if not os.path.exists(p):
            raise FileNotFoundError(f"Physical model blob missing at: {p}")

    # Locate private key
    resolved_key = find_private_key(private_key_path)
    if not resolved_key:
        raise FileNotFoundError(
            "No private signing key found. Please run 'ztz init' or provide --key <path>."
        )

    signer = ZTZSigner(resolved_key)
    sig_paths = [signer.sign_file(p) for p in blob_paths]

    return {
        "name": target.get("name", os.path.basename(blob_path)),
        "blob_path": blob_path,
        "blob_paths": blob_paths,
        "sig_path": sig_paths[0],
        "sig_paths": sig_paths,
        "signer_key": resolved_key,
        "size_bytes": target.get("size_bytes", os.path.getsize(blob_path)),
        "status": "SIGNED",
    }
