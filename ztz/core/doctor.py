"""
Diagnostics & System Health Sentinel for ZeroTrustZone (ztz/core/doctor.py).
Evaluates crypto backends, trust stores, model directories, runtime daemons,
and attestation cache health.
"""

import os
import sys
import platform
import socket
import urllib.request
from typing import Dict, Any, List

from ztz.core.trust_store import TrustStore, DEFAULT_SEARCH_PATHS, find_private_key
from ztz.core.model_manager import get_ollama_base_dir, discover_ollama_models
from ztz.lic.fingerprint import HardwareFingerprint
from ztz.core.context_shield import SECRET_PATTERNS
from ztz.core.cache import AttestationCache

def check_socket_port(host: str, port: int, timeout: float = 0.5) -> bool:
    """Checks if a TCP port is actively listening locally."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False

def run_diagnostics() -> Dict[str, Any]:
    """Runs full-system diagnostics and returns health checks."""
    checks = {}

    # 1. Environment & Platform
    checks["platform"] = {
        "os": platform.system(),
        "release": platform.release(),
        "arch": platform.machine(),
        "python_version": sys.version.split()[0],
        "is_64bit": sys.maxsize > 2**32,
    }

    # 2. Cryptographic Engine
    try:
        import cryptography
        crypto_ver = cryptography.__version__
        crypto_ok = True
    except Exception as e:
        crypto_ver = str(e)
        crypto_ok = False

    try:
        hw_fp = HardwareFingerprint.compute_fingerprint()
        hw_ok = True
    except Exception:
        hw_fp = "UNAVAILABLE"
        hw_ok = False

    checks["crypto"] = {
        "ok": crypto_ok and hw_ok,
        "cryptography_version": crypto_ver,
        "hardware_fingerprint": hw_fp,
    }

    # 3. Trust Stores & Authorities
    ts = TrustStore()
    authorities = ts.list_authorities()
    priv_key = find_private_key()
    
    searched_stores = []
    for p in DEFAULT_SEARCH_PATHS:
        searched_stores.append({
            "path": p,
            "exists": os.path.isdir(p),
        })

    checks["trust_store"] = {
        "ok": len(authorities) > 0,
        "loaded_authorities_count": len(authorities),
        "authorities": [a["name"] for a in authorities],
        "searched_paths": searched_stores,
        "default_signing_key": priv_key,
        "can_sign": priv_key is not None,
    }

    # 4. Ollama Runtime & Models
    ollama_dir = get_ollama_base_dir()
    ollama_dir_exists = os.path.isdir(ollama_dir)
    ollama_port_active = check_socket_port("127.0.0.1", 11434)
    
    discovered_models = []
    if ollama_dir_exists:
        try:
            discovered_models = discover_ollama_models(ollama_dir)
        except Exception:
            pass

    checks["ollama"] = {
        "directory": ollama_dir,
        "directory_exists": ollama_dir_exists,
        "service_online": ollama_port_active,
        "models_count": len(discovered_models),
        "signed_models_count": sum(1 for m in discovered_models if m.get("has_sig")),
    }

    # 5. Pre-Flight Attestation Cache
    cache_path = os.path.expanduser("~/.ztz/attestation_cache.db")
    cache_exists = os.path.exists(cache_path)
    cache_entries = 0
    cache_size_kb = 0
    if cache_exists:
        try:
            cache = AttestationCache(cache_path)
            cur = cache.conn.cursor()
            cur.execute("SELECT COUNT(*) FROM attestation_records")
            row = cur.fetchone()
            cache_entries = row[0] if row else 0
            cache_size_kb = round(os.path.getsize(cache_path) / 1024, 2)
        except Exception:
            pass

    checks["cache"] = {
        "path": cache_path,
        "exists": cache_exists,
        "records": cache_entries,
        "size_kb": cache_size_kb,
    }

    # 6. Context Shield Engine
    checks["context_shield"] = {
        "active_rules_count": len(SECRET_PATTERNS),
        "rules": [p[0] for p in SECRET_PATTERNS],
    }

    # Overall verdict
    is_ready = checks["crypto"]["ok"] and checks["trust_store"]["ok"]
    checks["verdict"] = "READY" if is_ready else "SETUP_RECOMMENDED"

    return checks
