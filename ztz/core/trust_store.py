"""
Local Trust Store manager for ZTZ.
Loads and caches pre-loaded public roots of trust from local unprivileged paths.
"""

import os
import glob
from typing import Dict, Any, List
from cryptography.hazmat.primitives import serialization

DEFAULT_ZTZ_STORE = os.path.expanduser("~/.ztz/keys")
DEFAULT_ZEROTRUSTZONE_STORE = os.path.expanduser("~/.zerotrustzone/keys")
DEFAULT_USER_STORE = os.path.expanduser("~/.ztz/trusted_keys")
DEFAULT_LOCAL_STORE = "./keys"
DEFAULT_SEARCH_PATHS = [DEFAULT_LOCAL_STORE, DEFAULT_ZTZ_STORE, DEFAULT_ZEROTRUSTZONE_STORE, DEFAULT_USER_STORE]

def get_default_key_dir() -> str:
    """Returns the primary directory for storing keys (~/.ztz/keys)."""
    return DEFAULT_ZTZ_STORE

def find_private_key(preferred_path: str = None, name: str = "authority") -> str:
    """
    Attempts to locate a private signing key:
    1. preferred_path (if provided and exists)
    2. ./keys/{name}_priv.pem
    3. ~/.ztz/keys/{name}_priv.pem
    4. ~/.zerotrustzone/keys/{name}_priv.pem
    5. ~/.ztz/trusted_keys/{name}_priv.pem
    """
    if preferred_path and os.path.exists(preferred_path):
        return preferred_path
    
    candidates = [
        os.path.join(DEFAULT_LOCAL_STORE, f"{name}_priv.pem"),
        os.path.join(DEFAULT_LOCAL_STORE, f"{name}.pem"),
        os.path.join(DEFAULT_ZTZ_STORE, f"{name}_priv.pem"),
        os.path.join(DEFAULT_ZTZ_STORE, f"{name}.pem"),
        os.path.join(DEFAULT_ZEROTRUSTZONE_STORE, f"{name}_priv.pem"),
        os.path.join(DEFAULT_ZEROTRUSTZONE_STORE, f"{name}.pem"),
        os.path.join(DEFAULT_USER_STORE, f"{name}_priv.pem"),
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return None

class TrustStore:
    def __init__(self, search_paths: List[str] = None):
        if search_paths is None:
            self.search_paths = list(DEFAULT_SEARCH_PATHS)
        elif isinstance(search_paths, str):
            self.search_paths = [search_paths]
        else:
            # Filter out None and ensure fallback paths are available if specified paths don't exist
            filtered = [p for p in search_paths if p]
            if not filtered:
                self.search_paths = list(DEFAULT_SEARCH_PATHS)
            else:
                self.search_paths = filtered
        self.authorities: Dict[str, Any] = {}
        self.reload()

    def reload(self):
        """Scans search paths and loads all valid public keys."""
        self.authorities.clear()
        for path in self.search_paths:
            if not os.path.isdir(path):
                continue
            for ext in ("*.pub.pem", "*_pub.pem", "*.pem"):
                for key_file in glob.glob(os.path.join(path, ext)):
                    # Avoid loading private keys by naming convention
                    if "priv" in os.path.basename(key_file):
                        continue
                    authority_name = os.path.basename(key_file).split(".")[0].replace("_pub", "")
                    try:
                        with open(key_file, "rb") as kf:
                            key_data = kf.read()
                            pub_key = serialization.load_pem_public_key(key_data)
                            self.authorities[authority_name] = {
                                "name": authority_name,
                                "path": key_file,
                                "key": pub_key,
                            }
                    except Exception:
                        continue

    def get_authority(self, name: str) -> Any:
        return self.authorities.get(name)

    def list_authorities(self) -> List[Dict[str, Any]]:
        return list(self.authorities.values())
