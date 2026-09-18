"""
Local Trust Store manager for UserShield.
Loads and caches pre-loaded public roots of trust from local unprivileged paths.
"""

import os
import glob
from typing import Dict, Any, List
from cryptography.hazmat.primitives import serialization

DEFAULT_USER_STORE = os.path.expanduser("~/.usershield/trusted_keys")
DEFAULT_LOCAL_STORE = "./keys"

class TrustStore:
    def __init__(self, search_paths: List[str] = None):
        if search_paths is None:
            self.search_paths = [DEFAULT_LOCAL_STORE, DEFAULT_USER_STORE]
        else:
            self.search_paths = search_paths
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
