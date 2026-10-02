"""
UserShield / ZTZ Initializer and Quickstart Setup (ztz/core/setup.py).
Sets up global configuration, trust store, and default Root Authority keypair.
"""

import os
import json
from typing import Dict, Any, Tuple
from ztz.core.crypto import generate_keypair
from ztz.core.trust_store import DEFAULT_USERSHIELD_STORE, TrustStore

USERSHIELD_HOME = os.path.expanduser("~/.usershield")
CONFIG_PATH = os.path.join(USERSHIELD_HOME, "config.json")

def init_environment(force: bool = False, key_type: str = "ed25519") -> Dict[str, Any]:
    """
    Initializes the local UserShield environment:
    - Creates ~/.usershield/keys
    - Generates an authority keypair if not present
    - Initializes ~/.usershield/config.json
    """
    os.makedirs(USERSHIELD_HOME, exist_ok=True)
    os.makedirs(DEFAULT_USERSHIELD_STORE, exist_ok=True)

    priv_key_path = os.path.join(DEFAULT_USERSHIELD_STORE, "authority_priv.pem")
    pub_key_path = os.path.join(DEFAULT_USERSHIELD_STORE, "authority_pub.pem")

    keys_created = False
    if force or not os.path.exists(priv_key_path) or not os.path.exists(pub_key_path):
        priv_key_path, pub_key_path = generate_keypair(
            key_type=key_type,
            out_dir=DEFAULT_USERSHIELD_STORE,
            name="authority",
        )
        keys_created = True

    # Initialize or update config
    config = {
        "version": "1.0",
        "default_trust_store": DEFAULT_USERSHIELD_STORE,
        "default_key": priv_key_path,
        "auto_protect_ollama": True,
        "use_instant_cache": True,
    }
    if not os.path.exists(CONFIG_PATH) or force:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)

    trust_store = TrustStore()

    return {
        "home_dir": USERSHIELD_HOME,
        "keys_dir": DEFAULT_USERSHIELD_STORE,
        "config_path": CONFIG_PATH,
        "private_key": priv_key_path,
        "public_key": pub_key_path,
        "keys_created": keys_created,
        "authorities_count": len(trust_store.list_authorities()),
    }
