"""
Air-Gapped License Manager for ZTZ Pro ($0.99 one-time / Enterprise).
Validates locally bound cryptographic license tokens (.lic) completely offline.
"""

import os
import json
import base64
from typing import Tuple, Dict, Any, Optional
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from ztz.lic.fingerprint import HardwareFingerprint

DEFAULT_LIC_PATHS = [
    "./ztz.lic",
    os.path.expanduser("~/.ztz/ztz.lic"),
]

# Public half of the vendor issuing key, shipped with the package. The private half
# lives only on the issuing machine (default ~/.ztz/vendor/vendor_priv.pem).
VENDOR_PUB_KEY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendor_pub.pem")
DEFAULT_VENDOR_PRIV_KEY_PATH = os.path.expanduser("~/.ztz/vendor/vendor_priv.pem")

def load_vendor_public_key(path: str = VENDOR_PUB_KEY_PATH) -> Optional[ed25519.Ed25519PublicKey]:
    try:
        with open(path, "rb") as f:
            key = serialization.load_pem_public_key(f.read())
    except (OSError, ValueError):
        return None
    return key if isinstance(key, ed25519.Ed25519PublicKey) else None

def _canonical(license_id, tier, machine_fingerprint, issued_at) -> bytes:
    return f"{license_id}:{tier}:{machine_fingerprint}:{issued_at}".encode("utf-8")

class LicenseManager:
    def __init__(self, vendor_pub_key: Optional[ed25519.Ed25519PublicKey] = None, custom_lic_path: Optional[str] = None):
        # Default to the embedded vendor key; a license is never accepted unsigned.
        self.vendor_pub_key = vendor_pub_key or load_vendor_public_key()
        self.custom_lic_path = custom_lic_path

    def locate_license_file(self) -> Optional[str]:
        if self.custom_lic_path and os.path.exists(self.custom_lic_path):
            return self.custom_lic_path
        for path in DEFAULT_LIC_PATHS:
            if os.path.exists(path):
                return path
        return None

    def verify_license(self) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Performs 100% offline verification of machine-bound license file.
        Returns (is_valid, status_message, license_metadata).
        """
        lic_file = self.locate_license_file()
        if not lic_file:
            return False, "No license file found. Operating in Community Mode.", {}

        try:
            with open(lic_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            return False, f"Malformed license file: {e}", {}

        required_keys = ("license_id", "tier", "machine_fingerprint", "signature")
        if not all(k in data for k in required_keys):
            return False, "License file missing mandatory cryptographic attributes", data

        # Check Hardware Fingerprint match
        current_fp = HardwareFingerprint.compute_fingerprint()
        stored_fp = data["machine_fingerprint"]
        if current_fp != stored_fp:
            return False, "Hardware fingerprint mismatch. License bound to different physical host.", data

        if self.vendor_pub_key is None:
            return False, "No vendor public key available; cannot authenticate license.", data

        try:
            sig_bytes = bytes.fromhex(data["signature"])
            self.vendor_pub_key.verify(
                sig_bytes,
                _canonical(data["license_id"], data["tier"], data["machine_fingerprint"], data.get("issued_at", 0)),
            )
        except InvalidSignature:
            return False, "Cryptographic vendor signature invalid or license forged.", data
        except Exception as e:
            return False, f"Signature verification error: {e}", data

        tier = data.get("tier", "pro").upper()
        return True, f"ZTZ {tier} verified for this host.", data

    @staticmethod
    def issue_token(
        license_id: str,
        tier: str,
        machine_fingerprint: str,
        issued_at: int,
        vendor_priv_key: ed25519.Ed25519PrivateKey,
    ) -> Dict[str, Any]:
        """
        Administrative issuance utility: signs machine fingerprint with vendor key.
        """
        signature = vendor_priv_key.sign(_canonical(license_id, tier, machine_fingerprint, issued_at))

        token = {
            "license_id": license_id,
            "tier": tier,
            "machine_fingerprint": machine_fingerprint,
            "issued_at": issued_at,
            "signature": signature.hex(),
        }
        return token
