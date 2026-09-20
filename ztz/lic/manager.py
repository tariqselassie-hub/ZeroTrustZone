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

class LicenseManager:
    def __init__(self, vendor_pub_key: Optional[ed25519.Ed25519PublicKey] = None, custom_lic_path: Optional[str] = None):
        self.vendor_pub_key = vendor_pub_key
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

        # If vendor public key is configured, verify the signature over token content
        if self.vendor_pub_key is not None:
            try:
                sig_bytes = bytes.fromhex(data["signature"])
                canonical_str = f"{data['license_id']}:{data['tier']}:{data['machine_fingerprint']}:{data.get('issued_at', 0)}"
                self.vendor_pub_key.verify(sig_bytes, canonical_str.encode("utf-8"))
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
        canonical_str = f"{license_id}:{tier}:{machine_fingerprint}:{issued_at}"
        signature = vendor_priv_key.sign(canonical_str.encode("utf-8"))
        
        token = {
            "license_id": license_id,
            "tier": tier,
            "machine_fingerprint": machine_fingerprint,
            "issued_at": issued_at,
            "signature": signature.hex(),
        }
        return token
