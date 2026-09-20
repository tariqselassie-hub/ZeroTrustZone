"""
Pre-Flight Validator for UserShield.
Performs memory-isolation invariant checks before runtime initialization.
"""

import os
import time
from typing import List, Dict, Any, Tuple
from usershield.core.trust_store import TrustStore
from usershield.core.crypto import UserShieldVerifier
from usershield.core.cache import AttestationCache

class PreFlightValidator:
    def __init__(self, trust_store: TrustStore, use_cache: bool = True):
        self.trust_store = trust_store
        self.use_cache = use_cache
        self.cache = AttestationCache() if use_cache else None

    def validate_file(self, target_path: str, sig_path: str = None) -> Dict[str, Any]:
        """
        Validates a single target file against all available trusted authorities.
        """
        if sig_path is None:
            sig_path = f"{target_path}.sig"

        result = {
            "resource": os.path.basename(target_path),
            "full_path": target_path,
            "sig_path": sig_path,
            "key": "None",
            "algo": "None",
            "status": "UNATTESTED",
            "error": None,
        }

        if not os.path.exists(target_path):
            result["status"] = "MISSING"
            result["error"] = "Target file not found"
            return result

        if not os.path.exists(sig_path):
            result["status"] = "NO_SIG"
            result["error"] = "Detached signature (.sig) missing"
            return result

        authorities = self.trust_store.list_authorities()
        if not authorities:
            result["status"] = "NO_ROOTS"
            result["error"] = "Trust store contains zero public authority keys"
            return result

        if self.use_cache:
            cached = self.cache.get_cached_attestation(target_path)
            if cached:
                result["key"] = cached["key"]
                result["algo"] = cached["algo"]
                result["status"] = cached["status"]
                result["error"] = cached["error"]
                return result

        # Try all trusted authorities
        for auth in authorities:
            is_valid, algo_or_err = UserShieldVerifier.verify_file(
                target_path,
                sig_path,
                auth["key"],
            )
            if is_valid:
                if self.use_cache:
                    self.cache.store_attestation(target_path, auth["name"], algo_or_err)
                result["key"] = auth["name"]
                result["algo"] = algo_or_err
                result["status"] = "VERIFIED"
                result["error"] = None
                return result

        # If loop completed without valid match:
        result["key"] = "Unknown"
        result["algo"] = "Invalid"
        result["status"] = "TAMPERED"
        result["error"] = "Signature does not match any trusted root of trust"
        return result

    def audit_batch(self, targets: List[str]) -> Tuple[bool, List[Dict[str, Any]], float]:
        """
        Audits a list of target files.
        Returns (all_clean, audit_rows, elapsed_seconds).
        """
        t0 = time.perf_counter()
        rows = []
        all_clean = True

        for target in targets:
            if not target:
                continue
            row = self.validate_file(target)
            rows.append(row)
            if row["status"] != "VERIFIED":
                all_clean = False

        elapsed = time.perf_counter() - t0
        return all_clean, rows, elapsed
