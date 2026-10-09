"""
Pre-Flight Validator for ZTZ.
Performs memory-isolation invariant checks before runtime initialization.
"""

import os
import time
import hashlib
from typing import List, Dict, Any, Optional, Tuple
from cryptography.hazmat.primitives import serialization
from ztz.core.trust_store import TrustStore
from ztz.core.crypto import ZTZVerifier
from ztz.core.cache import AttestationCache
from ztz.core.model_inspector import ModelFormatInspector

class PreFlightValidator:
    def __init__(self, trust_store: TrustStore, use_cache: bool = True):
        self.trust_store = trust_store
        self.use_cache = use_cache
        self.cache = AttestationCache() if use_cache else None

    def close(self):
        if self.cache:
            self.cache.close()
            self.cache = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def _cache_binding(self, sig_path: str, authority_name: str) -> Optional[str]:
        """
        Binds a cache row to the exact detached signature and the authority's current
        public key, so replacing the .sig or revoking/rotating the key invalidates it.
        """
        auth = self.trust_store.get_authority(authority_name)
        if auth is None:
            return None
        try:
            with open(sig_path, "rb") as sf:
                sig_bytes = sf.read()
        except OSError:
            return None
        pub_der = auth["key"].public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return hashlib.sha256(sig_bytes + b"|" + pub_der).hexdigest()

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
            "format": "UNKNOWN",
        }

        if not os.path.exists(target_path):
            result["status"] = "MISSING"
            result["error"] = "Target file not found"
            return result

        # Pre-Flight Container & Format Safety Check
        format_report = ModelFormatInspector.inspect(target_path)
        result["format"] = format_report.format
        if format_report.risk_level == "CRITICAL" and not format_report.is_safe_format:
            result["status"] = "UNSAFE_FORMAT"
            result["error"] = "; ".join(format_report.warnings)
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
            cached = self.cache.get_cached_attestation(
                target_path,
                binding_for=lambda name: self._cache_binding(sig_path, name),
            )
            if cached:
                result["key"] = cached["key"]
                result["algo"] = cached["algo"]
                result["status"] = cached["status"]
                result["error"] = cached["error"]
                return result

        # Try all trusted authorities
        for auth in authorities:
            is_valid, algo_or_err = ZTZVerifier.verify_file(
                target_path,
                sig_path,
                auth["key"],
            )
            if is_valid:
                if self.use_cache:
                    binding = self._cache_binding(sig_path, auth["name"])
                    if binding is not None:
                        self.cache.store_attestation(target_path, auth["name"], algo_or_err, binding)
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
            if row["status"] not in ("VERIFIED", "VERIFIED_CACHE"):
                all_clean = False

        elapsed = time.perf_counter() - t0
        return all_clean, rows, elapsed
