"""
ZTZ RAG and File Guard SDK Decorators.
"""

import inspect
from functools import wraps
from typing import List, Callable, Any

from ztz.sdk.exceptions import UntrustedPayloadError
from ztz.core.trust_store import TrustStore
from ztz.core.validator import PreFlightValidator

def guard(trust_store: str = "./keys", targets: List[str] = None):
    """
    ZTZ Pre-Flight Firewall Decorator.
    
    Intercepts function arguments specified in `targets`, validates their 
    cryptographic signatures against the provided `trust_store`, and raises an 
    UntrustedPayloadError if they fail attestation.
    """
    if targets is None:
        targets = []

    def decorator(func: Callable) -> Callable:
        sig = inspect.signature(func)

        @wraps(func)
        def wrapper(*args, **kwargs):
            # Bind arguments to function signature
            bound_args = sig.bind(*args, **kwargs)
            bound_args.apply_defaults()

            # Trust store is re-read per call so key revocation takes effect immediately.
            store = TrustStore([trust_store] if trust_store else None)
            # Leverage the O(1) instantaneous SQLite hardware-bound cache
            with PreFlightValidator(store, use_cache=True) as validator:
                for target_name in targets:
                    if target_name in bound_args.arguments:
                        file_path = bound_args.arguments[target_name]
                        if isinstance(file_path, str) and file_path:
                            row = validator.validate_file(file_path)
                            if row["status"] not in ("VERIFIED", "VERIFIED_CACHE"):
                                raise UntrustedPayloadError(
                                    f"ZTZ Security Lockdown: Target '{target_name}' at '{file_path}' "
                                    f"failed attestation. Reason: {row.get('error', 'Unknown')}"
                                )

            return func(*args, **kwargs)
        return wrapper
    return decorator
