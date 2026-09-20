"""
UserShield RAG and File Guard SDK Decorators.
"""

import inspect
from functools import wraps
from typing import List, Callable, Any

from usershield.sdk.exceptions import UntrustedPayloadError
from usershield.core.trust_store import TrustStore
from usershield.core.validator import PreFlightValidator

def guard(trust_store: str = "./keys", targets: List[str] = None):
    """
    UserShield Pre-Flight Firewall Decorator.
    
    Intercepts function arguments specified in `targets`, validates their 
    cryptographic signatures against the provided `trust_store`, and raises an 
    UntrustedPayloadError if they fail attestation.
    """
    if targets is None:
        targets = []

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Bind arguments to function signature
            sig = inspect.signature(func)
            bound_args = sig.bind(*args, **kwargs)
            bound_args.apply_defaults()
            
            store = TrustStore([trust_store] if trust_store else None)
            # Leverage the O(1) instantaneous SQLite hardware-bound cache
            validator = PreFlightValidator(store, use_cache=True)
            
            for target_name in targets:
                if target_name in bound_args.arguments:
                    file_path = bound_args.arguments[target_name]
                    if isinstance(file_path, str) and file_path:
                        row = validator.validate_file(file_path)
                        if row["status"] not in ("VERIFIED", "VERIFIED_CACHE"):
                            raise UntrustedPayloadError(
                                f"UserShield Security Lockdown: Target '{target_name}' at '{file_path}' "
                                f"failed attestation. Reason: {row.get('error', 'Unknown')}"
                            )
                            
            return func(*args, **kwargs)
        return wrapper
    return decorator
