"""
ZTZ RAG and File Guard SDK Decorators.
"""

import inspect
from contextlib import contextmanager
from functools import wraps
from typing import Iterator, List, Callable, Optional

from ztz.sdk.exceptions import UntrustedPayloadError
from ztz.core.file_pin import pin_files, unpin_files
from ztz.core.trust_store import TrustStore
from ztz.core.validator import PreFlightValidator


@contextmanager
def attested(*paths: str, trust_store: Optional[str] = None) -> Iterator[List[str]]:
    """
    Pins, then verifies every path; the files stay pinned for the whole block so
    the bytes the runtime loads are the bytes that were attested:

        with attested("model.onnx"):
            session = onnxruntime.InferenceSession("model.onnx")

    Raises UntrustedPayloadError if a file fails attestation or cannot be pinned.
    """
    targets = [p for p in paths if isinstance(p, str) and p]
    try:
        pins = pin_files(targets)
    except OSError as e:
        raise UntrustedPayloadError(
            f"ZTZ Security Lockdown: cannot pin '{e.filename}' against modification ({e.strerror})"
        ) from e
    try:
        # Trust store is re-read per call so key revocation takes effect immediately.
        store = TrustStore([trust_store] if trust_store else None)
        with PreFlightValidator(store, use_cache=True) as validator:
            for path in targets:
                row = validator.validate_file(path)
                if row["status"] not in ("VERIFIED", "VERIFIED_CACHE"):
                    raise UntrustedPayloadError(
                        f"ZTZ Security Lockdown: '{path}' failed attestation. "
                        f"Reason: {row.get('error', 'Unknown')}"
                    )
        yield targets
    finally:
        unpin_files(pins)


def guard(trust_store: str = None, targets: List[str] = None):
    """
    ZTZ Pre-Flight Firewall Decorator.

    Attests the file paths passed in the arguments named by `targets` against
    `trust_store` (default: the home trust roots, see
    ztz.core.trust_store.default_search_paths) and keeps them pinned while the
    function runs. Raises UntrustedPayloadError if any fails attestation.
    """
    if targets is None:
        targets = []

    def decorator(func: Callable) -> Callable:
        sig = inspect.signature(func)

        @wraps(func)
        def wrapper(*args, **kwargs):
            bound_args = sig.bind(*args, **kwargs)
            bound_args.apply_defaults()
            paths = [bound_args.arguments[name] for name in targets if name in bound_args.arguments]
            with attested(*paths, trust_store=trust_store):
                return func(*args, **kwargs)
        return wrapper
    return decorator
