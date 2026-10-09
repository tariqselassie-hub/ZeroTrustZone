"""
ZTZ RAG and File Guard SDK Decorators.
"""

import inspect
from contextlib import contextmanager
from functools import wraps
from typing import Iterator, List, Callable, Optional

from ztz.sdk.exceptions import UntrustedPayloadError
from ztz.core.file_pin import (
    FD_BINDING, NamedLinks, changed_files, group_by_dir, load_paths, pin_files, unpin_files,
)
from ztz.core.trust_store import TrustStore
from ztz.core.validator import PreFlightValidator


@contextmanager
def attested(*paths: str, trust_store: Optional[str] = None, keep_names: bool = False) -> Iterator[List[str]]:
    """
    Pins, then verifies every path; the files stay pinned for the whole block.
    Yields the paths to load, in order: on Linux these are the verified
    descriptors (/proc/self/fd/N), so load them rather than the original names
    to get the bytes that were attested; elsewhere they are the paths unchanged:

        with attested("model.onnx") as (model,):
            session = onnxruntime.InferenceSession(model)

    keep_names=True (Linux) yields <private dir>/<original name> symlinks to the
    descriptors instead, for loaders that pick a format from the file extension.
    Trade-off: a process running as the same user could swap such a link before
    the loader opens it, which bare descriptor paths rule out. Elsewhere it is a no-op.

    Raises UntrustedPayloadError if a file fails attestation or cannot be pinned.
    """
    targets = [p for p in paths if isinstance(p, str) and p]
    try:
        pins = pin_files(targets)
    except OSError as e:
        raise UntrustedPayloadError(
            f"ZTZ Security Lockdown: cannot pin '{e.filename}' against modification ({e.strerror})"
        ) from e
    named = None
    try:
        # Trust store is re-read per call so key revocation takes effect immediately.
        store = TrustStore([trust_store] if trust_store else None)
        bound = load_paths(pins)
        with PreFlightValidator(store, use_cache=True) as validator:
            for path in targets:
                row = validator.validate_file(path, read_path=bound.get(path))
                if row["status"] not in ("VERIFIED", "VERIFIED_CACHE"):
                    raise UntrustedPayloadError(
                        f"ZTZ Security Lockdown: '{path}' failed attestation. "
                        f"Reason: {row.get('error', 'Unknown')}"
                    )
        changed = changed_files(pins)
        if changed:
            raise UntrustedPayloadError(
                f"ZTZ Security Lockdown: '{changed[0]}' changed or was replaced during verification"
            )
        loads = [bound.get(path, path) for path in targets]
        if keep_names and FD_BINDING and pins:
            named = NamedLinks(group_by_dir(pin.path for pin in pins), bound)
            loads = [named.paths.get(path, load) for path, load in zip(targets, loads)]
        yield loads
    finally:
        if named:
            named.close()
        unpin_files(pins)


def guard(trust_store: str = None, targets: List[str] = None, keep_names: bool = False):
    """
    ZTZ Pre-Flight Firewall Decorator.

    Attests the file paths passed in the arguments named by `targets` against
    `trust_store` (default: the home trust roots, see
    ztz.core.trust_store.default_search_paths) and keeps them pinned while the
    function runs. Those arguments are replaced with the paths yielded by
    `attested` (the verified descriptors on Linux; see `attested` for
    keep_names). Raises UntrustedPayloadError if any fails attestation.
    """
    if targets is None:
        targets = []

    def decorator(func: Callable) -> Callable:
        sig = inspect.signature(func)

        @wraps(func)
        def wrapper(*args, **kwargs):
            bound_args = sig.bind(*args, **kwargs)
            bound_args.apply_defaults()
            names = [
                name for name in targets
                if isinstance(bound_args.arguments.get(name), str) and bound_args.arguments[name]
            ]
            files = (bound_args.arguments[n] for n in names)
            with attested(*files, trust_store=trust_store, keep_names=keep_names) as loads:
                bound_args.arguments.update(zip(names, loads))
                return func(*bound_args.args, **bound_args.kwargs)
        return wrapper
    return decorator
