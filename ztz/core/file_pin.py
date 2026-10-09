"""
Anti-TOCTOU file pinning: hold verified files so they cannot change between
attestation and load.

Windows: mandatory share-mode hold; any other open-for-write, delete or rename
is refused by the OS while pinned.
POSIX: best-effort advisory flock (only stops processes that also lock).
"""

import os
from typing import Any, List

if os.name == "nt":
    import ctypes
    from ctypes import wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _CreateFileW = _kernel32.CreateFileW
    _CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    _CreateFileW.restype = wintypes.HANDLE
    _CloseHandle = _kernel32.CloseHandle
    _CloseHandle.argtypes = [wintypes.HANDLE]
    _CloseHandle.restype = wintypes.BOOL

    _GENERIC_READ = 0x80000000
    _FILE_SHARE_READ = 0x00000001
    _OPEN_EXISTING = 3
    _FILE_ATTRIBUTE_NORMAL = 0x80
    _INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

    def _pin_windows(path: str):
        # Sharing READ only (no WRITE, no DELETE): fails with a sharing violation
        # if a writer already has the file open.
        handle = _CreateFileW(
            os.path.abspath(path), _GENERIC_READ, _FILE_SHARE_READ, None,
            _OPEN_EXISTING, _FILE_ATTRIBUTE_NORMAL, None,
        )
        if handle == _INVALID_HANDLE_VALUE or handle is None:
            err = ctypes.WinError(ctypes.get_last_error())
            err.filename = path
            raise err
        return handle


def pin_files(paths: List[str]) -> List[Any]:
    """
    Pins every existing file in paths until unpin_files.
    On Windows raises OSError (with .filename set) if any file cannot be pinned.
    """
    pins = []
    if os.name == "nt":
        try:
            for p in paths:
                if os.path.isfile(p):
                    pins.append(_pin_windows(p))
        except OSError:
            unpin_files(pins)
            raise
        return pins

    import fcntl
    for p in paths:
        if os.path.exists(p):
            fd = None
            try:
                # CWE-775: Open without O_CLOEXEC to hold lock in parent.
                # close_fds=True in Popen ensures the child does not inherit it.
                fd = os.open(p, os.O_RDONLY)  # karnak: ignore
                fcntl.flock(fd, fcntl.LOCK_SH)
                pins.append(fd)
            except Exception:
                if fd is not None:
                    os.close(fd)
    return pins


def unpin_files(pins: List[Any]):
    if os.name == "nt":
        for handle in pins:
            _CloseHandle(handle)
        return
    try:
        import fcntl
        for fd in pins:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
    except Exception:
        pass
