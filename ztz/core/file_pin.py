"""
Anti-TOCTOU file pinning: hold verified files so they cannot change between
attestation and load.

Windows: mandatory share-mode hold; any other open-for-write, delete or rename
is refused by the OS while pinned.
Linux: the file is opened once and verified and loaded through that descriptor
(/proc/self/fd/N), so swapping or deleting the path after the open has no
effect. In-place writes to the same inode are detected (fstat snapshot) up to
launch, not prevented; an advisory flock is held as well.
Other POSIX (macOS): advisory flock plus the same snapshot check; the path is
still what gets loaded.
"""

import os
import stat
import sys
from typing import Any, Dict, List, Optional

# /proc/self/fd/N reopens the pinned inode with an independent file offset.
# macOS /dev/fd/N dup()s instead (shared offset), so it is not used there.
FD_BINDING = sys.platform.startswith("linux") and os.path.isdir("/proc/self/fd")

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


def _snapshot(st: os.stat_result) -> tuple:
    # ctime cannot be set from userspace, so restoring mtime after a write is still caught.
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


class Pin:
    """
    A pinned file. load_path is what verification and the runtime must read:
    /proc/self/fd/N under FD_BINDING, the original path otherwise.
    """

    def __init__(self, path: str, handle: Any = None, fd: Optional[int] = None):
        self.path = path
        self.handle = handle
        self.fd = fd
        self.snapshot = _snapshot(os.fstat(fd)) if fd is not None else None
        self.load_path = f"/proc/self/fd/{fd}" if FD_BINDING and fd is not None else path

    def changed(self) -> bool:
        """True if the pinned bytes may differ from what was there at pin time (POSIX)."""
        if self.fd is None:
            return False
        if _snapshot(os.fstat(self.fd)) != self.snapshot:
            return True
        if FD_BINDING:
            return False  # the runtime loads through the fd; the path no longer matters
        try:
            return _snapshot(os.stat(self.path)) != self.snapshot
        except OSError:
            return True


def _pin_posix(path: str) -> Optional[Pin]:
    import errno
    import fcntl
    # O_NONBLOCK: a FIFO swapped in for the file must not hang the open.
    fd = os.open(path, os.O_RDONLY | os.O_NOCTTY | os.O_NONBLOCK)  # karnak: ignore
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, "not a regular file", path)
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except OSError as e:
            # Someone holds an exclusive lock: treat as an active writer, like Windows.
            raise OSError(e.errno, "file is exclusively locked by another process", path) from e
        return Pin(path, fd=fd)
    except BaseException:
        os.close(fd)
        raise


def pin_files(paths: List[str]) -> List[Pin]:
    """
    Pins every existing regular file in paths (duplicates once) until unpin_files.
    Raises OSError (with .filename set) if any file cannot be pinned; nothing
    stays pinned in that case. Missing files are skipped so validation reports them.
    """
    pins: List[Pin] = []
    seen = set()
    try:
        for p in paths:
            if p in seen or not os.path.isfile(p):
                continue
            seen.add(p)
            if os.name == "nt":
                pins.append(Pin(p, handle=_pin_windows(p)))
            else:
                pins.append(_pin_posix(p))
    except OSError as e:
        unpin_files(pins)
        if e.filename is None:
            e.filename = p
        raise
    return pins


def load_paths(pins: List[Pin]) -> Dict[str, str]:
    """Maps each pinned original path to the path the runtime must load."""
    return {pin.path: pin.load_path for pin in pins}


def changed_files(pins: List[Pin]) -> List[str]:
    """Original paths whose pinned content may have changed since pin_files."""
    return [pin.path for pin in pins if pin.changed()]


def pass_fds(pins: List[Pin]) -> tuple:
    """Descriptors a child process must inherit to open the load paths."""
    return tuple(pin.fd for pin in pins if FD_BINDING and pin.fd is not None)


def unpin_files(pins: List[Pin]):
    for pin in pins:
        try:
            if pin.handle is not None:
                _CloseHandle(pin.handle)
            elif pin.fd is not None:
                os.close(pin.fd)  # also releases the flock
        except OSError:
            pass
