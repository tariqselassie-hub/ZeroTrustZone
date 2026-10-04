"""
Instant Model Attestation Cache for ZTZ Pro.
Eliminates full SHA-256 streaming on warm model loads by caching inode/mtime/size
and cryptographically binding the cache row to the local machine fingerprint via HMAC.
"""

import sqlite3
import os
import sys
import hmac
import hashlib
import pathlib
from typing import Callable, Optional
from ztz.lic.fingerprint import HardwareFingerprint

CACHE_DB_PATH = os.path.expanduser("~/.ztz/cache.db")

class AttestationCache:
    def __init__(self, safe_db_path=CACHE_DB_PATH):
        self.db_path = str(pathlib.Path(safe_db_path).expanduser().resolve())
        
        # Security invariant: Prevent arbitrary -wal/-shm file creation attacks
        base_dir = pathlib.Path("~/.ztz").expanduser().resolve()
        target_path = pathlib.Path(self.db_path)
        
        if safe_db_path == CACHE_DB_PATH and not target_path.is_relative_to(base_dir):
            raise PermissionError(f"CRITICAL: Attestation cache path breached containment boundary: {self.db_path}")
            
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        # Validation may run on a worker thread (e.g. the async proxy); callers serialize access.
        self.safe_conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._set_pragmas()
        self._init_db()
        self.machine_key = HardwareFingerprint.compute_fingerprint().encode('utf-8')

    def _set_pragmas(self):
        self.safe_conn.execute("PRAGMA journal_mode = WAL;", ())  # karnak: ignore
        self.safe_conn.execute("PRAGMA synchronous = NORMAL;", ())
        self.safe_conn.execute("PRAGMA busy_timeout = 5000;", ())

    def _init_db(self):
        self.safe_conn.execute('''
            CREATE TABLE IF NOT EXISTS attestation_cache (
                file_path TEXT PRIMARY KEY,
                inode INTEGER,
                size INTEGER,
                mtime_ns INTEGER,
                auth_key TEXT,
                algo TEXT,
                signature TEXT
            )
        ''', ())
        self.safe_conn.commit()

    def _resolve_inode(self, file_path: str, stat_ino: int) -> Optional[int]:
        if stat_ino != 0:
            return stat_ino
        if sys.platform == "win32":
            # On Windows NTFS/FAT, os.stat.st_ino may be 0; compute stable 56-bit pseudo-inode from path
            normalized = os.path.abspath(file_path).lower().encode('utf-8')
            return int(hashlib.sha256(normalized).hexdigest()[:14], 16)
        return None

    def _sign_row(self, file_path, inode, size, mtime_ns, auth_key, algo, binding="") -> str:
        payload = f"{file_path}:{inode}:{size}:{mtime_ns}:{auth_key}:{algo}:{binding}".encode('utf-8')
        return hmac.new(self.machine_key, payload, hashlib.sha256).hexdigest()

    def get_cached_attestation(self, file_path: str, binding_for: Optional[Callable[[str], Optional[str]]] = None):
        """
        Returns the cached attestation for file_path, or None on any miss.
        binding_for(auth_key) must reproduce the binding passed to store_attestation
        (e.g. a digest of the .sig and the authority's public key); returning None
        means the authority is no longer trusted and forces a miss.
        """
        if not os.path.exists(file_path):
            return None
            
        stat = os.stat(file_path)
        size, mtime_ns = stat.st_size, stat.st_mtime_ns
        inode = self._resolve_inode(file_path, stat.st_ino)
        
        if inode is None:
            return None # Unstable inode on remote/unsupported NAS share
            
        cur = self.safe_conn.execute('SELECT inode, size, mtime_ns, auth_key, algo, signature FROM attestation_cache WHERE file_path = ?', (file_path,))
        row = cur.fetchone()
        if not row:
            return None
            
        c_inode, c_size, c_mtime_ns, c_auth_key, c_algo, c_signature = row
        
        # Verify filesystem metadata hasn't changed
        if c_inode != inode or c_size != size or c_mtime_ns != mtime_ns:
            return None
            
        binding = binding_for(c_auth_key) if binding_for else ""
        if binding is None:
            return None # Authority revoked or signature material changed

        # Verify the cryptographic signature of the cache row (Machine Binding + Anti-Tamper)
        expected_sig = self._sign_row(file_path, c_inode, c_size, c_mtime_ns, c_auth_key, c_algo, binding)
        if not hmac.compare_digest(c_signature, expected_sig):
            return None # Tampered cache row
            
        return {
            "key": c_auth_key,
            "algo": c_algo,
            "status": "VERIFIED_CACHE",
            "error": None
        }

    def store_attestation(self, file_path: str, auth_key: str, algo: str, binding: str = ""):
        if not os.path.exists(file_path):
            return
        stat = os.stat(file_path)
        size, mtime_ns = stat.st_size, stat.st_mtime_ns
        inode = self._resolve_inode(file_path, stat.st_ino)
        
        if inode is None:
            return # Don't cache unstable inodes
            
        signature = self._sign_row(file_path, inode, size, mtime_ns, auth_key, algo, binding)
        
        self.safe_conn.execute('''
            INSERT OR REPLACE INTO attestation_cache (file_path, inode, size, mtime_ns, auth_key, algo, signature)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (file_path, inode, size, mtime_ns, auth_key, algo, signature))
        self.safe_conn.commit()
        
    def clear(self):
        self.safe_conn.execute('DELETE FROM attestation_cache', ())
        self.safe_conn.commit()

    def close(self):
        if hasattr(self, 'safe_conn') and self.safe_conn:
            self.safe_conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

