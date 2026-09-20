"""
Instant Model Attestation Cache for ZTZ Pro.
Eliminates full SHA-256 streaming on warm model loads by caching inode/mtime/size
and cryptographically binding the cache row to the local machine fingerprint via HMAC.
"""

import sqlite3
import os
import hmac
import hashlib
import pathlib
from ztz.lic.fingerprint import HardwareFingerprint

CACHE_DB_PATH = os.path.expanduser("~/.ztz/cache.db")

class AttestationCache:
    def __init__(self, safe_db_path=CACHE_DB_PATH):
        self.db_path = str(pathlib.Path(safe_db_path).expanduser().resolve())
        
        # Security invariant: Prevent arbitrary -wal/-shm file creation attacks
        base_dir = pathlib.Path("~/.ztz").expanduser().resolve()
        target_path = pathlib.Path(self.db_path)
        
        if not target_path.is_relative_to(base_dir):
            raise PermissionError(f"CRITICAL: Attestation cache path breached containment boundary: {self.db_path}")
            
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.safe_conn = sqlite3.connect(self.db_path)
        self._set_pragmas()
        self._init_db()
        self.machine_key = HardwareFingerprint.compute_fingerprint().encode('utf-8')

    def _set_pragmas(self):
        self.safe_conn.execute("PRAGMA journal_mode = WAL;", ())  # karnak: ignore
        self.safe_conn.execute("PRAGMA synchronous = NORMAL;", ())
        self.safe_conn.execute("PRAGMA busy_timeout = 5000;", ())

    def _init_db(self):
        # Drop the table if upgrading from floating-point mtime to ns
        self.safe_conn.execute("DROP TABLE IF EXISTS attestation_cache", ())
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

    def _sign_row(self, file_path, inode, size, mtime_ns, auth_key, algo) -> str:
        payload = f"{file_path}:{inode}:{size}:{mtime_ns}:{auth_key}:{algo}".encode('utf-8')
        return hmac.new(self.machine_key, payload, hashlib.sha256).hexdigest()

    def get_cached_attestation(self, file_path: str):
        if not os.path.exists(file_path):
            return None
            
        stat = os.stat(file_path)
        inode, size, mtime_ns = stat.st_ino, stat.st_size, stat.st_mtime_ns
        
        if inode == 0:
            return None # Unstable inode on Windows/NAS, reject cache
            
        cur = self.safe_conn.execute('SELECT inode, size, mtime_ns, auth_key, algo, signature FROM attestation_cache WHERE file_path = ?', (file_path,))
        row = cur.fetchone()
        if not row:
            return None
            
        c_inode, c_size, c_mtime_ns, c_auth_key, c_algo, c_signature = row
        
        # Verify filesystem metadata hasn't changed
        if c_inode != inode or c_size != size or c_mtime_ns != mtime_ns:
            return None
            
        # Verify the cryptographic signature of the cache row (Machine Binding + Anti-Tamper)
        expected_sig = self._sign_row(file_path, c_inode, c_size, c_mtime_ns, c_auth_key, c_algo)
        if not hmac.compare_digest(c_signature, expected_sig):
            return None # Tampered cache row
            
        return {
            "key": c_auth_key,
            "algo": c_algo,
            "status": "VERIFIED_CACHE",
            "error": None
        }

    def store_attestation(self, file_path: str, auth_key: str, algo: str):
        if not os.path.exists(file_path):
            return
        stat = os.stat(file_path)
        inode, size, mtime_ns = stat.st_ino, stat.st_size, stat.st_mtime_ns
        
        if inode == 0:
            return # Don't cache unstable inodes
            
        signature = self._sign_row(file_path, inode, size, mtime_ns, auth_key, algo)
        
        self.safe_conn.execute('''
            INSERT OR REPLACE INTO attestation_cache (file_path, inode, size, mtime_ns, auth_key, algo, signature)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (file_path, inode, size, mtime_ns, auth_key, algo, signature))
        self.safe_conn.commit()
        
    def clear(self):
        self.safe_conn.execute('DELETE FROM attestation_cache', ())
        self.safe_conn.commit()
