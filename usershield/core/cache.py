"""
Instant Model Attestation Cache for UserShield Pro.
Eliminates full SHA-256 streaming on warm model loads by caching inode/mtime/size
and cryptographically binding the cache row to the local machine fingerprint via HMAC.
"""

import sqlite3
import os
import hmac
import hashlib
from usershield.lic.fingerprint import HardwareFingerprint

CACHE_DB_PATH = os.path.expanduser("~/.usershield/cache.db")

class AttestationCache:
    def __init__(self, db_path=CACHE_DB_PATH):
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.conn = sqlite3.connect(self.db_path)
        self._init_db()
        self.machine_key = HardwareFingerprint.compute_fingerprint().encode('utf-8')

    def _init_db(self):
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS attestation_cache (
                file_path TEXT PRIMARY KEY,
                inode INTEGER,
                size INTEGER,
                mtime REAL,
                auth_key TEXT,
                algo TEXT,
                signature TEXT
            )
        ''')
        self.conn.commit()

    def _sign_row(self, file_path, inode, size, mtime, auth_key, algo) -> str:
        payload = f"{file_path}:{inode}:{size}:{mtime}:{auth_key}:{algo}".encode('utf-8')
        return hmac.new(self.machine_key, payload, hashlib.sha256).hexdigest()

    def get_cached_attestation(self, file_path: str):
        if not os.path.exists(file_path):
            return None
            
        stat = os.stat(file_path)
        inode, size, mtime = stat.st_ino, stat.st_size, stat.st_mtime
        
        cur = self.conn.execute('SELECT inode, size, mtime, auth_key, algo, signature FROM attestation_cache WHERE file_path = ?', (file_path,))
        row = cur.fetchone()
        if not row:
            return None
            
        c_inode, c_size, c_mtime, c_auth_key, c_algo, c_signature = row
        
        # Verify filesystem metadata hasn't changed
        if c_inode != inode or c_size != size or c_mtime != mtime:
            return None
            
        # Verify the cryptographic signature of the cache row (Machine Binding + Anti-Tamper)
        expected_sig = self._sign_row(file_path, c_inode, c_size, c_mtime, c_auth_key, c_algo)
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
        inode, size, mtime = stat.st_ino, stat.st_size, stat.st_mtime
        signature = self._sign_row(file_path, inode, size, mtime, auth_key, algo)
        
        self.conn.execute('''
            INSERT OR REPLACE INTO attestation_cache (file_path, inode, size, mtime, auth_key, algo, signature)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (file_path, inode, size, mtime, auth_key, algo, signature))
        self.conn.commit()
        
    def clear(self):
        self.conn.execute('DELETE FROM attestation_cache')
        self.conn.commit()
