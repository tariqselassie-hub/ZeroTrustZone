"""
Cryptographic signing and verification engine for ZTZ.
Supports Ed25519 (high speed, constant time, 64-byte signatures) and RSA-PSS.
Includes streaming multi-gigabyte hashing for massive GGUF weight files.
"""

import os
import hashlib
from typing import Tuple, Optional, Union
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

CHUNK_SIZE = 64 * 1024 * 1024  # 64 MB streaming buffer

def compute_file_sha256(file_path: str) -> bytes:
    """Computes SHA-256 digest in chunks to handle multi-gigabyte GGUF models."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            hasher.update(chunk)
    return hasher.digest()

class ZTZSigner:
    """Administrative utility for creating detached cryptographic signatures."""
    
    def __init__(self, private_key_path: str, password: Optional[bytes] = None):
        self.private_key_path = private_key_path
        self.private_key = self._load_private_key(password)

    def _load_private_key(self, password: Optional[bytes]):
        if not os.path.exists(self.private_key_path):
            raise FileNotFoundError(f"Private key file not found: {self.private_key_path}")
            
        with open(self.private_key_path, "rb") as kf:
            return serialization.load_pem_private_key(kf.read(), password=password)

    def sign_file(self, target_file_path: str, output_sig_path: Optional[str] = None) -> str:
        """
        Signs target file and writes a detached .sig file.
        For Ed25519: signs raw content or digest.
        Returns the output signature file path.
        """
        if not os.path.exists(target_file_path):
            raise FileNotFoundError(f"Target file not found: {target_file_path}")
            
        if output_sig_path is None:
            output_sig_path = f"{target_file_path}.sig"

        file_digest = compute_file_sha256(target_file_path)

        if isinstance(self.private_key, ed25519.Ed25519PrivateKey):
            # Ed25519 signs the 32-byte SHA-256 digest
            signature = self.private_key.sign(file_digest)
        elif isinstance(self.private_key, rsa.RSAPrivateKey):
            # RSA-PSS on precomputed digest
            signature = self.private_key.sign(
                file_digest,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        else:
            raise TypeError(f"Unsupported private key type: {type(self.private_key)}")

        with open(output_sig_path, "wb") as sf:
            sf.write(signature)
            
        return output_sig_path

class ZTZVerifier:
    """Pre-flight verifier utilizing pre-loaded public keys."""
    
    @staticmethod
    def verify_file(
        target_file_path: str,
        sig_path: str,
        public_key: Union[ed25519.Ed25519PublicKey, rsa.RSAPublicKey],
    ) -> Tuple[bool, str]:
        """
        Validates target file against detached signature file.
        Returns (is_valid, algorithm_name).
        """
        if not os.path.exists(target_file_path):
            return False, "Target file missing"
        if not os.path.exists(sig_path):
            return False, "Detached .sig missing"

        try:
            with open(sig_path, "rb") as sf:
                signature = sf.read()
        except Exception as e:
            return False, f"Could not read .sig: {e}"

        file_digest = compute_file_sha256(target_file_path)

        try:
            if isinstance(public_key, ed25519.Ed25519PublicKey):
                public_key.verify(signature, file_digest)
                return True, "Ed25519"
            elif isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    signature,
                    file_digest,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
                return True, "RSA-PSS"
            else:
                return False, f"Unsupported public key type: {type(public_key)}"
        except InvalidSignature:
            return False, "Signature mismatch / Invariant violated"
        except Exception as e:
            return False, str(e)

def generate_keypair(
    key_type: str = "ed25519",
    out_dir: str = "./keys",
    name: str = "authority",
    rsa_bits: int = 4096,
) -> Tuple[str, str]:
    """Generates and writes an asymmetric keypair in PEM format."""
    os.makedirs(out_dir, exist_ok=True)
    priv_path = os.path.join(out_dir, f"{name}_priv.pem")
    pub_path = os.path.join(out_dir, f"{name}_pub.pem")

    if key_type.lower() == "ed25519":
        priv_key = ed25519.Ed25519PrivateKey.generate()
        pub_key = priv_key.public_key()
    elif key_type.lower() == "rsa":
        priv_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=rsa_bits,
        )
        pub_key = priv_key.public_key()
    else:
        raise ValueError(f"Unknown key type: {key_type}. Must be 'ed25519' or 'rsa'.")

    # Serialize private key
    priv_bytes = priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(priv_path, "wb") as f:
        f.write(priv_bytes)

    # Serialize public key
    pub_bytes = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(pub_path, "wb") as f:
        f.write(pub_bytes)

    return priv_path, pub_path
