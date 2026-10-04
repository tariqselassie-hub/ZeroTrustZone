"""
ZTZ Pre-Flight Context Firewall (core/context_shield.py)
Zero-Trust context sanitization, secret scrubbing, and cryptographic pre-flight
attestation before LLM ingestion (ZeroTrustZone Project).
"""

import re
import hashlib
import time
from typing import Dict, List, Any, Optional, Tuple, Union

# Signature Patterns for Common High-Risk Leaks
SECRET_PATTERNS = [
    # Private Keys (RSA, OpenSSH, EC, PGP, Generic)
    (
        "PRIVATE_KEY",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----[\s\S]+?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----",
            re.IGNORECASE
        )
    ),
    # Anthropic API / Admin Keys (sk-ant-api03-..., sk-ant-admin01-...).
    # Must precede the generic sk- rule so these are labelled correctly.
    # Key-body rules are greedy with no upper bound: a length cap plus a trailing \b
    # would stop at an internal '-' and leave the remainder of a long key unmasked.
    (
        "ANTHROPIC_API_KEY",
        re.compile(r"\bsk-ant-[a-z]+\d*-[A-Za-z0-9_-]{20,}")
    ),
    # OpenAI API Keys (legacy sk-..., project sk-proj-..., service account sk-svcacct-...)
    (
        "OPENAI_API_KEY",
        re.compile(r"\bsk-[A-Za-z0-9_-]{20,}")
    ),
    # GitHub Personal Access / OAuth Tokens
    (
        "GITHUB_TOKEN",
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}\b|\bgithub_pat_[a-zA-Z0-9_]{22,82}\b")
    ),
    # AWS Access Key ID
    (
        "AWS_ACCESS_KEY_ID",
        re.compile(r"\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b")
    ),
    # Google Cloud / Firebase API Key
    (
        "GOOGLE_API_KEY",
        re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")
    ),
    # Slack Tokens
    (
        "SLACK_TOKEN",
        re.compile(r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}\b")
    ),
    # JSON Web Tokens (JWT) / Bearer format
    (
        "JWT_BEARER_TOKEN",
        re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b")
    ),
    # Database URIs with credentials
    (
        "DATABASE_CREDENTIALS",
        re.compile(r"(?:postgres|postgresql|mysql|mongodb|redis):\/\/[a-zA-Z0-9_.-]+:[^@\s]+@[a-zA-Z0-9_.-]+(?::[0-9]+)?")
    ),
    # Hardcoded secrets / passwords in key-value format
    (
        "HARDCODED_SECRET",
        re.compile(r"""(?i)\b(?:api_key|apikey|secret_key|private_key|auth_token|access_token|password|passwd|pwd)\s*[:=]\s*['"]([a-zA-Z0-9!@#$%^&*()_+\-=\[\]{}|;:,.<>?/`~]{8,128})['"]""")
    ),
]


class EnclaveSeal:
    """Represents a cryptographic hardware/enclave attestation seal from Security Den (Pillar 4)."""
    def __init__(
        self,
        sealed: bool,
        mode: str,
        signature_hex: Optional[str] = None,
        ztz_trace: Optional[List[int]] = None,
        status: str = "SECURE",
        message: str = "Hardware seal active",
        timestamp: Optional[float] = None,
        key_id: Optional[str] = None
    ):
        self.sealed = sealed
        self.key_id = key_id
        self.mode = mode
        self.signature_hex = signature_hex
        self.ztz_trace = ztz_trace
        self.status = status
        self.message = message
        self.timestamp = timestamp or time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sealed": self.sealed,
            "mode": self.mode,
            "signature_hex": self.signature_hex,
            "ztz_trace": self.ztz_trace,
            "status": self.status,
            "message": self.message,
            "timestamp": self.timestamp,
            "key_id": self.key_id,
        }


# Local fallback seal: signed with the authority key so anyone holding the public key
# (i.e. the trust store) can verify it, and nobody without the private key can mint one.
LOCAL_SEAL_MODE = "LOCAL_AUTHORITY_SIG"
SEAL_KEY_ENV = "ZTZ_SEAL_KEY"
_seal_key_cache: Dict[Tuple[str, int], Any] = {}


def _load_seal_key():
    """Loads the local sealing key (ZTZ_SEAL_KEY, else the authority key), cached by mtime."""
    import os
    from ztz.core.trust_store import find_private_key
    from cryptography.hazmat.primitives import serialization

    path = os.environ.get(SEAL_KEY_ENV) or find_private_key()
    if not path or not os.path.isfile(path):
        return None
    cache_key = (os.path.abspath(path), os.stat(path).st_mtime_ns)
    if cache_key not in _seal_key_cache:
        try:
            with open(path, "rb") as kf:
                key = serialization.load_pem_private_key(kf.read(), password=None)
        except (OSError, ValueError, TypeError):
            return None
        _seal_key_cache.clear()
        _seal_key_cache[cache_key] = key
    return _seal_key_cache[cache_key]


def _seal_payload(payload_digest: str) -> bytes:
    return f"ztz-seal:v1:{payload_digest}".encode("utf-8")


class ContextAuditResult:
    """Represents the pre-flight verification output of context verification."""
    def __init__(
        self,
        clean_text: str,
        redactions_count: int,
        findings: List[Dict[str, Any]],
        digest_sha256: str,
        timestamp: float,
        passed_preflight: bool = True,
        seal: Optional[EnclaveSeal] = None
    ):
        self.clean_text = clean_text
        self.redactions_count = redactions_count
        self.findings = findings
        self.digest_sha256 = digest_sha256
        self.timestamp = timestamp
        self.passed_preflight = passed_preflight
        self.seal = seal

    def to_dict(self) -> Dict[str, Any]:
        return {
            "clean_text": self.clean_text,
            "redactions_count": self.redactions_count,
            "findings": self.findings,
            "digest_sha256": self.digest_sha256,
            "timestamp": self.timestamp,
            "passed_preflight": self.passed_preflight,
            "seal": self.seal.to_dict() if self.seal else None,
        }


class ContextShield:
    """
    Pre-Flight Context Firewall for Sovereign AI Runtimes.
    Guarantees that sensitive credentials, keys, and tokens are neutralized
    before prompts, context docs, or AST tokens are forwarded to LLM endpoints.
    """

    def __init__(self, private_key_pem: Optional[bytes] = None):
        self._private_key = None
        if private_key_pem:
            try:
                from cryptography.hazmat.primitives import serialization
                self._private_key = serialization.load_pem_private_key(private_key_pem, password=None)
            except Exception:
                self._private_key = None

    @classmethod
    def sanitize(cls, text: str) -> ContextAuditResult:
        """
        Sanitizes a single text block, masking detected credentials.
        Returns ContextAuditResult with clean text and audit trail.
        """
        if not text or not isinstance(text, str):
            return ContextAuditResult(
                clean_text=text or "",
                redactions_count=0,
                findings=[],
                digest_sha256=hashlib.sha256(b"").hexdigest(),
                timestamp=time.time(),
                passed_preflight=True
            )

        scrubbed = text
        findings = []
        total_redactions = 0

        for category, pattern in SECRET_PATTERNS:
            matches = list(pattern.finditer(scrubbed))
            if matches:
                for match in matches:
                    matched_str = match.group(0)
                    # Mask value
                    mask = f"[ZTZ_QUENCHED:{category}]"
                    scrubbed = scrubbed.replace(matched_str, mask)
                    total_redactions += 1
                    findings.append({
                        "category": category,
                        "offset": match.start(),
                        "length": len(matched_str)
                    })

        # Compute deterministic SHA-256 digest of sanitized context
        digest = hashlib.sha256(scrubbed.encode("utf-8")).hexdigest()

        return ContextAuditResult(
            clean_text=scrubbed,
            redactions_count=total_redactions,
            findings=findings,
            digest_sha256=digest,
            timestamp=time.time(),
            passed_preflight=True
        )

    @classmethod
    def request_enclave_seal(
        cls,
        payload_digest: str,
        enclave_url: Optional[str] = None,
        timeout_sec: float = 0.5
    ) -> EnclaveSeal:
        """
        Requests a ZTZ DSA attestation signature from ZTZ Enclave (Port 5555).
        Falls back to a local authority-key signature if the Enclave is offline,
        and to an explicit UNSEALED result if no signing key is available.
        """
        import os
        import json
        import urllib.request
        import urllib.error

        base_url = enclave_url or os.environ.get("ZTZ_ENCLAVE_URL", "http://127.0.0.1:5555")
        endpoint = f"{base_url.rstrip('/')}/api/dsa/sign"
        
        req_data = json.dumps({
            "payload": payload_digest,
            "key_seed": 777,
            "inject_fault": False
        }).encode("utf-8")

        req = urllib.request.Request(
            endpoint,
            data=req_data,
            headers={"Content-Type": "application/json", "User-Agent": "ZTZ-Sentinel/2.0"},
            method="POST"
        )

        try:
            with urllib.request.urlopen(req, timeout=timeout_sec) as response:
                if response.status == 200:
                    resp_body = json.loads(response.read().decode("utf-8"))
                    if resp_body.get("status") == "secure":
                        egress_data = resp_body.get("egress_data")
                        sig_hex = bytes(egress_data).hex() if egress_data else None
                        return EnclaveSeal(
                            sealed=True,
                            mode="ZTZ_DSA",
                            signature_hex=sig_hex,
                            ztz_trace=resp_body.get("ztz_trace"),
                            status="SECURE",
                            message=resp_body.get("message", "ZTZ Enclave attestation sealed.")
                        )
        except Exception:
            pass

        # Sovereign Local Fallback
        from ztz.core.crypto import sign_bytes, public_key_id

        priv = _load_seal_key()
        if priv is None:
            return EnclaveSeal(
                sealed=False,
                mode="UNSEALED",
                status="UNSEALED",
                message="Enclave offline and no local signing key; run 'ztz init' or set ZTZ_SEAL_KEY."
            )
        return EnclaveSeal(
            sealed=True,
            mode=LOCAL_SEAL_MODE,
            signature_hex=sign_bytes(priv, _seal_payload(payload_digest)).hex(),
            status="LOCAL_ATTESTED",
            message="Enclave offline: local authority signature attached.",
            key_id=public_key_id(priv.public_key()),
        )

    @staticmethod
    def verify_local_seal(payload_digest: str, seal: EnclaveSeal, trust_store) -> Optional[str]:
        """
        Verifies a LOCAL_AUTHORITY_SIG seal against the trust store.
        Returns the name of the authority that signed it, or None if invalid.
        """
        from cryptography.exceptions import InvalidSignature
        from ztz.core.crypto import verify_bytes, public_key_id

        if not seal or not seal.sealed or seal.mode != LOCAL_SEAL_MODE or not seal.signature_hex:
            return None
        try:
            sig = bytes.fromhex(seal.signature_hex)
        except ValueError:
            return None
        for auth in trust_store.list_authorities():
            if seal.key_id and public_key_id(auth["key"]) != seal.key_id:
                continue
            try:
                verify_bytes(auth["key"], sig, _seal_payload(payload_digest))
                return auth["name"]
            except (InvalidSignature, TypeError):
                continue
        return None

    @classmethod
    def seal_and_attest(
        cls,
        text: str,
        enclave_url: Optional[str] = None
    ) -> ContextAuditResult:
        """
        Sanitizes text and immediately requests a cryptographic attestation seal from Security Den.
        """
        result = cls.sanitize(text)
        seal = cls.request_enclave_seal(result.digest_sha256, enclave_url=enclave_url)
        result.seal = seal
        return result

    @classmethod
    def sanitize_messages(cls, messages: List[Dict[str, str]]) -> Tuple[List[Dict[str, str]], List[Dict[str, Any]], int]:
        """
        Sanitizes an entire chat history or multi-turn message array.
        Returns (sanitized_messages, all_findings, total_redactions).
        """
        sanitized_list = []
        all_findings = []
        total_redacted = 0

        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            if isinstance(content, str) and content:
                res = cls.sanitize(content)
                sanitized_list.append({"role": role, "content": res.clean_text})
                if res.findings:
                    all_findings.extend(res.findings)
                    total_redacted += res.redactions_count
            else:
                sanitized_list.append(dict(msg))

        return sanitized_list, all_findings, total_redacted

    @classmethod
    def seal_messages(
        cls,
        messages: List[Dict[str, str]],
        enclave_url: Optional[str] = None
    ) -> Tuple[List[Dict[str, str]], List[Dict[str, Any]], int, EnclaveSeal]:
        """
        Sanitizes an entire chat history or multi-turn message array and seals the composite payload.
        Returns (sanitized_messages, all_findings, total_redactions, seal).
        """
        sanitized_list, all_findings, total_redacted = cls.sanitize_messages(messages)
        composite_text = "||".join(m.get("content", "") for m in sanitized_list)
        composite_digest = hashlib.sha256(composite_text.encode("utf-8")).hexdigest()
        seal = cls.request_enclave_seal(composite_digest, enclave_url=enclave_url)
        return sanitized_list, all_findings, total_redacted, seal
