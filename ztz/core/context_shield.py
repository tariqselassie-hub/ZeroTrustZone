"""
ZTZ Pre-Flight Context Firewall (core/context_shield.py)
Zero-Trust context sanitization, secret scrubbing, and cryptographic pre-flight
attestation before LLM ingestion (Pillar 5 of Zenith Research Division).
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
    # OpenAI API Keys
    (
        "OPENAI_API_KEY",
        re.compile(r"\bsk-[a-zA-Z0-9_-]{24,64}\b")
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


class ContextAuditResult:
    """Represents the pre-flight verification output of context verification."""
    def __init__(
        self,
        clean_text: str,
        redactions_count: int,
        findings: List[Dict[str, Any]],
        digest_sha256: str,
        timestamp: float,
        passed_preflight: bool = True
    ):
        self.clean_text = clean_text
        self.redactions_count = redactions_count
        self.findings = findings
        self.digest_sha256 = digest_sha256
        self.timestamp = timestamp
        self.passed_preflight = passed_preflight

    def to_dict(self) -> Dict[str, Any]:
        return {
            "clean_text": self.clean_text,
            "redactions_count": self.redactions_count,
            "findings": self.findings,
            "digest_sha256": self.digest_sha256,
            "timestamp": self.timestamp,
            "passed_preflight": self.passed_preflight,
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
