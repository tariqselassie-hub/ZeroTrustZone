"""
UserShield: Offline-First Zero-Trust Cryptographic Pre-Flight Firewall for Local AI Weights & Context.
"""

__version__ = "0.1.0"
__author__ = "Zenith Research Division"

from usershield.core.crypto import UserShieldSigner, UserShieldVerifier
from usershield.core.trust_store import TrustStore
from usershield.core.validator import PreFlightValidator
from usershield.core.context_shield import ContextShield, ContextAuditResult
from usershield.lic.fingerprint import HardwareFingerprint
from usershield.lic.manager import LicenseManager

__all__ = [
    "UserShieldSigner",
    "UserShieldVerifier",
    "TrustStore",
    "PreFlightValidator",
    "ContextShield",
    "ContextAuditResult",
    "HardwareFingerprint",
    "LicenseManager",
]

