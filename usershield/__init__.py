"""
UserShield: Sovereign Offline-First Zero-Trust Cryptographic Pre-Flight AI Firewall.
Pillar 5 of UserShield Project.
"""

from ztz.sdk.decorators import guard
from ztz.sdk.exceptions import UntrustedPayloadError, ZTZSecurityException

# Expose subpackages
from usershield import core
from usershield import lic
from usershield import runners
from usershield import sdk
from usershield import ui

__all__ = [
    "guard",
    "UntrustedPayloadError",
    "ZTZSecurityException",
    "core",
    "lic",
    "runners",
    "sdk",
    "ui",
]
