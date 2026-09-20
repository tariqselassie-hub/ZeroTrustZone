"""
ZTZ SDK Exceptions.
"""

class ZTZSecurityException(Exception):
    """Base exception for all ZTZ security lockdown events."""
    pass

class UntrustedPayloadError(ZTZSecurityException):
    """Raised when a file fails cryptographic attestation before memory load."""
    pass
