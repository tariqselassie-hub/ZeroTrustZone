"""
UserShield SDK Exceptions.
"""

class UserShieldSecurityException(Exception):
    """Base exception for all UserShield security lockdown events."""
    pass

class UntrustedPayloadError(UserShieldSecurityException):
    """Raised when a file fails cryptographic attestation before memory load."""
    pass
