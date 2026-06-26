class PassGuardError(Exception):
    """Base exception for PassGuard."""


class InvalidPasswordError(PassGuardError):
    """Raised when the password input is invalid."""
