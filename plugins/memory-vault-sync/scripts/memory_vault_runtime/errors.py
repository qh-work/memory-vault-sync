"""Expected runtime failure categories shared by focused modules."""

from __future__ import annotations


class VaultSyncError(RuntimeError):
    """Base class for expected, user-actionable failures."""

    code = "sync_error"
    retryable = False


class ConfigurationError(VaultSyncError):
    code = "configuration"


class IdentityError(VaultSyncError):
    code = "identity"


class UnboundIdentityError(IdentityError):
    """No local workspace identity exists; another exact mode may be tried."""


class PrivacyError(VaultSyncError):
    code = "privacy"


class AuthenticationError(VaultSyncError):
    code = "authentication"


class OfflineError(VaultSyncError):
    code = "offline"
    retryable = True


class VerificationError(VaultSyncError):
    code = "verification"


class ConflictError(VaultSyncError):
    code = "conflict"


class StructuralRouteCorrectionRequired(ConflictError):
    code = "structural_route_correction_required"


class BusyError(VaultSyncError):
    code = "busy"
    retryable = True
