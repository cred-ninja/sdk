"""Cred SDK — Exception classes."""


class CredError(Exception):
    """Base exception for all Cred API errors."""

    def __init__(self, message: str, code: str, status_code: int) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(message={str(self)!r}, code={self.code!r}, status_code={self.status_code})"


class ConsentRequiredError(CredError):
    """Raised when a user has not yet consented to a service.

    The ``consent_url`` attribute contains the URL to redirect the user to
    complete the OAuth consent flow.
    """

    def __init__(self, message: str, consent_url: str) -> None:
        super().__init__(message, "consent_required", 403)
        self.consent_url = consent_url


class AgentRevokedException(CredError):
    """Raised when the agent token has been revoked server-side."""

    def __init__(self, message: str) -> None:
        super().__init__(message, "agent_revoked", 403)


class ScopeCeilingException(CredError):
    """Raised when requested scopes exceed the agent's ceiling."""

    def __init__(self, message: str) -> None:
        super().__init__(message, "scope_ceiling_exceeded", 403)


class RateLimitException(CredError):
    """Raised when the API rate limits the request."""

    def __init__(self, message: str) -> None:
        super().__init__(message, "rate_limited", 429)
