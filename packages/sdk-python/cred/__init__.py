"""Cred — credential delegation SDK for AI agents."""

from .client import AsyncCred, Cred
from .exceptions import (
    AgentRevokedException,
    ConsentRequiredError,
    CredError,
    RateLimitException,
    ScopeCeilingException,
)
from .identity import (
    AgentIdentity,
    CRED_PUBLIC_KEY_HEX,
    generate_agent_identity,
    verify_delegation_receipt,
)
from .models import DelegationResult, Connection

__all__ = [
    "Cred",
    "AsyncCred",
    "CredError",
    "ConsentRequiredError",
    "AgentRevokedException",
    "ScopeCeilingException",
    "RateLimitException",
    "AgentIdentity",
    "generate_agent_identity",
    "verify_delegation_receipt",
    "CRED_PUBLIC_KEY_HEX",
    "DelegationResult",
    "Connection",
]
