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
    DpopSigningIdentity,
    create_dpop_proof,
    generate_agent_identity,
    verify_delegation_receipt,
)
from .jcs import CanonicalJsonError, canonical_json
from .models import BrokeredUseResult, Connection, DelegationHandleResult, DelegationResult

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
    "create_dpop_proof",
    "DpopSigningIdentity",
    "canonical_json",
    "CanonicalJsonError",
    "verify_delegation_receipt",
    "CRED_PUBLIC_KEY_HEX",
    "BrokeredUseResult",
    "DelegationHandleResult",
    "DelegationResult",
    "Connection",
]
