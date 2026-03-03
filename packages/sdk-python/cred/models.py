"""Cred SDK — Response model dataclasses."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class DelegationResult:
    """Result of a successful delegation request."""

    access_token: str
    token_type: str
    service: str
    scopes: list[str]
    delegation_id: str
    expires_in: Optional[int] = None


@dataclass
class Connection:
    """A user's active service connection."""

    slug: str
    scopes_granted: list[str]
    app_client_id: Optional[str] = None
    consented_at: Optional[str] = None
