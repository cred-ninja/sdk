"""Cred SDK — Response model dataclasses."""

from __future__ import annotations

from datetime import datetime
from dataclasses import dataclass
from typing import Optional


@dataclass
class DelegationResult:
    """Result of a successful delegation request."""

    access_token: str
    token_type: str
    expires_in: int
    expires_at: datetime
    service: str
    scopes: list[str]
    delegation_id: str
    receipt: Optional[str] = None


@dataclass
class DelegationHandleResult:
    """Result of a successful brokered delegation request."""

    token_type: str
    expires_in: int
    expires_at: datetime
    service: str
    scopes: list[str]
    delegation_id: str
    user_id: str
    receipt: Optional[str] = None


@dataclass
class BrokeredUseResult:
    """Result of a brokered upstream API call."""

    status: int
    ok: bool
    content_type: str
    body: object
    truncated: bool = False
    truncated_at: Optional[int] = None


@dataclass
class Connection:
    """A user's active service connection."""

    slug: str
    scopes_granted: list[str]
    app_client_id: Optional[str] = None
    consented_at: Optional[str] = None
