"""Supported adapter plumbing, available since cred-auth 2.2.0.

These names/signatures are public and follow the SDK's major-version stability
contract. No framework imports, global token store, client ownership transfer or
framework exception translation lives here. Create a store per integration.
"""
from __future__ import annotations

import time
from datetime import datetime
from typing import Any, Optional

from .client import Cred

__all__ = ["resolve_client", "identity_kwargs", "agent_did", "expiry_epoch", "DelegationTokenStore"]


def resolve_client(agent_token: Optional[str], base_url: Optional[str], cred: Optional[Cred]) -> tuple[Cred, str]:
    """Use a caller-owned synchronous client, or build one from explicit config."""
    if cred is None:
        client = Cred(agent_token=agent_token, base_url=base_url)
        # Cred validates and refuses an absent URL before this point.
        assert base_url is not None
        return client, base_url
    if not isinstance(cred, Cred):
        raise TypeError("cred must be a synchronous cred.Cred client")
    if agent_token:
        raise ValueError("Pass agent_token or cred, not both")
    if base_url and base_url.rstrip("/") != cred.base_url:
        raise ValueError("base_url does not match the passed client's base_url")
    return cred, cred.base_url


def identity_kwargs(agent_identity: Any) -> dict[str, Any]:
    """Forward a configured signing identity without changing the unsigned call."""
    return {"agent_identity": agent_identity} if agent_identity is not None else {}


def agent_did(agent_identity: Any) -> str:
    """Cache binding for an optional signing identity."""
    return getattr(agent_identity, "did", "") or ""


def expiry_epoch(result: Any) -> float:
    """Use absolute expiry when available; otherwise relative expiry, or now."""
    expires_at = getattr(result, "expires_at", None)
    if isinstance(expires_at, datetime):
        return expires_at.timestamp()
    expires_in = getattr(result, "expires_in", 0)
    return time.time() + (expires_in if isinstance(expires_in, (int, float)) else 0)


class DelegationTokenStore:
    """In-process, per-instance handle-to-token storage, not persistent storage.

    Tokens are bound to server URL (trailing slashes ignored), agent DID and user.
    A lookup with user_id=None retains the adapters' single-user compatibility
    behavior: it skips only the user check. Multi-user tools must set user_id.
    Expiry is exclusive (now < expires_at); misses and expired entries are refused.
    Identical handles overwrite only within this store, matching adapter behavior.
    """

    def __init__(self, *, unknown_message: str = "Unknown or expired delegation: call the delegate tool first") -> None:
        self._entries: dict[str, tuple[str, float, str, str, Optional[str]]] = {}
        self._unknown_message = unknown_message

    def remember(self, delegation_id: str, token: str, expires_at: float, *,
                 base_url: str, agent_did: str, user_id: Optional[str] = None) -> None:
        """Remember a token and discard entries whose expiry has been reached."""
        now = time.time()
        for key in [k for k, entry in self._entries.items() if entry[1] <= now]:
            del self._entries[key]
        self._entries[delegation_id] = (token, expires_at, base_url.rstrip("/"), agent_did, user_id)

    def lookup(self, delegation_id: str, *, base_url: str, agent_did: str,
               user_id: Optional[str] = None) -> str:
        """Return a live matching token, or raise ValueError without disclosing it."""
        entry = self._entries.get(delegation_id)
        if entry is None or entry[1] <= time.time():
            self._entries.pop(delegation_id, None)
            raise ValueError(self._unknown_message)
        _, _, entry_base_url, entry_agent_did, entry_user_id = entry
        if (entry_base_url != base_url.rstrip("/") or entry_agent_did != agent_did
                or (user_id is not None and entry_user_id != user_id)):
            raise ValueError("This delegation was issued for a different server, agent or user")
        return entry[0]
