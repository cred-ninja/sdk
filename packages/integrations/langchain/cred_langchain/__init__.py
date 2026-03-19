"""Cred LangChain integration."""

from pydantic import SecretStr

from cred import Cred
from .toolkit import CredToolkit
from .tools import CredDelegateTool, CredStatusTool, CredRevokeTool


def secret_from_cred(
    service: str,
    user_id: str,
    cred: Cred,
    scopes: list[str] | None = None,
    app_client_id: str | None = None,
) -> SecretStr:
    """Drop-in replacement for secret_from_env() backed by Cred delegation."""
    result = cred.delegate(
        service=service,
        user_id=user_id,
        app_client_id=app_client_id,
        scopes=scopes,
    )
    return SecretStr(result.access_token)

__all__ = [
    "CredToolkit",
    "CredDelegateTool",
    "CredStatusTool",
    "CredRevokeTool",
    "secret_from_cred",
]
