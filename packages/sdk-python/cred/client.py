"""Cred SDK — Main client classes."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from urllib.parse import urlencode, urlparse

import httpx

from .exceptions import (
    AgentRevokedException,
    ConsentRequiredError,
    CredError,
    RateLimitException,
    ScopeCeilingException,
)
from .models import Connection, DelegationResult

DEFAULT_BASE_URL = "https://api.cred.ninja"
_LOCALHOSTS = {"localhost", "127.0.0.1", "::1"}


def _parse_expires_at(raw_value: Any, expires_in: int) -> datetime:
    if isinstance(raw_value, str):
        parsed_value = raw_value.replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(parsed_value)
        except ValueError:
            pass
    return datetime.now(timezone.utc) + timedelta(seconds=expires_in)


class _CredBase:
    def __init__(self, agent_token: str, base_url: str = DEFAULT_BASE_URL) -> None:
        if not agent_token:
            raise CredError("agent_token is required", "invalid_config", 0)
        self._agent_token = agent_token
        self._base_url = self._validate_base_url(base_url)

    @staticmethod
    def _validate_base_url(url: str) -> str:
        try:
            parsed = urlparse(url)
        except Exception:
            raise CredError(f'Invalid base_url: "{url}" — must be a valid HTTPS URL', "invalid_config", 0)

        if parsed.scheme == "https":
            return url.rstrip("/")

        if parsed.scheme == "http" and parsed.hostname in _LOCALHOSTS:
            return url.rstrip("/")

        raise CredError(
            "Invalid base_url: must use HTTPS except for localhost development URLs",
            "invalid_config",
            0,
        )

    def _auth_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._agent_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    @staticmethod
    def _build_delegation_result(data: dict[str, Any]) -> DelegationResult:
        raw_expires_in = data.get("expires_in")
        expires_in = int(raw_expires_in) if raw_expires_in is not None else 900
        expires_at = _parse_expires_at(data.get("expires_at") or data.get("expiresAt"), expires_in)
        return DelegationResult(
            access_token=data["access_token"],
            token_type=data["token_type"],
            expires_in=expires_in,
            expires_at=expires_at,
            service=data["service"],
            scopes=data["scopes"],
            delegation_id=data["delegation_id"],
            receipt=data.get("receipt"),
        )

    @staticmethod
    def _build_connections(data: dict[str, Any]) -> list[Connection]:
        connections = data.get("connections", [])
        return [
            Connection(
                slug=connection["slug"],
                scopes_granted=connection["scopesGranted"],
                app_client_id=connection.get("appClientId"),
                consented_at=connection.get("consentedAt"),
            )
            for connection in connections
        ]

    @staticmethod
    def _error_payload(response: httpx.Response) -> tuple[dict[str, Any], str, str]:
        body: dict[str, Any] = {}
        try:
            parsed = response.json()
            if isinstance(parsed, dict):
                body = parsed
        except Exception:
            pass

        message = body.get("message") or body.get("error") or f"Request failed with status {response.status_code}"
        error_code = str(body.get("error", "unknown"))
        return body, str(message), error_code

    def _handle_response(self, response: httpx.Response) -> Any:
        if response.status_code == 204:
            return {}

        if response.is_success:
            return response.json()

        body, message, error_code = self._error_payload(response)

        if response.status_code == 403 and error_code == "consent_required":
            raise ConsentRequiredError(message, str(body.get("consent_url", "")))
        if response.status_code == 403 and error_code == "agent_revoked":
            raise AgentRevokedException(message)
        if response.status_code == 403 and error_code == "scope_ceiling_exceeded":
            raise ScopeCeilingException(message)
        if response.status_code == 429 and error_code == "rate_limited":
            raise RateLimitException(message)

        raise CredError(message, error_code, response.status_code)

    def get_consent_url(
        self,
        service: str,
        user_id: str,
        app_client_id: str,
        scopes: list[str],
        redirect_uri: str,
    ) -> str:
        params = urlencode(
            {
                "app_client_id": app_client_id,
                "scopes": ",".join(scopes),
                "redirect_uri": redirect_uri,
            },
        )
        return f"{self._base_url}/api/connect/{service}/authorize?{params}"


class Cred(_CredBase):
    """Synchronous client for the Cred credential delegation API."""

    def __init__(
        self,
        agent_token: str,
        base_url: str = DEFAULT_BASE_URL,
    ) -> None:
        super().__init__(agent_token=agent_token, base_url=base_url)
        self._client = httpx.Client(
            base_url=self._base_url,
            headers=self._auth_headers(),
            timeout=30.0,
        )

    def delegate(
        self,
        service: str,
        user_id: str,
        app_client_id: Optional[str] = None,
        scopes: Optional[list[str]] = None,
        agent_did: Optional[str] = None,
    ) -> DelegationResult:
        body: dict[str, Any] = {
            "service": service,
            "user_id": user_id,
        }
        if app_client_id:
            body["appClientId"] = app_client_id
        if scopes:
            body["scopes"] = scopes
        if agent_did:
            body["agent_did"] = agent_did

        data = self._request_json("POST", "/api/v1/delegate", body)
        return self._build_delegation_result(data)

    def list_connections(
        self,
        user_id: str,
        app_client_id: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        params: dict[str, str] = {"user_id": user_id}
        if app_client_id:
            params["app_client_id"] = app_client_id

        data = self._request_json("GET", f"/api/v1/connections?{urlencode(params)}")
        return list(data.get("connections", []))

    def get_user_connections(
        self,
        user_id: str,
        app_client_id: Optional[str] = None,
    ) -> list[Connection]:
        return self._build_connections(
            {"connections": self.list_connections(user_id, app_client_id)},
        )

    def revoke(
        self,
        service: str,
        user_id: str,
        app_client_id: Optional[str] = None,
    ) -> None:
        params: dict[str, str] = {"user_id": user_id}
        if app_client_id:
            params["app_client_id"] = app_client_id

        self._request_no_content("DELETE", f"/api/v1/connections/{service}?{urlencode(params)}")

    def revoke_agent(self, agent_id: str) -> None:
        self._request_no_content("POST", f"/api/v1/agents/{agent_id}/revoke-all", {})

    def _request_json(self, method: str, path: str, body: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        response = self._client.request(method, path, json=body)
        payload = self._handle_response(response)
        if not isinstance(payload, dict):
            raise CredError("Expected JSON object response", "invalid_response", response.status_code)
        return payload

    def _request_no_content(self, method: str, path: str, body: Optional[dict[str, Any]] = None) -> None:
        response = self._client.request(method, path, json=body)
        if response.status_code != 204:
            self._handle_response(response)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "Cred":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


class AsyncCred(_CredBase):
    """Asynchronous client for the Cred credential delegation API."""

    def __init__(
        self,
        agent_token: str,
        base_url: str = DEFAULT_BASE_URL,
    ) -> None:
        super().__init__(agent_token=agent_token, base_url=base_url)
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            headers=self._auth_headers(),
            timeout=30.0,
        )

    async def delegate(
        self,
        service: str,
        user_id: str,
        app_client_id: Optional[str] = None,
        scopes: Optional[list[str]] = None,
        agent_did: Optional[str] = None,
    ) -> DelegationResult:
        body: dict[str, Any] = {
            "service": service,
            "user_id": user_id,
        }
        if app_client_id:
            body["appClientId"] = app_client_id
        if scopes:
            body["scopes"] = scopes
        if agent_did:
            body["agent_did"] = agent_did

        data = await self._request_json("POST", "/api/v1/delegate", body)
        return self._build_delegation_result(data)

    async def list_connections(
        self,
        user_id: str,
        app_client_id: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        params: dict[str, str] = {"user_id": user_id}
        if app_client_id:
            params["app_client_id"] = app_client_id

        data = await self._request_json("GET", f"/api/v1/connections?{urlencode(params)}")
        return list(data.get("connections", []))

    async def get_user_connections(
        self,
        user_id: str,
        app_client_id: Optional[str] = None,
    ) -> list[Connection]:
        return self._build_connections(
            {"connections": await self.list_connections(user_id, app_client_id)},
        )

    async def revoke(
        self,
        service: str,
        user_id: str,
        app_client_id: Optional[str] = None,
    ) -> None:
        params: dict[str, str] = {"user_id": user_id}
        if app_client_id:
            params["app_client_id"] = app_client_id

        await self._request_no_content("DELETE", f"/api/v1/connections/{service}?{urlencode(params)}")

    async def revoke_agent(self, agent_id: str) -> None:
        await self._request_no_content("POST", f"/api/v1/agents/{agent_id}/revoke-all", {})

    async def _request_json(self, method: str, path: str, body: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        response = await self._client.request(method, path, json=body)
        payload = self._handle_response(response)
        if not isinstance(payload, dict):
            raise CredError("Expected JSON object response", "invalid_response", response.status_code)
        return payload

    async def _request_no_content(self, method: str, path: str, body: Optional[dict[str, Any]] = None) -> None:
        response = await self._client.request(method, path, json=body)
        if response.status_code != 204:
            self._handle_response(response)

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "AsyncCred":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()
