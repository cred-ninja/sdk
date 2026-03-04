"""Cred SDK — Main client class.

Uses httpx for HTTP. Synchronous interface with async-ready httpx transport.
Python 3.9+ compatible.
"""

from __future__ import annotations

from typing import Any, Optional
from urllib.parse import urlencode

import httpx

from .exceptions import CredError, ConsentRequiredError
from .models import Connection, DelegationResult

DEFAULT_BASE_URL = "https://api.cred.ninja"


class Cred:
    """Client for the Cred credential delegation API.

    Args:
        agent_token: Agent token issued by Cred (starts with ``cred_at_``).
        base_url: Override the API base URL. Defaults to ``https://api.cred.ninja``.

    Example::

        from cred import Cred, ConsentRequiredError

        cred = Cred(agent_token=os.environ["CRED_AGENT_TOKEN"])

        try:
            result = cred.delegate(
                service="google",
                user_id="user_123",
                app_client_id="my_app",
                scopes=["calendar.readonly"],
            )
            print(result.access_token)
        except ConsentRequiredError as e:
            redirect_user_to(e.consent_url)
    """

    @staticmethod
    def _validate_base_url(url: str) -> str:
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
        except Exception:
            raise CredError(f'Invalid base_url: "{url}" — must be a valid HTTPS URL', "invalid_config", 0)
        if parsed.scheme != "https":
            raise CredError(
                "Invalid base_url: must use HTTPS — HTTP is not permitted (agent tokens would be sent in plaintext)",
                "invalid_config",
                0,
            )
        return url.rstrip("/")

    def __init__(
        self,
        agent_token: str,
        base_url: str = DEFAULT_BASE_URL,
    ) -> None:
        if not agent_token:
            raise CredError("agent_token is required", "invalid_config", 0)
        self._agent_token = agent_token
        self._base_url = self._validate_base_url(base_url)
        self._client = httpx.Client(
            base_url=self._base_url,
            headers=self._auth_headers(),
            timeout=30.0,
        )

    def _auth_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._agent_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    # ── Core methods ──────────────────────────────────────────────────────────

    def delegate(
        self,
        service: str,
        user_id: str,
        app_client_id: str,
        scopes: Optional[list[str]] = None,
        agent_did: Optional[str] = None,
    ) -> DelegationResult:
        """Get a delegated access token for a service on behalf of a user.

        ``app_client_id`` is required and should be baked into the agent's
        deployment config — agents always know which app they belong to.
        User-facing consent flows without app context belong in the portal,
        not the SDK.

        Args:
            service: The service slug (e.g., "google", "github").
            user_id: The user ID to delegate on behalf of.
            app_client_id: The app client ID.
            scopes: Optional list of scopes to request.
            agent_did: Optional agent DID for receipt generation.

        Raises:
            ConsentRequiredError: User has not yet connected this service.
                ``err.consent_url`` contains the URL to redirect the user.
            CredError: Any other API error.
        """
        body: dict[str, Any] = {
            "service": service,
            "user_id": user_id,
            "appClientId": app_client_id,
        }
        if scopes:
            body["scopes"] = scopes
        if agent_did:
            body["agent_did"] = agent_did

        data = self._post("/api/v1/delegate", body)
        return DelegationResult(
            access_token=data["access_token"],
            token_type=data["token_type"],
            expires_in=data.get("expires_in"),
            service=data["service"],
            scopes=data["scopes"],
            delegation_id=data["delegation_id"],
            receipt=data.get("receipt"),
        )

    def get_user_connections(
        self,
        user_id: str,
        app_client_id: Optional[str] = None,
    ) -> list[Connection]:
        """List all active service connections for a user.

        Args:
            user_id: The user whose connections to list.
            app_client_id: Optional — filter to a specific app.
        """
        params: dict[str, str] = {"user_id": user_id}
        if app_client_id:
            params["app_client_id"] = app_client_id

        data = self._get(f"/api/v1/connections?{urlencode(params)}")
        return [
            Connection(
                slug=c["slug"],
                scopes_granted=c["scopesGranted"],
                app_client_id=c.get("appClientId"),
                consented_at=c.get("consentedAt"),
            )
            for c in data.get("connections", [])
        ]

    def get_consent_url(
        self,
        service: str,
        user_id: str,
        app_client_id: str,
        scopes: list[str],
        redirect_uri: str,
    ) -> str:
        """Build a consent URL to redirect a user to connect a service.

        Pure URL construction — no HTTP call.
        """
        params = urlencode({
            "app_client_id": app_client_id,
            "scopes": ",".join(scopes),
            "redirect_uri": redirect_uri,
        })
        return f"{self._base_url}/api/connect/{service}/authorize?{params}"

    def revoke(
        self,
        service: str,
        user_id: str,
        app_client_id: Optional[str] = None,
    ) -> None:
        """Revoke a user's connection to a service.

        Raises:
            CredError: If no active connection found or other API error.
        """
        params: dict[str, str] = {"user_id": user_id}
        if app_client_id:
            params["app_client_id"] = app_client_id

        self._delete(f"/api/v1/connections/{service}?{urlencode(params)}")

    # ── Private HTTP helpers ──────────────────────────────────────────────────

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        response = self._client.post(path, json=body)
        return self._handle_response(response)

    def _get(self, path: str) -> dict[str, Any]:
        response = self._client.get(path)
        return self._handle_response(response)

    def _delete(self, path: str) -> None:
        response = self._client.delete(path)
        if response.status_code == 204:
            return
        self._handle_response(response)

    def _handle_response(self, response: httpx.Response) -> dict[str, Any]:
        if response.is_success:
            return response.json()

        body: dict[str, Any] = {}
        try:
            body = response.json()
        except Exception:
            pass

        message: str = (
            body.get("message")
            or body.get("error")
            or f"Request failed with status {response.status_code}"
        )

        if response.status_code == 403 and body.get("error") == "consent_required":
            consent_url = body.get("consent_url", "")
            raise ConsentRequiredError(message, consent_url)

        raise CredError(message, str(body.get("error", "unknown")), response.status_code)

    def close(self) -> None:
        """Close the underlying HTTP client. Call when done if not using as context manager."""
        self._client.close()

    def __enter__(self) -> "Cred":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
