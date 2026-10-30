"""Cred Semantic Kernel plugin tests.

Tests focus on: plugin construction, kernel_function metadata, invocation,
output JSON, and error propagation. The Cred client is mocked -- no real HTTP.
"""

import json
import time
from datetime import datetime, timedelta, timezone
from typing import Optional
import pytest
import httpx
from unittest.mock import MagicMock, patch

from cred import BrokeredUseResult, DelegationHandleResult, DelegationResult, ConsentRequiredError, CredError
from cred import generate_agent_identity
from cred_semantic_kernel import CredPlugin
from cred_semantic_kernel.plugin import _remember_delegation_token

TOKEN = "cred_at_test"
USER_ID = "user_123"
APP_CLIENT_ID = "app_1"
BASE_URL = "https://cred.example.com"
HANDLE_TOKEN = "eyJ.delegation.token-secret"


def make_delegation_result(
    *,
    access_token: str = "at",
    token_type: str = "Bearer",
    expires_in: int = 3600,
    service: str = "google",
    scopes: Optional[list[str]] = None,
    delegation_id: str = "del_1",
) -> DelegationResult:
    return DelegationResult(
        access_token=access_token,
        token_type=token_type,
        expires_in=expires_in,
        expires_at=datetime(2026, 3, 1, tzinfo=timezone.utc),
        service=service,
        scopes=scopes or [],
        delegation_id=delegation_id,
    )


def make_handle_result(
    *,
    token_type: str = "DPoP",
    token: str = HANDLE_TOKEN,
    expires_in: int = 3600,
    service: str = "google",
    user_id: str = USER_ID,
    scopes: Optional[list[str]] = None,
    delegation_id: str = "del_handle",
) -> DelegationHandleResult:
    return DelegationHandleResult(
        token_type=token_type,
        token=token,
        jkt="jkt_test",
        expires_in=expires_in,
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=expires_in),
        service=service,
        user_id=user_id,
        scopes=scopes or [],
        delegation_id=delegation_id,
    )


@pytest.fixture
def mock_cred():
    return MagicMock()


@pytest.fixture
def plugin(mock_cred):
    with patch("cred_semantic_kernel.plugin.Cred", return_value=mock_cred):
        return CredPlugin(
            agent_token=TOKEN,
            user_id=USER_ID,
            base_url=BASE_URL,
            app_client_id=APP_CLIENT_ID,
        )


# -- constructor ---------------------------------------------------------------

class TestConstructor:
    def test_creates_cred_client(self):
        with patch("cred_semantic_kernel.plugin.Cred") as mock_cls:
            CredPlugin(
                agent_token=TOKEN,
                user_id=USER_ID,
                app_client_id=APP_CLIENT_ID,
                base_url="http://localhost:3001",
            )
            mock_cls.assert_called_once_with(
                agent_token=TOKEN,
                base_url="http://localhost:3001",
            )

    def test_stores_user_id(self, plugin):
        assert plugin._user_id == USER_ID

    def test_stores_app_client_id(self, plugin):
        assert plugin._app_client_id == APP_CLIENT_ID

    def test_stores_token_format(self, mock_cred):
        with patch("cred_semantic_kernel.plugin.Cred", return_value=mock_cred):
            plugin = CredPlugin(
                agent_token=TOKEN,
                user_id=USER_ID,
                app_client_id=APP_CLIENT_ID,
                base_url=BASE_URL,
                token_format="handle",
            )
        assert plugin._token_format == "handle"


# -- kernel_function metadata --------------------------------------------------

class TestKernelFunction:
    def test_delegate_has_kernel_function_metadata(self, plugin):
        # kernel_function decorator adds __kernel_function_metadata__
        assert hasattr(plugin.delegate, "__kernel_function__")

    def test_delegate_is_callable(self, plugin):
        assert callable(plugin.delegate)

    def test_use_is_callable(self, plugin):
        assert callable(plugin.use)


# -- delegate invocation -------------------------------------------------------

class TestDelegate:
    def test_returns_json_with_access_token(self, plugin, mock_cred):
        mock_cred.delegate.return_value = make_delegation_result(
            access_token="ya29.mock",
            expires_in=3600,
            service="google",
            scopes=["calendar.readonly"],
            delegation_id="del_abc",
        )

        result_str = plugin.delegate(service="google", scopes="calendar.readonly")
        result = json.loads(result_str)

        assert result["access_token"] == "ya29.mock"
        assert result["token_type"] == "Bearer"
        assert result["expires_in"] == 3600
        assert result["service"] == "google"
        assert result["scopes"] == ["calendar.readonly"]
        assert result["delegation_id"] == "del_abc"

    def test_handle_mode_returns_json_without_access_token(self, mock_cred):
        identity = generate_agent_identity()
        mock_cred.delegate_handle.return_value = make_handle_result(
            scopes=["calendar.readonly"],
            delegation_id="del_brokered",
        )
        with patch("cred_semantic_kernel.plugin.Cred", return_value=mock_cred):
            plugin = CredPlugin(
                agent_token=TOKEN,
                user_id=USER_ID,
                app_client_id=APP_CLIENT_ID,
                base_url=BASE_URL,
                token_format="handle",
                agent_identity=identity,
            )

        result_str = plugin.delegate(service="google", scopes="calendar.readonly")
        result = json.loads(result_str)

        assert "access_token" not in result
        assert "token" not in result
        assert HANDLE_TOKEN not in result_str
        assert result["token_type"] == "DPoP"
        assert result["delegation_id"] == "del_brokered"
        mock_cred.delegate_handle.assert_called_once_with(
            service="google",
            user_id=USER_ID,
            app_client_id=APP_CLIENT_ID,
            scopes=["calendar.readonly"],
            agent_identity=identity,
        )

    def test_use_brokers_request(self, plugin, mock_cred):
        identity = generate_agent_identity()
        plugin._agent_identity = identity
        _remember_delegation_token("del_brokered", HANDLE_TOKEN, time.time() + 600)
        mock_cred.use.return_value = BrokeredUseResult(
            status=200,
            ok=True,
            content_type="application/json",
            body={"items": []},
        )

        result_str = plugin.use(
            delegation_id="del_brokered",
            url="https://www.googleapis.com/calendar/v3/calendars/primary/events",
            method="GET",
        )
        result = json.loads(result_str)

        assert result["ok"] is True
        assert result["body"] == {"items": []}
        mock_cred.use.assert_called_once_with(
            HANDLE_TOKEN,
            url="https://www.googleapis.com/calendar/v3/calendars/primary/events",
            method="GET",
            body=None,
            extra_headers=None,
            agent_identity=identity,
        )

    def test_use_requires_agent_identity(self, plugin, mock_cred):
        _remember_delegation_token("del_noid", HANDLE_TOKEN, time.time() + 600)

        with pytest.raises(ValueError, match="agent_identity"):
            plugin.use(delegation_id="del_noid", url="https://www.googleapis.com/x", method="GET")
        mock_cred.use.assert_not_called()

    def test_use_rejects_unknown_or_expired_delegation(self, plugin, mock_cred):
        plugin._agent_identity = generate_agent_identity()
        _remember_delegation_token("del_old", HANDLE_TOKEN, time.time() - 1)

        for delegation_id in ("del_never_seen", "del_old"):
            with pytest.raises(ValueError, match="Unknown or expired delegation"):
                plugin.use(delegation_id=delegation_id, url="https://www.googleapis.com/x", method="GET")
        mock_cred.use.assert_not_called()

    def test_passes_service_user_app_to_cred(self, plugin, mock_cred):
        mock_cred.delegate.return_value = make_delegation_result(service="github")

        plugin.delegate(service="github", scopes="repo")

        mock_cred.delegate.assert_called_once_with(
            service="github",
            user_id=USER_ID,
            app_client_id=APP_CLIENT_ID,
            scopes=["repo"],
        )

    def test_parses_comma_separated_scopes(self, plugin, mock_cred):
        mock_cred.delegate.return_value = make_delegation_result(
            scopes=["calendar.readonly", "calendar.events"],
        )

        plugin.delegate(service="google", scopes="calendar.readonly, calendar.events")

        call_kwargs = mock_cred.delegate.call_args.kwargs
        assert call_kwargs["scopes"] == ["calendar.readonly", "calendar.events"]

    def test_passes_none_scopes_when_empty_string(self, plugin, mock_cred):
        mock_cred.delegate.return_value = make_delegation_result()

        plugin.delegate(service="google", scopes="")

        call_kwargs = mock_cred.delegate.call_args.kwargs
        assert call_kwargs["scopes"] is None

    def test_propagates_consent_required_error(self, plugin, mock_cred):
        mock_cred.delegate.side_effect = ConsentRequiredError(
            "User has not consented",
            "https://cred.example.com/connect/google?user_id=user_123&app_client_id=app_1",
        )

        with pytest.raises(ConsentRequiredError) as exc_info:
            plugin.delegate(service="google", scopes="calendar.readonly")

        assert "/connect/google" in exc_info.value.consent_url

    def test_propagates_cred_error_on_401(self, plugin, mock_cred):
        mock_cred.delegate.side_effect = CredError(
            "Invalid agent token", "unauthorized", 401
        )

        with pytest.raises(CredError) as exc_info:
            plugin.delegate(service="google", scopes="")

        assert exc_info.value.status_code == 401

    def test_real_cred_client_delegates_against_mock_server(self):
        plugin = CredPlugin(
            agent_token=TOKEN,
            user_id=USER_ID,
            base_url=BASE_URL,
            app_client_id=APP_CLIENT_ID,
        )

        with patch("httpx.Client.request", return_value=httpx.Response(
            200,
            json={
                "access_token": "ya29.real",
                "token_type": "Bearer",
                "expires_in": 3600,
                "service": "google",
                "scopes": ["calendar.readonly"],
                "delegation_id": "del_real",
            },
        )) as request_mock:
            result_str = plugin.delegate(service="google", scopes="calendar.readonly")

        payload = json.loads(result_str)
        assert payload["access_token"] == "ya29.real"
        assert request_mock.called


# ── DPoP: agent_identity reaches delegate_handle() and use() ─────────────────

import base64 as _b64
import hashlib as _hashlib

from cred import canonical_json, generate_agent_identity


def _fake_cred_server(calls: list):
    """httpx.Client.request stand-in that records each request's headers."""
    def request(self, method, path, json=None, headers=None, **kwargs):
        calls.append({"path": path, "body": json, "headers": headers or {}})
        if path == "/api/v1/delegate":
            return httpx.Response(200, json={
                "access_token": HANDLE_TOKEN,
                "token_type": "DPoP",
                "cnf": {"jkt": "jkt_test"},
                "expires_in": 900,
                "service": "google",
                "user_id": USER_ID,
                "scopes": ["calendar.readonly"],
                "delegation_id": "del_bound",
            })
        return httpx.Response(200, json={"status": 200, "ok": True, "contentType": "application/json", "body": {}})
    return request


def _dpop_claims(proof: str) -> dict:
    segment = proof.split(".")[1]
    return json.loads(_b64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))


def _assert_dpop_bound(calls: list, identity, outputs: list) -> None:
    delegate_call, use_call = calls
    assert delegate_call["path"] == "/api/v1/delegate"
    assert delegate_call["body"]["agent_did"] == identity.did
    delegate_claims = _dpop_claims(delegate_call["headers"]["DPoP"])
    assert delegate_claims["htu"] == f"{BASE_URL}/api/v1/delegate"
    assert "ath" not in delegate_claims
    assert "cred_req" not in delegate_claims

    assert use_call["path"] == "/api/v1/use"
    use_claims = _dpop_claims(use_call["headers"]["DPoP"])
    assert use_claims["htu"] == f"{BASE_URL}/api/v1/use"
    expected_ath = _b64.urlsafe_b64encode(_hashlib.sha256(HANDLE_TOKEN.encode()).digest()).rstrip(b"=").decode()
    assert use_claims["ath"] == expected_ath
    # cred_req: the proof commits to the exact /api/v1/use body sent.
    expected_req = _b64.urlsafe_b64encode(
        _hashlib.sha256(canonical_json(use_call["body"]).encode("utf-8")).digest(),
    ).rstrip(b"=").decode()
    assert use_claims["cred_req"] == expected_req
    assert use_call["headers"]["Authorization"] == f"DPoP {HANDLE_TOKEN}"
    assert "delegation_id" not in use_call["body"]

    # The key never reaches what the model sees.
    for output in outputs:
        assert identity.private_key.hex() not in output
        assert HANDLE_TOKEN not in output
        assert "agent_identity" not in output


class TestAgentIdentity:
    def test_agent_identity_reaches_delegate_handle_and_use(self):
        import inspect

        identity = generate_agent_identity()
        plugin = CredPlugin(
            agent_token=TOKEN, user_id=USER_ID, app_client_id=APP_CLIENT_ID,
            base_url=BASE_URL, token_format="handle", agent_identity=identity,
        )
        for fn in (plugin.delegate, plugin.use):
            assert "agent_identity" not in inspect.signature(fn).parameters
        calls: list = []
        with patch("httpx.Client.request", _fake_cred_server(calls)):
            delegated = plugin.delegate(service="google", scopes="calendar.readonly")
            used = plugin.use(delegation_id="del_bound", url="https://www.googleapis.com/x", method="GET")
        _assert_dpop_bound(calls, identity, [delegated, used])
