"""Cred CrewAI Tool tests.

Mocks the Cred client — no real HTTP, no real API calls.
Tests focus on: tool configuration, naming, input schema, output format, error propagation.
"""

import warnings
warnings.filterwarnings("ignore", category=UserWarning)

import json
from datetime import datetime, timezone
from typing import Optional

import pytest
import httpx
from unittest.mock import MagicMock, patch

from cred import BrokeredUseResult, DelegationHandleResult, DelegationResult, ConsentRequiredError
from cred_crewai import CredTool, CredUseTool

TOKEN = "cred_at_test"
USER_ID = "user_123"
APP_CLIENT_ID = "app_1"
BASE_URL = "https://cred.example.com"


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
    token_type: str = "Delegation",
    expires_in: int = 3600,
    service: str = "google",
    user_id: str = USER_ID,
    scopes: Optional[list[str]] = None,
    delegation_id: str = "del_handle",
) -> DelegationHandleResult:
    return DelegationHandleResult(
        token_type=token_type,
        expires_in=expires_in,
        expires_at=datetime(2026, 3, 1, tzinfo=timezone.utc),
        service=service,
        user_id=user_id,
        scopes=scopes or [],
        delegation_id=delegation_id,
    )


@pytest.fixture
def mock_cred():
    return MagicMock()


@pytest.fixture
def tool(mock_cred):
    t = CredTool(
        agent_token=TOKEN,
        user_id=USER_ID,
        service="google",
        app_client_id=APP_CLIENT_ID,
        base_url=BASE_URL,
        scopes=["calendar.readonly"],
    )
    t._cred = mock_cred
    return t


# ── constructor & configuration ───────────────────────────────────────────────

class TestConstructor:
    def test_sets_service_from_param(self):
        t = CredTool(
            agent_token=TOKEN,
            user_id=USER_ID,
            service="github",
            app_client_id=APP_CLIENT_ID,
            base_url=BASE_URL,
        )
        assert t._service == "github"
        assert "github" in t.name

    def test_dynamic_name_includes_service(self):
        google_tool = CredTool(
            agent_token=TOKEN,
            user_id=USER_ID,
            service="google-calendar",
            app_client_id=APP_CLIENT_ID,
            base_url=BASE_URL,
        )
        assert google_tool.name == "cred_google_calendar_delegate"

    def test_dynamic_description_includes_service(self):
        t = CredTool(
            agent_token=TOKEN,
            user_id=USER_ID,
            service="github",
            app_client_id=APP_CLIENT_ID,
            base_url=BASE_URL,
        )
        assert "github" in t.description
        assert "access token" in t.description

    def test_handle_mode_description_mentions_handle(self):
        t = CredTool(
            agent_token=TOKEN,
            user_id=USER_ID,
            service="google",
            app_client_id=APP_CLIENT_ID,
            base_url=BASE_URL,
            token_format="handle",
        )
        assert "delegation handle" in t.description

    def test_stores_user_id(self):
        t = CredTool(
            agent_token=TOKEN,
            user_id="user_456",
            service="google",
            app_client_id=APP_CLIENT_ID,
            base_url=BASE_URL,
        )
        assert t._user_id == "user_456"

    def test_stores_scopes(self):
        scopes = ["calendar.readonly", "calendar.events"]
        t = CredTool(
            agent_token=TOKEN,
            user_id=USER_ID,
            service="google",
            app_client_id=APP_CLIENT_ID,
            base_url=BASE_URL,
            scopes=scopes,
        )
        assert t._scopes == scopes

    def test_defaults_scopes_to_empty_list(self):
        t = CredTool(
            agent_token=TOKEN,
            user_id=USER_ID,
            service="google",
            app_client_id=APP_CLIENT_ID,
            base_url=BASE_URL,
        )
        assert t._scopes == []

    def test_custom_base_url(self):
        with patch("cred_crewai.tool.Cred") as mock_cred_class:
            CredTool(
                agent_token=TOKEN,
                user_id=USER_ID,
                service="google",
                app_client_id=APP_CLIENT_ID,
                base_url="http://localhost:3001",
            )
            mock_cred_class.assert_called_once_with(
                agent_token=TOKEN,
                base_url="http://localhost:3001",
            )


# ── _run() ────────────────────────────────────────────────────────────────────

class TestRun:
    def test_returns_access_token_string(self, tool, mock_cred):
        mock_cred.delegate.return_value = make_delegation_result(
            access_token="ya29.mock",
            expires_in=3600,
            service="google",
            scopes=["calendar.readonly"],
            delegation_id="del_abc",
        )

        result = tool._run()

        assert result == "ya29.mock"
        assert isinstance(result, str)

    def test_handle_mode_returns_json_without_access_token(self, mock_cred):
        t = CredTool(
            agent_token=TOKEN,
            user_id=USER_ID,
            service="google",
            app_client_id=APP_CLIENT_ID,
            base_url=BASE_URL,
            scopes=["calendar.readonly"],
            token_format="handle",
        )
        t._cred = mock_cred
        mock_cred.delegate_handle.return_value = make_handle_result(
            scopes=["calendar.readonly"],
            delegation_id="del_brokered",
        )

        result = t._run()
        data = json.loads(result)

        assert "access_token" not in data
        assert data["delegation_id"] == "del_brokered"
        mock_cred.delegate_handle.assert_called_once_with(
            service="google",
            user_id=USER_ID,
            app_client_id=APP_CLIENT_ID,
            scopes=["calendar.readonly"],
        )

    def test_passes_service_user_app_client_id(self, tool, mock_cred):
        mock_cred.delegate.return_value = make_delegation_result()

        tool._run()

        mock_cred.delegate.assert_called_once_with(
            service="google",
            user_id=USER_ID,
            app_client_id=APP_CLIENT_ID,
            scopes=["calendar.readonly"],
        )

    def test_passes_scopes_when_configured(self, tool, mock_cred):
        tool._scopes = ["calendar.readonly", "calendar.events"]
        mock_cred.delegate.return_value = make_delegation_result(
            scopes=["calendar.readonly", "calendar.events"],
        )

        tool._run()

        call_args = mock_cred.delegate.call_args
        assert call_args.kwargs["scopes"] == ["calendar.readonly", "calendar.events"]

    def test_passes_none_scopes_when_empty(self, mock_cred):
        t = CredTool(
            agent_token=TOKEN,
            user_id=USER_ID,
            service="google",
            app_client_id=APP_CLIENT_ID,
            base_url=BASE_URL,
        )
        t._cred = mock_cred
        t._scopes = []

        mock_cred.delegate.return_value = make_delegation_result()

        t._run()

        call_args = mock_cred.delegate.call_args
        assert call_args.kwargs["scopes"] is None

    def test_propagates_consent_required_error(self, tool, mock_cred):
        mock_cred.delegate.side_effect = ConsentRequiredError(
            "User has not consented",
            "https://cred.example.com/connect/google?user_id=user_123&app_client_id=app_1",
        )

        with pytest.raises(ConsentRequiredError) as exc_info:
            tool._run()

        assert "/connect/google" in exc_info.value.consent_url

    def test_cred_use_tool_brokers_request(self, mock_cred):
        with patch("cred_crewai.tool.Cred", return_value=mock_cred):
            use_tool = CredUseTool(agent_token=TOKEN, base_url=BASE_URL)
        mock_cred.use.return_value = BrokeredUseResult(
            status=200,
            ok=True,
            content_type="application/json",
            body={"items": []},
        )

        result = use_tool._run(
            delegation_id="del_brokered",
            url="https://www.googleapis.com/calendar/v3/calendars/primary/events",
            method="GET",
        )

        data = json.loads(result)
        assert data["ok"] is True
        assert data["body"] == {"items": []}
        mock_cred.use.assert_called_once_with(
            delegation_id="del_brokered",
            url="https://www.googleapis.com/calendar/v3/calendars/primary/events",
            method="GET",
            body=None,
            extra_headers=None,
        )


# ── langchain compatibility ───────────────────────────────────────────────────

class TestLangChainCompatibility:
    def test_has_args_schema(self, tool):
        assert hasattr(tool, "args_schema")
        schema = tool.args_schema.model_json_schema()
        # Placeholder schema should be minimal
        assert isinstance(schema, dict)

    def test_is_base_tool(self, tool):
        from langchain_core.tools import BaseTool
        assert isinstance(tool, BaseTool)


class TestIntegrationFlow:
    def test_real_cred_client_delegates_against_mock_server(self):
        tool = CredTool(
            agent_token=TOKEN,
            user_id=USER_ID,
            service="google",
            app_client_id=APP_CLIENT_ID,
            base_url=BASE_URL,
            scopes=["calendar.readonly"],
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
            token = tool._run()

        assert token == "ya29.real"
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
                "token_type": "Delegation",
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
    expected_ath = _b64.urlsafe_b64encode(_hashlib.sha256(b"del_bound").digest()).rstrip(b"=").decode()
    assert use_claims["ath"] == expected_ath
    # cred_req: the proof commits to the exact /api/v1/use body sent.
    expected_req = _b64.urlsafe_b64encode(
        _hashlib.sha256(canonical_json(use_call["body"]).encode("utf-8")).digest(),
    ).rstrip(b"=").decode()
    assert use_claims["cred_req"] == expected_req

    # The key never reaches what the model sees.
    for output in outputs:
        assert identity.private_key.hex() not in output
        assert "agent_identity" not in output


class TestAgentIdentity:
    def test_agent_identity_reaches_delegate_handle_and_use(self):
        identity = generate_agent_identity()
        tool = CredTool(
            agent_token=TOKEN, user_id=USER_ID, service="google", app_client_id=APP_CLIENT_ID,
            base_url=BASE_URL, token_format="handle", agent_identity=identity,
        )
        use_tool = CredUseTool(agent_token=TOKEN, base_url=BASE_URL, agent_identity=identity)
        for t in (tool, use_tool):
            assert "agent_identity" not in t.args_schema.model_json_schema().get("properties", {})
        calls: list = []
        with patch("httpx.Client.request", _fake_cred_server(calls)):
            delegated = tool._run()
            used = use_tool._run(delegation_id="del_bound", url="https://www.googleapis.com/x")
        _assert_dpop_bound(calls, identity, [delegated, used])
