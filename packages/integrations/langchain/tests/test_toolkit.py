"""Cred LangChain integration tests.

Mocks the Cred client — no real HTTP, no real API calls.
Tests focus on: tool wiring, input schema, output shape, error propagation.
"""

import json
import warnings
warnings.filterwarnings("ignore", category=UserWarning)

from datetime import datetime, timedelta, timezone
from typing import Optional

import pytest
import httpx
from unittest.mock import MagicMock, patch
from langchain_core.tools import BaseTool
from pydantic import SecretStr

from cred import BrokeredUseResult, DelegationHandleResult, DelegationResult, Connection, ConsentRequiredError
import time

from cred import generate_agent_identity
from cred_langchain.tools import _remember_delegation_token
from cred_langchain import (
    CredToolkit,
    CredDelegateTool,
    CredUseTool,
    CredStatusTool,
    CredRevokeTool,
    secret_from_cred,
)


TOKEN = "cred_at_test"
USER_ID = "user_123"
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
def toolkit(mock_cred):
    tk = CredToolkit(agent_token=TOKEN, base_url=BASE_URL, user_id=USER_ID)
    tk._cred = mock_cred
    return tk


# ── CredToolkit ───────────────────────────────────────────────────────────────

class TestCredToolkit:
    def test_get_tools_returns_three_tools(self, toolkit):
        tools = toolkit.get_tools()
        assert len(tools) == 3

    def test_all_tools_are_base_tool_instances(self, toolkit):
        tools = toolkit.get_tools()
        assert all(isinstance(t, BaseTool) for t in tools)

    def test_tool_names(self, toolkit):
        names = {t.name for t in toolkit.get_tools()}
        assert names == {"cred_delegate", "cred_status", "cred_revoke"}

    def test_handle_mode_includes_use_tool(self, mock_cred):
        tk = CredToolkit(agent_token=TOKEN, base_url=BASE_URL, user_id=USER_ID, token_format="handle")
        tk._cred = mock_cred

        tools = tk.get_tools()

        assert {t.name for t in tools} == {"cred_delegate", "cred_use", "cred_status", "cred_revoke"}
        assert any(isinstance(t, CredUseTool) for t in tools)

    def test_tools_share_user_id(self, toolkit):
        tools = toolkit.get_tools()
        for tool in tools:
            assert tool._user_id == USER_ID

    def test_tools_share_cred_client(self, toolkit, mock_cred):
        tools = toolkit.get_tools()
        for tool in tools:
            assert tool._cred is mock_cred


# ── CredDelegateTool ──────────────────────────────────────────────────────────

class TestCredDelegateTool:
    def test_returns_json_with_access_token(self, toolkit, mock_cred):
        mock_cred.delegate.return_value = make_delegation_result(
            access_token="ya29.mock",
            expires_in=3600,
            service="google",
            scopes=["calendar.readonly"],
            delegation_id="del_abc",
        )

        tools = toolkit.get_tools()
        delegate = next(t for t in tools if t.name == "cred_delegate")
        result = delegate._run(
            service="google",
            app_client_id="app_1",
            scopes=["calendar.readonly"],
        )

        data = json.loads(result)
        assert data["access_token"] == "ya29.mock"
        assert data["service"] == "google"
        assert data["expires_in"] == 3600
        assert data["delegation_id"] == "del_abc"

    def test_passes_user_id_to_cred(self, toolkit, mock_cred):
        mock_cred.delegate.return_value = make_delegation_result()

        tools = toolkit.get_tools()
        delegate = next(t for t in tools if t.name == "cred_delegate")
        delegate._run(service="google", app_client_id="app_1", scopes=[])

        mock_cred.delegate.assert_called_once_with(
            service="google",
            user_id=USER_ID,
            app_client_id="app_1",
            scopes=[],
        )

    def test_handle_mode_returns_delegation_handle_without_access_token(self, mock_cred):
        mock_cred.delegate_handle.return_value = make_handle_result(
            scopes=["calendar.readonly"],
            delegation_id="del_brokered",
        )
        identity = generate_agent_identity()
        tk = CredToolkit(
            agent_token=TOKEN, base_url=BASE_URL, user_id=USER_ID, token_format="handle", agent_identity=identity,
        )
        tk._cred = mock_cred

        delegate = next(t for t in tk.get_tools() if t.name == "cred_delegate")
        result = delegate._run(
            service="google",
            app_client_id="app_1",
            scopes=["calendar.readonly"],
        )

        data = json.loads(result)
        assert "access_token" not in data
        assert data["token_type"] == "DPoP"
        assert "token" not in data
        assert HANDLE_TOKEN not in result
        assert data["delegation_id"] == "del_brokered"
        assert data["user_id"] == USER_ID
        mock_cred.delegate_handle.assert_called_once_with(
            service="google",
            user_id=USER_ID,
            app_client_id="app_1",
            scopes=["calendar.readonly"],
            agent_identity=identity,
        )

    def test_cred_use_tool_brokers_request(self, mock_cred):
        mock_cred.use.return_value = BrokeredUseResult(
            status=200,
            ok=True,
            content_type="application/json",
            body={"items": []},
        )
        identity = generate_agent_identity()
        use = CredUseTool()
        use._cred = mock_cred
        use._base_url = BASE_URL
        use._user_id = USER_ID
        use._agent_identity = identity
        _remember_delegation_token(
            "del_brokered", HANDLE_TOKEN, time.time() + 600,
            base_url=BASE_URL, agent_did=identity.did, user_id=USER_ID,
        )

        result = use._run(
            delegation_id="del_brokered",
            url="https://www.googleapis.com/calendar/v3/calendars/primary/events",
            method="GET",
        )

        data = json.loads(result)
        assert data["ok"] is True
        assert data["body"] == {"items": []}
        mock_cred.use.assert_called_once_with(
            HANDLE_TOKEN,
            url="https://www.googleapis.com/calendar/v3/calendars/primary/events",
            method="GET",
            body=None,
            extra_headers=None,
            agent_identity=identity,
        )

    def test_cred_use_tool_requires_agent_identity(self, mock_cred):
        use = CredUseTool()
        use._cred = mock_cred
        use._base_url = BASE_URL
        use._user_id = USER_ID
        _remember_delegation_token(
            "del_noid", HANDLE_TOKEN, time.time() + 600,
            base_url=BASE_URL, agent_did="", user_id=USER_ID,
        )

        with pytest.raises(ValueError, match="agent_identity"):
            use._run(delegation_id="del_noid", url="https://www.googleapis.com/x")
        mock_cred.use.assert_not_called()

    def test_cred_use_tool_rejects_unknown_or_expired_delegation(self, mock_cred):
        use = CredUseTool()
        use._cred = mock_cred
        use._base_url = BASE_URL
        use._user_id = USER_ID
        use._agent_identity = generate_agent_identity()
        _remember_delegation_token(
            "del_old", HANDLE_TOKEN, time.time() - 1,
            base_url=BASE_URL, agent_did="", user_id=USER_ID,
        )

        for delegation_id in ("del_never_seen", "del_old"):
            with pytest.raises(ValueError, match="Unknown or expired delegation"):
                use._run(delegation_id=delegation_id, url="https://www.googleapis.com/x")
        mock_cred.use.assert_not_called()

    def test_cred_use_tool_refuses_delegation_issued_for_another_scope(self, mock_cred):
        identity = generate_agent_identity()
        other = generate_agent_identity()
        url = "https://www.googleapis.com/x"
        _remember_delegation_token(
            "del_scoped", HANDLE_TOKEN, time.time() + 600,
            base_url=BASE_URL, agent_did=identity.did, user_id=USER_ID,
        )
        for base_url, agent, user_id in (
            ("https://other.example.com", identity, USER_ID),
            (BASE_URL, other, USER_ID),
            (BASE_URL, identity, "another_user"),
        ):
            use = CredUseTool()
            use._cred = mock_cred
            use._base_url = base_url
            use._user_id = user_id
            use._agent_identity = agent
            with pytest.raises(ValueError, match="different server, agent or user"):
                use._run(delegation_id="del_scoped", url=url)
        mock_cred.use.assert_not_called()

    def test_propagates_consent_required_error(self, toolkit, mock_cred):
        mock_cred.delegate.side_effect = ConsentRequiredError(
            "User has not consented",
            "https://cred.example.com/connect/google?user_id=user_123&app_client_id=app_1",
        )

        tools = toolkit.get_tools()
        delegate = next(t for t in tools if t.name == "cred_delegate")

        with pytest.raises(ConsentRequiredError) as exc_info:
            delegate._run(service="google", app_client_id="app_1", scopes=["calendar.readonly"])

        assert "/connect/google" in exc_info.value.consent_url

    def test_has_args_schema(self, toolkit):
        tools = toolkit.get_tools()
        delegate = next(t for t in tools if t.name == "cred_delegate")
        schema = delegate.args_schema.model_json_schema()
        assert "service" in schema["properties"]
        assert "scopes" in schema["properties"]

    def test_real_cred_client_delegates_against_mock_server(self):
        toolkit = CredToolkit(
            agent_token=TOKEN,
            user_id=USER_ID,
            base_url="https://cred.example.com",
        )
        delegate = next(t for t in toolkit.get_tools() if t.name == "cred_delegate")

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
            result = delegate._run(
                service="google",
                app_client_id="app_1",
                scopes=["calendar.readonly"],
            )

        payload = json.loads(result)
        assert payload["access_token"] == "ya29.real"
        assert request_mock.called


# ── CredStatusTool ────────────────────────────────────────────────────────────

class TestCredStatusTool:
    def test_returns_json_list_of_connections(self, toolkit, mock_cred):
        mock_cred.get_user_connections.return_value = [
            Connection(slug="google", scopes_granted=["calendar.readonly"],
                       app_client_id="app1", consented_at="2026-03-01T00:00:00Z"),
            Connection(slug="github", scopes_granted=["repo"],
                       app_client_id="app1", consented_at="2026-03-01T00:00:00Z"),
        ]

        tools = toolkit.get_tools()
        status = next(t for t in tools if t.name == "cred_status")
        result = status._run()

        data = json.loads(result)
        assert len(data) == 2
        assert data[0]["slug"] == "google"
        assert data[1]["slug"] == "github"

    def test_passes_user_id_to_cred(self, toolkit, mock_cred):
        mock_cred.get_user_connections.return_value = []

        tools = toolkit.get_tools()
        status = next(t for t in tools if t.name == "cred_status")
        status._run()

        mock_cred.get_user_connections.assert_called_once_with(USER_ID)

    def test_returns_empty_list_when_no_connections(self, toolkit, mock_cred):
        mock_cred.get_user_connections.return_value = []
        tools = toolkit.get_tools()
        status = next(t for t in tools if t.name == "cred_status")
        result = status._run()
        assert json.loads(result) == []


# ── CredRevokeTool ────────────────────────────────────────────────────────────

class TestCredRevokeTool:
    def test_returns_json_revoked_true(self, toolkit, mock_cred):
        mock_cred.revoke.return_value = None

        tools = toolkit.get_tools()
        revoke = next(t for t in tools if t.name == "cred_revoke")
        result = revoke._run(service="google")

        data = json.loads(result)
        assert data["revoked"] is True
        assert data["service"] == "google"

    def test_passes_user_id_and_service_to_cred(self, toolkit, mock_cred):
        mock_cred.revoke.return_value = None

        tools = toolkit.get_tools()
        revoke = next(t for t in tools if t.name == "cred_revoke")
        revoke._run(service="google", app_client_id="app1")

        mock_cred.revoke.assert_called_once_with(
            service="google",
            user_id=USER_ID,
            app_client_id="app1",
        )

    def test_has_args_schema(self, toolkit):
        tools = toolkit.get_tools()
        revoke = next(t for t in tools if t.name == "cred_revoke")
        schema = revoke.args_schema.model_json_schema()
        assert "service" in schema["properties"]


class TestSecretFromCred:
    def test_returns_secret_str_from_real_cred_client(self):
        from cred import Cred

        cred = Cred(agent_token=TOKEN, base_url="https://cred.example.com")

        with patch("httpx.Client.request", return_value=httpx.Response(
            200,
            json={
                "access_token": "ya29.secret",
                "token_type": "Bearer",
                "expires_in": 3600,
                "service": "google",
                "scopes": ["calendar.readonly"],
                "delegation_id": "del_secret",
            },
        )):
            secret = secret_from_cred(
                "google",
                USER_ID,
                cred,
                scopes=["calendar.readonly"],
                app_client_id="app_1",
            )

        assert isinstance(secret, SecretStr)
        assert secret.get_secret_value() == "ya29.secret"


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
        identity = generate_agent_identity()
        toolkit = CredToolkit(
            agent_token=TOKEN, base_url=BASE_URL, user_id=USER_ID,
            token_format="handle", agent_identity=identity,
        )
        tools = {t.name: t for t in toolkit.get_tools()}
        for name in ("cred_delegate", "cred_use"):
            assert "agent_identity" not in tools[name].args_schema.model_json_schema()["properties"]
        calls: list = []
        with patch("httpx.Client.request", _fake_cred_server(calls)):
            delegated = tools["cred_delegate"]._run(service="google", app_client_id="app_1", scopes=["calendar.readonly"])
            used = tools["cred_use"]._run(delegation_id="del_bound", url="https://www.googleapis.com/x")
        _assert_dpop_bound(calls, identity, [delegated, used])
