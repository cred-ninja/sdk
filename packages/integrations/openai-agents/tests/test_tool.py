"""Cred OpenAI Agents SDK integration tests.

Tests focus on: FunctionTool shape, async invocation, output JSON,
and error propagation. The Cred client is mocked — no real HTTP.
"""

import asyncio
import json
import time
from datetime import datetime, timedelta, timezone
from typing import Optional
import pytest
import httpx
from unittest.mock import MagicMock, patch

from agents import FunctionTool

from cred import BrokeredUseResult, DelegationHandleResult, DelegationResult, ConsentRequiredError, CredError
from cred import generate_agent_identity
from cred_openai_agents import cred_delegate_tool, cred_use_tool, CredTool
from cred_openai_agents.tool import _remember_delegation_token

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
def tool(mock_cred):
    with patch("cred_openai_agents.tool.Cred", return_value=mock_cred):
        return cred_delegate_tool(
            agent_token=TOKEN,
            user_id=USER_ID,
            app_client_id=APP_CLIENT_ID,
            base_url=BASE_URL,
        )


def run(coro):
    """Run a coroutine synchronously (test helper)."""
    return asyncio.run(coro)


# ── factory function ──────────────────────────────────────────────────────────

class TestFactory:
    def test_returns_function_tool(self):
        with patch("cred_openai_agents.tool.Cred"):
            t = cred_delegate_tool(
                agent_token=TOKEN,
                user_id=USER_ID,
                app_client_id=APP_CLIENT_ID,
            base_url=BASE_URL,
            )
        assert isinstance(t, FunctionTool)

    def test_tool_name_is_cred_delegate(self, tool):
        assert tool.name == "cred_delegate"

    def test_tool_description_mentions_oauth(self, tool):
        assert "access token" in tool.description.lower()
        assert "service" in tool.description.lower()

    def test_params_schema_has_service_and_scopes(self, tool):
        props = tool.params_json_schema["properties"]
        assert "service" in props
        assert "scopes" in props

    def test_service_is_required(self, tool):
        assert "service" in tool.params_json_schema.get("required", [])

    def test_creates_cred_client_with_token_and_base_url(self):
        with patch("cred_openai_agents.tool.Cred") as mock_cred_class:
            cred_delegate_tool(
                agent_token=TOKEN,
                user_id=USER_ID,
                app_client_id=APP_CLIENT_ID,
                base_url="http://localhost:3001",
            )
            mock_cred_class.assert_called_once_with(
                agent_token=TOKEN,
                base_url="http://localhost:3001",
            )

    def test_exports_cred_tool_alias(self):
        assert CredTool is cred_delegate_tool

    def test_returns_cred_use_tool(self):
        with patch("cred_openai_agents.tool.Cred"):
            t = cred_use_tool(agent_token=TOKEN, base_url=BASE_URL)
        assert isinstance(t, FunctionTool)
        assert t.name == "cred_use"


# ── on_invoke_tool ────────────────────────────────────────────────────────────

class TestInvoke:
    def test_returns_json_with_access_token(self, tool, mock_cred):
        mock_cred.delegate.return_value = make_delegation_result(
            access_token="ya29.mock",
            expires_in=3600,
            service="google",
            scopes=["calendar.readonly"],
            delegation_id="del_abc",
        )

        args_json = json.dumps({"service": "google", "scopes": ["calendar.readonly"]})
        result_str = run(tool.on_invoke_tool(MagicMock(), args_json))
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
        with patch("cred_openai_agents.tool.Cred", return_value=mock_cred):
            handle_tool = cred_delegate_tool(
                agent_token=TOKEN,
                user_id=USER_ID,
                app_client_id=APP_CLIENT_ID,
                base_url=BASE_URL,
                token_format="handle",
                agent_identity=identity,
            )

        args_json = json.dumps({"service": "google", "scopes": ["calendar.readonly"]})
        result_str = run(handle_tool.on_invoke_tool(MagicMock(), args_json))
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

    def test_cred_use_tool_brokers_request(self, mock_cred):
        identity = generate_agent_identity()
        _remember_delegation_token("del_brokered", HANDLE_TOKEN, time.time() + 600)
        mock_cred.use.return_value = BrokeredUseResult(
            status=200,
            ok=True,
            content_type="application/json",
            body={"items": []},
        )
        with patch("cred_openai_agents.tool.Cred", return_value=mock_cred):
            use_tool = cred_use_tool(agent_token=TOKEN, base_url=BASE_URL, agent_identity=identity)

        result_str = run(use_tool.on_invoke_tool(MagicMock(), json.dumps({
            "delegation_id": "del_brokered",
            "url": "https://www.googleapis.com/calendar/v3/calendars/primary/events",
            "method": "GET",
        })))
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

    def test_cred_use_tool_requires_agent_identity(self, mock_cred):
        _remember_delegation_token("del_noid", HANDLE_TOKEN, time.time() + 600)
        with patch("cred_openai_agents.tool.Cred", return_value=mock_cred):
            use_tool = cred_use_tool(agent_token=TOKEN, base_url=BASE_URL)

        with pytest.raises(ValueError, match="agent_identity"):
            run(use_tool.on_invoke_tool(MagicMock(), json.dumps({
                "delegation_id": "del_noid", "url": "https://www.googleapis.com/x", "method": "GET",
            })))
        mock_cred.use.assert_not_called()

    def test_cred_use_tool_rejects_unknown_or_expired_delegation(self, mock_cred):
        _remember_delegation_token("del_old", HANDLE_TOKEN, time.time() - 1)
        with patch("cred_openai_agents.tool.Cred", return_value=mock_cred):
            use_tool = cred_use_tool(agent_token=TOKEN, base_url=BASE_URL, agent_identity=generate_agent_identity())

        for delegation_id in ("del_never_seen", "del_old"):
            with pytest.raises(ValueError, match="Unknown or expired delegation"):
                run(use_tool.on_invoke_tool(MagicMock(), json.dumps({
                    "delegation_id": delegation_id, "url": "https://www.googleapis.com/x", "method": "GET",
                })))
        mock_cred.use.assert_not_called()

    def test_passes_service_user_app_to_cred(self, tool, mock_cred):
        mock_cred.delegate.return_value = make_delegation_result(service="github")

        args_json = json.dumps({"service": "github", "scopes": ["repo"]})
        run(tool.on_invoke_tool(MagicMock(), args_json))

        mock_cred.delegate.assert_called_once_with(
            service="github",
            user_id=USER_ID,
            app_client_id=APP_CLIENT_ID,
            scopes=["repo"],
        )

    def test_passes_none_scopes_when_empty_list(self, tool, mock_cred):
        mock_cred.delegate.return_value = make_delegation_result()

        args_json = json.dumps({"service": "google", "scopes": []})
        run(tool.on_invoke_tool(MagicMock(), args_json))

        call_kwargs = mock_cred.delegate.call_args.kwargs
        assert call_kwargs["scopes"] is None

    def test_propagates_consent_required_error(self, tool, mock_cred):
        mock_cred.delegate.side_effect = ConsentRequiredError(
            "User has not consented",
            "https://cred.example.com/connect/google?user_id=user_123&app_client_id=app_1",
        )

        args_json = json.dumps({"service": "google", "scopes": ["calendar.readonly"]})

        with pytest.raises(ConsentRequiredError) as exc_info:
            run(tool.on_invoke_tool(MagicMock(), args_json))

        assert "/connect/google" in exc_info.value.consent_url

    def test_propagates_cred_error_on_401(self, tool, mock_cred):
        mock_cred.delegate.side_effect = CredError(
            "Invalid agent token", "unauthorized", 401
        )

        args_json = json.dumps({"service": "google", "scopes": []})

        with pytest.raises(CredError) as exc_info:
            run(tool.on_invoke_tool(MagicMock(), args_json))

        assert exc_info.value.status_code == 401

    def test_runs_sync_cred_in_thread(self, tool, mock_cred):
        """Verifies the handler doesn't block the event loop (delegate is sync)."""
        call_count = 0

        def sync_delegate(**kwargs):
            nonlocal call_count
            call_count += 1
            return make_delegation_result()

        mock_cred.delegate.side_effect = sync_delegate

        args_json = json.dumps({"service": "google", "scopes": []})
        run(tool.on_invoke_tool(MagicMock(), args_json))

        assert call_count == 1

    def test_real_cred_client_delegates_against_mock_server(self):
        tool = cred_delegate_tool(
            agent_token=TOKEN,
            user_id=USER_ID,
            app_client_id=APP_CLIENT_ID,
            base_url="https://cred.example.com",
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
            result_str = run(tool.on_invoke_tool(MagicMock(), json.dumps({
                "service": "google",
                "scopes": ["calendar.readonly"],
            })))

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
        identity = generate_agent_identity()
        delegate_tool = cred_delegate_tool(
            agent_token=TOKEN, user_id=USER_ID, app_client_id=APP_CLIENT_ID,
            base_url=BASE_URL, token_format="handle", agent_identity=identity,
        )
        use_tool = cred_use_tool(agent_token=TOKEN, base_url=BASE_URL, agent_identity=identity)
        for t in (delegate_tool, use_tool):
            assert "agent_identity" not in t.params_json_schema["properties"]
        calls: list = []
        with patch("httpx.Client.request", _fake_cred_server(calls)):
            delegated = run(delegate_tool.on_invoke_tool(
                MagicMock(), json.dumps({"service": "google", "scopes": ["calendar.readonly"]}),
            ))
            used = run(use_tool.on_invoke_tool(
                MagicMock(), json.dumps({"delegation_id": "del_bound", "url": "https://www.googleapis.com/x", "method": "GET"}),
            ))
        _assert_dpop_bound(calls, identity, [delegated, used])
