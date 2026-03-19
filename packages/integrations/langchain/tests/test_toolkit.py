"""Cred LangChain integration tests.

Mocks the Cred client — no real HTTP, no real API calls.
Tests focus on: tool wiring, input schema, output shape, error propagation.
"""

import json
import warnings
warnings.filterwarnings("ignore", category=UserWarning)

import pytest
import httpx
from unittest.mock import MagicMock, patch
from langchain_core.tools import BaseTool
from pydantic import SecretStr

from cred import DelegationResult, Connection, ConsentRequiredError
from cred_langchain import (
    CredToolkit,
    CredDelegateTool,
    CredStatusTool,
    CredRevokeTool,
    secret_from_cred,
)


TOKEN = "cred_at_test"
USER_ID = "user_123"


@pytest.fixture
def mock_cred():
    return MagicMock()


@pytest.fixture
def toolkit(mock_cred):
    tk = CredToolkit(agent_token=TOKEN, user_id=USER_ID)
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
        mock_cred.delegate.return_value = DelegationResult(
            access_token="ya29.mock",
            token_type="Bearer",
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
        mock_cred.delegate.return_value = DelegationResult(
            access_token="at", token_type="Bearer",
            service="google", scopes=[], delegation_id="del_1",
        )

        tools = toolkit.get_tools()
        delegate = next(t for t in tools if t.name == "cred_delegate")
        delegate._run(service="google", app_client_id="app_1", scopes=[])

        mock_cred.delegate.assert_called_once_with(
            service="google",
            user_id=USER_ID,
            app_client_id="app_1",
            scopes=[],
        )

    def test_propagates_consent_required_error(self, toolkit, mock_cred):
        mock_cred.delegate.side_effect = ConsentRequiredError(
            "User has not consented",
            "https://api.cred.ninja/api/connect/google/authorize?app_client_id=app_1",
        )

        tools = toolkit.get_tools()
        delegate = next(t for t in tools if t.name == "cred_delegate")

        with pytest.raises(ConsentRequiredError) as exc_info:
            delegate._run(service="google", app_client_id="app_1", scopes=["calendar.readonly"])

        assert "/api/connect/google/authorize" in exc_info.value.consent_url

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
