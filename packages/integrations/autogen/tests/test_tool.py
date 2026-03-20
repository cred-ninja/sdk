"""Cred AutoGen integration tests.

Tests focus on: FunctionTool shape, invocation, output JSON,
and error propagation. The Cred client is mocked -- no real HTTP.
"""

import asyncio
import json
from datetime import datetime, timezone
from typing import Optional
import pytest
import httpx
from unittest.mock import MagicMock, patch

from autogen_core.tools import FunctionTool
from autogen_core import CancellationToken

from cred import DelegationResult, ConsentRequiredError, CredError
from cred_autogen import cred_delegate_tool, CredTool

TOKEN = "cred_at_test"
USER_ID = "user_123"
APP_CLIENT_ID = "app_1"


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


@pytest.fixture
def mock_cred():
    return MagicMock()


@pytest.fixture
def tool(mock_cred):
    with patch("cred_autogen.tool.Cred", return_value=mock_cred):
        return cred_delegate_tool(
            agent_token=TOKEN,
            user_id=USER_ID,
            app_client_id=APP_CLIENT_ID,
        )


def run(coro):
    """Run a coroutine synchronously (test helper)."""
    return asyncio.run(coro)


# -- factory function ---------------------------------------------------------

class TestFactory:
    def test_returns_function_tool(self):
        with patch("cred_autogen.tool.Cred"):
            t = cred_delegate_tool(
                agent_token=TOKEN,
                user_id=USER_ID,
                app_client_id=APP_CLIENT_ID,
            )
        assert isinstance(t, FunctionTool)

    def test_tool_name_is_cred_delegate(self, tool):
        assert tool.name == "cred_delegate"

    def test_tool_description_mentions_oauth(self, tool):
        assert "access token" in tool.description.lower()
        assert "service" in tool.description.lower()

    def test_creates_cred_client_with_token_and_base_url(self):
        with patch("cred_autogen.tool.Cred") as mock_cred_class:
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


# -- invocation ---------------------------------------------------------------

class TestInvoke:
    def test_returns_json_with_access_token(self, tool, mock_cred):
        mock_cred.delegate.return_value = make_delegation_result(
            access_token="ya29.mock",
            expires_in=3600,
            service="google",
            scopes=["calendar.readonly"],
            delegation_id="del_abc",
        )

        result_str = run(tool.run_json(
            {"service": "google", "scopes": ["calendar.readonly"]},
            CancellationToken(),
        ))
        result = json.loads(result_str)

        assert result["access_token"] == "ya29.mock"
        assert result["token_type"] == "Bearer"
        assert result["expires_in"] == 3600
        assert result["service"] == "google"
        assert result["scopes"] == ["calendar.readonly"]
        assert result["delegation_id"] == "del_abc"

    def test_passes_service_user_app_to_cred(self, tool, mock_cred):
        mock_cred.delegate.return_value = make_delegation_result(service="github")

        run(tool.run_json(
            {"service": "github", "scopes": ["repo"]},
            CancellationToken(),
        ))

        mock_cred.delegate.assert_called_once_with(
            service="github",
            user_id=USER_ID,
            app_client_id=APP_CLIENT_ID,
            scopes=["repo"],
        )

    def test_passes_none_scopes_when_empty_list(self, tool, mock_cred):
        mock_cred.delegate.return_value = make_delegation_result()

        run(tool.run_json(
            {"service": "google", "scopes": []},
            CancellationToken(),
        ))

        call_kwargs = mock_cred.delegate.call_args.kwargs
        assert call_kwargs["scopes"] is None

    def test_propagates_consent_required_error(self, tool, mock_cred):
        mock_cred.delegate.side_effect = ConsentRequiredError(
            "User has not consented",
            "https://api.cred.ninja/api/connect/google/authorize?app_client_id=app_1",
        )

        with pytest.raises(ConsentRequiredError) as exc_info:
            run(tool.run_json(
                {"service": "google", "scopes": ["calendar.readonly"]},
                CancellationToken(),
            ))

        assert "/api/connect/google/authorize" in exc_info.value.consent_url

    def test_propagates_cred_error_on_401(self, tool, mock_cred):
        mock_cred.delegate.side_effect = CredError(
            "Invalid agent token", "unauthorized", 401
        )

        with pytest.raises(CredError) as exc_info:
            run(tool.run_json(
                {"service": "google", "scopes": []},
                CancellationToken(),
            ))

        assert exc_info.value.status_code == 401

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
            result_str = run(tool.run_json(
                {"service": "google", "scopes": ["calendar.readonly"]},
                CancellationToken(),
            ))

        payload = json.loads(result_str)
        assert payload["access_token"] == "ya29.real"
        assert request_mock.called
