"""Cred AutoGen integration tests.

Tests focus on: FunctionTool shape, invocation, output JSON,
and error propagation. The Cred client is mocked -- no real HTTP.
"""

import asyncio
import json
import pytest
from unittest.mock import MagicMock, patch

from autogen_core.tools import FunctionTool
from autogen_core import CancellationToken

from cred import DelegationResult, ConsentRequiredError, CredError
from cred_autogen import cred_delegate_tool

TOKEN = "cred_at_test"
USER_ID = "user_123"
APP_CLIENT_ID = "app_1"


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


# -- invocation ---------------------------------------------------------------

class TestInvoke:
    def test_returns_json_with_access_token(self, tool, mock_cred):
        mock_cred.delegate.return_value = DelegationResult(
            access_token="ya29.mock",
            token_type="Bearer",
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
        mock_cred.delegate.return_value = DelegationResult(
            access_token="at", token_type="Bearer",
            service="github", scopes=[], delegation_id="del_1",
        )

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
        mock_cred.delegate.return_value = DelegationResult(
            access_token="at", token_type="Bearer",
            service="google", scopes=[], delegation_id="del_1",
        )

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
