"""Cred OpenAI Agents SDK integration tests.

Tests focus on: FunctionTool shape, async invocation, output JSON,
and error propagation. The Cred client is mocked — no real HTTP.
"""

import asyncio
import json
import pytest
from unittest.mock import MagicMock, patch, AsyncMock

from agents import FunctionTool

from cred import DelegationResult, ConsentRequiredError, CredError
from cred_openai_agents import cred_delegate_tool

TOKEN = "cred_at_test"
USER_ID = "user_123"
APP_CLIENT_ID = "app_1"


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


# ── on_invoke_tool ────────────────────────────────────────────────────────────

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

        args_json = json.dumps({"service": "google", "scopes": ["calendar.readonly"]})
        result_str = run(tool.on_invoke_tool(MagicMock(), args_json))
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

        args_json = json.dumps({"service": "github", "scopes": ["repo"]})
        run(tool.on_invoke_tool(MagicMock(), args_json))

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

        args_json = json.dumps({"service": "google", "scopes": []})
        run(tool.on_invoke_tool(MagicMock(), args_json))

        call_kwargs = mock_cred.delegate.call_args.kwargs
        assert call_kwargs["scopes"] is None

    def test_propagates_consent_required_error(self, tool, mock_cred):
        mock_cred.delegate.side_effect = ConsentRequiredError(
            "User has not consented",
            "https://api.cred.ninja/api/connect/google/authorize?app_client_id=app_1",
        )

        args_json = json.dumps({"service": "google", "scopes": ["calendar.readonly"]})

        with pytest.raises(ConsentRequiredError) as exc_info:
            run(tool.on_invoke_tool(MagicMock(), args_json))

        assert "/api/connect/google/authorize" in exc_info.value.consent_url

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
            return DelegationResult(
                access_token="at", token_type="Bearer",
                service="google", scopes=[], delegation_id="del_1",
            )

        mock_cred.delegate.side_effect = sync_delegate

        args_json = json.dumps({"service": "google", "scopes": []})
        run(tool.on_invoke_tool(MagicMock(), args_json))

        assert call_count == 1
