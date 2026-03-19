"""Cred CrewAI Tool tests.

Mocks the Cred client — no real HTTP, no real API calls.
Tests focus on: tool configuration, naming, input schema, output format, error propagation.
"""

import warnings
warnings.filterwarnings("ignore", category=UserWarning)

import pytest
from unittest.mock import MagicMock, patch

from cred import DelegationResult, ConsentRequiredError
from cred_crewai import CredTool

TOKEN = "cred_at_test"
USER_ID = "user_123"
APP_CLIENT_ID = "app_1"


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
        )
        assert t._service == "github"
        assert "github" in t.name

    def test_dynamic_name_includes_service(self):
        google_tool = CredTool(
            agent_token=TOKEN,
            user_id=USER_ID,
            service="google-calendar",
            app_client_id=APP_CLIENT_ID,
        )
        assert google_tool.name == "cred_google_calendar_delegate"

    def test_dynamic_description_includes_service(self):
        t = CredTool(
            agent_token=TOKEN,
            user_id=USER_ID,
            service="github",
            app_client_id=APP_CLIENT_ID,
        )
        assert "github" in t.description
        assert "access token" in t.description

    def test_stores_user_id(self):
        t = CredTool(
            agent_token=TOKEN,
            user_id="user_456",
            service="google",
            app_client_id=APP_CLIENT_ID,
        )
        assert t._user_id == "user_456"

    def test_stores_scopes(self):
        scopes = ["calendar.readonly", "calendar.events"]
        t = CredTool(
            agent_token=TOKEN,
            user_id=USER_ID,
            service="google",
            app_client_id=APP_CLIENT_ID,
            scopes=scopes,
        )
        assert t._scopes == scopes

    def test_defaults_scopes_to_empty_list(self):
        t = CredTool(
            agent_token=TOKEN,
            user_id=USER_ID,
            service="google",
            app_client_id=APP_CLIENT_ID,
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
        mock_cred.delegate.return_value = DelegationResult(
            access_token="ya29.mock",
            token_type="Bearer",
            expires_in=3600,
            service="google",
            scopes=["calendar.readonly"],
            delegation_id="del_abc",
        )

        result = tool._run()

        assert result == "ya29.mock"
        assert isinstance(result, str)

    def test_passes_service_user_app_client_id(self, tool, mock_cred):
        mock_cred.delegate.return_value = DelegationResult(
            access_token="at",
            token_type="Bearer",
            service="google",
            scopes=[],
            delegation_id="del_1",
        )

        tool._run()

        mock_cred.delegate.assert_called_once_with(
            service="google",
            user_id=USER_ID,
            app_client_id=APP_CLIENT_ID,
            scopes=["calendar.readonly"],
        )

    def test_passes_scopes_when_configured(self, tool, mock_cred):
        tool._scopes = ["calendar.readonly", "calendar.events"]
        mock_cred.delegate.return_value = DelegationResult(
            access_token="at",
            token_type="Bearer",
            service="google",
            scopes=["calendar.readonly", "calendar.events"],
            delegation_id="del_1",
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
        )
        t._cred = mock_cred
        t._scopes = []

        mock_cred.delegate.return_value = DelegationResult(
            access_token="at",
            token_type="Bearer",
            service="google",
            scopes=[],
            delegation_id="del_1",
        )

        t._run()

        call_args = mock_cred.delegate.call_args
        assert call_args.kwargs["scopes"] is None

    def test_propagates_consent_required_error(self, tool, mock_cred):
        mock_cred.delegate.side_effect = ConsentRequiredError(
            "User has not consented",
            "https://api.cred.ninja/api/connect/google/authorize?app_client_id=app_1",
        )

        with pytest.raises(ConsentRequiredError) as exc_info:
            tool._run()

        assert "/api/connect/google/authorize" in exc_info.value.consent_url


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
