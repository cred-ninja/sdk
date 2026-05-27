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
