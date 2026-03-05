"""Cred Semantic Kernel plugin tests.

Tests focus on: plugin construction, kernel_function metadata, invocation,
output JSON, and error propagation. The Cred client is mocked -- no real HTTP.
"""

import json
import pytest
from unittest.mock import MagicMock, patch

from cred import DelegationResult, ConsentRequiredError, CredError
from cred_semantic_kernel import CredPlugin

TOKEN = "cred_at_test"
USER_ID = "user_123"
APP_CLIENT_ID = "app_1"


@pytest.fixture
def mock_cred():
    return MagicMock()


@pytest.fixture
def plugin(mock_cred):
    with patch("cred_semantic_kernel.plugin.Cred", return_value=mock_cred):
        return CredPlugin(
            agent_token=TOKEN,
            user_id=USER_ID,
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


# -- kernel_function metadata --------------------------------------------------

class TestKernelFunction:
    def test_delegate_has_kernel_function_metadata(self, plugin):
        # kernel_function decorator adds __kernel_function_metadata__
        assert hasattr(plugin.delegate, "__kernel_function__")

    def test_delegate_is_callable(self, plugin):
        assert callable(plugin.delegate)


# -- delegate invocation -------------------------------------------------------

class TestDelegate:
    def test_returns_json_with_access_token(self, plugin, mock_cred):
        mock_cred.delegate.return_value = DelegationResult(
            access_token="ya29.mock",
            token_type="Bearer",
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

    def test_passes_service_user_app_to_cred(self, plugin, mock_cred):
        mock_cred.delegate.return_value = DelegationResult(
            access_token="at", token_type="Bearer",
            service="github", scopes=[], delegation_id="del_1",
        )

        plugin.delegate(service="github", scopes="repo")

        mock_cred.delegate.assert_called_once_with(
            service="github",
            user_id=USER_ID,
            app_client_id=APP_CLIENT_ID,
            scopes=["repo"],
        )

    def test_parses_comma_separated_scopes(self, plugin, mock_cred):
        mock_cred.delegate.return_value = DelegationResult(
            access_token="at", token_type="Bearer",
            service="google", scopes=["calendar.readonly", "calendar.events"],
            delegation_id="del_1",
        )

        plugin.delegate(service="google", scopes="calendar.readonly, calendar.events")

        call_kwargs = mock_cred.delegate.call_args.kwargs
        assert call_kwargs["scopes"] == ["calendar.readonly", "calendar.events"]

    def test_passes_none_scopes_when_empty_string(self, plugin, mock_cred):
        mock_cred.delegate.return_value = DelegationResult(
            access_token="at", token_type="Bearer",
            service="google", scopes=[], delegation_id="del_1",
        )

        plugin.delegate(service="google", scopes="")

        call_kwargs = mock_cred.delegate.call_args.kwargs
        assert call_kwargs["scopes"] is None

    def test_propagates_consent_required_error(self, plugin, mock_cred):
        mock_cred.delegate.side_effect = ConsentRequiredError(
            "User has not consented",
            "https://api.cred.ninja/api/connect/google/authorize?app_client_id=app_1",
        )

        with pytest.raises(ConsentRequiredError) as exc_info:
            plugin.delegate(service="google", scopes="calendar.readonly")

        assert "/api/connect/google/authorize" in exc_info.value.consent_url

    def test_propagates_cred_error_on_401(self, plugin, mock_cred):
        mock_cred.delegate.side_effect = CredError(
            "Invalid agent token", "unauthorized", 401
        )

        with pytest.raises(CredError) as exc_info:
            plugin.delegate(service="google", scopes="")

        assert exc_info.value.status_code == 401
