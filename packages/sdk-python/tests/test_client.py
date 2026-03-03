"""Cred Python SDK — Tests.

Uses respx to mock httpx requests. No real network calls.
"""

import pytest
import respx
import httpx

from cred import Cred, CredError, ConsentRequiredError, DelegationResult, Connection

BASE_URL = "https://api.cred.ninja"
TOKEN = "cred_at_test_token"


@pytest.fixture
def cred():
    return Cred(agent_token=TOKEN)


# ── constructor ───────────────────────────────────────────────────────────────

class TestConstructor:
    def test_raises_when_token_empty(self):
        with pytest.raises(CredError):
            Cred(agent_token="")

    def test_default_base_url(self, cred):
        assert cred._base_url == BASE_URL

    def test_custom_base_url_strips_trailing_slash(self):
        c = Cred(agent_token=TOKEN, base_url="http://localhost:3001/")
        assert c._base_url == "http://localhost:3001"

    def test_context_manager(self):
        with Cred(agent_token=TOKEN) as c:
            assert c._base_url == BASE_URL


# ── delegate() ────────────────────────────────────────────────────────────────

class TestDelegate:
    @respx.mock
    def test_returns_delegation_result_on_200(self, cred):
        respx.post(f"{BASE_URL}/api/v1/delegate").mock(return_value=httpx.Response(
            200,
            json={
                "access_token": "ya29.mock",
                "token_type": "Bearer",
                "expires_in": 3600,
                "service": "google",
                "scopes": ["calendar.readonly"],
                "delegation_id": "del_abc",
            },
        ))

        result = cred.delegate(
            service="google",
            user_id="user_1",
            app_client_id="app_1",
            scopes=["calendar.readonly"],
        )

        assert isinstance(result, DelegationResult)
        assert result.access_token == "ya29.mock"
        assert result.token_type == "Bearer"
        assert result.expires_in == 3600
        assert result.delegation_id == "del_abc"
        assert result.scopes == ["calendar.readonly"]

    @respx.mock
    def test_sends_authorization_header(self, cred):
        route = respx.post(f"{BASE_URL}/api/v1/delegate").mock(return_value=httpx.Response(
            200,
            json={
                "access_token": "at", "token_type": "Bearer",
                "service": "google", "scopes": [], "delegation_id": "del_1",
            },
        ))

        cred.delegate(service="google", user_id="u1", app_client_id="app1")

        assert route.called
        assert route.calls[0].request.headers["authorization"] == f"Bearer {TOKEN}"

    @respx.mock
    def test_raises_consent_required_on_403(self, cred):
        respx.post(f"{BASE_URL}/api/v1/delegate").mock(return_value=httpx.Response(
            403,
            json={
                "error": "consent_required",
                "message": "User has not consented",
                "consent_url": f"{BASE_URL}/api/connect/google/authorize?app_client_id=app1",
            },
        ))

        with pytest.raises(ConsentRequiredError) as exc_info:
            cred.delegate(service="google", user_id="u1", app_client_id="app1")

        err = exc_info.value
        assert err.status_code == 403
        assert err.code == "consent_required"
        assert "/api/connect/google/authorize" in err.consent_url

    @respx.mock
    def test_raises_cred_error_on_scope_escalation(self, cred):
        respx.post(f"{BASE_URL}/api/v1/delegate").mock(return_value=httpx.Response(
            403,
            json={
                "error": "scope_escalation_denied",
                "message": "Requested scopes exceed user consent",
            },
        ))

        with pytest.raises(CredError) as exc_info:
            cred.delegate(service="google", user_id="u1", app_client_id="app1",
                          scopes=["gmail.send"])

        assert exc_info.value.code == "scope_escalation_denied"
        assert exc_info.value.status_code == 403

    @respx.mock
    def test_raises_cred_error_on_401(self, cred):
        respx.post(f"{BASE_URL}/api/v1/delegate").mock(return_value=httpx.Response(
            401, json={"error": "Invalid or expired agent token"},
        ))

        with pytest.raises(CredError) as exc_info:
            cred.delegate(service="google", user_id="u1", app_client_id="app1")

        assert exc_info.value.status_code == 401

    @respx.mock
    def test_omits_scopes_when_not_provided(self, cred):
        route = respx.post(f"{BASE_URL}/api/v1/delegate").mock(return_value=httpx.Response(
            200,
            json={
                "access_token": "at", "token_type": "Bearer",
                "service": "google", "scopes": ["calendar.readonly"],
                "delegation_id": "del_1",
            },
        ))

        cred.delegate(service="google", user_id="u1", app_client_id="app1")

        body = route.calls[0].request.read()
        import json
        parsed = json.loads(body)
        assert "scopes" not in parsed


# ── get_user_connections() ────────────────────────────────────────────────────

class TestGetUserConnections:
    @respx.mock
    def test_returns_list_of_connections(self, cred):
        respx.get(url__startswith=f"{BASE_URL}/api/v1/connections").mock(
            return_value=httpx.Response(200, json={
                "connections": [
                    {"slug": "google", "scopesGranted": ["calendar.readonly"],
                     "consentedAt": "2026-03-01T00:00:00Z", "appClientId": "app1"},
                    {"slug": "github", "scopesGranted": ["repo"],
                     "consentedAt": "2026-03-01T00:00:00Z", "appClientId": "app1"},
                ],
            })
        )

        conns = cred.get_user_connections("user_1")

        assert len(conns) == 2
        assert all(isinstance(c, Connection) for c in conns)
        assert conns[0].slug == "google"
        assert conns[0].scopes_granted == ["calendar.readonly"]
        assert conns[1].slug == "github"

    @respx.mock
    def test_passes_user_id_and_app_client_id_as_params(self, cred):
        route = respx.get(url__startswith=f"{BASE_URL}/api/v1/connections").mock(
            return_value=httpx.Response(200, json={"connections": []})
        )

        cred.get_user_connections("user_1", app_client_id="app1")

        url = str(route.calls[0].request.url)
        assert "user_id=user_1" in url
        assert "app_client_id=app1" in url


# ── get_consent_url() ─────────────────────────────────────────────────────────

class TestGetConsentUrl:
    def test_builds_correct_url(self, cred):
        url = cred.get_consent_url(
            service="google",
            user_id="user_1",
            app_client_id="app_1",
            scopes=["calendar.readonly", "calendar.events"],
            redirect_uri="https://myapp.com/callback",
        )

        assert f"{BASE_URL}/api/connect/google/authorize" in url
        assert "app_client_id=app_1" in url
        assert "calendar.readonly" in url
        assert "redirect_uri=" in url

    def test_makes_no_http_call(self, cred):
        # No respx mock — if fetch fires, respx raises
        with respx.mock:
            url = cred.get_consent_url(
                service="google", user_id="u1", app_client_id="app1",
                scopes=["calendar.readonly"], redirect_uri="https://example.com/cb",
            )
        assert url  # just confirm it returned something


# ── revoke() ──────────────────────────────────────────────────────────────────

class TestRevoke:
    @respx.mock
    def test_resolves_on_204(self, cred):
        respx.delete(url__startswith=f"{BASE_URL}/api/v1/connections/google").mock(
            return_value=httpx.Response(204)
        )

        result = cred.revoke(service="google", user_id="user_1")
        assert result is None

    @respx.mock
    def test_passes_user_id_in_query(self, cred):
        route = respx.delete(url__startswith=f"{BASE_URL}/api/v1/connections/google").mock(
            return_value=httpx.Response(204)
        )

        cred.revoke(service="google", user_id="user_1", app_client_id="app1")

        url = str(route.calls[0].request.url)
        assert "user_id=user_1" in url
        assert "app_client_id=app1" in url

    @respx.mock
    def test_raises_cred_error_on_404(self, cred):
        respx.delete(url__startswith=f"{BASE_URL}/api/v1/connections/google").mock(
            return_value=httpx.Response(404, json={"error": "No active connection found"})
        )

        with pytest.raises(CredError) as exc_info:
            cred.revoke(service="google", user_id="user_1")

        assert exc_info.value.status_code == 404


# ── error hierarchy ───────────────────────────────────────────────────────────

class TestErrorHierarchy:
    def test_consent_required_is_cred_error(self):
        err = ConsentRequiredError("test", "https://example.com")
        assert isinstance(err, CredError)
        assert isinstance(err, ConsentRequiredError)
        assert err.code == "consent_required"
        assert err.status_code == 403
        assert err.consent_url == "https://example.com"

    def test_cred_error_attributes(self):
        err = CredError("something failed", "some_code", 500)
        assert str(err) == "something failed"
        assert err.code == "some_code"
        assert err.status_code == 500
