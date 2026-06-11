"""Cred Python SDK — Security regression tests.

These tests are deliberately separate from `test_client.py` so they do not
depend on `respx` (the optional dev dep that mocks httpx). The claims they
guard — HTTPS enforcement and token-isolation in errors — are part of the
public security contract in SECURITY-AUDITS.md and must keep running even
when optional test deps are missing.
"""

from __future__ import annotations

import pytest

from cred import AsyncCred, Cred, CredError


TOKEN = "cred_at_test_token"


# ── HTTPS enforcement at construction time ─────────────────────────────────────


class TestHttpsEnforcement:
    """Backs the Transport Security audit claim: non-HTTPS remote base URLs
    are rejected at construction time so the agent token cannot be sent in
    cleartext."""

    @pytest.mark.parametrize(
        "url",
        [
            "http://remote.example.com",
            "http://api.example.com:8080",
            "http://attacker.example/api",
        ],
    )
    def test_sync_rejects_non_https_remote(self, url: str) -> None:
        with pytest.raises(CredError, match="HTTPS"):
            Cred(agent_token=TOKEN, base_url=url)

    @pytest.mark.parametrize(
        "url",
        [
            "http://remote.example.com",
            "http://api.example.com:8080",
        ],
    )
    def test_async_rejects_non_https_remote(self, url: str) -> None:
        with pytest.raises(CredError, match="HTTPS"):
            AsyncCred(agent_token=TOKEN, base_url=url)

    @pytest.mark.parametrize(
        "url",
        [
            "http://localhost:3456",
            "http://127.0.0.1:3456",
            "http://[::1]:3456",
        ],
    )
    def test_sync_allows_http_localhost_for_dev(self, url: str) -> None:
        # Construction must NOT raise for documented localhost dev URLs.
        client = Cred(agent_token=TOKEN, base_url=url)
        assert client._base_url == url

    def test_sync_accepts_https_remote(self) -> None:
        client = Cred(agent_token=TOKEN, base_url="https://cred.example.com")
        assert client._base_url == "https://cred.example.com"


# ── Token-isolation regression ─────────────────────────────────────────────────


class TestTokenIsolation:
    """Backs the Design Principles claim: agent tokens are not interpolated
    into thrown errors, response messages, or log output. The construction
    path is the easiest leak surface to assert against — if a future
    refactor starts echoing the token into validation messages, this test
    fails."""

    SECRET = "cred_at_super_secret_value_do_not_leak"

    def test_https_rejection_error_does_not_contain_token(self) -> None:
        try:
            Cred(agent_token=self.SECRET, base_url="http://remote.example.com")
        except CredError as err:
            assert self.SECRET not in str(err)
            assert self.SECRET not in repr(err)
        else:
            raise AssertionError("expected CredError")

    def test_invalid_base_url_error_does_not_contain_token(self) -> None:
        try:
            Cred(agent_token=self.SECRET, base_url="not a url at all")
        except CredError as err:
            assert self.SECRET not in str(err)
            assert self.SECRET not in repr(err)
        else:
            raise AssertionError("expected CredError")

    def test_missing_base_url_error_does_not_contain_token(self) -> None:
        try:
            Cred(agent_token=self.SECRET, base_url=None)
        except CredError as err:
            assert self.SECRET not in str(err)
            assert self.SECRET not in repr(err)
        else:
            raise AssertionError("expected CredError")
