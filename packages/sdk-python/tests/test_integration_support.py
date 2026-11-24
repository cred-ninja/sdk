"""The supported helper module is usable without installing a framework."""
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from cred import Cred
from cred.integration_support import (
    DelegationTokenStore, agent_did, expiry_epoch, identity_kwargs, resolve_client,
)

CONTEXT = dict(base_url="https://cred.test/", agent_did="did:key:fixture", user_id="alice")


def test_store_instances_and_expiry_boundary(monkeypatch):
    monkeypatch.setattr("cred.integration_support.time.time", lambda: 100.0)
    first, second = DelegationTokenStore(), DelegationTokenStore()
    first.remember("id", "synthetic-secret", 101, **CONTEXT)
    assert first.lookup("id", **CONTEXT) == "synthetic-secret"
    with pytest.raises(ValueError, match="Unknown or expired"):
        second.lookup("id", **CONTEXT)
    monkeypatch.setattr("cred.integration_support.time.time", lambda: 101.0)
    with pytest.raises(ValueError, match="Unknown or expired"):
        first.lookup("id", **CONTEXT)
    assert first._entries == {}


def test_remember_cleanup_and_local_overwrite(monkeypatch):
    monkeypatch.setattr("cred.integration_support.time.time", lambda: 100.0)
    store = DelegationTokenStore(unknown_message="missing")
    store.remember("expired", "synthetic-old", 100, **CONTEXT)
    store.remember("id", "synthetic-new", 200, **CONTEXT)
    assert "expired" not in store._entries
    with pytest.raises(ValueError, match="missing"):
        store.lookup("expired", **CONTEXT)
    store.remember("id", "synthetic-other", 200, **dict(CONTEXT, user_id="bob"))
    with pytest.raises(ValueError, match="different server, agent or user"):
        store.lookup("id", **CONTEXT)
    assert store.lookup("id", **dict(CONTEXT, user_id=None)) == "synthetic-other"


def test_resolve_client_retains_signer_and_refuses_conflicts():
    calls = []
    def signer(*args):
        calls.append(args)
        return {}
    with Cred(base_url="https://cred.test/", sign_request=signer) as client:
        assert resolve_client(None, None, client) == (client, "https://cred.test")
        assert client._sign_request is signer
        with pytest.raises(ValueError, match="not both"):
            resolve_client("synthetic-agent", None, client)
        with pytest.raises(ValueError, match="does not match"):
            resolve_client(None, "https://other.test", client)
    with pytest.raises(TypeError, match="synchronous"):
        resolve_client(None, None, object())
    with pytest.raises(Exception, match="agent_token is required"):
        resolve_client(None, "https://cred.test", None)
    built, url = resolve_client("synthetic-agent", "https://cred.test/", None)
    assert url == "https://cred.test/"
    built.close()


def test_identity_and_expiry(monkeypatch):
    monkeypatch.setattr("cred.integration_support.time.time", lambda: 100.0)
    identity = SimpleNamespace(did="did:key:fixture")
    assert agent_did(identity) == "did:key:fixture"
    assert agent_did(None) == ""
    assert identity_kwargs(None) == {}
    assert identity_kwargs(identity) == {"agent_identity": identity}
    assert expiry_epoch(SimpleNamespace(expires_at=datetime(2030, 1, 1, tzinfo=timezone.utc))) == 1893456000
    assert expiry_epoch(SimpleNamespace(expires_in=30)) == 130
    assert expiry_epoch(SimpleNamespace(expires_in="invalid")) == 100
