"""Characterization of adapter-local plumbing before and after extraction."""
import importlib
import os
import time
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

MODULES = {
    "langchain": "cred_langchain.tools", "crewai": "cred_crewai.tool",
    "semantic-kernel": "cred_semantic_kernel.plugin", "autogen": "cred_autogen.tool",
    "openai-agents": "cred_openai_agents.tool",
}
ADAPTERS = os.environ.get("CRED_NATIVE_ADAPTERS", ",".join(MODULES)).split(",")


@pytest.mark.parametrize("adapter", ADAPTERS)
def test_token_store_contract(adapter):
    module = importlib.import_module(MODULES[adapter])
    context = dict(base_url="https://cred.test/", agent_did="did:key:fixture", user_id="alice")
    module._remember_delegation_token("plumbing", "synthetic-secret", time.time() + 60, **context)
    assert module._lookup_delegation_token("plumbing", **context) == "synthetic-secret"
    # Omitted user has always been the single-user compatibility path.
    assert module._lookup_delegation_token("plumbing", **dict(context, user_id=None)) == "synthetic-secret"
    for key, value in (("base_url", "https://other.test"), ("agent_did", "other"), ("user_id", "bob")):
        with pytest.raises(ValueError, match="different server, agent or user"):
            module._lookup_delegation_token("plumbing", **dict(context, **{key: value}))
    # Remember first: absence before insertion cannot detect a shared-store mutant.
    handle = "local-" + adapter
    module._remember_delegation_token(handle, "synthetic-secret", time.time() + 60, **context)
    assert module._lookup_delegation_token(handle, **context) == "synthetic-secret"
    for other in ADAPTERS:
        if other != adapter:
            foreign = importlib.import_module(MODULES[other])
            # Unique id for each owner avoids coupling to previous test state.
            with pytest.raises(ValueError, match="Unknown or expired"):
                foreign._lookup_delegation_token(handle, **context)
    module._remember_delegation_token("plumbing", "synthetic-secret", time.time() - 1, **context)
    with pytest.raises(ValueError, match="Unknown or expired"):
        module._lookup_delegation_token("plumbing", **context)


@pytest.mark.parametrize("adapter", ADAPTERS)
def test_identity_and_expiry_contract(adapter):
    module = importlib.import_module(MODULES[adapter])
    identity = SimpleNamespace(did="did:key:fixture")
    assert module._agent_did(None) == ""
    assert module._agent_did(identity) == identity.did
    assert module._identity_kwargs(None) == {}
    assert module._identity_kwargs(identity) == {"agent_identity": identity}
    date = datetime(2030, 1, 1, tzinfo=timezone.utc)
    assert module._expiry_epoch(SimpleNamespace(expires_at=date)) == date.timestamp()
    before = time.time()
    assert before + 30 <= module._expiry_epoch(SimpleNamespace(expires_in=30)) <= time.time() + 30
    assert before <= module._expiry_epoch(SimpleNamespace(expires_in="invalid")) <= time.time()
