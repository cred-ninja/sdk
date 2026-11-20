"""A caller-built client (for example one that signs WIMSE requests) can be passed in."""

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from cred import AsyncCred, Cred, create_wimse_http_signer
from cred_semantic_kernel.plugin import _resolve_client, CredPlugin

BASE_URL = "https://cred.example.com"


@pytest.fixture
def client():
    signer = create_wimse_http_signer(wit="a.b.c", private_key=ec.generate_private_key(ec.SECP256R1()), alg="ES256")
    return Cred(base_url=BASE_URL + "/", sign_request=signer)


def test_passed_client_is_used(client):
    obj = CredPlugin(agent_token=None, user_id="u", app_client_id="app", base_url=None, cred=client)
    assert obj._cred is client and obj._base_url == BASE_URL


def test_resolve_client_takes_the_url_from_the_client(client):
    assert _resolve_client(None, None, client) == (client, BASE_URL)
    assert _resolve_client(None, BASE_URL + "/", client) == (client, BASE_URL)


def test_resolve_client_refuses_conflicts(client):
    with pytest.raises(ValueError, match="not both"):
        _resolve_client("cred_at_x", None, client)
    with pytest.raises(ValueError, match="does not match"):
        _resolve_client(None, "https://other.example.com", client)
    with pytest.raises(TypeError, match="synchronous"):
        _resolve_client(None, None, AsyncCred(agent_token="t", base_url=BASE_URL))


def test_default_construction_is_unchanged():
    built, url = _resolve_client("cred_at_x", BASE_URL, None)
    assert isinstance(built, Cred) and url == BASE_URL
    with pytest.raises(Exception, match="agent_token is required"):
        _resolve_client(None, BASE_URL, None)
