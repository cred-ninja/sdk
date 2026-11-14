"""WIMSE HTTP-signature signing (draft-ietf-wimse-http-signature-08).

Requests are captured with respx after the client's request hook has signed
them. Each signature is checked by an independent base builder here (plain
string parsing, not the signer's code) and verified with ``cryptography``.
"""

import asyncio
import base64
import hashlib
import json
import re

import httpx
import pytest
import respx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from cred import AsyncCred, Cred, CredError, WIMSE_SIGNATURE_TAG, create_wimse_http_signer, generate_agent_identity

BASE_URL = "https://cred.example.com"
WIT = "eyJ0eXAiOiJ3aXQrand0In0.eyJzdWIiOiJ3aW1zZTovL2IuZXhhbXBsZS93In0.c2ln"


def p256():
    return ec.generate_private_key(ec.SECP256R1())


def parse_params(signature_input: str):
    m = re.fullmatch(r'wimse=\(([^)]*)\)(.*)', signature_input)
    assert m, signature_input
    names = re.findall(r'"([^"]+)"', m.group(1))
    params = dict(re.findall(r';([a-z-]+)=("(?:[^"\\]|\\.)*"|\d+)', m.group(2)))
    return names, params, signature_input[len("wimse="):]


def independent_base(request: httpx.Request):
    names, _, raw_params = parse_params(request.headers["signature-input"])
    url = request.url
    values = {
        "@method": request.method,
        "@path": url.path,
        "@query": "?" + url.query.decode(),
    }
    lines = [f'"{n}": {values[n] if n.startswith("@") else request.headers[n].strip()}' for n in names]
    lines.append(f'"@signature-params": {raw_params}')
    return "\n".join(lines).encode()


def verify(request: httpx.Request, key) -> None:
    sig = base64.b64decode(re.fullmatch(r"wimse=:([^:]+):", request.headers["signature"]).group(1))
    data = independent_base(request)
    if isinstance(key, ec.EllipticCurvePrivateKey):
        der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
        key.public_key().verify(der, data, ec.ECDSA(hashes.SHA256()))
    else:
        key.public_key().verify(sig, data)


def cred_with(key, alg="ES256", **opts):
    return Cred(base_url=BASE_URL, sign_request=create_wimse_http_signer(wit=WIT, private_key=key, alg=alg, **opts))


class TestSignedRequests:
    @respx.mock
    def test_signed_get_carries_wit_and_required_parameters(self):
        key = p256()
        route = respx.get(f"{BASE_URL}/api/v1/connections").mock(return_value=httpx.Response(200, json={"connections": []}))
        cred_with(key).list_connections(user_id="alice")
        req = route.calls.last.request
        assert req.headers["workload-identity-token"] == WIT
        assert "authorization" not in req.headers
        names, params, _ = parse_params(req.headers["signature-input"])
        assert names[:3] == ["@method", "@path", "@query"]
        assert "workload-identity-token" in names
        assert params["tag"] == f'"{WIMSE_SIGNATURE_TAG}"'
        assert params["wimse-aud"] == f'"{BASE_URL}/api/v1/connections"'
        assert int(params["expires"]) - int(params["created"]) == 60
        assert len(params["nonce"]) >= 18
        assert "keyid" not in params and "alg" not in params
        verify(req, key)

    @respx.mock
    def test_signed_post_covers_body_digest_and_content_type(self):
        key = p256()
        route = respx.post(f"{BASE_URL}/api/v1/delegate").mock(return_value=httpx.Response(200, json={
            "access_token": "t", "token_type": "Bearer", "expires_in": 60, "service": "google",
            "scopes": [], "delegation_id": "d",
        }))
        cred_with(key).delegate(service="google", user_id="alice", app_client_id="app")
        req = route.calls.last.request
        names, _, _ = parse_params(req.headers["signature-input"])
        assert "content-digest" in names and "content-type" in names
        expected = base64.b64encode(hashlib.sha256(req.content).digest()).decode()
        assert req.headers["content-digest"] == f"sha-256=:{expected}:"
        assert json.loads(req.content)["service"] == "google"
        verify(req, key)

    @respx.mock
    def test_use_covers_the_dpop_authorization_header(self):
        key = p256()
        route = respx.post(f"{BASE_URL}/api/v1/use").mock(return_value=httpx.Response(200, json={
            "ok": True, "status": 200, "headers": {}, "body": "{}",
        }))
        cred_with(key).use(token="dt", url="https://api.example.com/x?a=1", method="GET",
                           agent_identity=generate_agent_identity())
        req = route.calls.last.request
        names, _, _ = parse_params(req.headers["signature-input"])
        assert req.headers["authorization"] == "DPoP dt"
        assert "authorization" in names
        verify(req, key)

    @respx.mock
    def test_ed25519_and_query(self):
        key = ed25519.Ed25519PrivateKey.generate()
        route = respx.get(f"{BASE_URL}/api/v1/connections").mock(return_value=httpx.Response(200, json={"connections": []}))
        cred_with(key, alg="EdDSA").list_connections(user_id="alice")
        req = route.calls.last.request
        assert req.url.query.decode() == "user_id=alice"
        verify(req, key)

    @respx.mock
    def test_path_is_signed_as_sent_percent_encoding_kept(self):
        key = p256()
        route = respx.delete(url__regex=r".*/api/v1/connections/.*").mock(return_value=httpx.Response(204))
        cred_with(key).revoke(service="a/b c", user_id="alice")
        req = route.calls.last.request
        sent_path = req.url.raw_path.decode().split("?")[0]
        assert "%" in sent_path
        names, _, _ = parse_params(req.headers["signature-input"])
        sig = base64.b64decode(re.fullmatch(r"wimse=:([^:]+):", req.headers["signature"]).group(1))
        data = independent_base(req).replace(f'"@path": {req.url.path}'.encode(), f'"@path": {sent_path}'.encode())
        der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
        key.public_key().verify(der, data, ec.ECDSA(hashes.SHA256()))

    @respx.mock
    def test_rotating_wit_and_txn_token_are_read_per_request(self):
        key = p256()
        wits = iter(["a.b.c", "d.e.f"])
        txns = iter(["txn-1", "txn-2"])
        signer = create_wimse_http_signer(wit=lambda: next(wits), private_key=key, alg="ES256",
                                          txn_token=lambda: next(txns))
        route = respx.get(f"{BASE_URL}/api/v1/connections").mock(return_value=httpx.Response(200, json={"connections": []}))
        cred = Cred(base_url=BASE_URL, sign_request=signer)
        cred.list_connections(user_id="u")
        cred.list_connections(user_id="u")
        first, second = (c.request for c in route.calls)
        assert (first.headers["workload-identity-token"], first.headers["txn-token"]) == ("a.b.c", "txn-1")
        assert (second.headers["workload-identity-token"], second.headers["txn-token"]) == ("d.e.f", "txn-2")
        assert "txn-token" in parse_params(second.headers["signature-input"])[0]
        verify(second, key)

    @respx.mock
    def test_tampered_request_fails_independent_verification(self):
        key = p256()
        route = respx.get(f"{BASE_URL}/api/v1/connections").mock(return_value=httpx.Response(200, json={"connections": []}))
        cred_with(key).list_connections(user_id="alice")
        req = route.calls.last.request
        req.headers["workload-identity-token"] = "x.y.z"
        with pytest.raises(InvalidSignature):
            verify(req, key)

    @respx.mock
    def test_async_client_signs_the_same_way(self):
        key = p256()
        route = respx.get(f"{BASE_URL}/api/v1/connections").mock(return_value=httpx.Response(200, json={"connections": []}))

        async def go():
            async with AsyncCred(base_url=BASE_URL, sign_request=create_wimse_http_signer(
                    wit=WIT, private_key=key, alg="ES256")) as cred:
                await cred.list_connections(user_id="alice")

        asyncio.run(go())
        verify(route.calls.last.request, key)

    @respx.mock
    def test_agent_token_client_is_unchanged(self):
        route = respx.get(f"{BASE_URL}/api/v1/connections").mock(return_value=httpx.Response(200, json={"connections": []}))
        Cred(agent_token="tok", base_url=BASE_URL).list_connections(user_id="alice")
        req = route.calls.last.request
        assert req.headers["authorization"] == "Bearer tok"
        assert "signature-input" not in req.headers


class TestProblemDetails:
    @respx.mock
    def test_wimse_problem_details_surface_their_type_and_detail(self):
        respx.get(f"{BASE_URL}/api/v1/connections").mock(return_value=httpx.Response(
            400, headers={"content-type": "application/problem+json"},
            json={"type": "https://iana.org/assignments/http-problem-types#wimse-signature-invalid",
                  "title": "Invalid signature", "detail": "signature expired"}))
        with pytest.raises(CredError) as err:
            cred_with(p256()).list_connections(user_id="alice")
        assert err.value.code == "wimse-signature-invalid"
        assert str(err.value) == "signature expired"
        assert err.value.status_code == 400


class TestConfig:
    def test_neither_token_nor_signer_is_refused(self):
        with pytest.raises(CredError, match="agent_token is required"):
            Cred(base_url=BASE_URL)

    def test_token_and_signer_together_are_refused(self):
        signer = create_wimse_http_signer(wit=WIT, private_key=p256(), alg="ES256")
        with pytest.raises(CredError, match="not both"):
            Cred(agent_token="tok", base_url=BASE_URL, sign_request=signer)

    def test_key_and_alg_must_match(self):
        with pytest.raises(CredError, match="P-256"):
            create_wimse_http_signer(wit=WIT, private_key=ed25519.Ed25519PrivateKey.generate(), alg="ES256")
        with pytest.raises(CredError, match="Ed25519"):
            create_wimse_http_signer(wit=WIT, private_key=p256(), alg="EdDSA")
        with pytest.raises(CredError, match="unsupported alg"):
            create_wimse_http_signer(wit=WIT, private_key=p256(), alg="RS256")
        with pytest.raises(CredError, match="P-256"):
            create_wimse_http_signer(wit=WIT, private_key=ec.generate_private_key(ec.SECP384R1()), alg="ES256")

    def test_non_vchar_parameter_values_are_refused(self):
        signer = create_wimse_http_signer(wit=WIT, private_key=p256(), alg="ES256",
                                          audience=lambda url: "https://café.example/")
        with pytest.raises(CredError, match="VCHAR"):
            signer("GET", f"{BASE_URL}/x", {}, None)

    def test_default_audience_drops_query_and_default_port(self):
        signer = create_wimse_http_signer(wit=WIT, private_key=p256(), alg="ES256")
        added = signer("GET", "https://cred.example.com:443/api/v1/x?q=1", {}, None)
        assert parse_params(added["signature-input"])[1]["wimse-aud"] == '"https://cred.example.com/api/v1/x"'
        added = signer("GET", "http://127.0.0.1:3456/api/v1/x", {}, None)
        assert parse_params(added["signature-input"])[1]["wimse-aud"] == '"http://127.0.0.1:3456/api/v1/x"'
