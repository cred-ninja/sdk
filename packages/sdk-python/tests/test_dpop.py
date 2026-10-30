"""Cred Python SDK — DPoP proof (RFC 9449, Cred profile) tests.

Uses respx to mock httpx requests. No real network calls.
"""

import asyncio
import base64
import hashlib
import json
import time

import httpx
import pytest
import respx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from cred import AsyncCred, Cred, CredError, create_dpop_proof, generate_agent_identity

BASE_URL = "https://cred.example.com"
TOKEN = "cred_at_test_token"
HANDLE = "del_handle_abc"

HANDLE_RESPONSE = {
    "token_type": "Delegation",
    "expires_in": 900,
    "service": "google",
    "user_id": "user_1",
    "scopes": ["calendar.readonly"],
    "delegation_id": HANDLE,
}
USE_RESPONSE = {"status": 200, "ok": True, "contentType": "application/json", "body": {}}


def b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def decode_proof(proof: str) -> tuple[dict, dict, bytes]:
    header_b64, claims_b64, signature_b64 = proof.split(".")
    return (
        json.loads(b64url_decode(header_b64)),
        json.loads(b64url_decode(claims_b64)),
        b64url_decode(signature_b64),
    )


def expected_ath(handle: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(handle.encode("ascii")).digest()).rstrip(b"=").decode("ascii")


class TestCreateDpopProof:
    def test_header_carries_public_jwk_only(self):
        identity = generate_agent_identity()
        header, _, _ = decode_proof(create_dpop_proof(identity, "POST", f"{BASE_URL}/api/v1/delegate"))

        assert header["alg"] == "EdDSA"
        assert header["typ"] == "dpop+jwt"
        assert header["jwk"] == {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": base64.urlsafe_b64encode(identity.public_key).rstrip(b"=").decode("ascii"),
        }
        assert "d" not in header["jwk"]

    def test_claims_name_the_request(self):
        identity = generate_agent_identity()
        before = int(time.time())
        _, claims, _ = decode_proof(create_dpop_proof(identity, "POST", f"{BASE_URL}/api/v1/delegate"))

        assert claims["htm"] == "POST"
        assert claims["htu"] == f"{BASE_URL}/api/v1/delegate"
        assert isinstance(claims["iat"], int)
        assert before <= claims["iat"] <= int(time.time())
        assert isinstance(claims["jti"], str) and claims["jti"]
        assert "ath" not in claims

    def test_ath_present_only_with_handle(self):
        identity = generate_agent_identity()
        _, claims, _ = decode_proof(create_dpop_proof(identity, "POST", f"{BASE_URL}/api/v1/use", HANDLE))

        assert claims["ath"] == expected_ath(HANDLE)
        assert "=" not in claims["ath"]

    def test_jti_is_fresh_per_proof(self):
        identity = generate_agent_identity()
        first = decode_proof(create_dpop_proof(identity, "POST", f"{BASE_URL}/api/v1/use"))[1]
        second = decode_proof(create_dpop_proof(identity, "POST", f"{BASE_URL}/api/v1/use"))[1]
        assert first["jti"] != second["jti"]

    def test_encoding_is_compact_and_unpadded(self):
        identity = generate_agent_identity()
        proof = create_dpop_proof(identity, "POST", f"{BASE_URL}/api/v1/use", HANDLE)
        header_b64, claims_b64, signature_b64 = proof.split(".")

        assert "=" not in proof
        assert b" " not in b64url_decode(header_b64)
        assert b" " not in b64url_decode(claims_b64)
        assert len(b64url_decode(signature_b64)) == 64

    def test_signature_verifies_with_identity_public_key(self):
        identity = generate_agent_identity()
        proof = create_dpop_proof(identity, "POST", f"{BASE_URL}/api/v1/use", HANDLE)
        header_b64, claims_b64, _ = proof.split(".")
        _, _, signature = decode_proof(proof)

        Ed25519PublicKey.from_public_bytes(identity.public_key).verify(
            signature, f"{header_b64}.{claims_b64}".encode("ascii"),
        )

    def test_signature_does_not_verify_with_another_key(self):
        proof = create_dpop_proof(generate_agent_identity(), "POST", f"{BASE_URL}/api/v1/use")
        header_b64, claims_b64, _ = proof.split(".")
        _, _, signature = decode_proof(proof)

        with pytest.raises(InvalidSignature):
            Ed25519PublicKey.from_public_bytes(generate_agent_identity().public_key).verify(
                signature, f"{header_b64}.{claims_b64}".encode("ascii"),
            )

    def test_rejects_htu_with_query(self):
        with pytest.raises(ValueError, match="query or fragment"):
            create_dpop_proof(generate_agent_identity(), "POST", f"{BASE_URL}/api/v1/use?x=1")


class TestClientSendsDpop:
    @respx.mock
    def test_delegate_handle_sends_agent_did_and_proof(self):
        identity = generate_agent_identity()
        route = respx.post(f"{BASE_URL}/api/v1/delegate").mock(return_value=httpx.Response(200, json=HANDLE_RESPONSE))

        with Cred(agent_token=TOKEN, base_url=BASE_URL) as cred:
            cred.delegate_handle(service="google", user_id="user_1", app_client_id="app_1", agent_identity=identity)

        request = route.calls[0].request
        assert json.loads(request.read())["agent_did"] == identity.did
        assert request.headers["Authorization"] == f"Bearer {TOKEN}"
        _, claims, _ = decode_proof(request.headers["DPoP"])
        assert claims["htm"] == "POST"
        assert claims["htu"] == f"{BASE_URL}/api/v1/delegate"
        assert "ath" not in claims

    @respx.mock
    def test_delegate_handle_accepts_matching_agent_did(self):
        identity = generate_agent_identity()
        route = respx.post(f"{BASE_URL}/api/v1/delegate").mock(return_value=httpx.Response(200, json=HANDLE_RESPONSE))

        with Cred(agent_token=TOKEN, base_url=BASE_URL) as cred:
            cred.delegate_handle(service="google", user_id="user_1", agent_did=identity.did, agent_identity=identity)

        assert json.loads(route.calls[0].request.read())["agent_did"] == identity.did

    def test_delegate_handle_rejects_mismatched_agent_did(self):
        identity = generate_agent_identity()
        with respx.mock:
            with Cred(agent_token=TOKEN, base_url=BASE_URL) as cred:
                with pytest.raises(CredError, match="different agents"):
                    cred.delegate_handle(
                        service="google",
                        user_id="user_1",
                        agent_did=generate_agent_identity().did,
                        agent_identity=identity,
                    )
            assert respx.calls.call_count == 0

    @respx.mock
    def test_delegate_handle_without_identity_sends_no_proof(self):
        route = respx.post(f"{BASE_URL}/api/v1/delegate").mock(return_value=httpx.Response(200, json=HANDLE_RESPONSE))

        with Cred(agent_token=TOKEN, base_url=BASE_URL) as cred:
            cred.delegate_handle(service="google", user_id="user_1", agent_did="did:key:zLegacy")

        request = route.calls[0].request
        assert "DPoP" not in request.headers
        assert json.loads(request.read())["agent_did"] == "did:key:zLegacy"

    @respx.mock
    def test_use_sends_proof_bound_to_handle(self):
        identity = generate_agent_identity()
        route = respx.post(f"{BASE_URL}/api/v1/use").mock(return_value=httpx.Response(200, json=USE_RESPONSE))

        with Cred(agent_token=TOKEN, base_url=BASE_URL) as cred:
            cred.use(delegation_id=HANDLE, url="https://www.googleapis.com/calendar/v3/x", agent_identity=identity)

        request = route.calls[0].request
        _, claims, _ = decode_proof(request.headers["DPoP"])
        assert claims["htu"] == f"{BASE_URL}/api/v1/use"
        assert claims["ath"] == expected_ath(HANDLE)

    @respx.mock
    def test_use_without_identity_sends_no_proof(self):
        route = respx.post(f"{BASE_URL}/api/v1/use").mock(return_value=httpx.Response(200, json=USE_RESPONSE))

        with Cred(agent_token=TOKEN, base_url=BASE_URL) as cred:
            cred.use(delegation_id=HANDLE, url="https://www.googleapis.com/calendar/v3/x")

        assert "DPoP" not in route.calls[0].request.headers

    @respx.mock
    def test_htu_uses_normalised_base_url(self):
        identity = generate_agent_identity()
        route = respx.post(f"{BASE_URL}/api/v1/use").mock(return_value=httpx.Response(200, json=USE_RESPONSE))

        with Cred(agent_token=TOKEN, base_url=f"{BASE_URL}/") as cred:
            cred.use(delegation_id=HANDLE, url="https://www.googleapis.com/calendar/v3/x", agent_identity=identity)

        _, claims, _ = decode_proof(route.calls[0].request.headers["DPoP"])
        assert claims["htu"] == f"{BASE_URL}/api/v1/use"

    @respx.mock
    def test_async_client_sends_proofs(self):
        identity = generate_agent_identity()
        delegate_route = respx.post(f"{BASE_URL}/api/v1/delegate").mock(
            return_value=httpx.Response(200, json=HANDLE_RESPONSE),
        )
        use_route = respx.post(f"{BASE_URL}/api/v1/use").mock(return_value=httpx.Response(200, json=USE_RESPONSE))

        async def scenario():
            async with AsyncCred(agent_token=TOKEN, base_url=BASE_URL) as client:
                handle = await client.delegate_handle(service="google", user_id="user_1", agent_identity=identity)
                await client.use(
                    delegation_id=handle.delegation_id,
                    url="https://www.googleapis.com/calendar/v3/x",
                    agent_identity=identity,
                )

        asyncio.run(scenario())

        delegate_request = delegate_route.calls[0].request
        assert json.loads(delegate_request.read())["agent_did"] == identity.did
        _, delegate_claims, _ = decode_proof(delegate_request.headers["DPoP"])
        assert delegate_claims["htu"] == f"{BASE_URL}/api/v1/delegate"
        assert "ath" not in delegate_claims

        _, use_claims, _ = decode_proof(use_route.calls[0].request.headers["DPoP"])
        assert use_claims["htu"] == f"{BASE_URL}/api/v1/use"
        assert use_claims["ath"] == expected_ath(HANDLE)

    def test_async_client_rejects_mismatched_agent_did(self):
        identity = generate_agent_identity()

        async def scenario():
            async with AsyncCred(agent_token=TOKEN, base_url=BASE_URL) as client:
                await client.delegate_handle(
                    service="google",
                    user_id="user_1",
                    agent_did=generate_agent_identity().did,
                    agent_identity=identity,
                )

        with respx.mock:
            with pytest.raises(CredError, match="different agents"):
                asyncio.run(scenario())
