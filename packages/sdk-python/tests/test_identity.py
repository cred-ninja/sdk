"""Cred Python SDK — Identity tests."""

import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from cred import (
    AgentIdentity,
    CRED_PUBLIC_KEY_HEX,
    generate_agent_identity,
    verify_delegation_receipt,
)


class TestGenerateAgentIdentity:
    def test_returns_valid_did_key_string(self):
        identity = generate_agent_identity()
        assert identity.did.startswith("did:key:z")

    def test_exports_private_key_hex(self):
        identity = generate_agent_identity()
        exported = identity.export()
        assert exported["did"] == identity.did
        assert len(exported["private_key_hex"]) == 64

    def test_round_trips_through_export(self):
        identity = generate_agent_identity()
        imported = AgentIdentity.from_export(identity.export())
        assert imported.did == identity.did
        assert imported.public_key == identity.public_key


class TestVerifyDelegationReceipt:
    agent_did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"

    def test_returns_false_for_empty_receipt(self):
        assert verify_delegation_receipt("", expected_did=self.agent_did, cred_public_key="00" * 32) is False

    def test_raises_for_placeholder_public_key(self):
        header = _b64url_json({"alg": "EdDSA", "typ": "JWT"})
        payload = _b64url_json({"sub": self.agent_did})
        receipt = f"{header}.{payload}.sig"
        with pytest.raises(ValueError, match="placeholder"):
            verify_delegation_receipt(receipt, expected_did=self.agent_did)

    def test_returns_true_for_valid_signature(self):
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        public_key_hex = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

        header = _b64url_json({"alg": "EdDSA", "typ": "JWT"})
        payload = _b64url_json({
            "iss": "did:web:cred.ninja",
            "sub": self.agent_did,
            "iat": 1234567890,
            "service": "google",
            "scopes": ["calendar.read"],
            "userId": "user_hash_123",
            "appClientId": "app_xxx",
        })
        signature = private_key.sign(f"{header}.{payload}".encode("utf-8"))
        receipt = f"{header}.{payload}.{_b64url_bytes(signature)}"

        assert verify_delegation_receipt(
            receipt,
            expected_did=self.agent_did,
            cred_public_key=public_key_hex,
        ) is True

    def test_exported_public_key_constant_is_hex_or_placeholder(self):
        assert CRED_PUBLIC_KEY_HEX == "PLACEHOLDER_REPLACE_BEFORE_LAUNCH" or len(CRED_PUBLIC_KEY_HEX) == 64


def _b64url_json(payload: dict[str, object]) -> str:
    return _b64url_bytes(json.dumps(payload, separators=(",", ":")).encode("utf-8"))


def _b64url_bytes(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")
