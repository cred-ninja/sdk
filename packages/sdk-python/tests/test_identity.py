commit 25bb751459879598a621d9fc560828f9f05fa08e
Author: Kieran Sweeney <kilroy@kilroycreative.xyz>
Date:   Tue Mar 3 18:52:09 2026 -0500

    feat(sdk-python): DID agent identity + delegation receipt verification
    
    Mirror TypeScript DID-1 and DID-2 implementations in Python SDK:
    - generate_agent_identity() with Ed25519 key pair
    - AgentIdentity.from_export() for importing persisted identities
    - verify_delegation_receipt() for JWS verification
    - DelegationResult now includes optional receipt
    - Cred.delegate() accepts optional agent_did param
    
    Uses cryptography + base58 packages. 24 new tests (43 total passing).
    
    Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>

diff --git a/packages/sdk-python/tests/test_identity.py b/packages/sdk-python/tests/test_identity.py
new file mode 100644
index 0000000..7a3db06
--- /dev/null
+++ b/packages/sdk-python/tests/test_identity.py
@@ -0,0 +1,302 @@
+"""Cred Python SDK — Identity Tests.
+
+Tests for DID agent identity generation and delegation receipt verification.
+"""
+
+import base64
+import json
+
+import pytest
+from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
+from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
+
+from cred import (
+    AgentIdentity,
+    generate_agent_identity,
+    verify_delegation_receipt,
+    CRED_PUBLIC_KEY_HEX,
+    DelegationResult,
+)
+from cred.client import Cred
+
+
+# ── generate_agent_identity() ─────────────────────────────────────────────────
+
+class TestGenerateAgentIdentity:
+    def test_returns_valid_did_key_string(self):
+        identity = generate_agent_identity()
+
+        assert identity.did.startswith("did:key:z")
+        assert isinstance(identity.did, str)
+
+    def test_did_key_prefix_is_correct(self):
+        identity = generate_agent_identity()
+
+        # z6Mk is the base58btc encoding of multicodec 0xed01 (Ed25519)
+        assert identity.did.startswith("did:key:z6Mk")
+
+    def test_returns_32_byte_public_key(self):
+        identity = generate_agent_identity()
+
+        assert isinstance(identity.public_key, bytes)
+        assert len(identity.public_key) == 32
+
+    def test_returns_32_byte_private_key(self):
+        identity = generate_agent_identity()
+
+        assert isinstance(identity.private_key, bytes)
+        assert len(identity.private_key) == 32
+
+    def test_two_calls_produce_different_keys(self):
+        identity1 = generate_agent_identity()
+        identity2 = generate_agent_identity()
+
+        assert identity1.did != identity2.did
+        assert identity1.public_key != identity2.public_key
+        assert identity1.private_key != identity2.private_key
+
+    def test_export_returns_did_and_private_key_hex(self):
+        identity = generate_agent_identity()
+        exported = identity.export()
+
+        assert exported["did"] == identity.did
+        assert isinstance(exported["private_key_hex"], str)
+        assert len(exported["private_key_hex"]) == 64  # 32 bytes = 64 hex chars
+        assert all(c in "0123456789abcdef" for c in exported["private_key_hex"])
+
+
+# ── AgentIdentity.from_export() ───────────────────────────────────────────────
+
+class TestAgentIdentityFromExport:
+    def test_round_trip_generate_export_import(self):
+        original = generate_agent_identity()
+        exported = original.export()
+
+        imported = AgentIdentity.from_export(exported)
+
+        assert imported.did == original.did
+        assert imported.public_key == original.public_key
+        assert imported.private_key == original.private_key
+
+    def test_imported_identity_can_export_again(self):
+        original = generate_agent_identity()
+        exported1 = original.export()
+
+        imported = AgentIdentity.from_export(exported1)
+        exported2 = imported.export()
+
+        assert exported2["did"] == exported1["did"]
+        assert exported2["private_key_hex"] == exported1["private_key_hex"]
+
+    def test_raises_on_invalid_did_format(self):
+        with pytest.raises(ValueError, match="Invalid DID format"):
+            AgentIdentity.from_export({
+                "did": "not-a-did",
+                "private_key_hex": "00" * 32,
+            })
+
+    def test_raises_on_invalid_private_key_length(self):
+        with pytest.raises(ValueError, match="Invalid private key"):
+            AgentIdentity.from_export({
+                "did": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
+                "private_key_hex": "00" * 16,  # 16 bytes instead of 32
+            })
+
+    def test_raises_on_did_key_mismatch(self):
+        identity1 = generate_agent_identity()
+        identity2 = generate_agent_identity()
+
+        with pytest.raises(ValueError, match="DID does not match"):
+            AgentIdentity.from_export({
+                "did": identity1.did,
+                "private_key_hex": identity2.export()["private_key_hex"],
+            })
+
+
+# ── verify_delegation_receipt() ───────────────────────────────────────────────
+
+class TestVerifyDelegationReceipt:
+    agent_did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
+
+    def test_returns_false_for_none_receipt(self):
+        result = verify_delegation_receipt(
+            None,
+            expected_did=self.agent_did,
+            cred_public_key="00" * 32,
+        )
+        assert result is False
+
+    def test_returns_false_for_empty_string_receipt(self):
+        result = verify_delegation_receipt(
+            "",
+            expected_did=self.agent_did,
+            cred_public_key="00" * 32,
+        )
+        assert result is False
+
+    def test_returns_false_for_malformed_receipt_not_3_parts(self):
+        result = verify_delegation_receipt(
+            "only.two",
+            expected_did=self.agent_did,
+            cred_public_key="00" * 32,
+        )
+        assert result is False
+
+    def test_returns_false_for_malformed_receipt_invalid_base64(self):
+        result = verify_delegation_receipt(
+            "!!!.@@@.###",
+            expected_did=self.agent_did,
+            cred_public_key="00" * 32,
+        )
+        assert result is False
+
+    def test_raises_when_using_placeholder_public_key(self):
+        header = _base64url_encode(json.dumps({"alg": "EdDSA", "typ": "JWT"}))
+        payload = _base64url_encode(json.dumps({"sub": self.agent_did}))
+        receipt = f"{header}.{payload}.fakesig"
+
+        with pytest.raises(ValueError, match="CRED_PUBLIC_KEY_HEX is placeholder"):
+            verify_delegation_receipt(receipt, expected_did=self.agent_did)
+
+    def test_returns_false_for_wrong_algorithm_in_header(self):
+        header = _base64url_encode(json.dumps({"alg": "RS256", "typ": "JWT"}))
+        payload = _base64url_encode(json.dumps({"sub": self.agent_did}))
+        receipt = f"{header}.{payload}.fakesig"
+
+        result = verify_delegation_receipt(
+            receipt,
+            expected_did=self.agent_did,
+            cred_public_key="00" * 32,
+        )
+        assert result is False
+
+    def test_returns_false_for_mismatched_did(self):
+        header = _base64url_encode(json.dumps({"alg": "EdDSA", "typ": "JWT"}))
+        payload = _base64url_encode(json.dumps({"sub": "did:key:z6MkWRONG"}))
+        receipt = f"{header}.{payload}.fakesig"
+
+        result = verify_delegation_receipt(
+            receipt,
+            expected_did=self.agent_did,
+            cred_public_key="00" * 32,
+        )
+        assert result is False
+
+    def test_valid_jws_returns_true_when_signature_matches(self):
+        # Generate a real key pair for this test
+        private_key = Ed25519PrivateKey.generate()
+        public_key = private_key.public_key()
+        cred_public_key_hex = public_key.public_bytes(
+            Encoding.Raw, PublicFormat.Raw
+        ).hex()
+
+        # Create a valid receipt
+        header = _base64url_encode(json.dumps({"alg": "EdDSA", "typ": "JWT"}))
+        payload = _base64url_encode(json.dumps({
+            "iss": "did:web:cred.ninja",
+            "sub": self.agent_did,
+            "iat": 1234567890,
+            "service": "google",
+            "scopes": ["calendar.read"],
+            "userId": "user_hash_123",
+            "appClientId": "app_xxx",
+        }))
+
+        # Sign the message
+        signature_input = f"{header}.{payload}".encode("utf-8")
+        signature = private_key.sign(signature_input)
+        signature_b64 = _base64url_encode_bytes(signature)
+
+        receipt = f"{header}.{payload}.{signature_b64}"
+
+        result = verify_delegation_receipt(
+            receipt,
+            expected_did=self.agent_did,
+            cred_public_key=cred_public_key_hex,
+        )
+        assert result is True
+
+    def test_returns_false_when_signature_is_invalid(self):
+        # Generate a key pair
+        private_key = Ed25519PrivateKey.generate()
+        public_key = private_key.public_key()
+        cred_public_key_hex = public_key.public_bytes(
+            Encoding.Raw, PublicFormat.Raw
+        ).hex()
+
+        # Create a receipt with a fake signature
+        header = _base64url_encode(json.dumps({"alg": "EdDSA", "typ": "JWT"}))
+        payload = _base64url_encode(json.dumps({
+            "iss": "did:web:cred.ninja",
+            "sub": self.agent_did,
+            "iat": 1234567890,
+            "service": "google",
+            "scopes": ["calendar.read"],
+            "userId": "user_hash_123",
+            "appClientId": "app_xxx",
+        }))
+
+        # Use a fake signature
+        fake_signature = _base64url_encode_bytes(bytes(64))
+        receipt = f"{header}.{payload}.{fake_signature}"
+
+        result = verify_delegation_receipt(
+            receipt,
+            expected_did=self.agent_did,
+            cred_public_key=cred_public_key_hex,
+        )
+        assert result is False
+
+
+# ── CRED_PUBLIC_KEY_HEX constant ──────────────────────────────────────────────
+
+class TestCredPublicKeyHex:
+    def test_is_exported_as_placeholder(self):
+        assert CRED_PUBLIC_KEY_HEX == "PLACEHOLDER_REPLACE_BEFORE_LAUNCH"
+
+
+# ── Type definitions ──────────────────────────────────────────────────────────
+
+class TestTypeDefinitions:
+    def test_delegation_result_includes_optional_receipt(self):
+        result = DelegationResult(
+            access_token="token",
+            token_type="Bearer",
+            service="google",
+            scopes=[],
+            delegation_id="del_1",
+            receipt="header.payload.signature",
+        )
+        assert result.receipt == "header.payload.signature"
+
+    def test_delegation_result_works_without_receipt(self):
+        result = DelegationResult(
+            access_token="token",
+            token_type="Bearer",
+            service="google",
+            scopes=[],
+            delegation_id="del_1",
+        )
+        assert result.receipt is None
+
+    def test_cred_delegate_accepts_agent_did(self):
+        # Just verify the method signature accepts agent_did
+        # (actual HTTP call would be mocked in real test)
+        cred = Cred(agent_token="test_token")
+        # Check that the method signature includes agent_did
+        import inspect
+        sig = inspect.signature(cred.delegate)
+        assert "agent_did" in sig.parameters
+        assert sig.parameters["agent_did"].default is None
+
+
+# ── Helpers ───────────────────────────────────────────────────────────────────
+
+def _base64url_encode(data: str) -> str:
+    """Encode string to base64url."""
+    return base64.urlsafe_b64encode(data.encode()).rstrip(b"=").decode()
+
+
+def _base64url_encode_bytes(data: bytes) -> str:
+    """Encode bytes to base64url."""
+    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()
