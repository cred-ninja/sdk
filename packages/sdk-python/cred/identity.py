"""Agent Identity — DID:key generation and management.

Uses Ed25519 key pairs with did:key encoding (RFC draft-multiformats-multibase).
Uses `cryptography` package for Ed25519 operations.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

# ── Cred Public Key (pinned at build time) ───────────────────────────────────

CRED_PUBLIC_KEY_HEX = "PLACEHOLDER_REPLACE_BEFORE_LAUNCH"

# ── Base58btc alphabet (Bitcoin) ─────────────────────────────────────────────

_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _encode_base58(data: bytes) -> str:
    """Encode bytes to base58btc string."""
    if len(data) == 0:
        return ""

    # Count leading zeros
    zeros = 0
    for byte in data:
        if byte != 0:
            break
        zeros += 1

    # Convert to big integer and repeatedly divide by 58
    size = (len(data) * 138 // 100) + 1
    b58 = [0] * size
    length = 0

    for byte in data:
        carry = byte
        i = 0
        for j in range(size - 1, -1, -1):
            if carry == 0 and i >= length:
                break
            carry += 256 * b58[j]
            b58[j] = carry % 58
            carry //= 58
            i += 1
        length = i

    # Skip leading zeros in base58 result
    start = size - length
    while start < size and b58[start] == 0:
        start += 1

    # Build result string
    result = "1" * zeros
    for i in range(start, size):
        result += _BASE58_ALPHABET[b58[i]]

    return result


def _decode_base58(s: str) -> bytes:
    """Decode base58btc string to bytes."""
    if len(s) == 0:
        return b""

    # Build alphabet lookup
    lookup = {char: i for i, char in enumerate(_BASE58_ALPHABET)}

    # Count leading '1's (zeros)
    zeros = 0
    for char in s:
        if char != "1":
            break
        zeros += 1

    # Decode to bytes
    size = (len(s) * 733 // 1000) + 1
    result = [0] * size
    length = 0

    for char in s:
        value = lookup.get(char)
        if value is None:
            raise ValueError(f"Invalid base58 character: {char}")

        carry = value
        i = 0
        for j in range(size - 1, -1, -1):
            if carry == 0 and i >= length:
                break
            carry += 58 * result[j]
            result[j] = carry % 256
            carry //= 256
            i += 1
        length = i

    # Skip leading zeros in byte array
    start = size - length
    while start < size and result[start] == 0:
        start += 1

    # Prepend zeros and return
    return bytes([0] * zeros + result[start:])


# ── Ed25519 multicodec prefix ────────────────────────────────────────────────

# did:key multicodec prefix for Ed25519 public keys: 0xed01
# Encoded as varint: [0xed, 0x01]
_ED25519_MULTICODEC_PREFIX = bytes([0xED, 0x01])


# ── Types ────────────────────────────────────────────────────────────────────


@dataclass
class ExportedIdentity:
    """Exported identity for persistence."""

    did: str
    private_key_hex: str


class AgentIdentity:
    """Agent identity with Ed25519 key pair and DID.

    Attributes:
        did: DID in did:key format: did:key:z6Mk<base58-encoded-public-key>
        public_key: Raw 32-byte Ed25519 public key
        private_key: Raw 32-byte Ed25519 private key
    """

    def __init__(
        self,
        did: str,
        public_key: bytes,
        private_key: bytes,
    ) -> None:
        self._did = did
        self._public_key = bytes(public_key)
        self._private_key = bytes(private_key)

    @property
    def did(self) -> str:
        return self._did

    @property
    def public_key(self) -> bytes:
        return bytes(self._public_key)

    @property
    def private_key(self) -> bytes:
        return bytes(self._private_key)

    def export(self) -> dict[str, str]:
        """Export identity for persistence.

        Returns:
            Dict with 'did' and 'private_key_hex' keys.
        """
        return {
            "did": self._did,
            "private_key_hex": self._private_key.hex(),
        }

    @classmethod
    def from_export(cls, data: dict[str, str]) -> "AgentIdentity":
        """Import a persisted agent identity.

        Args:
            data: Dict with 'did' and 'private_key_hex' keys.

        Returns:
            AgentIdentity with full key pair.

        Raises:
            ValueError: If DID format is invalid or private key is wrong size.
        """
        did = data["did"]
        private_key_hex = data["private_key_hex"]

        # Validate DID format
        if not did.startswith("did:key:z"):
            raise ValueError("Invalid DID format: must start with did:key:z")

        # Decode private key from hex
        private_key_bytes = bytes.fromhex(private_key_hex)
        if len(private_key_bytes) != 32:
            raise ValueError("Invalid private key: must be 32 bytes")

        # Derive public key from private key using cryptography
        private_key_obj = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        public_key_obj = private_key_obj.public_key()
        public_key_bytes = public_key_obj.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        # Verify DID matches derived public key
        derived_did = _public_key_to_did(public_key_bytes)
        if derived_did != did:
            raise ValueError("DID does not match derived public key")

        return cls(did, public_key_bytes, private_key_bytes)


def _public_key_to_did(public_key: bytes) -> str:
    """Convert raw Ed25519 public key to did:key format."""
    # Prepend multicodec prefix and encode as base58btc
    prefixed = _ED25519_MULTICODEC_PREFIX + public_key
    # 'z' is the multibase prefix for base58btc
    return f"did:key:z{_encode_base58(prefixed)}"


def generate_agent_identity() -> AgentIdentity:
    """Generate a new agent identity with Ed25519 key pair.

    Returns:
        AgentIdentity with DID, public key, private key, and export function.
    """
    # Generate new Ed25519 key pair
    private_key_obj = Ed25519PrivateKey.generate()
    public_key_obj = private_key_obj.public_key()

    # Extract raw key bytes
    private_key_bytes = private_key_obj.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_key_bytes = public_key_obj.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    # Build did:key from public key
    did = _public_key_to_did(public_key_bytes)

    return AgentIdentity(did, public_key_bytes, private_key_bytes)


# ── Receipt Verification ─────────────────────────────────────────────────────


def _base64url_decode(s: str) -> bytes:
    """Decode base64url string to bytes."""
    import base64

    # Replace URL-safe characters and add padding
    s = s.replace("-", "+").replace("_", "/")
    # Add padding
    padding = 4 - (len(s) % 4)
    if padding != 4:
        s += "=" * padding
    return base64.b64decode(s)


def verify_delegation_receipt(
    receipt: Optional[str],
    expected_did: str,
    cred_public_key: Optional[str] = None,
) -> bool:
    """Verify a delegation receipt from the Cred API.

    Receipts are JWS compact serialization (header.payload.signature) signed
    by Cred's Ed25519 key. Returns True if signature is valid and DID matches.

    Args:
        receipt: JWS compact serialization string (or None).
        expected_did: Expected agent DID (sub claim in receipt payload).
        cred_public_key: Cred's public key in hex format (defaults to CRED_PUBLIC_KEY_HEX).

    Returns:
        True if receipt is valid and matches expected DID, False otherwise.

    Raises:
        ValueError: If CRED_PUBLIC_KEY_HEX is still placeholder.
    """
    # Return False for missing receipts (don't throw)
    if not receipt:
        return False

    cred_public_key_hex = cred_public_key or CRED_PUBLIC_KEY_HEX

    # Placeholder check — can't verify without real key
    if cred_public_key_hex == "PLACEHOLDER_REPLACE_BEFORE_LAUNCH":
        raise ValueError("CRED_PUBLIC_KEY_HEX is placeholder — cannot verify receipts")

    try:
        # Parse JWS compact serialization: header.payload.signature
        parts = receipt.split(".")
        if len(parts) != 3:
            return False

        header_b64, payload_b64, signature_b64 = parts

        # Decode and validate header
        header = json.loads(_base64url_decode(header_b64).decode("utf-8"))
        if header.get("alg") != "EdDSA" or header.get("typ") != "JWT":
            return False

        # Decode payload and verify DID matches
        payload = json.loads(_base64url_decode(payload_b64).decode("utf-8"))
        if payload.get("sub") != expected_did:
            return False

        # Verify signature
        signature_input = f"{header_b64}.{payload_b64}".encode("utf-8")
        signature = _base64url_decode(signature_b64)

        # Build Ed25519 public key object from raw bytes
        cred_public_key_bytes = bytes.fromhex(cred_public_key_hex)
        if len(cred_public_key_bytes) != 32:
            return False

        public_key_obj = Ed25519PublicKey.from_public_bytes(cred_public_key_bytes)
        public_key_obj.verify(signature, signature_input)
        return True
    except Exception:
        return False
