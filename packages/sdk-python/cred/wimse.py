"""WIMSE HTTP-signature request signing (draft-ietf-wimse-http-signature-08).

``create_wimse_http_signer`` returns a function for the client's
``sign_request`` option. The client calls it on the final request (headers and
encoded body exactly as they are sent), so ``authorization``, ``content-type``,
``content-digest``, ``txn-token`` and ``workload-identity-token`` are covered
whenever they are present. This matches the TypeScript SDK's
``createWimseHttpSigner``.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
from typing import Callable, Dict, Mapping, Optional, Union
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from .exceptions import CredError

WIMSE_SIGNATURE_TAG = "wimse-workload-to-workload"
# Section 3: request headers that MUST be signed when they exist.
_COVER_IF_PRESENT = ("content-type", "content-digest", "authorization", "txn-token", "workload-identity-token")
_DEFAULT_PORTS = {"http": 80, "https": 443}

StringSource = Union[str, Callable[[], str]]
RequestSigner = Callable[[str, str, Mapping[str, str], Optional[bytes]], Dict[str, str]]
WimsePrivateKey = Union[ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey]


def _sf_string(value: str) -> str:
    for ch in value:
        if ord(ch) < 0x20 or ord(ch) > 0x7E:
            raise CredError("wimse signer: header or parameter value outside VCHAR/SP", "invalid_config", 0)
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _default_audience(url: str) -> str:
    """The URL's origin and path, without its query (what Cred accepts for its routes)."""
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    port = parts.port
    netloc = host if port is None or _DEFAULT_PORTS.get(scheme) == port else f"{host}:{port}"
    return f"{scheme}://{netloc}{parts.path or '/'}"


def _resolve(source: Optional[Callable[[], Optional[str]]] | StringSource) -> Optional[str]:
    return source() if callable(source) else source


def create_wimse_http_signer(
    wit: StringSource,
    private_key: WimsePrivateKey,
    alg: str,
    audience: Optional[Callable[[str], str]] = None,
    txn_token: Optional[Callable[[], Optional[str]]] = None,
    lifetime_sec: int = 60,
) -> RequestSigner:
    """Build a request signer for ``Cred(sign_request=...)``.

    ``wit`` is the workload's WIT, or a function returning the current one.
    ``private_key`` is the key its ``cnf.jwk`` names: a P-256 key for
    ``ES256``, an Ed25519 key for ``EdDSA`` (or ``Ed25519``). ``audience``
    maps a request URL to its ``wimse-aud``; the default is the URL without
    its query. ``txn_token``, when given, returns a Txn-Token to carry and
    cover on each request. Signatures last ``lifetime_sec`` seconds (Cred
    accepts at most 300).

    The returned function takes ``(method, url, headers, body)`` for the final
    request and returns the headers to add: ``Workload-Identity-Token``,
    ``Txn-Token`` when configured, ``Content-Digest`` when there is a body,
    ``Signature-Input`` and ``Signature``.
    """
    normalized = "EdDSA" if alg == "Ed25519" else alg
    if normalized == "ES256":
        if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(private_key.curve, ec.SECP256R1):
            raise CredError("wimse signer: ES256 needs a P-256 private key", "invalid_config", 0)
    elif normalized == "EdDSA":
        if not isinstance(private_key, ed25519.Ed25519PrivateKey):
            raise CredError("wimse signer: EdDSA needs an Ed25519 private key", "invalid_config", 0)
    else:
        raise CredError(f"wimse signer: unsupported alg {alg!r}", "invalid_config", 0)
    if not isinstance(lifetime_sec, int) or not 1 <= lifetime_sec <= 300:
        raise CredError("wimse signer: lifetime_sec must be an integer from 1 to 300 (Cred refuses longer)",
                        "invalid_config", 0)

    def sign(method: str, url: str, headers: Mapping[str, str], body: Optional[bytes]) -> Dict[str, str]:
        final = {k.lower(): v for k, v in headers.items()}
        added: dict[str, str] = {}
        current_wit = _resolve(wit)
        if not current_wit:
            raise CredError("wimse signer: no WIT available", "invalid_config", 0)
        added["workload-identity-token"] = current_wit
        txn = _resolve(txn_token)
        if txn:
            added["txn-token"] = txn
        if body:
            digest = base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")
            added["content-digest"] = f"sha-256=:{digest}:"
        final.update(added)

        parts = urlsplit(url)
        components = [
            ("@method", method.upper()),
            ("@path", parts.path or "/"),
            # RFC 9421 section 2.2.7: the leading "?" included; "?" alone for no query.
            ("@query", f"?{parts.query}"),
        ]
        for name in _COVER_IF_PRESENT:
            if name in final:
                components.append((name, final[name].strip()))

        created = int(time.time())
        aud = audience(url) if audience else _default_audience(url)
        params = (
            "(" + " ".join(_sf_string(n) for n, _ in components) + ")"
            + f";created={created};expires={created + lifetime_sec}"
            + f";nonce={_sf_string(secrets.token_urlsafe(16))}"
            + f";tag={_sf_string(WIMSE_SIGNATURE_TAG)};wimse-aud={_sf_string(aud)}"
        )
        base = "\n".join(f"{_sf_string(n)}: {v}" for n, v in components) + f'\n"@signature-params": {params}'
        data = base.encode("utf-8")
        if isinstance(private_key, ec.EllipticCurvePrivateKey):
            r, s = decode_dss_signature(private_key.sign(data, ec.ECDSA(hashes.SHA256())))
            signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        else:
            signature = private_key.sign(data)
        added["signature-input"] = f"wimse={params}"
        added["signature"] = f"wimse=:{base64.b64encode(signature).decode('ascii')}:"
        return added

    return sign
