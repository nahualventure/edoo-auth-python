"""
Webhook signature verification — the JWKS-based check products run on every
incoming FusionAuth webhook request.
"""
import base64
import hashlib

import jwt
import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from edoo_auth.core.webhooks import InvalidWebhookSignature, verify_webhook_signature

JWKS_URI = "http://fusionauth:9011/.well-known/jwks.json"

BODY = b'{"event": {"type": "user.update", "user": {"email": "a@b.c"}}}'


def _body_hash(body: bytes) -> str:
    return base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")


def _sign(body: bytes, key, claims_override=None):
    claims = {"request_body_sha256": _body_hash(body)}
    if claims_override is not None:
        claims = claims_override
    return jwt.encode(claims, key, algorithm="RS256")


def test_valid_signature_returns_claims(mock_jwks, rsa_key):
    claims = verify_webhook_signature(BODY, _sign(BODY, rsa_key), jwks_uri=JWKS_URI)
    assert claims["request_body_sha256"] == _body_hash(BODY)


def test_missing_header_rejected(mock_jwks):
    with pytest.raises(InvalidWebhookSignature, match="Missing"):
        verify_webhook_signature(BODY, None, jwks_uri=JWKS_URI)
    with pytest.raises(InvalidWebhookSignature, match="Missing"):
        verify_webhook_signature(BODY, "", jwks_uri=JWKS_URI)


def test_tampered_body_rejected(mock_jwks, rsa_key):
    signature = _sign(BODY, rsa_key)
    tampered = BODY.replace(b"a@b.c", b"evil@x.y")
    with pytest.raises(InvalidWebhookSignature, match="hash mismatch"):
        verify_webhook_signature(tampered, signature, jwks_uri=JWKS_URI)


def test_wrong_key_rejected(mock_jwks):
    other_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    with pytest.raises(InvalidWebhookSignature, match="Invalid signature JWT"):
        verify_webhook_signature(BODY, _sign(BODY, other_key), jwks_uri=JWKS_URI)


def test_garbage_jwt_rejected(mock_jwks):
    with pytest.raises(InvalidWebhookSignature):
        verify_webhook_signature(BODY, "not-a-jwt-at-all", jwks_uri=JWKS_URI)


def test_missing_hash_claim_rejected(mock_jwks, rsa_key):
    signature = _sign(BODY, rsa_key, claims_override={"something_else": "x"})
    with pytest.raises(InvalidWebhookSignature, match="request_body_sha256"):
        verify_webhook_signature(BODY, signature, jwks_uri=JWKS_URI)
