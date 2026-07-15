from __future__ import annotations
"""
FusionAuth webhook signature verification (FA >= 1.48).

FA signs every webhook request with a key from Key Master and sends the
signature in the `X-FusionAuth-Signature-JWT` header: a JWT whose payload
carries `request_body_sha256` — the base64-encoded SHA-256 of the RAW request
body. Verification (per FA docs):

  1. Verify the JWT's signature against FA's JWKS endpoint (the JWT `kid`
     header selects the key, so rotation needs no receiver changes).
  2. SHA-256 the raw body bytes exactly as received — before any parsing.
  3. Constant-time compare against the claim.

Products call `verify_webhook_signature()` from their webhook endpoint and
treat `InvalidWebhookSignature` as an authentication failure (reject with 401).
"""
import base64
import hashlib
import hmac

import jwt
from jwt import PyJWKClientError

from edoo_auth.core.jwks import _get_jwks_client

# Asymmetric algorithms only — the whole point is JWKS, no shared secrets.
_ALGORITHMS = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA"]

SIGNATURE_HEADER = "X-FusionAuth-Signature-JWT"


class InvalidWebhookSignature(Exception):
    """The webhook request could not be authenticated as coming from FA."""


def verify_webhook_signature(raw_body: bytes, signature_jwt: str | None, *, jwks_uri: str) -> dict:
    """
    Verifies a FusionAuth webhook request. Returns the signature JWT claims on
    success, raises InvalidWebhookSignature otherwise.

    `raw_body` MUST be the unmodified request body bytes — the hash is over
    the exact bytes FA sent, not re-serialized JSON.
    """
    if not signature_jwt:
        raise InvalidWebhookSignature("Missing {} header".format(SIGNATURE_HEADER))

    try:
        signing_key = _get_jwks_client(jwks_uri).get_signing_key_from_jwt(signature_jwt)
    except PyJWKClientError as e:
        raise InvalidWebhookSignature(f"JWKS key lookup failed: {e}") from e

    try:
        claims = jwt.decode(
            signature_jwt,
            signing_key.key,
            algorithms=_ALGORITHMS,
            # The signature JWT is not an access token: no aud/iss/exp claims.
            options={"verify_aud": False},
        )
    except jwt.PyJWTError as e:
        raise InvalidWebhookSignature(f"Invalid signature JWT: {e}") from e

    expected = claims.get("request_body_sha256")
    if not expected:
        raise InvalidWebhookSignature("Signature JWT has no request_body_sha256 claim")

    actual = base64.b64encode(hashlib.sha256(raw_body).digest()).decode("ascii")
    if not hmac.compare_digest(expected, actual):
        raise InvalidWebhookSignature("Request body hash mismatch")

    return claims
