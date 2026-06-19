from __future__ import annotations
import time
import jwt
from jwt import PyJWKClient, PyJWKClientError

_jwks_clients: dict[str, tuple[PyJWKClient, float]] = {}
_CACHE_TTL = 300  # seconds


def _get_jwks_client(jwks_uri: str) -> PyJWKClient:
    cached = _jwks_clients.get(jwks_uri)
    if cached and time.time() - cached[1] < _CACHE_TTL:
        return cached[0]
    client = PyJWKClient(jwks_uri)
    _jwks_clients[jwks_uri] = (client, time.time())
    return client


def verify_token(
    token: str,
    *,
    jwks_uri: str,
    audience: str | list[str],
    issuer: str,
    algorithms: list[str] | None = None,
) -> dict:
    """
    Verify a FA-issued JWT against the JWKS endpoint.
    Returns the decoded claims dict on success, raises jwt.PyJWTError on failure.
    """
    client = _get_jwks_client(jwks_uri)
    try:
        signing_key = client.get_signing_key_from_jwt(token)
    except PyJWKClientError as e:
        raise jwt.InvalidTokenError(f"JWKS key fetch failed: {e}") from e

    return jwt.decode(
        token,
        signing_key.key,
        algorithms=algorithms or ["RS256"],
        audience=audience,
        issuer=issuer,
    )
