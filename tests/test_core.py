"""
Unit tests for edoo_auth.core.jwks — no Django, no network.
"""
import time
import pytest
import jwt
from unittest.mock import patch, MagicMock

from edoo_auth.core.jwks import verify_token, _get_jwks_client, _jwks_clients, _CACHE_TTL
from conftest import AUDIENCE, ISSUER, JWKS_URI


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_valid_token_returns_claims(mock_jwks, sign_token):
    token = sign_token()
    claims = verify_token(token, jwks_uri=JWKS_URI, audience=AUDIENCE, issuer=ISSUER)

    assert claims["sub"] == "user-uuid-1"
    assert claims["email"] == "teacher@apde.edu"
    assert claims["tid"] == "tenant-uuid-1"


# ---------------------------------------------------------------------------
# Expired token
# ---------------------------------------------------------------------------

def test_expired_token_raises(mock_jwks, sign_token):
    token = sign_token(exp_offset=-10)  # already expired
    with pytest.raises(jwt.ExpiredSignatureError):
        verify_token(token, jwks_uri=JWKS_URI, audience=AUDIENCE, issuer=ISSUER)


# ---------------------------------------------------------------------------
# Wrong audience
# ---------------------------------------------------------------------------

def test_wrong_audience_raises(mock_jwks, sign_token):
    token = sign_token(audience="some-other-app")
    with pytest.raises(jwt.InvalidAudienceError):
        verify_token(token, jwks_uri=JWKS_URI, audience=AUDIENCE, issuer=ISSUER)


# ---------------------------------------------------------------------------
# Wrong issuer
# ---------------------------------------------------------------------------

def test_wrong_issuer_raises(mock_jwks, sign_token):
    token = sign_token(issuer="http://evil.example.com")
    with pytest.raises(jwt.InvalidIssuerError):
        verify_token(token, jwks_uri=JWKS_URI, audience=AUDIENCE, issuer=ISSUER)


# ---------------------------------------------------------------------------
# JWKS key fetch failure (FA down)
# ---------------------------------------------------------------------------

def test_jwks_fetch_failure_raises(sign_token):
    from jwt import PyJWKClientError

    mock_client = MagicMock()
    mock_client.get_signing_key_from_jwt.side_effect = PyJWKClientError("connection refused")

    with patch("edoo_auth.core.jwks.PyJWKClient", return_value=mock_client):
        import edoo_auth.core.jwks as jwks_mod
        jwks_mod._jwks_clients.clear()

        token = sign_token()
        with pytest.raises(jwt.InvalidTokenError, match="JWKS key fetch failed"):
            verify_token(token, jwks_uri=JWKS_URI, audience=AUDIENCE, issuer=ISSUER)


# ---------------------------------------------------------------------------
# JWKS client cache — second call within TTL reuses the same client instance
# ---------------------------------------------------------------------------

def test_jwks_client_is_cached(sign_token):
    import edoo_auth.core.jwks as jwks_mod
    jwks_mod._jwks_clients.clear()

    with patch("edoo_auth.core.jwks.PyJWKClient") as MockClient:
        MockClient.return_value = MagicMock()
        _get_jwks_client(JWKS_URI)
        _get_jwks_client(JWKS_URI)
        # PyJWKClient constructor called only once despite two lookups
        assert MockClient.call_count == 1


def test_jwks_client_cache_expires(sign_token):
    import edoo_auth.core.jwks as jwks_mod
    jwks_mod._jwks_clients.clear()

    with patch("edoo_auth.core.jwks.PyJWKClient") as MockClient:
        MockClient.return_value = MagicMock()
        _get_jwks_client(JWKS_URI)

        # Backdate the cached timestamp so it looks expired
        uri, (client, _) = next(iter(jwks_mod._jwks_clients.items()))
        jwks_mod._jwks_clients[uri] = (client, time.time() - _CACHE_TTL - 1)

        _get_jwks_client(JWKS_URI)
        assert MockClient.call_count == 2
