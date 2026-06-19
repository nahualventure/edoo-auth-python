"""
Shared fixtures for edoo_auth tests.

Generates a real RSA-2048 key pair so we can sign JWTs exactly the way
FusionAuth does. The JWKS client is mocked so no network is needed — but
jwt.decode() runs against the real public key, so signature validation
is real, not faked.
"""
import time
import pytest
from unittest.mock import patch, MagicMock
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import jwt


AUDIENCE = "test-app-client-id"
ISSUER = "http://fusionauth:9011"
JWKS_URI = "http://fusionauth:9011/.well-known/jwks.json"

SCHOOL_A = "00000000-0000-0000-0000-000000000020"
SCHOOL_B = "00000000-0000-0000-0000-000000000021"


@pytest.fixture(scope="session")
def rsa_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )


@pytest.fixture(scope="session")
def sign_token(rsa_key):
    """Returns a factory that mints a signed JWT with the given claims."""
    def _sign(
        sub="user-uuid-1",
        email="teacher@apde.edu",
        tenant_id="tenant-uuid-1",
        exp_offset=300,
        audience=AUDIENCE,
        issuer=ISSUER,
        extra=None,
    ):
        payload = {
            "sub": sub,
            "email": email,
            "tid": tenant_id,
            "aud": audience,
            "iss": issuer,
            "iat": int(time.time()),
            "exp": int(time.time()) + exp_offset,
            **(extra or {}),
        }
        return jwt.encode(payload, rsa_key, algorithm="RS256")
    return _sign


@pytest.fixture
def mock_jwks(rsa_key):
    """
    Patches PyJWKClient so verify_token never hits the network.
    Returns the real RSA public key so jwt.decode() does real crypto validation.
    """
    mock_key = MagicMock()
    mock_key.key = rsa_key.public_key()

    mock_client = MagicMock()
    mock_client.get_signing_key_from_jwt.return_value = mock_key

    with patch("edoo_auth.core.jwks.PyJWKClient", return_value=mock_client):
        import edoo_auth.core.jwks as jwks_mod
        jwks_mod._jwks_clients.clear()
        yield mock_client
