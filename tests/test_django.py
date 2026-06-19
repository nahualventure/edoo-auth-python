"""
Integration tests for edoo_auth.django — uses Django's test client.
No real FusionAuth, no network. verify_token is mocked at the boundary.
"""
import pytest
from unittest.mock import patch
import jwt

from rest_framework.test import APIRequestFactory
from rest_framework.request import Request

from edoo_auth.django.authentication import FusionAuthJWTAuthentication, InternalApiKeyAuthentication
from edoo_auth.django.permissions import IsEdooAuthenticated, IsInternalService
from edoo_auth.core.types import TokenClaims
from conftest import AUDIENCE, ISSUER, JWKS_URI


pytestmark = pytest.mark.django_db


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

VALID_CLAIMS = TokenClaims(
    sub="user-uuid-1",
    email="teacher@apde.edu",
    tenant_id="tenant-uuid-1",
    exp=9999999999,
    raw={},
)

DJANGO_SETTINGS = {
    "FA_BASE_URL": "http://fusionauth:9011",
    "GET_AUDIENCE": lambda tid: AUDIENCE,
    "RESOLVE_USER": lambda claims: claims,
}

factory = APIRequestFactory()


def _authenticate(token: str | None = "Bearer fake.jwt.token"):
    """Build a request and run it through authentication + permission."""
    request = factory.get("/api/secret/")
    if token:
        request.META["HTTP_AUTHORIZATION"] = token
    return request


def _run_auth(request, verify_return=None, verify_raise=None):
    """Run FusionAuthJWTAuthentication against a request with mocked verify_token."""
    with patch("edoo_auth.django.authentication.verify_token") as mock_verify, \
         patch("edoo_auth.django.authentication.decode_access_token", return_value={"tid": "tenant-uuid-1"}), \
         patch("edoo_auth.django.authentication._cfg", return_value=DJANGO_SETTINGS):
        if verify_raise:
            mock_verify.side_effect = verify_raise
        else:
            mock_verify.return_value = {
                "sub": verify_return.sub,
                "email": verify_return.email,
                "tid": verify_return.tenant_id,
                "exp": verify_return.exp,
            }
        auth = FusionAuthJWTAuthentication()
        from rest_framework.request import Request
        drf_request = Request(request)
        return auth.authenticate(drf_request)


# ---------------------------------------------------------------------------
# FusionAuthJWTAuthentication
# ---------------------------------------------------------------------------

class TestFusionAuthJWTAuthentication:

    def test_valid_token_sets_auth_to_token_claims(self, sign_token, mock_jwks):
        request = _authenticate()
        result = _run_auth(request, verify_return=VALID_CLAIMS)

        assert result is not None
        user, claims = result
        assert isinstance(claims, TokenClaims)
        assert claims.email == "teacher@apde.edu"
        assert claims.sub == "user-uuid-1"

    def test_missing_authorization_header_returns_none(self):
        """No header = this authenticator abstains (returns None), lets DRF try others."""
        request = _authenticate(token=None)
        result = _run_auth(request, verify_return=VALID_CLAIMS)
        assert result is None

    def test_non_bearer_scheme_returns_none(self):
        request = _authenticate(token="Basic dXNlcjpwYXNz")
        result = _run_auth(request, verify_return=VALID_CLAIMS)
        assert result is None

    def test_expired_token_raises_authentication_failed(self):
        from rest_framework.exceptions import AuthenticationFailed
        request = _authenticate()
        with pytest.raises(AuthenticationFailed, match="Token expired"):
            _run_auth(request, verify_raise=jwt.ExpiredSignatureError("expired"))

    def test_invalid_token_raises_authentication_failed(self):
        from rest_framework.exceptions import AuthenticationFailed
        request = _authenticate()
        with pytest.raises(AuthenticationFailed, match="Invalid token"):
            _run_auth(request, verify_raise=jwt.InvalidTokenError("bad signature"))

    def test_unknown_user_raises_authentication_failed(self):
        """RESOLVE_USER returning None means the user doesn't exist locally."""
        from rest_framework.exceptions import AuthenticationFailed

        settings_no_user = {**DJANGO_SETTINGS, "RESOLVE_USER": lambda c: None}
        request = _authenticate()

        with patch("edoo_auth.django.authentication.verify_token") as mock_verify, \
             patch("edoo_auth.django.authentication.decode_access_token", return_value={"tid": "tenant-uuid-1"}), \
             patch("edoo_auth.django.authentication._cfg", return_value=settings_no_user):
            mock_verify.return_value = {
                "sub": VALID_CLAIMS.sub, "email": VALID_CLAIMS.email,
                "tid": VALID_CLAIMS.tenant_id,
                "exp": VALID_CLAIMS.exp,
            }
            auth = FusionAuthJWTAuthentication()
            from rest_framework.request import Request
            with pytest.raises(AuthenticationFailed, match="User not found"):
                auth.authenticate(Request(request))


# ---------------------------------------------------------------------------
# IsEdooAuthenticated permission
# ---------------------------------------------------------------------------

class TestIsEdooAuthenticated:

    def _make_drf_request(self, auth=VALID_CLAIMS):
        raw = factory.get("/")
        from rest_framework.request import Request
        req = Request(raw)
        req._auth = auth
        req._user = auth
        return req

    def test_valid_claims_grants_access(self):
        req = self._make_drf_request()
        assert IsEdooAuthenticated().has_permission(req, None) is True

    def test_non_token_claims_auth_denies(self):
        """String auth (e.g. api_key sentinel) must not pass IsEdooAuthenticated."""
        req = self._make_drf_request(auth="api_key")
        assert IsEdooAuthenticated().has_permission(req, None) is False

    def test_unauthenticated_request_denies(self):
        req = self._make_drf_request(auth=None)
        assert IsEdooAuthenticated().has_permission(req, None) is False


# ---------------------------------------------------------------------------
# InternalApiKeyAuthentication
# ---------------------------------------------------------------------------

class TestInternalApiKeyAuthentication:

    def _make_request(self, key: str | None):
        raw = factory.post("/api/reconcile/")
        if key:
            raw.META["HTTP_X_API_KEY"] = key
        from rest_framework.request import Request
        return Request(raw)

    def test_correct_key_authenticates(self):
        req = self._make_request("my-secret-key")
        with patch("edoo_auth.django.authentication.settings") as mock_settings:
            mock_settings.INTERNAL_API_KEY = "my-secret-key"
            result = InternalApiKeyAuthentication().authenticate(req)
        assert result == ("internal", "api_key")

    def test_wrong_key_raises_authentication_failed(self):
        from rest_framework.exceptions import AuthenticationFailed
        req = self._make_request("wrong-key")
        with patch("edoo_auth.django.authentication.settings") as mock_settings:
            mock_settings.INTERNAL_API_KEY = "my-secret-key"
            with pytest.raises(AuthenticationFailed, match="Invalid API key"):
                InternalApiKeyAuthentication().authenticate(req)

    def test_missing_key_returns_none(self):
        """No header = abstain, not reject."""
        req = self._make_request(None)
        result = InternalApiKeyAuthentication().authenticate(req)
        assert result is None

    def test_unconfigured_secret_raises(self):
        from rest_framework.exceptions import AuthenticationFailed
        req = self._make_request("any-key")
        with patch("edoo_auth.django.authentication.settings") as mock_settings:
            mock_settings.INTERNAL_API_KEY = None
            with pytest.raises(AuthenticationFailed, match="INTERNAL_API_KEY not configured"):
                InternalApiKeyAuthentication().authenticate(req)


# ---------------------------------------------------------------------------
# IsInternalService permission
# ---------------------------------------------------------------------------

class TestIsInternalService:

    def _make_request(self, auth):
        raw = factory.post("/")
        from rest_framework.request import Request
        req = Request(raw)
        req._auth = auth
        return req

    def test_api_key_sentinel_grants_access(self):
        assert IsInternalService().has_permission(self._make_request("api_key"), None) is True

    def test_token_claims_denies(self):
        """A JWT-authenticated request must not access internal endpoints."""
        assert IsInternalService().has_permission(self._make_request(VALID_CLAIMS), None) is False

    def test_unauthenticated_denies(self):
        assert IsInternalService().has_permission(self._make_request(None), None) is False


# ---------------------------------------------------------------------------
# _cfg() misconfiguration
# ---------------------------------------------------------------------------

class TestCfgValidation:

    def _request(self):
        raw = factory.get("/")
        raw.META["HTTP_AUTHORIZATION"] = "Bearer fake.jwt.token"
        return Request(raw)

    def test_missing_edoo_auth_setting_raises(self):
        with patch("edoo_auth.django.authentication.settings") as mock_settings:
            del mock_settings.EDOO_AUTH  # attribute doesn't exist
            type(mock_settings).EDOO_AUTH = property(lambda s: None)
            auth = FusionAuthJWTAuthentication()
            with pytest.raises(RuntimeError, match="EDOO_AUTH is not configured"):
                auth.authenticate(self._request())

    def test_missing_required_key_raises(self):
        with patch("edoo_auth.django.authentication._cfg", side_effect=RuntimeError("EDOO_AUTH['GET_AUDIENCE'] is required")):
            auth = FusionAuthJWTAuthentication()
            with pytest.raises(RuntimeError, match="GET_AUDIENCE"):
                auth.authenticate(self._request())


# ---------------------------------------------------------------------------
# Token with missing required claims (sub / exp) → 401, not 500
# ---------------------------------------------------------------------------

class TestMalformedTokenClaims:

    def _run(self, payload):
        raw = factory.get("/")
        raw.META["HTTP_AUTHORIZATION"] = "Bearer fake.jwt.token"
        req = Request(raw)

        with patch("edoo_auth.django.authentication.verify_token", return_value=payload), \
             patch("edoo_auth.django.authentication.decode_access_token", return_value={"tid": "t1"}), \
             patch("edoo_auth.django.authentication._cfg", return_value=DJANGO_SETTINGS):
            from rest_framework.exceptions import AuthenticationFailed
            with pytest.raises(AuthenticationFailed, match="missing required claim"):
                FusionAuthJWTAuthentication().authenticate(req)

    def test_missing_sub_raises_authentication_failed(self):
        # Key absent entirely — payload["sub"] KeyErrors
        self._run({"email": "x@y.com", "tid": "t1", "exp": 9999999999})

    def test_missing_exp_raises_authentication_failed(self):
        self._run({"sub": "u1", "email": "x@y.com", "tid": "t1"})


# ---------------------------------------------------------------------------
# authenticate_header — DRF uses this to decide 401 vs 403
# ---------------------------------------------------------------------------

def test_authenticate_header_returns_bearer():
    raw = factory.get("/")
    assert FusionAuthJWTAuthentication().authenticate_header(Request(raw)) == "Bearer"


# ---------------------------------------------------------------------------
# ISSUER and ALGORITHMS overrides are forwarded to verify_token
# ---------------------------------------------------------------------------

def test_custom_issuer_and_algorithms_forwarded(mock_jwks, sign_token):
    custom_settings = {
        **DJANGO_SETTINGS,
        "ISSUER": "https://custom-issuer.example.com",
        "ALGORITHMS": ["RS512"],
    }
    raw = factory.get("/")
    raw.META["HTTP_AUTHORIZATION"] = "Bearer fake.jwt.token"
    req = Request(raw)

    with patch("edoo_auth.django.authentication.verify_token") as mock_verify, \
         patch("edoo_auth.django.authentication.decode_access_token", return_value={"tid": "t1"}), \
         patch("edoo_auth.django.authentication._cfg", return_value=custom_settings):
        mock_verify.return_value = {
            "sub": "u1", "email": "a@b.com", "tid": "t1",
            "exp": 9999999999,
        }
        FusionAuthJWTAuthentication().authenticate(req)

    _, kwargs = mock_verify.call_args
    assert kwargs["issuer"] == "https://custom-issuer.example.com"
    assert kwargs["algorithms"] == ["RS512"]
