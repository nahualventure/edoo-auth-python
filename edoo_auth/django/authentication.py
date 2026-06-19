from __future__ import annotations
import jwt
import secrets
from django.conf import settings
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.request import Request

from edoo_auth.core.jwks import verify_token
from edoo_auth.core.oidc import decode_access_token
from edoo_auth.core.types import TokenClaims


def _cfg() -> dict:
    cfg = getattr(settings, "EDOO_AUTH", None)
    if not cfg:
        raise RuntimeError("EDOO_AUTH is not configured in Django settings")
    for key in ("FA_BASE_URL", "RESOLVE_USER", "GET_AUDIENCE"):
        if key not in cfg:
            raise RuntimeError(f"EDOO_AUTH['{key}'] is required")
    return cfg


class FusionAuthJWTAuthentication(BaseAuthentication):
    """
    DRF authentication class that validates FA-issued JWTs via JWKS.

    Requires in settings.py:

        EDOO_AUTH = {
            "FA_BASE_URL": "https://your-fa-instance.com",
            "GET_AUDIENCE": lambda tid: "fa-client-id",  # receives tid claim, returns expected client_id
            "RESOLVE_USER": lambda claims: User.objects.filter(fusionauth_user_id=claims.sub).first(),
        }

    Sets request.auth to TokenClaims on success.
    """

    def authenticate(self, request: Request):
        token = self._extract_token(request)
        if token is None:
            return None

        cfg = _cfg()
        fa_base_url = cfg["FA_BASE_URL"]

        # Decode tid unverified so we can resolve the audience before full verification
        unverified = decode_access_token(token)
        audience = cfg["GET_AUDIENCE"](unverified.get("tid", ""))

        try:
            payload = verify_token(
                token,
                jwks_uri=f"{fa_base_url}/.well-known/jwks.json",
                audience=audience,
                issuer=cfg.get("ISSUER", fa_base_url),
                algorithms=cfg.get("ALGORITHMS", ["RS256"]),
            )
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Token expired")
        except jwt.PyJWTError as e:
            raise AuthenticationFailed(f"Invalid token: {e}")

        try:
            claims = TokenClaims(
                sub=payload["sub"],
                email=payload.get("email", ""),
                tenant_id=payload.get("tid", ""),
                exp=payload["exp"],
                raw=payload,
            )
        except KeyError as e:
            raise AuthenticationFailed(f"Token missing required claim: {e}")

        user = cfg["RESOLVE_USER"](claims)
        if user is None:
            raise AuthenticationFailed("User not found")

        return (user, claims)

    def authenticate_header(self, request: Request) -> str:
        return "Bearer"

    def _extract_token(self, request: Request) -> str | None:
        auth = request.META.get("HTTP_AUTHORIZATION", "")
        if not auth.startswith("Bearer "):
            return None
        return auth[len("Bearer "):]


class InternalApiKeyAuthentication(BaseAuthentication):
    """
    Authentication for machine-to-machine calls (e.g. Next.js BFF → Django).
    Validates X-API-Key header against INTERNAL_API_KEY in settings.

    Sets request.user to a sentinel string 'internal' and request.auth to 'api_key'.
    """

    def authenticate(self, request: Request):
        key = request.META.get("HTTP_X_API_KEY")
        if not key:
            return None

        expected = getattr(settings, "INTERNAL_API_KEY", None)
        if not expected:
            raise AuthenticationFailed("INTERNAL_API_KEY not configured")
        if not secrets.compare_digest(key, expected):
            raise AuthenticationFailed("Invalid API key")

        return ("internal", "api_key")
