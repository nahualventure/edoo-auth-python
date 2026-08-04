"""
Django integration.

Only the API-auth classes are re-exported here, since they need the [django]
extra alone. EdooAuthClient and EdooAuthMiddleware need authlib from [oidc], and
importing them here would make the DRF auth class unimportable on an API-only
install. Import those from their own modules:

    from edoo_auth.django.client import EdooAuthClient
    from edoo_auth.django.middleware import EdooAuthMiddleware
"""
from edoo_auth.django.authentication import FusionAuthJWTAuthentication, InternalApiKeyAuthentication
from edoo_auth.django.permissions import IsEdooAuthenticated, IsInternalService

__all__ = [
    "FusionAuthJWTAuthentication",
    "InternalApiKeyAuthentication",
    "IsEdooAuthenticated",
    "IsInternalService",
]
