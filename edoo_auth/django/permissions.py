from rest_framework.permissions import BasePermission
from rest_framework.request import Request

from edoo_auth.core.types import TokenClaims


class IsEdooAuthenticated(BasePermission):
    """
    Confirms FusionAuthJWTAuthentication ran successfully — i.e. the request
    carries a valid FA-issued JWT for a known product identity.

    FusionAuth only gates product-level access; it has no notion of
    per-school authorization. If a consumer needs to scope a request to a
    school (or any other sub-resource), it must enforce that itself against
    its own membership/ownership data — there is no universal convention
    across products (some use an X-School-ID header, some a query param,
    Edoo doesn't scope by school at all) so it doesn't belong in this class.
    """

    def has_permission(self, request: Request, view) -> bool:
        return isinstance(request.auth, TokenClaims)


class IsInternalService(BasePermission):
    """
    Confirms InternalApiKeyAuthentication ran successfully.
    Use on machine-to-machine endpoints (e.g. reconcile).
    """

    def has_permission(self, request: Request, view) -> bool:
        return request.auth == "api_key"
