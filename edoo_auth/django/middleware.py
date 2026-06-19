"""
EdooAuthMiddleware — populates request.auth on every request from the Django session.
Refreshes the token transparently if within the threshold window.
Also populates request.user from the local DB so existing Django views keep working.

Add to MIDDLEWARE after AuthenticationMiddleware:
    "edoo_auth.django.middleware.EdooAuthMiddleware"
"""
import logging
from typing import Optional

from django.conf import settings
from django.http import HttpRequest
from django.utils.deprecation import MiddlewareMixin

from edoo_auth.core.types import TokenClaims
from edoo_auth.django.client import EdooAuthClient

log = logging.getLogger("edoo_auth.middleware")


def _build_client(request: HttpRequest):  # type: Optional[EdooAuthClient]
    cfg = getattr(settings, "EDOO_AUTH_OIDC", None)
    if not cfg:
        return None
    return EdooAuthClient(cfg, request)



class EdooAuthMiddleware(MiddlewareMixin):
    def process_request(self, request: HttpRequest):
        client = _build_client(request)
        if not client:
            return
        slot = client.refresh_if_needed()
        if slot:
            request.auth = TokenClaims(
                sub=slot.user_id,
                email=slot.email,
                tenant_id=slot.tenant_id,
                exp=slot.expires_at // 1000,
                raw={},
            )
            if not request.user.is_authenticated:
                cfg = getattr(settings, "EDOO_AUTH_OIDC", None)
                if cfg and cfg.on_session_resumed:
                    try:
                        cfg.on_session_resumed(request, slot.email)
                    except Exception:
                        log.exception("on_session_resumed hook raised")
        else:
            request.auth = None
