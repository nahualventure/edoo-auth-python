from __future__ import annotations
"""
Django view factory for receiving FusionAuth webhooks.

Follows the ecosystem FRD pattern: ONE endpoint per action, each backed by
its own FA webhook registration (e.g. `user.update` → `.../user-update`).
Products own the event semantics; the library owns transport and security:
signature verification (JWKS, no shared secrets), body parsing, and the
response contract (200 handled/ignored, 403 bad signature, 400 malformed).

Usage (product side):

    # urls.py
    from edoo_auth.django.webhooks import fa_webhook_view
    from myapp.fa_events import handle_user_update

    urlpatterns = [
        path('fa/webhooks/user-update', fa_webhook_view('user.update', handle_user_update)),
    ]

    # myapp/fa_events.py
    def handle_user_update(event):     # event = FA's event object
        ...

Requires EDOO_AUTH['FA_BASE_URL'] in Django settings (already present for
products using FusionAuthJWTAuthentication).
"""
import json

from django.conf import settings
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from edoo_auth.core.webhooks import (
    SIGNATURE_HEADER,
    InvalidWebhookSignature,
    verify_webhook_signature,
)


def fa_webhook_view(event_type, handler):
    """
    Builds a webhook endpoint for a single FA event type. Verifies FA's
    signature, then calls `handler(event)` when the event matches; any other
    event type is acknowledged with 200 and ignored (the FA webhook for this
    endpoint should only subscribe to `event_type` anyway). The handler runs
    synchronously; configure the FA webhook fire-and-forget.
    """

    @csrf_exempt
    @require_POST
    def view(request):
        jwks_uri = settings.EDOO_AUTH["FA_BASE_URL"].rstrip("/") + "/.well-known/jwks.json"

        try:
            verify_webhook_signature(
                request.body,
                request.headers.get(SIGNATURE_HEADER),
                jwks_uri=jwks_uri,
            )
        except InvalidWebhookSignature:
            return HttpResponse(status=403)

        try:
            event = json.loads(request.body)["event"]
            incoming_type = event["type"]
        except (ValueError, KeyError, TypeError):
            return HttpResponse(status=400)

        if incoming_type == event_type:
            handler(event)
        return HttpResponse(status=200)

    return view
