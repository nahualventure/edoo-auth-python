from __future__ import annotations
"""
Django view factory for receiving FusionAuth webhooks.

Products own the event semantics; the library owns transport and security:
signature verification (JWKS, no shared secrets), body parsing, and the
response contract (200 handled/ignored, 401 bad signature, 400 malformed).

Usage (product side):

    # urls.py
    from edoo_auth.django.webhooks import fa_webhook_view
    from myapp.fa_events import on_fa_event

    urlpatterns = [
        path('fa/webhooks/', fa_webhook_view(on_fa_event)),
    ]

    # myapp/fa_events.py
    def on_fa_event(event_type, event):     # event = FA's event object
        if event_type == 'user.update':
            ...
        # unhandled event types are simply ignored

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


def fa_webhook_view(on_event):
    """
    Builds a webhook endpoint that verifies FA's signature and dispatches to
    `on_event(event_type, event)`. The callable is invoked synchronously;
    FA webhooks should be configured fire-and-forget (non-transactional).
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
            return HttpResponse(status=401)

        try:
            event = json.loads(request.body)["event"]
            event_type = event["type"]
        except (ValueError, KeyError, TypeError):
            return HttpResponse(status=400)

        on_event(event_type, event)
        return HttpResponse(status=200)

    return view
