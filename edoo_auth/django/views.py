"""
OIDC views — mount via edoo_auth.django.urls or include manually.

  GET  /auth/login         → redirect to FA authorize
  GET  /auth/callback      → exchange code, create session
  POST /auth/logout        → revoke refresh token, clear session
  POST /auth/switch        → switch active session slot
  POST /auth/switch-school → set active school for current slot
"""
from __future__ import annotations
import logging

from authlib.integrations.django_client import OAuthError
from django.conf import settings
from django.http import HttpRequest, HttpResponseBadRequest, JsonResponse
from django.shortcuts import redirect
from django.views.decorators.http import require_GET, require_POST, require_http_methods

from edoo_auth.core.oidc_types import EdooAuthConfig
from edoo_auth.django.client import EdooAuthClient


def _cfg() -> EdooAuthConfig:
    cfg = getattr(settings, "EDOO_AUTH_OIDC", None)
    if not cfg:
        raise RuntimeError("EDOO_AUTH_OIDC is not configured in Django settings")
    return cfg


def _client(request: HttpRequest) -> EdooAuthClient:
    return EdooAuthClient(_cfg(), request)


def _success_redirect(cfg: EdooAuthConfig) -> str:
    return getattr(cfg, "login_redirect_url", "/")


@require_GET
def login(request: HttpRequest):
    cfg = _cfg()
    tenant_id = request.GET.get("tenant_id") or getattr(cfg, "default_tenant_id", None)
    if not tenant_id:
        return HttpResponseBadRequest("tenant_id is required")

    # Returns an HttpResponse redirect — authlib builds the URL and stores PKCE state
    return EdooAuthClient(cfg, request).initiate_login(
        tenant_id=tenant_id,
        tenant_name=request.GET.get("tenant_name"),
        email=request.GET.get("email"),
        school_id=request.GET.get("school_id"),
        prompt=request.GET.get("prompt"),
    )


log = logging.getLogger("edoo_auth")


@require_GET
def callback(request: HttpRequest):
    error = request.GET.get("error")
    if error:
        return redirect("/?error=" + error)

    cfg = _cfg()
    try:
        result = EdooAuthClient(cfg, request).handle_callback()
    except OAuthError as e:
        log.error("OAuthError: %s", e)
        return redirect(f"/?error={e.error}")
    except ValueError as e:
        log.error("ValueError: %s", e)
        return HttpResponseBadRequest(str(e))
    except Exception as e:
        log.exception("Unexpected error in callback")
        raise

    log.info("callback result: status=%s email=%s", result.status, result.email)
    if result.status == "ok":
        return redirect(_success_redirect(cfg))
    if result.status == "blocked":
        return redirect(f"/?error=blocked&email={result.email}")
    return redirect(f"/?error=not_found&email={result.email}")


@require_http_methods(["GET", "POST"])
def logout(request: HttpRequest):
    from urllib.parse import urlencode
    from django.contrib.auth import logout as django_logout
    cfg = _cfg()
    user_id = request.POST.get("user_id")
    tenant_id = request.POST.get("tenant_id")
    client = _client(request)
    slot = client.get_session()
    resolved_tenant_id = tenant_id or (slot.tenant_id if slot else cfg.default_tenant_id)
    client.logout(user_id=user_id, tenant_id=tenant_id)
    django_logout(request)
    public_url = (cfg.fa_public_url or cfg.fa_base_url).rstrip("/")
    client_id = cfg.on_get_tenant_client(resolved_tenant_id).client_id
    post_logout = request.build_absolute_uri("/user/login/")
    qs = urlencode({"client_id": client_id, "post_logout_redirect_uri": post_logout})
    return redirect(f"{public_url}/oauth2/logout?{qs}")


@require_POST
def switch_account(request: HttpRequest):
    tenant_id = request.POST.get("tenant_id")
    user_id = request.POST.get("user_id")
    if not tenant_id or not user_id:
        return HttpResponseBadRequest("tenant_id and user_id are required")

    cfg = _cfg()
    slot = EdooAuthClient(cfg, request).switch_account(tenant_id, user_id)
    if not slot:
        return JsonResponse({"error": "session not found"}, status=404)
    return redirect(_success_redirect(cfg))


@require_POST
def switch_school(request: HttpRequest):
    school_id = request.POST.get("school_id")
    if not school_id:
        return HttpResponseBadRequest("school_id is required")

    _client(request).set_active_school(school_id)
    return redirect(request.POST.get("next", "/"))
