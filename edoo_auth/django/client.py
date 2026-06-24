from __future__ import annotations
"""
EdooAuthClient — Django counterpart of the TS EdooAuthClient class.

authlib handles: PKCE generation, state/nonce, code exchange, ID token verification.
We handle: multi-slot sessions, refresh deduplication, revocation.
"""
import logging
import threading
import time

log = logging.getLogger("edoo_auth")

from authlib.integrations.django_client import OAuth
from django.http import HttpRequest, HttpResponse

from edoo_auth.core.oidc import (
    build_session_slot,
    refresh_tokens,
    revoke_token,
)
from edoo_auth.core.session import (
    clear_session_slot,
    get_active_session,
    get_all_slots,
    get_last_school,
    get_session_slot,
    set_last_school,
    set_last_tenant,
    set_session_slot,
)
from edoo_auth.core.oidc_types import CallbackResult, EdooAuthConfig, SessionSlot


# One OAuth registry per process — providers are registered lazily per product+tenant.
#
# KNOWN LIMITATION: this registry, and the refresh dedup below, are process-local.
# They do nothing to coordinate across multiple gunicorn workers or replicas. If two
# processes race a refresh for the same session slot, FA's refresh-token rotation
# will invalidate one of them — that request's user gets logged out even though a
# valid refreshed session exists in the other process. Safe today only as long as
# this isn't actually run with >1 worker/replica per active session; revisit with a
# distributed lock (app-provided, not hardcoded to a specific backend like Redis) if
# that ever changes.
_oauth = OAuth()
_registered: set[str] = set()
_registry_lock = threading.Lock()


def _get_oauth_client(config: EdooAuthConfig, tenant_id: str, tenant_client_id: str, tenant_client_secret: str):
    """
    Returns an authlib OAuth client registered for this product+clientId combo.
    Registers on first call, reuses on subsequent calls.

    Fetches the OIDC discovery doc via fa_base_url (server-to-server), then
    replaces fa_base_url with fa_public_url in the authorize_url so the browser
    is redirected to the correct public host. Token exchange and JWKS still use
    the internal base URL.
    """
    key = f"{config.product}:{tenant_client_id}"
    if key not in _registered:
        with _registry_lock:
            if key not in _registered:
                import httpx as _httpx
                internal = config.fa_base_url.rstrip('/')
                public = (config.fa_public_url or config.fa_base_url).rstrip('/')
                discovery_url = f"{internal}/.well-known/openid-configuration?tenantId={tenant_id}"
                meta = _httpx.get(discovery_url, timeout=10).json()

                authorize_url = meta["authorization_endpoint"].replace(internal, public, 1)

                _oauth.register(
                    name=key,
                    client_id=tenant_client_id,
                    client_secret=tenant_client_secret,
                    authorize_url=authorize_url,
                    access_token_url=meta["token_endpoint"],
                    jwks_uri=meta["jwks_uri"],
                    client_kwargs={
                        "scope": "openid email offline_access",
                        "code_challenge_method": "S256",
                    },
                )
                _registered.add(key)
    return _oauth.create_client(key)


# In-flight refresh deduplication — keyed by "product:tenantId:userId".
# Process-local only — see the limitation noted above the OAuth registry.
_refresh_lock = threading.Lock()
_in_flight_refresh: dict[str, threading.Event] = {}
_refresh_results: dict[str, SessionSlot | None] = {}


class EdooAuthClient:
    def __init__(self, config: EdooAuthConfig, request: HttpRequest):
        self.config = config
        self.request = request

    # ── Tenant resolution ─────────────────────────────────────────────────────

    # ── Login initiation ──────────────────────────────────────────────────────

    def initiate_login(self, tenant_id: str, *, tenant_name: str | None = None, email: str | None = None, school_id: str | None = None, prompt: str | None = None) -> HttpResponse:
        """
        Redirects the browser to the FA authorize URL.
        authlib generates PKCE verifier+challenge, state, nonce and stores them
        in request.session automatically.
        Returns an HttpResponse redirect.
        """
        tenant_client = self.config.on_get_tenant_client(tenant_id)
        oauth_client = _get_oauth_client(self.config, tenant_id, tenant_client.client_id, tenant_client.client_secret)

        # Store our own extras in session — authlib owns the PKCE/state/nonce keys
        self.request.session["edoo_pkce_tenant"] = tenant_id
        self.request.session["edoo_pkce_tenant_name"] = tenant_name or tenant_id
        if school_id:
            self.request.session["edoo_pkce_school"] = school_id
        self.request.session.modified = True

        extras = {}
        if email:
            extras["login_hint"] = email
        if prompt:
            extras["prompt"] = prompt

        return oauth_client.authorize_redirect(self.request, self.config.redirect_uri, **extras)

    # ── Callback handling ─────────────────────────────────────────────────────

    def handle_callback(self) -> CallbackResult:
        """
        Completes the OIDC flow. authlib validates state, exchanges the code,
        and verifies the ID token (signature, iss, aud, exp, nonce).
        We then run the profile check and persist the session slot.

        School-level access is not part of this flow — FusionAuth gates
        product-level identity only. Per-school authorization is an
        app-layer concern, enforced by each consumer against its own
        membership data.
        """
        session = self.request.session
        tenant_id = session.pop("edoo_pkce_tenant", None)
        tenant_name = session.pop("edoo_pkce_tenant_name", tenant_id)
        school_id = session.pop("edoo_pkce_school", None)
        session.modified = True

        if not tenant_id:
            raise ValueError("Missing PKCE tenant — session expired or tampered")

        tenant_client = self.config.on_get_tenant_client(tenant_id)
        oauth_client = _get_oauth_client(self.config, tenant_id, tenant_client.client_id, tenant_client.client_secret)

        token = oauth_client.authorize_access_token(self.request)
        id_claims = token["userinfo"]  # authlib fetches and verifies userinfo / id_token claims

        profile = self.config.on_profile_check(id_claims["email"], school_id)

        if profile["status"] == "ok":
            slot = build_session_slot(token, id_claims, tenant_id, tenant_name)
            set_session_slot(self.request, self.config.product, tenant_id, slot)
            set_last_tenant(self.request, self.config.product, tenant_id, id_claims["sub"])
            if school_id:
                set_last_school(self.request, self.config.product, tenant_id, id_claims["sub"], school_id)
            log.info("login success user=%s", id_claims["email"])
            if self.config.on_login_success:
                try:
                    self.config.on_login_success(self.request, id_claims["email"])
                except Exception:
                    log.exception("on_login_success hook raised")

        if profile["status"] == "ok":
            return CallbackResult(status="ok", email=id_claims["email"])
        if profile["status"] == "blocked":
            return CallbackResult(status="blocked", email=id_claims["email"])
        return CallbackResult(status="not_found", email=id_claims["email"])

    # ── Session access ────────────────────────────────────────────────────────

    def get_session(self) -> SessionSlot | None:
        return get_active_session(self.request, self.config.product)

    def get_sessions(self) -> list[SessionSlot]:
        return get_all_slots(self.request, self.config.product)

    def get_active_school(self) -> str | None:
        slot = self.get_session()
        if not slot:
            return None
        return get_last_school(self.request, self.config.product, slot.tenant_id, slot.user_id)

    def set_active_school(self, school_id: str) -> None:
        slot = self.get_session()
        if not slot:
            return
        set_last_school(self.request, self.config.product, slot.tenant_id, slot.user_id, school_id)

    def switch_account(self, tenant_id: str, user_id: str) -> SessionSlot | None:
        slot = get_session_slot(self.request, self.config.product, tenant_id, user_id)
        if not slot:
            return None

        threshold_ms = self.config.token_refresh_threshold_seconds * 1000
        if int(time.time() * 1000) > slot.expires_at - threshold_ms:
            slot = self._do_refresh(slot)

        if slot:
            set_last_tenant(self.request, self.config.product, tenant_id, slot.user_id)

        return slot

    # ── Refresh ───────────────────────────────────────────────────────────────

    def refresh_if_needed(self) -> SessionSlot | None:
        slot = self.get_session()
        if not slot:
            return None

        threshold_ms = self.config.token_refresh_threshold_seconds * 1000
        if int(time.time() * 1000) > slot.expires_at - threshold_ms:
            return self._do_refresh(slot)

        return slot

    def _do_refresh(self, slot: SessionSlot) -> SessionSlot | None:
        key = f"{self.config.product}:{slot.tenant_id}:{slot.user_id}"

        with _refresh_lock:
            if key in _in_flight_refresh:
                event = _in_flight_refresh[key]
            else:
                event = threading.Event()
                _in_flight_refresh[key] = event
                event = None

        if event is not None:
            event.wait(timeout=10)
            return _refresh_results.get(key)

        done_event = _in_flight_refresh[key]
        try:
            result = self._perform_refresh(slot)
            _refresh_results[key] = result
            return result
        finally:
            done_event.set()
            with _refresh_lock:
                _in_flight_refresh.pop(key, None)
                _refresh_results.pop(key, None)

    def _perform_refresh(self, slot: SessionSlot) -> SessionSlot | None:
        tenant_client = self.config.on_get_tenant_client(slot.tenant_id)
        token = refresh_tokens(self.config, tenant_client, slot.refresh_token)

        if not token:
            clear_session_slot(self.request, self.config.product, slot.tenant_id, slot.user_id)
            return None

        expires_in = token.get("expires_in", 3600)

        new_slot = SessionSlot(
            access_token=token["access_token"],
            refresh_token=token.get("refresh_token", slot.refresh_token),
            expires_at=int(time.time() * 1000) + expires_in * 1000,
            user_id=slot.user_id,
            tenant_id=slot.tenant_id,
            tenant_name=slot.tenant_name,
            email=slot.email,
        )

        set_session_slot(self.request, self.config.product, slot.tenant_id, new_slot)
        return new_slot

    # ── Logout ────────────────────────────────────────────────────────────────

    def logout(self, *, user_id: str | None = None, tenant_id: str | None = None) -> None:
        if user_id and tenant_id:
            slot = get_session_slot(self.request, self.config.product, tenant_id, user_id)
        else:
            slot = self.get_session()
        if not slot:
            return

        try:
            tenant_client = self.config.on_get_tenant_client(slot.tenant_id)
            revoke_token(self.config, tenant_client, slot.refresh_token)
        except Exception:
            pass

        clear_session_slot(self.request, self.config.product, slot.tenant_id, slot.user_id)
