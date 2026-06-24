from __future__ import annotations
from dataclasses import dataclass
from typing import Callable


@dataclass
class SessionSlot:
    access_token: str
    refresh_token: str
    expires_at: int                 # Unix ms
    user_id: str
    tenant_id: str
    tenant_name: str
    email: str


@dataclass(frozen=True)
class TenantClient:
    client_id: str
    client_secret: str


@dataclass(frozen=True)
class CallbackResult:
    status: str                     # 'ok' | 'not_found' | 'blocked'
    email: str | None = None


@dataclass
class EdooAuthConfig:
    product: str
    fa_base_url: str
    redirect_uri: str
    on_get_tenant_client: Callable[[str], TenantClient]
    on_profile_check: Callable[[str, str], dict]    # email, school_id → {status}
    on_login_success: Callable | None = None        # (request, email) → None — called after successful OIDC callback
    on_session_resumed: Callable | None = None      # (request, email) → None — called each request when token slot is valid but Django session has no authenticated user
    fa_public_url: str | None = None                # browser-facing authorize URL, defaults to fa_base_url
    token_refresh_threshold_seconds: int = 120
    session_max_age: int = 60 * 60 * 24 * 30       # 30 days
    login_redirect_url: str = '/dashboard'
    default_tenant_id: str = ''
