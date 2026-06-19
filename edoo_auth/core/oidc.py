from __future__ import annotations
"""
OIDC logic — authlib handles the protocol plumbing (PKCE, state, nonce,
code exchange, ID token verification). We own everything above that:
session slots, refresh deduplication, revocation.
"""
import base64
import json
import time

import httpx

from edoo_auth.core.oidc_types import EdooAuthConfig, SessionSlot, TenantClient


# ---------------------------------------------------------------------------
# Access token — decode only (trusted via TLS from token exchange/refresh)
# ---------------------------------------------------------------------------

def decode_access_token(access_token: str) -> dict:
    """
    Decodes without verifying. Safe only when the token arrived directly
    from FA over TLS in a token exchange or refresh response — never from
    an untrusted source.
    """
    payload = access_token.split(".")[1]
    padded = payload + "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


# ---------------------------------------------------------------------------
# Token refresh
# ---------------------------------------------------------------------------

def refresh_tokens(config: EdooAuthConfig, tenant_client: TenantClient, refresh_token: str) -> dict | None:
    """
    POST /oauth2/token with grant_type=refresh_token.
    Returns new token response dict, or None if the refresh token is expired/revoked.
    """
    res = httpx.post(
        f"{config.fa_base_url}/oauth2/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": tenant_client.client_id,
            "client_secret": tenant_client.client_secret,
        },
    )
    if not res.is_success:
        return None
    body = res.json()
    if "error" in body:
        return None
    return body


# ---------------------------------------------------------------------------
# Token revocation
# ---------------------------------------------------------------------------

def revoke_token(config: EdooAuthConfig, tenant_client: TenantClient, refresh_token: str) -> None:
    """Best-effort refresh token revocation — never raises."""
    try:
        httpx.post(
            f"{config.fa_base_url}/oauth2/token/revoke",
            data={
                "token": refresh_token,
                "client_id": tenant_client.client_id,
                "client_secret": tenant_client.client_secret,
            },
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Session slot builder
# ---------------------------------------------------------------------------

def build_session_slot(token: dict, id_claims: dict, tenant_id: str, tenant_name: str) -> SessionSlot:
    expires_in = token.get("expires_in", 3600)
    return SessionSlot(
        access_token=token["access_token"],
        refresh_token=token["refresh_token"],
        expires_at=int(time.time() * 1000) + expires_in * 1000,
        user_id=id_claims["sub"],
        tenant_id=tenant_id,
        tenant_name=tenant_name,
        email=id_claims["email"],
    )
