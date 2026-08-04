from __future__ import annotations
"""
Token decoding — no verification, no network, no third-party imports.

Kept free of httpx/authlib so the [django] extra can decode a token without
pulling in the [oidc] stack. Verification lives in core.jwks.
"""
import base64
import json


def decode_access_token(access_token: str) -> dict:
    """
    Decodes without verifying. Safe only when the token arrived directly
    from FA over TLS in a token exchange or refresh response — never from
    an untrusted source.
    """
    payload = access_token.split(".")[1]
    padded = payload + "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))
