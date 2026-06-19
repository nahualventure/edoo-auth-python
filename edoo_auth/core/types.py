from __future__ import annotations
from dataclasses import dataclass


@dataclass(frozen=True)
class TokenClaims:
    sub: str                        # FA user ID
    email: str
    tenant_id: str                  # tid claim
    exp: int
    raw: dict                       # full decoded payload
