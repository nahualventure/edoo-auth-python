"""
Session slot storage backed by Django's request.session.

Mirrors the TS session.ts slot model:
  - One slot per tenantId:userId
  - Last-account pointer for active session resolution
  - Last-school pointer per slot
  - Slots are stored as plain dicts in request.session (Django signs the whole session)

Key naming mirrors the TS cookie names for consistency:
  edoo_slot_{product}_{tenantId}:{userId}
  edoo_last_tenant_{product}
  edoo_last_school_{product}_{tenantId}:{userId}
"""
from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from django.http import HttpRequest

from edoo_auth.core.oidc_types import SessionSlot

ROUTING_MAX_AGE = 60 * 60 * 24 * 365


def _slot_key(product: str, tenant_id: str, user_id: str) -> str:
    return f"edoo_slot_{product}_{tenant_id}:{user_id}"


def _last_tenant_key(product: str) -> str:
    return f"edoo_last_tenant_{product}"


def _last_school_key(product: str, tenant_id: str, user_id: str) -> str:
    return f"edoo_last_school_{product}_{tenant_id}:{user_id}"


def _slot_to_dict(slot: SessionSlot) -> dict:
    return {
        "access_token": slot.access_token,
        "refresh_token": slot.refresh_token,
        "expires_at": slot.expires_at,
        "user_id": slot.user_id,
        "tenant_id": slot.tenant_id,
        "tenant_name": slot.tenant_name,
        "email": slot.email,
    }


def _dict_to_slot(d: dict) -> SessionSlot:
    return SessionSlot(
        access_token=d["access_token"],
        refresh_token=d["refresh_token"],
        expires_at=d["expires_at"],
        user_id=d["user_id"],
        tenant_id=d["tenant_id"],
        tenant_name=d["tenant_name"],
        email=d["email"],
    )


def set_session_slot(request: "HttpRequest", product: str, tenant_id: str, slot: SessionSlot) -> None:
    key = _slot_key(product, tenant_id, slot.user_id)
    request.session[key] = _slot_to_dict(slot)
    request.session.modified = True


def get_session_slot(request: "HttpRequest", product: str, tenant_id: str, user_id: str) -> SessionSlot | None:
    key = _slot_key(product, tenant_id, user_id)
    data = request.session.get(key)
    if not data:
        return None
    try:
        return _dict_to_slot(data)
    except (KeyError, TypeError):
        return None


def clear_session_slot(request: "HttpRequest", product: str, tenant_id: str, user_id: str) -> None:
    slot_key = _slot_key(product, tenant_id, user_id)
    school_key = _last_school_key(product, tenant_id, user_id)
    request.session.pop(slot_key, None)
    request.session.pop(school_key, None)
    request.session.modified = True


def get_all_slots(request: "HttpRequest", product: str) -> list[SessionSlot]:
    prefix = f"edoo_slot_{product}_"
    slots = []
    for key, value in request.session.items():
        if key.startswith(prefix):
            try:
                slots.append(_dict_to_slot(value))
            except (KeyError, TypeError):
                pass
    return slots


def get_active_session(request: "HttpRequest", product: str) -> SessionSlot | None:
    last = request.session.get(_last_tenant_key(product))
    if last:
        # last is "tenantId:userId"
        parts = last.split(":", 1)
        if len(parts) == 2:
            slot = get_session_slot(request, product, parts[0], parts[1])
            if slot:
                return slot
    slots = get_all_slots(request, product)
    return slots[0] if slots else None


def set_last_tenant(request: "HttpRequest", product: str, tenant_id: str, user_id: str) -> None:
    request.session[_last_tenant_key(product)] = f"{tenant_id}:{user_id}"
    request.session.modified = True


def set_last_school(request: "HttpRequest", product: str, tenant_id: str, user_id: str, school_id: str) -> None:
    request.session[_last_school_key(product, tenant_id, user_id)] = school_id
    request.session.modified = True


def get_last_school(request: "HttpRequest", product: str, tenant_id: str, user_id: str) -> str | None:
    return request.session.get(_last_school_key(product, tenant_id, user_id))
