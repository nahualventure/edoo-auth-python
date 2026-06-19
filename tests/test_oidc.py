"""
Tests for the OIDC logic we own:
  - decode_access_token
  - session slot storage (set/get/clear/enumerate/pointer logic)
"""
import base64
import json
import time
import pytest
from unittest.mock import MagicMock, patch

from edoo_auth.core.oidc import decode_access_token
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
from edoo_auth.core.oidc_types import SessionSlot


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

PRODUCT = "class"
TENANT_A = "tenant-a"
TENANT_B = "tenant-b"
USER_1 = "user-uuid-1"
USER_2 = "user-uuid-2"
SCHOOL_A = "00000000-0000-0000-0000-000000000020"
SCHOOL_B = "00000000-0000-0000-0000-000000000021"


def make_slot(user_id=USER_1, tenant_id=TENANT_A, email="teacher@apde.edu") -> SessionSlot:
    return SessionSlot(
        access_token="tok",
        refresh_token="ref",
        expires_at=int(time.time() * 1000) + 3_600_000,
        user_id=user_id,
        tenant_id=tenant_id,
        tenant_name="APDE",
        email=email,
    )


class FakeSession(dict):
    """Dict that accepts .modified = True like Django's session."""
    modified = False


def make_request() -> MagicMock:
    req = MagicMock()
    req.session = FakeSession()
    return req


# ---------------------------------------------------------------------------
# decode_access_token
# ---------------------------------------------------------------------------

class TestDecodeAccessToken:

    def _make_token(self, payload: dict) -> str:
        encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        return f"header.{encoded}.signature"

    def test_decodes_standard_claims(self):
        payload = {"sub": "user-1", "email": "a@b.com", "exp": 9999}
        token = self._make_token(payload)
        claims = decode_access_token(token)
        assert claims["sub"] == "user-1"
        assert claims["email"] == "a@b.com"

    def test_handles_padding_correctly(self):
        # Payloads of different lengths to exercise all 4 padding cases
        for extra_bytes in range(4):
            payload = {"sub": "x" * (10 + extra_bytes)}
            token = self._make_token(payload)
            assert decode_access_token(token)["sub"] == "x" * (10 + extra_bytes)


# ---------------------------------------------------------------------------
# session storage
# ---------------------------------------------------------------------------

class TestSessionStorage:

    def test_set_and_get_slot(self):
        req = make_request()
        slot = make_slot()
        set_session_slot(req, PRODUCT, TENANT_A, slot)
        retrieved = get_session_slot(req, PRODUCT, TENANT_A, USER_1)
        assert retrieved is not None
        assert retrieved.user_id == USER_1
        assert retrieved.access_token == "tok"

    def test_get_nonexistent_slot_returns_none(self):
        req = make_request()
        assert get_session_slot(req, PRODUCT, TENANT_A, "ghost-user") is None

    def test_clear_slot_removes_it(self):
        req = make_request()
        set_session_slot(req, PRODUCT, TENANT_A, make_slot())
        clear_session_slot(req, PRODUCT, TENANT_A, USER_1)
        assert get_session_slot(req, PRODUCT, TENANT_A, USER_1) is None

    def test_clear_slot_also_removes_last_school(self):
        req = make_request()
        set_session_slot(req, PRODUCT, TENANT_A, make_slot())
        set_last_school(req, PRODUCT, TENANT_A, USER_1, SCHOOL_A)
        clear_session_slot(req, PRODUCT, TENANT_A, USER_1)
        assert get_last_school(req, PRODUCT, TENANT_A, USER_1) is None

    def test_get_all_slots_returns_all_stored(self):
        req = make_request()
        set_session_slot(req, PRODUCT, TENANT_A, make_slot(user_id=USER_1, tenant_id=TENANT_A))
        set_session_slot(req, PRODUCT, TENANT_B, make_slot(user_id=USER_2, tenant_id=TENANT_B))
        slots = get_all_slots(req, PRODUCT)
        user_ids = {s.user_id for s in slots}
        assert user_ids == {USER_1, USER_2}

    def test_get_all_slots_ignores_other_products(self):
        req = make_request()
        set_session_slot(req, PRODUCT, TENANT_A, make_slot())
        set_session_slot(req, "finance", TENANT_A, make_slot(user_id=USER_2))
        slots = get_all_slots(req, PRODUCT)
        assert len(slots) == 1
        assert slots[0].user_id == USER_1

    def test_get_active_session_follows_last_tenant_pointer(self):
        req = make_request()
        set_session_slot(req, PRODUCT, TENANT_A, make_slot(user_id=USER_1, tenant_id=TENANT_A))
        set_session_slot(req, PRODUCT, TENANT_B, make_slot(user_id=USER_2, tenant_id=TENANT_B))
        set_last_tenant(req, PRODUCT, TENANT_B, USER_2)
        active = get_active_session(req, PRODUCT)
        assert active is not None
        assert active.user_id == USER_2

    def test_get_active_session_falls_back_to_first_slot(self):
        req = make_request()
        set_session_slot(req, PRODUCT, TENANT_A, make_slot())
        # No last_tenant pointer set
        active = get_active_session(req, PRODUCT)
        assert active is not None
        assert active.user_id == USER_1

    def test_get_active_session_returns_none_when_empty(self):
        req = make_request()
        assert get_active_session(req, PRODUCT) is None

    def test_get_active_session_recovers_if_pointer_points_to_cleared_slot(self):
        req = make_request()
        set_session_slot(req, PRODUCT, TENANT_A, make_slot(user_id=USER_1, tenant_id=TENANT_A))
        set_session_slot(req, PRODUCT, TENANT_B, make_slot(user_id=USER_2, tenant_id=TENANT_B))
        set_last_tenant(req, PRODUCT, TENANT_B, USER_2)
        clear_session_slot(req, PRODUCT, TENANT_B, USER_2)
        # Pointer is stale — should fall back to remaining slot
        active = get_active_session(req, PRODUCT)
        assert active is not None
        assert active.user_id == USER_1

    def test_last_school_set_and_get(self):
        req = make_request()
        set_last_school(req, PRODUCT, TENANT_A, USER_1, SCHOOL_B)
        assert get_last_school(req, PRODUCT, TENANT_A, USER_1) == SCHOOL_B

    def test_last_school_is_per_slot(self):
        req = make_request()
        set_last_school(req, PRODUCT, TENANT_A, USER_1, SCHOOL_A)
        set_last_school(req, PRODUCT, TENANT_B, USER_2, SCHOOL_B)
        assert get_last_school(req, PRODUCT, TENANT_A, USER_1) == SCHOOL_A
        assert get_last_school(req, PRODUCT, TENANT_B, USER_2) == SCHOOL_B

    def test_corrupted_slot_is_ignored_by_get_all(self):
        req = make_request()
        set_session_slot(req, PRODUCT, TENANT_A, make_slot())
        # Manually corrupt a slot
        req.session[f"edoo_slot_{PRODUCT}_{TENANT_B}:{USER_2}"] = {"broken": True}
        slots = get_all_slots(req, PRODUCT)
        assert len(slots) == 1
        assert slots[0].user_id == USER_1
