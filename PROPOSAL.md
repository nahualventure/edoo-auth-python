# edoo-auth — Python Package Proposal

## What it is

`edoo-auth` is the Python counterpart to the TypeScript `@edoo/auth-client` library. It handles authentication for Edoo's Python/Django services, providing two distinct functionalities under one package, installable separately depending on what the service needs.

---

## The two install targets

### 1. `edoo-auth[django]` — JWKS validation for API services

For services that **only consume JWTs** — they don't handle login, they just need to validate Bearer tokens on incoming API requests. This is what Finance, Admissions, and any other Django microservice that receives calls from a frontend would use.

**What it provides:**

- `FusionAuthJWTAuthentication` — a DRF authentication class that validates FA-issued JWTs by fetching the public key from FA's JWKS endpoint (`/.well-known/jwks.json`). Sets `request.auth` to a `TokenClaims` dataclass.
- `IsEdooAuthenticated` — a DRF permission class that confirms the token is valid and that the `X-School-ID` header is present and within the token's `accessibleSchools` claim.
- `InternalApiKeyAuthentication` + `IsInternalService` — for machine-to-machine calls (e.g. a BFF calling an internal endpoint). Validates `X-API-Key` against a configured secret.

**Settings required:**

```python
EDOO_AUTH = {
    "FA_BASE_URL": "https://your-fa-instance.com",
    "AUDIENCE":    "umbrella-app-client-id",
    "RESOLVE_USER": lambda claims: claims,  # or look up a User from the DB
}

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ["edoo_auth.django.authentication.FusionAuthJWTAuthentication"],
    "DEFAULT_PERMISSION_CLASSES":     ["edoo_auth.django.permissions.IsEdooAuthenticated"],
}
```

**That's it.** No login views, no sessions, no cookies. Every request is validated independently against the JWKS endpoint (with a 5-minute in-process cache on the public key).

---

### 2. `edoo-auth[django-oidc]` — Full OIDC login flow for Django monoliths

For services that **own the login flow** — they serve a UI, handle the OAuth callback, manage sessions, and refresh tokens. This is what Edoo SIS uses. Edoo SIS is a legacy Django monolith that can't be migrated to the Next.js stack, so the package meets it where it is rather than forcing a rewrite.

Builds on top of `[django]` and adds:

- `EdooAuthClient` — the main client class, instantiated per-request. Handles login initiation, callback, session management, token refresh, and logout.
- `EdooAuthMiddleware` — reads the session slot on every request, refreshes the token if near expiry, and populates `request.auth` with a `TokenClaims` instance (same interface as the JWKS path).
- Five URL-mounted views: `login`, `callback`, `logout`, `switch` (account), `switch-school`.
- `edoo_auth.django.urls` — drop-in URL include.

**Settings required:**

```python
EDOO_AUTH_OIDC = EdooAuthConfig(
    product='sis',
    fa_base_url='https://your-fa-instance.com',
    redirect_uri='https://your-app.com/auth/callback',
    on_get_tenant_umbrella_client=lambda tenant_id: TenantClient(client_id=..., client_secret=...),
    on_resolve_tenants=lambda email: [],          # multi-tenant lookup if needed
    on_get_accounts=lambda email, tenant_id: [],  # local user/school lookup
    on_reconcile=lambda user_id, fa_uid, school_id: {"status": "ok"},  # link FA user to local user
    on_profile_check=lambda email, school_id: {"status": "ok"},        # check account is active
    login_redirect_url='/dashboard',
    default_tenant_id='...',
)
```

```python
urlpatterns = [
    path('auth/', include('edoo_auth.django.urls')),
    ...
]
```

**Session model:** each logged-in account is stored as a slot in Django's server-side session (`django_session` table). The browser holds only a session ID cookie — no auth data in the cookie itself. Multiple accounts can be active simultaneously (e.g. a teacher logged in under two schools/tenants), and the package handles switching between them transparently.

**Token refresh** happens automatically on every request via the middleware, with thread-safe deduplication — concurrent requests for the same slot share a single refresh call instead of hammering FA.

---

## How it compares to the TypeScript library

| | TypeScript `@edoo/auth-client` | Python `edoo-auth` |
|---|---|---|
| **Target runtime** | Next.js (BFF / Edge) | Django |
| **JWKS validation** | No — TS apps delegate API auth to Django | Yes — `[django]` install target |
| **OIDC login flow** | Yes | Yes — `[django-oidc]` install target |
| **Session storage** | One signed cookie per session slot (cookie-per-slot, 4KB limit managed per-slot) | Django server-side session (DB-backed by default, swap to Redis for horizontal scale) |
| **Token refresh** | Middleware on every BFF request, cookie rewritten | Middleware on every Django request, session updated in DB |
| **Auth state carrier** | Cookies (browser → Next.js BFF) | Session ID cookie (browser → Django) |
| **Multi-account** | Multiple cookies, one per slot | Multiple keys in one session, one per slot |
| **Logout** | Clears cookie, revokes refresh token | Clears session slot, revokes refresh token |

### Why the session storage differs

The TS library uses a cookie-per-slot approach because Next.js is a **BFF** — it must be stateless so it can be deployed across many edge nodes without a shared store. The cookie carries the full slot data (signed, not encrypted) so any node can read it without coordination.

Django SIS is not a BFF — it **is** the backend. It can read from its own database on every request. Server-side sessions are the idiomatic Django pattern, every piece of the Django ecosystem expects them, and scaling is a matter of swapping `SESSION_ENGINE` to a Redis-backed backend. There is no reason to fight the framework.

### Why JWKS is only in Python

The TS apps (Class, Finance) don't validate JWTs themselves — they pass the token through to the Django API, which does the validation. The Next.js BFF doesn't need to trust the token content, it just needs to forward it. Django is the actual trust boundary.

---

## Reconciliation

Both the TS and Python libraries implement the same `reconcile()` logic — it's a core part of Edoo's auth model:

1. After login, FA returns the schools the user is registered in via a custom JWT claim (`accessibleSchools`).
2. The app calls `on_get_accounts(email, tenant_id)` to find any local user records not yet linked to a FA user ID.
3. For each unlinked local account, it calls `on_reconcile(user_id, fa_user_id, school_id)` so the app writes the link.
4. The merged set of schools (FA-known + newly reconciled) becomes the session's `accessible_schools`.

This means a user can log in once and gain access to all their schools, even if some were created before their FA account was linked.

---

## What's left before production

- [ ] Publish to private PyPI index so services can pin a version
