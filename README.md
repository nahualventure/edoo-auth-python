# edoo-auth

Python authentication library for Edoo Django services. Handles FusionAuth JWT validation and the full OIDC login/session/refresh flow, depending on which install target you use.

## Install targets

### `edoo-auth[django]` — JWT validation for API services

For services that **only consume JWTs** — they don't handle login, they just validate Bearer tokens on incoming requests. This is what Finance, Admissions, and other Django services that receive API calls from a frontend use.

```
pip install "edoo-auth[django] @ git+https://github.com/nahualventure/edoo-auth-python.git"
```

### `edoo-auth[django-oidc]` — Full OIDC login flow for Django monoliths

For services that **own the login flow** — serve a UI, handle the OAuth callback, manage sessions, and refresh tokens. This is what Edoo SIS uses.

```
pip install "edoo-auth[django-oidc] @ git+https://github.com/nahualventure/edoo-auth-python.git"
```

---

## `edoo-auth[django]` — JWT validation

Add to `settings.py`:

```python
EDOO_AUTH = {
    "FA_BASE_URL": "https://your-fa-instance.com",
    # Receives the tid claim from the token, returns the expected FA client_id for aud validation.
    # Single-tenant: return the env var. Multi-tenant: look up client_id from DB by tenant_id.
    "GET_AUDIENCE": lambda tid: os.getenv("FA_CLIENT_ID"),
    "RESOLVE_USER": lambda claims: claims,  # or look up a User from DB
}

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "edoo_auth.django.authentication.FusionAuthJWTAuthentication"
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "edoo_auth.django.permissions.IsEdooAuthenticated"
    ],
}
```

### What's provided

**`FusionAuthJWTAuthentication`** — DRF authentication class. Validates FA-issued JWTs against FA's JWKS endpoint (`/.well-known/jwks.json`). Sets `request.auth` to a `TokenClaims` dataclass:

```python
@dataclass(frozen=True)
class TokenClaims:
    sub: str        # FA user UUID
    email: str
    tenant_id: str
    exp: int
    raw: dict       # full decoded payload
```

JWKS keys are cached per URI with a 5-minute TTL — no round-trip on every request.

**`IsEdooAuthenticated`** — DRF permission class. Grants access when `request.auth` is a `TokenClaims` instance. School/tenant-level scoping is each product's responsibility (via its own membership tables or conventions).

**`InternalApiKeyAuthentication`** + **`IsInternalService`** — for machine-to-machine calls. Validates `X-API-Key` against `settings.INTERNAL_API_KEY` using constant-time comparison.

### Optional settings

```python
EDOO_AUTH = {
    ...
    "ISSUER": "https://your-fa-public-url.com",       # validates `iss` claim
    "ALGORITHMS": ["RS256"],                           # default: ["RS256"]
}
```

---

## `edoo-auth[django-oidc]` — Full OIDC flow

### 1. Configure

```python
from edoo_auth.core.oidc_types import EdooAuthConfig, TenantClient

EDOO_AUTH_OIDC = EdooAuthConfig(
    product="sis",
    fa_base_url=os.getenv("FA_BASE_URL", "http://fusionauth:9011"),
    fa_public_url=os.getenv("FA_PUBLIC_URL", None),   # browser-facing URL if different
    redirect_uri=os.getenv("APP_URL") + "/auth/callback/",
    default_tenant_id=os.getenv("FA_TENANT_ID"),

    # Returns the OIDC client credentials for a given tenant
    on_get_tenant_client=lambda tenant_id: TenantClient(
        client_id=os.getenv("FA_CLIENT_ID"),
        client_secret=os.getenv("FA_CLIENT_SECRET"),
    ),

    # Called after FA login — check whether the local account is active
    # Return {"status": "ok"} | {"status": "blocked"} | {"status": "not_found"}
    on_profile_check=lambda email, school_id: {"status": "ok"},

    # Optional: called after a successful login (e.g. django.contrib.auth.login)
    on_login_success=None,

    # Optional: called when middleware resumes an existing session (e.g. re-run django.contrib.auth.login)
    on_session_resumed=None,

    login_redirect_url="/dashboard/",
    token_refresh_threshold_seconds=120,
    session_max_age=60 * 60 * 24 * 30,
)
```

### 2. Add middleware and URLs

```python
# settings.py
MIDDLEWARE = [
    ...
    "edoo_auth.django.middleware.EdooAuthMiddleware",
]

# urls.py
urlpatterns = [
    path("auth/", include("edoo_auth.django.urls")),
    ...
]
```

### 3. Hook implementations

Keep hook functions out of `local.py` — put them in a dedicated module (e.g. `auth_hooks.py`) and import them. This matters because `local.py` is loaded during Django settings initialization, before the app registry is ready. Model imports inside hooks must be **function-local**:

```python
# auth_hooks.py

def resolve_user(claims):
    from users.models import CustomUser
    return CustomUser.objects.filter(fusionauth_user_id=claims.sub).first()

def profile_check(email, school_id):
    from users.models import CustomUser
    try:
        user = CustomUser.objects.get(email=email)
    except CustomUser.DoesNotExist:
        return {"status": "not_found"}
    if not user.is_active:
        return {"status": "blocked"}
    return {"status": "ok"}

def on_login(request, email):
    from django.contrib.auth import login as django_login
    from users.models import CustomUser
    try:
        user = CustomUser.objects.get(email=email)
        user.backend = "django.contrib.auth.backends.ModelBackend"
        django_login(request, user)
    except CustomUser.DoesNotExist:
        pass
```

### Session model

Each logged-in account is stored as a slot in Django's server-side session. The browser holds only a session ID cookie — no auth data in the cookie itself. Multiple accounts (different tenants or emails) can be active simultaneously; the package handles switching between them.

Token refresh happens automatically on every request via the middleware, with in-process deduplication — concurrent requests for the same slot share a single refresh call.

> **Known limitation:** refresh deduplication is process-local. If gunicorn runs with multiple workers or replicas, two processes can race a refresh for the same slot. FA's refresh-token rotation will invalidate one of them, logging that request's user out. Revisit with a distributed lock if running >1 worker per active session becomes a concern.

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/auth/login/` | Redirects to FA authorize. Accepts `tenant_id`, `email`, `school_id`, `prompt` query params. |
| `GET` | `/auth/callback/` | Exchanges the authorization code, runs `on_profile_check`, creates the session slot. |
| `POST` | `/auth/logout/` | Revokes the refresh token, clears the session slot, redirects to FA logout. |
| `POST` | `/auth/switch/` | Switches the active session slot (multi-account). Body: `{"tenant_id": "...", "user_id": "..."}` |
| `POST` | `/auth/switch-school/` | Sets the active school for the current slot. Body: `{"school_id": "..."}` |

### Cookie settings

Recommended for production:

```python
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SECURE = True
```

---

## Architecture notes

### FusionAuth topology

Edoo runs one FA Tenant + one FA Application per product deployment (one school per Edoo SIS instance). `FA_TENANT_ID` and `FA_CLIENT_ID` are env vars — no runtime tenant disambiguation needed for single-tenant products.

Multi-tenant products (Class, Finance, Admissions) share one FA deployment across multiple schools. Their `on_get_tenant_client` hook handles tenant lookup dynamically.

### What FusionAuth does and doesn't own

FA gatekeeps **product-level identity** only — it answers "is this user authenticated for this product?" Per-school authorization is entirely an app-layer concern, enforced by each product against its own membership tables. FA tokens carry no per-school access data.

---

## Development

```bash
cd edoo-auth-python
pip install -e ".[dev]"
pytest
```

Tests use a real RSA key pair for signing tokens and a mocked JWKS client — no network, no FusionAuth needed.
