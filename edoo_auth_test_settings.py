"""Minimal Django settings for the edoo_auth test suite."""
SECRET_KEY = "test-secret-key"
INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "rest_framework",
]
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "edoo_auth.django.authentication.FusionAuthJWTAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "edoo_auth.django.permissions.IsEdooAuthenticated",
    ],
}
EDOO_AUTH = {
    "FA_BASE_URL": "http://fusionauth:9011",
    "AUDIENCE": "test-app-client-id",
    "RESOLVE_USER": lambda claims: claims,
}
INTERNAL_API_KEY = "test-internal-api-key"
