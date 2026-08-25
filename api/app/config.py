"""Application settings + the U2 host-import guard.

The guard below is STRUCTURAL, not social: importing app.* outside a container
once dumped the whole lab .env through a ValidationError (Settings extra=forbid
discovers a repo-root .env), forcing two full secret-rotation cycles — see
progress.md's U2 arc. Containers are detected via /.dockerenv; the pytest suite
is exempt because tests legitimately import app.* on the host.
"""
import os
import sys
from pathlib import Path

from functools import lru_cache
from pydantic_settings import BaseSettings

GUARD_ENV_OVERRIDE = "SOVEREIGN_ALLOW_HOST_SETTINGS"

def _host_settings_import_blocked(dockerenv_path: str = "/.dockerenv",
                                  modules=None) -> bool:
    """True when Settings would load on a host checkout (the leak vector).

    Injectable parameters exist purely for regression tests; real calls probe
    the live filesystem and sys.modules.
    """
    if Path(dockerenv_path).exists():
        return False                       # inside a container: normal case
    modules = sys.modules if modules is None else modules
    if "pytest" in modules:
        return False                       # local test suite imports by design
    return os.environ.get(GUARD_ENV_OVERRIDE) != "1"

def _enforce_host_import_guard() -> None:
    if _host_settings_import_blocked():
        raise RuntimeError(
            "Refusing to load app settings OUTSIDE a container. "
            "Settings(extra='forbid') discovers a repository .env on a host "
            "checkout and echoes every secret in its validation error "
            "(the overnight U2 incident class). Run this code inside a "
            f"container, under pytest, or set {GUARD_ENV_OVERRIDE}=1 "
            "deliberately.")

_enforce_host_import_guard()

class Settings(BaseSettings):
    keycloak_base_url: str = "http://keycloak:8080"
    # Host-facing issuer base — matches Keycloak's --hostname pin (Ruling 5):
    # real tokens carry iss=http://localhost:<port>/realms/<realm>.
    kc_frontend_url: str = "http://localhost:8080"
    kc_realm: str = "sovereign"
    kc_app_client: str = "sovereign-app"
    api_audience: str = "sovereign-mail-api"
    introspection_client_id: str = "mail-introspection"
    mail_domain: str = "sovereign.mail"
    imap_host: str = "dovecot"
    imap_port: int = 143
    smtp_host: str = "postfix"
    smtp_port: int = 2587
    allowed_redirect_uris: list[str] = [
        "http://localhost:8000/auth/callback", "http://localhost:*/*", "sovereign://callback"]
    ca_cert_path: str = "/certs/rootCA.pem"

    class Config:
        env_file = ".env"
        # Defense-in-depth (never-import-app-on-host rule): if Settings is ever
        # constructed where a repo .env gets discovered, extra="forbid" would turn
        # every unrelated secret-bearing line into a ValidationError dump. Ignore
        # unknown keys instead; this complements the ban, it does not replace it.
        extra = "ignore"

@lru_cache
def get_settings() -> Settings:
    return Settings()
