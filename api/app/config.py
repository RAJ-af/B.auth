"""Application settings + the U2 host-import guard.

The guard below is STRUCTURAL, not social: importing app.* with a repository
.env discoverable from the working directory once dumped every secret through
a Settings ValidationError (extra=forbid enumerates unknown keys) — two full
secret-rotation cycles overnight; see progress.md's U2 arc.

Detection models the LEAK VECTOR, not containerhood: pydantic resolves
env_file=".env" against the CWD, so the guard refuses import whenever a .env
exists in the CWD or any ancestor. An earlier /.dockerenv heuristic was
replaced after live verification showed it blind exactly at the incident site
(GitHub Codespace hosts ARE dev containers, so /.dockerenv exists there).
Containers stay clean because nothing mounts a .env into them (secrets arrive
via compose env injection). The pytest suite is exempt — tests legitimately
import app.* on the host — and SOVEREIGN_ALLOW_HOST_SETTINGS=1 is the explicit
escape hatch for deliberate host-side probes.
"""
import os
import sys
from pathlib import Path
from typing import Literal

from functools import lru_cache
from pydantic_settings import BaseSettings

GUARD_ENV_OVERRIDE = "SOVEREIGN_ALLOW_HOST_SETTINGS"

def _repo_env_discoverable(start: str | None = None) -> bool:
    """True when a .env sits in `start` (default: CWD) or any ancestor — i.e.
    exactly where pydantic's relative env_file resolution could find one.
    Ancestors are included as safety margin beyond pydantic's CWD-only lookup;
    overblocking fails safe and the error message names the override."""
    d = Path.cwd() if start is None else Path(start)
    return any((p / ".env").is_file() for p in (d, *d.parents))

def _host_settings_import_blocked(start: str | None = None,
                                  modules=None) -> bool:
    """True when importing this module risks echoing secret-bearing .env lines.

    Injectable parameters exist purely for regression tests; real calls probe
    the live filesystem and sys.modules.
    """
    if os.environ.get(GUARD_ENV_OVERRIDE) == "1":
        return False                       # deliberate host-side probe: opt-in
    modules = sys.modules if modules is None else modules
    if "pytest" in modules:
        return False                       # local test suite imports by design
    return _repo_env_discoverable(start)

def _enforce_host_import_guard() -> None:
    if _host_settings_import_blocked():
        raise RuntimeError(
            "Refusing to load app settings with a repository .env discoverable "
            "from the current directory. Settings(extra='forbid') would echo "
            "every secret in its validation error (the overnight U2 incident "
            f"class). Run inside a container, under pytest, or set "
            f"{GUARD_ENV_OVERRIDE}=1 deliberately.")

_enforce_host_import_guard()

class Settings(BaseSettings):
    keycloak_base_url: str = "http://keycloak:8080"
    # Host-facing issuer base — matches Keycloak's --hostname pin (Ruling 5):
    # real tokens carry iss=http://localhost:<port>/realms/<realm>.
    kc_frontend_url: str = "http://localhost:8080"
    # Browser-facing base of THIS api — the admin login's redirect_uri target.
    # Distinct from kc_frontend_url: that names Keycloak, this names us.
    api_public_url: str = "http://localhost:8000"
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
        "http://localhost:8000/auth/callback", "http://localhost:*/*", "sovereign://callback",
        # Keycloak honors no port wildcards (Wave B gate finding) — the admin
        # dashboard callback is pinned literally, matching the seeded client.
        "http://localhost:8000/admin/callback"]
    ca_cert_path: str = "/certs/rootCA.pem"

    # --- Identity & Auth Flow subsystem (spec 2026-08-25 §16) ---
    postgres_host: str = "postgres"
    postgres_port: int = 5432
    postgres_user: str = ""
    postgres_password: str = ""
    sovereign_app_db: str = "sovereign_app"
    otp_provider: str = "console"
    twilio_account_sid: str = ""
    twilio_auth_token: str = ""
    twilio_from_number: str = ""
    otp_code_ttl_seconds: int = 300
    otp_resend_cooldown_seconds: int = 60
    otp_max_sends_per_hour: int = 3
    otp_max_verify_attempts: int = 5
    otp_daily_cap: int = 200
    idverify_mode: Literal["off", "auto", "manual"] = "off"
    idverify_script: str = "/verify/mock-idverify.sh"
    idverify_timeout_seconds: int = 20
    family_link_cooldown_hours: int = 48
    recovery_request_ttl_seconds: int = 600
    recovery_min_dwell_seconds: int = 600
    recovery_reset_session_ttl_seconds: int = 600
    recovery_max_attempts_per_hour: int = 3
    password_min_length: int = 12
    sovereign_admin_user: str = "admin@sovereign.mail"
    ldap_host: str = "openldap"
    ldap_admin_password: str = ""         # lifecycle: spec §15.1 row 1

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
