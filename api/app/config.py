from functools import lru_cache
from pydantic_settings import BaseSettings

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
