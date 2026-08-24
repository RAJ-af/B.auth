import logging
import jwt
from fastapi import Depends, HTTPException, Request
from jwt import PyJWKClient, InvalidTokenError
from app.config import get_settings

log = logging.getLogger(__name__)

class AuthError(Exception):
    def __init__(self, status_code: int, detail: str):
        self.status_code, self.detail = status_code, detail

class JWTVerifier:
    def __init__(self, issuer: str, audience: str, jwks_url: str | None = None):
        self.issuer, self.audience = issuer, audience
        url = jwks_url or f"{issuer}/protocol/openid-connect/certs"
        self._jwk_client = PyJWKClient(url)

    def verify(self, token: str) -> dict:
        try:
            key = self._jwk_client.get_signing_key_from_jwt(token).key
            return jwt.decode(token, key, algorithms=["RS256"],
                              audience=self.audience, issuer=self.issuer,
                              options={"require": ["exp", "iss", "aud", "sub"]})
        except InvalidTokenError as e:
            raise AuthError(401, f"invalid_token: {e}") from e
        except Exception as e:  # JWKS fetch problems etc.
            log.warning("token validation infrastructure error: %s", e)
            raise AuthError(503, "identity provider unavailable") from e

# Issuer topology per ledger Ruling 5: Keycloak is pinned with
# --hostname http://localhost:${KEYCLOAK_PORT}, so real tokens carry
# iss="http://localhost:<port>/realms/<realm>" (a host-facing STRING), while the
# JWKS must be fetched over the compose network at KEYCLOAK_BASE_URL
# ("http://keycloak:8080"). NEVER derive one from the other.
_verifier: JWTVerifier | None = None
def get_verifier() -> JWTVerifier:
    global _verifier
    if _verifier is None:
        s = get_settings()
        issuer = f"{s.kc_frontend_url}/realms/{s.kc_realm}"          # token iss STRING (host-facing)
        jwks_url = f"{s.keycloak_base_url}/realms/{s.kc_realm}/protocol/openid-connect/certs"  # network path (compose net)
        _verifier = JWTVerifier(issuer, s.api_audience, jwks_url=jwks_url)
    return _verifier

def get_current_user(request: Request) -> dict:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "missing bearer token",
                            headers={"WWW-Authenticate": "Bearer"})
    raw_token = auth.removeprefix("Bearer ").strip()
    request.state.raw_token = raw_token   # consumed later by XOAUTH2 mail sessions
    try:
        return get_verifier().verify(raw_token)
    except AuthError as e:
        raise HTTPException(e.status_code, e.detail,
                            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'})
