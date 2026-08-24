import logging, secrets
from fnmatch import fnmatchcase
from fastapi import APIRouter, Depends, HTTPException
from ..config import get_settings
from ..pkce_util import make_pkce_pair
from .. import keycloak as kcm
from ..auth import AuthError, get_current_user

log = logging.getLogger(__name__)
router = APIRouter(tags=["auth"])

def _validate_redirect(uri: str) -> None:
    # Spec §6: redirect_uri is validated against the same allow-list Keycloak
    # enforces — Settings.allowed_redirect_uris. Entries are exact-match except
    # for fnmatch wildcards ("http://localhost:*/*" admits any localhost port
    # and path). Note this deliberately does NOT admit other loopback spellings
    # (e.g. http://127.0.0.1/...).
    allowed = get_settings().allowed_redirect_uris
    if not any(fnmatchcase(uri, pat) for pat in allowed):
        raise HTTPException(400, "redirect_uri not allowed")

@router.get("/login")
def login(redirect_uri: str):
    _validate_redirect(redirect_uri)
    try:
        disc = kcm.get_discovery()
    except kcm.KeycloakUnavailable as e:
        raise HTTPException(503, f"identity provider unavailable: {e}")
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    verifier, challenge = make_pkce_pair()
    kcm.get_state_store().put(state, {"verifier": verifier, "nonce": nonce,
                                      "redirect_uri": redirect_uri})
    return {"authorization_url": kcm.build_authorize_url(disc, redirect_uri, state, nonce, challenge)}

@router.get("/auth/callback")
def callback(code: str, state: str):
    # Pop state BEFORE any Keycloak round-trip: bad state fails fast without
    # contacting the IdP.
    data = kcm.get_state_store().pop(state)
    if not data:
        raise HTTPException(400, "unknown or expired state")
    try:
        disc = kcm.get_discovery()
    except kcm.KeycloakUnavailable as e:
        raise HTTPException(503, f"identity provider unavailable: {e}")
    try:
        tokens = kcm.exchange_code(disc, code, data)
    except AuthError as e:
        raise HTTPException(e.status_code, e.detail)
    except kcm.KeycloakUnavailable as e:
        raise HTTPException(503, f"identity provider unavailable: {e}")
    return {k: tokens[k] for k in ("access_token", "refresh_token", "id_token", "expires_in")
            if k in tokens}

@router.get("/me")
def me(user: dict = Depends(get_current_user)):
    return {"sub": user.get("sub"), "email": user.get("email"),
            "name": user.get("name") or user.get("preferred_username")}
