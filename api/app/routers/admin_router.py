"""Admin dashboard plumbing (spec §11): PKCE entry, opaque cookie sessions,
CSRF-guarded HTML posts, plus a bearer path for scripted checks.

Session model is deliberately the SAME in-memory shape as keycloak.LoginStateStore
(register #5 covers the Redis move when we scale past one replica).
"""
import secrets
import time

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse

from .. import keycloak as kc
from ..auth import get_verifier
from ..config import get_settings

router = APIRouter(prefix="/admin", tags=["admin"])

_sessions: dict[str, dict] = {}        # sid -> {claims, csrf, t}
_login_states = kc.LoginStateStore(ttl_seconds=600)

ADMIN_SESSION_TTL_SECONDS = 3600
ADMIN_COOKIE = "admin_session"


def _verify(token: str) -> dict:       # module-level so tests can swap
    return get_verifier().verify(token)


def _has_admin_role(claims: dict) -> bool:
    return "sovereign-admin" in (
        (claims or {}).get("realm_access", {}) or {}).get("roles", [])


def _session_from_cookie(request: Request) -> dict | None:
    sid = request.cookies.get(ADMIN_COOKIE)
    s = _sessions.get(sid or "")
    if not s:
        return None
    if time.time() - s["t"] > ADMIN_SESSION_TTL_SECONDS:
        _sessions.pop(sid, None)     # expired entry must not linger forever
        return None
    return s | {"sid": sid}


def require_admin(request: Request) -> dict:
    """Dual-mode gate. Bearer wins when present (scripted/API use); otherwise
    the browser cookie session must exist. Both paths demand the realm role."""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        try:
            claims = _verify(auth.removeprefix("Bearer ").strip())
        except kc.KeycloakUnavailable as e:
            raise HTTPException(503, str(e))
        except Exception as e:                      # AuthError etc.
            raise HTTPException(401, f"invalid admin token: {e}")
        if not _has_admin_role(claims):
            raise HTTPException(403, "sovereign-admin role required")
        return claims
    sess = _session_from_cookie(request)
    if not sess or not _has_admin_role(sess["claims"]):
        raise HTTPException(403, "admin session required")
    return sess["claims"]


def csrf_token_for(sid: str) -> str | None:
    """Safe lookup — None on unknown/expired sid; callers guard."""
    s = _sessions.get(sid)
    return None if not s else s["csrf"]


def check_csrf(request: Request, form_field_value: str | None) -> None:
    sess = _session_from_cookie(request)
    if not sess or not form_field_value or form_field_value != sess["csrf"]:
        raise HTTPException(403, "bad CSRF token")


@router.get("/login")
def admin_login():
    s = get_settings()
    discovery = kc.get_discovery()
    state, nonce = secrets.token_urlsafe(16), secrets.token_urlsafe(16)
    verifier_plain = secrets.token_urlsafe(32)
    import base64, hashlib
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier_plain.encode()).digest()).rstrip(b"=").decode()
    redirect_uri = f"{s.kc_frontend_url}/admin/callback"
    _login_states.put(state, {"redirect_uri": redirect_uri,
                              "verifier": verifier_plain, "nonce": nonce})
    return RedirectResponse(
        kc.build_authorize_url(discovery, redirect_uri, state, nonce, challenge),
        status_code=302)


@router.get("/callback")
def admin_callback(code: str = "", state: str = ""):
    st = _login_states.pop(state)
    if not st:
        raise HTTPException(400, "unknown or expired login state")
    s = get_settings()
    discovery = kc.get_discovery()
    try:
        tokens = kc.exchange_code(discovery, code, st)
    except kc.KeycloakUnavailable as e:
        raise HTTPException(503, str(e))
    except Exception as e:                      # AuthError etc.
        raise HTTPException(401, f"code exchange failed: {e}")
    try:
        claims = _verify(tokens["access_token"])
    except Exception as e:
        raise HTTPException(401, f"token validation failed: {e}")
    if not _has_admin_role(claims):
        raise HTTPException(403, "your account lacks the sovereign-admin role")
    sid = secrets.token_urlsafe(32)
    _sessions[sid] = {"claims": claims, "csrf": secrets.token_urlsafe(24),
                      "t": time.time()}
    resp = RedirectResponse("/admin", status_code=302)
    resp.set_cookie(ADMIN_COOKIE, sid, httponly=True, samesite="lax",
                    path="/", max_age=ADMIN_SESSION_TTL_SECONDS)
    return resp


@router.get("/logout")
def admin_logout(request: Request):
    sid = request.cookies.get(ADMIN_COOKIE)
    _sessions.pop(sid or "", None)
    resp = RedirectResponse("/", status_code=302)
    resp.delete_cookie(ADMIN_COOKIE, path="/")
    return resp


# PLACEHOLDER: Task 9 replaces this body with the real reviews listing.
# Exists only so the bearer-gate test exercises require_admin on a live route;
# without a route, /admin/api/reviews is a plain 404 and the gate never fires.
@router.get("/api/reviews")
def admin_reviews_placeholder(claims: dict = Depends(require_admin)):
    return {"reviews": []}
