"""Admin dashboard plumbing (spec §11): PKCE entry, opaque cookie sessions,
CSRF-guarded HTML posts, plus a bearer path for scripted checks.

Session model is deliberately the SAME in-memory shape as keycloak.LoginStateStore
(register #5 covers the Redis move when we scale past one replica).
"""
import secrets
import time
from pathlib import Path
from urllib.parse import parse_qs

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from .. import keycloak as kc
from ..auth import get_verifier
from ..config import get_settings
from ..services import idverify as idv
from ..services import recovery as rc

router = APIRouter(prefix="/admin", tags=["admin"])

_templates = Jinja2Templates(
    directory=str(Path(__file__).resolve().parents[2] / "templates"))

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
    try:
        discovery = kc.get_discovery()
    except kc.KeycloakUnavailable as e:
        raise HTTPException(503, str(e))
    state, nonce = secrets.token_urlsafe(16), secrets.token_urlsafe(16)
    verifier_plain = secrets.token_urlsafe(32)
    import base64, hashlib
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier_plain.encode()).digest()).rstrip(b"=").decode()
    redirect_uri = f"{s.api_public_url}/admin/callback"
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
    try:
        discovery = kc.get_discovery()
    except kc.KeycloakUnavailable as e:
        raise HTTPException(503, str(e))
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


def _page(request: Request, name: str, **ctx) -> HTMLResponse:
    sess = _session_from_cookie(request)
    ctx |= {"csrf": sess["csrf"], "claims_email":
            (sess["claims"].get("email") if sess else "")}
    return _templates.TemplateResponse(request, name, ctx)


@router.get("", response_class=HTMLResponse)
@router.get("/", response_class=HTMLResponse)
def admin_home(request: Request):
    sess = _session_from_cookie(request)
    if not sess:
        return RedirectResponse("/admin/login", status_code=302)
    return _page(request, "admin/reviews.html", reviews=idv.list_pending())


@router.get("/reviews/{review_id}", response_class=HTMLResponse)
def review_detail(request: Request, review_id: int):
    sess = _session_from_cookie(request)
    if not sess:
        return RedirectResponse("/admin/login", status_code=302)
    rev = idv.get_review(review_id)
    if not rev:
        raise HTTPException(404, "no such review")
    return _page(request, "admin/review_detail.html", review=rev)


async def _urlencoded_form(request: Request) -> dict[str, str]:
    """HTML <form> posts are application/x-www-form-urlencoded; parse them with
    the stdlib. (starlette's request.form() refuses to run at all without the
    python-multipart package — even for urlencoded bodies — a dependency we
    deliberately do not carry.) Anything else parses as an empty form, which
    check_csrf then rejects."""
    ctype = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if ctype != "application/x-www-form-urlencoded":
        return {}
    raw = (await request.body()).decode("utf-8", errors="replace")
    return {k: v[0] for k, v in
            parse_qs(raw, keep_blank_values=True).items()}


@router.post("/reviews/{review_id}/decide")
async def review_decide(request: Request, review_id: int):
    sess = _session_from_cookie(request)
    if not sess:
        return RedirectResponse("/admin/login", status_code=302)
    form = await _urlencoded_form(request)
    check_csrf(request, form.get("csrf"))
    # Validate BEFORE dispatch: decide_review's ValueError must never reach a
    # forged form field as a 500 — a bad decision is a client error (422).
    decision = form.get("decision", "")
    if decision not in ("approved", "rejected"):
        raise HTTPException(422, "decision must be 'approved' or 'rejected'")
    idv.decide_review(review_id, decision, sess["claims"]["email"])
    return RedirectResponse("/admin", status_code=303)


@router.get("/api/reviews")
def api_reviews(claims: dict = Depends(require_admin)):
    return {"reviews": idv.list_pending()}


@router.post("/api/reviews/{review_id}/approve")
def api_approve(review_id: int, claims: dict = Depends(require_admin)):
    """Scripted-approval path used by smoke-test; HTML flow stays CSRF-guarded."""
    if not idv.decide_review(review_id, "approved", claims["email"]):
        raise HTTPException(404, "no pending review with that id")
    return {"ok": True}


@router.post("/api/recovery/{req_id}/grant")
def api_recovery_grant(req_id: str, claims: dict = Depends(require_admin)):
    """Bearer path granting a pending_admin recovery (spec §13); the dashboard
    route lands with the service. Only actionable requests grant — anything
    else is the same generic 404 (no state oracle for scripted probes)."""
    if not rc.admin_grant(req_id, claims["email"]):
        raise HTTPException(404, "no actionable recovery request with that id")
    return {"ok": True}
