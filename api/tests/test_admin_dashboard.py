"""Admin auth: bearer-role gate + opaque cookie sessions + CSRF."""
import base64
import json

import pytest
from fastapi.testclient import TestClient

from app.main import create_app

def _token(roles):
    payload = {"exp": 4102444800, "iss": "http://localhost:8080/realms/sovereign",
               "aud": "sovereign-mail-api", "sub": "admin-1",
               "email": "admin@sovereign.mail",
               "realm_access": {"roles": roles}}
    return "header." + base64.urlsafe_b64encode(
        json.dumps(payload).encode()).decode().rstrip("=")


ROLE_TOKEN = _token(["sovereign-admin"])
NO_ROLE_TOKEN = _token(["offline_access"])


@pytest.fixture
def world(monkeypatch):
    sessions: dict[str, dict] = {}
    states: dict[str, dict] = {}

    import app.routers.admin_router as ar
    monkeypatch.setattr(ar, "_sessions", sessions)
    monkeypatch.setattr(ar._login_states, "put", lambda s, d: states.update({s: d}))
    monkeypatch.setattr(ar._login_states, "pop", lambda s: states.pop(s, None))

    def fake_verify(token):
        assert token in (ROLE_TOKEN, NO_ROLE_TOKEN)
        return json.loads(base64.urlsafe_b64decode(
            token.split(".")[1] + "==").decode())
    monkeypatch.setattr(ar, "_verify", fake_verify)

    # Host-side tests cannot reach http://keycloak:8080 (compose-network hostname),
    # so get_discovery is stubbed like test_auth_router does; the fake authorize
    # URL builder below ignores the discovery payload anyway.
    def fake_discovery():
        return {"authorization_endpoint": "http://kc/authorize"}
    monkeypatch.setattr(ar.kc, "get_discovery", fake_discovery)

    def fake_exchange(discovery, code, state_data):
        return {"access_token": ROLE_TOKEN if code == "good"
                else NO_ROLE_TOKEN}
    monkeypatch.setattr(ar.kc, "exchange_code", fake_exchange)

    def fake_authorize(discovery, redirect_uri, state, nonce, challenge):
        return f"http://kc/authorize?state={state}"
    monkeypatch.setattr(ar.kc, "build_authorize_url", fake_authorize)

    return {"client": TestClient(create_app()), "sessions": sessions}


def test_login_redirects_to_keycloak(world):
    r = world["client"].get("/admin/login", follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"].startswith("http://kc/authorize")


def test_callback_good_role_sets_session_cookie(world):
    r = world["client"].get("/admin/login", follow_redirects=False)
    state = r.headers["location"].split("state=")[1]
    r2 = world["client"].get(f"/admin/callback?code=good&state={state}",
                             follow_redirects=False)
    assert r2.status_code == 302 and r2.headers["location"] == "/admin"
    cookie = r2.headers["set-cookie"]
    assert "HttpOnly" in cookie and "samesite=lax" in cookie.lower()
    sid = cookie.split("admin_session=")[1].split(";")[0]
    assert sid in world["sessions"]
    # single-use state consumed:
    assert world["client"].get(
        f"/admin/callback?code=good&state={state}",
        follow_redirects=False).status_code == 400


def test_callback_without_role_is_403_no_cookie(world):
    r = world["client"].get("/admin/login", follow_redirects=False)
    state = r.headers["location"].split("state=")[1]
    r2 = world["client"].get(f"/admin/callback?code=norole&state={state}",
                             follow_redirects=False)
    assert r2.status_code == 403
    assert "admin_session" not in r2.headers.get("set-cookie", "")


def test_require_admin_bearer_path(world):
    ok = world["client"].get("/admin/api/reviews",
                             headers={"Authorization": f"Bearer {ROLE_TOKEN}"})
    assert ok.status_code != 403          # Task 9 replaces this placeholder body
    bad = world["client"].get("/admin/api/reviews",
                              headers={"Authorization": f"Bearer {NO_ROLE_TOKEN}"})
    assert bad.status_code == 403
