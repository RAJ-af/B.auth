import pytest, time
from unittest.mock import patch
from urllib.parse import urlparse, parse_qs
from fastapi import Request
from fastapi.testclient import TestClient
from app.main import create_app
from app.auth import get_current_user, JWTVerifier
from app import auth as auth_module
from app import keycloak as kcm
from tests.mock_jwks import make_jwks_server, mint

DISC = {"authorization_endpoint": "http://kc.test/auth",
        "token_endpoint": "http://kc.test/token"}

@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(kcm, "get_discovery", lambda: DISC)
    return TestClient(create_app())

def override_user(app, email="bob@sovereign.mail"):
    def fake(request: Request):
        request.state.raw_token = "faketoken"
        return {"sub": "s", "email": email}
    app.dependency_overrides[get_current_user] = fake

def test_login_builds_url_and_stores_state(client):
    r = client.get("/login", params={"redirect_uri": "http://localhost:8000/auth/callback"})
    assert r.status_code == 200
    # Brief defect fix: the original asserted the literal substring
    # "authorization_endpoint" inside the URL, but build_authorize_url (approved
    # Task 9 code) emits the endpoint's VALUE, not the discovery key name. Anchor
    # on the discovered endpoint instead, then verify the state really was stored.
    url = r.json()["authorization_url"]
    assert url.startswith(DISC["authorization_endpoint"] + "?")
    state = parse_qs(urlparse(url).query)["state"][0]
    stored = kcm.get_state_store().pop(state)
    assert stored["redirect_uri"] == "http://localhost:8000/auth/callback"
    assert stored["verifier"]

def test_login_rejects_unknown_redirect(client):
    assert client.get("/login", params={"redirect_uri": "http://evil.example/cb"}).status_code == 400

# redirect_uri validation consumes Settings.allowed_redirect_uris (spec §6: same
# allow-list Keycloak enforces) with fnmatch semantics — the wildcard entry
# "http://localhost:*/*" admits any localhost port + path; non-wildcard entries stay exact.
def test_login_allows_wildcard_localhost_redirect(client):
    r = client.get("/login", params={"redirect_uri": "http://localhost:9999/anything"})
    assert r.status_code == 200

def test_login_rejects_non_localhost_even_with_path(client):
    # Loopback IP is NOT allowed — only the "localhost" hostname matches any entry.
    assert client.get("/login", params={"redirect_uri": "http://127.0.0.1:8000/auth/callback"}).status_code == 400

def test_callback_exchanges(client):
    kcm.get_state_store().put("s-ok", {"verifier": "v", "nonce": "n",
                                       "redirect_uri": "http://localhost:8000/auth/callback"})
    with patch.object(kcm, "exchange_code", return_value={"access_token": "a"}) as ex:
        r = client.get("/auth/callback", params={"code": "c", "state": "s-ok"})
    assert r.status_code == 200 and r.json()["access_token"] == "a"
    assert ex.call_args.args[2]["verifier"] == "v"

def test_callback_bad_state(client):
    assert client.get("/auth/callback", params={"code": "c", "state": "nope"}).status_code == 400

def test_me_requires_real_dependency():
    # /me uses the real dependency (not overridden): junk token -> 401
    c = TestClient(create_app())
    assert c.get("/me").status_code == 401
    assert c.get("/me", headers={"Authorization": "Bearer junk"}).status_code == 401

def test_me_with_overridden_dependency():
    app = create_app(); override_user(app)
    r = TestClient(app).get("/me")
    assert r.status_code == 200 and r.json()["email"] == "bob@sovereign.mail"

def test_token_without_email_claim_is_401_not_500(monkeypatch):
    # Whole-branch review F7 hardening: every mail route binds user["email"].
    # A cryptographically VALID RS256 token lacking the claim must fail as a
    # clean 401 at the single choke point in get_current_user — never as a raw
    # 500 from dict indexing inside a router. Real dependency path (mock JWKS,
    # no dependency override) so the guard itself is what's under test.
    h = make_jwks_server()
    try:
        iss = "http://kc.test/realms/sovereign"
        monkeypatch.setattr(auth_module, "_verifier",
                            JWTVerifier(iss, "sovereign-mail-api", jwks_url=h["url"]))
        c = TestClient(create_app())
        base = {"exp": int(time.time()) + 300, "iss": iss,
                "aud": "sovereign-mail-api", "sub": "u-1"}
        r = c.get("/me", headers={"Authorization": "Bearer " + mint(h, dict(base))})
        assert r.status_code == 401 and "email claim" in r.json()["detail"]
        ok = c.get("/me", headers={"Authorization": "Bearer " + mint(
            h, {**base, "email": "a@sovereign.mail"})})
        assert ok.status_code == 200 and ok.json()["email"] == "a@sovereign.mail"
    finally:
        h["server"].shutdown()
