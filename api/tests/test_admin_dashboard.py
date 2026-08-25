"""Admin auth: bearer-role gate + opaque cookie sessions + CSRF."""
import base64
import json

import pytest
from fastapi.testclient import TestClient

from app import keycloak as kc
import app.routers.admin_router as ar
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

    # The real /admin/api/reviews route (Task 9) reads Postgres, which host-side
    # tests cannot reach. Stub the read path here; the queue fixture below
    # overrides the idverify service functions directly, so this only backs the
    # bearer-gate smoke test on the empty queue.
    import app.db as appdb
    monkeypatch.setattr(appdb, "many", lambda q, p=(): [])

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


def _login_state(client):
    r = client.get("/admin/login", follow_redirects=False)
    return r.headers["location"].split("state=")[1]


# Fix round 1: exchange_code failures must map to clean statuses, never a raw
# 500 — KC outage surfaces 503 (KeycloakUnavailable caught FIRST, mirroring the
# _verify block ordering), anything else (expired/replayed code etc.) is 401.
def test_callback_kc_outage_is_503(world, monkeypatch):
    def outage(discovery, code, state_data):
        raise kc.KeycloakUnavailable("token endpoint unreachable")
    monkeypatch.setattr(ar.kc, "exchange_code", outage)
    state = _login_state(world["client"])
    resp = world["client"].get(f"/admin/callback?code=good&state={state}",
                               follow_redirects=False)
    assert resp.status_code == 503


def test_callback_exchange_failure_is_401(world, monkeypatch):
    def rejected(discovery, code, state_data):
        raise Exception("expired or replayed authorization code")
    monkeypatch.setattr(ar.kc, "exchange_code", rejected)
    state = _login_state(world["client"])
    resp = world["client"].get(f"/admin/callback?code=good&state={state}",
                               follow_redirects=False)
    assert resp.status_code == 401


# Fold-in from T8 review: kc.get_discovery() calls inside admin_login and
# admin_callback are unguarded against a KC outage -> raw 500. Both must map
# KeycloakUnavailable to 503, same pattern as the exchange_code wrap.
def test_login_kc_outage_is_503(world, monkeypatch):
    def outage():
        raise kc.KeycloakUnavailable("discovery endpoint unreachable")
    monkeypatch.setattr(ar.kc, "get_discovery", outage)
    r = world["client"].get("/admin/login", follow_redirects=False)
    assert r.status_code == 503


def test_callback_kc_discovery_outage_is_503(world, monkeypatch):
    state = _login_state(world["client"])

    def outage():
        raise kc.KeycloakUnavailable("discovery endpoint unreachable")
    monkeypatch.setattr(ar.kc, "get_discovery", outage)
    resp = world["client"].get(f"/admin/callback?code=good&state={state}",
                               follow_redirects=False)
    assert resp.status_code == 503


def _login(world):
    r = world["client"].get("/admin/login", follow_redirects=False)
    state = r.headers["location"].split("state=")[1]
    cb = world["client"].get(f"/admin/callback?code=good&state={state}",
                             follow_redirects=False)
    sid = cb.headers["set-cookie"].split("admin_session=")[1].split(";")[0]
    return sid, world["sessions"][sid]["csrf"]


def test_csrf_required_for_html_posts(world):
    """(Relocated here from Task 8 — the decide ROUTE must exist to observe 403.)"""
    sid, csrf = _login(world)
    r = world["client"].post("/admin/reviews/1/decide",
                             data={"decision": "approve"},
                             cookies={"admin_session": sid})
    assert r.status_code == 403
    r2 = world["client"].post("/admin/reviews/1/decide",
                              data={"decision": "approve", "csrf": csrf},
                              cookies={"admin_session": sid})
    assert r2.status_code != 403


@pytest.fixture
def queue(monkeypatch):
    """In-memory stand-in for the review service storage. The row mirrors the
    real _MASKED_COLUMNS shape — document_type plus an identities COUNT only;
    raw payload keys never appear here (§10.2 masking guarantee)."""
    rows = [{"review_id": 7, "email": "fam@sovereign.mail",
             "reason": "policy_manual", "status": "pending",
             "error_detail": None,
             "document_type": "national_id",
             "identities_count": 3,
             "created_at": "2026-08-25T10:00:00Z"}]

    import app.services.idverify as iv
    monkeypatch.setattr(iv, "list_pending", lambda: rows)
    monkeypatch.setattr(iv, "get_review",
                        lambda rid: next((r for r in rows
                                          if r["review_id"] == rid), None))
    def decide(rid, decision, reviewer):
        for r in rows:
            if r["review_id"] == rid and r["status"] == "pending":
                r["status"] = decision
                r["reviewed_by"] = reviewer
                return True
        return False
    monkeypatch.setattr(iv, "decide_review", decide)
    return rows


def test_queue_page_lists_pending_with_masks(world, queue):
    sid, _ = _login(world)
    html = world["client"].get("/admin", cookies={"admin_session": sid}).text
    assert "fam@sovereign.mail" in html and "policy_manual" in html
    assert "AB1234567" not in html          # raw numbers never reach templates


def test_decide_requires_csrf_then_flips_status(world, queue):
    sid, csrf = _login(world)
    r = world["client"].post("/admin/reviews/7/decide",
                             data={"decision": "approved"},
                             cookies={"admin_session": sid}, follow_redirects=False)
    assert r.status_code == 403
    r2 = world["client"].post("/admin/reviews/7/decide",
                              data={"decision": "approved", "csrf": csrf},
                              cookies={"admin_session": sid}, follow_redirects=False)
    assert r2.status_code == 303
    assert queue[0]["status"] == "approved"


def test_json_api_bearer_path(world, queue):
    r = world["client"].get("/admin/api/reviews",
                            headers={"Authorization": f"Bearer {ROLE_TOKEN}"})
    assert r.status_code == 200
    body = r.json()
    assert body["reviews"][0]["email"] == "fam@sovereign.mail"
    # masked columns ONLY — §10.2 forbids payload passthrough:
    assert set(body["reviews"][0]) <= {
        "review_id", "email", "reason", "status", "error_detail",
        "document_type", "identities_count", "created_at"}
