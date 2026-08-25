"""Notifications: in-app rows are authoritative; email fan-out is best-effort.
Also covers the /account endpoints (profile, list, mark-read) and their
JWT-email scoping."""
import pytest
from fastapi import Request
from fastapi.testclient import TestClient

from app.services import notifications as nf


@pytest.fixture
def rows(monkeypatch):
    store = []

    monkeypatch.setattr(nf, "_insert", lambda r: store.append(r) or r)
    monkeypatch.setattr(nf, "_fetch", lambda email, limit:
                        [r for r in store if r["email"] == email][-limit:])
    sent = []
    monkeypatch.setattr(nf, "_submit_mime",
                        lambda msg, rcpts: sent.append(rcpts) or (
                            (_ for _ in ()).throw(RuntimeError("smtp down"))
                            if len(sent) == 2 else None))
    return {"store": store, "sent": sent}


def test_notify_inserts_in_app_row(rows):
    n = nf.notify("a@sovereign.mail", "family_request_received",
                  "Someone requested to link with you. Open your app to review.")
    assert n["email"] == "a@sovereign.mail" and n["read_at"] is None


def test_fan_out_email_survives_smtp_failure(rows):
    nf.fan_out_email("a@sovereign.mail", "Sovereign Mail: new family request",
                     "Open your Sovereign Mail app to review this request.")
    # first send OK; force a second that raises inside _submit_mime
    try:
        nf.fan_out_email("a@sovereign.mail", "again", "body")
    except RuntimeError:
        raise AssertionError("email fan-out must never propagate failures")


def test_pointer_emails_carry_no_links(rows):
    captured = {}
    def fake_build(**kw):
        captured.update(kw)
        class M: pass
        return M()
    import app.smtp_client as sc
    orig = nf._build_mime
    nf._build_mime = fake_build          # noqa: deliberate direct swap for capture
    try:
        nf.fan_out_email("a@sovereign.mail", "subject", "text body")
    finally:
        nf._build_mime = orig
    assert "http" not in captured["text"].lower()
    assert captured["from_"].startswith("noreply@")


def test_notify_returns_complete_row_with_real_ids(monkeypatch):
    """notify() must hand back the COMPLETE stored row -- a real integer
    notif_id and a non-null created_at (INSERT .. RETURNING) -- because the
    family-link flows need actual ids, not just an echo of what was passed in."""
    from datetime import datetime, timezone
    created = datetime(2026, 8, 25, tzinfo=timezone.utc)
    monkeypatch.setattr(nf, "one",
                        lambda q, p=(): {"notif_id": 42, "created_at": created})
    n = nf.notify("a@sovereign.mail", "family_request_received", "body text")
    assert set(n) == {"email", "type", "body", "notif_id", "created_at",
                      "read_at"}
    assert isinstance(n["notif_id"], int) and n["notif_id"] == 42
    assert n["created_at"] is not None
    assert n["read_at"] is None


# --- /account endpoints ------------------------------------------------------

JWT_EMAIL = "me@sovereign.mail"


def _account_client(monkeypatch, jwt_email=JWT_EMAIL):
    """TestClient with get_current_user overridden to a fixed JWT identity and
    the notification seams faked in-memory."""
    import app.db as appdb
    from app.auth import get_current_user
    from app.main import create_app

    fetched, marked, profile_lookups = [], [], []

    def fake_fetch(email, limit=50):
        fetched.append((email, limit))
        return [{"notif_id": 7, "email": email, "type": "family_request_received",
                 "body": "Someone requested to link with you.",
                 "link_ref": None, "created_at": "2026-08-25T00:00:00Z",
                 "read_at": None}]

    def fake_mark(email, notif_id):
        marked.append((email, notif_id))

    def fake_one(q, p=()):
        profile_lookups.append(p[0] if p else None)
        if p and p[0] == jwt_email:
            return {"email": jwt_email, "display_name": "Me",
                    "phone_e164": "+911234567890",
                    "account_type": "independent", "guardian_phone": None,
                    "tier": "tier1_phone", "verification": "pending_identity",
                    "status": "active", "created_at": "2026-08-25T00:00:00Z"}
        return None

    monkeypatch.setattr(nf, "_fetch", fake_fetch)
    monkeypatch.setattr(nf, "mark_read", fake_mark)
    monkeypatch.setattr(appdb, "one", fake_one)

    app = create_app()

    def fake_user(request: Request):     # mirrors the real dependency contract,
        request.state.raw_token = "faketoken"   # including the raw-token stash
        return {"sub": "s", "email": jwt_email}
    app.dependency_overrides[get_current_user] = fake_user
    return TestClient(app), {"fetched": fetched, "marked": marked,
                             "profile_lookups": profile_lookups}


def auth():
    return {"Authorization": "Bearer faketoken"}


def test_account_notifications_use_jwt_email(monkeypatch):
    client, seams = _account_client(monkeypatch)
    r = client.get("/account/notifications", headers=auth())
    assert r.status_code == 200
    body = r.json()["notifications"]
    # scope comes from the JWT, never from anything client-supplied
    assert seams["fetched"] == [(JWT_EMAIL, 50)]
    assert body and all(n["email"] == JWT_EMAIL for n in body)


def test_account_notifications_ignore_client_supplied_email(monkeypatch):
    """Cross-user probe: a query-param email must not widen the scope."""
    client, seams = _account_client(monkeypatch)
    r = client.get("/account/notifications", headers=auth(),
                   params={"email": "victim@sovereign.mail"})
    assert r.status_code == 200
    assert seams["fetched"] == [(JWT_EMAIL, 50)]
    assert all(n["email"] == JWT_EMAIL for n in r.json()["notifications"])


def test_mark_read_binds_to_jwt_email(monkeypatch):
    client, seams = _account_client(monkeypatch)
    r = client.post("/account/notifications/7/read", headers=auth())
    assert r.status_code == 200 and r.json() == {"ok": True}
    assert seams["marked"] == [(JWT_EMAIL, 7)]      # email from JWT, id from path


def test_profile_returns_own_row(monkeypatch):
    client, seams = _account_client(monkeypatch)
    r = client.get("/account/profile", headers=auth())
    assert r.status_code == 200
    b = r.json()
    assert b["email"] == JWT_EMAIL
    assert b["tier"] == "tier1_phone"
    assert seams["profile_lookups"] == [JWT_EMAIL]


def test_profile_missing_row_is_404(monkeypatch):
    import app.db as appdb
    client, seams = _account_client(monkeypatch)
    monkeypatch.setattr(appdb, "one", lambda q, p=(): None)   # no accounts row
    r = client.get("/account/profile", headers=auth())
    assert r.status_code == 404
