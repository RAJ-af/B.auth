"""Signup flow against faked storage/LDAP/OTP boundaries (contract §8.4)."""
import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture
def w(monkeypatch):
    """Everything the router touches, swapped for in-memory fakes."""
    sessions: dict[str, dict] = {}
    ldap_created: list[tuple] = []
    otp_sent: list[str] = []

    import app.routers.signup_router as sr
    monkeypatch.setattr(sr, "_create_session",
                        lambda tok, payload, ttl=900:
                        sessions.update({tok: {"payload": payload,
                                               "stage": "awaiting_otp"}}))
    monkeypatch.setattr(sr, "_get_session", lambda tok: sessions.get(tok))
    monkeypatch.setattr(sr, "_update_session",
                        lambda tok, payload, stage:
                        sessions[tok].update({"payload": payload, "stage": stage})
                        or sessions[tok])
    monkeypatch.setattr(sr, "_delete_session",
                        lambda tok: sessions.pop(tok, None))
    monkeypatch.setattr(sr.ldap_admin, "address_exists",
                        lambda e: e == "taken@sovereign.mail")

    def fake_create(email, display_name, password):
        ldap_created.append((email, display_name, password))
    monkeypatch.setattr(sr.ldap_admin, "create_user", fake_create)

    def fake_send(phone, purpose, channel="sms"):
        otp_sent.append(phone)
    def fake_verify(phone, purpose, code):
        return code == "123456"
    monkeypatch.setattr(sr.otp_service, "send_challenge", fake_send)
    monkeypatch.setattr(sr.otp_service, "verify_challenge", fake_verify)

    # Settings override: conftest pins MAIL_DOMAIN=test.mail (ldap tests), but
    # this module's flows use @sovereign.mail. Swap the router-bound get_settings
    # so the REAL valid_email/password_ok run against sovereign.mail.
    import types as _ts
    _real_s = sr.get_settings()
    _d = dict(_real_s.model_dump()) if hasattr(_real_s, "model_dump") else dict(_real_s)
    _d["mail_domain"] = "sovereign.mail"
    monkeypatch.setattr(sr, "get_settings", lambda: _ts.SimpleNamespace(**_d))

    # provisioning writes go through app.db; swap them so no Postgres is needed
    sql: list[tuple] = []
    import app.db as appdb
    monkeypatch.setattr(appdb, "execute", lambda q, p=(): sql.append((q, p)))
    monkeypatch.setattr(appdb, "one", lambda q, p=(): None)

    from fastapi.testclient import TestClient
    return {"client": TestClient(create_app()), "sessions": sessions,
            "ldap_created": ldap_created, "otp_sent": otp_sent, "sql": sql}


def _start(w, email="newuser@sovereign.mail", **over):
    body = {"email": email, "display_name": "New User",
            "phone_e164": "+911234567890", "account_type": "independent"}
    body |= over
    r = w["client"].post("/signup/start", json=body)
    assert r.status_code == 202, r.text
    return r.json()["session_token"]


def test_start_contract(w):
    r = w["client"].post("/signup/start", json={
        "email": "x@sovereign.mail", "display_name": "X",
        "phone_e164": "+911234567890", "account_type": "independent"})
    j = r.json()
    assert r.status_code == 202
    assert j["stage"] == "awaiting_otp"
    assert set(j) >= {"session_token", "stage", "message"}
    assert w["otp_sent"] == ["+911234567890"]       # this start sent an OTP


def test_duplicate_email_is_409_before_any_otp(w):
    r = w["client"].post("/signup/start", json={
        "email": "taken@sovereign.mail", "display_name": "T",
        "phone_e164": "+911234567891", "account_type": "independent"})
    assert r.status_code == 409
    assert w["otp_sent"] == []


def test_validation_rejects_bad_shapes(w):
    for bad in [{"email": "UPPER@sovereign.mail"},
                {"email": "weird@other.domain"},
                {"phone_e164": "09123456789"},
                {"phone_e164": "+123"},                # too short
                {"account_type": "guardian_managed"},  # guardian_phone missing
                ]:
        body = {"email": "ok@sovereign.mail", "display_name": "Ok",
                "phone_e164": "+911234567890", "account_type": "independent"}
        body |= bad
        assert w["client"].post("/signup/start", json=body).status_code == 422, bad
    # guardian_managed WITH guardian phone passes
    body = {"email": "kid@sovereign.mail", "display_name": "Kid",
            "phone_e164": "+911234567892",
            "account_type": "guardian_managed", "guardian_phone": "+919999999999"}
    assert w["client"].post("/signup/start", json=body).status_code == 202


def test_verify_then_complete_skip_tier1(w):
    tok = _start(w)
    r = w["client"].post("/signup/verify-otp", json={"token": tok, "code": "123456"})
    assert r.status_code == 200
    j = r.json()
    assert j["stage"] == "awaiting_identity_choice" and j["tier"] == "tier1_phone"

    done = w["client"].post("/signup/complete",
                            json={"token": tok, "choice": {"kind": "skip"},
                                  "password": "long-enough-password-1"})
    assert done.status_code == 201, done.text
    b = done.json()
    assert b["account"] == "active" and b["tier"] == "tier1_phone"
    assert b["verification"] == "pending_identity"
    assert w["ldap_created"][0][0] == "newuser@sovereign.mail"


def test_wrong_otp_is_401_and_keeps_stage(w):
    tok = _start(w)
    r = w["client"].post("/signup/verify-otp", json={"token": tok, "code": "000000"})
    assert r.status_code == 401
    assert w["sessions"][tok]["stage"] == "awaiting_otp"


def test_complete_requires_verified_otp(w):
    tok = _start(w)
    r = w["client"].post("/signup/complete",
                         json={"token": tok, "choice": {"kind": "skip"},
                               "password": "long-enough-password-1"})
    assert r.status_code == 400          # still awaiting_otp
    assert w["ldap_created"] == []


def test_weak_password_422_no_ldap_write(w):
    tok = _start(w)
    w["client"].post("/signup/verify-otp", json={"token": tok, "code": "123456"})
    r = w["client"].post("/signup/complete",
                         json={"token": tok, "choice": {"kind": "skip"},
                               "password": "short"})
    assert r.status_code == 422
    assert w["ldap_created"] == []


def test_off_mode_soft_fallback_contract(w, monkeypatch):
    """idverify off + skip-choice => plain tier1 (§8.4); no 503 anywhere here."""
    tok = _start(w)
    w["client"].post("/signup/verify-otp", json={"token": tok, "code": "123456"})
    r = w["client"].post("/signup/complete",
                         json={"token": tok, "choice": {"kind": "skip"},
                               "password": "long-enough-password-1"})
    assert r.status_code == 201
    assert "identity_status" not in r.json()