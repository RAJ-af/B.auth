"""Signup flow against faked storage/LDAP/OTP boundaries (contract §8.4)."""
import json
import time

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
    # so the REAL valid_email/password_ok run against sovereign.mail. ONE shared
    # namespace (not a fresh object per call) so Task 7's mode-binding tests can
    # monkeypatch idverify_mode on the very object the router reads back.
    import types as _ts
    _real_s = sr.get_settings()
    _d = dict(_real_s.model_dump()) if hasattr(_real_s, "model_dump") else dict(_real_s)
    _d["mail_domain"] = "sovereign.mail"
    _settings_ns = _ts.SimpleNamespace(**_d)
    monkeypatch.setattr(sr, "get_settings", lambda: _settings_ns)

    # provisioning writes go through app.db; swap them so no Postgres is needed
    sql: list[tuple] = []
    import app.db as appdb
    monkeypatch.setattr(appdb, "execute", lambda q, p=(): sql.append((q, p)))
    monkeypatch.setattr(appdb, "one", lambda q, p=(): None)

    # Manual-review queue seam: no DB locally, so _enqueue_review is the only
    # seam these tests need to observe verification_reviews inserts.
    reviews: list[dict] = []
    monkeypatch.setattr(idverify_mod(), "_enqueue_review",
                        lambda email, payload, *, reason, detail:
                        reviews.append({"email": email, "status": "pending",
                                        "reason": reason,
                                        "error_detail": detail}))

    from fastapi.testclient import TestClient
    return {"client": TestClient(create_app()), "sessions": sessions,
            "ldap_created": ldap_created, "otp_sent": otp_sent, "sql": sql,
            "reviews": reviews}


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


def test_ldap_down_503_session_retained_then_recovers(w, monkeypatch):
    """LdapUnavailable during complete => honest 503; session RETAINED so the
    same token completes successfully once the directory recovers."""
    import app.routers.signup_router as sr

    tok = _start(w)
    w["client"].post("/signup/verify-otp", json={"token": tok, "code": "123456"})
    payload = {"token": tok, "choice": {"kind": "skip"},
               "password": "long-enough-password-1"}

    def down(email, display_name, password):
        raise sr.ldap_admin.LdapUnavailable("connection refused")
    monkeypatch.setattr(sr.ldap_admin, "create_user", down)

    r = w["client"].post("/signup/complete", json=payload)
    assert r.status_code == 503
    assert tok in w["sessions"]              # session survives the outage

    def recovered(email, display_name, password):
        w["ldap_created"].append((email, display_name, password))
    monkeypatch.setattr(sr.ldap_admin, "create_user", recovered)

    r2 = w["client"].post("/signup/complete", json=payload)
    assert r2.status_code == 201
    assert r2.json()["account"] == "active"
    assert tok not in w["sessions"]          # burned only on full success


def test_trailing_newline_local_part_is_422_not_500(w):
    """$-anchor regression pin: '$' matches BEFORE a trailing newline, so the
    old LOCAL_PART.match('x\\n') passed while ldap_admin's fullmatch rejected
    it — a reachable raw 500. API-layer fullmatch closes the divergence."""
    r = w["client"].post("/signup/start", json={
        "email": "x\n@sovereign.mail", "display_name": "X",
        "phone_e164": "+911234567890", "account_type": "independent"})
    assert r.status_code == 422
    assert w["sessions"] == {}               # nothing persisted
    assert w["otp_sent"] == []               # no budget touched


def test_ldap_probe_outage_at_start_is_503_no_otp_burned(w, monkeypatch):
    """Directory outage at /signup/start => clean 503 (never a raw 500) and
    zero OTP sends attempted."""
    import app.routers.signup_router as sr

    def probe_down(email):
        raise sr.ldap_admin.LdapUnavailable("connection refused")
    monkeypatch.setattr(sr.ldap_admin, "address_exists", probe_down)

    r = w["client"].post("/signup/start", json={
        "email": "anyone@sovereign.mail", "display_name": "A",
        "phone_e164": "+911234567890", "account_type": "independent"})
    assert r.status_code == 503
    assert w["otp_sent"] == []
    assert w["sessions"] == {}


def test_real_get_session_accepts_both_payload_shapes(monkeypatch):
    """Gate-fix regression: the live psycopg3 dict_row driver decodes jsonb to
    a dict BEFORE _get_session sees it, so json.loads(dict) was a TypeError
    500 at verify-otp/complete. The REAL seam (not the fixture fake) must
    accept the driver shape and the JSON-string shape interchangeably."""
    import app.db as appdb
    import app.routers.signup_router as sr

    payload = {"email": "gatedrive@sovereign.mail", "display_name": "G",
               "phone_e164": "+911234567890", "account_type": "independent"}
    exp = time.time() + 900

    monkeypatch.setattr(appdb, "one", lambda q, p=(): {
        "payload_json": dict(payload),       # live-driver shape: already a dict
        "stage": "awaiting_otp", "exp": exp})
    out = sr._get_session("tok")
    assert out == {"payload": payload, "stage": "awaiting_otp"}

    monkeypatch.setattr(appdb, "one", lambda q, p=(): {
        "payload_json": json.dumps(payload),  # fake shape: raw JSON text
        "stage": "awaiting_otp", "exp": exp})
    out = sr._get_session("tok")
    assert out == {"payload": payload, "stage": "awaiting_otp"}


def test_verify_otp_with_live_driver_shape_session(monkeypatch):
    """Full-flow gate pin: REAL session seams over a db fake returning the
    live psycopg3 shape — verify-otp must proceed normally, never 500."""
    import app.db as appdb
    import app.routers.signup_router as sr

    rows = {"tok": {"payload_json": {"email": "gatedrive@sovereign.mail",
                                     "display_name": "G",
                                     "phone_e164": "+911234567890",
                                     "account_type": "independent"},
                    "stage": "awaiting_otp",          # driver-decoded jsonb
                    "exp": time.time() + 900}}
    monkeypatch.setattr(appdb, "one", lambda q, p=(): rows.get(p[0]))

    def fake_execute(q, p=()):
        # Mirror the real UPDATE signup_sessions ... so stage flips on disk.
        if p and len(p) == 3:
            rows[p[2]]["payload_json"] = json.loads(p[0])
            rows[p[2]]["stage"] = p[1]
    monkeypatch.setattr(appdb, "execute", fake_execute)

    def fake_send(phone, purpose, channel="sms"):
        pass
    def fake_verify(phone, purpose, code):
        return code == "123456"
    monkeypatch.setattr(sr.otp_service, "send_challenge", fake_send)
    monkeypatch.setattr(sr.otp_service, "verify_challenge", fake_verify)

    client = TestClient(create_app())
    r = client.post("/signup/verify-otp",
                    json={"token": "tok", "code": "123456"})
    assert r.status_code == 200
    assert r.json()["stage"] == "awaiting_identity_choice"
    assert rows["tok"]["stage"] == "awaiting_identity_choice"


# --- Task 7: AUTO/MANUAL dispatch through /signup/complete -------------------

def _submit_id_choice():
    return {"kind": "submit_id", "full_name": "New User",
            "document_type": "national_id", "id_number": "AB1234567",
            "consent_selfie": True}


def test_auto_mode_verified_upgrades_tier(w, monkeypatch):
    """IDVERIFY_MODE=auto + verifier says yes -> tier2_identity/auto_verified,
    no identity_status field in the body, and the raw id number never reaches
    a signup session."""
    monkeypatch.setattr(sr_settings(), "idverify_mode", "auto")

    def fake_run(payload):
        return {"contract_version": 1, "verified": True,
                "identities": [{"is_minor": False, "name": payload["full_name"],
                                "type": payload["document_type"],
                                "number_masked": "••••9999"}], "warnings": []}
    monkeypatch.setattr(idverify_mod(), "run_auto_check", fake_run)
    tok = _start(w)
    w["client"].post("/signup/verify-otp", json={"token": tok, "code": "123456"})
    r = w["client"].post("/signup/complete",
                         json={"token": tok, "choice": _submit_id_choice(),
                               "password": "long-enough-password-1"})
    b = r.json()
    assert r.status_code == 201
    assert (b["tier"], b["verification"]) == ("tier2_identity", "auto_verified")
    assert "identity_status" not in b
    # raw id number never persisted anywhere reachable (signup_sessions only;
    # verification_reviews deliberately keeps it for operator review):
    blob = json.dumps(w["sessions"])
    assert "AB1234567" not in blob


def test_manual_mode_queues_review_and_stays_tier1(w, monkeypatch):
    """IDVERIFY_MODE=manual -> policy_manual row queued for operators while the
    account still provisions at tier1 with queued_manual_review status."""
    monkeypatch.setattr(sr_settings(), "idverify_mode", "manual")
    tok = _start(w)
    w["client"].post("/signup/verify-otp", json={"token": tok, "code": "123456"})
    r = w["client"].post("/signup/complete",
                         json={"token": tok, "choice": _submit_id_choice(),
                               "password": "long-enough-password-1"})
    b = r.json()
    assert r.status_code == 201
    assert (b["tier"], b["verification"]) == ("tier1_phone", "pending_identity")
    assert b["identity_status"] == "queued_manual_review"


def test_infra_failure_soft_fallback_queues_script_error(w, monkeypatch):
    """Verifier infra blowup mid-complete => the 201 invariant holds, the
    soft-fallback union member is returned, and an auto_script_error row lands
    in the review queue."""
    monkeypatch.setattr(sr_settings(), "idverify_mode", "auto")

    def boom(payload):
        raise idverify_mod().IdverifyInfraError("script missing")
    monkeypatch.setattr(idverify_mod(), "run_auto_check", boom)
    tok = _start(w)
    w["client"].post("/signup/verify-otp", json={"token": tok, "code": "123456"})
    r = w["client"].post("/signup/complete",
                         json={"token": tok, "choice": _submit_id_choice(),
                               "password": "long-enough-password-1"})
    b = r.json()
    assert r.status_code == 201                      # complete NEVER fails post-OTP
    assert b["identity_status"] == "auto_check_unavailable"
    assert b["tier"] == "tier1_phone"
    # and a verification_reviews row was queued with reason auto_script_error:
    assert [row["reason"] for row in w["reviews"]] == ["auto_script_error"]


# small helpers used by the Task 7 tests above
def sr_settings():
    import app.routers.signup_router as m
    return m.get_settings()


def idverify_mod():
    from app.services import idverify
    return idverify