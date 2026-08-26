"""Recovery: friction everywhere, silence outward (spec §13, §15.3).

Service-level suite plus an HTTP-layer pin set: the fixture swaps the storage
seams (_load_active trio, device seam, OTP/notify/LDAP edges) and freezes time
at rc.time (the shared time module), so TestClient exercises REAL router code
against faked storage and every wire shape is pinned byte-for-byte.
"""
import json

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.services import devices as dv
from app.services import recovery as rc


START_BODY = b'{"received":true}'


@pytest.fixture
def w(monkeypatch):
    reqs: dict[str, dict] = {}
    seq = {"n": 0}
    store = {"accounts": {"alice@sovereign.mail": True,
                          "bob@sovereign.mail": True}}
    events: list[tuple] = []
    links: list[dict] = []
    clock = {"t": 1_800_000_000.0}

    def req_id():
        seq["n"] += 1
        return f"rq-{seq['n']}"

    monkeypatch.setattr(rc.time, "time", lambda: clock["t"])
    monkeypatch.setattr(rc, "_account_exists",
                        lambda e: store["accounts"].get(e, False))
    monkeypatch.setattr(rc, "_save",
                        lambda r: reqs.__setitem__(r["req_id"], r) or r)
    monkeypatch.setattr(rc, "_active_for", lambda e: next(
        (r for r in reqs.values() if r["email"] == e
         and r["status"] in ("awaiting_phone", "pending_family",
                             "pending_dwell", "pending_admin",
                             "authorized")), None))
    monkeypatch.setattr(rc, "_get", lambda rid: reqs.get(rid))
    # R3 seam: the unit-testable unit behind void_requests_for_device.
    monkeypatch.setattr(rc, "_active_by_device", lambda h: next(
        (r for r in reqs.values() if r.get("recog") == h
         and r["status"] in ("awaiting_phone", "pending_family",
                             "pending_dwell")), None))
    monkeypatch.setattr(rc, "_new_id", req_id)
    # Inclusive boundary: the frozen clock gives every start the SAME
    # created_at, so strict '>' would never accumulate toward the cap.
    monkeypatch.setattr(rc, "_starts_in_last_hour", lambda e, t: sum(
        1 for r in reqs.values() if r["email"] == e and r["created_at"] >= t))
    from app.services import otp_service as _ot

    def fake_verify(phone, purpose, code):
        if code != "123456":
            raise _ot.InvalidCode("codes do not match")
        return True
    monkeypatch.setattr(rc.otp_service, "send_challenge",
                        lambda *a, **k: events.append(("otp_sent", a[0])))
    monkeypatch.setattr(rc.otp_service, "verify_challenge", fake_verify)
    monkeypatch.setattr(rc, "_phone_for",
                        lambda e: "+seed-" + e.split("@")[0])
    # Guardianship control seams (§8.2): default world has only INDEPENDENT
    # accounts and no phone-matched guardians; individual tests override.
    monkeypatch.setattr(rc, "_account_control", lambda e: (
        {"account_type": "independent", "guardian_phone": None}
        if store["accounts"].get(e) else None))
    monkeypatch.setattr(rc, "_accounts_with_phone", lambda p: [])
    monkeypatch.setattr(rc, "_actor_is_managed", lambda e: False)
    # R7: fake returns PRODUCTION-SHAPED rows (link_id/requester_email/
    # target_email/status/usable_at_ts). Each fixture entry {"member_of": e,
    # "partner": p} models one usable link between e and p; partner is optional
    # because existence-only tests (branch pick, expiry) never name it.
    def fake_active_links(e):
        return [{"link_id": i,
                 "requester_email": e,
                 "target_email": l.get("partner"),
                 "status": "approved",
                 "usable_at_ts": clock["t"]}
                for i, l in enumerate(links, start=1)
                if l["member_of"] == e]
    monkeypatch.setattr(rc.family, "active_links_for", fake_active_links)
    monkeypatch.setattr(dv, "resolve", lambda raw: None)
    monkeypatch.setattr(rc.notifications, "notify",
                        lambda e, t, b: events.append(("note", e, t)))
    monkeypatch.setattr(rc.notifications, "fan_out_email",
                        lambda *a, **k: events.append(("email",) + a))
    monkeypatch.setattr(rc.notifications, "send_sms_alert",
                        lambda p, b: events.append(("sms", p)) or True)
    monkeypatch.setattr(rc.ldap_admin, "set_password",
                        lambda e, p: events.append(("pwset", e)))
    # test_devices' fixture clears VOID_HOOKS and runs earlier alphabetically;
    # make registration order-independent for this suite.
    if rc.void_requests_for_device not in dv.VOID_HOOKS:
        dv.VOID_HOOKS.append(rc.void_requests_for_device)

    def advance(seconds):
        clock["t"] += seconds

    return {"reqs": reqs, "events": events, "links": links,
            "advance": advance, "store": store}


def test_unknown_and_known_email_byte_identical(w):
    a = rc.start_recovery("nobody@sovereign.mail", None)
    b = rc.start_recovery("alice@sovereign.mail", None)
    assert rc.public_view(a) == rc.public_view(b) == json.loads(START_BODY)


def test_start_always_sends_otp_when_known_and_budgeted(w):
    rc.start_recovery("alice@sovereign.mail", None)
    assert ("otp_sent", "+seed-alice") in [
        ("otp_sent", e[1]) for e in w["events"] if e[0] == "otp_sent"]


def test_attempt_budget_is_silent(w):
    for _ in range(int(rc_max())):
        rc.start_recovery("alice@sovereign.mail", None)
    n_before = len([e for e in w["events"] if e[0] == "otp_sent"])
    out = rc.start_recovery("alice@sovereign.mail", None)   # over budget
    assert rc.public_view(out) == json.loads(START_BODY)     # looks normal...
    n_after = len([e for e in w["events"] if e[0] == "otp_sent"])
    assert n_after == n_before                               # ...but did NOTHING


def rc_max():
    from app.config import get_settings
    return get_settings().recovery_max_attempts_per_hour


def test_supersede_cancels_previous(w):
    rc.start_recovery("alice@sovereign.mail", None)
    first = [r for r in w["reqs"].values() if r["email"] == "alice@sovereign.mail"][0]
    rc.start_recovery("alice@sovereign.mail", None)
    assert first["status"] == "cancelled"
    assert first["cancel_reason"] == "superseded"


def test_branch_pick_pending_admin_without_factors(w):
    out = rc.start_recovery("alice@sovereign.mail", None)
    rc.verify_otp("alice@sovereign.mail", "123456")
    assert out["status"] == "pending_admin"


def test_device_path_requires_full_dwell(w, monkeypatch):
    raw = "devraw123"
    dev = {"device_hash": "h" * 64, "email": "alice@sovereign.mail"}
    monkeypatch.setattr(dv, "resolve", lambda r: dev if r == raw else None)
    out = rc.start_recovery("alice@sovereign.mail", raw)
    rc.verify_otp("alice@sovereign.mail", "123456")
    assert out["status"] == "pending_dwell"
    # too early (brief's [:1] slice could never equal a 2-tuple — full compare):
    w["advance"](rc_min_dwell() - 10)
    assert rc.maybe_complete("alice@sovereign.mail", "new-password-long",
                             raw) == ("not_ready", 403)
    # past the dwell wall:
    w["advance"](20)
    status, code = rc.maybe_complete("alice@sovereign.mail",
                                     "new-password-long", raw)
    assert (status, code) == ("completed", 201)
    assert ("pwset", "alice@sovereign.mail") in w["events"]
    assert ("sms",) == tuple(e[:1] for e in w["events"] if e[0] == "sms")[0]


def rc_min_dwell():
    from app.config import get_settings
    return get_settings().recovery_min_dwell_seconds


def test_family_window_expiry_no_auto_dwell_fallback(w, monkeypatch):
    """§13.5: an EXPIRED family window flips expired lazily on next touch and
    completes as invalid_request — the user must start over and consume a
    fresh attempt. (Device-present variant pinned by its sibling below.)"""
    w["links"].append({"member_of": "alice@sovereign.mail"})
    raw = None
    out = rc.start_recovery("alice@sovereign.mail", raw)
    rc.verify_otp("alice@sovereign.mail", "123456")
    assert out["status"] == "pending_family"
    ttl = ttl_seconds()
    w["advance"](ttl + 1)
    assert rc._refresh_state(out)["status"] == "expired"      # lazy flip
    status, code = rc.maybe_complete("alice@sovereign.mail",
                                     "new-password-long", raw)
    assert (status, code) == ("invalid_request", 400)         # NOT a dwell path


def test_expired_family_window_with_device_stays_dead(w, monkeypatch):
    """Q3 pin: family outranks device at branch pick, and once the window is
    EXPIRED the recognized device cannot revive it as dwell — no auto fallback
    even when the SAME device presents at complete time."""
    raw = "devrawFAM"
    dev = {"device_hash": "f" * 64, "email": "alice@sovereign.mail"}
    monkeypatch.setattr(dv, "resolve", lambda r: dev if r == raw else None)
    w["links"].append({"member_of": "alice@sovereign.mail"})
    out = rc.start_recovery("alice@sovereign.mail", raw)
    rc.verify_otp("alice@sovereign.mail", "123456")
    assert out["status"] == "pending_family"                  # family wins
    w["advance"](ttl_seconds() + 1)
    assert rc._refresh_state(out)["status"] == "expired"      # lazy flip
    status, code = rc.maybe_complete("alice@sovereign.mail",
                                     "new-password-long", raw)
    assert (status, code) == ("invalid_request", 400)         # NOT revived as dwell


def ttl_seconds():
    from app.config import get_settings
    return get_settings().recovery_request_ttl_seconds


def test_family_approve_unlocks_completion(w):
    # R7: the approving member must be a genuine party to a usable link.
    w["links"].append({"member_of": "alice@sovereign.mail",
                       "partner": "member@sovereign.mail"})
    out = rc.start_recovery("alice@sovereign.mail", None)
    rc.verify_otp("alice@sovereign.mail", "123456")
    assert rc.family_approve("member@sovereign.mail", "alice@sovereign.mail")
    assert w["reqs"][out["req_id"]]["decided_by"] == "member@sovereign.mail"
    status, code = rc.maybe_complete("alice@sovereign.mail",
                                     "new-password-long", None)
    assert (status, code) == ("completed", 201)


def test_family_approve_without_standing_changes_nothing(w):
    """R7 pinning: a member with no link to the requester is refused BEFORE any
    state is touched — the window stays open for someone who does have standing."""
    w["links"].append({"member_of": "alice@sovereign.mail",
                       "partner": "relative@sovereign.mail"})
    out = rc.start_recovery("alice@sovereign.mail", None)
    rc.verify_otp("alice@sovereign.mail", "123456")
    assert out["status"] == "pending_family"
    assert rc.family_approve("mallory@sovereign.mail",
                             "alice@sovereign.mail") is False
    assert out["status"] == "pending_family"          # untouched
    assert out["decided_by"] is None                  # nothing was written


def test_managed_approver_leaves_request_untouched_wire_silent(w, monkeypatch):
    """§8.2 point 2 + R7 oracle at the HTTP layer: a managed actor's
    family-approve attempt — even sitting on a usable link — changes NOTHING
    and sees the SAME constant body as everyone else."""
    monkeypatch.setattr(rc, "_actor_is_managed",
                        lambda e: e == "managed@sovereign.mail")
    w["links"].append({"member_of": "alice@sovereign.mail",
                       "partner": "managed@sovereign.mail"})
    out = rc.start_recovery("alice@sovereign.mail", None)
    rc.verify_otp("alice@sovereign.mail", "123456")
    assert out["status"] == "pending_family"

    c = _jwt_client("managed@sovereign.mail")
    resp = c.post("/recovery/family-approve",
                  json={"requester_email": "alice@sovereign.mail"})
    assert resp.status_code == 200
    assert resp.content == START_BODY         # wire-silent refusal (R7)
    assert out["status"] == "pending_family"  # request untouched
    assert out["decided_by"] is None          # nothing was written


def test_family_approve_self_approval_refused(w):
    """R7 pinning: sitting on a usable link does NOT let the requester approve
    their own window — two-party control holds even for linked accounts."""
    w["links"].append({"member_of": "alice@sovereign.mail",
                       "partner": "relative@sovereign.mail"})
    out = rc.start_recovery("alice@sovereign.mail", None)
    rc.verify_otp("alice@sovereign.mail", "123456")
    assert out["status"] == "pending_family"
    assert rc.family_approve("alice@sovereign.mail",
                             "alice@sovereign.mail") is False
    assert out["status"] == "pending_family"          # untouched
    assert out["decided_by"] is None                  # nothing was written


def test_delete_device_voids_pending_dwell(w, monkeypatch):
    raw = "devrawXYZ"
    dev = {"device_hash": "abcd" * 16, "email": "alice@sovereign.mail"}
    monkeypatch.setattr(dv, "resolve", lambda r: dev if r == raw else None)
    out = rc.start_recovery("alice@sovereign.mail", raw)
    rc.verify_otp("alice@sovereign.mail", "123456")
    assert out["status"] == "pending_dwell"
    dv.fire_void(dev["device_hash"])                          # what account_router DELETE triggers
    assert out["status"] == "cancelled"
    assert out["cancel_reason"] == "device_removed"


def test_wrong_otp_never_advances(w):
    out = rc.start_recovery("alice@sovereign.mail", None)
    with pytest.raises(Exception):
        rc.verify_otp("alice@sovereign.mail", "000000")
    assert out["status"] == "awaiting_phone"


# --- R5: cancel standing -------------------------------------------------------

def test_cancel_without_standing_changes_nothing(w):
    """A JWT that neither owns the email nor sits on an active family link with
    it must leave the request untouched — yet the caller sees no difference."""
    out = rc.start_recovery("alice@sovereign.mail", None)
    assert rc.cancel("alice@sovereign.mail", "mallory@sovereign.mail") is False
    assert out["status"] == "awaiting_phone"          # still live server-side
    assert out["cancel_reason"] is None               # nothing was written


def test_owner_cancel_wipes_active_request(w):
    out = rc.start_recovery("alice@sovereign.mail", None)
    assert rc.cancel("alice@sovereign.mail", "alice@sovereign.mail") is True
    assert out["status"] == "cancelled"


# --- admin grant ---------------------------------------------------------------

def test_admin_grant_flips_pending_admin_to_authorized(w):
    out = rc.start_recovery("alice@sovereign.mail", None)
    rc.verify_otp("alice@sovereign.mail", "123456")
    assert out["status"] == "pending_admin"
    assert rc.admin_grant(out["req_id"], "sec-reviewer") is True
    rec = w["reqs"][out["req_id"]]
    assert rec["status"] == "authorized"
    assert rec["decided_by"] == "admin:sec-reviewer"
    # the granted path completes like family-approved ones do:
    assert rc.maybe_complete("alice@sovereign.mail",
                             "new-password-long", None) == ("completed", 201)


# --- N1: notification coverage (spec §12/§13) ---------------------------------

def _notes(w, kind):
    return [e for e in w["events"] if e[0] == kind]


def test_family_branch_notifies_every_linked_member_once(w):
    """Branch pick into pending_family tells EVERY active&cooled member exactly
    once — in-app row plus one pointer-only email each, requester MASKED."""
    w["links"].append({"member_of": "alice@sovereign.mail",
                       "partner": "mem1@sovereign.mail"})
    w["links"].append({"member_of": "alice@sovereign.mail",
                       "partner": "mem2@sovereign.mail"})
    out = rc.start_recovery("alice@sovereign.mail", None)
    n_at_start = len(w["events"])     # owner's own start notice precedes this
    rc.verify_otp("alice@sovereign.mail", "123456")
    assert out["status"] == "pending_family"
    picked = w["events"][n_at_start:]
    notes = [e[1] for e in picked if e[0] == "note"]
    emails = [e for e in picked if e[0] == "email"]
    for member in ("mem1@sovereign.mail", "mem2@sovereign.mail"):
        assert notes.count(member) == 1          # exactly once per member
        assert [e[1] for e in emails].count(member) == 1
    assert not any(e[1].startswith("alice@") for e in emails)  # requester not fanned
    body = next(e for e in emails if e[1] == "mem1@sovereign.mail")
    assert "family recovery approval needed" in body[2]      # subject style
    assert "a***@sovereign.mail" in body[3]      # masked name, per §12 shape
    assert "http" not in body[3].lower()         # pointer-only, LOAD-BEARING


def test_managed_recovery_lands_pending_admin_and_notifies_guardian(
        w, monkeypatch):
    """§8.2 point 3: a managed account's own recovery routes to pending_admin
    ALWAYS — even with usable links present — and the GUARDIAN learns."""
    w["store"]["accounts"]["kid@sovereign.mail"] = True   # the dependent exists
    monkeypatch.setattr(rc, "_account_control", lambda e: {
        "account_type": "guardian_managed",
        "guardian_phone": "+919999999999"})
    monkeypatch.setattr(rc, "_accounts_with_phone",
                        lambda p: ["guardian@sovereign.mail"])
    w["links"].append({"member_of": "kid@sovereign.mail",
                       "partner": "member@sovereign.mail"})   # must be IGNORED
    out = rc.start_recovery("kid@sovereign.mail", None)
    rc.verify_otp("kid@sovereign.mail", "123456")
    assert out["status"] == "pending_admin"      # never pending_family/dwell
    assert ("note", "guardian@sovereign.mail", "guardian_recovery_alert") \
        in w["events"]
    email = next(e for e in _notes(w, "email")
                 if e[1] == "guardian@sovereign.mail")
    assert "k***@sovereign.mail" in email[3]     # masked dependent, never raw
    assert "http" not in email[3].lower()        # pointer-only, LOAD-BEARING
    # the family window never opened: no member was invited to approve
    assert "member@sovereign.mail" not in [e[1] for e in _notes(w, "email")]


def test_cancel_notifies_owner_regardless_of_canceller(w):
    """§13: owner is told about every cancel — own or a standing member's.
    Wire silence unchanged: this is a service-level side effect only."""
    out = rc.start_recovery("alice@sovereign.mail", None)
    rc.cancel("alice@sovereign.mail", "alice@sovereign.mail")
    assert ("note", "alice@sovereign.mail", "recovery_cancelled") in w["events"]
    assert any(e[0] == "email" and e[1] == "alice@sovereign.mail"
               for e in w["events"])

    # second round: a MEMBER cancelling still reaches the owner
    w["links"].append({"member_of": "alice@sovereign.mail",
                       "partner": "member@sovereign.mail"})
    out2 = rc.start_recovery("alice@sovereign.mail", None)
    n_before = len([e for e in _notes(w, "note")
                    if e[1] == "alice@sovereign.mail"
                    and e[2] == "recovery_cancelled"])
    rc.cancel("alice@sovereign.mail", "member@sovereign.mail")
    n_after = len([e for e in _notes(w, "note")
                   if e[1] == "alice@sovereign.mail"
                   and e[2] == "recovery_cancelled"])
    assert n_after == n_before + 1
    assert out2["status"] == "cancelled"


def test_failed_cancel_notifies_nothing(w):
    rc.start_recovery("alice@sovereign.mail", None)
    n = len(w["events"])
    assert rc.cancel("alice@sovereign.mail",
                     "mallory@sovereign.mail") is False   # no standing
    assert len(w["events"]) == n              # zero side effects, wire-silent


# --- assisted-queue listing (README §9/§10; masking idiom) ---------------------

def test_list_pending_admin_masks_and_orders_newest_first(monkeypatch):
    """Projection whitelist + masked address: the raw email never crosses the
    service boundary, rows come back newest-first (§13 queue discipline)."""
    seen: list[tuple] = []

    def fake_many(q, p=()):
        seen.append((q, p))
        return [{"req_id": "rq-new", "email": "alice@sovereign.mail",
                 "status": "pending_admin", "created_at": 1_800_000_200.0},
                {"req_id": "rq-old", "email": "bob@sovereign.mail",
                 "status": "pending_admin", "created_at": 1_800_000_100.0}]
    monkeypatch.setattr(rc, "many", fake_many)

    out = rc.list_pending_admin()
    q = seen[0][0]
    assert "status='pending_admin'" in q
    assert "ORDER BY created_at DESC" in q
    assert out == [
        {"req_id": "rq-new", "email_masked": "a***@sovereign.mail",
         "status": "pending_admin", "created_at": 1_800_000_200.0},
        {"req_id": "rq-old", "email_masked": "b***@sovereign.mail",
         "status": "pending_admin", "created_at": 1_800_000_100.0}]
    import json as _json
    assert "alice@sovereign.mail" not in _json.dumps(out)   # raw never leaks


def test_list_pending_admin_empty(monkeypatch):
    monkeypatch.setattr(rc, "many", lambda q, p=(): [])
    assert rc.list_pending_admin() == []


# --- HTTP layer pins (§15.3 wire shapes; REAL router code, faked storage) ----

def _jwt_client(email: str) -> TestClient:
    """TestClient with get_current_user overridden to a fixed identity,
    mirroring the real dependency contract (raw_token stash included). The
    request arg MUST be annotated Request — FastAPI solves the override's
    own signature, and an unannotated param becomes a required query field."""
    from app.auth import get_current_user
    from fastapi import Request

    app = create_app()

    def fake_user(request: Request):
        request.state.raw_token = "faketoken"
        return {"sub": "s", "email": email}
    app.dependency_overrides[get_current_user] = fake_user
    return TestClient(app)


def test_http_start_known_and_unknown_byte_identical(w):
    c = TestClient(create_app())
    unknown = c.post("/recovery/start", json={"email": "nobody@sovereign.mail"})
    known = c.post("/recovery/start", json={"email": "alice@sovereign.mail"})
    assert unknown.status_code == known.status_code == 202
    assert unknown.content == known.content == START_BODY


def test_http_cancel_never_leaks_standing(w):
    """Standing-oracle regression guard (R5): a non-standing JWT must see the
    SAME 200 {"received":true} an owner would see — reintroducing any ok/404
    split or error body fails here."""
    out = rc.start_recovery("alice@sovereign.mail", None)
    c = _jwt_client("mallory@sovereign.mail")
    r = c.post("/recovery/cancel", json={"email": "alice@sovereign.mail"})
    assert r.status_code == 200
    assert r.content == START_BODY
    assert out["status"] == "awaiting_phone"      # untouched server-side
    # the request really was live: the owner can still cancel it afterwards
    assert rc.cancel("alice@sovereign.mail", "alice@sovereign.mail") is True


def test_http_wrong_otp_single_401_shape(w):
    """One 401 body forever — regardless of attempt count or target email."""
    c = TestClient(create_app())
    rc.start_recovery("alice@sovereign.mail", None)
    first = c.post("/recovery/verify-otp",
                   json={"email": "alice@sovereign.mail", "code": "000000"})
    again = c.post("/recovery/verify-otp",
                   json={"email": "alice@sovereign.mail", "code": "111111"})
    other = c.post("/recovery/verify-otp",
                   json={"email": "mallory@sovereign.mail", "code": "222222"})
    assert first.status_code == again.status_code == other.status_code == 401
    assert first.content == again.content == other.content


def test_http_short_password_422_before_service_touch(w, monkeypatch):
    """password_min_length rejects at the router BEFORE the service runs —
    a spy on maybe_complete must record zero calls even with a live request."""
    seen: list[tuple] = []
    monkeypatch.setattr(rc, "maybe_complete",
                        lambda *a, **k: seen.append(a) or ("completed", 201))
    rc.start_recovery("alice@sovereign.mail", None)   # live request waiting
    c = TestClient(create_app())
    r = c.post("/recovery/complete",
               json={"email": "alice@sovereign.mail", "new_password": "short"})
    assert r.status_code == 422
    assert seen == []                             # service never touched
