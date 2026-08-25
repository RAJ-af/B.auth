"""Recovery: friction everywhere, silence outward (spec §13, §15.3).

Service-level suite. The fixture swaps the storage seams (_load_active trio,
device seam, OTP/notify/LDAP edges) and freezes time at rc.time (the shared
time module), so every timing rule is exercised by advancing one clock.
"""
import json

import pytest

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
                        lambda *a, **k: events.append(("email", a[0])))
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
    """§13/register#13: even WITH a recognized device, an EXPIRED family window
    stays dead — the user must start over and consume a fresh attempt."""
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
