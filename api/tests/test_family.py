"""Family-link lifecycle (spec §12): tier gate, pair rate-limit, approval
cooldown, instant revoke, pointer-only notices both directions, plus the
/family router contract (JWT-scoped, lowercase target normalization).

The fixture swaps the storage seams at module level (_put_link/_get_link/
apply_status_change/_account_tier/_pair_request_count/_approved_rows); the fake
apply_status_change mirrors the PRODUCTION call shape -- name plus a positional
tuple matching _STATUS_CHANGE placeholder order:
  approve -> (approved_at_ts, usable_at_ts, link_id)
  revoke  -> (revoked_by, link_id)
"""
import pytest
from fastapi import Request
from fastapi.testclient import TestClient

from app.services import family as fm


@pytest.fixture
def world(monkeypatch):
    links: dict[int, dict] = {}
    seq = {"n": 0}
    notes: list[tuple] = []
    emails = {"a@sovereign.mail": {"tier": "tier2_identity",
                                   "account_type": "independent"},
              "b@sovereign.mail": {"tier": "tier1_phone",
                                   "account_type": "independent"},
              "t2@sovereign.mail": {"tier": "tier2_identity",
                                    "account_type": "independent"},
              "t1@sovereign.mail": {"tier": "tier1_phone",
                                    "account_type": "independent"},
              "managed@sovereign.mail": {"tier": "tier2_identity",
                                         "account_type": "guardian_managed"}}

    def fake_put(l):
        seq["n"] += 1
        l = l | {"link_id": seq["n"]}
        links[seq["n"]] = l
        return l
    monkeypatch.setattr(fm, "_put_link", fake_put)

    def fake_get(lid):
        # reshape to the production row shape (_get_link aliases columns to
        # requester_email/target_email); None when absent
        l = links.get(lid)
        if not l:
            return None
        return {"link_id": l["link_id"],
                "requester_email": l["requester"],
                "target_email": l["target"],
                "status": l["status"],
                "created_at": l["created_at"],
                "expires_at_ts": l["expires_at_ts"],
                "approved_at_ts": l.get("approved_at_ts"),
                "usable_at_ts": l.get("usable_at_ts")}
    monkeypatch.setattr(fm, "_get_link", fake_get)

    def fake_apply(name, params):
        assert isinstance(params, tuple), "production must pass positional tuples"
        if name == "approve":
            approved_at_ts, usable_at_ts, lid = params
            links[lid].update({"status": "approved",
                               "approved_at_ts": approved_at_ts,
                               "usable_at_ts": usable_at_ts})
        else:
            revoked_by, lid = params
            links[lid].update({"status": "revoked", "revoked_by": revoked_by})
    monkeypatch.setattr(fm, "apply_status_change", fake_apply)

    monkeypatch.setattr(fm, "_account_tier",
                        lambda e: emails.get(e, {}).get("tier"))
    monkeypatch.setattr(fm, "_account_type",
                        lambda e: emails.get(e, {}).get("account_type"))
    monkeypatch.setattr(fm, "_pair_request_count", lambda a, b, since: sum(
        1 for l in links.values() if {l["requester"], l["target"]} ==
        {a, b} and l["created_at"] >= since))
    monkeypatch.setattr(fm, "_approved_rows", lambda e: [
        fake_get(l["link_id"]) for l in links.values()
        if l["status"] == "approved" and e in (l["requester"], l["target"])])
    monkeypatch.setattr(fm.notifications, "notify",
                        lambda e, t, b: notes.append((e, t, b)) or {})
    monkeypatch.setattr(fm.notifications, "fan_out_email",
                        lambda *a, **k: notes.append(("email",) + a))
    now = 1_800_000_000.0
    monkeypatch.setattr(fm.time, "time", lambda: now)
    return {"links": links, "notes": notes, "emails": emails, "now": now}


def test_request_creates_pending_with_expiry(world):
    l = fm.request_link("a@sovereign.mail", "t1@sovereign.mail")
    assert l["status"] == "requested"
    assert l["expires_at_ts"] - world["now"] == 600            # 10-minute window
    kinds = [(e, t) for e, t, *_ in world["notes"]]
    assert ("t1@sovereign.mail", "family_request_received") in kinds
    assert ("a@sovereign.mail", "family_request_sent") in kinds


def test_request_notice_bodies_are_pointer_only(world):
    fm.request_link("a@sovereign.mail", "t1@sovereign.mail")
    for note in world["notes"]:
        body = note[-1]
        assert "http" not in body.lower()          # no action URLs, ever


def test_tier2_gate_on_requester(world):
    with pytest.raises(fm.NotEligible):
        fm.request_link("b@sovereign.mail", "a@sovereign.mail")


def test_unknown_target_is_no_such_target(world):
    with pytest.raises(fm.NoSuchTarget):
        fm.request_link("a@sovereign.mail", "ghost@sovereign.mail")
    assert world["notes"] == []          # nothing notified for a dead target


def test_self_link_rejected(world):
    with pytest.raises(fm.NoSuchTarget):
        fm.request_link("a@sovereign.mail", "a@sovereign.mail")


def test_pair_rate_limit_two_per_day(world):
    # Both sides Tier 2 so the reverse-direction probe reaches the pair budget
    # (a Tier 1 requester would be stopped by the 422 tier gate first).
    fm.request_link("a@sovereign.mail", "t2@sovereign.mail")
    fm.request_link("a@sovereign.mail", "t2@sovereign.mail")   # supersedes previous? NO — counted
    with pytest.raises(fm.RateLimited):
        fm.request_link("a@sovereign.mail", "t2@sovereign.mail")
    # reverse direction counts toward the SAME pair budget:
    with pytest.raises(fm.RateLimited):
        fm.request_link("t2@sovereign.mail", "a@sovereign.mail")


def test_approve_sets_cooldown_usable_at(world):
    l = fm.request_link("a@sovereign.mail", "t1@sovereign.mail")
    fm.approve(l["link_id"], "t1@sovereign.mail")
    got = world["links"][l["link_id"]]
    assert got["status"] == "approved"
    assert got["usable_at_ts"] - got["approved_at_ts"] == 48 * 3600


def test_approve_notifies_both_parties(world):
    l = fm.request_link("a@sovereign.mail", "t1@sovereign.mail")
    fm.approve(l["link_id"], "t1@sovereign.mail")
    kinds = [n[1] for n in world["notes"]]     # email copies are wider tuples
    assert kinds.count("family_link_approved") == 2


def test_approve_by_wrong_party_is_403_shaped(world):
    l = fm.request_link("a@sovereign.mail", "t1@sovereign.mail")
    with pytest.raises(fm.NotAuthorized):
        fm.approve(l["link_id"], "t2@sovereign.mail")


def test_approve_of_expired_request_is_inactive(world, monkeypatch):
    l = fm.request_link("a@sovereign.mail", "t1@sovereign.mail")
    monkeypatch.setattr(fm.time, "time",
                        lambda: world["now"] + fm.REQUEST_TTL_SECONDS + 1)
    with pytest.raises(fm.NoSuchTarget):
        fm.approve(l["link_id"], "t1@sovereign.mail")


def test_revoke_is_instant_and_notifies_both(world):
    l = fm.request_link("a@sovereign.mail", "t1@sovereign.mail")
    fm.approve(l["link_id"], "t1@sovereign.mail")
    fm.revoke(l["link_id"], "a@sovereign.mail")
    assert world["links"][l["link_id"]]["status"] == "revoked"
    kinds = [n[1] for n in world["notes"]]     # email copies are wider tuples
    assert "family_link_revoked" in kinds
    assert kinds.count("family_link_revoked") == 2


# --- N1: transition fan-out reaches BOTH neighborhoods (spec §12) ------------

def _seed_cooled_link(world, requester, target):
    """Insert an already-approved-and-cooled link directly (usable now), so its
    parties count as live members of an account's link neighborhood. Keyed at
    1000+ so it can never collide with fake_put's sequence ids."""
    lid = 1000 + len(world["links"])
    world["links"][lid] = {
        "link_id": lid,
        "requester": requester, "target": target,
        "status": "approved", "created_at": world["now"],
        "expires_at_ts": world["now"] + 600,
        "approved_at_ts": world["now"], "usable_at_ts": world["now"]}
    return lid


def test_approve_fans_out_to_both_neighborhoods(world):
    """§12: EVERY transition notifies all linked members of BOTH accounts'
    neighborhoods — in-app row plus one pointer-only email each."""
    # a's neighborhood holds t2; t1's holds c (both usable NOW):
    _seed_cooled_link(world, "t2@sovereign.mail", "a@sovereign.mail")
    _seed_cooled_link(world, "t1@sovereign.mail", "c@sovereign.mail")
    l = fm.request_link("a@sovereign.mail", "t1@sovereign.mail")
    fm.approve(l["link_id"], "t1@sovereign.mail")

    mails = [n for n in world["notes"] if n[0] == "email"
             and "family link approved" in n[2]]
    recipients = sorted(n[1] for n in mails)
    # pair + both neighborhoods, deduped:
    assert recipients == ["a@sovereign.mail", "c@sovereign.mail",
                          "t1@sovereign.mail", "t2@sovereign.mail"]
    for who in recipients:
        inapp = [n for n in world["notes"]
                 if n[0] == who and n[1] == "family_link_approved"]
        mine = [n for n in mails if n[1] == who]
        assert len(inapp) == 1 and len(mine) == 1    # exactly once per member
        assert "http" not in mine[0][3].lower()      # pointer-only


def test_revoke_fans_out_to_neighborhood_members_too(world):
    _seed_cooled_link(world, "t2@sovereign.mail", "a@sovereign.mail")
    l = fm.request_link("a@sovereign.mail", "t1@sovereign.mail")
    fm.approve(l["link_id"], "t1@sovereign.mail")
    world["notes"].clear()
    fm.revoke(l["link_id"], "a@sovereign.mail")
    revoked = [n for n in world["notes"] if n[0] == "email"
               and "family link revoked" in n[2]]
    assert sorted(n[1] for n in revoked) == [
        "a@sovereign.mail", "t1@sovereign.mail", "t2@sovereign.mail"]
    assert all("http" not in n[3].lower() for n in revoked)
    # in-app rows mirror the email fan-out exactly:
    inapp = [n for n in world["notes"] if n[0] != "email"
             and n[1] == "family_link_revoked"]
    assert sorted(n[0] for n in inapp) == [
        "a@sovereign.mail", "t1@sovereign.mail", "t2@sovereign.mail"]


def test_managed_account_cannot_create_family_link(world):
    """§8.2 enforcement point 2: a guardian_managed caller is refused at
    CREATE with the same NotEligible shape the router maps to 422."""
    with pytest.raises(fm.NotEligible, match="managed"):
        fm.request_link("managed@sovereign.mail", "a@sovereign.mail")
    assert world["notes"] == []          # nothing notified, nothing stored
    assert world["links"] == {}


def test_active_links_respects_cooldown_window(world, monkeypatch):
    l = fm.request_link("a@sovereign.mail", "t1@sovereign.mail")
    fm.approve(l["link_id"], "t1@sovereign.mail")
    assert fm.active_links_for("a@sovereign.mail") == []       # still cooling down
    future = world["now"] + 48 * 3600 + 1
    monkeypatch.setattr(fm.time, "time", lambda: future)       # jump past cooldown
    active = fm.active_links_for("a@sovereign.mail")
    assert len(active) == 1 and active[0]["link_id"] == l["link_id"]


# --- /family router ----------------------------------------------------------

JWT_EMAIL = "me@sovereign.mail"


def _jwt_client(monkeypatch):
    from app.auth import get_current_user
    from app.main import create_app

    app = create_app()

    def fake_user(request: Request):     # mirrors the real dependency contract,
        request.state.raw_token = "faketoken"   # including the raw-token stash
        return {"sub": "s", "email": JWT_EMAIL}
    app.dependency_overrides[get_current_user] = fake_user
    return TestClient(app)


def test_family_routes_require_jwt():
    from app.main import create_app
    client = TestClient(create_app())
    r = client.post("/family/requests", json={"target_email": "t1@sovereign.mail"})
    assert r.status_code == 401


def test_create_request_returns_202_contract(monkeypatch):
    seen = {}

    def fake_request(requester, target):
        seen["call"] = (requester, target)
        return {"link_id": 9, "status": "requested",
                "expires_at_ts": 1_800_000_600.0}
    monkeypatch.setattr(fm, "request_link", fake_request)
    client = _jwt_client(monkeypatch)
    r = client.post("/family/requests",
                    json={"target_email": "T1@Sovereign.Mail"},
                    headers={"Authorization": "Bearer faketoken"})
    assert r.status_code == 202
    body = r.json()
    assert body["link_id"] == 9
    assert body["expires_within_seconds"] == 600
    assert body["expires_at"] == 1_800_000_600.0
    # actor from the JWT, target normalized server-side
    assert seen["call"] == (JWT_EMAIL, "t1@sovereign.mail")
