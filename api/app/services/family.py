"""Family-link lifecycle (spec §12): tier-gated requests, approve-button-only
acceptance, approval cooldown before usability, instant revoke, pointer-only
notifications both directions, ≤2 requests per unordered pair per rolling 24h.
"""
import time

from ..config import get_settings
from ..db import execute, many, one
from . import notifications

REQUEST_TTL_SECONDS = 600


class NotEligible(Exception):
    pass


class NoSuchTarget(Exception):
    pass


class RateLimited(Exception):
    pass


class NotAuthorized(Exception):
    pass


# --- storage ------------------------------------------------------------------

def _put_link(l: dict) -> dict:
    rid = one("""INSERT INTO family_links (requester_email, target_email,
                                           status, expires_at)
                 VALUES (%s, %s, 'requested', to_timestamp(%s))
                 RETURNING link_id""",
              (l["requester"], l["target"], l["expires_at_ts"]))
    return l | {"link_id": rid["link_id"]}


def _get_link(link_id: int) -> dict | None:
    return one("""SELECT link_id,requester_email,target_email,status,
                         extract(epoch from created_at)::float AS created_at,
                         extract(epoch from expires_at)::float AS expires_at_ts,
                         extract(epoch from approved_at)::float AS approved_at_ts,
                         extract(epoch from usable_at)::float AS usable_at_ts
                  FROM family_links WHERE link_id=%s""", (link_id,))


# Positional %s only — app.db speaks tuples. Placeholder order IS the tuple
# contract: SET-clause params come first, WHERE-clause params last, so
# "approve" takes (approved_at_ts, usable_at_ts, link_id) and "revoke" takes
# (revoked_by, link_id). Revoke is deliberately UNGUARDED by status (MVP
# ruling): an instant kill from any live state; a double-revoke just
# re-updates the row and re-notifies.
_STATUS_CHANGE = {
    "approve": """UPDATE family_links SET status='approved',
                    approved_at=to_timestamp(%s),
                    usable_at=to_timestamp(%s)
                  WHERE link_id=%s AND status='requested'""",
    "revoke":  """UPDATE family_links SET status='revoked', revoked_at=now(),
                    revoked_by=%s
                  WHERE link_id=%s""",
}


def apply_status_change(name: str, params: tuple) -> None:
    """Seam kept as name+params; params is POSITIONAL because app.db accepts
    %s tuples only. The order contract lives in _STATUS_CHANGE above."""
    execute(_STATUS_CHANGE[name], params)


def _account_tier(email: str) -> str | None:
    r = one("SELECT tier FROM accounts WHERE email=%s", (email,))
    return r and r["tier"]


def _pair_request_count(a: str, b: str, since_ts: float) -> int:
    return len(many("""SELECT 1 FROM family_links
                       WHERE ((requester_email=%s AND target_email=%s)
                           OR (requester_email=%s AND target_email=%s))
                         AND created_at >= to_timestamp(%s)""",
                    (a, b, b, a, since_ts)))


def _approved_rows(email: str) -> list[dict]:
    """Candidate approved links touching either side of the pair; usability
    (cooldown elapsed) is decided against the clock by active_links_for so
    tests can freeze time at the same seam the production filter uses."""
    return many("""SELECT link_id, requester_email, target_email, status,
                          extract(epoch from usable_at)::float AS usable_at_ts
                   FROM family_links
                   WHERE status='approved'
                     AND (requester_email=%s OR target_email=%s)""",
                (email, email))


def active_links_for(email: str) -> list[dict]:
    now = time.time()
    return [r for r in _approved_rows(email) if r["usable_at_ts"] <= now]


def pending_requests_for(email: str) -> list[dict]:
    return many("""SELECT link_id, requester_email, expires_at FROM family_links
                   WHERE target_email=%s AND status='requested'
                     AND expires_at > now()
                   ORDER BY created_at DESC""", (email,))


# --- lifecycle ---------------------------------------------------------------

def request_link(requester_email: str, target_email: str) -> dict:
    if _account_tier(requester_email) != "tier2_identity":
        raise NotEligible("family linking requires Tier 2 identity verification")
    if not _account_tier(target_email):
        raise NoSuchTarget("no such member")
    if requester_email == target_email:
        raise NoSuchTarget("cannot link yourself")
    if _pair_request_count(requester_email, target_email,
                           time.time() - 86400) >= 2:
        raise RateLimited("too many requests between these accounts today")
    now = time.time()
    link = {"requester": requester_email, "target": target_email,
            "status": "requested", "created_at": now,
            "expires_at_ts": now + REQUEST_TTL_SECONDS}
    stored = _put_link(link)
    notifications.notify(target_email, "family_request_received",
                         f"{requester_email} asked to link accounts with you. "
                         "Open your app to approve or ignore.")
    notifications.notify(requester_email, "family_request_sent",
                         f"Request sent to {target_email}. They have "
                         f"{REQUEST_TTL_SECONDS // 60} minutes to respond.")
    notifications.fan_out_email(
        target_email, "Sovereign Mail: family link request",
        f"{requester_email} requested to link with your account. Open your "
        "Sovereign Mail app to review. This mailbox does not accept actions "
        "by reply.")
    return stored


def approve(link_id: int, actor_email: str) -> None:
    link = _require_actor(link_id, actor_email, side="target")
    now = time.time()
    if link["status"] != "requested" or now > link["expires_at_ts"]:
        raise NoSuchTarget("request no longer active")
    cooldown = get_settings().family_link_cooldown_hours * 3600
    apply_status_change("approve", (now, now + cooldown, link["link_id"]))
    for who in (link["requester_email"], link["target_email"]):
        notifications.notify(who, "family_link_approved",
                             "Family link approved. Recovery assistance becomes "
                             "available after the safety cooldown.")


def revoke(link_id: int, actor_email: str) -> None:
    link = _require_actor(link_id, actor_email, side="either")
    apply_status_change("revoke", (actor_email, link["link_id"]))
    for who in (link["requester_email"], link["target_email"]):
        notifications.notify(who, "family_link_revoked",
                             "A family link was revoked. It can no longer assist "
                             "recovery.")


def _require_actor(link_id: int, actor_email: str, *, side: str) -> dict:
    link = _get_link(link_id)
    if not link:
        raise NoSuchTarget("no such link")
    allowed = ({link["target_email"]} if side == "target"
               else {link["requester_email"], link["target_email"]})
    if actor_email not in allowed:
        raise NotAuthorized("not your link")
    return link
