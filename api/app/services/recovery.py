"""Account recovery (spec §13): OTP always; device dwell / family approval /
admin grant as the OR-leg. Outward-facing views are CONSTANT by design — see
public_view(). Every timing rule here exists because a stolen second factor
must still hit a human-speed wall.

Storage contract (app.db speaks POSITIONAL %s tuples only): timestamps cross
the boundary as epoch floats bound through to_timestamp(%s); to_timestamp(NULL)
yields NULL, so one INSERT shape covers first-write and every transition.
"""
import secrets
import time

from ..config import get_settings
from ..db import execute, many, one
from . import devices, family, ldap_admin, notifications, otp_service

PENDING_BRANCHES = ("pending_family", "pending_dwell", "pending_admin")


class WrongCode(Exception):
    pass


# --- storage ------------------------------------------------------------------

def _new_id() -> str:
    return "rq-" + secrets.token_urlsafe(12)


def _account_exists(email: str) -> bool:
    return one("SELECT 1 FROM accounts WHERE email=%s", (email,)) is not None


def _save(r: dict) -> dict:
    """Insert-or-update by req_id. The param tuple is built EXPLICITLY from the
    record's canonical keys (never splatted) so column order is auditable:
    authorized_at/expires_at are epoch floats (or None) behind to_timestamp(%s).
    """
    execute("""INSERT INTO recovery_requests
               (req_id,email,status,recognizing_device_hash,recognized_device,
                authorized_at,decided_by_member,cancel_reason,expires_at)
               VALUES (%s,%s,%s,%s,%s,to_timestamp(%s),%s,%s,to_timestamp(%s))
               ON CONFLICT (req_id) DO UPDATE SET
                 status=EXCLUDED.status,
                 recognizing_device_hash=EXCLUDED.recognizing_device_hash,
                 recognized_device=EXCLUDED.recognized_device,
                 authorized_at=EXCLUDED.authorized_at,
                 decided_by_member=EXCLUDED.decided_by_member,
                 cancel_reason=EXCLUDED.cancel_reason,
                 expires_at=EXCLUDED.expires_at""",
            (r["req_id"], r["email"], r["status"], r.get("recog"),
             r.get("recognized"), r.get("authorized_at_ts"),
             r.get("decided_by"), r.get("cancel_reason"),
             r.get("expires_at")))
    return r


def _get(req_id: str) -> dict | None:
    """Row shape that round-trips into _save: recog/decided_by/authorized_at_ts
    are the record-side names for recognizing_device_hash/decided_by_member/
    authorized_at; epochs come back as floats."""
    return one("""SELECT req_id,email,status,
                         recognizing_device_hash AS recog,
                         recognized_device AS recognized,
                         extract(epoch from authorized_at)::float AS authorized_at_ts,
                         decided_by_member AS decided_by,
                         cancel_reason,
                         extract(epoch from created_at)::float AS created_at,
                         extract(epoch from expires_at)::float AS expires_at
                  FROM recovery_requests WHERE req_id=%s""", (req_id,))


def _active_for(email: str) -> dict | None:
    # 'authorized' stays live until completed: family-approved/admin-granted
    # requests must remain completable (§13.6) and cancellable anytime (§13.8).
    row = one("""SELECT req_id FROM recovery_requests WHERE email=%s
                 AND status IN ('awaiting_phone','pending_family',
                                'pending_dwell','pending_admin','authorized')
                 ORDER BY created_at DESC LIMIT 1""", (email,))
    return _get(row["req_id"]) if row else None


def _starts_in_last_hour(email: str, since_ts: float) -> int:
    return len(many("""SELECT 1 FROM recovery_requests WHERE email=%s
                       AND created_at > to_timestamp(%s)""",
                    (email, since_ts)))


def _active_by_device(device_hash: str) -> dict | None:
    """R3 seam: newest live request leaning on this device. Kept separate so
    unit tests can patch lookup and lifecycle independently."""
    return one("""SELECT req_id FROM recovery_requests
                  WHERE recognizing_device_hash=%s
                    AND status IN ('awaiting_phone','pending_family',
                                   'pending_dwell')
                  ORDER BY created_at DESC LIMIT 1""", (device_hash,))


def _phone_for(email: str) -> str:
    r = one("SELECT phone_e164 FROM accounts WHERE email=%s", (email,))
    return r["phone_e164"] if r else ""


# --- public envelope ----------------------------------------------------------

def public_view(internal_result: dict) -> dict:
    """THE anti-enumeration constant. Nothing about existence, budget, or
    branch may vary this body."""
    return {"received": True}


def list_pending_admin() -> list[dict]:
    """Assisted-recovery queue for operators (README §9/§10; spec §13
    pending_admin). Projection whitelist ONLY — the raw address never crosses
    this boundary, mirroring the reviews endpoint's masking idiom (§10.2)."""
    rows = many("""SELECT req_id, email, status,
                          extract(epoch from created_at)::float AS created_at
                   FROM recovery_requests WHERE status='pending_admin'
                   ORDER BY created_at DESC""")
    return [{"req_id": r["req_id"],
             "email_masked": notifications.mask_email(r["email"]),
             "status": r["status"], "created_at": r["created_at"]}
            for r in rows]


# --- lifecycle ------------------------------------------------------------------

def _cancel(r: dict, reason: str) -> dict:
    r |= {"status": "cancelled", "cancel_reason": reason}
    return _save(r)


def start_recovery(email: str, device_raw: str | None) -> dict:
    s = get_settings()
    now = time.time()
    known = _account_exists(email)
    within_budget = (_starts_in_last_hour(email, now - 3600)
                     < s.recovery_max_attempts_per_hour) if known else False
    if known and within_budget:
        try:
            # OTP BEFORE any write: a provider/budget failure persists nothing
            # and leaves any earlier active request untouched.
            otp_service.send_challenge(_phone_for(email), "recovery")
        except (otp_service.BudgetExceeded, otp_service.OtpSendError):
            return {"received": True}            # silent drop, nothing persisted
        prev = _active_for(email)
        if prev:
            _cancel(prev, "superseded")
        dev = devices.resolve(device_raw) if device_raw else None
        rec = _save({
            "req_id": _new_id(), "email": email, "status": "awaiting_phone",
            "recog": dev["device_hash"] if dev else None,
            "recognized": bool(dev), "authorized_at_ts": None,
            "decided_by": None, "cancel_reason": None,
            "created_at": now, "expires_at": now})
        notifications.notify(email, "recovery_started",
                             "A recovery was started for your account. If this "
                             "wasn't you, open the app and cancel it.")
        notifications.fan_out_email(
            email, "Sovereign Mail: recovery started",
            "A password recovery was started for your account. Open your "
            "Sovereign Mail app to review or cancel. This mailbox does not "
            "accept actions by reply.")
        return rec                               # internal record; router flattens
    return {"received": True}                    # unknown OR over-budget: same view


def verify_otp(email: str, code: str) -> str:
    r = _active_for(email)
    if not r or r["status"] != "awaiting_phone":
        raise WrongCode("no active recovery")
    try:
        ok = otp_service.verify_challenge(_phone_for(email), "recovery", code)
    except otp_service.InvalidCode as e:
        raise WrongCode(str(e)) from e           # one exception shape outward
    if not ok:                                   # no live challenge row
        raise WrongCode("codes do not match")
    # Branch pick happens NOW (§13.4), never at start.
    s = get_settings()
    now = time.time()
    linked = family.active_links_for(email)
    if linked:
        r |= {"status": "pending_family",
              "expires_at": now + s.recovery_request_ttl_seconds}
    elif r["recognized"]:
        r |= {"status": "pending_dwell", "authorized_at_ts": now}
    else:
        r |= {"status": "pending_admin"}
    _save(r)
    return r["status"]


def _is_linked_member(member: str, requester: str) -> bool:
    """R7 standing: the caller must be a party to one of the requester's
    USABLE links — active_links_for already applies the cooldown filter, so
    cooling-down links cannot approve."""
    return any(member in (l.get("requester_email"), l.get("target_email"))
               for l in family.active_links_for(requester))


def family_approve(member_email: str, requester_email: str) -> bool:
    """False means 'nothing changed' — standing is checked BEFORE any state
    touch and the router answers both outcomes with one constant body (R7,
    wire silence mirroring R5)."""
    member = member_email.lower()
    requester = requester_email.lower()
    # member == requester is refused outright: a requester sitting on ANY link
    # would otherwise trivially self-approve their own window, defeating the
    # two-party control the family branch exists to provide.
    if member == requester or not _is_linked_member(member, requester):
        return False
    r = _active_for(requester)
    if not r or r["status"] != "pending_family":
        return False
    if time.time() > r["expires_at"]:
        r |= {"status": "expired"}               # lazy flip on touch
        _save(r)
        return False
    r |= {"status": "authorized", "decided_by": member,
          "authorized_at_ts": time.time()}
    _save(r)
    return True


def _refresh_state(r: dict) -> dict:
    if r["status"] == "pending_family" and time.time() > r["expires_at"]:
        r |= {"status": "expired"}               # lazy flip; NO dwell fallback
        _save(r)
    return r


def maybe_complete(email: str, new_password: str,
                   device_raw: str | None) -> tuple[str, int]:
    """Returns (router-detail-string, http_code). Terminal-dead states are
    invalid_request(400); every not-yet reason is the same not_ready(403)."""
    r = _active_for(email)
    if not r:
        return "invalid_request", 400
    r = _refresh_state(r)
    st = r["status"]
    if st in ("cancelled", "expired", "denied"):
        return "invalid_request", 400
    satisfied = False
    if st == "authorized":                       # family-approved / admin-granted
        satisfied = True
    elif st == "pending_dwell":
        if device_raw is None or r["recog"] != (
                devices.resolve(device_raw) or {}).get("device_hash"):
            return "not_ready", 403              # same device must finish the wait
        if time.time() < (r["authorized_at_ts"] or 0) + \
                get_settings().recovery_min_dwell_seconds:
            return "not_ready", 403              # human-speed wall (§13.6)
        satisfied = True
    else:                                        # awaiting_phone/pending_*/…
        return "not_ready", 403
    ldap_admin.set_password(email, new_password)  # LDAP only; accounts row untouched
    r |= {"status": "completed"}
    _save(r)
    acct_phone = _phone_for(email)
    notifications.notify(email, "password_reset_completed",
                         "Your password was reset. If this wasn't you, contact "
                         "your administrator immediately.")
    notifications.send_sms_alert(acct_phone,
                                 "Sovereign Mail: your password was just "
                                 "reset. If this wasn't you, act now.")
    return "completed", 201


def _has_standing(actor_email: str, email: str) -> bool:
    """Owner themself, or a party to an active family link with the owner."""
    actor = actor_email.lower()
    if actor == email:
        return True
    return any(actor in (l.get("requester_email"), l.get("target_email"))
               for l in family.active_links_for(email))


def cancel(email: str, actor_email: str) -> bool:
    """False means 'nothing changed' — the ROUTER still answers with the
    constant OK_BODY, so standing is invisible on the wire (§15.3/R5)."""
    email = email.lower()
    if not _has_standing(actor_email, email):
        return False
    r = _active_for(email)
    if not r:
        return False
    _cancel(r, f"cancelled_by:{actor_email.lower()}")
    return True


def void_requests_for_device(device_hash: str) -> None:
    row = _active_by_device(device_hash)
    if row:
        r = _get(row["req_id"])
        _cancel(r, "device_removed")


devices.VOID_HOOKS.append(void_requests_for_device)


def admin_grant(req_id: str, reviewer: str) -> bool:
    r = _get(req_id)
    if not r or r["status"] != "pending_admin":
        return False
    r |= {"status": "authorized", "decided_by": f"admin:{reviewer}",
          "authorized_at_ts": time.time()}
    _save(r)
    return True
