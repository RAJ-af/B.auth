"""Self-service signup: start -> verify-otp -> complete (spec §8).

Invariant under test: after a verified phone OTP, /signup/complete cannot fail
for identity-reasons — identity checks may only ADD information (soft-fallback),
never block provisioning. 503 marks infrastructure unavailability ONLY: the
OTP-send step (budget/provider) at start, and directory failures (LDAP probe
at start, provisioning at complete). verify-otp never returns 503.
"""
import json
import re
import secrets
import time

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..config import get_settings
from ..services import ldap_admin, otp_service
from ..services.idverify import IdentityOutcome

router = APIRouter(prefix="/signup", tags=["signup"])

# Anchor-free and fullmatch()-checked, byte-identical to ldap_admin's
# _EMAIL_LOCAL: '$' alone would match BEFORE a trailing newline, letting "x\n"
# pass here and die as a raw ValueError 500 at the LDAP boundary.
LOCAL_PART = re.compile(r"[a-z0-9][a-z0-9._-]{0,30}")
PHONE_E164 = re.compile(r"^\+[1-9]\d{7,14}$")


def valid_email(email: str) -> bool:
    local, _, domain = email.partition("@")
    return bool(local and domain == get_settings().mail_domain
                and LOCAL_PART.fullmatch(local))


def valid_phone(phone: str) -> bool:
    return bool(PHONE_E164.match(phone))


def password_ok(password: str) -> bool:
    return len(password) >= get_settings().password_min_length


# --- storage (module-level so tests can swap) --------------------------------

SIGNUP_SESSION_TTL_SECONDS = 900       # spec §8.2


def _create_session(token: str, payload: dict, ttl: int =
                    SIGNUP_SESSION_TTL_SECONDS) -> None:
    from ..db import execute
    execute("""INSERT INTO signup_sessions (token, payload_json, stage, expires_at)
               VALUES (%s, %s, 'awaiting_otp', to_timestamp(%s))""",
            (token, json.dumps(payload), time.time() + ttl))


def _get_session(token: str) -> dict | None:
    from ..db import one
    r = one("""SELECT payload_json, stage, extract(epoch from expires_at)::float AS exp
               FROM signup_sessions WHERE token=%s""", (token,))
    if not r or r["exp"] < time.time():
        return None
    raw = r["payload_json"]
    if isinstance(raw, (str, bytes, bytearray)):
        # Fakes hand back JSON text; the live psycopg3 dict_row driver decodes
        # jsonb to a dict before this seam sees it. Accept both shapes.
        raw = json.loads(raw)
    return {"payload": raw, "stage": r["stage"]}


def _update_session(token: str, payload: dict, stage: str) -> dict:
    from ..db import execute
    execute("UPDATE signup_sessions SET payload_json=%s, stage=%s WHERE token=%s",
            (json.dumps(payload), stage, token))
    return {"payload": payload, "stage": stage}


def _delete_session(token: str) -> None:
    from ..db import execute
    execute("DELETE FROM signup_sessions WHERE token=%s", (token,))


class StartBody(BaseModel):
    email: str
    display_name: str
    phone_e164: str
    account_type: str                 # independent | guardian_managed
    guardian_phone: str | None = None


class VerifyBody(BaseModel):
    token: str
    code: str


class CompleteBody(BaseModel):
    token: str
    choice: dict                      # {"kind":"skip"} | {"kind":"submit_id", ...}
    password: str


def _provision_account_strict(payload: dict, password: str) -> None:
    """Create LDAP entry + accounts row. Raises 409-shaped AddressTaken upward."""
    ldap_admin.create_user(payload["email"], payload["display_name"], password)
    from ..db import execute
    execute("""INSERT INTO accounts (email,display_name,phone_e164,account_type,
                                     guardian_phone,tier,verification,status)
               VALUES (%s,%s,%s,%s,%s,%s,%s,'active')
               ON CONFLICT (email) DO NOTHING""",
            (payload["email"], payload["display_name"], payload["phone_e164"],
             payload["account_type"],
             payload.get("guardian_phone"),
             payload.get("final_tier", "tier1_phone"),
             payload.get("final_verification", "pending_identity")))


@router.post("/start", status_code=202)
def start(body: StartBody):
    if body.account_type not in ("independent", "guardian_managed"):
        raise HTTPException(422, "unknown account_type")
    if body.account_type == "guardian_managed" and not (
            body.guardian_phone and valid_phone(body.guardian_phone)):
        raise HTTPException(422, "guardian_phone required for guardian_managed")
    if not valid_email(body.email):
        raise HTTPException(422, "invalid email (local part lowercase alnum ._- , "
                                 f"domain must be {get_settings().mail_domain})")
    if not valid_phone(body.phone_e164):
        raise HTTPException(422, "phone must be E.164 like +911234567890")
    try:
        if ldap_admin.address_exists(body.email):
            raise HTTPException(409, "Address already registered")
    except ldap_admin.LdapUnavailable as e:
        # Directory outage at the front door: clean 503, no OTP budget burned.
        raise HTTPException(503, f"directory unavailable: {e}")
    token = secrets.token_urlsafe(24)
    try:
        otp_service.send_challenge(body.phone_e164, "signup")
    except otp_service.BudgetExceeded as e:
        # Anti-enumeration posture: same shape as success-era responses; the
        # caller learns only "wait". Spec §15.3 keeps this deliberate.
        raise HTTPException(503, f"otp temporarily unavailable: {e}")
    except otp_service.OtpSendError as e:
        raise HTTPException(503, f"otp temporarily unavailable: {e}")
    _create_session(token, body.model_dump())
    return {"session_token": token, "stage": "awaiting_otp",
            "message": f"code sent to {body.phone_e164}"}


@router.post("/verify-otp")
def verify_otp(body: VerifyBody):
    sess = _get_session(body.token)
    if not sess or sess["stage"] != "awaiting_otp":
        raise HTTPException(400, "unknown or expired session")
    p = sess["payload"]
    try:
        ok = otp_service.verify_challenge(p["phone_e164"], "signup", body.code)
    except otp_service.InvalidCode as e:
        raise HTTPException(401, str(e))
    if not ok:                           # unknown phone/purpose: generic fail
        raise HTTPException(401, "invalid or expired code")
    s = get_settings()
    options = [{"kind": "skip",
                "description": "Continue with Tier 1 (phone verified)"},
               {"kind": "submit_id",
                "description": f"Verify government ID for Tier 2 "
                               f"(mode: {s.idverify_mode})"}]
    _update_session(body.token, p, "awaiting_identity_choice")
    return {"stage": "awaiting_identity_choice", "tier": "tier1_phone",
            "identity_options": options}


@router.post("/complete", status_code=201)
def complete(body: CompleteBody):
    sess = _get_session(body.token)
    if not sess or sess["stage"] != "awaiting_identity_choice":
        raise HTTPException(400, "unknown session or OTP not yet verified")
    p = sess["payload"]
    kind = body.choice.get("kind")
    if kind not in ("skip", "submit_id"):
        raise HTTPException(422, "choice.kind must be skip|submit_id")
    if not password_ok(body.password):
        raise HTTPException(422, f"password must be at least "
                                 f"{get_settings().password_min_length} chars")
    final_tier, final_verification = "tier1_phone", "pending_identity"
    extra: dict = {}
    if kind == "submit_id":
        outcome = _run_identity_step(body.choice, p)     # never raises user-facing 5xx
        if outcome.tier == "tier2_identity":
            final_tier, final_verification = outcome.tier, outcome.verification
        elif outcome.reason_detail:
            extra = {"identity_status": outcome.identity_status,
                     "detail": outcome.reason_detail}
        else:
            extra = {"identity_status": outcome.identity_status}
    try:
        _provision_account_strict(p | {"final_tier": final_tier,
                                       "final_verification": final_verification},
                                  body.password)
    except ldap_admin.AddressTaken:
        raise HTTPException(409, "Address already registered")
    except ldap_admin.LdapUnavailable as e:
        # Honest infrastructure failure, not an identity verdict: the plan's
        # explicit contract is 503 with the session RETAINED so the client can
        # re-complete once the directory recovers. _delete_session below only
        # runs on success, so the session survives this raise.
        raise HTTPException(503, f"directory unavailable: {e}")
    _delete_session(body.token)
    out = {"account": "active", "email": p["email"],
           "tier": final_tier, "verification": final_verification,
           "message": ("Tier 1 active. You can submit an ID later "
                       "from account settings." if kind == "skip"
                       else "Account ready.")} | extra
    return out


def _run_identity_step(choice: dict, payload: dict) -> IdentityOutcome:
    """Task 6 lands off-mode; Task 7 completes AUTO/MANUAL. Never raises
    user-facing 5xx: infra trouble becomes the soft-fallback union member."""
    from ..services.idverify import outcome_for_mode
    return outcome_for_mode(get_settings().idverify_mode, choice,
                            payload.get("email", ""))
