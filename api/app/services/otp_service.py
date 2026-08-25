"""Phone-OTP challenges: budgets, lifecycle, verification (spec §9).

Design rule under test: the provider call happens BEFORE any state is recorded;
a provider failure raises OtpSendError and consumes NOTHING.
"""
import hashlib
import logging
import secrets
import time

from ..config import get_settings
from ..db import execute, many, one
from ..ssha_util import verify_ssha
from .providers import console, twilio

log = logging.getLogger(__name__)


class BudgetExceeded(Exception):
    pass


class OtpSendError(Exception):
    pass


class InvalidCode(Exception):
    pass


def _get_provider():
    name = get_settings().otp_provider
    return {"console": console, "twilio": twilio}[name]


# --- SQL wrappers (tests swap these) ---------------------------------------

def _insert_challenge(row: dict) -> dict:
    # Uses positional (%s) parameters to match the db module's tuple-based interface.
    execute(
        """INSERT INTO otp_challenges
           (purpose, phone_e164, code_sha256, channel, expires_at, attempts_left)
           VALUES (%s,%s,%s,%s,to_timestamp(%s),%s)""",
        (row["purpose"], row["phone"], row["code_sha256"], row["channel"],
         row["expires_at"], row["attempts_left"]))
    return row


def _latest_active(phone: str, purpose: str, now: float) -> dict | None:
    return one("""SELECT id, code_sha256, attempts_left,
                         extract(epoch from expires_at)::float AS expires_at_ts,
                         consumed_at IS NOT NULL AS consumed
                  FROM otp_challenges WHERE phone_e164=%s AND purpose=%s
                    AND created_at > to_timestamp(%s) - interval '1 hour'
                  ORDER BY created_at DESC LIMIT 1""",
              (phone, purpose, now))


def _last_send_ts(phone: str, purpose: str) -> float | None:
    r = one("""SELECT extract(epoch from created_at)::float AS ts
               FROM otp_challenges WHERE phone_e164=%s AND purpose=%s
               ORDER BY created_at DESC LIMIT 1""",
            (phone, purpose))
    return r["ts"] if r else None


def _count_since(phone: str, since_ts: float) -> int:
    return many("""SELECT 1 FROM otp_challenges
                   WHERE phone_e164=%s AND created_at >= to_timestamp(%s)""",
                (phone, since_ts)).__len__()


# --- logic -------------------------------------------------------------------

def within_budget(last_send_ts: float | None, sends_last_hour: int,
                  sends_today: int, *, now: float, cooldown_s: int,
                  hourly: int, daily: int) -> None:
    if last_send_ts is not None and now - last_send_ts < cooldown_s:
        raise BudgetExceeded(f"resend cooldown ({cooldown_s}s)")
    if sends_last_hour >= hourly:
        raise BudgetExceeded(f"hourly cap ({hourly})")
    if sends_today >= daily:
        raise BudgetExceeded(f"daily cap ({daily})")


def check_code(stored_hash: str | None, attempts_left: int | None,
               expires_at_ts: float | None, consumed: bool, code: str,
               *, now: float) -> bool:
    if stored_hash is None:
        return False                     # unknown phone/purpose: generic fail
    if consumed:
        raise InvalidCode("code consumed")
    if expires_at_ts is not None and now > expires_at_ts:
        raise InvalidCode("code expired")
    if attempts_left is not None and attempts_left <= 0:
        raise InvalidCode("no attempts left")
    # Constant-time compare over the SHA-256 hex of the presented code.
    presented = hashlib.sha256(code.encode()).hexdigest()
    if not secrets.compare_digest(presented, stored_hash):
        raise InvalidCode("codes do not match")
    return True


def send_challenge(phone: str, purpose: str, channel: str = "sms") -> None:
    s = get_settings()
    now = time.time()
    within_budget(_last_send_ts(phone, purpose),
                  _count_since(phone, now - 3600),
                  _count_since(phone, now - 86400),
                  now=now, cooldown_s=s.otp_resend_cooldown_seconds,
                  hourly=s.otp_max_sends_per_hour, daily=s.otp_daily_cap)
    code = f"{secrets.randbelow(10 ** 6):06d}"
    if not _get_provider().send_otp(phone, code, channel):
        raise OtpSendError("provider rejected the send")
    _insert_challenge({
        "purpose": purpose, "phone": phone,
        "code_sha256": hashlib.sha256(code.encode()).hexdigest(),
        "channel": channel, "expires_at": now + s.otp_code_ttl_seconds,
        "attempts_left": s.otp_max_verify_attempts,
        "created_at": now})


def verify_challenge(phone: str, purpose: str, code: str) -> bool:
    now = time.time()
    ch = _latest_active(phone, purpose, now)
    try:
        check_code(ch and ch["code_sha256"], ch and ch["attempts_left"],
                   ch and ch["expires_at_ts"], bool(ch and ch["consumed"]),
                   code, now=now)
    except InvalidCode as e:
        if ch and "expired" not in str(e) and "consumed" not in str(e):
            execute("UPDATE otp_challenges SET attempts_left=attempts_left-1 "
                    "WHERE id=%s", (ch["id"],))
        raise
    execute("UPDATE otp_challenges SET consumed_at=now() WHERE id=%s",
            (ch["id"],))
    return True