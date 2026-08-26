"""Notification fan-out (spec §12): in-app rows are the source of truth;
EMAIL COPIES ARE POINTER-ONLY -- they name the event and say 'open the app',
never carrying action URLs. SMS carries recovery alerts ONLY (§9 channel rule).
"""
import logging

from ..config import get_settings
from ..db import execute, many, one
from .providers.console import send_sms as _console_sms

log = logging.getLogger(__name__)


def mask_email(address: str) -> str:
    """Canonical masked address form (spec §12 body shape 'R***@sovereign.mail'):
    keep the local part's first character only; the domain is this system's own
    and carries no per-user information. Used by every notification body and
    admin listing that must name an account without disclosing it."""
    local, _, domain = address.partition("@")
    if not domain:
        return "***"
    return f"{local[:1]}***@{domain}"


def _insert(row: dict) -> dict:
    """Insert and return the COMPLETE stored row. INSERT..RETURNING supplies
    the server-generated notif_id/created_at (family-link flows need real ids);
    row already carries read_at=None from notify()."""
    ids = one("""INSERT INTO notifications (email, type, body)
                 VALUES (%s,%s,%s)
                 RETURNING notif_id, created_at""",
              (row["email"], row["type"], row["body"]))
    return {**row, "notif_id": ids["notif_id"],
            "created_at": ids["created_at"]}


def _fetch(email: str, limit: int) -> list[dict]:
    return many("""SELECT notif_id, type, body, link_ref, created_at, read_at
                   FROM notifications WHERE email=%s
                   ORDER BY created_at DESC LIMIT %s""", (email, limit))


def notify(email: str, type_: str, body: str) -> dict:
    return _insert({"email": email, "type": type_, "body": body,
                    "read_at": None})


def list_for(email: str, limit: int = 50) -> list[dict]:
    return _fetch(email, limit)


def mark_read(email: str, notif_id: int) -> None:
    execute("UPDATE notifications SET read_at=now() WHERE notif_id=%s AND email=%s",
            (notif_id, email))


def _build_mime(**kw):
    from ..smtp_client import build_mime
    return build_mime(kw["from_"], kw["to"], kw.get("cc") or [],
                      [], kw["subject"], kw["text"], None)


def _submit_mime(msg, rcpts):
    from ..smtp_client import submit_message
    submit_message(msg, rcpts)


def fan_out_email(to_email: str, subject: str, body_text: str) -> None:
    """Best-effort by design: the in-app notification ALREADY exists before we
    get here, and §12 forbids an email failure from surfacing as user error.
    Nothing inside this function is allowed to escape -- settings lookup
    included."""
    try:
        s = get_settings()
        msg = _build_mime(from_=f"noreply@{s.mail_domain}", to=[to_email],
                          subject=subject, text=body_text)
        _submit_mime(msg, [to_email])
    except Exception as e:                      # noqa: BLE001 — pointer copies never fail loudly
        log.warning("notification email to %s failed: %s", to_email, e)


def send_sms_alert(phone: str, body: str) -> bool:
    s = get_settings()
    if s.otp_provider == "twilio":
        from .providers import twilio
        return twilio.send_sms(phone, body)
    return _console_sms(phone, body)
