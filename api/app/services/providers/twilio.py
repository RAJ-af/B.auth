"""Twilio REST provider. Credentials come from Settings/env; a failed HTTP call
returns False so callers keep their budgets intact (spec §9).

Credentials are passed via httpx's auth tuple (→ BasicAuth), never a manually
built Authorization header: httpx's auth_flow runs AFTER header preparation and
overwrites any manual value, so a hand-rolled header would be silently replaced
by the auth kwarg's credentials on every request.
"""
import logging

import httpx

from ...config import get_settings

log = logging.getLogger("otp.twilio")


def send_sms(phone_number: str, body: str) -> bool:
    s = get_settings()
    url = f"https://api.twilio.com/2010-04-01/Accounts/{s.twilio_account_sid}/Messages.json"
    try:
        r = httpx.post(url,
                       auth=(s.twilio_account_sid, s.twilio_auth_token),
                       data={"To": phone_number, "From": s.twilio_from_number,
                             "Body": body}, timeout=15.0)
        return r.status_code < 300
    except Exception as e:                      # noqa: BLE001
        log.warning("twilio sms failed: %s", e)
        return False


def send_otp(phone_number: str, code: str, channel: str) -> bool:
    text = (f"Sovereign Mail verification code: {code}"
            if channel == "sms" else
            f"Your Sovereign Mail code is {code}. Repeat digit by digit.")
    return send_sms(phone_number, text)