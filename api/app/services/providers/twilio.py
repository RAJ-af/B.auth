"""Twilio REST provider. Credentials come from Settings/env; a failed HTTP call
returns False so callers keep their budgets intact (spec §9)."""
import base64
import logging

import httpx

from ...config import get_settings

log = logging.getLogger("otp.twilio")


def send_sms(phone_number: str, body: str) -> bool:
    s = get_settings()
    url = f"https://api.twilio.com/2010-04-01/Accounts/{s.twilio_account_sid}/Messages.json"
    auth = base64.b64encode(
        f"{s.twilio_account_sid}:{s.twilio_auth_token}".encode()).decode()
    try:
        r = httpx.post(url, auth=("sid-placeholder-not-used", ""),
                       headers={"Authorization": f"Basic {auth}"},
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