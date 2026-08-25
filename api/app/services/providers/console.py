"""Dev-only OTP provider: codes go to api container logs. NEVER set OTP_PROVIDER=
console outside local/codespace labs (spec §9 warning box)."""
import logging

log = logging.getLogger("otp.console")


def _mask_phone(phone_number: str) -> str:
    """Mask a phone number for safe logging — never log raw PII."""
    if len(phone_number) > 7:
        return phone_number[:3] + "****" + phone_number[-4:]
    return "****"


def send_otp(phone_number: str, code: str, channel: str) -> bool:
    # The code prints IN FULL: the log line is this provider's only delivery
    # channel (T5/T16 gate steps read it from docker compose logs), the code is
    # synthetic/single-purpose/short-TTL, and console mode is spec-forbidden
    # outside labs. Phone masking stays — that is real PII.
    log.warning("OTP for %s via %s: %s",
                _mask_phone(phone_number), channel, code)
    return True


def send_sms(phone_number: str, body: str) -> bool:
    log.warning("SMS to %s: %s", _mask_phone(phone_number), body)
    return True