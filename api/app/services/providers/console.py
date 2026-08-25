"""Dev-only OTP provider: codes go to api container logs. NEVER set OTP_PROVIDER=
console outside local/codespace labs (spec §9 warning box)."""
import logging

log = logging.getLogger("otp.console")


def _mask_phone(phone_number: str) -> str:
    """Mask a phone number for safe logging — never log raw PII."""
    if len(phone_number) > 7:
        return phone_number[:3] + "****" + phone_number[-4:]
    return "****"


def _mask_code(code: str) -> str:
    """Show only the first three digits of a code in logs."""
    return code[:3] + "***" if len(code) > 3 else "***"


def send_otp(phone_number: str, code: str, channel: str) -> bool:
    log.warning("OTP for %s via %s: %s",
                _mask_phone(phone_number), channel, _mask_code(code))
    return True


def send_sms(phone_number: str, body: str) -> bool:
    log.warning("SMS to %s: %s", _mask_phone(phone_number), body)
    return True