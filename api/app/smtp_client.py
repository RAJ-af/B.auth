"""Outbound submission: MIME building, request validation, SMTP STARTTLS submit.

TLS posture (Task 13 / D1): full verification retained -- create_default_context
loads the lab CA AND keeps check_hostname=True. The postfix :2587 listener serves
/certs/server.crt whose SAN includes DNS:postfix (and DNS:mail.sovereign.mail),
so connecting to the compose service name "postfix" passes hostname verification
without weakening anything. Verified live on the codespace stack.
"""
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from .config import get_settings
from .imap_client import DownstreamError

RECIPIENT_LIMIT = 50
BODY_LIMIT_BYTES = 10 * 1024 * 1024
# Header-injection surface: a recipient carrying CR/LF smuggles protocol lines,
# a comma would silently split into extra envelope recipients when joined into
# the To/Cc header, and angle brackets can spoof the display-address form.
FORBIDDEN_RCPT_CHARS = ("\r", "\n", ",", "<", ">")

def build_mime(from_: str, to: list[str], cc: list[str], bcc: list[str],
               subject: str, text: str, html: str | None) -> EmailMessage:
    s = get_settings()
    m = EmailMessage()
    m["From"] = from_
    m["To"] = ", ".join(to)
    if cc:
        m["Cc"] = ", ".join(cc)
    m["Subject"] = subject
    m["Date"] = formatdate(localtime=False)
    m["Message-ID"] = make_msgid(domain=s.mail_domain)
    m.set_content(text)
    if html:
        m.add_alternative(html, subtype="html")
    return m

def validate_send_request(*, to: list[str], cc: list[str], bcc: list[str],
                          subject: str, text: str, html: str | None) -> None:
    for r in (*to, *cc, *bcc):
        if any(ch in r for ch in FORBIDDEN_RCPT_CHARS):
            raise ValueError(
                f"invalid recipient {r!r}: CR/LF, comma and angle brackets "
                "are not allowed")
    rcpt_total = len([r for r in (*to, *cc, *bcc) if r])
    if rcpt_total == 0:
        raise ValueError("at least one recipient required")
    if rcpt_total > RECIPIENT_LIMIT:
        raise ValueError(f"more than {RECIPIENT_LIMIT} recipients")
    # Byte count, not char count — the limit is what goes on the wire (UTF-8).
    if len(text.encode()) + len((html or "").encode()) > BODY_LIMIT_BYTES:
        raise ValueError("body too large")

def submit_message(msg: EmailMessage, envelope_rcpts: list[str]) -> None:
    s = get_settings()
    try:
        ctx = ssl.create_default_context(cafile=s.ca_cert_path)   # CA + hostname checks ON
        # local_hostname: announce our mail domain in HELO/EHLO instead of the
        # bare container IP — sheds Rspamd's HFILTER_HELO_BAREIP on every send.
        with smtplib.SMTP(s.smtp_host, s.smtp_port, timeout=30,
                          local_hostname=s.mail_domain) as smtp:
            smtp.starttls(context=ctx)
            smtp.send_message(msg, from_addr=msg["From"], to_addrs=envelope_rcpts)
    except (smtplib.SMTPException, OSError, ssl.SSLError) as e:
        raise DownstreamError(f"smtp submit failed: {e}") from e
