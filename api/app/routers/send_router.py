import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from ..auth import get_current_user
from ..imap_client import MailSession, DownstreamError
from ..smtp_client import (build_mime, validate_send_request, submit_message,
                           RECIPIENT_LIMIT, BODY_LIMIT_BYTES)

log = logging.getLogger(__name__)
router = APIRouter(tags=["send"])

class SendBody(BaseModel):
    to: list[str] = Field(min_length=1)
    cc: list[str] = []
    bcc: list[str] = []
    subject: str = Field(min_length=1, max_length=998)
    text: str = ""
    html: str | None = None

def enforce_sender(msg, claimed_email: str) -> None:
    """From := token claim. Any client-supplied From is deleted first, so a
    spoofed header can never survive to the wire."""
    if "From" in msg:
        del msg["From"]
    msg["From"] = claimed_email

@router.post("/send", status_code=202)
def send(body: SendBody, request: Request, user: dict = Depends(get_current_user)):
    try:
        validate_send_request(to=body.to, cc=body.cc, bcc=body.bcc,
                              subject=body.subject, text=body.text, html=body.html)
    except ValueError as e:
        raise HTTPException(422, str(e))
    msg = build_mime(user["email"], body.to, body.cc, body.bcc,
                     body.subject, body.text or "", body.html)
    enforce_sender(msg, user["email"])           # From := claim, spoof impossible
    recipients = [*body.to, *body.cc, *body.bcc]
    try:
        submit_message(msg, recipients)
    except DownstreamError as e:
        raise HTTPException(502, str(e))
    message_id = msg["Message-ID"]
    try:                                          # best-effort Sent copy
        with MailSession(user["email"], request.state.raw_token) as s:
            s.append("Sent", msg.as_bytes())
    except Exception:
        log.warning("sent-copy append failed for %s", user["email"])
    return {"message_id": str(message_id)}
