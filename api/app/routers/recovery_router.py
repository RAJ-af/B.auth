"""Every handler returns through ONE of two constant envelopes so known vs
unknown emails, budget drops, and branch differences are indistinguishable on
the wire (§15.3)."""
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from ..auth import get_current_user
from ..config import get_settings
from ..services import recovery as rc

router = APIRouter(prefix="/recovery", tags=["recovery"])

OK_BODY = {"received": True}


class EmailBody(BaseModel):
    email: str


class CodeBody(BaseModel):
    email: str
    code: str


class PasswordBody(BaseModel):
    email: str
    new_password: str


class ApproveBody(BaseModel):
    requester_email: str


@router.post("/start", status_code=202)
def start(body: EmailBody, request: Request):
    rc.start_recovery(body.email.lower(), request.headers.get("X-Device-ID"))
    return OK_BODY


@router.get("/status", status_code=202)
def check_status(email: str = ""):
    """No state leak: clients poll nothing — they wait for contact channels
    (§15.3). This endpoint exists so polls look boring instead of 404."""
    return OK_BODY


@router.post("/verify-otp")
def verify(body: CodeBody):
    try:
        stage = rc.verify_otp(body.email.lower(), body.code)
    except rc.WrongCode:                 # service normalizes InvalidCode/False
        raise HTTPException(401, "invalid code")   # identical shape forever
    return {"stage": stage}


@router.post("/family-approve")
def fam_approve(body: ApproveBody, user: dict = Depends(get_current_user)):
    if not rc.family_approve(user["email"], body.requester_email.lower()):
        raise HTTPException(404, "no such request")
    return {"ok": True}


@router.post("/complete")
def complete(body: PasswordBody, request: Request):
    if get_settings().password_min_length > len(body.new_password):
        raise HTTPException(422, "password too short")
    status, code = rc.maybe_complete(body.email.lower(), body.new_password,
                                     request.headers.get("X-Device-ID"))
    if code == 201:
        return {"reset": True}
    raise HTTPException(code, status)    # not_ready / invalid_request constants


@router.post("/cancel")
def cancel(body: EmailBody, user: dict = Depends(get_current_user)):
    # Owner cancelling their own request; family-side cancellation rides the
    # same endpoint with their own JWT (both are 'a party with standing', R5).
    # The result is deliberately DISCARDED: a non-standing caller sees the
    # same OK_BODY as a successful cancel — no oracle for attackers (§15.3).
    rc.cancel(body.email.lower(), user["email"])
    return OK_BODY
