from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ..auth import get_current_user
from ..services import devices as dv
from ..services import notifications as nf

router = APIRouter(prefix="/account", tags=["account"])


@router.get("/profile")
def profile(user: dict = Depends(get_current_user)):
    from ..db import one
    row = one("""SELECT email, display_name, phone_e164, account_type,
                        guardian_phone, tier, verification, status, created_at
                 FROM accounts WHERE email=%s""", (user["email"],))
    if not row:
        raise HTTPException(404, "no profile row (seeded-before-migration user?)")
    return row


@router.get("/notifications")
def my_notifications(user: dict = Depends(get_current_user)):
    return {"notifications": nf.list_for(user["email"])}


@router.get("/dependents")
def dependents(user: dict = Depends(get_current_user)):
    """Guardian roster (§8.2 enforcement point 1): managed accounts whose
    guardian_phone equals THIS caller's account phone. Phones are deliberately
    non-unique (spec §6), so one number can control several dependents.
    Projection whitelist + masked address — same idiom as admin listings."""
    from ..db import many, one
    me = one("SELECT phone_e164 FROM accounts WHERE email=%s",
             (user["email"],))
    if not me:
        raise HTTPException(404, "no profile row (seeded-before-migration user?)")
    rows = many("""SELECT email, display_name, created_at FROM accounts
                   WHERE account_type='guardian_managed' AND guardian_phone=%s
                   ORDER BY created_at""", (me["phone_e164"],))
    return {"dependents": [
        {"email_masked": nf.mask_email(r["email"]),
         "display_name": r["display_name"], "created_at": r["created_at"]}
        for r in rows]}


@router.post("/notifications/{notif_id}/read")
def mark(notif_id: int, user: dict = Depends(get_current_user)):
    nf.mark_read(user["email"], notif_id)
    return {"ok": True}


class DeviceBody(BaseModel):
    label: str


@router.post("/devices")
def add_device(body: DeviceBody, user: dict = Depends(get_current_user)):
    raw, _ = dv.mint()
    row = dv.register(user["email"], body.label, raw)
    # The raw id crosses the wire exactly once; only its hash remains server-side.
    return {"device_id": raw, "label": row["label"],
            "header": "X-Device-ID", "device_hash": row["device_hash"]}


@router.get("/devices")
def my_devices(user: dict = Depends(get_current_user)):
    return {"devices": dv.list_for(user["email"])}


@router.delete("/devices/{device_hash}")
def remove_device(device_hash: str, user: dict = Depends(get_current_user)):
    if not dv.delete(user["email"], device_hash):
        raise HTTPException(404, "no such device for this account")
    return {"ok": True, "note": "any pending recovery relying on this device "
                                "was cancelled"}
