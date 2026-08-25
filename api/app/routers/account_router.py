from fastapi import APIRouter, Depends, HTTPException

from ..auth import get_current_user
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


@router.post("/notifications/{notif_id}/read")
def mark(notif_id: int, user: dict = Depends(get_current_user)):
    nf.mark_read(user["email"], notif_id)
    return {"ok": True}
