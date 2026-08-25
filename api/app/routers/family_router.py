from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ..auth import get_current_user
from ..services import family as fm

router = APIRouter(prefix="/family", tags=["family"])


class RequestBody(BaseModel):
    target_email: str


@router.post("/requests", status_code=202)
def create(body: RequestBody, user: dict = Depends(get_current_user)):
    try:
        link = fm.request_link(user["email"], body.target_email.lower())
    except fm.NotEligible as e:
        raise HTTPException(422, str(e))
    except fm.NoSuchTarget as e:
        # §15.3 anti-enumeration is a RECOVERY-only rule; family requests
        # legitimately tell the requester the member does not exist.
        raise HTTPException(404, str(e))
    except fm.RateLimited as e:
        raise HTTPException(429, str(e))
    return {"link_id": link["link_id"],
            "expires_at": link["expires_at_ts"],
            "expires_within_seconds": fm.REQUEST_TTL_SECONDS}


@router.post("/requests/{link_id}/approve")
def approve(link_id: int, user: dict = Depends(get_current_user)):
    try:
        fm.approve(link_id, user["email"])
    except fm.NoSuchTarget as e:      # includes expired/no-longer-active requests
        raise HTTPException(404, str(e))
    except fm.NotAuthorized as e:
        raise HTTPException(403, str(e))
    return {"ok": True}


@router.post("/requests/{link_id}/revoke")
def revoke(link_id: int, user: dict = Depends(get_current_user)):
    try:
        fm.revoke(link_id, user["email"])
    except fm.NoSuchTarget as e:
        raise HTTPException(404, str(e))
    except fm.NotAuthorized as e:
        raise HTTPException(403, str(e))
    return {"ok": True}


@router.get("/links")
def links(user: dict = Depends(get_current_user)):
    return {"links": fm.active_links_for(user["email"])}


@router.get("/requests")
def incoming(user: dict = Depends(get_current_user)):
    return {"requests": fm.pending_requests_for(user["email"])}
