from fastapi import APIRouter, Depends, HTTPException, Query, Request
from ..auth import get_current_user
from ..imap_client import MailSession, DownstreamError, FOLDER_ALLOWLIST

router = APIRouter(tags=["mail"])
MAX_PAGE = 100

@router.get("/emails")
def list_emails(request: Request, user: dict = Depends(get_current_user),
                folder: str = "INBOX",
                limit: int = Query(50, le=MAX_PAGE, ge=0),
                offset: int = Query(0, ge=0)):
    if folder not in FOLDER_ALLOWLIST:
        raise HTTPException(422, f"folder must be one of {sorted(FOLDER_ALLOWLIST)}")
    try:
        with MailSession(user["email"], request.state.raw_token) as s:
            total, msgs = s.list(folder, limit, offset)
    except DownstreamError as e:
        raise HTTPException(502, str(e))
    return {"total": total, "messages": msgs}

@router.get("/emails/{uid}")
def read_email(uid: int, request: Request, user: dict = Depends(get_current_user),
               folder: str = "INBOX"):
    if folder not in FOLDER_ALLOWLIST:
        raise HTTPException(422, f"folder must be one of {sorted(FOLDER_ALLOWLIST)}")
    try:
        with MailSession(user["email"], request.state.raw_token) as s:
            return s.read(uid, folder)
    except DownstreamError as e:
        raise HTTPException(404 if "not found" in str(e) else 502, str(e))

@router.get("/search")
def search(request: Request, q: str = "", user: dict = Depends(get_current_user),
           folder: str = "INBOX"):
    if not q.strip():
        raise HTTPException(400, "query parameter q is required")
    if folder not in FOLDER_ALLOWLIST:
        raise HTTPException(422, f"folder must be one of {sorted(FOLDER_ALLOWLIST)}")
    try:
        with MailSession(user["email"], request.state.raw_token) as s:
            total, msgs = s.search_text(folder, q)
    except DownstreamError as e:
        raise HTTPException(502, str(e))
    return {"total": total, "messages": msgs}
