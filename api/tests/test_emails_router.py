import pytest
from fastapi import Request
from fastapi.testclient import TestClient
from app.main import create_app
from app.auth import get_current_user
from app import imap_client as im
from app.routers import emails_router as er

SUM = {"uid": 7, "subject": "Hi", "from_": "a@x.y", "to": ["b@x.y"], "date": None,
       "seen": False, "size": 10}

class FakeSession:
    calls = []
    def __init__(self, username, token): FakeSession.calls.append((username, token))
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def list(self, folder="INBOX", limit=50, offset=0): return 1, [dict(SUM)]
    def read(self, uid, folder="INBOX"):
        if uid != 7: raise im.DownstreamError("message not found")
        return {"summary": SUM, "headers": {}, "text_body": "t", "html_body": None,
                "attachments": []}
    def search_text(self, folder, q): return 1, [dict(SUM)]

def make_client(session_cls):
    er.MailSession = session_cls          # routers bind this name at module import
    FakeSession.calls = []
    app = create_app()
    def fake_user(request: Request):      # mirrors the real dependency's contract,
        request.state.raw_token = "faketoken"   # including the raw-token stash
        return {"sub": "s", "email": "bob@sovereign.mail"}
    app.dependency_overrides[get_current_user] = fake_user
    return TestClient(app)

def auth(): return {"Authorization": "Bearer faketoken"}

def test_list_ok():
    assert make_client(FakeSession).get("/emails", headers=auth()).json()["total"] == 1

def test_list_bad_folder():
    assert make_client(FakeSession).get(
        "/emails", params={"folder": "Trash"}, headers=auth()).status_code == 422

def test_read_found():
    assert make_client(FakeSession).get("/emails/7", headers=auth()).json()["text_body"] == "t"

def test_read_missing():
    assert make_client(FakeSession).get("/emails/9", headers=auth()).status_code == 404

def test_downstream_maps_502():
    class Boom(FakeSession):
        def list(self, *a, **k): raise im.DownstreamError("imap down")
    assert make_client(Boom).get("/emails", headers=auth()).status_code == 502

def test_search_requires_q():
    assert make_client(FakeSession).get("/search", headers=auth()).status_code == 400

def test_search_ok():
    r = make_client(FakeSession).get("/search", params={"q": "Hi"}, headers=auth())
    assert r.json()["messages"][0]["uid"] == 7

def test_session_gets_email_and_raw_token():
    c = make_client(FakeSession)
    c.get("/emails", headers=auth())
    assert FakeSession.calls[-1] == ("bob@sovereign.mail", "faketoken")
