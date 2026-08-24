import smtplib
import ssl
import pytest
from fastapi import Request
from fastapi.testclient import TestClient

from app.auth import get_current_user
from app.main import create_app
import app.smtp_client as sc
import app.routers.send_router as sr
from app.smtp_client import build_mime, RECIPIENT_LIMIT, BODY_LIMIT_BYTES
from app.routers.send_router import enforce_sender, validate_send_request

# --- unit level: mime builder + request validation ---

def test_build_mime_plain():
    m = build_mime("a@x.y", ["b@x.y"], [], [], "Sub", "hello", None)
    assert m["Subject"] == "Sub" and m["From"] == "a@x.y"
    assert m.get_content_type() == "text/plain"

def test_build_mime_multipart_with_html():
    # Brief-skeleton correction (D3): add_alternative() -- the briefed impl --
    # yields multipart/alternative, which is the RFC-correct type for
    # text+html representations of the SAME content (not mixed).
    m = build_mime("a@x.y", ["b@x.y"], [], [], "Sub", "hello", "<b>hi</b>")
    assert m.get_content_type() == "multipart/alternative"
    assert m.iter_parts() and {p.get_content_type() for p in m.iter_parts()} == {
        "text/plain", "text/html"}

def test_enforce_sender_overwrites_spoof():
    m = build_mime("evil@attacker.io", ["b@x.y"], [], [], "S", "t", None)
    enforce_sender(m, "alice@sovereign.mail")
    assert m["From"] == "alice@sovereign.mail"

def test_recipient_limit():
    with pytest.raises(ValueError):
        validate_send_request(to=[f"u{i}@x.y" for i in range(RECIPIENT_LIMIT + 1)],
                              cc=[], bcc=[], subject="s", text="t", html=None)

def test_body_limit():
    with pytest.raises(ValueError):
        validate_send_request(to=["b@x.y"], cc=[], bcc=[], subject="s",
                              text="x" * (BODY_LIMIT_BYTES + 1), html=None)

# --- router level (stubbed SMTP at the smtplib seam + stubbed IMAP session) ---

class FakeSMTP:
    sent = None
    def __init__(self, host, port, timeout=None): pass
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def starttls(self, context=None): pass
    def send_message(self, m, from_addr=None, to_addrs=None): FakeSMTP.sent = m

class FakeSession:
    folders = []
    def __init__(self, *a): pass
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def append(self, folder, raw): FakeSession.folders.append(folder)

def make_client(monkeypatch, smtp_cls=FakeSMTP):
    monkeypatch.setattr(sc.smtplib, "SMTP", smtp_cls)
    # D4: the CA bundle path (/certs/rootCA.pem) only exists inside the api
    # container; create_default_context(cafile=...) would raise FileNotFoundError
    # (an OSError -> DownstreamError -> 502) locally. Stub it at the same
    # module-attribute seam as smtplib; production code stays unmodified.
    real_ctx = ssl.create_default_context   # bind BEFORE patching (sc.ssl IS stdlib ssl)
    monkeypatch.setattr(sc.ssl, "create_default_context",
                        lambda cafile=None: real_ctx())
    sr.MailSession = FakeSession
    FakeSMTP.sent = None; FakeSession.folders = []
    app = create_app()
    def fake_user(request: Request):      # mirrors the real dependency's contract,
        request.state.raw_token = "fake"  # incl. the raw-token stash; MUST be typed,
        return {"sub": "s", "email": "alice@sovereign.mail"}  # else FastAPI treats it
                                              # as a required query field (D0, 422s).
    app.dependency_overrides[get_current_user] = fake_user
    return TestClient(app)

def auth(): return {"Authorization": "Bearer fake"}

def test_send_202_forces_from_and_sent_copy(monkeypatch):
    r = make_client(monkeypatch).post(
        "/send", headers=auth(),
        json={"to": ["bob@sovereign.mail"], "subject": "Yo", "text": "hi"})
    assert r.status_code == 202 and "message_id" in r.json()
    assert FakeSMTP.sent["From"] == "alice@sovereign.mail"   # spoof impossible
    assert FakeSession.folders == ["Sent"]

def test_send_smtp_failure_maps_502(monkeypatch):
    class BoomSMTP(FakeSMTP):
        def send_message(self, *a, **k): raise smtplib.SMTPException("relay refused")
    r = make_client(monkeypatch, smtp_cls=BoomSMTP).post(
        "/send", headers=auth(),
        json={"to": ["bob@sovereign.mail"], "subject": "Y", "text": "hi"})
    assert r.status_code == 502

def test_send_zero_recipients_rejected(monkeypatch):
    r = make_client(monkeypatch).post(
        "/send", headers=auth(),
        json={"to": [], "cc": ["c@x.y"], "bcc": ["b@x.y"],
              "subject": "Y", "text": "hi"})
    assert r.status_code == 422   # pydantic min_length=1 on to

def test_send_all_blank_recipients_rejected(monkeypatch):
    r = make_client(monkeypatch).post(
        "/send", headers=auth(),
        json={"to": [""], "cc": [""], "bcc": [""],
              "subject": "Y", "text": "hi"})
    assert r.status_code == 422   # validate_send_request counts only non-empty

def test_send_recipient_over_limit_maps_422(monkeypatch):
    r = make_client(monkeypatch).post(
        "/send", headers=auth(),
        json={"to": [f"u{i}@x.y" for i in range(RECIPIENT_LIMIT + 1)],
              "subject": "Y", "text": "hi"})
    assert r.status_code == 422
