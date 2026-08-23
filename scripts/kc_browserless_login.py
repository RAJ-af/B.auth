#!/usr/bin/env python3
"""Browser-less Keycloak login: authorization-code + PKCE driving the HTML forms."""
import argparse, html.parser, json, sys, os
import httpx
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "api"))
from app.pkce_util import make_pkce_pair, compute_totp


def _relax_cookie_flags(jar):
    """Keycloak marks its session cookies `Secure` and `Version=1` because
    http://localhost counts as a secure context server-side. Browsers exempt
    localhost from both rules; Python's cookie jar does not, so clear the flags
    on stored cookies after every response (client-side only)."""
    def _hook(_response=None):
        for c in jar:
            c.version = 0
            c.rfc2109 = False
            c.secure = False
    return _hook

class _Form(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(); self.forms = []; self.cur = None
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self.cur = {"action": a.get("action"), "fields": {}}
        elif tag == "input" and self.cur is not None and a.get("name"):
            self.cur["fields"][a["name"]] = a.get("value", "")
    def handle_endtag(self, tag):
        if tag == "form" and self.cur is not None:
            self.forms.append(self.cur); self.cur = None

def parse_forms(body: str):
    p = _Form(); p.feed(body); return p.forms

def login(base_url: str, realm: str, client_id: str, redirect_uri: str,
          username: str, password: str, totp_secret: str) -> dict:
    s = httpx.Client(base_url=base_url, follow_redirects=False, timeout=30.0)
    s.event_hooks["response"] = [_relax_cookie_flags(s.cookies.jar)]
    verifier, challenge = make_pkce_pair()
    r = s.get(f"/realms/{realm}/protocol/openid-connect/auth", params={
        "response_type": "code", "client_id": client_id, "redirect_uri": redirect_uri,
        "scope": "openid email profile", "state": "smoke-state", "nonce": "smoke-nonce",
        "code_challenge": challenge, "code_challenge_method": "S256"})
    form = next((f for f in parse_forms(r.text) if "authenticate" in (f["action"] or "")), None)
    assert form, f"no login form; status={r.status_code}"
    data = dict(form["fields"]); data.update({"username": username, "password": password, "login": "Sign In"})
    r = s.post(form["action"], data=data)
    body = r.text
    if 'name="otp"' in body:
        oform = next(f for f in parse_forms(body) if "totp" in (f["action"] or "") or "login-actions" in (f["action"] or ""))
        d = dict(oform["fields"]); d["otp"] = compute_totp(totp_secret)
        r = s.post(oform["action"], data=d)
    elif 'name="totpSecret"' in body:
        # First login: Configure-OTP required action. The enrollment form carries the
        # server-generated secret in a hidden `totpSecret` field — override it with our
        # known TEST_TOTP_SECRET_* so scripts stay deterministic (KC 26 has no admin
        # endpoint to attach OTP credentials directly).
        eform = next((f for f in parse_forms(body) if "totpSecret" in f["fields"]), None)
        assert eform is not None, "no totp enrollment form"
        d = dict(eform["fields"])
        d["totpSecret"] = totp_secret
        d["totp"] = compute_totp(totp_secret)
        d["userLabel"] = "seeded"
        r = s.post(eform["action"], data=d)
    loc = r.headers.get("location", "")
    assert "code=" in loc, f"expected code redirect, got {r.status_code}: {loc[:200]}"
    code = loc.split("code=")[1].split("&")[0]
    tok = s.post(f"/realms/{realm}/protocol/openid-connect/token", data={
        "grant_type": "authorization_code", "client_id": client_id, "code": code,
        "redirect_uri": redirect_uri, "code_verifier": verifier})
    assert tok.status_code == 200, tok.text
    return tok.json()

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", required=True); ap.add_argument("--realm", required=True)
    ap.add_argument("--client-id", required=True); ap.add_argument("--redirect-uri", required=True)
    ap.add_argument("--username", required=True); ap.add_argument("--password", required=True)
    ap.add_argument("--totp-secret", required=True)
    print(json.dumps(login(**vars(ap.parse_args())), indent=2))
