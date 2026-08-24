#!/usr/bin/env python3
"""Live integration check against the running stack (host-side).

Run from the repo root (reads .env from CWD):
    cd /workspaces/B.auth && python3 scripts/live_check.py

Covers: alice browserless PKCE+TOTP login -> POST /send -> bob list / read /
search. DKIM + Sent-copy Maildir grepping stays in scripts/smoke-test.sh; this
script is purely API-path.
"""
import json, os, sys, time, urllib.error, urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
from kc_browserless_login import login as kc_login

BASE = os.environ.get("API_BASE", "http://localhost:8000")
KC_BASE = os.environ.get("KC_BASE", "http://localhost:8080")
REDIRECT = "http://localhost:8000/auth/callback"
# Unique per run so lookups can't collide with stale live-check mail already in
# bob's INBOX on re-runs (D1). Built once, used for both send and lookup.
SUBJECT = f"live-check-{int(time.time())}"

def env(k):
    """Config value: real environment first, else .env parsed from CWD.

    Lines are stripped so values carry no trailing newline and comment lines
    are skipped — unlike a bare split of the raw file lines.
    """
    if k in os.environ:
        return os.environ[k]
    vals = {}
    with open(".env") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, val = line.partition("=")
                vals[key] = val
    return vals[k]

def api(method, path, token=None, body=None):
    req = urllib.request.Request(BASE + path, method=method)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    data = None
    if body is not None:
        req.add_header("Content-Type", "application/json")
        data = json.dumps(body).encode()
    try:
        with urllib.request.urlopen(req, data) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        # Surface status + response body so failures are debuggable; these API
        # error bodies carry no credentials. Exit nonzero instead of raising so
        # the traceback never risks echoing request state.
        detail = e.read().decode(errors="replace")[:500]
        raise SystemExit(f"FAIL {method} {path} -> HTTP {e.code}: {detail}")

def get_tokens(user, secret):
    return kc_login(KC_BASE, env("KC_REALM"), env("KC_APP_CLIENT"), REDIRECT,
                    user, env("TEST_USER_PASSWORD"), secret)

def step(name, fn):
    out = fn(); print(f"PASS {name}", flush=True); return out

alice = step("alice login",
             lambda: get_tokens(env("TEST_USER_ALICE"), env("TEST_TOTP_SECRET_ALICE")))
bob = step("bob login (first-run TOTP enrollment expected)",
           lambda: get_tokens(env("TEST_USER_BOB"), env("TEST_TOTP_SECRET_BOB")))
step("alice /me", lambda: api("GET", "/me", alice["access_token"]))
mid = step("alice sends", lambda: api("POST", "/send", alice["access_token"], {
    "to": [env("TEST_USER_BOB")], "cc": ["outside@example.org"],
    "subject": SUBJECT, "text": "integration hello"}))["message_id"]
inbox = step("bob lists inbox", lambda: api("GET", "/emails", bob["access_token"]))
assert inbox["total"] >= 1, "bob inbox empty"
matches = [m for m in inbox["messages"] if m["subject"] == SUBJECT]
assert matches, f"no message with subject {SUBJECT!r} in listed page ({inbox['total']} total)"
target = matches[0]
full = step("bob reads", lambda: api("GET", f"/emails/{target['uid']}", bob["access_token"]))
assert "integration hello" in (full["text_body"] or ""), \
    f"text body mismatch: {(full['text_body'] or '')!r}"
found = step("bob searches", lambda: api("GET", "/search?q=live-check", bob["access_token"]))
assert found["total"] >= 1 and any(m["uid"] == target["uid"] for m in found["messages"]), \
    f"uid {target['uid']} not among search hits for 'live-check'"
step("done", lambda: print(f"LIVE CHECK OK (subject={SUBJECT} message_id={mid})", flush=True))
