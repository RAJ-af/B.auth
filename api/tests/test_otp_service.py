"""otp_service budget + verification logic; SQL is faked at module boundary."""
import base64
import time

import httpx
import pytest

from app.services import otp_service as ot


class FlakyProvider:
    def __init__(self, ok=True):
        self.ok = ok
        self.calls = []
    def send_otp(self, phone, code, channel):
        self.calls.append((phone, code, channel))
        return self.ok
    def send_sms(self, phone, body):
        self.calls.append((phone, body))
        return self.ok


@pytest.fixture
def store(monkeypatch):
    """In-memory stand-in for the SQL wrappers."""
    rows = []
    monkeypatch.setattr(ot, "_insert_challenge",
                        lambda r: rows.append(r) or r)
    monkeypatch.setattr(ot, "_latest_active", lambda phone, purpose, now:
                        max((r for r in rows if r["phone"] == phone
                             and r["purpose"] == purpose), default=None,
                           key=lambda r: r["created_at"]))
    monkeypatch.setattr(ot, "_last_send_ts", lambda phone, purpose:
                        max((r["created_at"] for r in rows
                             if r["phone"] == phone), default=None))
    monkeypatch.setattr(ot, "_count_since", lambda phone, since:
                        sum(1 for r in rows if r["phone"] == phone
                            and r["created_at"] >= since))
    return {"rows": rows, "provider": None}


def _install(store, ok=True, monkeypatch=None):
    p = FlakyProvider(ok)
    store["provider"] = p
    monkeypatch.setattr(ot, "_get_provider", lambda: p)
    return p


NOW = 1_800_000_000.0


def test_budget_pure_logic():
    with pytest.raises(ot.BudgetExceeded, match="cooldown"):
        ot.within_budget(NOW - 10, 0, 0, now=NOW, cooldown_s=60, hourly=3, daily=200)
    with pytest.raises(ot.BudgetExceeded, match="hourly"):
        ot.within_budget(None, 3, 3, now=NOW, cooldown_s=60, hourly=3, daily=200)
    with pytest.raises(ot.BudgetExceeded, match="daily"):
        ot.within_budget(None, 1, 200, now=NOW, cooldown_s=60, hourly=3, daily=200)
    ot.within_budget(None, 2, 5, now=NOW, cooldown_s=60, hourly=3, daily=200)  # OK


def test_send_success_records_and_calls_provider(store, monkeypatch):
    p = _install(store, monkeypatch=monkeypatch)
    ot.send_challenge("+15550001", "signup", "sms")
    assert len(p.calls) == 1
    phone, code, channel = p.calls[0]
    assert phone == "+15550001" and channel == "sms"
    assert len(code) == 6 and code.isdigit()
    row = store["rows"][0]
    from app.ssha_util import verify_ssha
    assert row["code_sha256"].startswith("{SSHA}") or len(row["code_sha256"]) == 64


def test_provider_failure_does_not_consume_budget(store, monkeypatch):
    _install(store, ok=False, monkeypatch=monkeypatch)
    with pytest.raises(ot.OtpSendError):
        ot.send_challenge("+15550002", "signup", "sms")
    assert store["rows"] == []          # nothing recorded -> budget untouched


def test_cooldown_blocks_second_send(store, monkeypatch):
    _install(store, monkeypatch=monkeypatch)
    t = time.time()
    monkeypatch.setattr(ot.time, "time", lambda: t)
    ot.send_challenge("+15550003", "signup", "sms")
    monkeypatch.setattr(ot.time, "time", lambda: t + 5)   # inside 60s cooldown
    with pytest.raises(ot.BudgetExceeded):
        ot.send_challenge("+15550003", "signup", "sms")


def test_check_code_paths():
    import hashlib
    good = hashlib.sha256(b"123456").hexdigest()
    assert ot.check_code(good, 5, NOW + 60, False, "123456", now=NOW)
    with pytest.raises(ot.InvalidCode, match="match"):
        ot.check_code(good, 5, NOW + 60, False, "654321", now=NOW)
    with pytest.raises(ot.InvalidCode, match="expired"):
        ot.check_code(good, 5, NOW - 1, False, "123456", now=NOW)
    with pytest.raises(ot.InvalidCode, match="attempts"):
        ot.check_code(good, 0, NOW + 60, False, "654321", now=NOW)
    with pytest.raises(ot.InvalidCode, match="consumed"):
        ot.check_code(good, 5, NOW + 60, True, "123456", now=NOW)
    assert ot.check_code(None, None, None, False, "000000", now=NOW) is False


# --- verify_challenge (fix round 1: previously untested) --------------------

def _shape_latest(store, monkeypatch):
    """Wrap the store fixture's _latest_active so returned rows carry the same
    keys the real SQL projection produces (id, expires_at_ts, consumed)."""
    def latest(phone, purpose, now):
        row = next((r for r in store["rows"]
                    if r["phone"] == phone and r["purpose"] == purpose), None)
        if row is None:
            return None
        return {"id": 1,
                "code_sha256": row["code_sha256"],
                "attempts_left": row["attempts_left"],
                "expires_at_ts": row["expires_at"],
                "consumed": False}
    monkeypatch.setattr(ot, "_latest_active", latest)


def test_verify_unknown_phone_returns_false(store, monkeypatch):
    """No challenge row -> clean False, never a TypeError/raw 500."""
    _install(store, monkeypatch=monkeypatch)
    assert ot.verify_challenge("+15550009", "signup", "123456") is False


def test_verify_correct_code_consumes(store, monkeypatch):
    p = _install(store, monkeypatch=monkeypatch)
    _shape_latest(store, monkeypatch)
    updates = []
    monkeypatch.setattr(ot, "execute",
                        lambda q, params=(): updates.append((q, params)))
    ot.send_challenge("+15550010", "signup", "sms")
    code = p.calls[0][1]
    assert ot.verify_challenge("+15550010", "signup", code) is True
    assert any("consumed_at" in q for q, _ in updates)


def test_verify_wrong_code_decrements_attempts(store, monkeypatch):
    p = _install(store, monkeypatch=monkeypatch)
    _shape_latest(store, monkeypatch)
    updates = []
    monkeypatch.setattr(ot, "execute",
                        lambda q, params=(): updates.append((q, params)))
    ot.send_challenge("+15550011", "signup", "sms")
    real = p.calls[0][1]
    wrong = "000000" if real != "000000" else "111111"   # deterministic mismatch
    with pytest.raises(ot.InvalidCode):
        ot.verify_challenge("+15550011", "signup", wrong)
    assert sum("attempts_left=attempts_left-1" in q for q, _ in updates) == 1


# --- twilio wire credentials (fix round 1 regression) -----------------------

def test_twilio_wire_header_carries_real_credentials(monkeypatch):
    """Regression: httpx's auth_flow OVERWRITES any manually set Authorization
    header, so the previous code (manual header + placeholder auth tuple) always
    authenticated as the placeholder and every send got a 401. This test
    inspects what actually goes out on the wire via MockTransport."""
    from app.services.providers import twilio as tw

    captured = {}

    def handler(request):
        captured["authorization"] = request.headers["Authorization"]
        return httpx.Response(201, json={"sid": "SM-dummy"})

    def fake_post(url, **kwargs):
        # Route through MockTransport so we can inspect the outgoing request.
        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            return client.post(url, **kwargs)

    class _StubSettings:
        twilio_account_sid = "AC-dummy-sid"
        twilio_auth_token = "dummy-token"
        twilio_from_number = "+15550009999"

    monkeypatch.setattr(tw.httpx, "post", fake_post)
    monkeypatch.setattr(tw, "get_settings", lambda: _StubSettings())

    assert tw.send_otp("+15550001", "123456", "sms") is True
    wire = captured["authorization"]
    assert wire.startswith("Basic ")
    decoded = base64.b64decode(wire.removeprefix("Basic ")).decode()
    assert decoded == "AC-dummy-sid:dummy-token"