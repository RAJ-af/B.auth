import hashlib

import pytest

from app.services import devices as dv


@pytest.fixture
def world(monkeypatch):
    drows, arows, fired = {}, {"me@sovereign.mail": True}, []
    monkeypatch.setattr(dv, "_insert_row", lambda r: drows.setdefault(r["device_hash"], r))
    monkeypatch.setattr(dv, "_find_by_hash", lambda h: drows.get(h))
    monkeypatch.setattr(dv, "_rows_for", lambda e: [r for r in drows.values()
                                                    if r["email"] == e])
    monkeypatch.setattr(dv, "_drop_row", lambda h: drows.pop(h, None) is not None)
    monkeypatch.setattr(dv, "_bump_seen", lambda h: drows[h].update(
        {"last_seen_at": "bumped"}))
    dv.VOID_HOOKS.clear()
    dv.VOID_HOOKS.append(lambda h: fired.append(h))
    return {"drows": drows, "fired": fired}


def test_mint_returns_raw_and_never_stores_it(world):
    raw, raw_b = dv.mint()
    assert isinstance(raw, str) and len(raw_b) >= 16
    # nothing persisted yet at all:
    assert world["drows"] == {}


def test_register_stores_only_hash(world):
    raw, _ = dv.mint()
    row = dv.register("me@sovereign.mail", "Pixel 8", raw)
    stored = list(world["drows"].values())[0]
    assert stored["device_hash"] == hashlib.sha256(raw.encode()).hexdigest()
    assert raw not in str(world["drows"])
    assert "raw" not in row and "device_hash" in row


def test_resolve_hits_and_bumps(world):
    raw, _ = dv.mint()
    dv.register("me@sovereign.mail", "Pixel 8", raw)
    hit = dv.resolve(raw)
    assert hit and hit["email"] == "me@sovereign.mail"
    assert list(world["drows"].values())[0]["last_seen_at"] == "bumped"
    assert dv.resolve("garbage") is None


def test_delete_fires_void_hook_before_removal(world, monkeypatch):
    """§13 ordering guarantee: void hooks run BEFORE the row disappears."""
    order: list[str] = []

    real_hooks = list(dv.VOID_HOOKS)
    dv.VOID_HOOKS[:] = [lambda h: order.append("hook")]   # exactly one hook

    def spy_drop(h):
        order.append("drop")
        return True
    monkeypatch.setattr(dv, "_drop_row", spy_drop)

    raw, _ = dv.mint()
    row = dv.register("me@sovereign.mail", "D", raw)
    assert dv.delete("me@sovereign.mail", row["device_hash"]) is True
    assert order == ["hook", "drop"]        # hook fired BEFORE removal
    dv.VOID_HOOKS[:] = real_hooks


def test_delete_requires_owner_match(world):
    raw, _ = dv.mint()
    row = dv.register("me@sovereign.mail", "D", raw)
    other = dv.delete("intruder@sovereign.mail", row["device_hash"])
    assert other is False
