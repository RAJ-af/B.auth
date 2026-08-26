"""Spec §16: /healthz carries a db field (SELECT 1 probe). Liveness stays
200 + status ok even when the dependency is down — honesty, not self-harm."""


def test_healthz_ok(client, monkeypatch):
    import app.db as appdb
    monkeypatch.setattr(appdb, "one", lambda q, p=(): [{"?column?": 1}])
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "db": "ok"}


def test_healthz_reports_down_but_stays_200(client, monkeypatch):
    import app.db as appdb

    def boom(q, p=()):
        raise RuntimeError("connection refused")
    monkeypatch.setattr(appdb, "one", boom)
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "db": "down"}
