"""DSN builder pins (live connectivity is a codespace wave gate, not local)."""
from app.db import dsn


def test_dsn_contains_all_components(monkeypatch):
    import app.config as cfg
    monkeypatch.setattr(cfg.get_settings, "cache_clear", lambda: None)
    s = cfg.get_settings.__wrapped__() if hasattr(cfg.get_settings, "__wrapped__") else cfg.get_settings()
    monkeypatch.setattr(cfg, "get_settings", lambda: type(
        "S", (), {
            "postgres_host": "pg.test", "postgres_port": 6543,
            "sovereign_app_db": "sovereign_app", "postgres_user": "u",
            "postgres_password": "p"})())
    import importlib
    from app import db
    importlib.reload(db)
    d = db.dsn()
    assert "host=pg.test" in d and "port=6543" in d and "dbname=sovereign_app" in d
    assert "user=u" in d and "password=p" in d