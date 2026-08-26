import logging
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.config import get_settings

logging.basicConfig(level=logging.INFO)

def create_app() -> FastAPI:
    app = FastAPI(title="sovereign-mail-api", docs_url=None, redoc_url=None)
    settings = get_settings()

    # Admin dashboard assets (templates reference /static/admin.css).
    static_dir = Path(__file__).resolve().parents[1] / "static"
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/healthz")
    def healthz():
        # Spec §16: extends with a "db" field (SELECT 1 probe). Overall status
        # stays ok + HTTP 200 — container LIVENESS vs dependency honesty: the
        # orchestrator must not restart a healthy api because postgres is down.
        from app import db as appdb
        try:
            appdb.one("SELECT 1")
            db_status = "ok"
        except Exception:                    # noqa: BLE001 — any DB failure is "down"
            db_status = "down"
        return {"status": "ok", "db": db_status}

    from app.routers import auth_router, emails_router, send_router
    from app.routers import signup_router, admin_router, account_router
    from app.routers import family_router, recovery_router
    app.include_router(auth_router.router)
    app.include_router(emails_router.router)
    app.include_router(send_router.router)
    app.include_router(signup_router.router)
    app.include_router(admin_router.router)
    app.include_router(account_router.router)
    app.include_router(family_router.router)
    app.include_router(recovery_router.router)

    return app

app = create_app()
