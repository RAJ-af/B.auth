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
        return {"status": "ok"}

    from app.routers import auth_router, emails_router, send_router
    from app.routers import signup_router, admin_router
    app.include_router(auth_router.router)
    app.include_router(emails_router.router)
    app.include_router(send_router.router)
    app.include_router(signup_router.router)
    app.include_router(admin_router.router)

    return app

app = create_app()
