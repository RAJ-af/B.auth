import logging
from fastapi import FastAPI
from app.config import get_settings

logging.basicConfig(level=logging.INFO)

def create_app() -> FastAPI:
    app = FastAPI(title="sovereign-mail-api", docs_url=None, redoc_url=None)
    settings = get_settings()

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    from app.routers import auth_router, emails_router, send_router
    from app.routers import signup_router
    app.include_router(auth_router.router)
    app.include_router(emails_router.router)
    app.include_router(send_router.router)
    app.include_router(signup_router.router)

    return app

app = create_app()
