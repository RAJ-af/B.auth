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

    return app

app = create_app()
