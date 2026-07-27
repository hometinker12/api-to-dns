from fastapi import APIRouter
from fastapi.responses import JSONResponse
from sqlalchemy import text

from ..db import SessionLocal

router = APIRouter(tags=["health"])


@router.get("/health", include_in_schema=False)
def health() -> dict:
    return {"status": "ok"}


@router.get("/ready", include_in_schema=False)
def ready():
    try:
        with SessionLocal() as db:
            db.exec(text("SELECT 1"))
    except Exception:
        return JSONResponse(status_code=503, content={"status": "not_ready"})
    return {"status": "ready"}
