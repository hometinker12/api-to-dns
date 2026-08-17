from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlmodel import Session

from ..db import get_db

router = APIRouter(tags=["health"])


@router.get("/health", include_in_schema=False)
def health() -> dict:
    return {"status": "ok"}


@router.get("/ready", include_in_schema=False)
def ready(db: Session = Depends(get_db)):
    try:
        db.exec(text("SELECT 1"))
    except Exception:
        return JSONResponse(status_code=503, content={"status": "not_ready"})
    return {"status": "ready"}
