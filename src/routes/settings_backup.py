import asyncio

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import JSONResponse, Response
from sqlmodel import Session
from starlette.status import HTTP_202_ACCEPTED, HTTP_409_CONFLICT

from .. import backup_service
from ..activity_logging import (
    emit_activity_event,
)
from ..backup_service import BackupError
from ..db import SessionLocal, get_db
from ..event_types import (
    EVENT_SYSTEM_BACKUP_EXPORTED,
    EVENT_SYSTEM_BACKUP_IMPORT_FAILED,
    EVENT_SYSTEM_BACKUP_IMPORTED,
)
from ..log_constants import (
    LOG_CATEGORY_SECURITY,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_WARNING,
)
from ..operational_logging import LOGGER
from ..rbac import (
    ROLE_GLOBAL_ADMIN,
    require_role,
)
from ..restart import (
    perform_application_restart,
)
from ..settings_context import render_settings
from ..web import (
    client_ip,
)

router = APIRouter(tags=["settings"], include_in_schema=False)


def _backup_categories_from_form(categories: list[str] | None) -> list[str]:
    return backup_service.normalize_categories(categories or [], default_on=False)


@router.post("/settings/backup/export", include_in_schema=False)
def settings_backup_export(
    request: Request,
    categories: list[str] = Form(default_factory=list),
    encrypt: str | None = Form(None),
    password: str = Form(""),
    password_confirm: str = Form(""),
    db: Session = Depends(get_db),
    user: str = Depends(require_role(ROLE_GLOBAL_ADMIN)),
):
    selected = _backup_categories_from_form(categories)
    if not selected:
        return render_settings(
            request,
            user,
            "backup",
            db=db,
            section="export",
            message="Select at least one category to export.",
            message_kind="error",
        )
    do_encrypt = (encrypt or "").strip().lower() in {"1", "true", "on", "yes"}
    if do_encrypt:
        if password != password_confirm:
            return render_settings(
                request,
                user,
                "backup",
                db=db,
                section="export",
                message="Backup passwords do not match.",
                message_kind="error",
            )
    try:
        payload = backup_service.build_payload(db, selected)
        raw = backup_service.serialize_backup(payload, encrypt=do_encrypt, password=password or None)
        emit_activity_event(
            db,
            event_type=EVENT_SYSTEM_BACKUP_EXPORTED,
            level=LOG_LEVEL_WARNING,
            category=LOG_CATEGORY_SECURITY,
            status="success",
            actor_type="user",
            actor_id=user,
            actor_label=user,
            message="Configuration backup exported",
            details={
                "categories": selected,
                "encrypted": do_encrypt,
                "bytes": len(raw),
            },
            request_method=request.method,
            request_path=str(request.url.path),
            request_ip=client_ip(request),
        )
        db.commit()
    except BackupError as exc:
        return render_settings(
            request,
            user,
            "backup",
            db=db,
            section="export",
            message=str(exc),
            message_kind="error",
        )
    filename = backup_service.backup_filename()
    return Response(
        content=raw,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/settings/backup/import/progress", include_in_schema=False)
def settings_backup_import_progress(
    db: Session = Depends(get_db),
    user: str = Depends(require_role(ROLE_GLOBAL_ADMIN)),
):
    return JSONResponse(backup_service.get_restore_progress(db))


def _run_backup_import_sync(
    *,
    raw: bytes,
    password: str,
    categories: list[str],
    user: str,
) -> None:
    def progress(phase: str, percent: int, message: str) -> None:
        with SessionLocal() as progress_db:
            backup_service.write_restore_progress(
                progress_db,
                phase=phase,
                percent=percent,
                message=message,
            )

    try:
        payload = backup_service.load_backup_bytes(raw, password or None)
        with SessionLocal() as db:
            result = backup_service.restore_payload(db, payload, categories, progress_cb=progress)
            emit_activity_event(
                db,
                event_type=EVENT_SYSTEM_BACKUP_IMPORTED,
                level=LOG_LEVEL_WARNING,
                category=LOG_CATEGORY_SECURITY,
                status="success",
                actor_type="user",
                actor_id=user,
                actor_label=user,
                message="Configuration backup imported",
                details={
                    "categories": result.get("categories"),
                    "summary": result.get("summary"),
                    "restarting": result.get("restarting"),
                },
            )
            db.commit()
            restarting = bool(result.get("restarting"))
            backup_service.write_restore_progress(
                db,
                phase="complete",
                percent=100,
                message="Restarting application…" if restarting else "Restore complete.",
                done=True,
                result_status="success",
                restarting=restarting,
            )
        if restarting:
            perform_application_restart(scheduled=False)
    except Exception as exc:
        LOGGER.exception("Configuration backup import failed")
        with SessionLocal() as db:
            emit_activity_event(
                db,
                event_type=EVENT_SYSTEM_BACKUP_IMPORT_FAILED,
                level=LOG_LEVEL_ERROR,
                category=LOG_CATEGORY_SECURITY,
                status="error",
                actor_type="user",
                actor_id=user,
                actor_label=user,
                message="Configuration backup import failed",
                details={"error": str(exc)[:500]},
            )
            db.commit()
            backup_service.write_restore_progress(
                db,
                phase="error",
                percent=100,
                message="Restore failed.",
                done=True,
                error=str(exc)[:500],
                result_status="error",
            )


async def _run_backup_import(*, raw: bytes, password: str, categories: list[str], user: str) -> None:
    try:
        await asyncio.to_thread(
            _run_backup_import_sync,
            raw=raw,
            password=password,
            categories=categories,
            user=user,
        )
    finally:
        with SessionLocal() as db:
            backup_service.mark_restore_worker_finished(db)


@router.post("/settings/backup/import-async", include_in_schema=False)
async def settings_backup_import_async(
    request: Request,
    backup_file: UploadFile = File(...),
    categories: list[str] = Form(default_factory=list),
    password: str = Form(""),
    confirm_replace: str | None = Form(None),
    db: Session = Depends(get_db),
    user: str = Depends(require_role(ROLE_GLOBAL_ADMIN)),
):
    if (confirm_replace or "").strip() not in {"1", "true", "on", "yes"}:
        return JSONResponse(
            {"detail": "Confirm destructive replace before restoring."},
            status_code=400,
        )
    selected = _backup_categories_from_form(categories)
    if not selected:
        return JSONResponse({"detail": "Select at least one category to restore."}, status_code=400)
    raw = await backup_file.read(backup_service.MAX_BACKUP_UPLOAD_BYTES + 1)
    if not raw:
        return JSONResponse({"detail": "Backup file is empty."}, status_code=400)
    if len(raw) > backup_service.MAX_BACKUP_UPLOAD_BYTES:
        return JSONResponse(
            {
                "detail": f"Backup file exceeds the {backup_service.MAX_BACKUP_UPLOAD_BYTES // (1024 * 1024)} MiB upload limit."
            },
            status_code=400,
        )
    # Fail fast on decrypt / full record validation before starting the worker.
    # Decrypt off the event loop so attacker-controlled PBKDF2 cannot stall requests.
    try:
        payload = await asyncio.to_thread(backup_service.load_backup_bytes, raw, password or None)
        backup_service.validate_restore_records(selected, payload)
    except BackupError as exc:
        return JSONResponse({"detail": str(exc)}, status_code=400)

    if not backup_service.try_begin_restore(db):
        return JSONResponse({"detail": "A restore is already in progress."}, status_code=HTTP_409_CONFLICT)
    asyncio.create_task(_run_backup_import(raw=raw, password=password, categories=selected, user=user))
    return JSONResponse({"status": "started"}, status_code=HTTP_202_ACCEPTED)
