import asyncio
from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from sqlmodel import Session
from starlette.status import HTTP_202_ACCEPTED, HTTP_404_NOT_FOUND, HTTP_409_CONFLICT

from .. import letsencrypt
from ..activity_logging import (
    LOGGER,
    emit_activity_event,
)
from ..db import SessionLocal, get_db
from ..letsencrypt import LetsEncryptError
from ..log_constants import (
    LOG_CATEGORY_SECURITY,
    LOG_LEVEL_WARNING,
)
from ..rbac import (
    ROLE_SYSTEM_UPDATE,
    require_role,
)
from ..restart import (
    is_restart_required,
    mark_restart_required,
)
from ..settings_context import render_settings
from ..ssl_certs import (
    MAX_SSL_CERT_UPLOAD_BYTES,
    MAX_SSL_KEY_UPLOAD_BYTES,
    CertificateInstallError,
    OpenSSLUnavailableError,
    cert_exists,
    create_self_signed_cert,
    install_uploaded_cert,
    is_ssl_enabled,
    read_upload_bounded,
    regenerate_self_signed_cert,
    set_ssl_enabled,
)

router = APIRouter(tags=["settings"], include_in_schema=False)


@router.post("/settings/system/ssl", response_class=HTMLResponse, include_in_schema=False)
def settings_update_ssl(
    request: Request,
    ssl_enabled: str | None = Form(None),
    redirect_section: str = Form("ssl_certificate"),
    db: Session = Depends(get_db),
    user: str = Depends(require_role(ROLE_SYSTEM_UPDATE)),
):
    desired = ssl_enabled is not None
    if desired and not cert_exists():
        _emit_ssl_audit(
            db,
            action="toggled",
            user=user,
            status="error",
            message="SSL enable rejected: no certificate installed",
            details={"ssl_enabled": desired},
        )
        return render_settings(
            request,
            user,
            "system_settings",
            db=db,
            message=(
                "Cannot enable SSL: no certificate is installed. Upload a PEM certificate "
                "or create a self-signed certificate first."
            ),
            message_kind="error",
            section=redirect_section,
        )
    previous = is_ssl_enabled(db)
    set_ssl_enabled(db, desired)
    if desired != previous:
        mark_restart_required(db, reason="SSL listener setting changed.")
    _emit_ssl_audit(
        db,
        action="toggled",
        user=user,
        message=f"SSL listener {'enabled' if desired else 'disabled'} (restart required)",
        details={"ssl_enabled": desired, "previous": previous, "changed": desired != previous},
    )
    return render_settings(
        request,
        user,
        "system_settings",
        db=db,
        message=("SSL setting saved. Restart the application for the change to take effect."),
        message_kind="warning",
        section=redirect_section,
    )


@router.post("/settings/system/ssl-upload", response_class=HTMLResponse, include_in_schema=False)
async def settings_upload_ssl(
    request: Request,
    ssl_key: UploadFile = File(...),
    ssl_cert: UploadFile = File(...),
    redirect_section: str = Form("ssl_certificate"),
    db: Session = Depends(get_db),
    user: str = Depends(require_role(ROLE_SYSTEM_UPDATE)),
):
    try:
        key_bytes = await read_upload_bounded(ssl_key, MAX_SSL_KEY_UPLOAD_BYTES)
        cert_bytes = await read_upload_bounded(ssl_cert, MAX_SSL_CERT_UPLOAD_BYTES)
    except CertificateInstallError as exc:
        _emit_ssl_audit(
            db,
            action="upload_failed",
            user=user,
            status="error",
            message=f"SSL certificate upload rejected: {exc}",
            details={"reason": str(exc)},
        )
        return render_settings(
            request,
            user,
            "system_settings",
            db=db,
            message=str(exc),
            message_kind="error",
            section=redirect_section,
        )
    except Exception as exc:  # noqa: BLE001 — UploadFile.read failures are surfaced verbatim
        _emit_ssl_audit(
            db,
            action="upload_failed",
            user=user,
            status="error",
            message=f"SSL certificate upload failed: {exc}",
            details={"reason": str(exc)},
        )
        return render_settings(
            request,
            user,
            "system_settings",
            db=db,
            message=f"Failed to read upload: {exc}",
            message_kind="error",
            section=redirect_section,
        )

    try:
        metadata = install_uploaded_cert(key_bytes, cert_bytes)
    except CertificateInstallError as exc:
        _emit_ssl_audit(
            db,
            action="upload_failed",
            user=user,
            status="error",
            message=f"SSL certificate upload rejected: {exc}",
            details={"reason": str(exc)},
        )
        return render_settings(
            request,
            user,
            "system_settings",
            db=db,
            message=str(exc),
            message_kind="error",
            section=redirect_section,
        )

    mark_restart_required(db, reason="SSL certificate uploaded.")
    _emit_ssl_audit(
        db,
        action="uploaded",
        user=user,
        message=f"SSL certificate uploaded (CN={metadata.get('common_name') or 'unknown'})",
        details={
            "common_name": metadata.get("common_name") or "",
            "not_after": metadata.get("not_after_iso") or "",
            "fingerprint": metadata.get("fingerprint") or "",
        },
    )
    return render_settings(
        request,
        user,
        "system_settings",
        db=db,
        message=("SSL certificate uploaded. Restart the application for the new certificate to take effect."),
        message_kind="warning",
        section=redirect_section,
    )


@router.post("/settings/system/ssl-regenerate", response_class=HTMLResponse, include_in_schema=False)
def settings_regenerate_ssl(
    request: Request,
    redirect_section: str = Form("ssl_certificate"),
    db: Session = Depends(get_db),
    user: str = Depends(require_role(ROLE_SYSTEM_UPDATE)),
):
    already_existed = cert_exists()
    user_message = ""
    try:
        if already_existed:
            metadata = regenerate_self_signed_cert(db)
            action = "regenerated"
            user_message = "Self-signed certificate regenerated."
        else:
            metadata = create_self_signed_cert(db)
            action = "created"
            user_message = "Self-signed certificate created."
        mark_restart_required(db, reason=user_message)
        _emit_ssl_audit(
            db,
            action=action,
            user=user,
            message=f"{user_message} (CN={metadata.get('common_name') or 'unknown'})",
            details={
                "common_name": metadata.get("common_name") or "",
                "not_after": metadata.get("not_after_iso") or "",
                "fingerprint": metadata.get("fingerprint") or "",
                "source": metadata.get("source") or "",
            },
        )
    except OpenSSLUnavailableError as exc:
        _emit_ssl_audit(
            db,
            action="regenerate_failed",
            user=user,
            status="error",
            message=f"Self-signed certificate generation failed: {exc}",
            details={"reason": str(exc)},
        )
        return render_settings(
            request,
            user,
            "system_settings",
            db=db,
            message=str(exc),
            message_kind="error",
            section=redirect_section,
        )
    except RuntimeError as exc:
        _emit_ssl_audit(
            db,
            action="regenerate_failed",
            user=user,
            status="error",
            message=f"Self-signed certificate generation failed: {exc}",
            details={"reason": str(exc)},
        )
        return render_settings(
            request,
            user,
            "system_settings",
            db=db,
            message=f"Failed to generate self-signed certificate: {exc}",
            message_kind="error",
            section=redirect_section,
        )

    return render_settings(
        request,
        user,
        "system_settings",
        db=db,
        message=(f"{user_message} Restart the application for the new certificate to take effect."),
        message_kind="warning",
        section=redirect_section,
    )


def _emit_ssl_audit(
    db,
    *,
    action: str,
    user: str,
    message: str,
    status: str = "success",
    details: dict[str, Any] | None = None,
) -> None:
    emit_activity_event(
        db,
        event_type=f"system.ssl_{action}",
        level=LOG_LEVEL_WARNING,
        category=LOG_CATEGORY_SECURITY,
        status=status,
        actor_type="user",
        actor_label=user,
        message=message,
        details=details or {},
    )


def _le_start_form_kwargs(
    *,
    email: str,
    root_dns_domain: str,
    common_name: str,
    subject_alt_names: str,
    challenge_type: str,
    zone_id: str,
    staging: str | None,
    renew_before_expiry_days: int,
    scheduled_restart_enabled: str | None,
    scheduled_restart_time: str,
) -> dict[str, Any]:
    return {
        "email": email,
        "root_dns_domain": root_dns_domain,
        "common_name": common_name,
        "subject_alt_names": subject_alt_names,
        "challenge_type": challenge_type,
        "zone_id": int(zone_id) if str(zone_id).strip() else None,
        "staging": staging is not None,
        "renew_before_expiry_days": renew_before_expiry_days,
        "scheduled_restart_enabled": (
            True if scheduled_restart_enabled is None else scheduled_restart_enabled is not None
        ),
        "scheduled_restart_time": scheduled_restart_time,
    }


def _le_issued_message(db, config: dict[str, Any]) -> str:
    message = "Let's Encrypt certificate installed. Restart the application to use it."
    message += letsencrypt.http_auto_renew_notice(db, config)
    return message


def _apply_le_start_result(db, result: dict[str, Any], *, user: str) -> tuple[str, str]:
    if result.get("status") == "issued":
        mark_restart_required(db, reason="Let's Encrypt certificate installed.")
        config = result.get("config") or {}
        return (_le_issued_message(db, config), "warning")
    return (
        "Let's Encrypt enrollment started. Complete the challenge, then continue enrollment.",
        "success",
    )


def _emit_le_started(db, result: dict[str, Any], *, user: str) -> None:
    config = result.get("config") or {}
    _emit_ssl_audit(
        db,
        action="letsencrypt_start",
        user=user,
        message="Let's Encrypt enrollment started",
        details={
            "root_dns_domain": config.get("root_dns_domain", ""),
            "common_name": config.get("common_name", ""),
            "subject_alt_names": config.get("subject_alt_names", []),
            "zone_id": config.get("zone_id"),
            "challenge_type": config.get("challenge_type", ""),
        },
    )


def _run_le_auto_enrollment_sync(kwargs: dict[str, Any], *, user: str) -> None:
    def progress(phase: str, percent: int, message: str) -> None:
        with SessionLocal() as progress_db:
            letsencrypt.write_enrollment_progress(
                progress_db,
                phase=phase,
                percent=percent,
                message=message,
            )

    try:
        with SessionLocal() as db:
            result = letsencrypt.start_enrollment(db, progress_cb=progress, **kwargs)
            message, _kind = _apply_le_start_result(db, result, user=user)
            _emit_le_started(db, result, user=user)
            status = result.get("status") or ""
        with SessionLocal() as progress_db:
            letsencrypt.write_enrollment_progress(
                progress_db,
                phase="complete",
                percent=100,
                message=message,
                done=True,
                result_status=status,
            )
    except letsencrypt.LetsEncryptError as exc:
        with SessionLocal() as progress_db:
            letsencrypt.write_enrollment_progress(
                progress_db,
                phase="error",
                percent=0,
                message=str(exc),
                done=True,
                error=str(exc),
            )
    except Exception as exc:
        LOGGER.exception("Let's Encrypt auto enrollment failed")
        with SessionLocal() as progress_db:
            letsencrypt.write_enrollment_progress(
                progress_db,
                phase="error",
                percent=0,
                message=str(exc),
                done=True,
                error=str(exc),
            )


async def _run_le_auto_enrollment(kwargs: dict[str, Any], *, user: str) -> None:
    try:
        await asyncio.to_thread(_run_le_auto_enrollment_sync, kwargs, user=user)
    finally:
        with SessionLocal() as db:
            letsencrypt.mark_enrollment_worker_finished(db)


@router.get("/settings/system/ssl-letsencrypt/progress", include_in_schema=False)
def settings_letsencrypt_progress(
    db: Session = Depends(get_db),
    user: str = Depends(require_role(ROLE_SYSTEM_UPDATE)),
):
    payload = letsencrypt.get_enrollment_progress(db)
    if payload.get("done") and not payload.get("error"):
        payload["restart_required"] = is_restart_required(db)
    return JSONResponse(payload)


@router.post("/settings/system/ssl-letsencrypt/start-async", include_in_schema=False)
async def settings_letsencrypt_start_async(
    request: Request,
    email: str = Form(...),
    root_dns_domain: str = Form(...),
    common_name: str = Form(...),
    subject_alt_names: str = Form(""),
    challenge_type: str = Form("dns-01"),
    zone_id: str = Form(""),
    staging: str | None = Form(None),
    renew_before_expiry_days: int = Form(letsencrypt.DEFAULT_RENEW_BEFORE_DAYS),
    scheduled_restart_enabled: str | None = Form(None),
    scheduled_restart_time: str = Form(letsencrypt.DEFAULT_SCHEDULED_RESTART_TIME),
    db: Session = Depends(get_db),
    user: str = Depends(require_role(ROLE_SYSTEM_UPDATE)),
):
    if challenge_type != letsencrypt.CHALLENGE_DNS or not str(zone_id).strip():
        _emit_ssl_audit(
            db,
            action="letsencrypt_start_failed",
            user=user,
            status="error",
            message="Let's Encrypt async enrollment rejected: DNS-01 with API zone required",
            details={"challenge_type": challenge_type, "zone_id": zone_id},
        )
        return JSONResponse(
            {"detail": "Async enrollment requires DNS-01 with an API configured zone."},
            status_code=400,
        )
    kwargs = _le_start_form_kwargs(
        email=email,
        root_dns_domain=root_dns_domain,
        common_name=common_name,
        subject_alt_names=subject_alt_names,
        challenge_type=challenge_type,
        zone_id=zone_id,
        staging=staging,
        renew_before_expiry_days=renew_before_expiry_days,
        scheduled_restart_enabled=scheduled_restart_enabled,
        scheduled_restart_time=scheduled_restart_time,
    )
    if not letsencrypt.try_begin_enrollment(db):
        _emit_ssl_audit(
            db,
            action="letsencrypt_start_failed",
            user=user,
            status="error",
            message="Let's Encrypt async enrollment rejected: already in progress",
        )
        return JSONResponse(
            {"detail": "Let's Encrypt enrollment is already in progress."}, status_code=HTTP_409_CONFLICT
        )
    _emit_ssl_audit(
        db,
        action="letsencrypt_start_async",
        user=user,
        message="Let's Encrypt async enrollment started",
        details={
            "root_dns_domain": kwargs.get("root_dns_domain", ""),
            "common_name": kwargs.get("common_name", ""),
            "zone_id": kwargs.get("zone_id"),
            "challenge_type": kwargs.get("challenge_type", ""),
        },
    )
    asyncio.create_task(_run_le_auto_enrollment(kwargs, user=user))
    return JSONResponse({"status": "started"}, status_code=HTTP_202_ACCEPTED)


@router.post("/settings/system/ssl-letsencrypt/start", response_class=HTMLResponse, include_in_schema=False)
def settings_letsencrypt_start(
    request: Request,
    email: str = Form(...),
    root_dns_domain: str = Form(...),
    common_name: str = Form(...),
    subject_alt_names: str = Form(""),
    challenge_type: str = Form("dns-01"),
    zone_id: str = Form(""),
    staging: str | None = Form(None),
    renew_before_expiry_days: int = Form(letsencrypt.DEFAULT_RENEW_BEFORE_DAYS),
    scheduled_restart_enabled: str | None = Form(None),
    scheduled_restart_time: str = Form(letsencrypt.DEFAULT_SCHEDULED_RESTART_TIME),
    db: Session = Depends(get_db),
    user: str = Depends(require_role(ROLE_SYSTEM_UPDATE)),
):
    try:
        kwargs = _le_start_form_kwargs(
            email=email,
            root_dns_domain=root_dns_domain,
            common_name=common_name,
            subject_alt_names=subject_alt_names,
            challenge_type=challenge_type,
            zone_id=zone_id,
            staging=staging,
            renew_before_expiry_days=renew_before_expiry_days,
            scheduled_restart_enabled=scheduled_restart_enabled,
            scheduled_restart_time=scheduled_restart_time,
        )
        result = letsencrypt.start_enrollment(db, **kwargs)
        message, kind = _apply_le_start_result(db, result, user=user)
        _emit_le_started(db, result, user=user)
    except LetsEncryptError as exc:
        return render_settings(
            request,
            user,
            "system_settings",
            db=db,
            message=str(exc),
            message_kind="error",
            section="ssl_certificate",
        )
    return render_settings(
        request, user, "system_settings", db=db, message=message, message_kind=kind, section="ssl_certificate"
    )


@router.post("/settings/system/ssl-letsencrypt/continue", response_class=HTMLResponse, include_in_schema=False)
def settings_letsencrypt_continue(
    request: Request,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(ROLE_SYSTEM_UPDATE)),
):
    try:
        result = letsencrypt.continue_enrollment(db)
        config = result.get("config") or {}
        mark_restart_required(db, reason="Let's Encrypt certificate installed.")
        _emit_ssl_audit(
            db,
            action="letsencrypt_continue",
            user=user,
            message="Let's Encrypt certificate installed",
            details={
                "root_dns_domain": config.get("root_dns_domain", ""),
                "common_name": config.get("common_name", ""),
                "subject_alt_names": config.get("subject_alt_names", []),
            },
        )
    except LetsEncryptError as exc:
        return render_settings(
            request,
            user,
            "system_settings",
            db=db,
            message=str(exc),
            message_kind="error",
            section="ssl_certificate",
        )
    issued_message = _le_issued_message(db, config)
    return render_settings(
        request,
        user,
        "system_settings",
        db=db,
        message=issued_message,
        message_kind="warning",
        section="ssl_certificate",
    )


@router.post("/settings/system/ssl-letsencrypt/cancel", response_class=HTMLResponse, include_in_schema=False)
def settings_letsencrypt_cancel(
    request: Request,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(ROLE_SYSTEM_UPDATE)),
):
    letsencrypt.cancel_enrollment(db)
    _emit_ssl_audit(db, action="letsencrypt_cancel", user=user, message="Let's Encrypt enrollment cancelled")
    return render_settings(
        request,
        user,
        "system_settings",
        db=db,
        message="Let's Encrypt enrollment cancelled.",
        section="ssl_certificate",
    )


@router.post("/settings/system/ssl-letsencrypt/config", response_class=HTMLResponse, include_in_schema=False)
def settings_letsencrypt_config(
    request: Request,
    email: str = Form(""),
    root_dns_domain: str = Form(""),
    common_name: str = Form(""),
    subject_alt_names: str = Form(""),
    challenge_type: str = Form("dns-01"),
    zone_id: str = Form(""),
    staging: str | None = Form(None),
    renew_before_expiry_days: int = Form(letsencrypt.DEFAULT_RENEW_BEFORE_DAYS),
    scheduled_restart_enabled: str | None = Form(None),
    scheduled_restart_time: str = Form(letsencrypt.DEFAULT_SCHEDULED_RESTART_TIME),
    auto_renew_enabled: str | None = Form(None),
    config_notice: str = Form(""),
    db: Session = Depends(get_db),
    user: str = Depends(require_role(ROLE_SYSTEM_UPDATE)),
):
    notice = (config_notice or "").strip()
    try:
        existing = letsencrypt.get_config(db) or {}
        challenge = challenge_type or existing.get("challenge_type", letsencrypt.CHALLENGE_DNS)
        zone_id_val = int(zone_id) if str(zone_id).strip() else existing.get("zone_id")
        if challenge == letsencrypt.CHALLENGE_HTTP:
            zone_id_val = None
        if notice == "auto_renew_on" and not letsencrypt.auto_renew_supported(challenge, zone_id_val):
            raise LetsEncryptError(
                "Automatic certificate renewal requires an automated DNS challenge zone (not Manual DNS instructions)."
            )
        letsencrypt.save_config(
            db,
            email=email or existing.get("email", ""),
            root_dns_domain=root_dns_domain or existing.get("root_dns_domain", ""),
            common_name=common_name or existing.get("common_name", ""),
            subject_alt_names=subject_alt_names or existing.get("subject_alt_names", []),
            challenge_type=challenge_type or existing.get("challenge_type", "dns-01"),
            zone_id=int(zone_id) if str(zone_id).strip() else existing.get("zone_id"),
            staging=staging is not None,
            renew_before_expiry_days=renew_before_expiry_days,
            scheduled_restart_enabled=scheduled_restart_enabled is not None,
            scheduled_restart_time=scheduled_restart_time,
            auto_renew_enabled=auto_renew_enabled is not None,
        )
        _emit_ssl_audit(
            db,
            action="letsencrypt_config",
            user=user,
            message="Let's Encrypt settings saved",
            details={"config_notice": notice, "auto_renew_enabled": auto_renew_enabled is not None},
        )
    except LetsEncryptError as exc:
        return render_settings(
            request,
            user,
            "system_settings",
            db=db,
            message=str(exc),
            message_kind="error",
            section="ssl_certificate",
        )
    if notice == "auto_renew_on":
        message = "Automatic certificate renewal was turned on."
    elif notice == "auto_renew_off":
        message = "Automatic certificate renewal was turned off."
    else:
        message = "Let's Encrypt settings saved."
    return render_settings(request, user, "system_settings", db=db, message=message, section="ssl_certificate")


@router.get("/.well-known/acme-challenge/{token}", response_class=PlainTextResponse, include_in_schema=False)
def letsencrypt_http_challenge(token: str, db: Session = Depends(get_db)):
    response = letsencrypt.http_challenge_response(db, token)
    if response is None:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Challenge token not found")
    return PlainTextResponse(response)
