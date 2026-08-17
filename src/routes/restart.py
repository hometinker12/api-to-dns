from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlmodel import Session
from starlette.status import HTTP_303_SEE_OTHER

from ..activity_logging import (
    emit_activity_event,
)
from ..db import get_db
from ..http_utils import (
    wants_json_response,
)
from ..models import (
    LOG_LEVEL_WARNING,
)
from ..rbac import (
    ROLE_SYSTEM_UPDATE,
    require_role,
)
from ..restart import (
    clear_restart_required,
    perform_application_restart,
)
from ..web import (
    nav_context,
)

router = APIRouter(tags=["system"], include_in_schema=False)


@router.post("/system/restart", include_in_schema=False)
def system_restart(
    request: Request,
    db: Session = Depends(get_db),
    user: str = Depends(require_role(ROLE_SYSTEM_UPDATE)),
):
    preview = nav_context(db, user).get("restart_preview", {})
    clear_restart_required(db)
    emit_activity_event(
        db,
        event_type="system.restart_requested",
        level=LOG_LEVEL_WARNING,
        status="success",
        actor_type="user",
        actor_label=user,
        message="Application restart requested",
        details=preview,
    )
    perform_application_restart(scheduled=False)
    if wants_json_response(request):
        return JSONResponse({"status": "restarting", **preview})
    return RedirectResponse(url=request.headers.get("referer") or "/admin", status_code=HTTP_303_SEE_OTHER)
