from fastapi import FastAPI

from .api_keys import router as api_keys_router
from .auth_pages import router as auth_pages_router
from .dns_api import router as dns_api_router
from .dns_browser import router as dns_browser_router
from .health import router as health_router
from .restart import router as restart_router
from .settings_alerts import router as settings_alerts_router
from .settings_backup import router as settings_backup_router
from .settings_pages import router as settings_pages_router
from .settings_plugins import router as settings_plugins_router
from .settings_ssl import router as settings_ssl_router
from .settings_system import router as settings_system_router
from .settings_users import router as settings_users_router
from .zones import router as zones_router


def include_routers(app: FastAPI) -> None:
    app.include_router(health_router)
    app.include_router(auth_pages_router)
    app.include_router(dns_api_router)
    app.include_router(dns_browser_router)
    app.include_router(zones_router)
    app.include_router(api_keys_router)
    app.include_router(settings_pages_router)
    app.include_router(settings_users_router)
    app.include_router(settings_plugins_router)
    app.include_router(settings_system_router)
    app.include_router(settings_ssl_router)
    app.include_router(settings_backup_router)
    app.include_router(settings_alerts_router)
    app.include_router(restart_router)
