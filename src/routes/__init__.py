from fastapi import FastAPI

from .auth_pages import router as auth_pages_router
from .dns_api import router as dns_api_router
from .dns_browser import router as dns_browser_router
from .health import router as health_router


def include_routers(app: FastAPI) -> None:
    app.include_router(health_router)
    app.include_router(auth_pages_router)
    app.include_router(dns_api_router)
    app.include_router(dns_browser_router)
