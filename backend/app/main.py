"""FastAPI application factory and entrypoint."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.router import api_router
from app.core.config import settings
from app.core.exceptions import register_exception_handlers
from app.core.logging import configure_logging, get_logger
from app.middleware.rate_limit import RateLimitMiddleware
from app.middleware.security import SecurityHeadersMiddleware
from app.redis.client import close_redis

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(_: FastAPI):
    configure_logging("DEBUG" if settings.DEBUG else "INFO")
    logger.info("app_startup", extra={"env": settings.ENV})
    yield
    await close_redis()
    logger.info("app_shutdown")


def create_app() -> FastAPI:
    docs_kwargs = (
        {"docs_url": None, "redoc_url": None, "openapi_url": None}
        if settings.is_production
        else {"docs_url": "/docs", "redoc_url": "/redoc", "openapi_url": "/openapi.json"}
    )
    app = FastAPI(
        title=settings.PROJECT_NAME,
        version="0.1.0",
        lifespan=lifespan,
        **docs_kwargs,
    )

    app.add_middleware(SecurityHeadersMiddleware, hsts=settings.is_production)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    register_exception_handlers(app)
    app.include_router(api_router, prefix=settings.API_V1_PREFIX)
    return app


app = create_app()
