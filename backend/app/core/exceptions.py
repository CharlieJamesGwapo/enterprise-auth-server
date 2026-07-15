"""Application exception hierarchy and FastAPI handlers."""

from __future__ import annotations

from fastapi import FastAPI, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.logging import get_logger

logger = get_logger(__name__)


class AppError(Exception):
    """Base class for all application errors."""

    status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR
    error_code: str = "internal_error"
    message: str = "An unexpected error occurred."

    def __init__(self, message: str | None = None, *, detail: object = None) -> None:
        self.message = message or self.message
        self.detail = detail
        super().__init__(self.message)


class AuthError(AppError):
    status_code = status.HTTP_401_UNAUTHORIZED
    error_code = "authentication_error"
    message = "Authentication failed."


class PermissionDenied(AppError):
    status_code = status.HTTP_403_FORBIDDEN
    error_code = "permission_denied"
    message = "You do not have permission to perform this action."


class NotFoundError(AppError):
    status_code = status.HTTP_404_NOT_FOUND
    error_code = "not_found"
    message = "Resource not found."


class ConflictError(AppError):
    status_code = status.HTTP_409_CONFLICT
    error_code = "conflict"
    message = "Resource already exists."


class ValidationError(AppError):
    status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
    error_code = "validation_error"
    message = "Invalid input."


class RateLimited(AppError):
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    error_code = "rate_limited"
    message = "Too many requests. Please try again later."


class ServiceUnavailable(AppError):
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    error_code = "service_unavailable"
    message = "A dependency is temporarily unavailable. Please retry."


class AccountLocked(AuthError):
    error_code = "account_locked"
    message = "Account temporarily locked due to too many failed attempts."


class TokenReplayError(AuthError):
    error_code = "token_replay_detected"
    message = "Refresh token reuse detected."


def _payload(exc: AppError) -> dict[str, object]:
    body: dict[str, object] = {"error": exc.error_code, "detail": exc.message}
    if exc.detail is not None:
        body["context"] = exc.detail
    return body


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def _handle_app_error(_: Request, exc: AppError) -> JSONResponse:
        if exc.status_code >= 500:
            logger.error("app_error", extra={"error_code": exc.error_code}, exc_info=exc)
        return JSONResponse(status_code=exc.status_code, content=_payload(exc))

    @app.exception_handler(RequestValidationError)
    async def _handle_validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": "validation_error",
                "detail": "Request validation failed.",
                "context": jsonable_encoder(exc.errors()),
            },
        )

    @app.exception_handler(StarletteHTTPException)
    async def _handle_http_exception(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": "http_error", "detail": str(exc.detail)},
        )

    @app.exception_handler(Exception)
    async def _handle_unexpected(_: Request, exc: Exception) -> JSONResponse:
        logger.error("unhandled_exception", exc_info=exc)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": "internal_error", "detail": "An unexpected error occurred."},
        )
