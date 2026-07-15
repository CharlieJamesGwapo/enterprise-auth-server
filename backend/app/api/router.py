"""Aggregate v1 API router."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import auth, email, health, oauth, sessions, two_factor, users
from app.schemas.common import ErrorResponse

# Shared OpenAPI documentation for error responses common to authenticated,
# permission-gated, validated, and rate-limited endpoints. Additive only —
# does not affect runtime behavior.
COMMON_ERRORS: dict[int | str, dict[str, object]] = {
    401: {"model": ErrorResponse},
    403: {"model": ErrorResponse},
    422: {"model": ErrorResponse},
    429: {"model": ErrorResponse},
}

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(auth.router, responses=COMMON_ERRORS)
api_router.include_router(email.router, responses=COMMON_ERRORS)
api_router.include_router(oauth.router, responses=COMMON_ERRORS)
api_router.include_router(two_factor.router, responses=COMMON_ERRORS)
api_router.include_router(sessions.router, responses=COMMON_ERRORS)
api_router.include_router(users.router, responses=COMMON_ERRORS)
