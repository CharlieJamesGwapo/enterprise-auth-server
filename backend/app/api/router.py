"""Aggregate v1 API router."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import auth, health, sessions, two_factor, users

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(two_factor.router)
api_router.include_router(sessions.router)
api_router.include_router(users.router)
