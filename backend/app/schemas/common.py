"""Shared response schemas."""

from __future__ import annotations

from pydantic import BaseModel


class Message(BaseModel):
    detail: str


class ErrorResponse(BaseModel):
    error: str
    detail: str


class Page[T](BaseModel):
    items: list[T]
    total: int
    limit: int
    offset: int
