"""Email delivery backends and message model."""

from __future__ import annotations

from app.services.email.backends import (
    OUTBOX,
    ConsoleEmailBackend,
    EmailBackend,
    EmailMessage,
    InMemoryEmailBackend,
    SMTPEmailBackend,
    get_email_backend,
)

__all__ = [
    "OUTBOX",
    "ConsoleEmailBackend",
    "EmailBackend",
    "EmailMessage",
    "InMemoryEmailBackend",
    "SMTPEmailBackend",
    "get_email_backend",
]
