"""Structured audit logging.

Emits security-relevant events through the structured JSON logger. When the
dedicated audit-log persistence slice lands, this is the single choke point to
also write rows to the ``audit_logs`` table — call sites won't change.
"""

from __future__ import annotations

from app.core.logging import get_logger

_logger = get_logger("audit")


def audit(event: str, *, user_id: str | None = None, **fields: object) -> None:
    """Record an audit event with structured context."""
    _logger.info(event, extra={"audit_event": event, "user_id": user_id, **fields})
