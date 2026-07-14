"""Notification service: builds and dispatches transactional emails."""

from __future__ import annotations

from app.core.logging import get_logger
from app.services.email import templates
from app.services.email.backends import EmailBackend

logger = get_logger("notifications")


class NotificationService:
    def __init__(self, backend: EmailBackend) -> None:
        self.backend = backend

    async def _send(self, message) -> None:
        try:
            await self.backend.send(message)
        except Exception:  # pragma: no cover - never break the request on email failure
            logger.error("email_delivery_failed", extra={"to": message.to}, exc_info=True)

    async def send_welcome(self, to: str, name: str) -> None:
        await self._send(templates.welcome_email(to, name))

    async def send_verification(self, to: str, token: str) -> None:
        await self._send(templates.verification_email(to, token))

    async def send_password_reset(self, to: str, token: str) -> None:
        await self._send(templates.password_reset_email(to, token))

    async def send_password_changed(self, to: str) -> None:
        await self._send(templates.password_changed_email(to))

    async def send_email_change(self, to: str, token: str) -> None:
        await self._send(templates.email_change_email(to, token))

    async def send_new_device_alert(self, to: str, *, device: str, browser: str, ip: str) -> None:
        await self._send(templates.new_device_email(to, device=device, browser=browser, ip=ip))
