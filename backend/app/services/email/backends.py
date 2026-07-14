"""Pluggable email backends.

- ``smtp``     → real delivery via aiosmtplib (prod / MailHog in dev).
- ``console``  → logs the message (local dev without a mail server).
- ``memory``   → appends to a process-global OUTBOX (tests assert on this).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from email.message import EmailMessage as MIMEMessage

import aiosmtplib

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger("email")


@dataclass
class EmailMessage:
    to: str
    subject: str
    html: str
    text: str


# Process-global outbox used by the in-memory backend (tests inspect/clear this).
OUTBOX: list[EmailMessage] = []


class EmailBackend(ABC):
    @abstractmethod
    async def send(self, message: EmailMessage) -> None: ...


class InMemoryEmailBackend(EmailBackend):
    async def send(self, message: EmailMessage) -> None:
        OUTBOX.append(message)


class ConsoleEmailBackend(EmailBackend):
    async def send(self, message: EmailMessage) -> None:
        logger.info(
            "email_sent",
            extra={"to": message.to, "subject": message.subject, "backend": "console"},
        )


class SMTPEmailBackend(EmailBackend):
    async def send(self, message: EmailMessage) -> None:
        mime = MIMEMessage()
        mime["From"] = f"{settings.EMAIL_FROM_NAME} <{settings.EMAIL_FROM}>"
        mime["To"] = message.to
        mime["Subject"] = message.subject
        mime.set_content(message.text)
        mime.add_alternative(message.html, subtype="html")

        await aiosmtplib.send(
            mime,
            hostname=settings.EMAIL_HOST,
            port=settings.EMAIL_PORT,
            username=settings.EMAIL_USERNAME or None,
            password=settings.EMAIL_PASSWORD or None,
            start_tls=settings.EMAIL_USE_TLS,
        )
        logger.info("email_sent", extra={"to": message.to, "backend": "smtp"})


def get_email_backend() -> EmailBackend:
    match settings.EMAIL_BACKEND:
        case "smtp":
            return SMTPEmailBackend()
        case "memory":
            return InMemoryEmailBackend()
        case _:
            return ConsoleEmailBackend()
