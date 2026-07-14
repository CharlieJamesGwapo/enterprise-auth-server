"""HTML/text email templates. Each builder returns a ready-to-send EmailMessage."""

from __future__ import annotations

from app.core.config import settings
from app.services.email.backends import EmailMessage

_STYLE = (
    "font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;"
    "line-height:1.5;color:#1a1a2e"
)


def _wrap(title: str, body_html: str) -> str:
    return (
        f'<div style="{_STYLE};max-width:520px;margin:0 auto">'
        f'<h2 style="color:#0f3460">{title}</h2>{body_html}'
        f'<hr style="border:none;border-top:1px solid #eee;margin:24px 0">'
        f'<p style="font-size:12px;color:#888">{settings.EMAIL_FROM_NAME}</p></div>'
    )


def _button(url: str, label: str) -> str:
    return (
        f'<p><a href="{url}" style="background:#0f3460;color:#fff;padding:10px 18px;'
        f'border-radius:6px;text-decoration:none;display:inline-block">{label}</a></p>'
        f'<p style="font-size:13px;color:#666">Or copy this link: {url}</p>'
    )


def welcome_email(to: str, name: str) -> EmailMessage:
    display = name or to
    html = _wrap(
        "Welcome!",
        f"<p>Hi {display}, your account has been created. We're glad to have you on board.</p>",
    )
    return EmailMessage(
        to=to,
        subject=f"Welcome to {settings.EMAIL_FROM_NAME}",
        html=html,
        text=f"Hi {display}, your account has been created.",
    )


def verification_email(to: str, token: str) -> EmailMessage:
    url = f"{settings.APP_BASE_URL}/verify-email?token={token}"
    html = _wrap(
        "Verify your email",
        "<p>Confirm your email address to finish setting up your account.</p>"
        + _button(url, "Verify email"),
    )
    return EmailMessage(
        to=to,
        subject="Verify your email address",
        html=html,
        text=f"Verify your email: {url}",
    )


def password_reset_email(to: str, token: str) -> EmailMessage:
    url = f"{settings.APP_BASE_URL}/reset-password?token={token}"
    mins = settings.PASSWORD_RESET_EXPIRE_MINUTES
    html = _wrap(
        "Reset your password",
        f"<p>We received a request to reset your password. This link expires in "
        f"{mins} minutes. If you didn't request this, you can ignore this email.</p>"
        + _button(url, "Reset password"),
    )
    return EmailMessage(
        to=to,
        subject="Reset your password",
        html=html,
        text=f"Reset your password (expires in {mins} min): {url}",
    )


def password_changed_email(to: str) -> EmailMessage:
    html = _wrap(
        "Your password was changed",
        "<p>Your password was just changed. If this wasn't you, reset your "
        "password immediately and contact support.</p>",
    )
    return EmailMessage(
        to=to,
        subject="Your password was changed",
        html=html,
        text="Your password was just changed. If this wasn't you, act now.",
    )


def email_change_email(to: str, token: str) -> EmailMessage:
    url = f"{settings.APP_BASE_URL}/confirm-email-change?token={token}"
    html = _wrap(
        "Confirm your new email",
        "<p>Confirm this address to complete your email change.</p>"
        + _button(url, "Confirm new email"),
    )
    return EmailMessage(
        to=to,
        subject="Confirm your new email address",
        html=html,
        text=f"Confirm your new email: {url}",
    )


def new_device_email(to: str, *, device: str, browser: str, ip: str) -> EmailMessage:
    html = _wrap(
        "New sign-in to your account",
        f"<p>A new sign-in was detected:</p><ul>"
        f"<li>Device: {device}</li><li>Browser: {browser}</li>"
        f"<li>IP address: {ip}</li></ul>"
        "<p>If this wasn't you, change your password and review your sessions.</p>",
    )
    return EmailMessage(
        to=to,
        subject="New sign-in to your account",
        html=html,
        text=f"New sign-in: device={device}, browser={browser}, ip={ip}.",
    )
