"""Password strength policy validation."""

from __future__ import annotations

import re

from app.core.exceptions import ValidationError

# A tiny embedded denylist of the most common passwords. In production this
# would be backed by a larger list (e.g. Have I Been Pwned k-anonymity API).
_COMMON = {
    "password",
    "password1",
    "12345678",
    "qwerty123",
    "letmein1",
    "welcome1",
    "admin123",
    "iloveyou",
    "changeme",
}

_MIN_LENGTH = 8


def validate_password_strength(password: str) -> None:
    """Raise ValidationError if the password fails the strength policy."""
    problems: list[str] = []
    if len(password) < _MIN_LENGTH:
        problems.append(f"at least {_MIN_LENGTH} characters")
    if not re.search(r"[a-z]", password):
        problems.append("a lowercase letter")
    if not re.search(r"[A-Z]", password):
        problems.append("an uppercase letter")
    if not re.search(r"\d", password):
        problems.append("a digit")
    if not re.search(r"[^A-Za-z0-9]", password):
        problems.append("a symbol")

    if problems:
        raise ValidationError(f"Password must contain {', '.join(problems)}.")
    if password.lower() in _COMMON:
        raise ValidationError("This password is too common. Choose a stronger one.")
