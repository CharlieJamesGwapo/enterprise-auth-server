"""Symmetric encryption for secrets at rest (TOTP secrets).

Uses Fernet (AES-128-CBC + HMAC-SHA256) with the key from ``ENCRYPTION_KEY``.
The key is validated at import time so a misconfigured deployment fails fast
rather than at first 2FA setup.
"""

from __future__ import annotations

from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import settings


class DecryptionError(RuntimeError):
    """Raised when stored ciphertext cannot be decrypted (tampering/key change)."""


@lru_cache
def _fernet() -> Fernet:
    try:
        return Fernet(settings.ENCRYPTION_KEY.encode())
    except (ValueError, TypeError) as exc:  # pragma: no cover - config error
        raise RuntimeError(
            "ENCRYPTION_KEY must be a urlsafe base64-encoded 32-byte Fernet key."
        ) from exc


def encrypt(plaintext: str) -> str:
    """Encrypt a UTF-8 string, returning urlsafe-base64 ciphertext."""
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str) -> str:
    """Decrypt ciphertext produced by :func:`encrypt`."""
    try:
        return _fernet().decrypt(ciphertext.encode()).decode()
    except InvalidToken as exc:
        raise DecryptionError("Unable to decrypt stored secret.") from exc
