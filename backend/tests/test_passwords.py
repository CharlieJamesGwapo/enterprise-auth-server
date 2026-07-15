"""Unit tests for the password strength policy (per-rule coverage)."""

from __future__ import annotations

import pytest

from app.core.exceptions import ValidationError
from app.core.passwords import validate_password_strength

STRONG = "Str0ng!Passw0rd"


def test_too_short_rejected():
    with pytest.raises(ValidationError) as exc:
        validate_password_strength("Ab1!")
    assert "8 characters" in str(exc.value)


def test_missing_lowercase_rejected():
    with pytest.raises(ValidationError) as exc:
        validate_password_strength("ALLUPPER1!")
    assert "lowercase" in str(exc.value)


def test_missing_uppercase_rejected():
    with pytest.raises(ValidationError) as exc:
        validate_password_strength("alllower1!")
    assert "uppercase" in str(exc.value)


def test_missing_digit_rejected():
    with pytest.raises(ValidationError) as exc:
        validate_password_strength("NoDigitsHere!")
    assert "digit" in str(exc.value)


def test_missing_symbol_rejected():
    with pytest.raises(ValidationError) as exc:
        validate_password_strength("NoSymbol123")
    assert "symbol" in str(exc.value)


def test_common_password_rejected(monkeypatch):
    """The denylist is checked case-insensitively after the character-class
    rules pass. None of the shipped ``_COMMON`` entries happen to satisfy
    every character-class rule simultaneously (they're all lowercase-only),
    so to exercise this branch in isolation we monkeypatch the denylist with
    an entry that does — without changing production behavior/data.
    """
    import app.core.passwords as passwords_module

    candidate = "Str0ng!Passw0rd"
    monkeypatch.setattr(passwords_module, "_COMMON", {candidate.lower()})
    with pytest.raises(ValidationError) as exc:
        validate_password_strength(candidate)
    assert "too common" in str(exc.value)


def test_known_denylist_entries_present():
    # Sanity check the real (unmodified) denylist used in production.
    from app.core.passwords import _COMMON

    assert "password" in _COMMON
    assert "welcome1" in _COMMON


def test_strong_password_passes():
    validate_password_strength(STRONG)  # no raise
