"""Safe User-Agent parsing into structured device metadata.

Wraps the ``user-agents`` library so the rest of the app depends on a small,
stable dataclass rather than the parser's API. Never raises on malformed input.
"""

from __future__ import annotations

from dataclasses import dataclass

from user_agents import parse as _ua_parse


@dataclass(frozen=True)
class DeviceInfo:
    device_name: str
    device_type: str  # Desktop | Mobile | Tablet | Bot | Unknown
    browser: str
    browser_version: str
    operating_system: str
    operating_system_version: str
    user_agent: str


def _clean(value: str | None) -> str:
    if not value or value.lower() in {"other", "none"}:
        return ""
    return value


def parse_user_agent(raw: str | None) -> DeviceInfo:
    """Parse a User-Agent string; return best-effort structured metadata."""
    raw = raw or ""
    ua = _ua_parse(raw)

    if ua.is_bot:
        device_type = "Bot"
    elif ua.is_tablet:
        device_type = "Tablet"
    elif ua.is_mobile:
        device_type = "Mobile"
    elif ua.is_pc:
        device_type = "Desktop"
    else:
        device_type = "Unknown"

    os_family = _clean(ua.os.family)
    device_model = _clean(ua.device.family)
    # Desktops rarely expose a model; fall back to a readable OS-based name.
    device_name = device_model or (f"{os_family} {device_type}".strip() or "Unknown")

    return DeviceInfo(
        device_name=device_name,
        device_type=device_type,
        browser=_clean(ua.browser.family) or "Unknown",
        browser_version=ua.browser.version_string or "",
        operating_system=os_family or "Unknown",
        operating_system_version=ua.os.version_string or "",
        user_agent=raw[:512],
    )
