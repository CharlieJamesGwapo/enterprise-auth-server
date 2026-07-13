"""Pluggable Geo-IP resolution.

No MaxMind/GeoIP database is bundled (offline-safe), so by default this reads
location hints from upstream CDN/proxy headers (e.g. Cloudflare's
``CF-IPCountry``). Swap in a real resolver by replacing :func:`resolve_location`.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class GeoLocation:
    country: str | None = None
    city: str | None = None


def resolve_location(ip: str | None, headers: dict[str, str] | None = None) -> GeoLocation:
    """Best-effort location from proxy headers; returns empty location if unknown."""
    headers = {k.lower(): v for k, v in (headers or {}).items()}
    country = headers.get("cf-ipcountry") or headers.get("x-country")
    city = headers.get("cf-ipcity") or headers.get("x-city")
    if country and country.upper() in {"XX", "T1"}:  # CF sentinels for unknown/Tor
        country = None
    return GeoLocation(country=country or None, city=city or None)
