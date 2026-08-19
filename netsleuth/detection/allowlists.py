"""Built-in allowlists of well-known, OS-level background domains.

Every domain-joined Windows/macOS machine queries these on a schedule
(telemetry, update checks, connectivity probes), so periodicity alone is
never suspicious for them. Keeping the list in one module makes it easy
to audit and extend; entries match a name or any subdomain of it.
"""

from __future__ import annotations

# "*.X" matches X itself and any name ending in ".X"
TELEMETRY_DOMAINS: tuple[str, ...] = (
    "*.events.data.microsoft.com",   # Windows telemetry endpoints
    "*.windowsupdate.com",           # Windows Update signature/metadata
    "*.msftncsi.com",                # network connectivity indicator
    "*.windows.com",                 # general Windows services
    "*.bing.com",                    # Edge default search
    "*.msn.com",                     # Edge default home/news
    "*.apple.com",                   # macOS/iOS update & telemetry
    "*.in-addr.arpa",                # reverse DNS (PTR) maintenance
)


def is_telemetry_domain(name: str) -> bool:
    """True when *name* matches a built-in OS-background allowlist entry."""
    if not name:
        return False
    n = name.lower().rstrip(".")
    for pattern in TELEMETRY_DOMAINS:
        base = pattern[2:] if pattern.startswith("*.") else pattern
        if n == base or n.endswith("." + base):
            return True
    return False
