"""IP classification: internal vs external, no external lookups."""

from __future__ import annotations

import ipaddress


def is_internal_ip(ip: str) -> bool:
    """True for RFC1918 private, loopback, link-local, CGNAT and ULA space."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_loopback or addr.is_link_local:
        return True
    if addr.version == 4:
        return addr.is_private or addr in ipaddress.ip_network("100.64.0.0/10")
    return addr.is_private          # covers fc00::/7 unique-local for IPv6


def classify_network(ip: str) -> str:
    """Short label for where an address lives."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown"
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link-local"
    if addr.is_multicast:
        return "multicast"
    if addr.is_reserved:
        return "reserved"
    if is_internal_ip(ip):
        return "private"
    return "public"
