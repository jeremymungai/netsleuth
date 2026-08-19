"""Domain-controller identification from capture data.

Domain-joined Windows machines talk to their DC on a schedule (Group
Policy refresh, Kerberos, SYSVOL reads), so periodic connections to a DC
on Kerberos/RPC/LDAP/SMB ports are expected. Before flagging that
traffic as beaconing, detectors need to know which internal host *is*
the DC. Two signals, both from the capture itself:

1. SRV resolution — an answer to ``_ldap._tcp.dc._msdcs.<domain>`` names
   the DC; an A record for that name gives its IP. (Only works when the
   capture actually carries the SRV rdata.)
2. LDAP listener — an internal host that accepts connections on
   389/636/3268/3269 is serving LDAP, which on a Windows LAN means the
   DC (or an LDAP server that behaves identically from a traffic-shape
   perspective).

``--dc`` CLI overrides are merged in by the pipeline, not here.
"""

from __future__ import annotations

LDAP_PORTS = {389, 636, 3268, 3269}
# ports on a DC that carry scheduled Windows traffic (plus the ephemeral
# RPC range, which starts at 49152 — LSA/FRS/WinRM endpoints live there)
DC_SERVICE_PORTS = {88, 135, 389, 445, 464, 636, 3268, 3269}
EPHEMERAL_MIN = 49152


def is_dc_port(port: int) -> bool:
    """Standard Windows DC service port, or a DC's dynamic RPC port."""
    return port in DC_SERVICE_PORTS or port >= EPHEMERAL_MIN


def _srv_target_ips(result) -> set[str]:
    """Resolve ``_ldap._tcp.dc._msdcs`` SRV targets to IPs via A answers."""
    if result.dns is None:
        return set()
    dc_names: set[str] = set()
    for q in result.dns.queries:
        if not q.is_response or "._msdcs." not in q.name:
            continue
        if not q.name.startswith("_ldap._tcp"):
            continue
        for ans in q.answers:
            # SRV rdata renders as "prio weight port target" (or just the
            # target); the hostname is the last dot-containing token
            for token in reversed(ans.split()):
                if "." in token and not token[0].isdigit():
                    dc_names.add(token.rstrip("."))
                    break
    if not dc_names:
        return set()
    ips: set[str] = set()
    for q in result.dns.queries:
        if not q.is_response or q.name.rstrip(".").lower() not in dc_names:
            continue
        for ans in q.answers:
            parts = ans.split(".")
            if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255
                                       for p in parts):
                ips.add(ans)
    return ips


def _ldap_listeners(result) -> set[str]:
    """Internal hosts accepting connections on LDAP ports."""
    ov = result.overview
    if ov is None:
        return set()
    hosts = getattr(ov, "hosts", None) or {}
    listeners: set[str] = set()
    for f in ov.flow_tracker.flows.values():
        if f.proto != "tcp" or f.dport not in LDAP_PORTS:
            continue
        if not (f.ack_of_syn or f.bytes > 0):
            continue                    # SYN-only probes don't prove a listener
        h = hosts.get(f.dst)
        if h is not None and h.is_internal:
            listeners.add(f.dst)
    return listeners


def find_domain_controllers(result) -> set[str]:
    """Best-effort set of DC IPs seen in this capture (never exhaustive)."""
    dcs = _ldap_listeners(result)
    dcs |= _srv_target_ips(result)
    internal_only = getattr(result.overview, "hosts", None) if result.overview is not None else None
    if internal_only:
        dcs = {ip for ip in dcs
               if ip not in internal_only or internal_only[ip].is_internal}
    return dcs
