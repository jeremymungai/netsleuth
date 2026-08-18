"""ARP analyzer: mapping inventory and anomaly signals.

The capture dissector encodes ARP packets as a human-readable payload
string ("who-has X? tell Y" / "X is-at MAC"); this analyzer parses those
back into structured events and tracks IP→MAC claims over time. The
*interpretation* (possible ARP spoofing) belongs to detection.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from netsleuth.models import Packet


@dataclass
class ARPEvent:
    ts: float
    kind: str              # request | reply
    sender_ip: str
    sender_mac: str
    target_ip: str

    def to_dict(self) -> dict:
        from netsleuth.models import iso
        return {"ts": iso(self.ts), "kind": self.kind, "sender_ip": self.sender_ip,
                "sender_mac": self.sender_mac, "target_ip": self.target_ip}


@dataclass
class ARPData:
    events: list[ARPEvent] = field(default_factory=list)
    ip_claims: dict[str, set[str]] = field(default_factory=dict)    # ip → macs

    def conflicts(self) -> dict[str, list[str]]:
        """IPs claimed by more than one MAC address."""
        return {ip: sorted(macs) for ip, macs in self.ip_claims.items() if len(macs) > 1}

    def to_dict(self) -> dict:
        return {"events": [e.to_dict() for e in self.events[:2000]],
                "conflicts": self.conflicts()}


_WHO_HAS = re.compile(r"who-has (\S+)\? tell (\S+)")
_IS_AT = re.compile(r"(\S+) is-at (\S+)")


class ARPAnalyzer:
    name = "arp"

    def __init__(self) -> None:
        self.data = ARPData()

    def feed(self, pkt: Packet) -> None:
        if pkt.proto != "arp":
            return
        text = pkt.payload.decode("utf-8", "replace")
        m = _WHO_HAS.search(text)
        if m:
            ev = ARPEvent(pkt.ts, "request", sender_ip=m.group(2),
                          sender_mac=pkt.mac_src, target_ip=m.group(1))
        else:
            m2 = _IS_AT.search(text)
            if m2:
                ev = ARPEvent(pkt.ts, "reply", sender_ip=m2.group(1),
                              sender_mac=m2.group(2), target_ip=pkt.dst)
            else:
                return
        self.data.events.append(ev)
        if ev.kind == "reply" and ev.sender_mac:
            self.data.ip_claims.setdefault(ev.sender_ip, set()).add(ev.sender_mac.lower())

    def finalize(self) -> None:
        pass
