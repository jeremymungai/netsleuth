"""Per-packet TCP/IP metadata collector for covert-channel analysis.

The streaming pass throws packets away; covert-channel analysis of
IP/TCP metadata (IP ID, TTL, ports, flags, sizes) needs per-packet
sequences. This collector keeps compact per-source tuples during the
pass, strictly capped so hostile captures cannot exhaust memory.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from netsleuth.models import Packet

MAX_PER_SOURCE = 20_000             # observation tuples per source host
MAX_SOURCES = 2_000


@dataclass
class MetaObs:
    ts: float
    frame: int
    ip_id: int
    ip_ttl: int
    sport: int
    dport: int
    flags: str
    length: int                      # frame length (wire)


@dataclass
class CovertCollector:
    name = "covert-collector"

    seqs: dict[str, list[MetaObs]] = field(default_factory=dict)
    dropped_sources: int = 0

    def feed(self, pkt: Packet) -> None:
        if pkt.proto not in ("tcp", "udp") or not pkt.src:
            return
        seq = self.seqs.get(pkt.src)
        if seq is None:
            if len(self.seqs) >= MAX_SOURCES:
                self.dropped_sources += 1
                return
            seq = self.seqs[pkt.src] = []
        if len(seq) < MAX_PER_SOURCE:
            seq.append(MetaObs(pkt.ts, pkt.frame, pkt.ip_id, pkt.ip_ttl,
                               pkt.sport, pkt.dport, pkt.tcp_flags,
                               pkt.frame_len))

    def finalize(self) -> None:
        pass
