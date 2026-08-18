"""ICMP analyzer: echo traffic carrying payloads (tunnel/exfil signal)."""

from __future__ import annotations

from netsleuth.models import ICMPObservation, Packet

_TYPES = {0: "echo-reply", 3: "dest-unreachable", 4: "source-quench",
          5: "redirect", 8: "echo-request", 9: "router-advert",
          10: "router-solicit", 11: "time-exceeded", 12: "param-problem",
          13: "timestamp", 14: "timestamp-reply"}


class ICMPAnalyzer:
    name = "icmp"

    def __init__(self, keep_payload: int = 256) -> None:
        self.observations: list[ICMPObservation] = []
        self.echo_pairs = 0
        self._keep = keep_payload

    def feed(self, pkt: Packet) -> None:
        if pkt.proto not in ("icmp", "icmp6") or pkt.icmp_type < 0:
            return
        kind = _TYPES.get(pkt.icmp_type, f"type-{pkt.icmp_type}")
        if pkt.proto == "icmp6":
            kind = {128: "echo-request", 129: "echo-reply"}.get(pkt.icmp_type, f"v6-type-{pkt.icmp_type}")
        if kind == "echo-request":
            self.echo_pairs += 1
        if pkt.payload_len > 0:
            self.observations.append(ICMPObservation(
                ts=pkt.ts, src=pkt.src, dst=pkt.dst, icmp_type=kind,
                payload_len=pkt.payload_len, payload=pkt.payload[:self._keep]))

    def finalize(self) -> None:
        pass
