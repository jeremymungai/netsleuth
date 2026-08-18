"""Analyzer registry.

Packet-fed analyzers implement :class:`PacketAnalyzer`; stream-fed ones
implement :class:`StreamAnalyzer` and run after reassembly. The pipeline
discovers everything through ``PACKET_ANALYZERS`` / ``STREAM_ANALYZERS``.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from netsleuth.models import Packet, StreamData


@runtime_checkable
class PacketAnalyzer(Protocol):
    """Consumes normalized packets during the single streaming pass."""

    name: str

    def feed(self, pkt: Packet) -> None: ...

    def finalize(self) -> None: ...


@runtime_checkable
class StreamAnalyzer(Protocol):
    """Consumes reconstructed TCP streams after the packet pass."""

    name: str

    def analyze(self, streams: list[StreamData]) -> None: ...


def packet_analyzers():
    from netsleuth.analyzers import arp, dhcp, dns, icmp, overview
    return [overview.OverviewAnalyzer(), dns.DNSAnalyzer(), dhcp.DHCPAnalyzer(),
            arp.ARPAnalyzer(), icmp.ICMPAnalyzer()]


def stream_analyzers():
    from netsleuth.analyzers import clearcreds, http, tls
    return [http.HTTPAnalyzer(), tls.TLSAnalyzer(), clearcreds.ClearTextAnalyzer()]
