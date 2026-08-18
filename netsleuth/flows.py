"""Flow and conversation tracking.

A *flow* is one direction of a 5-tuple (proto, src, sport, dst, dport);
a *conversation* is the bidirectional pair. Scan and beacon detectors
consume these aggregates, which is why they carry TCP flag statistics.
"""

from __future__ import annotations

from netsleuth.models import Conversation, Flow, Packet


class FlowTracker:
    """Aggregates packets into directional flows and conversations."""

    def __init__(self) -> None:
        self.flows: dict[tuple, Flow] = {}
        self.conversations: dict[tuple, Conversation] = {}
        # pending half-open conversations: first packet seen from a side
        self._conv_initiator: dict[tuple, str] = {}

    def feed(self, pkt: Packet) -> None:
        if pkt.proto not in ("tcp", "udp") or not pkt.src or not pkt.dst:
            return
        flow = self.flows.get(pkt.src and (pkt.proto, pkt.src, pkt.sport, pkt.dst, pkt.dport))
        if flow is None:
            flow = Flow(proto=pkt.proto, src=pkt.src, sport=pkt.sport,
                        dst=pkt.dst, dport=pkt.dport)
            self.flows[flow.key] = flow
        flow.packets += 1
        flow.bytes += pkt.payload_len
        if flow.first_ts is None or pkt.ts < flow.first_ts:
            flow.first_ts = pkt.ts
        if flow.last_ts is None or pkt.ts > flow.last_ts:
            flow.last_ts = pkt.ts
        if pkt.proto == "tcp":
            flags = pkt.tcp_flags
            if "S" in flags and "A" not in flags:
                flow.syn_count += 1
            if "S" in flags and "A" in flags:
                # this direction answers a handshake started by its peer
                peer = self.flows.get((pkt.proto, pkt.dst, pkt.dport, pkt.src, pkt.sport))
                if peer is not None:
                    peer.ack_of_syn = True
            if "F" in flags:
                flow.fin_count += 1
            if "R" in flags:
                flow.rst_count += 1
        self._conversation(pkt)

    def _conversation(self, pkt: Packet) -> None:
        ckey = self._ckey(pkt)
        conv = self.conversations.get(ckey)
        if conv is None:
            initiator = self._conv_initiator.get(ckey)
            if initiator is None:
                # first packet decides who the "client" is
                self._conv_initiator[ckey] = pkt.src
                a, a_port, b, b_port = pkt.src, pkt.sport, pkt.dst, pkt.dport
            elif initiator == pkt.src:
                a, a_port, b, b_port = pkt.src, pkt.sport, pkt.dst, pkt.dport
            else:
                a, a_port, b, b_port = pkt.dst, pkt.dport, pkt.src, pkt.sport
            conv = Conversation(a=a, b=b, a_port=a_port, b_port=b_port, proto=pkt.proto)
            self.conversations[ckey] = conv
        conv.packets += 1
        conv.bytes += pkt.payload_len
        if conv.first_ts is None or pkt.ts < conv.first_ts:
            conv.first_ts = pkt.ts
        if conv.last_ts is None or pkt.ts > conv.last_ts:
            conv.last_ts = pkt.ts

    @staticmethod
    def _ckey(pkt: Packet) -> tuple:
        """Canonical bidirectional key (smaller endpoint first)."""
        left, right = (pkt.src, pkt.sport), (pkt.dst, pkt.dport)
        if right < left:
            left, right = right, left
        return (pkt.proto, left, right)

    # -- queries used by detectors -------------------------------------------

    def syn_scans(self, established_threshold: float = 0.3):
        """Yield flows that look like SYN-scan attempts (SYN, no completion).

        A source sending many SYNs to distinct ports where fewer than
        ``established_threshold`` of the handshakes complete is the
        classic SYN / half-open scan signature.
        """
        by_src: dict[str, list[Flow]] = {}
        for f in self.flows.values():
            if f.proto == "tcp" and f.syn_count and f.src:
                by_src.setdefault(f.src, []).append(f)
        for src, flist in by_src.items():
            attempted = [f for f in flist if f.syn_count and not f.ack_of_syn]
            if len(attempted) < 10:
                continue
            if len(attempted) / max(len(flist), 1) < established_threshold:
                continue
            yield src, attempted
