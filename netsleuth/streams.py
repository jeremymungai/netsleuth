"""TCP stream reconstruction.

Reassembles both directions of every TCP conversation in capture order,
handling retransmissions and (limited) out-of-order delivery. Sequence
numbers are stored relative to the first sequence number observed per
direction, so the 32-bit wraparound is handled correctly for streams
smaller than 4 GiB.

Deliberate limitations (documented in docs/DESIGN.md):
  * sequence gaps are *counted*, not filled — content after a gap is
    still returned, concatenated (matches "follow stream" usefulness);
  * no TCP timestamp/PAWS processing;
  * per-direction buffering is capped to bound memory on huge transfers.
"""

from __future__ import annotations

from typing import Optional

from netsleuth.models import Packet, StreamData, StreamInfo

SEQ_MOD = 1 << 32


class _Direction:
    """Reassembly state for one direction of a stream."""

    __slots__ = ("base", "segments", "syn_seen", "fin_seen", "total_wire",
                 "buffered", "capped")

    def __init__(self) -> None:
        self.base: Optional[int] = None       # sequence number of SYN (or first data)
        self.segments: dict[int, bytes] = {}
        self.syn_seen = False
        self.fin_seen = False
        self.total_wire = 0                   # bytes on the wire incl. retransmits
        self.buffered = 0
        self.capped = False

    def rel(self, seq: int) -> int:
        return (seq - (self.base or 0)) % SEQ_MOD

    def add(self, seq: int, data: bytes, limit: int) -> None:
        if self.base is None:
            self.base = seq
        if not data:
            return
        self.total_wire += len(data)
        if self.buffered >= limit:
            self.capped = True
            return
        r = self.rel(seq)
        existing = self.segments.get(r)
        if existing is not None and len(existing) >= len(data):
            return                            # pure retransmission
        self.buffered += len(data) - (len(existing) if existing else 0)
        self.segments[r] = data

    def assemble(self) -> tuple[bytes, int]:
        """Return (payload, gap_count) with overlaps/retransmits merged."""
        out = bytearray()
        cursor: Optional[int] = None
        gaps = 0
        for seq in sorted(self.segments):
            data = self.segments[seq]
            end = seq + len(data)
            if cursor is None:
                cursor = 0 if seq == 0 else seq
                if seq > 0:
                    gaps += 1                 # missing bytes before first segment
            if end <= cursor:
                continue                      # fully seen already
            if seq > cursor:
                gaps += 1
                cursor = seq
            out += data[cursor - seq:]
            cursor = end
        return bytes(out), gaps


class _Stream:
    """Both directions of one TCP conversation, keyed canonically."""

    def __init__(self, limit: int) -> None:
        self.fwd = _Direction()               # initiator → responder
        self.rev = _Direction()
        self.limit = limit
        self.first_ts: Optional[float] = None
        self.last_ts: Optional[float] = None
        self.packets = 0
        self.client = ""
        self.server = ""
        self.client_port = 0
        self.server_port = 0
        self.syn_seen = False
        self.synack_seen = False
        self.fin_both = False
        self.rst_seen = False
        self._fin_fwd = False
        self._fin_rev = False


class StreamReassembler:
    """Feed TCP packets; finalize into ordered :class:`StreamData` results."""

    DEFAULT_LIMIT = 64 * 1024 * 1024          # per-direction buffer cap (64 MiB)
    MAX_STREAMS = 50_000                      # max tracked streams across capture

    def __init__(self, limit: int = DEFAULT_LIMIT, max_streams: int = MAX_STREAMS) -> None:
        self.limit = limit
        self.max_streams = max_streams
        self.streams: dict[tuple, _Stream] = {}
        self.capped_streams = 0
        self.dropped_streams = 0

    @staticmethod
    def _key(pkt: Packet) -> tuple:
        left, right = (pkt.src, pkt.sport), (pkt.dst, pkt.dport)
        if right < left:
            left, right = right, left
        return (left, right)

    def feed(self, pkt: Packet) -> None:
        if pkt.proto != "tcp" or not pkt.src or not pkt.dst:
            return
        key = self._key(pkt)
        st = self.streams.get(key)
        if st is None:
            if len(self.streams) >= self.max_streams:
                self.dropped_streams += 1
                return
            st = _Stream(self.limit)
            self.streams[key] = st
            st.client, st.client_port = pkt.src, pkt.sport
            st.server, st.server_port = pkt.dst, pkt.dport
        st.packets += 1
        if st.first_ts is None or pkt.ts < st.first_ts:
            st.first_ts = pkt.ts
        if st.last_ts is None or pkt.ts > st.last_ts:
            st.last_ts = pkt.ts

        from_client = (pkt.src, pkt.sport) == (st.client, st.client_port)
        d = st.fwd if from_client else st.rev
        flags = pkt.tcp_flags

        if "S" in flags:
            if "A" not in flags:
                if from_client:
                    st.syn_seen = True
                    if st.fwd.base is None:
                        st.fwd.base = (pkt.tcp_seq + 1) % SEQ_MOD
            else:
                st.synack_seen = True
                if not from_client and st.rev.base is None:
                    st.rev.base = (pkt.tcp_seq + 1) % SEQ_MOD
        if "F" in flags:
            if from_client:
                st._fin_fwd = True
            else:
                st._fin_rev = True
        if "R" in flags:
            st.rst_seen = True

        if pkt.payload:
            d.add(pkt.tcp_seq, pkt.payload, self.limit)

        st.fin_both = st._fin_fwd and st._fin_rev

    def finalize(self) -> list[StreamData]:
        """Produce StreamData records ordered by first packet time."""
        out: list[StreamData] = []
        ordered = sorted(self.streams.values(), key=lambda s: s.first_ts or 0)
        for idx, st in enumerate(ordered):
            c2s, gaps1 = st.fwd.assemble()
            s2c, gaps2 = st.rev.assemble()
            info = StreamInfo(
                index=idx, client=st.client, server=st.server,
                client_port=st.client_port, server_port=st.server_port,
                start_ts=st.first_ts, end_ts=st.last_ts, packets=st.packets,
                bytes_c2s=len(c2s), bytes_s2c=len(s2c),
                handshake=st.syn_seen and st.synack_seen,
                terminated_cleanly=st.fin_both,
                gaps=gaps1 + gaps2,
            )
            if st.fwd.capped or st.rev.capped:
                self.capped_streams += 1
            out.append(StreamData(info=info, c2s=c2s, s2c=s2c))
        return out
