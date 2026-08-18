"""Tests for capture ingestion, flow tracking and TCP stream reassembly."""

from __future__ import annotations

import pytest

from netsleuth.capture import CaptureError, CaptureReader, detect_format
from netsleuth.flows import FlowTracker
from netsleuth.streams import StreamReassembler

from pcapfix import (
    BASE_TS, dns_pair, icmp_echo, syn_scan, tcp_conversation, udp_pair, write_pcap,
)

C, S = "192.168.1.50", "93.184.216.34"


# --------------------------------------------------------------------- format

def test_rejects_non_capture(tmp_path):
    p = tmp_path / "notes.txt"
    p.write_text("hello, definitely not a packet capture")
    with pytest.raises(CaptureError, match="not a pcap"):
        detect_format(str(p))


def test_rejects_empty_file(tmp_path):
    p = tmp_path / "empty.pcap"
    p.write_bytes(b"")
    with pytest.raises(CaptureError, match="empty"):
        detect_format(str(p))


def test_rejects_missing_file(tmp_path):
    with pytest.raises(CaptureError, match="cannot read"):
        detect_format(str(tmp_path / "ghost.pcap"))


def test_detects_pcap_and_pcapng(tmp_path):
    from scapy.utils import PcapNgWriter
    pkts = dns_pair(C, "8.8.8.8", "example.com", answers=["93.184.216.34"])
    p1 = write_pcap(tmp_path / "c.pcap", pkts)
    assert detect_format(p1)[0] == "pcap"
    p2 = str(tmp_path / "c.pcapng")
    with PcapNgWriter(p2) as w:
        for pkt in pkts:
            w.write(pkt)
    assert detect_format(p2)[0] == "pcapng"
    out = list(CaptureReader(p2))
    assert len(out) == 2 and out[0].dns is not None


def test_truncated_pcap_still_yields_packets(tmp_path):
    """A capture cut mid-file must not crash the reader."""
    pkts = tcp_conversation(C, 44000, S, 80, [b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"], [b"y" * 50])
    full = tmp_path / "full.pcap"
    write_pcap(full, pkts)
    data = full.read_bytes()
    (tmp_path / "cut.pcap").write_bytes(data[: int(len(data) * 0.55)])
    reader = CaptureReader(str(tmp_path / "cut.pcap"))
    pkts_out = list(reader)
    assert len(pkts_out) >= 1
    assert reader.meta.truncated is True
    assert any("truncated" in n.lower() for n in reader.meta.notes)


# ----------------------------------------------------------------- ingestion

def test_reader_metadata_and_dns_normalization(tmp_path):
    pkts = dns_pair(C, "8.8.8.8", "example.com", answers=["93.184.216.34"])
    path = write_pcap(tmp_path / "dns.pcap", pkts)
    reader = CaptureReader(path)
    out = list(reader)
    assert reader.meta.packet_count == 2
    assert reader.meta.format == "pcap"
    assert reader.meta.linktype == "Ethernet"
    assert reader.meta.first_ts is not None and reader.meta.last_ts >= reader.meta.first_ts

    q = next(p for p in out if p.dns and not p.dns.is_response)
    assert q.proto == "udp"
    assert q.dns.name == "example.com"
    assert q.dns.qtype == "A"
    assert q.dns.client == C

    r = next(p for p in out if p.dns and p.dns.is_response)
    assert r.dns.response_code == "NOERROR"
    assert "93.184.216.34" in r.dns.answers


def test_dns_nxdomain(tmp_path):
    pkts = dns_pair(C, "8.8.8.8", "nope.invalid", answers=[], rcode=3)
    path = write_pcap(tmp_path / "nx.pcap", pkts)
    out = list(CaptureReader(path))
    resp = next(p for p in out if p.dns and p.dns.is_response)
    assert resp.dns.response_code == "NXDOMAIN"


def test_icmp_payload(tmp_path):
    pkts = [icmp_echo(C, S, b"secret-icmp-data"), icmp_echo(C, S, b"secret-icmp-data", reply=True)]
    path = write_pcap(tmp_path / "icmp.pcap", pkts)
    out = list(CaptureReader(path))
    assert all(p.proto == "icmp" for p in out)
    assert out[0].payload == b"secret-icmp-data"
    assert out[0].icmp_type == 8
    assert out[1].icmp_type == 0


def test_max_packets_stops_early(tmp_path):
    pkts = syn_scan(C, S, range(100, 140))
    path = write_pcap(tmp_path / "scan.pcap", pkts)
    reader = CaptureReader(path, max_packets=10)
    out = list(reader)
    assert len(out) == 10
    assert any("max-packets" in n for n in reader.meta.notes)


# --------------------------------------------------------------------- flows

def test_flow_and_conversation_tracking(tmp_path):
    pkts = tcp_conversation(C, 44000, S, 80, [b"hello"], [b"world"])
    path = write_pcap(tmp_path / "tcp.pcap", pkts)
    tracker = FlowTracker()
    for p in CaptureReader(path):
        tracker.feed(p)
    assert len(tracker.conversations) == 1
    conv = next(iter(tracker.conversations.values()))
    assert (conv.a, conv.a_port, conv.b, conv.b_port) == (C, 44000, S, 80)
    assert conv.proto == "tcp"
    assert conv.bytes == 10
    fwd = tracker.flows[("tcp", C, 44000, S, 80)]
    assert fwd.ack_of_syn is True       # handshake completed
    assert fwd.syn_count == 1


def test_udp_conversations(tmp_path):
    pkts = udp_pair(C, 5353, "8.8.8.8", 53, c2s=b"q", s2c=b"a")
    path = write_pcap(tmp_path / "udp.pcap", pkts)
    tracker = FlowTracker()
    for p in CaptureReader(path):
        tracker.feed(p)
    assert len(tracker.conversations) == 1
    assert next(iter(tracker.conversations.values())).proto == "udp"


def test_syn_scan_flows(tmp_path):
    pkts = syn_scan(C, S, range(100, 130))
    path = write_pcap(tmp_path / "scan.pcap", pkts)
    tracker = FlowTracker()
    for p in CaptureReader(path):
        tracker.feed(p)
    scans = list(tracker.syn_scans())
    assert len(scans) == 1
    src, flows = scans[0]
    assert src == C
    assert len(flows) >= 25


# ------------------------------------------------------------------- streams

def test_stream_reassembly_basic(tmp_path):
    c2s = [b"GET /flag HTTP/1.1\r\nHost: ctf.example\r\n\r\n"]
    s2c = [b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nFLAG!"]
    pkts = tcp_conversation(C, 44001, S, 80, c2s, s2c)
    path = write_pcap(tmp_path / "st.pcap", pkts)
    re = StreamReassembler()
    for p in CaptureReader(path):
        re.feed(p)
    streams = re.finalize()
    assert len(streams) == 1
    st = streams[0]
    assert st.info.handshake is True
    assert st.info.terminated_cleanly is True
    assert st.info.gaps == 0
    assert st.c2s == b"".join(c2s)
    assert st.s2c == b"".join(s2c)
    assert st.info.bytes_c2s == len(st.c2s)
    assert st.info.client == C and st.info.server == S
    assert st.info.client_port == 44001 and st.info.server_port == 80


def test_stream_reassembly_split_segments(tmp_path):
    """One logical message split across many small TCP segments."""
    big = bytes(range(256)) * 40                       # 10240 bytes
    pkts = tcp_conversation(C, 44002, S, 8080, [big], [], segment_size=100)
    path = write_pcap(tmp_path / "split.pcap", pkts)
    re = StreamReassembler()
    for p in CaptureReader(path):
        re.feed(p)
    st = re.finalize()[0]
    assert st.c2s == big
    assert st.info.gaps == 0


def test_stream_reassembly_retransmission(tmp_path):
    c2s = [b"part1-", b"part2"]
    pkts = tcp_conversation(C, 44003, S, 80, c2s, [], retransmit_index=1)
    path = write_pcap(tmp_path / "ret.pcap", pkts)
    re = StreamReassembler()
    for p in CaptureReader(path):
        re.feed(p)
    st = re.finalize()[0]
    assert st.c2s == b"part1-part2"      # duplicate bytes must not double


def test_stream_no_handshake_still_reassembles(tmp_path):
    """Mid-stream captures (no SYN) still produce content."""
    pkts = tcp_conversation(C, 44004, S, 443, [b"payload-without-syn"], [], handshake=False, close=False)
    path = write_pcap(tmp_path / "nosyn.pcap", pkts)
    re = StreamReassembler()
    for p in CaptureReader(path):
        re.feed(p)
    st = re.finalize()[0]
    assert st.c2s == b"payload-without-syn"
    assert st.info.handshake is False


def test_multiple_streams_ordered_by_time(tmp_path):
    s1 = tcp_conversation(C, 44010, S, 80, [b"one"], [], base_ts=BASE_TS)
    s2 = tcp_conversation(C, 44011, S, 80, [b"two"], [], base_ts=BASE_TS + 5)
    path = write_pcap(tmp_path / "multi.pcap", s1 + s2)
    re = StreamReassembler()
    for p in CaptureReader(path):
        re.feed(p)
    streams = re.finalize()
    assert len(streams) == 2
    assert streams[0].c2s == b"one" and streams[0].info.index == 0
    assert streams[1].c2s == b"two" and streams[1].info.index == 1
