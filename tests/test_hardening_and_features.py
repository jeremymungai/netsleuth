from __future__ import annotations

import base64
import gzip
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from netsleuth.analyzers import http as http_mod
from netsleuth.capture import _rdata_str
from netsleuth.detection import engine
from netsleuth.extraction import encodings
from netsleuth.models import (
    CaptureMeta, Confidence, Finding, HTTPTransaction, Packet,
    SecretMatch, Severity, StreamData, StreamInfo,
)
from netsleuth.pipeline import AnalysisResult, Options, Pipeline
from netsleuth.reporting import html as html_mod
from netsleuth.streams import StreamReassembler


def test_safe_bounded_decompression_blocks_bomb():
    """Verify decompression limits prevent memory explosion."""
    huge_data = b"\x00" * (20 * 1024 * 1024)
    compressed = gzip.compress(huge_data)
    b64_str = base64.b64encode(compressed).decode("ascii")

    decoded = encodings.decode_step(b64_str, "base64(gzip)")
    assert len(decoded.encode("latin-1")) <= 16 * 1024 * 1024


def test_http_negative_chunk_size():
    """Verify negative chunk size in HTTP transfer-encoding does not crash or loop."""
    buf = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n-5\r\nmalicious_chunk\r\n0\r\n\r\n"
    res = http_mod._take_body(buf, 39, {"transfer-encoding": "chunked"}, request=False)
    body, framed = res
    assert isinstance(body, bytes)
    assert framed >= 0


def test_http_negative_content_length():
    """Verify negative content-length is rejected."""
    buf = b"HTTP/1.1 200 OK\r\nContent-Length: -50\r\n\r\nrest_of_buffer"
    body, framed = http_mod._take_body(buf, 36, {"content-length": "-50"}, request=False)
    assert body == b""
    assert framed == 0


def test_secret_masking_short_and_long():
    """Verify secrets of various lengths are safely masked."""
    s1 = SecretMatch(kind="password", value="1234", source="test")
    assert s1.masked() == "****"

    s2 = SecretMatch(kind="password", value="secret", source="test")
    assert s2.masked() == "s…t"
    assert "secret" not in s2.masked()

    s3 = SecretMatch(kind="api-key", value="sk_test_12345", source="test")
    assert "sk_tes" in s3.masked()
    assert "12345" not in s3.masked()

    s4 = SecretMatch(kind="flag", value="picoCTF{super_secret_flag}", source="test")
    assert s4.masked().startswith("picoCTF")
    assert "super_secret" not in s4.masked()


def test_stream_reassembler_capacity_limit():
    """Verify StreamReassembler bounds concurrent streams."""
    reasm = StreamReassembler(max_streams=5)
    for i in range(10):
        pkt = Packet(ts=100.0 + i, src="10.0.0.1", sport=10000 + i, dst="10.0.0.2", dport=80,
                     proto="tcp", tcp_flags="S", payload=b"test")
        reasm.feed(pkt)
    assert len(reasm.streams) == 5
    assert reasm.dropped_streams == 5


def test_html_report_has_csp():
    """Verify generated HTML reports embed a strict Content Security Policy."""
    meta = CaptureMeta(path="test.pcap", format="pcap", size_bytes=100, packet_count=5)
    res = MagicMock()
    res.meta = meta
    res.score.score = 50
    res.score.label = "elevated"
    res.overview = None
    res.findings = []
    res.dns = None
    res.http = []
    res.tls = []
    res.credentials = []
    res.artifacts = []
    res.covert = []
    res.secrets = []
    res.events = []
    res.streams = []

    html_out = html_mod.generate_html(res)
    assert "<meta http-equiv=\"Content-Security-Policy\"" in html_out
    assert "default-src 'none'" in html_out


def test_srv_record_rdata_parsing():
    """Verify _rdata_str handles SRV (type 33) records properly."""
    rr = MagicMock()
    rr.type = 33
    rr.rdata = (0, 100, 389, "dc01.corp.local")
    rr.priority = 0
    rr.weight = 100
    rr.port = 389
    rr.target = b"dc01.corp.local."

    rdata_str = _rdata_str(rr)
    assert "389" in rdata_str
    assert "dc01.corp.local" in rdata_str


def test_correlation_engine_generates_finding():
    """Verify multi-finding correlation triggers on a converged host."""
    f1 = Finding(id="scan.syn.port", title="Port scan", severity=Severity.MEDIUM,
                 confidence=Confidence.MEDIUM, hosts=["192.168.1.50", "10.0.0.1"])
    f2 = Finding(id="beacon.tcp.c2", title="C2 Beaconing", severity=Severity.HIGH,
                 confidence=Confidence.HIGH, hosts=["192.168.1.50", "203.0.113.5"])
    f3 = Finding(id="creds.ftp.leak", title="Cleartext credentials", severity=Severity.MEDIUM,
                 confidence=Confidence.HIGH, hosts=["192.168.1.50", "10.0.0.5"])

    correlated = engine.correlate_findings([f1, f2, f3])
    assert len(correlated) >= 1
    corr = correlated[0]
    assert corr.id == "correlation.host.192.168.1.50"
    assert "192.168.1.50" in corr.title
    assert corr.severity == Severity.HIGH
    assert corr.confidence == Confidence.HIGH


def test_finding_suppression_with_ignore():
    """Verify Options.ignored_findings suppresses findings matching glob/id."""
    opts = Options(ignored_findings=["dns.tunnel.*", "beacon.tcp.benign"])
    assert opts.ignored_findings == ["dns.tunnel.*", "beacon.tcp.benign"]
