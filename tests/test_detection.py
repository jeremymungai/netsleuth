"""Detection engine tests.

Two sides, matching the portfolio's LogSentinel philosophy:
  1. attack-shaped traffic fires the right finding with real evidence;
  2. benign traffic stays quiet (no false-positive findings).
Detectors are exercised both through synthetic AnalysisResults (precise
control) and full pipelines over generated captures (integration).
"""

from __future__ import annotations

import pytest

from netsleuth.detection import behaviors, beaconing, dnshunt, engine, misc, scoring
from netsleuth.flows import FlowTracker
from netsleuth.models import (
    Confidence, Credential, DNSRecord, Finding, Flow, Severity, StreamData,
    StreamInfo, HTTPTransaction,
)
from netsleuth.pipeline import Options, Pipeline

from pcapfix import BASE_TS, dns_pair, syn_scan, tcp_conversation, write_pcap

C, S = "192.168.1.50", "203.0.113.25"


# ------------------------------------------------------------------ helpers

class FakeOverview:
    def __init__(self, flows=(), conversations=()):
        ft = FlowTracker()
        ft.flows = {f.key: f for f in flows}
        ft.conversations = {(c.a, c.b, c.a_port, c.b_port, c.proto): c
                            for c in conversations}
        self.flow_tracker = ft
        self.hosts = {}


def flow(src, sport, dst, dport, *, syn=1, established=False, ts=BASE_TS,
         payload=0, rst=0):
    return Flow(proto="tcp", src=src, sport=sport, dst=dst, dport=dport,
                packets=2, bytes=payload, first_ts=ts, last_ts=ts + 0.1,
                syn_count=syn, ack_of_syn=established, rst_count=rst)


class FakeResult:
    def __init__(self, **kw):
        self.overview = kw.get("overview")
        self.dns = kw.get("dns")
        self.arp = kw.get("arp")
        self.icmp = kw.get("icmp", [])
        self.http = kw.get("http", [])
        self.tls = kw.get("tls", [])
        self.credentials = kw.get("credentials", [])
        self.secrets = kw.get("secrets", [])
        self.artifacts = kw.get("artifacts", [])
        self.findings = []
        self.events = []
        self.streams = []
        self.stream_data = []
        self.smtp_traffic = []
        self.banners = {}


# ---------------------------------------------------------------- SYN scans

def test_syn_scan_detected_synthetic():
    flows = [flow(C, 40000 + i, S, 100 + i) for i in range(40)]
    res = FakeResult(overview=FakeOverview(flows=flows))
    findings = behaviors.detect_syn_scan(res)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.HIGH
    assert f.hosts == [C]
    assert "40" in f.description
    assert f.wireshark_filters == [f"ip.src == {C} && tcp.flags.syn == 1 && !tcp.flags.ack"]
    assert any(m.technique == "T1046" for m in f.mitre)


def test_benign_browsing_not_a_scan():
    """A host visiting 6 different services is normal, not a scan."""
    flows = [flow(C, 40000 + i, "93.184.216.34", p, established=True)
             for i, p in enumerate((80, 443, 8080, 53, 22, 25))]
    res = FakeResult(overview=FakeOverview(flows=flows))
    assert behaviors.detect_syn_scan(res) == []


def test_syn_scan_via_pipeline(tmp_path):
    pkts = syn_scan(C, S, range(100, 145))
    path = write_pcap(tmp_path / "scan.pcap", pkts)
    res = Pipeline(path, Options(modules={"overview", "detect"})).run()
    assert any(f.id == f"scan.syn.{C}" for f in res.findings)
    assert res.score.score >= 60


# --------------------------------------------------------------- host sweep

def test_host_sweep_detected():
    flows = [flow(C, 40000 + i, f"10.1.1.{i}", 445) for i in range(25)]
    res = FakeResult(overview=FakeOverview(flows=flows))
    findings = behaviors.detect_host_scan(res)
    assert len(findings) == 1
    assert "25 hosts" in findings[0].title or "25" in findings[0].title


# ---------------------------------------------------------------- beaconing

def test_beaconing_regular_intervals_detected():
    flows = []
    t = BASE_TS
    for i in range(20):
        flows.append(flow(C, 50000 + i, S, 443, established=True, ts=t,
                          payload=512))
        t += 60.0
    res = FakeResult(overview=FakeOverview(flows=flows))
    findings = beaconing.detect_tcp_beaconing(res)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.HIGH and f.confidence == Confidence.HIGH
    assert "60.0s interval" in f.title
    assert "not evidence of compromise on its own" in f.explanation  # honesty!
    assert any(m.technique.startswith("T1071") for m in f.mitre)


def test_beaconing_irregular_traffic_quiet():
    import random
    random.seed(7)
    flows = []
    t = BASE_TS
    for i in range(20):
        flows.append(flow(C, 50000 + i, S, 443, established=True, ts=t,
                          payload=random.randint(100, 4000)))
        t += random.uniform(1, 200)
    res = FakeResult(overview=FakeOverview(flows=flows))
    assert beaconing.detect_tcp_beaconing(res) == []


def test_beaconing_too_few_connections_quiet():
    flows = [flow(C, 50000 + i, S, 443, established=True, ts=BASE_TS + i * 60)
             for i in range(5)]
    res = FakeResult(overview=FakeOverview(flows=flows))
    assert beaconing.detect_tcp_beaconing(res) == []


# --------------------------------------------------------------- dns tunnel

def make_dns_data(queries):
    from netsleuth.analyzers.dns import DNSAnalyzer
    from netsleuth.models import Packet
    ana = DNSAnalyzer()
    for i, (name, ts) in enumerate(queries):
        p = Packet(ts=ts, src=C, dst="8.8.8.8", proto="udp", sport=5353, dport=53)
        p.dns = DNSRecord(ts=ts, client=C, server="8.8.8.8", name=name,
                          qtype="A", is_response=False)
        ana.feed(p)
    return ana.data


def test_dns_tunneling_detected():
    import base64, random
    random.seed(1)
    queries = []
    for i in range(40):
        chunk = base64.b32encode(random.randbytes(20)).decode().lower()
        queries.append((f"{chunk}.tunnel.evil.example", BASE_TS + i))
    res = FakeResult(dns=make_dns_data(queries))
    findings = dnshunt.detect_dns_tunneling(res)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.HIGH
    assert "evil.example" in f.title          # stats key on the base domain
    assert len(f.evidence) >= 2
    assert f.wireshark_filters == ['dns.qry.name contains "evil.example"']


def test_normal_dns_quiet():
    names = (["www.google.com", "example.com", "github.com",
              "api.example.com", "cdn.example.com", "mail.example.com"]) * 4
    queries = [(names[i], BASE_TS + i) for i in range(len(names))]
    res = FakeResult(dns=make_dns_data(queries))
    assert dnshunt.detect_dns_tunneling(res) == []


def test_nxdomain_anomaly():
    queries = [(f"host{i}.broken.example", BASE_TS + i) for i in range(20)]
    data = make_dns_data(queries)
    # mark them all as NXDOMAIN responses
    for q in data.queries:
        q.is_response = True
        q.response_code = "NXDOMAIN"
    for st in data.domain_stats.values():
        st.nxdomain = 20
    res = FakeResult(dns=data)
    findings = dnshunt.detect_nxdomain_anomaly(res)
    assert findings and "NXDOMAIN" in findings[0].title


# --------------------------------------------------------------- cleartext

def test_cleartext_creds_finding():
    creds = [Credential(ts=BASE_TS, protocol="ftp", client=C, server=S,
                        username="alice", password="wonderland")]
    res = FakeResult(credentials=creds)
    findings = misc.detect_cleartext_protocols(res)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.HIGH and f.confidence == Confidence.HIGH
    assert "wonderland" not in f.evidence[0]      # masked in evidence!
    assert "alice" in f.evidence[0]


# ------------------------------------------------------------------ scoring

def test_scoring_single_critical_dominates():
    crit = Finding(id="x", title="t", severity=Severity.CRITICAL,
                   confidence=Confidence.HIGH)
    lows = [Finding(id=f"l{i}", title="t", severity=Severity.LOW,
                    confidence=Confidence.LOW) for i in range(5)]
    score = scoring.score_findings([crit] + lows)
    assert 90 <= score.score <= 100
    assert score.breakdown["CRITICAL"] == 1
    assert score.breakdown["LOW"] == 5


def test_scoring_empty_is_zero():
    s = scoring.score_findings([])
    assert s.score == 0 and s.label == "none"


def test_scoring_medium_confidence_discounts():
    med_high = Finding(id="a", title="t", severity=Severity.HIGH,
                       confidence=Confidence.HIGH)
    med_med = Finding(id="b", title="t", severity=Severity.HIGH,
                      confidence=Confidence.MEDIUM)
    assert scoring.score_findings([med_med]).score < \
           scoring.score_findings([med_high]).score


# ------------------------------------------------------------- integration

def test_full_detection_over_story_capture(tmp_path):
    """Scan + beacon + tunnel + cleartext creds in one pipeline run."""
    import base64, random
    random.seed(42)
    pkts = []
    pkts += syn_scan(C, S, range(100, 130))
    # beacon: 12 regular connections to C2
    t = BASE_TS + 100
    for i in range(12):
        pkts += tcp_conversation(C, 51000 + i, "198.51.100.66", 4444,
                                 [b"beacon-ping"], [b"ok"], base_ts=t,
                                 handshake=False, close=False)
        t += 60.0
    # DNS tunnel
    for i in range(30):
        chunk = base64.b32encode(random.randbytes(20)).decode().lower()
        pkts += dns_pair(C, "8.8.8.8", f"{chunk}.t.c2bad.example")
    # cleartext FTP creds
    pkts += tcp_conversation(C, 52000, S, 21, [b"USER admin\r\nPASS Passw0rd!\r\n"],
                             [b"220 srv\r\n230 ok\r\n"], base_ts=BASE_TS + 50)
    path = write_pcap(tmp_path / "story.pcap", pkts)

    res = Pipeline(path).run()
    ids = [f.id for f in res.findings]
    assert any(i.startswith("scan.syn.") for i in ids)
    assert any(i.startswith("beacon.tcp.") for i in ids)
    assert any(i.startswith("dns.tunnel.") for i in ids)
    assert "creds.cleartext.ftp" in ids
    assert res.score.score >= 80
    # timeline got built with events
    assert res.events and len(res.events) > 10
    # every finding carries a Wireshark filter or explicitly has none
    for f in res.findings:
        assert isinstance(f.wireshark_filters, list)
        assert f.explanation and f.verification  # explainability contract


def test_clean_capture_low_score(tmp_path):
    """Ordinary browsing + DNS keeps a low risk score."""
    pkts = []
    pkts += dns_pair(C, "8.8.8.8", "www.example.com", answers=["93.184.216.34"])
    pkts += dns_pair(C, "8.8.8.8", "github.com", answers=["140.82.121.4"])
    body = b"<html>hello world</html>"
    pkts += tcp_conversation(C, 44001, "93.184.216.34", 80,
                             [b"GET /index.html HTTP/1.1\r\nHost: www.example.com\r\n"
                              b"User-Agent: Mozilla/5.0\r\n\r\n"],
                             [b"HTTP/1.1 200 OK\r\nContent-Length: "
                              + str(len(body)).encode()
                              + b"\r\nContent-Type: text/html\r\n\r\n" + body])
    path = write_pcap(tmp_path / "clean.pcap", pkts)
    res = Pipeline(path).run()
    high = [f for f in res.findings if f.severity.value in ("HIGH", "CRITICAL")]
    assert high == [], [f.title for f in high]
    assert res.score.score < 35


def test_detector_crash_does_not_kill_engine(monkeypatch):
    """A raising detector surfaces as an INFO finding, never an abort."""
    def broken(result):
        raise RuntimeError("boom")
    real = behaviors.detect_syn_scan
    monkeypatch.setattr(behaviors, "detect_syn_scan", broken)
    try:
        # FakeResult has just enough for detect_host_scan to no-op cleanly
        findings = _run_engine_safe(FakeResult())
        assert any(f.id.startswith("internal.detector-error")
                   and f.severity == Severity.INFO for f in findings)
    finally:
        monkeypatch.setattr(behaviors, "detect_syn_scan", real)


def _run_engine_safe(result):
    """Directly exercise engine.run_detectors' error containment."""
    return engine.run_detectors(result)
