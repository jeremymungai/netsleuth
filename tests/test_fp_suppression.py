"""Regression tests for false-positive suppression.

Each test encodes a false positive observed on a real enterprise capture
(Windows domain-joined host, DC at 10.0.19.9, CDN traffic) and asserts
the detector stays quiet — while the matching true-positive case still
fires.
"""

from __future__ import annotations

from netsleuth.covert import fields as covert_fields, variation
from netsleuth.detection import allowlists, beaconing, dcs, dnshunt
from netsleuth.models import DNSRecord, Flow, Host, Packet

C, DC = "10.0.19.14", "10.0.19.9"
BASE_TS = 1_648_000_000.0


class FakeHosts:
    def __init__(self):
        self.flow_tracker = type("FT", (), {"flows": {}, "conversations": {}})()
        self.hosts = {}


class FakeResult:
    def __init__(self, **kw):
        self.overview = kw.get("overview")
        self.dns = kw.get("dns")
        self.domain_controllers = kw.get("domain_controllers", set())
        self.http = kw.get("http", [])


def make_dns_data(queries):
    """queries: (name, ts, rcode, is_response) tuples."""
    from netsleuth.analyzers.dns import DNSAnalyzer
    ana = DNSAnalyzer()
    for i, (name, ts, rcode, resp) in enumerate(queries):
        p = Packet(ts=ts, src=C, dst=DC, proto="udp", sport=5353, dport=53)
        p.dns = DNSRecord(ts=ts, client=C, server=DC, name=name, qtype="A",
                          is_response=resp, response_code=rcode, frame=i + 1)
        ana.feed(p)
    return ana.data


# ---------------------------------------------------- Improvement 2: DNS FPs

def test_ad_discovery_queries_not_tunneling():
    """_ldap SRV + WPAD lookups must not be flagged as DNS tunneling."""
    names = (["_ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.burnincandle.com",
              "wpad.burnincandle.com", "BURNINCANDLE-DC.burnincandle.com",
              "wpad.mshome.net"] * 12)
    queries = [(n, BASE_TS + i, "NXDOMAIN", False) for i, n in enumerate(names)]
    assert dnshunt.detect_dns_tunneling(FakeResult(dns=make_dns_data(queries))) == []


def test_ad_discovery_nxdomain_not_anomaly():
    """WPAD retries NXDOMAIN by design — no DGA-style finding."""
    queries = ([("wpad.burnincandle.com", BASE_TS + i, "NXDOMAIN", True)
                for i in range(40)])
    assert dnshunt.detect_nxdomain_anomaly(FakeResult(dns=make_dns_data(queries))) == []


def test_real_tunneling_still_detected():
    import base64, random
    random.seed(7)
    queries = []
    for i in range(40):
        chunk = base64.b32encode(random.randbytes(20)).decode().lower()
        queries.append((f"{chunk}.tunnel.evil.example", BASE_TS + i, "NOERROR", False))
    findings = dnshunt.detect_dns_tunneling(FakeResult(dns=make_dns_data(queries)))
    assert len(findings) == 1 and "evil.example" in findings[0].title


# ------------------------------------------------- Improvement 3: telemetry

def test_telemetry_allowlist_matching():
    assert allowlists.is_telemetry_domain("v10.events.data.microsoft.com")
    assert allowlists.is_telemetry_domain("ctldl.windowsupdate.com")
    assert not allowlists.is_telemetry_domain("otectagain.top")
    assert not allowlists.is_telemetry_domain("seaskysafe.com")


def test_telemetry_dns_beacon_skipped_but_c2_kept():
    """Periodic lookups of telemetry domains are quiet; unknown C2 fires."""
    def dns_with(name):
        queries = [(name, BASE_TS + i * 1800, "NOERROR", False) for i in range(12)]
        return FakeResult(dns=make_dns_data(queries))
    assert beaconing.detect_dns_beaconing(dns_with("v10.events.data.microsoft.com")) == []
    assert beaconing.detect_dns_beaconing(dns_with("ctldl.windowsupdate.com")) == []
    assert len(beaconing.detect_dns_beaconing(dns_with("otectagain.top"))) == 1


def test_wpad_dns_beacon_skipped():
    queries = [("wpad.mshome.net", BASE_TS + i * 60, "NXDOMAIN", False)
               for i in range(15)]
    assert beaconing.detect_dns_beaconing(FakeResult(dns=make_dns_data(queries))) == []


# ---------------------------------------------- Improvement 4: Host header

def test_hostname_alphabet_not_a_covert_channel():
    values = ["ctldl.windowsupdate.com", "x1.c.lencr.org",
              "oceriesfornot.top", "r3.i.lencr.org"] * 8
    assert variation.all_hostnames(sorted(set(values)))
    assert not variation.all_hostnames(["a", "ab", "ba", "b"] * 8)


# --------------------------------------- Improvement 5: DC identification

def test_dc_ports():
    assert dcs.is_dc_port(88) and dcs.is_dc_port(445) and dcs.is_dc_port(135)
    assert dcs.is_dc_port(49667)
    assert not dcs.is_dc_port(443) and not dcs.is_dc_port(8080)


def test_ldap_listener_identified_as_dc():
    ov = FakeHosts()
    ov.hosts = {DC: Host(ip=DC, is_internal=True),
                C: Host(ip=C, is_internal=True)}
    f = Flow(proto="tcp", src=C, sport=50000, dst=DC, dport=389,
             packets=6, bytes=200, first_ts=BASE_TS, last_ts=BASE_TS + 1,
             ack_of_syn=True)
    ov.flow_tracker.flows[f.key] = f
    assert dcs.find_domain_controllers(FakeResult(overview=ov)) == {DC}


def _beacon_flows(dst, dport, n=10):
    flows = [Flow(proto="tcp", src=C, sport=40000 + i, dst=dst,
                  dport=dport, packets=4, bytes=100,
                  first_ts=BASE_TS + i * 600.0, last_ts=BASE_TS + i * 600.0 + 1,
                  syn_count=1, ack_of_syn=True)
             for i in range(n)]
    return {fl.key: fl for fl in flows}


def test_periodic_dc_traffic_not_beaconing():
    ov = FakeHosts()
    ov.flow_tracker.flows = _beacon_flows(DC, 445)
    res = FakeResult(overview=ov, domain_controllers={DC})
    assert beaconing.detect_tcp_beaconing(res) == []


def test_periodic_external_traffic_still_beacons():
    ov = FakeHosts()
    ov.flow_tracker.flows = _beacon_flows("185.166.143.50", 443)
    res = FakeResult(overview=ov, domain_controllers={DC})
    assert len(beaconing.detect_tcp_beaconing(res)) == 1


# ---------------------------------- Improvement 1: external TCP/IP metadata

class _Obs:
    def __init__(self, ts, flags="SA", ip_id=1, length=60, dport=443,
                 ip_ttl=0):
        self.ts, self.flags, self.ip_id, self.length = ts, flags, ip_id, length
        self.frame, self.dport, self.ip_ttl = 1, dport, ip_ttl


class _Collector:
    def __init__(self, seqs):
        self.seqs = seqs


def _external_tcp_stream():
    return _Collector({"104.80.96.219": [_Obs(BASE_TS + i, ip_id=2 * i + (i % 2))
                                         for i in range(20)]})


def test_external_tcp_metadata_fields_skipped():
    # the LAN is known (one internal host), so the external CDN source's
    # kernel-owned fields must be filtered out
    class Res:
        overview = type("OV", (), {"hosts": {
            C: Host(ip=C, is_internal=True),
            "104.80.96.219": Host(ip="104.80.96.219", is_internal=False)}})()
        covert_collector = _external_tcp_stream()
        http = []
        dns = None
    streams = covert_fields.extract_all(Res)
    fields = {s.field for s in streams}
    assert "IP ID parity" not in fields and "TCP flag set" not in fields


def test_internal_tcp_metadata_fields_kept():
    class Res:
        overview = type("OV", (), {"hosts": {C: Host(ip=C, is_internal=True)}})()
        covert_collector = _Collector({C: [_Obs(BASE_TS + i,
                                                ip_id=(i * 7919) % 65536 + (i % 2))
                                           for i in range(20)]})
        http = []
        dns = None
    streams = covert_fields.extract_all(Res)
    assert "IP ID parity" in {s.field for s in streams}
