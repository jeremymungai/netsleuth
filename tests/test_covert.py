"""Covert-channel engine tests.

Positive: a known message hidden in HTTP version selection (and one in
DNS query-type choice) must be recovered — field identified, sequence
length correct, mapping tried, message decoded. Negative: benign
version variation and scapy's sequential IP IDs must NOT produce
candidates. The expected message is never hard-coded into the engine —
only into these tests.
"""

from __future__ import annotations

import random

from netsleuth.covert import encoding, variation
from netsleuth.pipeline import Options, Pipeline

from pcapfix import (
    BASE_TS, dns_pair, dns_qtype_covert, http_version_benign,
    http_version_covert, syn_scan, tcp_conversation, write_pcap,
)

C, S = "192.168.1.50", "203.0.113.9"
TRUTH = b"COVERT{m3tadata_ch4nn3l}"
DNS_TRUTH = b"DNS{tiny_meta}"


def covert_pcap(tmp_path, message=TRUTH):
    pkts, _ = http_version_covert(C, S, message)
    # red herrings: a second client with constant versions, random DNS
    # qtypes from a third, and a normal page fetch
    rng = random.Random(5)
    pkts += http_version_benign("192.168.1.61", S,
                                ["1.1"] * 60, base_ts=BASE_TS + 5)
    pkts += http_version_benign("192.168.1.62", S,
                                [rng.choice(("1.0", "1.1")) for _ in range(60)],
                                base_ts=BASE_TS + 6)
    for i in range(40):
        qtype = rng.choice(("A", "AAAA"))
        pkts += dns_pair("192.168.1.62", "8.8.8.8", f"h{i}.example",
                         answers=[], response=False)
    pkts += syn_scan("192.168.1.70", S, range(300, 330), base_ts=BASE_TS + 9)
    return write_pcap(tmp_path / "covert.pcap", pkts)


def run(path, modules=None):
    opts = Options(modules=modules) if modules else Options()
    return Pipeline(path, opts).run()


# ------------------------------------------------------------- unit: variation

def test_variation_two_state_pattern():
    rep = variation.analyze_variation(["A", "B"] * 20)
    assert rep.cardinality == 2
    assert rep.pattern == "two-state repeated sequence"
    assert variation.is_interesting(rep)


def test_variation_constant_and_one_sided_not_interesting():
    assert not variation.is_interesting(
        variation.analyze_variation(["1.1"] * 40))
    assert not variation.is_interesting(
        variation.analyze_variation(["1.0"] * 30 + ["1.1"] * 30))
    assert not variation.is_interesting(
        variation.analyze_variation(["A", "B", "A"]))       # too short


# -------------------------------------------------------------- unit: encoding

def test_mapping_candidates_binary_both_orders():
    maps = encoding.mapping_candidates(["1.0", "1.1", "1.0", "1.1"])
    assert len(maps) == 2
    texts = {m["1.0"] for m in maps}
    assert texts == {"0", "1"}


def test_bits_to_bytes_msb_and_lsb():
    bits = "01001000" "01101001"                    # "Hi"
    assert encoding.bits_to_bytes(bits, "msb", "trailing") == b"Hi"
    lsb = encoding.bits_to_bytes(bits, "lsb", "trailing")
    assert lsb == bytes(int(b[::-1], 2) for b in ("01001000", "01101001"))


def test_decode_recovers_roundtrip():
    msg = b"Hi"
    bits = "".join(format(b, "08b") for b in msg)
    values = []
    for ch in bits:
        values.append("1.1" if ch == "1" else "1.0")
    cands = encoding.decode_candidates(values)
    assert cands, "expected at least one candidate"
    best = cands[0]
    assert best.data.startswith(msg) or msg in best.data
    assert best.printable > 0.9


# -------------------------------------------------------- positive: HTTP covert

def test_http_version_channel_recovered(tmp_path):
    res = run(covert_pcap(tmp_path))
    cands = [c for c in res.covert
             if c.protocol == "http" and c.field == "request version"
             and c.source == C]
    assert cands, [c.field for c in res.covert]
    c = cands[0]
    assert TRUTH.decode() in c.decoded
    assert c.sequence_len == len(TRUTH) * 8
    assert set(c.observed_values) == {"HTTP/1.0", "HTTP/1.1"}
    assert c.mapping and ("HTTP/1.0" in c.mapping)
    assert c.bits_len == len(TRUTH) * 8
    assert c.byte_len == len(TRUTH)
    assert c.confidence in ("medium", "high")
    assert c.wireshark_filters and "http.request" in c.wireshark_filters[0]
    assert c.assumptions and c.alternatives_considered


def test_covert_becomes_finding(tmp_path):
    res = run(covert_pcap(tmp_path))
    ids = [f.id for f in res.findings]
    assert any(i.startswith("covert.http.request version") for i in ids)
    cov = next(f for f in res.findings if f.id.startswith("covert.http"))
    assert cov.wireshark_filters and cov.evidence
    assert any(m.technique == "T1132.001" for m in cov.mitre)


# ---------------------------------------------------------- positive: DNS qtype

def test_dns_qtype_channel_recovered(tmp_path):
    pkts, _ = dns_qtype_covert("192.168.1.63", "8.8.8.8", DNS_TRUTH)
    path = write_pcap(tmp_path / "dnscovert.pcap", pkts)
    res = run(path)
    cands = [c for c in res.covert if c.protocol == "dns"
             and c.field == "query type"]
    assert cands, [c.field for c in res.covert]
    assert DNS_TRUTH.decode() in cands[0].decoded
    assert cands[0].frames                     # DNS observations carry frames


# --------------------------------------------------------------- negative cases

def test_benign_random_versions_no_candidate(tmp_path):
    """Random 50/50 version choice decodes to noise → engine stays quiet."""
    rng = random.Random(1234)
    pkts = http_version_benign(C, S,
                               [rng.choice(("1.0", "1.1")) for _ in range(80)])
    path = write_pcap(tmp_path / "benign.pcap", pkts)
    res = run(path)
    version_cands = [c for c in res.covert
                     if c.field == "request version" and c.decoded]
    assert version_cands == [] or all(
        c.printable_ratio < 0.8 for c in version_cands)


def test_constant_versions_no_candidate(tmp_path):
    path = write_pcap(tmp_path / "const.pcap", http_version_benign(C, S, ["1.1"] * 80))
    res = run(path)
    assert [c for c in res.covert if c.field == "request version"] == []


def test_sequential_ip_ids_not_flagged(tmp_path):
    """scapy writes sequential IP IDs (perfect parity alternation → 'UUU…');
    that benign generator must not become a covert finding."""
    pkts = tcp_conversation(C, 49000, S, 80,
                            [b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"] * 8,
                            [b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"] * 8)
    path = write_pcap(tmp_path / "seq.pcap", pkts)
    res = run(path)
    assert [c for c in res.covert if c.field == "IP ID parity"] == []


# ------------------------------------------------------------------ CLI

def test_cli_covert_command(tmp_path):
    from typer.testing import CliRunner
    from netsleuth.cli import app
    runner = CliRunner()
    cap = covert_pcap(tmp_path)
    r = runner.invoke(app, ["covert", cap])
    assert r.exit_code == 0
    assert "covert" in r.output.lower()
    # message appears only via the decoded candidate; keep assertion robust
    # to terminal wrapping
    joined = r.output.replace("\n", "")
    assert ("COVERT{" in joined) or ("m3tadata" in joined)


def test_ctf_includes_covert_phase(tmp_path):
    from typer.testing import CliRunner
    from netsleuth.cli import app
    runner = CliRunner()
    cap = covert_pcap(tmp_path)
    r = runner.invoke(app, ["ctf", cap, "--reveal"])
    assert r.exit_code == 0
    assert "covert" in r.output.lower()
