"""Reporting tests: markdown, html escaping, wireshark companion, json."""

from __future__ import annotations

import json

from netsleuth.pipeline import Options, Pipeline
from netsleuth.reporting import html as html_mod
from netsleuth.reporting import markdown as md_mod
from netsleuth.reporting import wireshark as ws_mod
from netsleuth.reporting.reports import write_report

from pcapfix import dns_pair, tcp_conversation, write_pcap

C, S = "192.168.1.50", "203.0.113.9"


def story_pcap(tmp_path):
    pkts = []
    pkts += dns_pair(C, "8.8.8.8", "evil<xss>.example<script>alert(1)</script>")
    body = b"<html>FLAG{r3port_t3st}</html>"
    pkts += tcp_conversation(
        C, 44001, S, 80,
        [b"GET /q?cmd=cat+/etc/passwd HTTP/1.1\r\nHost: \"quoted<script>\r\n"
         b"User-Agent: sqlmap/1.7\r\n\r\n"],
        [b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode()
         + b"\r\n\r\n" + body])
    return write_pcap(tmp_path / "rep.pcap", pkts)


def run(path):
    return Pipeline(path).run()


def test_markdown_report_structure(tmp_path):
    res = run(story_pcap(tmp_path))
    md = md_mod.generate_markdown(res)
    for section in ("Executive summary", "Capture overview", "Hosts", "DNS findings",
                    "HTTP findings", "Suspicious activity", "Timeline",
                    "Recommended manual investigation"):
        assert section in md, section
    assert "Risk score" in md


def test_html_report_escapes_capture_content(tmp_path):
    """The report renders attacker-controlled strings — they must be escaped."""
    res = run(story_pcap(tmp_path))
    page = html_mod.generate_html(res)
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page
    assert "<!DOCTYPE html>" in page
    assert "onclick" not in page
    # no external resources
    assert "http://" not in page.replace("http.request", "").replace("http.host", "")
    assert "https://" not in page


def test_json_report_roundtrip(tmp_path):
    res = run(story_pcap(tmp_path))
    data = json.loads(json.dumps(res.to_dict()))
    assert data["meta"]["packet_count"] > 0
    assert "findings" in data and "score" in data
    if res.secrets:
        assert data["secrets"][0]["value"] != res.secrets[0].value   # masked
    # masked creds
    for c in data["credentials"]:
        assert "password" in c


def test_wireshark_companion(tmp_path):
    res = run(story_pcap(tmp_path))
    groups = ws_mod.companion_filters(res)
    flat = [f for _t, fs in groups for f in fs]
    assert any("ip.addr ==" in f for f in flat)
    assert any("dns.qry.name" in f for f in flat)
    # every filter is a plausible display filter (no newlines, sane length)
    for f in flat:
        assert "\n" not in f and len(f) < 200


def test_write_report_all_formats(tmp_path):
    pcap = story_pcap(tmp_path)
    res = run(pcap)
    for fmt, marker in (("json", '"meta"'), ("md", "# NetSleuth"),
                        ("html", "<!DOCTYPE html>")):
        out = tmp_path / f"report.{fmt}"
        write_report(res, fmt, str(out))
        content = out.read_text(encoding="utf-8")
        assert marker in content
