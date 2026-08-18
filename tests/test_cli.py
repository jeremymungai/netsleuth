"""CLI end-to-end tests via typer's CliRunner."""

from __future__ import annotations

import base64
import json
import os

from typer.testing import CliRunner

from netsleuth.cli import app

from pcapfix import BASE_TS, dns_pair, icmp_echo, syn_scan, tcp_conversation, write_pcap

runner = CliRunner()
C, S = "192.168.1.50", "203.0.113.9"


def build_capture(tmp_path, story="rich"):
    pkts = []
    if story == "rich":
        pkts += dns_pair(C, "8.8.8.8", "flagtown.example", answers=["203.0.113.9"])
        body = b"<html>picoCTF{cl1_t3st}</html>"
        pkts += tcp_conversation(
            C, 44001, S, 80,
            [b"GET /flag.php HTTP/1.1\r\nHost: flagtown.example\r\n\r\n"],
            [b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode()
             + b"\r\n\r\n" + body])
        pkts += tcp_conversation(C, 44002, S, 21,
                                 [b"USER ctfuser\r\nPASS ctfcmd;ls\r\n"],
                                 [b"220 ok\r\n230 ok\r\n"], base_ts=BASE_TS + 10)
        pkts += [icmp_echo(C, "198.51.100.7", b"n0t_a_tunn3l_payload_yes")]
    elif story == "clean":
        pkts += dns_pair(C, "8.8.8.8", "example.com", answers=["93.184.216.34"])
    elif story == "scan":
        pkts += syn_scan(C, S, range(100, 140))
    return write_pcap(tmp_path / "cap.pcap", pkts)


# ----------------------------------------------------------------- basics

def test_help_lists_all_commands():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for cmd in ("analyze", "summary", "hosts", "dns", "http", "tls", "streams",
                "stream", "extract", "secrets", "ctf", "detect", "timeline",
                "report"):
        assert cmd in result.output


def test_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "NetSleuth" in result.output


def test_missing_file_error_is_clean():
    result = runner.invoke(app, ["summary", "does-not-exist.pcap"])
    assert result.exit_code == 2
    assert "error" in result.output.lower()
    assert "Traceback" not in result.output


def test_non_capture_file_error(tmp_path):
    f = tmp_path / "fake.pcap"
    f.write_text("this is just text")
    result = runner.invoke(app, ["summary", str(f)])
    assert result.exit_code == 2
    assert "not a pcap" in result.output


# ------------------------------------------------------------- per-command

def test_summary_json(tmp_path):
    cap = build_capture(tmp_path, "clean")
    result = runner.invoke(app, ["summary", cap, "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["packet_count"] == 2
    assert data["format"] == "pcap"


def test_summary_table(tmp_path):
    cap = build_capture(tmp_path, "clean")
    result = runner.invoke(app, ["summary", cap])
    assert result.exit_code == 0
    assert "Capture Overview" in result.output
    assert "Packets" in result.output


def test_hosts_and_dns(tmp_path):
    cap = build_capture(tmp_path, "rich")
    assert runner.invoke(app, ["hosts", cap]).exit_code == 0
    r = runner.invoke(app, ["dns", cap])
    assert r.exit_code == 0
    assert "flagtown.example" in r.output


def test_http_stream_and_follow(tmp_path):
    cap = build_capture(tmp_path, "rich")
    r = runner.invoke(app, ["http", cap])
    assert r.exit_code == 0
    # note: table cells wrap at 80 cols under CliRunner, so match pieces
    assert "flagtown.example" in r.output
    assert "flag.php" in r.output.replace("\n", "")
    assert "200" in r.output
    r = runner.invoke(app, ["streams", cap])
    assert r.exit_code == 0
    r = runner.invoke(app, ["stream", cap, "0"])
    assert r.exit_code == 0
    assert "GET /flag.php" in r.output
    assert "tcp.stream == 0" in r.output


def test_stream_out_of_range(tmp_path):
    cap = build_capture(tmp_path, "clean")
    result = runner.invoke(app, ["stream", cap, "99"])
    assert result.exit_code == 2


def test_extract_writes_files(tmp_path):
    cap = build_capture(tmp_path, "rich")
    out = tmp_path / "carved"
    result = runner.invoke(app, ["extract", cap, "--output", str(out), "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["artifacts"]
    written = out / data["artifacts"][0]["filename"]
    assert written.exists()
    assert len(data["artifacts"][0]["sha256"]) == 64


def test_extract_requires_output(tmp_path):
    cap = build_capture(tmp_path, "rich")
    result = runner.invoke(app, ["extract", cap])
    assert result.exit_code == 2
    assert "--output" in result.output


def test_secrets_masked_and_revealed(tmp_path):
    cap = build_capture(tmp_path, "rich")
    r = runner.invoke(app, ["secrets", cap])
    assert r.exit_code == 0
    assert "picoCTF{cl1_t3st}" not in r.output          # masked by default
    r2 = runner.invoke(app, ["secrets", cap, "--reveal"])
    assert "picoCTF{cl1_t3st}" in r2.output


def test_secrets_custom_pattern(tmp_path):
    cap = build_capture(tmp_path, "rich")
    r = runner.invoke(app, ["secrets", cap, "--pattern", "ctfcmd;ls"])
    assert r.exit_code == 0
    assert "ctfcmd" in r.output


def test_secrets_bad_regex(tmp_path):
    cap = build_capture(tmp_path, "rich")
    result = runner.invoke(app, ["secrets", cap, "--pattern", "[unclosed"])
    assert result.exit_code == 2


def test_detect_and_json(tmp_path):
    cap = build_capture(tmp_path, "scan")
    r = runner.invoke(app, ["detect", cap])
    assert r.exit_code == 0
    assert "RISK SCORE" in r.output
    r2 = runner.invoke(app, ["detect", cap, "--json"])
    data = json.loads(r2.output)
    assert data["score"]["score"] >= 60
    assert any(f["id"].startswith("scan.syn.") for f in data["findings"])


def test_timeline_filters(tmp_path):
    cap = build_capture(tmp_path, "rich")
    r = runner.invoke(app, ["timeline", cap, "--kind", "dns"])
    assert r.exit_code == 0
    assert "DNS query" in r.output
    r2 = runner.invoke(app, ["timeline", cap, "--host", "10.9.9.9"])
    assert r2.exit_code == 0


def test_analyze_guided(tmp_path):
    cap = build_capture(tmp_path, "rich")
    r = runner.invoke(app, ["analyze", cap, "--verbose"])
    assert r.exit_code == 0
    for step in ("STEP 1", "STEP 11", "Wireshark"):
        assert step in r.output
    assert "picoCTF{cl1_t3st}" not in r.output      # masked by default


def test_ctf_mode(tmp_path):
    cap = build_capture(tmp_path, "rich")
    r = runner.invoke(app, ["ctf", cap, "--reveal"])
    assert r.exit_code == 0
    assert "picoCTF{cl1_t3st}" in r.output
    assert "CTF MODE" in r.output
    assert "How it was found" in r.output
    assert "checklist" in r.output.lower()


def test_ctf_xor(tmp_path):
    flag = b"flag{xor_me_plz}"
    key = 0x5A
    cipher = bytes(b ^ key for b in flag)
    pkts = tcp_conversation(C, 44500, S, 4444, [cipher], [],
                            base_ts=BASE_TS, handshake=False, close=False)
    cap = write_pcap(tmp_path / "xor.pcap", pkts)
    r = runner.invoke(app, ["ctf", cap, "--reveal"])
    assert r.exit_code == 0
    assert "flag{xor_me_plz}" in r.output
    assert "0x5a" in r.output.lower()


def test_ctf_base64(tmp_path):
    inner = "flag{b64_w1n}"
    blob = base64.b64encode(inner.encode()).decode()
    pkts = tcp_conversation(C, 44501, S, 8080, [f"note {blob}\r\n".encode()], [],
                            base_ts=BASE_TS, handshake=False, close=False)
    cap = write_pcap(tmp_path / "b64.pcap", pkts)
    r = runner.invoke(app, ["ctf", cap, "--reveal"])
    assert "flag{b64_w1n}" in r.output


def test_report_formats(tmp_path):
    cap = build_capture(tmp_path, "rich")
    for fmt, marker in (("html", "<!DOCTYPE html>"), ("md", "# NetSleuth"),
                        ("json", '"meta"')):
        out = tmp_path / f"r.{fmt}"
        r = runner.invoke(app, ["report", cap, "--format", fmt,
                                "--output", str(out)])
        assert r.exit_code == 0, r.output
        assert marker in out.read_text(encoding="utf-8")


def test_report_bad_format(tmp_path):
    cap = build_capture(tmp_path, "clean")
    result = runner.invoke(app, ["report", cap, "--format", "pdf"])
    assert result.exit_code == 2
