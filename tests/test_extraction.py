"""Extraction tests: rules, encodings, carving, secrets."""

from __future__ import annotations

import base64

import pytest

from netsleuth import rules as rules_mod
from netsleuth.extraction import carve, encodings, secrets, strings
from netsleuth.models import StreamData, StreamInfo
from netsleuth.pipeline import Options, Pipeline

from pcapfix import tcp_conversation, write_pcap

C, S = "192.168.1.50", "93.184.216.34"


# ------------------------------------------------------------------- rules

def test_builtin_rules_load():
    book = rules_mod.load_rules()
    assert any(r.kind == "flag" for r in book.values())
    assert any(r.kind == "api-key" for r in book.values())


def test_custom_rule_override_and_merge(tmp_path):
    custom = tmp_path / "custom.yaml"
    custom.write_text(
        "rules:\n"
        "  - id: my.flag\n"
        "    kind: flag\n"
        "    pattern: 'MINE\\{[!-~]{4,}\\}'\n"
        "    confidence: high\n"
        "    score: 100\n"
        "  - id: ctf.flag.named\n"                 # overrides builtin by id? no —
        "    kind: flag\n"                          # (namespaced below)
        "    pattern: 'OVERRIDDEN\\{\\}'\n")
    book = rules_mod.load_rules([str(custom)])
    assert "custom.my.flag" in book
    assert book["custom.ctf.flag.named"].pattern == r"OVERRIDDEN\{\}"
    assert book["ctf.flag.named"].pattern != r"OVERRIDDEN\{\}"  # builtin intact


def test_bad_rule_file_raises(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("rules: 'not a list'")
    with pytest.raises(rules_mod.RuleError):
        rules_mod.load_rules([str(bad)])
    with pytest.raises(rules_mod.RuleError):
        rules_mod.load_rules([str(tmp_path / "missing.yaml")])


# ---------------------------------------------------------------- encodings

def test_base64_detection_and_chain():
    inner = "FLAG{b64_inside}"
    once = base64.b64encode(inner.encode()).decode()
    chain = encodings.analyze_chain(once)
    assert chain.steps[0].encoding == "Base64"
    assert chain.final == inner
    assert chain.final_is_printable


def test_double_encoding_chain():
    import urllib.parse
    # \xff\xfe\xfb bytes guarantee base64 specials (+ or /) so the URL
    # layer really has something to encode (>=2 %xx sequences)
    inner = "flag{d0uble_3ncoded\xff\xfe\xfb}".encode("latin-1")
    once = base64.b64encode(inner).decode()
    assert "+" in once or "/" in once
    twice = urllib.parse.quote(once, safe="")
    chain = encodings.analyze_chain(twice)
    assert [s.encoding for s in chain.steps] == ["URL-encoded", "Base64"]
    assert chain.final == inner.decode("latin-1")


def test_hex_detection():
    chain = encodings.analyze_chain("666c61677b6865787d")
    assert chain.steps[0].encoding == "Hex"
    assert chain.final == "flag{hex}"


def test_plain_text_not_detected():
    assert encodings.detect_encoding("just normal words here") is None


def test_xor_brute():
    flag = b"flag{xor_is_fun}"
    key = 0x2A
    blob = bytes(b ^ key for b in flag)
    hits = encodings.xor_brute_prefix(blob)
    assert (key, "flag{xor_is_fun}") in hits


# ------------------------------------------------------------------ carving

def fake_result(http_transactions=(), smtp=(), stream_data=()):
    class R:
        pass
    r = R()
    r.http = list(http_transactions)
    r.smtp_traffic = list(smtp)
    r.stream_data = list(stream_data)
    return r


def test_carve_http_body_with_magic_typing(tmp_path):
    from netsleuth.models import HTTPTransaction
    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
    t = HTTPTransaction(ts=1.0, stream=0, client=C, host="evil.test",
                        method="GET", url="/payloads/img.png", path="/payloads/img.png",
                        status=200, content_type_resp="image/png", resp_body=png)
    arts = carve.carve_all(fake_result([t]), str(tmp_path))
    assert len(arts) == 1
    a = arts[0]
    assert a.detected_type == "PNG image"
    assert a.filename.endswith("img.png")
    assert len(a.sha256) == 64 and len(a.md5) == 32
    assert (tmp_path / a.filename).exists()


def test_carve_sanitizes_evil_filenames(tmp_path):
    from netsleuth.models import HTTPTransaction
    t = HTTPTransaction(ts=1.0, stream=0, client=C, host="x", method="GET",
                        url="/..%2F..%2Fetc%2Fpasswd", path="/../../etc/passwd",
                        status=200, resp_body=b"root:x:0:0:root:/root:/bin/sh\n")
    arts = carve.carve_all(fake_result([t]), str(tmp_path))
    a = arts[0]
    assert ".." not in a.filename
    assert "\\" not in a.filename and "/" not in a.filename
    resolved = (tmp_path / a.filename).resolve()
    assert str(resolved).startswith(str(tmp_path.resolve()))


def test_carve_smtp_attachment(tmp_path):
    mail = (b"From: a@b\nTo: c@d\nSubject: s\n"
            b"MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=X\n\n"
            b"--X\nContent-Type: text/plain\n\nhello\n"
            b"--X\nContent-Type: application/octet-stream\n"
            b"Content-Disposition: attachment; filename=\"payload.exe\"\n"
            b"Content-Transfer-Encoding: base64\n\n"
            + base64.b64encode(b"MZ" + b"\x00" * 30) + b"\n--X--\n")
    st = StreamData(info=StreamInfo(index=3, client=C, server=S, client_port=1,
                                    server_port=25),
                    c2s=b"EHLO x\r\nMAIL FROM:<a@b>\r\nDATA\r\n" + mail + b"\r\n.\r\n")
    r = fake_result(smtp=[{"stream": 3, "from": "a@b", "to": ["c@d"],
                           "client": C, "server": S, "has_data": True}],
                    stream_data=[st])
    arts = carve.carve_all(r, str(tmp_path))
    exe = [a for a in arts if a.filename.endswith("payload.exe")]
    assert exe and exe[0].detected_type == "Windows PE executable"


def test_carve_budget(tmp_path):
    from netsleuth.models import HTTPTransaction
    big = b"A" * 700
    w = carve._Writer(str(tmp_path), budget=1000)
    assert w.write(big, "one.bin") is not None
    assert w.write(big, "two.bin") is None          # over budget → refused
    assert w.skipped == 1


# ------------------------------------------------------------------ secrets

def build_stream(c2s: bytes, s2c: bytes = b"", port=80, index=0):
    return StreamData(info=StreamInfo(index=index, client=C, server=S,
                                      client_port=44000, server_port=port,
                                      start_ts=1755400000.0),
                      c2s=c2s, s2c=s2c)


class FakeResult:
    def __init__(self, streams=(), http=(), dns=None, icmp=()):
        self.stream_data = list(streams)
        self.http = list(http)
        self.dns = dns
        self.icmp = list(icmp)


def test_secret_flag_in_stream():
    st = build_stream(b"hello\r\npicoCTF{str34ms_ar3_fun}\r\nbye\r\n")
    hits = secrets.scan(FakeResult(streams=[st]))
    flags = [h for h in hits if h.kind == "flag"]
    assert any("picoCTF{str34ms_ar3_fun}" in h.value for h in flags)
    m = flags[0]
    assert "TCP stream 0" in m.source
    assert m.confidence == "high"
    assert "netsleuth stream 0" in m.how


def test_secret_aws_key_in_http_body():
    from netsleuth.models import HTTPTransaction
    t = HTTPTransaction(ts=1.0, stream=1, client=C, host="paste.test",
                        method="GET", url="/p", path="/p", status=200,
                        resp_body=b"leaked key: AKIAIOSFODNN7EXAMPLE oh no")
    hits = secrets.scan(FakeResult(http=[t]))
    keys = [h for h in hits if h.kind == "api-key"]
    assert any("AKIAIOSFODNN7EXAMPLE" in h.value for h in keys)


def test_secret_custom_cli_pattern():
    st = build_stream(b"data ZZZ{custom_pattern_here} more")
    rule = rules_mod.adhoc_rule(r"ZZZ\{[a-z_]+\}")
    hits = secrets.scan(FakeResult(streams=[st]), extra_rule=rule)
    assert any(h.value == "ZZZ{custom_pattern_here}" for h in hits)


def test_secret_masking():
    from netsleuth.models import SecretMatch
    m = SecretMatch(kind="flag", value="picoCTF{abcdef123}", source="x")
    masked = m.masked()
    assert "abcdef123" not in masked
    assert masked.startswith("picoCTF")


def test_secrets_end_to_end(tmp_path):
    """Flag hidden in an HTTP response body, found via the full pipeline."""
    body = b"<html>FLAG{http_b0dy_sc4n}</html>"
    pkts = tcp_conversation(C, 44001, S, 80,
                            [b"GET /flag HTTP/1.1\r\nHost: ctf.test\r\n\r\n"],
                            [b"HTTP/1.1 200 OK\r\nContent-Length: "
                             + str(len(body)).encode() + b"\r\n\r\n" + body])
    path = write_pcap(tmp_path / "ctf.pcap", pkts)
    res = Pipeline(path, Options(modules={"streams", "http", "secrets"})).run()
    assert any("FLAG{http_b0dy_sc4n}" in s.value for s in res.secrets)


# ------------------------------------------------------------------ strings

def test_string_ranking():
    data = (b"ordinary text that nobody cares about          \n"
            b"password=Sup3rS3cr3t!\n"
            b"https://evil.example/payload\n"
            b"MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=")
    top = strings.top_strings(data, n=5)
    values = [s.value for s in top]
    assert values[0].startswith(b"password=".decode())
    assert any(v.startswith("https://") for v in values)
