"""Analyzer tests: HTTP, TLS, cleartext protocols, DHCP, ARP, ICMP.

TLS fixtures are hand-built byte strings — that is the point: the parser
is verified against known-good wire structure, not against whatever a
library happens to emit.
"""

from __future__ import annotations

import struct

from netsleuth.analyzers.clearcreds import ClearTextAnalyzer
from netsleuth.analyzers.dhcp import parse_dhcp
from netsleuth.analyzers.dns import shannon_entropy
from netsleuth.analyzers.http import HTTPAnalyzer
from netsleuth.analyzers.tls import TLSAnalyzer, parse_x509_basics
from netsleuth.models import StreamData, StreamInfo
from netsleuth.pipeline import Options, Pipeline

from pcapfix import write_pcap, tcp_conversation, dns_pair

C, S = "192.168.1.50", "203.0.113.9"


def make_stream(c2s: bytes, s2c: bytes = b"", port=80, index=0) -> StreamData:
    info = StreamInfo(index=index, client=C, server=S, client_port=44000,
                      server_port=port, start_ts=1755400000.0, end_ts=1755400001.0)
    return StreamData(info=info, c2s=c2s, s2c=s2c)


# ------------------------------------------------------------------ HTTP

def test_http_get_response_pair():
    c2s = (b"GET /download/report.pdf?a=1&b=2 HTTP/1.1\r\n"
           b"Host: files.example.com\r\n"
           b"User-Agent: Mozilla/5.0 (test)\r\n"
           b"\r\n")
    s2c = (b"HTTP/1.1 200 OK\r\n"
           b"Content-Type: application/pdf\r\n"
           b"Server: nginx\r\n"
           b"Content-Length: 5\r\n\r\n" + b"%PDF-")
    http = HTTPAnalyzer()
    http.analyze([make_stream(c2s, s2c)])
    assert len(http.transactions) == 1
    t = http.transactions[0]
    assert t.method == "GET" and t.status == 200
    assert t.host == "files.example.com"
    assert t.path == "/download/report.pdf"
    assert t.query == "a=1&b=2"
    assert t.user_agent == "Mozilla/5.0 (test)"
    assert t.content_type_resp == "application/pdf"
    assert t.resp_body == b"%PDF-"


def test_http_post_body_and_keepalive():
    body = b"username=admin&password=hunter2"
    c2s = (b"POST /login HTTP/1.1\r\nHost: x.test\r\n"
           b"Content-Type: application/x-www-form-urlencoded\r\n"
           + f"Content-Length: {len(body)}\r\n\r\n".encode() + body +
           b"GET /next HTTP/1.1\r\nHost: x.test\r\n\r\n")
    s2c = (b"HTTP/1.1 302 Found\r\nContent-Length: 0\r\n\r\n"
           b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
    http = HTTPAnalyzer()
    http.analyze([make_stream(c2s, s2c)])
    ts = http.transactions
    assert len(ts) == 2
    assert ts[0].method == "POST" and ts[0].status == 302
    assert ts[0].req_body == body
    assert ts[1].method == "GET" and ts[1].status == 200
    assert ts[1].resp_body == b"ok"


def test_http_chunked_response():
    s2c = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
           b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
    http = HTTPAnalyzer()
    http.analyze([make_stream(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", s2c)])
    assert http.transactions[0].resp_body == b"hello world"


def test_http_basic_auth_extraction():
    import base64
    cred = base64.b64encode(b"admin:secretpw").decode()
    c2s = (f"GET /admin HTTP/1.1\r\nHost: x\r\nAuthorization: Basic {cred}\r\n\r\n").encode()
    clear = ClearTextAnalyzer()
    clear.analyze([make_stream(c2s, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")])
    assert any(c.username == "admin" and c.password == "secretpw"
               for c in clear.credentials)


def test_http_on_nonstandard_port_detected_by_content():
    c2s = b"GET /ctf HTTP/1.1\r\nHost: ctf.local\r\n\r\n"
    http = HTTPAnalyzer()
    http.analyze([make_stream(c2s, b"", port=31337)])
    assert len(http.transactions) == 1


# ------------------------------------------------------------------- TLS

def build_client_hello(sni=b"example.com", ciphers=(0x1301, 0xc02f, 0x1302),
                       alpn=(b"h2", b"http/1.1"), version=0x0303):
    def ext(etype, data):
        return struct.pack(">HH", etype, len(data)) + data

    exts = b""
    if sni:
        name = struct.pack(">H", len(sni)) + sni
        sni_list = b"\x00" + name
        exts += ext(0, struct.pack(">H", len(sni_list)) + sni_list)
    exts += ext(10, b"\x00\x02\x00\x1d")                     # supported_groups: x25519
    exts += ext(11, b"\x01\x00")                             # ec_point_formats: uncompressed
    if alpn:
        protos = b"".join(bytes([len(p)]) + p for p in alpn)
        exts += ext(16, protos)
    supported_versions = struct.pack(">B", 2 * 2) + struct.pack(">HH", 0x0303, 0x0304)
    exts += ext(43, supported_versions)

    body = struct.pack(">H", version) + b"\x11" * 32          # version + random
    body += b"\x00"                                           # session id
    body += struct.pack(">H", len(ciphers) * 2) + b"".join(struct.pack(">H", c) for c in ciphers)
    body += b"\x01\x00"                                       # compression methods
    body += struct.pack(">H", len(exts)) + exts
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def build_server_hello(cipher=0x1301):
    body = struct.pack(">H", 0x0303) + b"\x22" * 32 + b"\x00"
    body += struct.pack(">H", cipher) + b"\x00"
    exts = struct.pack(">H", 4) + struct.pack(">HH", 43, 2) + struct.pack(">H", 0x0304)
    body += exts
    hs = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + struct.pack(">H", len(hs)) + hs


def der_len(n):
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def der_tlv(tag, content):
    return bytes([tag]) + der_len(len(content)) + content


def build_cert(cn=b"example.com", issuer_cn=b"Test CA"):
    oid_cn = der_tlv(0x06, b"\x55\x04\x03")
    oid_sha256rsa = der_tlv(0x06, b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b")

    def name(cn_bytes):
        return der_tlv(0x30, der_tlv(0x31, der_tlv(0x30, oid_cn + der_tlv(0x0c, cn_bytes))))

    validity = der_tlv(0x30, der_tlv(0x17, b"250101000000Z") + der_tlv(0x17, b"351231235959Z"))
    spki = der_tlv(0x30, der_tlv(0x30, der_tlv(0x06, b"\x2a\x86\x48\xce\x3d\x02\x01")) + der_tlv(0x03, b"\x00\x04\x20" + b"\x01" * 32))
    tbs = (der_tlv(0xA0, der_tlv(0x02, b"\x02"))            # version v3
           + der_tlv(0x02, b"\x01\x02\x03")                  # serial
           + der_tlv(0x30, oid_sha256rsa + der_tlv(0x05, b""))
           + name(issuer_cn) + validity + name(cn) + spki)
    cert = der_tlv(0x30, tbs + der_tlv(0x30, oid_sha256rsa + der_tlv(0x05, b""))
                   + der_tlv(0x03, b"\x00" + b"\xaa" * 16))
    return cert


def build_certificate_message(cert_der):
    cert_entry = len(cert_der).to_bytes(3, "big") + cert_der
    body = len(cert_entry).to_bytes(3, "big") + cert_entry
    hs = b"\x0b" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + struct.pack(">H", len(hs)) + hs


def test_tls_client_hello_sni_ja3_alpn():
    c2s = build_client_hello()
    s2c = build_server_hello() + build_certificate_message(build_cert())
    tls = TLSAnalyzer()
    tls.analyze([make_stream(c2s, s2c, port=443)])
    assert len(tls.sessions) == 1
    s = tls.sessions[0]
    assert s.sni == "example.com"
    assert "TLS 1.3" in s.tls_version
    assert s.alpn == ["h2", "http/1.1"]
    assert len(s.ja3) == 32                                    # md5 hex
    assert "771" in s.ja3_clear and "4865" in s.ja3_clear      # version + TLS1.3 cipher


def test_tls_certificate_metadata():
    cert = build_cert(cn=b"evil.example", issuer_cn=b"Evil CA")
    info = parse_x509_basics(cert)
    assert info["subject"] == "CN=evil.example"
    assert info["issuer"] == "CN=Evil CA"
    assert info["not_before"] == "2025-01-01 00:00:00Z"
    assert info["not_after"] == "2035-12-31 23:59:59Z"
    assert info["self_signed"] is False

    self_signed = build_cert(cn=b"localhost", issuer_cn=b"localhost")
    assert parse_x509_basics(self_signed)["self_signed"] is True


def test_tls_grease_excluded_from_ja3():
    c2s = build_client_hello(ciphers=(0x0a0a, 0x1301))         # GREASE + real
    tls = TLSAnalyzer()
    tls.analyze([make_stream(c2s, b"", port=443)])
    assert "2570" not in tls.sessions[0].ja3_clear            # 0x0a0a decimal


# --------------------------------------------------------------- cleartext

def test_ftp_credentials():
    c2s = b"USER alice\r\nPASS Sup3rS3cret\r\nSYST\r\nPWD\r\n"
    s2c = b"220 ftp.test FTP\r\n331 need password\r\n230 logged in\r\n"
    clear = ClearTextAnalyzer()
    clear.analyze([make_stream(c2s, s2c, port=21)])
    creds = [c for c in clear.credentials if c.protocol == "ftp"]
    assert creds and creds[0].username == "alice"
    assert creds[0].password == "Sup3rS3cret"
    assert "230" in creds[0].detail
    assert any("ftp.test" in b for b in clear.banners.values())


def test_smtp_auth_and_envelope():
    import base64
    c2s = (b"EHLO client\r\n"
           b"AUTH LOGIN\r\n" +
           base64.b64encode(b"alice") + b"\r\n" +
           base64.b64encode(b"pass123") + b"\r\n" +
           b"MAIL FROM:<alice@test>\r\nRCPT TO:<bob@test>\r\nDATA\r\n"
           b"Subject: hi\r\n\r\nbody here\r\n.\r\nQUIT\r\n")
    clear = ClearTextAnalyzer()
    clear.analyze([make_stream(c2s, b"250 ok\r\n", port=25)])
    assert any(c.protocol == "smtp" and c.username == "alice" and c.password == "pass123"
               for c in clear.credentials)
    assert clear.smtp_traffic and clear.smtp_traffic[0]["from"] == "alice@test"
    assert clear.smtp_traffic[0]["to"] == ["bob@test"]


def test_imap_pop3_credentials():
    clear = ClearTextAnalyzer()
    clear.analyze([make_stream(b"a001 LOGIN bob hunter2\r\n", b"* OK\r\n", port=143)])
    clear.analyze([make_stream(b"USER bob\r\nPASS hunter2\r\n", b"+OK\r\n", port=110)])
    protos = {c.protocol for c in clear.credentials}
    assert protos == {"imap", "pop3"}


# ------------------------------------------------------------------- DHCP

def build_dhcp(msg_type=1, mac=b"\x08\x00\x27\xaa\xbb\xcc", hostname=b"lab-pc",
               requested=b"\x0a\x00\x00\x07"):
    pkt = bytes([1, 1, 6, 0]) + b"\x12\x34\x56\x78"          # op,htype,hlen,hops,xid
    pkt += b"\x00\x00\x00\x00"                                # secs, flags
    pkt += b"\x00\x00\x00\x00"                                # ciaddr
    pkt += b"\x0a\x00\x00\x09"                                # yiaddr
    pkt += b"\x0a\x00\x00\x01"                                # siaddr
    pkt += b"\x00\x00\x00\x00"                                # giaddr
    pkt += mac + b"\x00" * 10                                 # chaddr
    pkt += b"\x00" * 64 + b"\x00" * 128                       # sname, file
    pkt += b"\x63\x82\x53\x63"
    pkt += bytes([53, 1, msg_type])
    pkt += bytes([12, len(hostname)]) + hostname
    pkt += bytes([50, 4]) + requested
    pkt += b"\xff"
    return pkt


def test_dhcp_parse():
    obs = parse_dhcp(build_dhcp(1))
    assert obs.message_type == "discover"
    assert obs.client_mac == "08:00:27:aa:bb:cc"
    assert obs.hostname == "lab-pc"
    assert obs.requested_ip == "10.0.0.7"
    obs5 = parse_dhcp(build_dhcp(5))
    assert obs5.message_type == "ack" and obs5.assigned_ip == "10.0.0.9"
    assert parse_dhcp(b"not-dhcp-at-all" * 20) is None


# ---------------------------------------------------------------- entropy

def test_shannon_entropy():
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("ab") == 1.0
    # hex-encoded random bytes: ~4 bits/char
    import hashlib
    hexish = hashlib.sha256(b"x").hexdigest()
    assert 3.5 < shannon_entropy(hexish) <= 4.0


# ------------------------------------------------------------- integration

def test_pipeline_end_to_end(tmp_path):
    """DNS + HTTP + FTP in one capture, through the full pipeline."""
    pkts = []
    pkts += dns_pair(C, "8.8.8.8", "files.example.com", answers=["203.0.113.9"])
    pkts += tcp_conversation(C, 44001, S, 80,
                             [b"GET /a HTTP/1.1\r\nHost: files.example.com\r\n\r\n"],
                             [b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"])
    pkts += tcp_conversation(C, 44002, S, 21,
                             [b"USER bob\r\nPASS pw\r\n"],
                             [b"220 welcome\r\n230 ok\r\n"])
    path = write_pcap(tmp_path / "mix.pcap", pkts)
    res = Pipeline(path, Options(modules={"overview", "dns", "streams", "http", "creds"})).run()
    assert res.meta.packet_count > 0
    assert res.overview.hosts[C].hostnames == set()          # C is client, not resolved
    assert "203.0.113.9" in res.overview.hosts
    assert res.overview.hosts["203.0.113.9"].hostnames == {"files.example.com"}
    assert len(res.http) == 1 and res.http[0].path == "/a"
    assert any(c.protocol == "ftp" and c.username == "bob" for c in res.credentials)
    assert len(res.streams) == 2
